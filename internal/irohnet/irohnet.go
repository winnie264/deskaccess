package irohnet

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/rdpanywhere/rdpanywhere/internal/config"
	"github.com/rdpanywhere/rdpanywhere/internal/logger"
	"github.com/rdpanywhere/rdpanywhere/internal/protocol"
	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/endpointticket"
	"github.com/tmc/go-iroh/iroh"
	irohkey "github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

const (
	ALPNPairing = "DeskAccess/pairing/iroh/1"
	ALPNTunnel  = "DeskAccess/tunnel/iroh/1"

	tunnelKeepaliveInterval = 25 * time.Second
	tunnelKeepaliveTimeout  = 8 * time.Second
)

var log = logger.For(logger.Component("iroh"))

type Handler func(conn io.ReadWriteCloser, remotePeerID string)

type Backend struct {
	ep *iroh.Endpoint

	mu             sync.RWMutex
	pairingHandler Handler
	tunnelHandler  Handler
	relayEnabled   bool
	lastErr        string
	lastOnline     time.Time
	keepaliveOK    int64
	keepaliveFail  int64
	tunnelConns    map[string]*iroh.Conn
	tunnelKeepers  map[string]context.CancelFunc
	lookup         *iroh.AddressLookupServices
	pkarrPublisher *iroh.PkarrPublisher
}

func New(ctx context.Context, cfg *config.Config) (*Backend, error) {
	if cfg == nil || cfg.Iroh.Mode == "" || cfg.Iroh.Mode == "disabled" {
		return nil, nil
	}
	priv, err := cfg.PrivateKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("load iroh key: %w", err)
	}
	sk, err := irohkey.SecretKeyFromEd25519(ed25519.PrivateKey(priv))
	if err != nil {
		return nil, fmt.Errorf("convert iroh key: %w", err)
	}

	relayMode, relayEnabled, err := relayMode(cfg.Iroh)
	if err != nil {
		return nil, err
	}
	lookup, pkarrPublisher := newAddressLookup(sk)
	opts := []iroh.Option{
		iroh.WithSecretKey(sk),
		iroh.WithALPNs(ALPNPairing, ALPNTunnel),
		iroh.WithRelayMode(relayMode),
		iroh.WithNetReport(),
	}
	if lookup != nil && !lookup.IsEmpty() {
		opts = append(opts, iroh.WithAddressLookup(lookup))
	}

	ep, err := iroh.Bind(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("bind iroh endpoint: %w", err)
	}
	b := &Backend{
		ep:             ep,
		relayEnabled:   relayEnabled,
		tunnelConns:    make(map[string]*iroh.Conn),
		tunnelKeepers:  make(map[string]context.CancelFunc),
		lookup:         lookup,
		pkarrPublisher: pkarrPublisher,
	}

	go b.acceptLoop(ctx)
	if lookup != nil {
		b.publishAddr("startup")
		go b.publishAddrLoop(ctx)
	}
	if relayEnabled {
		go b.keepaliveLoop(ctx)
	}
	log.Info("iroh backend started",
		"endpoint_id", ep.ID().String(),
		"mode", cfg.Iroh.Mode,
		"discovery", lookup != nil && !lookup.IsEmpty(),
		"pkarr_publisher", pkarrPublisher != nil)
	return b, nil
}

func newAddressLookup(sk irohkey.SecretKey) (*iroh.AddressLookupServices, *iroh.PkarrPublisher) {
	var lookup iroh.AddressLookupServices
	lookup.SetAddrFilter(iroh.RelayOnlyFilter)
	var publisher *iroh.PkarrPublisher
	log.Info("iroh discovery configuring pkarr publisher", "relay", iroh.N0DNSPkarrRelayProd)
	if p, err := iroh.N0PkarrPublisher(sk, nil); err != nil {
		log.Warn("iroh pkarr publisher disabled", "err", err)
	} else {
		publisher = p
		lookup.AddPublisher(publisher)
		log.Info("iroh discovery pkarr publisher enabled", "relay", iroh.N0DNSPkarrRelayProd)
	}
	log.Info("iroh discovery configuring pkarr resolver", "relay", iroh.N0DNSPkarrRelayProd)
	if resolver, err := iroh.N0PkarrResolver(nil); err != nil {
		log.Warn("iroh pkarr resolver disabled", "err", err)
	} else {
		lookup.AddResolver(resolver)
		log.Info("iroh discovery pkarr resolver enabled", "relay", iroh.N0DNSPkarrRelayProd)
	}
	lookup.AddResolver(iroh.N0DNSAddressLookup(nil))
	log.Info("iroh discovery DNS resolver enabled", "origin", dns.N0DNSEndpointOriginProd)
	return &lookup, publisher
}

func (b *Backend) SetHandlers(pairing Handler, tunnel Handler) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.pairingHandler = pairing
	b.tunnelHandler = tunnel
	b.mu.Unlock()
}

func (b *Backend) Close(ctx context.Context) error {
	if b == nil || b.ep == nil {
		return nil
	}
	b.mu.Lock()
	for key, conn := range b.tunnelConns {
		conn.CloseWithError(0, "backend shutdown")
		delete(b.tunnelConns, key)
	}
	for key, cancel := range b.tunnelKeepers {
		cancel()
		delete(b.tunnelKeepers, key)
	}
	publisher := b.pkarrPublisher
	b.pkarrPublisher = nil
	b.mu.Unlock()
	if publisher != nil {
		_ = publisher.Close()
	}
	return b.ep.Shutdown(ctx)
}

func (b *Backend) Ticket() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return b.TicketContext(ctx)
}

func (b *Backend) TicketContext(ctx context.Context) (string, error) {
	if b == nil || b.ep == nil {
		return "", fmt.Errorf("iroh backend is not running")
	}
	if b.relayEnabled {
		if err := b.ep.Online(ctx); err != nil {
			b.setLastError(err)
			return "", fmt.Errorf("iroh relay is not online yet: %w", err)
		}
	}
	addr := b.ep.Addr()
	if b.relayEnabled && len(addr.RelayURLs()) == 0 {
		err := fmt.Errorf("iroh relay is not online yet")
		b.setLastError(err)
		return "", err
	}
	b.setLastError(nil)
	return endpointticket.Encode(addr), nil
}

func (b *Backend) Status() map[string]any {
	if b == nil || b.ep == nil {
		return map[string]any{"enabled": false, "running": false}
	}
	addr := b.ep.Addr()
	relayURLs := addr.RelayURLs()
	b.mu.RLock()
	lastErr := b.lastErr
	relayEnabled := b.relayEnabled
	lastOnline := b.lastOnline
	keepaliveOK := b.keepaliveOK
	keepaliveFail := b.keepaliveFail
	b.mu.RUnlock()
	return map[string]any{
		"enabled":        true,
		"running":        true,
		"ready":          !relayEnabled || len(relayURLs) > 0,
		"endpoint_id":    b.ep.ID().String(),
		"discovery":      b.lookup != nil && !b.lookup.IsEmpty(),
		"pkarr_publish":  b.pkarrPublisher != nil,
		"relay_enabled":  relayEnabled,
		"relay_urls":     len(relayURLs),
		"direct_addrs":   len(addr.Addrs()),
		"last_error":     lastErr,
		"last_online":    lastOnline,
		"keepalive_ok":   keepaliveOK,
		"keepalive_fail": keepaliveFail,
	}
}

func (b *Backend) OpenPairing(ctx context.Context, ticket string) (io.ReadWriteCloser, error) {
	return b.openStream(ctx, ticket, ALPNPairing)
}

func (b *Backend) OpenTunnel(ctx context.Context, ticket string) (io.ReadWriteCloser, error) {
	return b.openStream(ctx, ticket, ALPNTunnel)
}

func (b *Backend) openStream(ctx context.Context, ticket string, alpn string) (io.ReadWriteCloser, error) {
	if b == nil || b.ep == nil {
		return nil, fmt.Errorf("iroh backend is not running")
	}
	addr, err := endpointticket.Decode(ticket)
	if err != nil {
		return nil, fmt.Errorf("decode iroh ticket: %w", err)
	}
	if alpn == ALPNTunnel {
		return b.openCachedTunnelStream(ctx, addr, alpn)
	}
	return b.openNewStream(ctx, addr, alpn)
}

func (b *Backend) openCachedTunnelStream(ctx context.Context, addr netaddr.EndpointAddr, alpn string) (io.ReadWriteCloser, error) {
	key := addr.ID.String() + "|" + alpn
	b.mu.RLock()
	conn := b.tunnelConns[key]
	b.mu.RUnlock()
	if conn == nil {
		var err error
		conn, err = b.connectTunnelWithFallback(ctx, addr, alpn, "connect")
		if err != nil {
			return nil, err
		}
		b.mu.Lock()
		existing := b.tunnelConns[key]
		if existing != nil {
			conn.CloseWithError(0, "duplicate cached tunnel connection")
			conn = existing
		} else {
			b.tunnelConns[key] = conn
			b.startTunnelKeeperLocked(key, conn, addr, alpn)
		}
		b.mu.Unlock()
	} else {
		log.Info("iroh reusing tunnel connection", "alpn", alpn, "peer", short(addr.ID.String()))
	}

	stream, err := conn.OpenStreamConn(ctx)
	if err == nil {
		log.Info("iroh stream opened", "alpn", alpn, "peer", short(addr.ID.String()))
		return &connWithClose{Conn: stream}, nil
	}

	log.Warn("iroh cached tunnel stream open failed, reconnecting", "alpn", alpn, "peer", short(addr.ID.String()), "err", err)
	b.mu.Lock()
	if b.tunnelConns[key] == conn {
		delete(b.tunnelConns, key)
		b.stopTunnelKeeperLocked(key)
	}
	b.mu.Unlock()
	conn.CloseWithError(0, "")

	conn, err = b.connectTunnelWithFallback(ctx, addr, alpn, "reconnect")
	if err != nil {
		return nil, fmt.Errorf("reconnect iroh tunnel: %w", err)
	}
	b.mu.Lock()
	b.tunnelConns[key] = conn
	b.startTunnelKeeperLocked(key, conn, addr, alpn)
	b.mu.Unlock()

	stream, err = conn.OpenStreamConn(ctx)
	if err != nil {
		conn.CloseWithError(0, "")
		b.mu.Lock()
		if b.tunnelConns[key] == conn {
			delete(b.tunnelConns, key)
			b.stopTunnelKeeperLocked(key)
		}
		b.mu.Unlock()
		return nil, fmt.Errorf("open iroh stream after reconnect: %w", err)
	}
	log.Info("iroh stream opened", "alpn", alpn, "peer", short(addr.ID.String()))
	return &connWithClose{Conn: stream}, nil
}

func (b *Backend) connectTunnelWithFallback(ctx context.Context, addr netaddr.EndpointAddr, alpn string, reason string) (*iroh.Conn, error) {
	conn, err := b.connect(ctx, addr, alpn)
	if err != nil && b.lookup != nil {
		log.Info("iroh tunnel connect failed, resolving fresh endpoint via pkarr/dns", "reason", reason, "alpn", alpn, "peer", short(addr.ID.String()), "err", err)
		resolved, resolveErr := b.resolveEndpoint(ctx, addr.ID)
		if resolveErr != nil {
			log.Warn("iroh tunnel discovery fallback failed", "reason", reason, "alpn", alpn, "peer", short(addr.ID.String()), "connect_err", err, "resolve_err", resolveErr)
		} else {
			log.Info("iroh retrying tunnel with discovered address", "reason", reason, "alpn", alpn, "peer", short(addr.ID.String()), "addrs", len(resolved.Addrs()), "relay_urls", len(resolved.RelayURLs()))
			conn, err = b.connect(ctx, resolved, alpn)
		}
	}
	return conn, err
}

func (b *Backend) openNewStream(ctx context.Context, addr netaddr.EndpointAddr, alpn string) (io.ReadWriteCloser, error) {
	conn, err := b.connect(ctx, addr, alpn)
	if err != nil && b.lookup != nil {
		log.Info("iroh connect failed, resolving fresh endpoint via pkarr/dns", "alpn", alpn, "peer", short(addr.ID.String()), "err", err)
		resolved, resolveErr := b.resolveEndpoint(ctx, addr.ID)
		if resolveErr != nil {
			log.Warn("iroh discovery fallback failed", "alpn", alpn, "peer", short(addr.ID.String()), "connect_err", err, "resolve_err", resolveErr)
		} else {
			log.Info("iroh retrying with discovered address", "alpn", alpn, "peer", short(addr.ID.String()), "addrs", len(resolved.Addrs()), "relay_urls", len(resolved.RelayURLs()))
			conn, err = b.connect(ctx, resolved, alpn)
		}
	}
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamConn(ctx)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, fmt.Errorf("open iroh stream: %w", err)
	}
	log.Info("iroh stream opened", "alpn", alpn, "peer", short(addr.ID.String()))
	return &connWithClose{Conn: stream, parent: conn, closeParent: true}, nil
}

func (b *Backend) startTunnelKeeperLocked(key string, conn *iroh.Conn, addr netaddr.EndpointAddr, alpn string) {
	if b.tunnelKeepers[key] != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	b.tunnelKeepers[key] = cancel
	go b.tunnelKeepaliveLoop(ctx, key, conn, addr, alpn)
}

func (b *Backend) stopTunnelKeeperLocked(key string) {
	if cancel := b.tunnelKeepers[key]; cancel != nil {
		cancel()
		delete(b.tunnelKeepers, key)
	}
}

func (b *Backend) tunnelKeepaliveLoop(ctx context.Context, key string, conn *iroh.Conn, addr netaddr.EndpointAddr, alpn string) {
	ticker := time.NewTicker(tunnelKeepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := b.tunnelKeepaliveOnce(ctx, conn, addr, alpn); err != nil {
				log.Warn("iroh tunnel keepalive failed", "alpn", alpn, "peer", short(addr.ID.String()), "err", err)
				b.mu.Lock()
				if b.tunnelConns[key] == conn {
					conn.CloseWithError(0, "tunnel keepalive failed")
					delete(b.tunnelConns, key)
				}
				b.stopTunnelKeeperLocked(key)
				b.mu.Unlock()
				return
			}
		}
	}
}

func (b *Backend) tunnelKeepaliveOnce(parent context.Context, conn *iroh.Conn, addr netaddr.EndpointAddr, alpn string) error {
	ctx, cancel := context.WithTimeout(parent, tunnelKeepaliveTimeout)
	defer cancel()
	stream, err := conn.OpenStreamConn(ctx)
	if err != nil {
		return fmt.Errorf("open ping stream: %w", err)
	}
	defer stream.Close()
	if err := protocol.WriteFrame(stream, protocol.MsgTunnelPing, protocol.TunnelPing{TimeUnix: time.Now().Unix()}); err != nil {
		return fmt.Errorf("write ping: %w", err)
	}
	clearDeadline := setStreamReadDeadline(stream, time.Now().Add(tunnelKeepaliveTimeout))
	defer clearDeadline()
	msgType, _, err := protocol.ReadFrame(stream)
	if err != nil {
		return fmt.Errorf("read pong: %w", err)
	}
	if msgType != protocol.MsgTunnelPong {
		return fmt.Errorf("unexpected ping response 0x%02x", msgType)
	}
	log.Debug("iroh tunnel keepalive ok", "alpn", alpn, "peer", short(addr.ID.String()))
	return nil
}

func setStreamReadDeadline(stream net.Conn, deadline time.Time) func() {
	if err := stream.SetReadDeadline(deadline); err != nil {
		log.Debug("set iroh stream read deadline failed", "err", err)
		return func() {}
	}
	return func() {
		if err := stream.SetReadDeadline(time.Time{}); err != nil {
			log.Debug("clear iroh stream read deadline failed", "err", err)
		}
	}
}

func (b *Backend) connect(ctx context.Context, addr netaddr.EndpointAddr, alpn string) (*iroh.Conn, error) {
	if b.lookup != nil {
		original := addr
		log.Info("iroh resolving endpoint via pkarr/dns before connect",
			"alpn", alpn,
			"peer", short(addr.ID.String()),
			"ticket_addrs", len(addr.Addrs()),
			"ticket_relay_urls", len(addr.RelayURLs()))
		resolved, err := b.resolveEndpoint(ctx, addr.ID)
		if err != nil {
			if !hasEndpointRoutes(original) {
				return nil, fmt.Errorf("iroh discovery: %w", err)
			}
			log.Warn("iroh discovery unavailable, using ticket addresses",
				"alpn", alpn,
				"peer", short(addr.ID.String()),
				"ticket_addrs", len(original.Addrs()),
				"ticket_relay_urls", len(original.RelayURLs()),
				"err", err)
			addr = original
		} else {
			log.Info("iroh using discovered endpoint before connect",
				"alpn", alpn,
				"peer", short(addr.ID.String()),
				"discovered_addrs", len(resolved.Addrs()),
				"discovered_relay_urls", len(resolved.RelayURLs()),
				"ticket_addrs", len(original.Addrs()),
				"ticket_relay_urls", len(original.RelayURLs()))
			addr = resolved
		}
	} else {
		log.Info("iroh discovery unavailable before connect", "alpn", alpn, "peer", short(addr.ID.String()), "addrs", len(addr.Addrs()), "relay_urls", len(addr.RelayURLs()))
	}
	log.Info("iroh connecting", "alpn", alpn, "peer", short(addr.ID.String()), "addrs", len(addr.Addrs()), "relay_urls", len(addr.RelayURLs()))
	conn, err := b.ep.Connect(ctx, addr, alpn)
	if err != nil {
		return nil, fmt.Errorf("iroh connect: %w", err)
	}
	log.Info("iroh connected, waiting for handshake", "alpn", alpn, "peer", short(addr.ID.String()))
	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		conn.CloseWithError(0, "handshake timeout")
		return nil, fmt.Errorf("iroh handshake: %w", ctx.Err())
	}
	log.Info("iroh handshake ready", "alpn", alpn, "peer", short(addr.ID.String()), "used_0rtt", conn.Used0RTT())
	if conn.Used0RTT() {
		log.Debug("iroh connection resumed", "alpn", alpn, "peer", short(addr.ID.String()), "used_0rtt", true)
	}
	return conn, nil
}

func hasEndpointRoutes(addr netaddr.EndpointAddr) bool {
	return len(addr.Addrs()) > 0 || len(addr.RelayURLs()) > 0
}

func (b *Backend) resolveEndpoint(ctx context.Context, id irohkey.EndpointID) (netaddr.EndpointAddr, error) {
	if b == nil || b.lookup == nil {
		return netaddr.EndpointAddr{}, fmt.Errorf("iroh discovery is not configured")
	}
	started := time.Now()
	log.Info("iroh discovery resolving endpoint via pkarr/dns", "peer", short(id.String()))
	var lastErr error
	for item, err := range b.lookup.Resolve(ctx, id) {
		if err != nil {
			lastErr = err
			log.Warn("iroh discovery lookup failed", "peer", short(id.String()), "err", err)
			continue
		}
		addr := item.Addr()
		if len(addr.Addrs()) == 0 {
			log.Info("iroh discovery record had no addrs", "peer", short(id.String()), "source", item.Provenance())
			continue
		}
		log.Info("iroh discovery resolved endpoint",
			"peer", short(id.String()),
			"source", item.Provenance(),
			"addrs", len(addr.Addrs()),
			"relay_urls", len(addr.RelayURLs()),
			"duration", time.Since(started).String())
		return addr, nil
	}
	if lastErr != nil {
		log.Warn("iroh discovery resolving endpoint failed", "peer", short(id.String()), "duration", time.Since(started).String(), "err", lastErr)
		return netaddr.EndpointAddr{}, lastErr
	}
	log.Warn("iroh discovery resolving endpoint produced no records", "peer", short(id.String()), "duration", time.Since(started).String())
	return netaddr.EndpointAddr{}, fmt.Errorf("no iroh discovery records found")
}

func (b *Backend) publishAddr(reason string) {
	if b == nil || b.lookup == nil || b.ep == nil {
		return
	}
	addr := b.ep.Addr()
	data := dns.EndpointDataFromAddr(addr)
	if !data.HasAddrs() {
		log.Debug("iroh discovery publish skipped: no addrs", "reason", reason)
		return
	}
	log.Info("iroh discovery publishing address via pkarr/dns",
		"reason", reason,
		"relay_urls", len(addr.RelayURLs()),
		"direct_addrs", len(addr.IPAddrs()))
	b.lookup.Publish(data)
	log.Info("iroh discovery address published",
		"reason", reason,
		"relay_urls", len(addr.RelayURLs()),
		"direct_addrs", len(addr.IPAddrs()))
}

func (b *Backend) publishAddrLoop(ctx context.Context) {
	w := b.ep.WatchAddr()
	for {
		_, err := w.Updated(ctx)
		if err != nil {
			return
		}
		b.publishAddr("addr_change")
	}
}

func (b *Backend) acceptLoop(ctx context.Context) {
	for {
		conn, err := b.ep.Accept(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				if isEndpointClosed(err) {
					return
				}
				log.Warn("iroh accept failed", "err", err)
				time.Sleep(time.Second)
				continue
			}
		}
		go b.handleConn(ctx, conn)
	}
}

func (b *Backend) handleConn(ctx context.Context, conn *iroh.Conn) {
	remotePeerID, err := endpointIDToPeerID(conn.RemoteID())
	if err != nil {
		log.Warn("iroh remote id conversion failed", "err", err)
		conn.CloseWithError(0, "bad remote id")
		return
	}
	log.Info("iroh connection accepted", "peer", short(remotePeerID), "alpn", conn.ALPN())
	defer log.Info("iroh connection handler ended", "peer", short(remotePeerID), "alpn", conn.ALPN())
	for {
		stream, err := conn.AcceptStreamConn(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				log.Debug("iroh accept stream ended", "peer", short(remotePeerID), "alpn", conn.ALPN(), "err", err)
			}
			return
		}
		log.Info("iroh stream accepted", "peer", short(remotePeerID), "alpn", conn.ALPN())
		wrapped := &connWithClose{Conn: stream}

		b.mu.RLock()
		pairingHandler := b.pairingHandler
		tunnelHandler := b.tunnelHandler
		b.mu.RUnlock()

		switch conn.ALPN() {
		case ALPNPairing:
			if pairingHandler == nil {
				log.Warn("iroh pairing stream closed without handler", "peer", short(remotePeerID))
				wrapped.Close()
				continue
			}
			go pairingHandler(wrapped, remotePeerID)
		case ALPNTunnel:
			if tunnelHandler == nil {
				log.Warn("iroh tunnel stream closed without handler", "peer", short(remotePeerID))
				wrapped.Close()
				continue
			}
			go tunnelHandler(wrapped, remotePeerID)
		default:
			log.Warn("iroh unsupported alpn", "alpn", conn.ALPN(), "peer", short(remotePeerID))
			wrapped.Close()
			return
		}
	}
}

func isEndpointClosed(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "endpoint closed") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "closed listener")
}

func (b *Backend) keepaliveLoop(ctx context.Context) {
	b.keepaliveOnce(ctx, "startup")
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			b.keepaliveOnce(ctx, "periodic")
		case <-ctx.Done():
			return
		}
	}
}

func (b *Backend) keepaliveOnce(ctx context.Context, reason string) {
	if b == nil || b.ep == nil {
		return
	}
	onlineCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	started := time.Now()
	if err := b.ep.Online(onlineCtx); err != nil {
		b.setLastError(err)
		b.bumpKeepalive(false, time.Time{})
		log.Warn("iroh relay keepalive failed",
			"reason", reason,
			"duration", time.Since(started).String(),
			"err", err,
		)
		return
	}
	now := time.Now()
	b.setLastError(nil)
	b.bumpKeepalive(true, now)
	addr := b.ep.Addr()
	log.Info("iroh relay keepalive ok",
		"reason", reason,
		"relay_urls", len(addr.RelayURLs()),
		"direct_addrs", len(addr.Addrs()),
		"duration", time.Since(started).String(),
	)
}

func (b *Backend) bumpKeepalive(ok bool, lastOnline time.Time) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if ok {
		b.keepaliveOK++
		b.lastOnline = lastOnline
		return
	}
	b.keepaliveFail++
}

func (b *Backend) setLastError(err error) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		b.lastErr = ""
		return
	}
	b.lastErr = err.Error()
}

func relayMode(cfg config.IrohConfig) (relay.Mode, bool, error) {
	switch cfg.Mode {
	case "disabled", "":
		return relay.ModeDisabled(), false, nil
	case "custom":
		urls := make([]netaddr.RelayURL, 0, len(cfg.Servers))
		for _, raw := range cfg.Servers {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			if _, err := url.Parse(raw); err != nil {
				return relay.ModeDisabled(), false, fmt.Errorf("invalid iroh relay URL %q: %w", raw, err)
			}
			u, err := netaddr.ParseRelayURL(raw)
			if err != nil {
				return relay.ModeDisabled(), false, fmt.Errorf("invalid iroh relay URL %q: %w", raw, err)
			}
			urls = append(urls, u)
		}
		return relay.ModeCustomURLs(urls...), true, nil
	default:
		return relay.ModeDefault(), true, nil
	}
}

func endpointIDToPeerID(id irohkey.EndpointID) (string, error) {
	pub := id.PublicKey().Ed25519()
	libp2pPub, err := libp2pcrypto.UnmarshalEd25519PublicKey(pub)
	if err != nil {
		return "", err
	}
	pid, err := peer.IDFromPublicKey(libp2pPub)
	if err != nil {
		return "", err
	}
	return pid.String(), nil
}

func TicketEndpointID(ticket string) (irohkey.EndpointID, error) {
	addr, err := endpointticket.Decode(ticket)
	if err != nil {
		return irohkey.EndpointID{}, err
	}
	return addr.ID, nil
}

type connWithClose struct {
	net.Conn
	parent      *iroh.Conn
	closeParent bool
}

func (c *connWithClose) Close() error {
	err := c.Conn.Close()
	if c.parent != nil && c.closeParent {
		c.parent.CloseWithError(0, "stream closed")
	}
	return err
}

func (c *connWithClose) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func LogValue(b *Backend) slog.Value {
	if b == nil || b.ep == nil {
		return slog.StringValue("disabled")
	}
	return slog.StringValue(b.ep.ID().String())
}
