package node

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/control"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/multiformats/go-multiaddr"

	"github.com/libp2p/go-libp2p"
	"github.com/rdpanywhere/rdpanywhere/internal/config"
	"github.com/rdpanywhere/rdpanywhere/internal/dht"
	"github.com/rdpanywhere/rdpanywhere/internal/logger"
)

const (
	ProtocolTunnel  = "/DeskAccess/tunnel/1.0.0"
	ProtocolPairing = "/DeskAccess/pairing/1.0.0"

	keepAliveInterval  = 25 * time.Second
	reservationRefresh = 20 * time.Minute
	reconnectBackoff   = 5 * time.Second
	reconnectMaxWait   = 2 * time.Minute
)

type ConnType string

const (
	ConnDirect  ConnType = "direct"
	ConnRelayed ConnType = "relayed"
	ConnUnknown ConnType = "unknown"
)

// PublicRelays — circuit relay v2 nodes used for NAT traversal.
//
// These are Protocol Labs / Amino DHT bootstrap nodes that also run circuit
// relay v2 as LIMITED relays (time and bandwidth capped, but publicly available).
// See: https://discuss.ipfs.tech/t/19545
//
// The bootstrap.libp2p.io entries are intentionally absent — those are
// peer-discovery nodes only and always return RESERVATION_REFUSED.
//
// For unlimited relay throughput, deploy cmd/relay-server on any public VPS
// and point relay.url in the config at it.
var PublicRelays = []string{
	// Equinix Metal nodes — Protocol Labs operated, confirmed relay v2.
	// TCP and QUIC addresses for the same peer are merged before dialing.
	"/ip4/147.75.80.110/tcp/4001/p2p/QmbFgm5zan8P6eWWmeyfncR5feYEMPbht5b1FW1C37aQ7y",
	"/ip4/147.75.80.110/udp/4001/quic-v1/p2p/QmbFgm5zan8P6eWWmeyfncR5feYEMPbht5b1FW1C37aQ7y",
	"/ip4/147.75.195.153/tcp/4001/p2p/QmW9m57aiBDHAkKj9nmFSEn7ZqrcF1fZS4bipsTCHburei",
	"/ip4/147.75.195.153/udp/4001/quic-v1/p2p/QmW9m57aiBDHAkKj9nmFSEn7ZqrcF1fZS4bipsTCHburei",
	"/ip4/147.75.70.221/tcp/4001/p2p/Qme8g49gm3q4Acp7xWBKg3nAa9fxZ1YmyDJdyGgoG6LsXh",
	"/ip4/147.75.70.221/udp/4001/quic-v1/p2p/Qme8g49gm3q4Acp7xWBKg3nAa9fxZ1YmyDJdyGgoG6LsXh",
}

var log = logger.For(logger.CompNode)

type Node struct {
	Host   host.Host
	PeerID peer.ID
	cfg    *config.Config

	mu                sync.RWMutex
	relayAddrs        []multiaddr.Multiaddr
	relayInfos        []peer.AddrInfo
	relayRefusedUntil []time.Time // indexed same as relayInfos; zero = not refused
	onAddrsChange     func([]string)
	lastRelayErr      string
	lastDHTErr        string

	dhtClient *dht.Client // nil until DHT bootstraps; used for relay fallback + peer lookup

	relayCancel context.CancelFunc
	dhtCancel   context.CancelFunc
	dhtGen      uint64

	// testRelayMask overrides RelayMask() when non-zero.
	// Set by NewFromHost for in-process test nodes.
	testRelayMask byte
}

func New(ctx context.Context, cfg *config.Config) (*Node, error) {
	privKeyBytes, err := cfg.PrivateKeyBytes()
	if err != nil {
		return nil, logger.Wrap("load private key", err)
	}
	libp2pPriv, err := libp2pcrypto.UnmarshalEd25519PrivateKey(privKeyBytes[:ed25519.PrivateKeySize])
	if err != nil {
		return nil, logger.Wrap("unmarshal libp2p key", err)
	}

	cm, err := connmgr.NewConnManager(50, 200)
	if err != nil {
		return nil, err
	}

	opts := []libp2p.Option{
		libp2p.Identity(libp2pPriv),
		libp2p.ConnectionManager(cm),
		libp2p.ListenAddrStrings(
			"/ip4/0.0.0.0/tcp/0",
			"/ip4/0.0.0.0/udp/0/quic-v1",
			"/ip6/::/tcp/0",
			"/ip6/::/udp/0/quic-v1",
		),
		libp2p.EnableNATService(),
		libp2p.EnableHolePunching(),
	}

	if cfg.Relay.Mode == "custom" && len(cfg.Relay.Allowlist) > 0 {
		opts = append(opts, libp2p.ConnectionGater(
			&allowlistGater{allowed: cfg.Relay.Allowlist},
		))
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, logger.Wrap("create libp2p host", err)
	}

	n := &Node{Host: h, PeerID: h.ID(), cfg: cfg}

	relayInfos, err := n.resolveRelays()
	if err != nil {
		// Degraded mode: no relays resolved (DNS failure?). Start anyway —
		// direct LAN connections and previously-paired peers may still work.
		n.setRelayError(err)
		log.Warn("relay address resolution failed — starting in degraded mode", "err", err)
	} else {
		n.relayInfos = relayInfos
		n.relayRefusedUntil = make([]time.Time, len(relayInfos))
	}

	if n.libp2pActive() {
		h.Network().Notify(&dcutrNotifier{n: n})
	}

	// Attempt initial relay reservation. Non-fatal — the background keepalive
	// loop will keep retrying. Direct P2P still works without relay.
	if n.relayEnabled() && len(n.relayInfos) > 0 {
		reserveCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		if err := n.reserveAll(reserveCtx); err != nil {
			n.setRelayError(err)
			log.Warn("initial relay reservation failed — will retry in background",
				"err", err)
		}
		cancel()
	}

	if len(n.relayAddrs) > 0 {
		log.Info("node online",
			"peer_id", h.ID().String(),
			"relay_addrs", len(n.relayAddrs),
			"label", cfg.Node.Label,
		)
	} else {
		log.Warn("node online (no relay — direct connections only)",
			"peer_id", h.ID().String(),
			"label", cfg.Node.Label,
		)
	}

	n.startRelayLoops(ctx)
	n.startDHT(ctx)

	return n, nil
}

// ApplyNetworkConfig re-reads the current config and applies relay/DHT changes
// without restarting the process or replacing the libp2p host identity.
func (n *Node) ApplyNetworkConfig(ctx context.Context) error {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	if n.relayCancel != nil {
		n.relayCancel()
		n.relayCancel = nil
	}
	if n.dhtCancel != nil {
		n.dhtCancel()
		n.dhtCancel = nil
	}
	oldDHT := n.dhtClient
	n.dhtClient = nil
	n.relayAddrs = nil
	n.relayInfos = nil
	n.relayRefusedUntil = nil
	n.mu.Unlock()
	if oldDHT != nil {
		_ = oldDHT.Close()
	}

	if n.relayEnabled() {
		relayInfos, err := n.resolveRelays()
		if err != nil {
			n.setRelayError(err)
			log.Warn("relay address resolution failed after config change", "err", err)
		} else {
			n.mu.Lock()
			n.relayInfos = relayInfos
			n.relayRefusedUntil = make([]time.Time, len(relayInfos))
			n.mu.Unlock()
			reserveCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			if err := n.reserveAll(reserveCtx); err != nil {
				n.setRelayError(err)
				log.Warn("relay reservation failed after config change", "err", err)
			}
			cancel()
		}
	}
	n.fireAddrsChange()
	n.startRelayLoops(ctx)
	n.startDHT(ctx)
	return nil
}

func (n *Node) startRelayLoops(ctx context.Context) {
	if !n.relayEnabled() {
		return
	}
	relayCtx, cancel := context.WithCancel(ctx)
	n.mu.Lock()
	if n.relayCancel != nil {
		n.relayCancel()
	}
	n.relayCancel = cancel
	n.mu.Unlock()
	go n.keepAliveLoop(relayCtx)
	go n.reservationRefreshLoop(relayCtx)
}

func (n *Node) startDHT(ctx context.Context) {
	if !n.dhtEnabled() {
		n.mu.Lock()
		if n.dhtCancel != nil {
			n.dhtCancel()
			n.dhtCancel = nil
		}
		n.dhtClient = nil
		n.mu.Unlock()
		return
	}
	dhtCtx, cancel := context.WithCancel(ctx)
	n.mu.Lock()
	if n.dhtCancel != nil {
		n.dhtCancel()
	}
	n.dhtCancel = cancel
	n.dhtGen++
	gen := n.dhtGen
	n.mu.Unlock()
	go func() {
		dc, err := dht.New(dhtCtx, n.Host, n.cfg.DHT)
		if err != nil {
			if dhtCtx.Err() == nil {
				n.setDHTError(err)
				log.Warn("DHT init failed (relay fallback disabled)", "err", err)
			}
			cancel()
			return
		}
		n.mu.Lock()
		if n.dhtGen == gen {
			n.dhtClient = dc
			n.lastDHTErr = ""
		} else if dc != nil {
			_ = dc.Close()
		}
		n.mu.Unlock()
	}()
}

// DHT returns the Kademlia DHT client, or nil if not yet initialised.
// Used by the presence manager for cold-start peer lookup.
func (n *Node) DHT() *dht.Client {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.dhtClient
}

func (n *Node) WaitDHTReady(ctx context.Context) error {
	started := time.Now()
	dc, err := n.waitDHTClient(ctx, "backend startup", n.NodeID(), started)
	if err != nil {
		return err
	}
	if !dc.WaitReady(ctx) {
		return fmt.Errorf("DHT bootstrap not ready")
	}
	log.Info("libp2p DHT backend ready", "routing_table_size", dc.RoutingTableSize(), "duration", time.Since(started).String())
	return nil
}

func (n *Node) waitDHTClient(ctx context.Context, operation string, peerID string, started time.Time) (*dht.Client, error) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	log.Info("libp2p DHT waiting for client", "operation", operation, "peer", short(peerID))
	for {
		n.mu.RLock()
		dc := n.dhtClient
		enabled := n.dhtEnabled()
		lastErr := n.lastDHTErr
		n.mu.RUnlock()
		if dc != nil {
			log.Info("libp2p DHT client available", "operation", operation, "peer", short(peerID), "duration", time.Since(started).String())
			return dc, nil
		}
		if !enabled {
			err := fmt.Errorf("DHT is disabled")
			log.Warn("libp2p DHT client unavailable", "operation", operation, "peer", short(peerID), "duration", time.Since(started).String(), "err", err)
			return nil, err
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			if lastErr != "" {
				return nil, fmt.Errorf("DHT is not ready: %s", lastErr)
			}
			log.Warn("libp2p DHT client wait timed out", "operation", operation, "peer", short(peerID), "duration", time.Since(started).String(), "err", ctx.Err())
			return nil, fmt.Errorf("DHT is not ready")
		}
	}
}

func (n *Node) NetworkStatus() map[string]any {
	n.mu.RLock()
	defer n.mu.RUnlock()

	relayConnected := n.relayEnabled() && len(n.relayAddrs) > 0
	dhtPeers := 0
	if n.dhtClient != nil {
		dhtPeers = n.dhtClient.RoutingTableSize()
	}
	return map[string]any{
		"relay": map[string]any{
			"enabled":          n.relayEnabled(),
			"connected":        relayConnected,
			"relay_count":      len(n.relayInfos),
			"reserved_addrs":   len(n.relayAddrs),
			"last_error":       n.lastRelayErr,
			"reservation_mask": n.RelayMask(),
		},
		"dht": map[string]any{
			"enabled":            n.dhtEnabled(),
			"running":            n.dhtClient != nil,
			"ready":              n.dhtClient != nil && dhtPeers > 0,
			"routing_table_size": dhtPeers,
			"last_error":         n.lastDHTErr,
		},
	}
}

// FindPeerAddrs resolves a peer through the libp2p DHT and returns dialable
// multiaddrs. This is used for DHT-only invite links that do not carry relay
// reservation addresses.
func (n *Node) FindPeerAddrs(ctx context.Context, peerID string) ([]string, error) {
	started := time.Now()
	log.Info("libp2p DHT peer address resolve requested", "peer", short(peerID))
	pid, err := peer.Decode(peerID)
	if err != nil {
		log.Warn("libp2p DHT peer address resolve failed", "peer", short(peerID), "err", err)
		return nil, logger.Wrap("invalid peer id", err)
	}

	dc, err := n.waitDHTClient(ctx, "peer address resolve", peerID, started)
	if err != nil {
		log.Warn("libp2p DHT peer address resolve failed", "peer", short(peerID), "duration", time.Since(started).String(), "err", err)
		return nil, err
	}

	if !dc.WaitReady(ctx) {
		log.Warn("libp2p DHT peer address resolve failed", "peer", short(peerID), "duration", time.Since(started).String(), "err", "DHT bootstrap not ready")
		return nil, fmt.Errorf("DHT bootstrap not ready")
	}
	info, err := dc.FindPeer(ctx, pid)
	if err != nil {
		log.Warn("libp2p DHT peer address resolve failed", "peer", short(peerID), "duration", time.Since(started).String(), "err", err)
		return nil, logger.Wrap("DHT find peer", err)
	}
	out := make([]string, 0, len(info.Addrs))
	for _, addr := range info.Addrs {
		if isLoopbackMultiaddr(addr) {
			continue
		}
		out = append(out, addr.String())
	}
	if len(out) == 0 {
		log.Warn("libp2p DHT peer address resolve returned no external addrs", "peer", short(peerID), "raw_addrs", len(info.Addrs), "duration", time.Since(started).String())
		return nil, fmt.Errorf("DHT returned no externally dialable addresses")
	}
	log.Info("libp2p DHT peer address resolve succeeded", "peer", short(peerID), "raw_addrs", len(info.Addrs), "external_addrs", len(out), "duration", time.Since(started).String())
	return out, nil
}

// FindIdentityAddrs resolves an invite public key through the app-specific DHT
// provider record published by the host.
func (n *Node) FindIdentityAddrs(ctx context.Context, publicKeyHex string, expectedPeerID string) ([]string, error) {
	started := time.Now()
	log.Info("libp2p DHT identity address resolve requested", "peer", short(expectedPeerID), "public_key", short(publicKeyHex))
	key, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		log.Warn("libp2p DHT identity address resolve failed", "peer", short(expectedPeerID), "err", err)
		return nil, logger.Wrap("decode public key", err)
	}
	expected, err := peer.Decode(expectedPeerID)
	if err != nil {
		log.Warn("libp2p DHT identity address resolve failed", "peer", short(expectedPeerID), "err", err)
		return nil, logger.Wrap("invalid peer id", err)
	}

	dc, err := n.waitDHTClient(ctx, "identity address resolve", expectedPeerID, started)
	if err != nil {
		log.Warn("libp2p DHT identity address resolve failed", "peer", short(expectedPeerID), "duration", time.Since(started).String(), "err", err)
		return nil, err
	}
	if !dc.WaitReady(ctx) {
		log.Warn("libp2p DHT identity address resolve failed", "peer", short(expectedPeerID), "duration", time.Since(started).String(), "err", "DHT bootstrap not ready")
		return nil, fmt.Errorf("DHT bootstrap not ready")
	}
	info, err := dc.FindIdentityProvider(ctx, key, expected)
	if err != nil {
		log.Warn("libp2p DHT identity address resolve failed", "peer", short(expectedPeerID), "duration", time.Since(started).String(), "err", err)
		return nil, err
	}
	if len(info.Addrs) > 0 {
		out := make([]string, 0, len(info.Addrs))
		for _, addr := range info.Addrs {
			if isLoopbackMultiaddr(addr) {
				continue
			}
			out = append(out, addr.String())
		}
		if len(out) == 0 {
			log.Warn("libp2p DHT identity address resolve returned only loopback", "peer", short(expectedPeerID), "raw_addrs", len(info.Addrs), "duration", time.Since(started).String())
			return nil, fmt.Errorf("identity provider returned only loopback addresses")
		}
		log.Info("libp2p DHT identity address resolve succeeded", "peer", short(expectedPeerID), "raw_addrs", len(info.Addrs), "external_addrs", len(out), "duration", time.Since(started).String())
		return out, nil
	}
	if err := n.Host.Connect(ctx, info); err != nil {
		log.Warn("libp2p DHT identity provider connect failed", "peer", short(expectedPeerID), "duration", time.Since(started).String(), "err", err)
		return nil, logger.Wrap("connect to identity provider", err)
	}
	log.Info("libp2p DHT identity provider connected without advertised addrs", "peer", short(expectedPeerID), "duration", time.Since(started).String())
	return nil, nil
}

func isLoopbackMultiaddr(addr multiaddr.Multiaddr) bool {
	for _, proto := range []int{multiaddr.P_IP4, multiaddr.P_IP6} {
		value, err := addr.ValueForProtocol(proto)
		if err != nil {
			continue
		}
		ip := net.ParseIP(value)
		return ip != nil && ip.IsLoopback()
	}
	return false
}

// PublishDHTIdentityNow refreshes this node's app identity provider record in
// the libp2p DHT when DHT is enabled.
func (n *Node) PublishDHTIdentityNow(ctx context.Context) {
	n.mu.RLock()
	dc := n.dhtClient
	n.mu.RUnlock()
	if dc != nil {
		log.Info("libp2p DHT identity publish requested")
		go dc.PublishNow(ctx)
	}
}

func (n *Node) NodeID() string { return n.PeerID.String() }

func (n *Node) RelayMask() byte {
	n.mu.RLock()
	defer n.mu.RUnlock()
	// Test nodes set testRelayMask directly to bypass relay connection check
	if n.testRelayMask != 0 {
		return n.testRelayMask
	}
	if !n.relayEnabled() {
		return 0
	}
	var mask byte
	for i, relayInfo := range n.relayInfos {
		if i >= 8 {
			break
		}
		if n.Host.Network().Connectedness(relayInfo.ID) == network.Connected {
			mask |= 1 << uint(i)
		}
	}
	return mask
}

func (n *Node) RelayAddrs() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if !n.relayEnabled() {
		return nil
	}
	out := make([]string, len(n.relayAddrs))
	for i, a := range n.relayAddrs {
		out[i] = a.String()
	}
	return out
}

func (n *Node) OnAddrsChange(fn func([]string)) {
	n.mu.Lock()
	n.onAddrsChange = fn
	n.mu.Unlock()
}

func (n *Node) SetTunnelHandler(fn func(network.Stream)) {
	n.Host.SetStreamHandler(ProtocolTunnel, fn)
}

func (n *Node) SetPairingHandler(fn func(network.Stream)) {
	n.Host.SetStreamHandler(ProtocolPairing, fn)
}

func (n *Node) ConnTypeFor(peerID string) ConnType {
	pid, err := peer.Decode(peerID)
	if err != nil {
		return ConnUnknown
	}
	for _, conn := range n.Host.Network().ConnsToPeer(pid) {
		if !strings.Contains(conn.RemoteMultiaddr().String(), "p2p-circuit") {
			return ConnDirect
		}
	}
	if len(n.Host.Network().ConnsToPeer(pid)) > 0 {
		return ConnRelayed
	}
	return ConnUnknown
}

func (n *Node) OpenTunnel(ctx context.Context, peerID string, relayAddrs []string) (network.Stream, error) {
	info, err := n.buildAddrInfo(peerID, relayAddrs)
	if err != nil {
		return nil, err
	}
	if err := n.Host.Connect(ctx, info); err != nil {
		return nil, logger.Wrap("connect to peer", err)
	}
	ct := n.ConnTypeFor(peerID)
	log.Info("tunnel stream opened", "peer", short(peerID), "conn_type", ct)
	return n.Host.NewStream(ctx, info.ID, ProtocolTunnel)
}

func (n *Node) OpenPairing(ctx context.Context, peerID string, relayAddrs []string) (network.Stream, error) {
	info, err := n.buildAddrInfo(peerID, relayAddrs)
	if err != nil {
		return nil, err
	}
	if err := n.Host.Connect(ctx, info); err != nil {
		return nil, logger.Wrap("connect for pairing", err)
	}
	log.Debug("pairing stream opened", "peer", short(peerID))
	return n.Host.NewStream(ctx, info.ID, ProtocolPairing)
}

func (n *Node) Close() error {
	log.Info("node shutting down", "peer_id", n.PeerID.String())
	n.mu.Lock()
	if n.relayCancel != nil {
		n.relayCancel()
	}
	if n.dhtCancel != nil {
		n.dhtCancel()
	}
	dc := n.dhtClient
	n.dhtClient = nil
	n.mu.Unlock()
	if dc != nil {
		_ = dc.Close()
	}
	return n.Host.Close()
}

// --- DCUtR event notifier ---

type dcutrNotifier struct{ n *Node }
type node = Node

func (d *dcutrNotifier) Connected(_ network.Network, conn network.Conn) {
	addr := conn.RemoteMultiaddr().String()
	pid := conn.RemotePeer().String()
	if strings.Contains(addr, "p2p-circuit") {
		log.Info("relay connection established, attempting hole punch",
			"peer", short(pid), "via", "relay")
	} else {
		log.Info("direct connection established (hole punch succeeded)",
			"peer", short(pid), "addr", addr)
	}
}

func (d *dcutrNotifier) Disconnected(_ network.Network, conn network.Conn) {
	addr := conn.RemoteMultiaddr().String()
	pid := conn.RemotePeer().String()
	if strings.Contains(addr, "p2p-circuit") {
		log.Debug("relay connection closed", "peer", short(pid))
	} else {
		log.Debug("direct connection closed", "peer", short(pid))
	}
}

func (d *dcutrNotifier) Listen(_ network.Network, _ multiaddr.Multiaddr)      {}
func (d *dcutrNotifier) ListenClose(_ network.Network, _ multiaddr.Multiaddr) {}

// --- keepalive + reservation loops ---

func (n *Node) keepAliveLoop(ctx context.Context) {
	ticker := time.NewTicker(keepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			n.pingRelays(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (n *Node) pingRelays(ctx context.Context) {
	n.mu.RLock()
	infos := n.relayInfos
	n.mu.RUnlock()

	for _, info := range infos {
		if n.Host.Network().Connectedness(info.ID) != network.Connected {
			log.Warn("relay disconnected, reconnecting", "relay", short(info.ID.String()))
			go n.reconnectWithBackoff(ctx)
			return
		}
	}
	log.Debug("relay keepalive ok", "relays", len(infos))
}

func (n *Node) reconnectWithBackoff(ctx context.Context) {
	backoff := reconnectBackoff
	attempt := 0
	for {
		attempt++
		// After a few static-relay failures, ask the DHT for additional candidates.
		if attempt > 3 {
			n.addDHTRelays()
		}
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := n.reserveAll(rctx)
		cancel()

		if err == nil && len(n.RelayAddrs()) > 0 {
			n.setRelayError(nil)
			log.Info("relay reconnected", "attempts", attempt)
			n.fireAddrsChange()
			return
		}
		log.Warn("relay reconnect failed, retrying",
			"attempt", attempt, "backoff", backoff, "err", err)
		select {
		case <-time.After(backoff):
			if backoff < reconnectMaxWait {
				backoff *= 2
			}
		case <-ctx.Done():
			return
		}
	}
}

// addDHTRelays queries the DHT routing table for peers that advertise
// circuit relay v2 and appends any new ones to relayInfos.
// Called from reconnectWithBackoff after the static list is exhausted.
func (n *Node) addDHTRelays() {
	n.mu.RLock()
	dc := n.dhtClient
	n.mu.RUnlock()
	if dc == nil || dc.RoutingTableSize() == 0 {
		return
	}
	candidates := dc.RelayPeers()
	if len(candidates) == 0 {
		log.Debug("DHT relay fallback: no relay-capable peers in routing table yet")
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	added := 0
	for _, info := range candidates {
		if n.hasRelayInfo(info.ID) {
			continue
		}
		n.relayInfos = append(n.relayInfos, info)
		n.relayRefusedUntil = append(n.relayRefusedUntil, time.Time{})
		added++
	}
	if added > 0 {
		log.Info("DHT relay fallback: added candidates", "count", added)
	}
}

// hasRelayInfo reports whether info.ID is already in relayInfos.
// Caller must hold n.mu.
func (n *Node) hasRelayInfo(id peer.ID) bool {
	for _, ri := range n.relayInfos {
		if ri.ID == id {
			return true
		}
	}
	return false
}

func (n *Node) reservationRefreshLoop(ctx context.Context) {
	ticker := time.NewTicker(reservationRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			if err := n.reserveAll(rctx); err != nil {
				n.setRelayError(err)
				log.Warn("reservation refresh failed", "err", err)
			} else {
				n.setRelayError(nil)
				log.Debug("relay reservation refreshed", "addrs", len(n.relayAddrs))
				n.fireAddrsChange()
			}
			cancel()
		case <-ctx.Done():
			return
		}
	}
}

func (n *Node) reserveAll(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.relayAddrs = nil
	started := time.Now()
	log.Info("libp2p relay reservation started", "relays", len(n.relayInfos))

	type result struct {
		addrs []multiaddr.Multiaddr
		err   error
	}

	// Attempt all relays in parallel with a short per-relay timeout.
	// This prevents one unresponsive relay from blocking the others.
	const perRelayTimeout = 8 * time.Second
	results := make([]result, len(n.relayInfos))
	var wg sync.WaitGroup

	for i, relayInfo := range n.relayInfos {
		// Skip relays that explicitly refused us recently — back off for 30 min
		// rather than hammering them on the normal reconnect schedule.
		if !n.relayRefusedUntil[i].IsZero() && time.Now().Before(n.relayRefusedUntil[i]) {
			log.Debug("relay skipped (refused cooloff)", "relay", short(relayInfo.ID.String()),
				"retry_in", time.Until(n.relayRefusedUntil[i]).Round(time.Second))
			continue
		}

		wg.Add(1)
		go func(idx int, ri peer.AddrInfo) {
			defer wg.Done()
			rctx, cancel := context.WithTimeout(ctx, perRelayTimeout)
			defer cancel()

			if err := n.Host.Connect(rctx, ri); err != nil {
				log.Warn("libp2p relay connect failed", "relay", short(ri.ID.String()), "err", err)
				results[idx] = result{err: err}
				return
			}
			log.Info("libp2p relay connected", "relay", short(ri.ID.String()))
			reservation, err := client.Reserve(rctx, n.Host, ri)
			if err != nil {
				if strings.Contains(err.Error(), "RESERVATION_REFUSED") {
					// Explicit refusal — cool off for 30 min, don't spam.
					n.relayRefusedUntil[idx] = time.Now().Add(30 * time.Minute)
					log.Warn("relay refused reservation — cooling off 30m",
						"relay", short(ri.ID.String()))
				} else {
					log.Warn("libp2p relay reserve failed", "relay", short(ri.ID.String()), "err", err)
				}
				results[idx] = result{err: err}
				return
			}
			n.relayRefusedUntil[idx] = time.Time{} // clear any previous cooloff on success
			var addrs []multiaddr.Multiaddr
			for _, addr := range reservation.Addrs {
				circ, err := buildCircuitAddr(addr, ri.ID, n.PeerID)
				if err != nil {
					continue
				}
				addrs = append(addrs, circ)
				log.Info("libp2p relay slot reserved", "relay", short(ri.ID.String()), "addr", circ.String())
			}
			results[idx] = result{addrs: addrs}
		}(i, relayInfo)
	}
	wg.Wait()

	var lastErr error
	failed := 0
	for _, r := range results {
		if r.err != nil {
			failed++
			lastErr = r.err
			continue
		}
		n.relayAddrs = append(n.relayAddrs, r.addrs...)
	}

	if len(n.relayAddrs) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("all relay candidates skipped")
		}
		err := fmt.Errorf("all relay reservations failed (%d/%d relays failed; public libp2p relays are best-effort, use a custom/self-hosted relay for reliable relay mode): %w", failed, len(n.relayInfos), lastErr)
		log.Warn("libp2p relay reservation failed", "relays", len(n.relayInfos), "failed", failed, "duration", time.Since(started).String(), "err", err)
		return err
	}
	n.lastRelayErr = ""
	log.Info("libp2p relay reservations active", "count", len(n.relayAddrs), "duration", time.Since(started).String())
	return nil
}

func (n *Node) setRelayError(err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err == nil {
		n.lastRelayErr = ""
		return
	}
	n.lastRelayErr = err.Error()
}

func (n *Node) setDHTError(err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err == nil {
		n.lastDHTErr = ""
		return
	}
	n.lastDHTErr = err.Error()
}

func (n *Node) fireAddrsChange() {
	n.mu.RLock()
	cb := n.onAddrsChange
	addrs := make([]string, len(n.relayAddrs))
	for i, a := range n.relayAddrs {
		addrs[i] = a.String()
	}
	n.mu.RUnlock()
	if cb != nil {
		cb(addrs)
	}
}

func (n *Node) resolveRelays() ([]peer.AddrInfo, error) {
	var rawAddrs []string
	switch n.cfg.Relay.Mode {
	case "", "disabled":
		log.Info("relay disabled by config")
		return nil, nil
	case "custom":
		rawAddrs = n.cfg.Relay.Servers
		log.Info("relay: custom servers only", "count", len(rawAddrs))
	case "mixed":
		rawAddrs = append(append([]string{}, PublicRelays...), n.cfg.Relay.Servers...)
		log.Info("relay: public + custom servers", "total", len(rawAddrs))
	default: // "public"
		rawAddrs = PublicRelays
	}
	log.Info("libp2p relay resolving configured relays", "mode", n.cfg.Relay.Mode, "raw_count", len(rawAddrs))
	var infos []peer.AddrInfo
	byPeer := make(map[peer.ID]int)
	for _, raw := range rawAddrs {
		ma, err := multiaddr.NewMultiaddr(raw)
		if err != nil {
			log.Warn("invalid relay addr, skipping", "addr", raw, "err", err)
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			log.Warn("invalid relay p2p addr, skipping", "addr", raw, "err", err)
			continue
		}
		info.Addrs = filterNonLoopbackMultiaddrs(info.Addrs)
		if len(info.Addrs) == 0 {
			log.Warn("loopback relay addr skipped", "addr", raw, "reason", "relay must be reachable from other machines")
			continue
		}
		if idx, ok := byPeer[info.ID]; ok {
			infos[idx].Addrs = appendUniqueMultiaddrs(infos[idx].Addrs, info.Addrs)
			continue
		}
		byPeer[info.ID] = len(infos)
		infos = append(infos, *info)
	}
	if len(infos) == 0 {
		log.Warn("libp2p relay resolving configured relays failed", "mode", n.cfg.Relay.Mode, "raw_count", len(rawAddrs), "err", "no valid relay addresses configured")
		return nil, logger.Wrapf("no valid relay addresses configured")
	}
	log.Info("libp2p relay resolving configured relays succeeded", "mode", n.cfg.Relay.Mode, "raw_count", len(rawAddrs), "valid_count", len(infos))
	return infos, nil
}

func filterNonLoopbackMultiaddrs(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	out := make([]multiaddr.Multiaddr, 0, len(addrs))
	for _, addr := range addrs {
		if isLoopbackMultiaddr(addr) {
			continue
		}
		out = append(out, addr)
	}
	return out
}

func appendUniqueMultiaddrs(dst, src []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	seen := make(map[string]struct{}, len(dst)+len(src))
	for _, addr := range dst {
		seen[addr.String()] = struct{}{}
	}
	for _, addr := range src {
		key := addr.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		dst = append(dst, addr)
	}
	return dst
}

func (n *Node) relayEnabled() bool {
	return n.cfg != nil &&
		n.cfg.ActiveNetworkBackend() == "libp2p_relay" &&
		n.cfg.Relay.Mode != "" &&
		n.cfg.Relay.Mode != "disabled"
}

func (n *Node) dhtEnabled() bool {
	return n.cfg != nil &&
		n.cfg.DHT.Mode != "" &&
		n.cfg.DHT.Mode != "disabled"
}

func (n *Node) libp2pActive() bool {
	if n == nil || n.cfg == nil {
		return false
	}
	if n.relayEnabled() || n.dhtEnabled() {
		return true
	}
	return false
}

func (n *Node) buildAddrInfo(peerID string, relayAddrs []string) (peer.AddrInfo, error) {
	pid, err := peer.Decode(peerID)
	if err != nil {
		return peer.AddrInfo{}, logger.Wrap("invalid peer id", err)
	}
	var addrs []multiaddr.Multiaddr
	for _, raw := range relayAddrs {
		ma, err := multiaddr.NewMultiaddr(raw)
		if err != nil {
			continue
		}
		addrs = append(addrs, ma)
	}
	return peer.AddrInfo{ID: pid, Addrs: addrs}, nil
}

func buildCircuitAddr(relayTransportAddr multiaddr.Multiaddr, relayID, targetID peer.ID) (multiaddr.Multiaddr, error) {
	relayP2P, _ := multiaddr.NewComponent("p2p", relayID.String())
	circuit, _ := multiaddr.NewComponent("p2p-circuit", "")
	target, _ := multiaddr.NewComponent("p2p", targetID.String())
	return multiaddr.Join(relayTransportAddr, relayP2P, circuit, target), nil
}

// short returns the first 12 chars of a peer ID for log readability.
func short(id string) string {
	if len(id) > 12 {
		return id[:12] + "…"
	}
	return id
}

type allowlistGater struct{ allowed []string }

func (g *allowlistGater) InterceptPeerDial(p peer.ID) bool { return g.isAllowed(p) }
func (g *allowlistGater) InterceptAddrDial(p peer.ID, _ multiaddr.Multiaddr) bool {
	return g.isAllowed(p)
}
func (g *allowlistGater) InterceptAccept(_ network.ConnMultiaddrs) bool { return true }
func (g *allowlistGater) InterceptSecured(_ network.Direction, p peer.ID, _ network.ConnMultiaddrs) bool {
	return g.isAllowed(p)
}
func (g *allowlistGater) InterceptUpgraded(_ network.Conn) (bool, control.DisconnectReason) {
	return true, 0
}
func (g *allowlistGater) isAllowed(p peer.ID) bool {
	pid := p.String()
	for _, a := range g.allowed {
		if a == pid {
			return true
		}
	}
	return false
}
