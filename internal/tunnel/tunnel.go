// Package tunnel handles the RDP data channel.
//
// Protocol flow (after pairing authentication):
//
//	CLIENT                              HOST
//	│                                    │
//	├─ OpenTunnel() ───────────────────► │  (libp2p stream)
//	│                                    │
//	│──── CONNECT {token, target} ──────►│  present session token + loopback target
//	│◄─── 200 TunnelReady  ──────────────│  token OK → switch to raw TCP
//	│◄─── TunnelError {reason}      ─────│  token invalid → close
//	│                                    │
//	│════════════ raw RDP bytes ═════════│  mstsc ↔ localhost:3389
package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/rdpanywhere/rdpanywhere/internal/config"
	"github.com/rdpanywhere/rdpanywhere/internal/logger"
	"github.com/rdpanywhere/rdpanywhere/internal/netbackend"
	"github.com/rdpanywhere/rdpanywhere/internal/node"
	"github.com/rdpanywhere/rdpanywhere/internal/presence"
	"github.com/rdpanywhere/rdpanywhere/internal/protocol"
)

var tlog = logger.For(logger.CompTunnel)

const tunnelResponseTimeout = 15 * time.Second
const bridgeProgressEvery = 4 * 1024 * 1024

// Manager handles RDP tunnels on both host and client sides.
type Manager struct {
	mu       sync.Mutex
	n        *node.Node
	cfg      *config.Config
	presence *presence.Manager
	sessions *protocol.SessionStore // shared with pairing.Manager
	backends *netbackend.Registry
}

// LocalProxy is a running local listener that opens a fresh remote tunnel stream
// for each accepted client connection. Close stops accepting new clients and
// closes any client sockets currently bridged through the proxy.
type LocalProxy struct {
	Addr string

	ln     net.Listener
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

func newLocalProxy(addr string, ln net.Listener) *LocalProxy {
	return &LocalProxy{Addr: addr, ln: ln, conns: make(map[net.Conn]struct{})}
}

func (p *LocalProxy) track(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		conn.Close()
		return
	}
	p.conns[conn] = struct{}{}
}

func (p *LocalProxy) untrack(conn net.Conn) {
	p.mu.Lock()
	delete(p.conns, conn)
	p.mu.Unlock()
}

func (p *LocalProxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	var conns []net.Conn
	for conn := range p.conns {
		conns = append(conns, conn)
	}
	p.conns = make(map[net.Conn]struct{})
	p.mu.Unlock()

	err := p.ln.Close()
	for _, conn := range conns {
		conn.Close()
	}
	return err
}

func (p *LocalProxy) CloseConnections() {
	p.mu.Lock()
	var conns []net.Conn
	for conn := range p.conns {
		conns = append(conns, conn)
	}
	p.conns = make(map[net.Conn]struct{})
	p.mu.Unlock()
	for _, conn := range conns {
		conn.Close()
	}
}

func New(n *node.Node, cfg *config.Config, pres *presence.Manager, sessions *protocol.SessionStore) *Manager {
	m := &Manager{n: n, cfg: cfg, presence: pres, sessions: sessions, backends: netbackend.NewRegistry()}
	m.backends.Register(netbackend.NewLibp2p(n), netbackend.BackendLibp2pDHT)
	n.SetTunnelHandler(m.handleIncoming)
	return m
}

// SetIroh injects the go-iroh backend.
func (m *Manager) SetIroh(i interface {
	TicketContext(ctx context.Context) (string, error)
	OpenPairing(ctx context.Context, ticket string) (io.ReadWriteCloser, error)
	OpenTunnel(ctx context.Context, ticket string) (io.ReadWriteCloser, error)
}) {
	if i == nil {
		m.backends.Unregister(netbackend.BackendIroh)
		return
	}
	m.backends.Register(netbackend.NewIroh(i))
}

// SetBitTorrentQUIC injects the direct QUIC transport used by BitTorrent DHT.
func (m *Manager) SetBitTorrentQUIC(q interface {
	OpenPairing(ctx context.Context, endpoint string) (io.ReadWriteCloser, error)
	OpenTunnel(ctx context.Context, endpoint string) (io.ReadWriteCloser, error)
}) {
	if q == nil {
		m.backends.Unregister(netbackend.BackendBitTorrentDHT)
		return
	}
	m.backends.Register(netbackend.NewDirectQUIC(q))
}

// --- HOST SIDE ---

// handleIncoming is called when a client opens a tunnel stream.
// Runs the TunnelHello / TunnelReady handshake, then proxies raw RDP data.
func (m *Manager) handleIncoming(s network.Stream) {
	m.handleIncomingConn(s, s.Conn().RemotePeer().String(), func() { s.Reset() })
}

// HandleIrohIncoming runs the tunnel protocol over an iroh stream.
func (m *Manager) HandleIrohIncoming(conn io.ReadWriteCloser, remotePeerID string) {
	m.handleIncomingConn(conn, remotePeerID, func() { conn.Close() })
}

// HandleQUICIncoming runs the tunnel protocol over a direct QUIC stream.
func (m *Manager) HandleQUICIncoming(conn io.ReadWriteCloser, remotePeerID string) {
	m.handleIncomingConn(conn, remotePeerID, func() { conn.Close() })
}

func (m *Manager) handleIncomingConn(s io.ReadWriteCloser, remote string, reset func()) {

	// --- handshake ---
	msgType, payload, err := protocol.ReadFrame(s)
	if err != nil {
		tlog.Error("read tunnel hello", "peer", remote[:12], "err", err)
		reset()
		return
	}
	if msgType == protocol.MsgTunnelPing {
		var ping protocol.TunnelPing
		if err := protocol.Decode(payload, &ping); err != nil {
			tlog.Warn("decode tunnel ping failed", "peer", remote[:12], "err", err)
			reset()
			return
		}
		tlog.Debug("tunnel ping received", "peer", remote[:12], "time_unix", ping.TimeUnix)
		if err := protocol.WriteFrame(s, protocol.MsgTunnelPong, protocol.TunnelPong{TimeUnix: time.Now().Unix()}); err != nil {
			tlog.Warn("write tunnel pong failed", "peer", remote[:12], "err", err)
			reset()
		}
		return
	}
	if msgType != protocol.MsgTunnelHello {
		tlog.Warn("expected TunnelHello", "peer", remote[:12], "got", fmt.Sprintf("0x%02x", msgType))
		reset()
		return
	}
	var hello protocol.TunnelHello
	if err := protocol.Decode(payload, &hello); err != nil {
		tlog.Error("decode tunnel hello", "err", err)
		reset()
		return
	}
	if hello.Version > protocol.Version {
		tlog.Warn("unsupported protocol version", "peer", remote[:12], "version", hello.Version)
		protocol.WriteFrame(s, protocol.MsgTunnelError, protocol.TunnelError{
			Reason: fmt.Sprintf("unsupported protocol version %d", hello.Version),
		})
		s.Close()
		return
	}
	if hello.Method != "" && !strings.EqualFold(hello.Method, "CONNECT") {
		tlog.Warn("unsupported tunnel method", "peer", remote[:12], "method", hello.Method, "stream_id", hello.StreamID)
		protocol.WriteFrame(s, protocol.MsgTunnelError, protocol.TunnelError{
			Reason: fmt.Sprintf("unsupported tunnel method %q", hello.Method),
		})
		s.Close()
		return
	}

	m.mu.Lock()
	grant, err := m.sessions.VerifyGrant(hello.SessionToken)
	m.mu.Unlock()
	if err != nil {
		tlog.Warn("session token rejected", "peer", remote[:12], "err", err)
		protocol.WriteFrame(s, protocol.MsgTunnelError, protocol.TunnelError{Reason: err.Error()})
		s.Close()
		return
	}
	if grant.PeerID != remote {
		tlog.Warn("session token peer mismatch",
			"issued_for", grant.PeerID[:12], "used_by", remote[:12])
		protocol.WriteFrame(s, protocol.MsgTunnelError, protocol.TunnelError{
			Reason: "session token was not issued for this peer",
		})
		s.Close()
		return
	}
	grantedPort := grant.TargetPort
	if grantedPort <= 0 {
		grantedPort = m.configuredTargetPort()
	}
	if hello.TargetPort > 0 && hello.TargetPort != grantedPort {
		tlog.Warn("CONNECT target port rejected",
			"peer", remote[:12],
			"requested_port", hello.TargetPort,
			"granted_port", grantedPort,
			"stream_id", hello.StreamID)
		protocol.WriteFrame(s, protocol.MsgTunnelError, protocol.TunnelError{
			Reason: fmt.Sprintf("target port %d was not granted by the invite", hello.TargetPort),
		})
		s.Close()
		return
	}
	targetAddr := m.targetAddrForPort(grantedPort)
	if strings.TrimSpace(hello.TargetHost) != "" && !isLoopbackHost(hello.TargetHost) {
		tlog.Warn("non-loopback CONNECT target rejected",
			"peer", remote[:12],
			"target_host", hello.TargetHost,
			"target_port", hello.TargetPort,
			"stream_id", hello.StreamID)
		protocol.WriteFrame(s, protocol.MsgTunnelError, protocol.TunnelError{
			Reason: "only loopback targets are allowed",
		})
		s.Close()
		return
	}
	tlog.Info("CONNECT request accepted",
		"peer", remote[:12],
		"target", targetAddr,
		"target_host", connectTargetHost(hello.TargetHost),
		"requested_port", hello.TargetPort,
		"granted_port", grantedPort,
		"stream_id", hello.StreamID)

	if err := protocol.WriteFrame(s, protocol.MsgTunnelReady, protocol.TunnelReady{
		HostLabel: m.cfg.Node.Label,
		Status:    200,
		Message:   "Connection Established",
	}); err != nil {
		tlog.Error("write TunnelReady", "err", err)
		reset()
		return
	}
	tlog.Info("CONNECT response sent",
		"peer", remote[:12],
		"status", 200,
		"target", targetAddr,
		"target_port", grantedPort,
		"stream_id", hello.StreamID)

	tlog.Info("data channel open", "peer", remote[:12], "target", targetAddr, "stream_id", hello.StreamID)
	m.proxyToService(s, remote, targetAddr, hello.StreamID)
}

// proxyToService dials the local service (RDP/VNC/SSH) and bridges the stream.
func (m *Manager) proxyToService(s io.ReadWriteCloser, remote string, targetAddr string, streamID string) {
	targetHost, targetPort := splitTargetAddr(targetAddr)
	tlog.Info("connecting to local service",
		"peer", remote[:12],
		"target", targetAddr,
		"target_host", targetHost,
		"target_port", targetPort,
		"stream_id", streamID)
	svcConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		tlog.Error("local service unreachable",
			"addr", targetAddr,
			"target_port", targetPort,
			"peer", remote[:12],
			"stream_id", streamID,
			"err", err)
		s.Close()
		return
	}
	tuneTCPConn(svcConn)
	tlog.Info("local service connected",
		"peer", remote[:12],
		"target", targetAddr,
		"target_port", targetPort,
		"local_addr", svcConn.LocalAddr().String(),
		"remote_addr", svcConn.RemoteAddr().String(),
		"stream_id", streamID)
	tlog.Info("bridging stream to local service",
		"peer", remote[:12], "target", targetAddr, "stream_id", streamID)
	bridgeLogged("host", remote[:12], streamID, targetAddr, s, svcConn, "service_to_remote", "remote_to_service")
	tlog.Info("data channel closed", "peer", remote[:12], "target_port", targetPort, "stream_id", streamID)
}

func (m *Manager) targetAddrForPort(port int) string {
	if port > 0 && port <= 65535 {
		return net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port))
	}
	if m.cfg != nil && strings.TrimSpace(m.cfg.RDP.TargetAddr) != "" {
		return m.cfg.RDP.TargetAddr
	}
	return "127.0.0.1:3389"
}

func (m *Manager) configuredTargetPort() int {
	if m != nil && m.cfg != nil {
		if target := strings.TrimSpace(m.cfg.RDP.TargetAddr); target != "" {
			if idx := strings.LastIndex(target, ":"); idx >= 0 && idx < len(target)-1 {
				if parsed, err := strconv.Atoi(target[idx+1:]); err == nil && parsed > 0 && parsed <= 65535 {
					return parsed
				}
			}
		}
	}
	return 3389
}

func connectTargetHost(host string) string {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return "127.0.0.1"
	}
	return host
}

func isLoopbackHost(host string) bool {
	host = connectTargetHost(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// --- CLIENT SIDE ---

// Connect opens a tunnel to a remote peer.
// targetPort: the port on the HOST side to connect to (3389, 5900, 22, etc.)
// The host's tunnel handler will forward to that port.
func (m *Manager) Connect(
	ctx context.Context,
	peerID string,
	relayAddrs []string,
	sessionToken []byte,
	targetPort int,
) (localAddr string, err error) {
	proxy, err := m.ConnectSession(ctx, peerID, relayAddrs, sessionToken, targetPort)
	if err != nil {
		return "", err
	}
	return proxy.Addr, nil
}

func (m *Manager) ConnectSession(
	ctx context.Context,
	peerID string,
	relayAddrs []string,
	sessionToken []byte,
	targetPort int,
) (*LocalProxy, error) {
	return m.connectStream(ctx, peerID, relayAddrs, "", sessionToken, targetPort)
}

// ConnectIroh opens a tunnel to a remote peer via an iroh endpoint ticket.
func (m *Manager) ConnectIroh(
	ctx context.Context,
	peerID string,
	ticket string,
	sessionToken []byte,
	targetPort int,
) (localAddr string, err error) {
	proxy, err := m.ConnectIrohSession(ctx, peerID, ticket, sessionToken, targetPort)
	if err != nil {
		return "", err
	}
	return proxy.Addr, nil
}

func (m *Manager) ConnectIrohSession(
	ctx context.Context,
	peerID string,
	ticket string,
	sessionToken []byte,
	targetPort int,
) (*LocalProxy, error) {
	return m.connectStream(ctx, peerID, nil, ticket, sessionToken, targetPort)
}

// ConnectBitTorrentQUIC opens a tunnel via a BitTorrent DHT-discovered QUIC endpoint.
func (m *Manager) ConnectBitTorrentQUIC(
	ctx context.Context,
	peerID string,
	endpoint string,
	sessionToken []byte,
	targetPort int,
) (localAddr string, err error) {
	proxy, err := m.ConnectBitTorrentQUICSession(ctx, peerID, endpoint, sessionToken, targetPort)
	if err != nil {
		return "", err
	}
	return proxy.Addr, nil
}

func (m *Manager) ConnectBitTorrentQUICSession(
	ctx context.Context,
	peerID string,
	endpoint string,
	sessionToken []byte,
	targetPort int,
) (*LocalProxy, error) {
	return m.connectStream(ctx, peerID, nil, "quic:"+endpoint, sessionToken, targetPort)
}

func (m *Manager) connectStream(
	ctx context.Context,
	peerID string,
	relayAddrs []string,
	transportEndpoint string,
	sessionToken []byte,
	targetPort int,
) (*LocalProxy, error) {
	// If the preferred port is already in use, fall back to a free local port
	// so multiple active app sessions can coexist.
	ln, err := listenLocalTunnel(m.cfg.RDP.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("local listen %s: %w", normalizeListenAddr(m.cfg.RDP.ListenAddr), err)
	}

	localAddr := ln.Addr().String()
	proxy := newLocalProxy(localAddr, ln)
	tlog.Info("local proxy started", "addr", localAddr, "peer", peerID[:12])

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				tlog.Info("local proxy stopped", "addr", localAddr, "peer", peerID[:12], "err", err)
				return
			}
			proxy.track(conn)
			tlog.Info("RDP client connected",
				"addr", localAddr,
				"proxy_addr", conn.LocalAddr().String(),
				"client_addr", conn.RemoteAddr().String(),
				"target_port", targetPort)
			tuneTCPConn(conn)
			go func(conn net.Conn) {
				defer proxy.untrack(conn)
				openCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				streamID := newStreamID()
				tlog.Info("opening tunnel stream for local client",
					"peer", peerID[:12],
					"stream_id", streamID,
					"proxy_addr", conn.LocalAddr().String(),
					"client_addr", conn.RemoteAddr().String(),
					"target_port", targetPort)
				openStarted := time.Now()
				stream, err := m.openDataStream(openCtx, peerID, relayAddrs, transportEndpoint, sessionToken, targetPort, streamID)
				if err != nil {
					tlog.Warn("open tunnel stream for local client failed",
						"peer", peerID[:12],
						"stream_id", streamID,
						"duration", time.Since(openStarted).String(),
						"proxy_addr", conn.LocalAddr().String(),
						"client_addr", conn.RemoteAddr().String(),
						"target_port", targetPort,
						"err", err)
					proxy.CloseConnections()
					conn.Close()
					return
				}
				tlog.Info("bridging local RDP client to tunnel",
					"peer", peerID[:12],
					"stream_id", streamID,
					"open_duration", time.Since(openStarted).String(),
					"proxy_addr", conn.LocalAddr().String(),
					"client_addr", conn.RemoteAddr().String(),
					"target_port", targetPort)
				if bridgeLogged("client", peerID[:12], streamID, "", conn, stream, "remote_to_local", "local_to_remote") {
					tlog.Warn("tunnel bridge failed, closing active local proxy connections",
						"peer", peerID[:12],
						"stream_id", streamID,
						"proxy_addr", conn.LocalAddr().String(),
						"target_port", targetPort)
					proxy.CloseConnections()
				}
				tlog.Info("local RDP connection ended",
					"peer", peerID[:12],
					"stream_id", streamID,
					"proxy_addr", conn.LocalAddr().String(),
					"client_addr", conn.RemoteAddr().String(),
					"target_port", targetPort)
			}(conn)
		}
	}()

	return proxy, nil
}

func (m *Manager) openDataStream(
	ctx context.Context,
	peerID string,
	relayAddrs []string,
	transportEndpoint string,
	sessionToken []byte,
	targetPort int,
	streamID string,
) (io.ReadWriteCloser, error) {
	var stream io.ReadWriteCloser
	var err error
	if strings.HasPrefix(transportEndpoint, "quic:") {
		endpoint := strings.TrimPrefix(transportEndpoint, "quic:")
		backend, getErr := m.backends.MustGet(netbackend.BackendBitTorrentDHT)
		if getErr != nil {
			return nil, getErr
		}
		tlog.Info("opening direct QUIC tunnel stream", "peer", peerID[:12], "stream_id", streamID, "target_port", targetPort)
		stream, err = backend.OpenTunnel(ctx, netbackend.Target{
			PeerID:       peerID,
			QUICEndpoint: endpoint,
		})
	} else if transportEndpoint != "" {
		backend, getErr := m.backends.MustGet(netbackend.BackendIroh)
		if getErr != nil {
			return nil, getErr
		}
		tlog.Info("opening iroh tunnel stream", "peer", peerID[:12], "stream_id", streamID, "target_port", targetPort)
		stream, err = backend.OpenTunnel(ctx, netbackend.Target{
			PeerID:     peerID,
			IrohTicket: transportEndpoint,
		})
	} else {
		backend, getErr := m.backends.MustGet(netbackend.BackendLibp2pRelay)
		if getErr != nil {
			return nil, getErr
		}
		tlog.Info("opening libp2p tunnel stream", "peer", peerID[:12], "stream_id", streamID, "target_port", targetPort)
		stream, err = backend.OpenTunnel(ctx, netbackend.Target{
			PeerID:     peerID,
			RelayAddrs: relayAddrs,
		})
	}
	if err != nil {
		return nil, fmt.Errorf("open tunnel stream: %w", err)
	}
	tlog.Info("remote tunnel stream opened", "peer", peerID[:12], "stream_id", streamID, "target_port", targetPort)

	// --- client-side handshake ---
	if err := protocol.WriteFrame(stream, protocol.MsgTunnelHello, protocol.TunnelHello{
		Version:      protocol.Version,
		Method:       "CONNECT",
		SessionToken: sessionToken,
		TargetHost:   "127.0.0.1",
		TargetPort:   targetPort,
		StreamID:     streamID,
	}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("send tunnel hello: %w", err)
	}

	clearDeadline := setReadDeadline(stream, time.Now().Add(tunnelResponseTimeout))
	msgType, payload, err := protocol.ReadFrame(stream)
	clearDeadline()
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("read tunnel response within %s: %w", tunnelResponseTimeout, err)
	}
	switch msgType {
	case protocol.MsgTunnelReady:
		var ready protocol.TunnelReady
		protocol.Decode(payload, &ready)
		tlog.Info("CONNECT response ready", "host", ready.HostLabel, "status", ready.Status, "message", ready.Message, "stream_id", streamID)

	case protocol.MsgTunnelError:
		var e protocol.TunnelError
		protocol.Decode(payload, &e)
		stream.Close()
		return nil, fmt.Errorf("host rejected tunnel: %s", e.Reason)

	default:
		stream.Close()
		return nil, fmt.Errorf("unexpected tunnel response type 0x%02x", msgType)
	}
	return stream, nil
}

func listenLocalTunnel(preferred string) (net.Listener, error) {
	addr := normalizeListenAddr(preferred)
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		return ln, nil
	}
	if !isAddrInUse(err) {
		return nil, err
	}

	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil || host == "" {
		host = "127.0.0.1"
	}
	fallback := net.JoinHostPort(host, "0")
	ln, fallbackErr := net.Listen("tcp", fallback)
	if fallbackErr != nil {
		return nil, fmt.Errorf("%w; dynamic fallback %s failed: %v", err, fallback, fallbackErr)
	}
	tlog.Warn("preferred local tunnel port busy, using dynamic port",
		"preferred", addr, "actual", ln.Addr().String())
	return ln, nil
}

func normalizeListenAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "127.0.0.1:0"
	}
	return addr
}

func loopbackClientAddr(addr string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || port == "" {
		return addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" || host == "::1" || host == "localhost" {
		return net.JoinHostPort("127.0.0.1", port)
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && ip.IsUnspecified() {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return net.JoinHostPort(host, port)
}

func isAddrInUse(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") ||
		strings.Contains(msg, "only one usage of each socket address")
}

// ConnectToPaired connects to a paired remote using live relay addrs from presence.
// sessionToken comes from a fresh pairing exchange on each connect.
func (m *Manager) ConnectToPaired(
	ctx context.Context,
	peerID string,
	sessionToken []byte,
) (string, error) {
	if m.presence == nil {
		return "", fmt.Errorf("presence manager unavailable")
	}
	addrs := m.presence.GetPeerAddrs(peerID)
	if len(addrs) == 0 {
		// Fallback: last stored addrs from config
		for _, r := range m.cfg.Remotes {
			if r.NodeID == peerID {
				addrs = r.RelayAddrs
				break
			}
		}
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("peer %s is offline or has no known relay addresses", peerID[:12])
	}
	// targetPort 0 = use the host's configured port (host decides, not client)
	return m.Connect(ctx, peerID, addrs, sessionToken, 0)
}

// LaunchResult is returned by LaunchRDP so callers know what happened.
type LaunchResult struct {
	Launched  bool   // true if an RDP client was started
	Client    string // "mstsc", "xfreerdp", "remmina", etc.
	LocalAddr string // the address the client is pointed at
	Error     string // non-empty if launch failed
}

// LaunchClient launches the appropriate client for the given protocol.
// protocol: "rdp" | "vnc" | "ssh" | "custom"
func LaunchClient(localAddr, protocol string) LaunchResult {
	var err error
	var clientName string

	switch protocol {
	case "vnc":
		err = launchVNC(localAddr)
		clientName = vncClientName()
	case "ssh":
		err = launchSSH(localAddr)
		clientName = "ssh"
	default: // "rdp" or anything else
		err = launchRDP(localAddr)
		clientName = rdpClientName()
	}

	if err != nil {
		return LaunchResult{
			Launched:  false,
			LocalAddr: localAddr,
			Error:     err.Error(),
		}
	}
	return LaunchResult{
		Launched:  true,
		LocalAddr: localAddr,
		Client:    clientName,
	}
}

// LaunchRDP is kept for backward compatibility.
func LaunchRDP(localAddr string) LaunchResult {
	return LaunchClient(localAddr, "rdp")
}

// bridge copies data bidirectionally between two ReadWriteClosers.
func bridge(a, b io.ReadWriteCloser) {
	bridgeLogged("", "", "", "", a, b, "b_to_a", "a_to_b")
}

func bridgeLogged(side, peer, streamID, targetAddr string, a, b io.ReadWriteCloser, bToA string, aToB string) bool {
	done := make(chan bool, 2)
	var teardownOnce sync.Once
	teardown := func(reason, direction string) {
		teardownOnce.Do(func() {
			logTunnelTeardown(side, peer, streamID, targetAddr, reason, direction)
			a.Close()
			b.Close()
		})
	}
	go func() {
		n, err := copyWithProgress(a, b, side, peer, streamID, targetAddr, bToA)
		logBridgeCopy(side, peer, streamID, targetAddr, bToA, n, err)
		failed := bridgeCopyFailed(err)
		if failed {
			teardown("copy_error", bToA)
		} else {
			teardown("peer_closed", bToA)
		}
		done <- failed
	}()
	go func() {
		n, err := copyWithProgress(b, a, side, peer, streamID, targetAddr, aToB)
		logBridgeCopy(side, peer, streamID, targetAddr, aToB, n, err)
		failed := bridgeCopyFailed(err)
		if failed {
			teardown("copy_error", aToB)
		} else {
			teardown("peer_closed", aToB)
		}
		done <- failed
	}()
	firstFailed := <-done
	secondFailed := <-done
	return firstFailed || secondFailed
}

func copyWithProgress(dst io.Writer, src io.Reader, side, peer, streamID, targetAddr, direction string) (int64, error) {
	if side != "" {
		logBridgeProgress("waiting for tunnel bytes", side, peer, streamID, targetAddr, direction, 0)
	}
	buf := make([]byte, 32*1024)
	var total int64
	var nextProgress int64 = bridgeProgressEvery
	first := true
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				total += int64(nw)
				if side != "" && first {
					logBridgeProgress("tunnel bytes started", side, peer, streamID, targetAddr, direction, total)
					first = false
				}
				if side != "" && total >= nextProgress {
					logBridgeProgress("tunnel bytes progressing", side, peer, streamID, targetAddr, direction, total)
					nextProgress += bridgeProgressEvery
				}
			}
			if ew != nil {
				return total, ew
			}
			if nr != nw {
				return total, io.ErrShortWrite
			}
		}
		if er != nil {
			return total, er
		}
	}
}

func logBridgeProgress(msg, side, peer, streamID, targetAddr, direction string, bytes int64) {
	args := []any{
		"side", side,
		"peer", peer,
		"stream_id", streamID,
		"direction", direction,
		"bytes", bytes,
	}
	if targetAddr != "" {
		_, targetPort := splitTargetAddr(targetAddr)
		args = append(args, "target", targetAddr, "target_port", targetPort)
	}
	tlog.Info(msg, args...)
}

func logTunnelTeardown(side, peer, streamID, targetAddr, reason, direction string) {
	if side == "" {
		return
	}
	args := []any{
		"side", side,
		"peer", peer,
		"stream_id", streamID,
		"reason", reason,
	}
	if direction != "" {
		args = append(args, "direction", direction)
	}
	if targetAddr != "" {
		_, targetPort := splitTargetAddr(targetAddr)
		args = append(args, "target", targetAddr, "target_port", targetPort)
	}
	tlog.Info("tearing down tunnel stream", args...)
}

func bridgeCopyFailed(err error) bool {
	return err != nil &&
		!errors.Is(err, io.EOF) &&
		!isUseOfClosedNetworkConnection(err) &&
		!isConnectionReset(err)
}

func logBridgeCopy(side, peer, streamID, targetAddr, direction string, bytes int64, err error) {
	if side == "" {
		return
	}
	args := []any{
		"side", side,
		"peer", peer,
		"stream_id", streamID,
		"direction", direction,
		"bytes", bytes,
	}
	if targetAddr != "" {
		_, targetPort := splitTargetAddr(targetAddr)
		args = append(args, "target", targetAddr, "target_port", targetPort)
	}
	if err != nil && !errors.Is(err, io.EOF) && !isUseOfClosedNetworkConnection(err) && !isConnectionReset(err) {
		tlog.Warn("tunnel copy ended with error", append(args, "err", err)...)
		return
	}
	msg := "tunnel copy ended"
	if side == "host" && direction == "remote_to_service" {
		msg = "data written to local service"
	} else if side == "host" && direction == "service_to_remote" {
		msg = "data read from local service"
	}
	if side == "host" && bytes == 0 {
		tlog.Warn("tunnel side closed before data transfer", args...)
		return
	}
	tlog.Info(msg, args...)
}

func isUseOfClosedNetworkConnection(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "use of closed network connection")
}

func isConnectionReset(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "forcibly closed by the remote host") ||
		strings.Contains(msg, "wsarecv")
}

func tuneTCPConn(conn net.Conn) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcp.SetNoDelay(true)
	_ = tcp.SetKeepAlive(true)
	_ = tcp.SetKeepAlivePeriod(30 * time.Second)
}

func closeWrite(v any) {
	if cw, ok := v.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func setReadDeadline(v any, deadline time.Time) func() {
	if rd, ok := v.(interface{ SetReadDeadline(time.Time) error }); ok {
		if err := rd.SetReadDeadline(deadline); err != nil {
			tlog.Debug("set read deadline failed", "err", err)
			return func() {}
		}
		return func() {
			if err := rd.SetReadDeadline(time.Time{}); err != nil {
				tlog.Debug("clear read deadline failed", "err", err)
			}
		}
	}
	return func() {}
}

func newStreamID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func splitTargetAddr(addr string) (string, string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, ""
	}
	return host, port
}
