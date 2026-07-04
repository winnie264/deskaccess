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
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/rdpanywhere/rdpanywhere/internal/btdht"
	"github.com/rdpanywhere/rdpanywhere/internal/config"
	"github.com/rdpanywhere/rdpanywhere/internal/logger"
	"github.com/rdpanywhere/rdpanywhere/internal/netbackend"
	"github.com/rdpanywhere/rdpanywhere/internal/node"
	"github.com/rdpanywhere/rdpanywhere/internal/presence"
	"github.com/rdpanywhere/rdpanywhere/internal/protocol"
)

var tlog = logger.For(logger.CompTunnel)

const tunnelResponseTimeout = 15 * time.Second
const defaultTunnelOpenTimeout = 30 * time.Second
const irohTunnelOpenTimeout = 2 * time.Minute
const bridgeSlowWriteThreshold = 2 * time.Second
const bridgeWriteBufferSize = 32 * 1024

var bridgeWriteTimeout = 30 * time.Second

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

	ln             net.Listener
	mu             sync.Mutex
	conns          map[net.Conn]struct{}
	streams        map[string]*proxyStream
	connectionPath string
	connectionAddr string
	closed         bool
	onClose        func()
	closeOnce      sync.Once
}

type proxyStream struct {
	client net.Conn
	remote io.Closer
}

func newLocalProxy(addr string, ln net.Listener) *LocalProxy {
	return &LocalProxy{Addr: addr, ln: ln, conns: make(map[net.Conn]struct{}), streams: make(map[string]*proxyStream)}
}

func (p *LocalProxy) SetConnectionPath(path string, addr string) {
	path = normalizeConnectionPath(path)
	if p == nil || path == "" || path == "unknown" {
		return
	}
	p.mu.Lock()
	p.connectionPath = path
	if strings.TrimSpace(addr) != "" {
		p.connectionAddr = strings.TrimSpace(addr)
	}
	p.mu.Unlock()
}

func (p *LocalProxy) ConnectionPath() string {
	if p == nil {
		return "unknown"
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.connectionPath == "" {
		return "unknown"
	}
	return p.connectionPath
}

func (p *LocalProxy) ConnectionAddr() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.connectionAddr
}

func (p *LocalProxy) SetOnClose(fn func()) {
	if p == nil {
		return
	}
	p.mu.Lock()
	closed := p.closed
	previous := p.onClose
	if previous == nil {
		p.onClose = fn
	} else if fn != nil {
		p.onClose = func() {
			previous()
			fn()
		}
	}
	p.mu.Unlock()
	if closed && fn != nil {
		fn()
	}
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

func (p *LocalProxy) trackStream(streamID string, client net.Conn, remote io.Closer) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		client.Close()
		if remote != nil {
			remote.Close()
		}
		return false
	}
	p.conns[client] = struct{}{}
	p.streams[streamID] = &proxyStream{client: client, remote: remote}
	return true
}

func (p *LocalProxy) untrackStream(streamID string, client net.Conn) {
	p.mu.Lock()
	delete(p.streams, streamID)
	delete(p.conns, client)
	p.mu.Unlock()
}

func (p *LocalProxy) CloseStream(streamID string) {
	p.mu.Lock()
	stream := p.streams[streamID]
	delete(p.streams, streamID)
	if stream != nil {
		delete(p.conns, stream.client)
	}
	p.mu.Unlock()
	if stream == nil {
		return
	}
	stream.client.Close()
	if stream.remote != nil {
		stream.remote.Close()
	}
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
	var streams []io.Closer
	for _, stream := range p.streams {
		if stream.remote != nil {
			streams = append(streams, stream.remote)
		}
	}
	p.conns = make(map[net.Conn]struct{})
	p.streams = make(map[string]*proxyStream)
	p.mu.Unlock()

	err := p.ln.Close()
	for _, conn := range conns {
		conn.Close()
	}
	for _, stream := range streams {
		stream.Close()
	}
	p.notifyClosed()
	return err
}

func (p *LocalProxy) notifyClosed() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() {
		p.mu.Lock()
		fn := p.onClose
		p.mu.Unlock()
		if fn != nil {
			fn()
		}
	})
}

func (p *LocalProxy) CloseConnections() {
	p.mu.Lock()
	var conns []net.Conn
	for conn := range p.conns {
		conns = append(conns, conn)
	}
	var streams []io.Closer
	for _, stream := range p.streams {
		if stream.remote != nil {
			streams = append(streams, stream.remote)
		}
	}
	p.conns = make(map[net.Conn]struct{})
	p.streams = make(map[string]*proxyStream)
	p.mu.Unlock()
	for _, conn := range conns {
		conn.Close()
	}
	for _, stream := range streams {
		stream.Close()
	}
}

func (p *LocalProxy) ActiveClients() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.conns)
}

func (p *LocalProxy) ActiveStreams() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.streams)
}

func New(n *node.Node, cfg *config.Config, pres *presence.Manager, sessions *protocol.SessionStore) *Manager {
	m := &Manager{n: n, cfg: cfg, presence: pres, sessions: sessions, backends: netbackend.NewRegistry()}
	if n.Libp2pRunning() {
		m.SetLibp2p(true)
	}
	return m
}

// SetLibp2p registers or unregisters the libp2p backend. The service calls
// this only after the libp2p backend lifecycle has been started.
func (m *Manager) SetLibp2p(enabled bool) {
	if enabled {
		m.backends.Register(netbackend.NewLibp2p(m.n), netbackend.BackendLibp2pDHT)
		m.n.SetTunnelHandler(m.handleIncoming)
		return
	}
	m.backends.Unregister(netbackend.BackendLibp2pRelay, netbackend.BackendLibp2pDHT)
}

// SetIroh injects the iroh sidecar backend.
func (m *Manager) SetIroh(i interface {
	TicketContext(ctx context.Context) (string, error)
	OpenPairing(ctx context.Context, ticket string) (io.ReadWriteCloser, error)
	OpenTunnel(ctx context.Context, ticket string) (io.ReadWriteCloser, error)
	CloseTunnel(peerID string, reason string) int
}) {
	if i == nil {
		m.backends.Unregister(netbackend.BackendIroh)
		return
	}
	m.backends.Register(netbackend.NewIrohSidecar(i))
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
	m.backends.Register(btdht.NewDirectQUICBackend(q))
}

// --- HOST SIDE ---

// handleIncoming is called when a client opens a tunnel stream.
// Runs the TunnelHello / TunnelReady handshake, then proxies raw RDP data.
func (m *Manager) handleIncoming(s network.Stream) {
	m.handleIncomingConn(s, s.Conn().RemotePeer().String(), netbackend.BackendLibp2pRelay, func() { s.Reset() })
}

// HandleIrohIncoming runs the tunnel protocol over an iroh stream.
func (m *Manager) HandleIrohIncoming(conn io.ReadWriteCloser, remotePeerID string) {
	m.handleIncomingConn(conn, remotePeerID, netbackend.BackendIroh, func() { conn.Close() })
}

// HandleQUICIncoming runs the tunnel protocol over a direct QUIC stream.
func (m *Manager) HandleQUICIncoming(conn io.ReadWriteCloser, remotePeerID string) {
	m.handleIncomingConn(conn, remotePeerID, netbackend.BackendBitTorrentDHT, func() { conn.Close() })
}

func (m *Manager) handleIncomingConn(s io.ReadWriteCloser, remote string, transportBackend string, reset func()) {

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
	requestPeerID, err := tunnelHelloNodeID(hello, remote, transportBackend)
	if err != nil {
		tlog.Warn("tunnel rejected because node id is invalid", "transport_peer", shortPeer(remote), "stream_id", hello.StreamID, "err", err)
		protocol.WriteFrame(s, protocol.MsgTunnelError, protocol.TunnelError{Reason: err.Error()})
		s.Close()
		return
	}
	if requestPeerID != remote {
		tlog.Info("tunnel mapped transport peer to DeskAccess node", "transport_peer", shortPeer(remote), "node_id", shortPeer(requestPeerID), "stream_id", hello.StreamID, "transport_backend", transportBackend)
	}

	m.mu.Lock()
	grant, err := m.sessions.VerifyGrant(hello.SessionToken)
	m.mu.Unlock()
	if err != nil {
		tlog.Warn("session token rejected",
			"audit_event", "tunnel_session_token_rejected",
			"peer", shortPeer(requestPeerID),
			"transport_peer", shortPeer(remote),
			"stream_id", hello.StreamID,
			"target_host", connectTargetHost(hello.TargetHost),
			"target_port", hello.TargetPort,
			"transport_backend", transportBackend,
			"err", err)
		protocol.WriteFrame(s, protocol.MsgTunnelError, protocol.TunnelError{Reason: err.Error()})
		s.Close()
		return
	}
	if grant.PeerID != requestPeerID {
		tlog.Warn("session token peer mismatch",
			"audit_event", "tunnel_session_token_rejected",
			"reason", "peer_mismatch",
			"issued_for", shortPeer(grant.PeerID),
			"used_by", shortPeer(requestPeerID),
			"transport_peer", shortPeer(remote),
			"stream_id", hello.StreamID,
			"transport_backend", transportBackend)
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
			"audit_event", "tunnel_session_token_rejected",
			"reason", "target_port_mismatch",
			"peer", shortPeer(requestPeerID),
			"transport_peer", shortPeer(remote),
			"requested_port", hello.TargetPort,
			"granted_port", grantedPort,
			"stream_id", hello.StreamID,
			"transport_backend", transportBackend)
		protocol.WriteFrame(s, protocol.MsgTunnelError, protocol.TunnelError{
			Reason: fmt.Sprintf("target port %d was not granted by the invite", hello.TargetPort),
		})
		s.Close()
		return
	}
	targetAddr := m.targetAddrForPort(grantedPort)
	if strings.TrimSpace(hello.TargetHost) != "" && !isLoopbackHost(hello.TargetHost) {
		tlog.Warn("non-loopback CONNECT target rejected",
			"audit_event", "tunnel_session_token_rejected",
			"reason", "non_loopback_target",
			"peer", shortPeer(requestPeerID),
			"transport_peer", shortPeer(remote),
			"target_host", hello.TargetHost,
			"target_port", hello.TargetPort,
			"stream_id", hello.StreamID,
			"transport_backend", transportBackend)
		protocol.WriteFrame(s, protocol.MsgTunnelError, protocol.TunnelError{
			Reason: "only loopback targets are allowed",
		})
		s.Close()
		return
	}
	tlog.Info("security audit: tunnel session authorized",
		"audit_event", "tunnel_session_authorized",
		"peer", shortPeer(requestPeerID),
		"transport_peer", shortPeer(remote),
		"stream_id", hello.StreamID,
		"target_host", connectTargetHost(hello.TargetHost),
		"requested_port", hello.TargetPort,
		"granted_port", grantedPort,
		"transport_backend", transportBackend)
	tlog.Info("CONNECT request accepted",
		"peer", shortPeer(requestPeerID),
		"transport_peer", shortPeer(remote),
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
		"peer", shortPeer(requestPeerID),
		"transport_peer", shortPeer(remote),
		"status", 200,
		"target", targetAddr,
		"target_port", grantedPort,
		"stream_id", hello.StreamID)

	tlog.Info("data channel open", "peer", shortPeer(requestPeerID), "transport_peer", shortPeer(remote), "target", targetAddr, "stream_id", hello.StreamID)
	m.proxyToService(s, requestPeerID, targetAddr, hello.StreamID)
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
	proxy.SetOnClose(func() {
		m.closeBackendTunnel(peerID, transportEndpoint, "local proxy closed")
	})
	tlog.Info("local proxy started", "addr", localAddr, "peer", peerID[:12])

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				tlog.Info("local proxy stopped", "addr", localAddr, "peer", peerID[:12], "err", err)
				proxy.notifyClosed()
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
				openTimeout := defaultTunnelOpenTimeout
				if transportEndpoint != "" && !strings.HasPrefix(transportEndpoint, "quic:") {
					openTimeout = irohTunnelOpenTimeout
				}
				openCtx, cancel := context.WithTimeout(context.Background(), openTimeout)
				defer cancel()
				streamID := newStreamID()
				tlog.Info("opening tunnel stream for local client",
					"peer", peerID[:12],
					"stream_id", streamID,
					"timeout", openTimeout.String(),
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
					conn.Close()
					return
				}
				proxy.SetConnectionPath(connectionPathForStream(stream, transportEndpoint), m.connectionAddrForStream(stream, transportEndpoint))
				if !proxy.trackStream(streamID, conn, stream) {
					tlog.Warn("local proxy closed before stream could be tracked",
						"peer", peerID[:12],
						"stream_id", streamID,
						"proxy_addr", conn.LocalAddr().String(),
						"client_addr", conn.RemoteAddr().String(),
						"target_port", targetPort)
					return
				}
				tlog.Info("bridging local RDP client to tunnel",
					"peer", peerID[:12],
					"stream_id", streamID,
					"open_duration", time.Since(openStarted).String(),
					"proxy_addr", conn.LocalAddr().String(),
					"client_addr", conn.RemoteAddr().String(),
					"target_port", targetPort)
				defer proxy.untrackStream(streamID, conn)
				if bridgeLogged("client", peerID[:12], streamID, conn.RemoteAddr().String(), conn, stream, "remote_to_local", "local_to_remote") {
					tlog.Warn("tunnel bridge failed, closing matching local proxy stream",
						"peer", peerID[:12],
						"stream_id", streamID,
						"proxy_addr", conn.LocalAddr().String(),
						"target_port", targetPort)
					proxy.CloseStream(streamID)
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

type connectionPathReporter interface {
	ConnectionPath() string
}

type connectionAddrReporter interface {
	ConnectionRemoteAddr() string
}

func connectionPathForStream(stream io.ReadWriteCloser, transportEndpoint string) string {
	if strings.HasPrefix(transportEndpoint, "quic:") {
		return "direct"
	}
	if transportEndpoint == "" {
		return "relayed"
	}
	if reporter, ok := stream.(connectionPathReporter); ok {
		return reporter.ConnectionPath()
	}
	return "unknown"
}

func (m *Manager) connectionAddrForStream(stream io.ReadWriteCloser, transportEndpoint string) string {
	if strings.HasPrefix(transportEndpoint, "quic:") {
		if m == nil || m.backends == nil {
			return ""
		}
		backend, ok := m.backends.Get(netbackend.BackendBitTorrentDHT)
		if !ok {
			return ""
		}
		reporter, ok := backend.(netbackend.DisplayAddrBackend)
		if !ok {
			return ""
		}
		return reporter.ConnectionDisplayAddr(netbackend.Target{
			QUICEndpoint: strings.TrimPrefix(transportEndpoint, "quic:"),
		})
	}
	if reporter, ok := stream.(connectionAddrReporter); ok {
		addr := strings.TrimSpace(reporter.ConnectionRemoteAddr())
		if isIrohVirtualAddr(addr) {
			return ""
		}
		return addr
	}
	return ""
}

func isIrohVirtualAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = strings.Trim(addr, "[]")
	}
	host = strings.Trim(host, "[]")
	return strings.HasPrefix(strings.ToLower(host), "fd15:")
}

func normalizeConnectionPath(path string) string {
	switch strings.ToLower(strings.TrimSpace(path)) {
	case "direct":
		return "direct"
	case "relay", "relayed":
		return "relayed"
	case "iroh_virtual":
		return "direct"
	default:
		return "unknown"
	}
}

func tunnelHelloNodeID(hello protocol.TunnelHello, transportPeerID string, transportBackend string) (string, error) {
	nodeID := strings.TrimSpace(hello.NodeID)
	if nodeID == "" {
		if transportBackend == netbackend.BackendIroh {
			return "", fmt.Errorf("tunnel hello is missing DeskAccess node id; upgrade DeskAccess on the client and try again")
		}
		return strings.TrimSpace(transportPeerID), nil
	}
	if _, err := peer.Decode(nodeID); err != nil {
		return "", fmt.Errorf("invalid DeskAccess node id in tunnel hello")
	}
	return nodeID, nil
}

func shortPeer(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
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
		NodeID:       m.n.NodeID(),
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

func (m *Manager) closeBackendTunnel(peerID string, transportEndpoint string, reason string) {
	if m == nil || m.backends == nil || strings.TrimSpace(peerID) == "" {
		return
	}
	backendName := netbackend.BackendLibp2pRelay
	switch {
	case strings.HasPrefix(transportEndpoint, "quic:"):
		backendName = netbackend.BackendBitTorrentDHT
	case strings.TrimSpace(transportEndpoint) != "":
		backendName = netbackend.BackendIroh
	}
	backend, ok := m.backends.Get(backendName)
	if !ok || backend == nil {
		return
	}
	closer, ok := backend.(netbackend.TunnelCloser)
	if !ok {
		return
	}
	closed := closer.CloseTunnel(peerID, reason)
	if closed > 0 {
		tlog.Info("backend cached tunnel closed",
			"backend", backendName,
			"peer", peerID[:12],
			"count", closed,
			"reason", reason)
	}
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
	logTunnelStreamLifecycle("tunnel stream bridge opened", side, peer, streamID, targetAddr)
	teardown := func(reason, direction string, abortive bool) {
		teardownOnce.Do(func() {
			logTunnelTeardown(side, peer, streamID, targetAddr, reason, direction)
			if abortive {
				closeAbortive(a)
				closeAbortive(b)
				return
			}
			closeGraceful(a)
			closeGraceful(b)
		})
	}
	go func() {
		n, err := copyWithProgress(a, b, side, peer, streamID, targetAddr, bToA)
		logBridgeCopy(side, peer, streamID, targetAddr, bToA, n, err)
		failed := bridgeCopyFailed(err)
		if failed {
			teardown("copy_error", bToA, true)
		} else {
			closeWrite(a)
		}
		done <- failed
	}()
	go func() {
		n, err := copyWithProgress(b, a, side, peer, streamID, targetAddr, aToB)
		logBridgeCopy(side, peer, streamID, targetAddr, aToB, n, err)
		failed := bridgeCopyFailed(err)
		if failed {
			teardown("copy_error", aToB, true)
		} else {
			closeWrite(b)
		}
		done <- failed
	}()
	firstFailed := <-done
	secondFailed := <-done
	teardown("both_directions_closed", "", false)
	logTunnelStreamLifecycle("tunnel stream bridge closed", side, peer, streamID, targetAddr)
	return firstFailed || secondFailed
}

func copyWithProgress(dst io.Writer, src io.Reader, side, peer, streamID, targetAddr, direction string) (int64, error) {
	buf := make([]byte, bridgeWriteBufferSize)
	var total int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := writeFullWithDeadline(dst, buf[:nr], side, peer, streamID, targetAddr, direction)
			if nw > 0 {
				total += int64(nw)
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

func writeFullWithDeadline(dst io.Writer, p []byte, side, peer, streamID, targetAddr, direction string) (int, error) {
	total := 0
	chunkSize := writeChunkSize(dst)
	for total < len(p) {
		end := len(p)
		if chunkSize > 0 && end-total > chunkSize {
			end = total + chunkSize
		}
		started := time.Now()
		clearWriteDeadline := setWriteDeadline(dst, time.Now().Add(bridgeWriteTimeout))
		n, err := dst.Write(p[total:end])
		clearWriteDeadline()
		duration := time.Since(started)
		if side != "" && duration >= bridgeSlowWriteThreshold {
			logBridgeSlowWrite(side, peer, streamID, targetAddr, direction, n, end-total, duration, err)
		}
		if n > 0 {
			total += n
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func writeChunkSize(dst io.Writer) int {
	if s, ok := dst.(interface{ WriteChunkSize() int }); ok {
		if size := s.WriteChunkSize(); size > 0 {
			return size
		}
	}
	return 0
}

func logBridgeSlowWrite(side, peer, streamID, targetAddr, direction string, bytes int, attempted int, duration time.Duration, err error) {
	args := []any{
		"side", side,
		"peer", peer,
		"stream_id", streamID,
		"direction", direction,
		"bytes", bytes,
		"attempted", attempted,
		"duration", duration.String(),
	}
	if targetAddr != "" {
		args = appendBridgeEndpointArgs(args, side, targetAddr)
	}
	if err != nil {
		tlog.Warn("tunnel write slow/failed", append(args, "err", err)...)
		return
	}
	tlog.Warn("tunnel write slow", args...)
}

func appendBridgeEndpointArgs(args []any, side string, endpointAddr string) []any {
	if endpointAddr == "" {
		return args
	}
	if side == "client" {
		return append(args, "client_addr", endpointAddr)
	}
	_, targetPort := splitTargetAddr(endpointAddr)
	return append(args, "target", endpointAddr, "target_port", targetPort)
}

func logTunnelStreamLifecycle(msg, side, peer, streamID, targetAddr string) {
	if side == "" {
		return
	}
	args := []any{
		"side", side,
		"peer", peer,
		"stream_id", streamID,
	}
	if targetAddr != "" {
		args = appendBridgeEndpointArgs(args, side, targetAddr)
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
		args = appendBridgeEndpointArgs(args, side, targetAddr)
	}
	tlog.Info("tearing down tunnel stream", args...)
}

func bridgeCopyFailed(err error) bool {
	return err != nil &&
		!errors.Is(err, io.EOF) &&
		!isTunnelClosedError(err)
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
	}
	if targetAddr != "" {
		args = appendBridgeEndpointArgs(args, side, targetAddr)
	}
	if err != nil && !errors.Is(err, io.EOF) && !isTunnelClosedError(err) {
		tlog.Warn("tunnel copy ended with error", append(args, "bytes", bytes, "err", err)...)
		return
	}
	if cause := bridgeCloseCause(err); cause != "" {
		args = append(args, "close_cause", cause)
	}
	if side == "host" && bytes == 0 {
		tlog.Warn("tunnel side closed before data transfer", args...)
		return
	}
	tlog.Info("tunnel copy ended", args...)
}

func bridgeCloseCause(err error) string {
	switch {
	case err == nil:
		return "nil"
	case errors.Is(err, io.EOF):
		return "eof"
	case isTunnelClosedError(err):
		return "closed"
	default:
		return ""
	}
}

func isUseOfClosedNetworkConnection(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "use of closed network connection")
}

func isTunnelClosedError(err error) bool {
	return errors.Is(err, net.ErrClosed) ||
		isUseOfClosedNetworkConnection(err) ||
		isConnectionReset(err) ||
		isIrohRemoteClosed(err)
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

func isIrohRemoteClosed(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	return msg == "internal_error (remote)" ||
		strings.Contains(msg, "application error 0x0 (remote)") ||
		strings.Contains(msg, "canceled by remote with error code 0")
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

func closeAbortive(v any) {
	if ac, ok := v.(interface{ AbortClose() error }); ok {
		_ = ac.AbortClose()
		return
	}
	closeGraceful(v)
}

func closeGraceful(v any) {
	if c, ok := v.(io.Closer); ok {
		_ = c.Close()
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

func setWriteDeadline(v any, deadline time.Time) func() {
	if wd, ok := v.(interface{ SetWriteDeadline(time.Time) error }); ok {
		if err := wd.SetWriteDeadline(deadline); err != nil {
			tlog.Debug("set write deadline failed", "err", err)
			return func() {}
		}
		return func() {
			if err := wd.SetWriteDeadline(time.Time{}); err != nil {
				tlog.Debug("clear write deadline failed", "err", err)
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
