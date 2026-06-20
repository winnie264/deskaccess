package quicnet

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/quic-go/quic-go"
	"github.com/rdpanywhere/rdpanywhere/internal/config"
	"github.com/rdpanywhere/rdpanywhere/internal/logger"
)

const (
	alpn       = "DeskAccess/quic-direct/1"
	kindPair   = byte(1)
	kindTun    = byte(2)
	idleTime   = 2 * time.Minute
	keepAlive  = 20 * time.Second
	maxStreams = 256
)

var log = logger.For(logger.Component("quic"))

type Handler func(conn io.ReadWriteCloser, remotePeerID string)

type Backend struct {
	listener *quic.Listener
	cert     tls.Certificate
	certPub  ed25519.PublicKey

	mu             sync.RWMutex
	pairingHandler Handler
	tunnelHandler  Handler
	conns          map[string]*quic.Conn
}

func New(ctx context.Context, cfg *config.Config, priv ed25519.PrivateKey) (*Backend, error) {
	if cfg == nil || cfg.BTDHT.Mode == "" || cfg.BTDHT.Mode == "disabled" {
		return nil, nil
	}
	cert, pub, err := tlsCertificate(priv)
	if err != nil {
		return nil, err
	}
	ln, err := quic.ListenAddr("0.0.0.0:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		NextProtos:   []string{alpn},
	}, quicConfig())
	if err != nil {
		return nil, fmt.Errorf("listen quic: %w", err)
	}
	b := &Backend{listener: ln, cert: cert, certPub: pub, conns: make(map[string]*quic.Conn)}
	go b.acceptLoop(ctx)
	log.Info("direct QUIC backend started", "addr", ln.Addr().String())
	return b, nil
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

func (b *Backend) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	for key, conn := range b.conns {
		conn.CloseWithError(0, "backend shutdown")
		delete(b.conns, key)
	}
	b.mu.Unlock()
	if b.listener != nil {
		return b.listener.Close()
	}
	return nil
}

func (b *Backend) Addrs() []string {
	if b == nil || b.listener == nil {
		return nil
	}
	addr := b.listener.Addr().String()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return []string{addr}
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return localUDPAddrs(port)
	}
	return []string{net.JoinHostPort(host, port)}
}

func (b *Backend) Status() map[string]any {
	if b == nil || b.listener == nil {
		return map[string]any{"enabled": false, "running": false}
	}
	return map[string]any{
		"enabled": true,
		"running": true,
		"ready":   true,
		"addrs":   b.Addrs(),
	}
}

func (b *Backend) OpenPairing(ctx context.Context, endpoint string) (io.ReadWriteCloser, error) {
	return b.openStream(ctx, endpoint, kindPair)
}

func (b *Backend) OpenTunnel(ctx context.Context, endpoint string) (io.ReadWriteCloser, error) {
	return b.openStream(ctx, endpoint, kindTun)
}

func (b *Backend) openStream(ctx context.Context, endpoint string, kind byte) (io.ReadWriteCloser, error) {
	addr, expectedPub, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	conn, err := b.cachedConn(ctx, addr, expectedPub)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		b.dropConn(endpoint)
		return nil, fmt.Errorf("open quic stream: %w", err)
	}
	if _, err := stream.Write([]byte{kind}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write stream kind: %w", err)
	}
	return stream, nil
}

func (b *Backend) cachedConn(ctx context.Context, addr string, expectedPub ed25519.PublicKey) (*quic.Conn, error) {
	key := hex.EncodeToString(expectedPub) + "@" + addr
	b.mu.Lock()
	conn := b.conns[key]
	if conn != nil {
		b.mu.Unlock()
		log.Info("reusing direct QUIC connection", "addr", addr)
		return conn, nil
	}
	b.mu.Unlock()

	tlsConf := &tls.Config{
		ServerName:         "deskaccess",
		Certificates:       []tls.Certificate{b.cert},
		NextProtos:         []string{alpn},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeer(rawCerts, expectedPub)
		},
	}
	conn, err := quic.DialAddr(ctx, addr, tlsConf, quicConfig())
	if err != nil {
		return nil, fmt.Errorf("dial quic %s: %w", addr, err)
	}
	b.mu.Lock()
	b.conns[key] = conn
	b.mu.Unlock()
	log.Info("direct QUIC connected", "addr", addr)
	return conn, nil
}

func (b *Backend) dropConn(endpoint string) {
	addr, expectedPub, err := parseEndpoint(endpoint)
	if err != nil {
		return
	}
	key := hex.EncodeToString(expectedPub) + "@" + addr
	b.mu.Lock()
	if conn := b.conns[key]; conn != nil {
		conn.CloseWithError(0, "")
		delete(b.conns, key)
	}
	b.mu.Unlock()
}

func (b *Backend) acceptLoop(ctx context.Context) {
	for {
		conn, err := b.listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if isServerClosed(err) {
				return
			}
			log.Warn("direct QUIC accept failed", "err", err)
			continue
		}
		go b.handleConn(ctx, conn)
	}
}

func isServerClosed(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "server closed") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "closed listener")
}

func (b *Backend) handleConn(ctx context.Context, conn *quic.Conn) {
	remotePeerID := peerIDFromTLSState(conn.ConnectionState().TLS)
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go b.handleStream(stream, remotePeerID)
	}
}

func (b *Backend) handleStream(stream *quic.Stream, remotePeerID string) {
	var kind [1]byte
	if _, err := io.ReadFull(stream, kind[:]); err != nil {
		stream.Close()
		return
	}
	b.mu.RLock()
	pairing := b.pairingHandler
	tunnel := b.tunnelHandler
	b.mu.RUnlock()
	switch kind[0] {
	case kindPair:
		if pairing != nil {
			pairing(stream, remotePeerID)
			return
		}
	case kindTun:
		if tunnel != nil {
			tunnel(stream, remotePeerID)
			return
		}
	}
	stream.Close()
}

func Endpoint(publicKeyHex, addr string) string {
	return strings.ToLower(publicKeyHex) + "@" + addr
}

func parseEndpoint(endpoint string) (string, ed25519.PublicKey, error) {
	pubHex, addr, ok := strings.Cut(endpoint, "@")
	if !ok || strings.TrimSpace(addr) == "" {
		return "", nil, fmt.Errorf("invalid direct QUIC endpoint")
	}
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		return "", nil, fmt.Errorf("decode direct QUIC public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return "", nil, fmt.Errorf("direct QUIC public key must be %d bytes", ed25519.PublicKeySize)
	}
	return addr, ed25519.PublicKey(pubBytes), nil
}

func tlsCertificate(priv ed25519.PrivateKey) (tls.Certificate, ed25519.PublicKey, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return tls.Certificate{}, nil, fmt.Errorf("derive ed25519 public key")
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "DeskAccess direct QUIC"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(nil, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("create direct QUIC certificate: %w", err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        tmpl,
	}
	return cert, pub, nil
}

func verifyPeer(rawCerts [][]byte, expected ed25519.PublicKey) error {
	pub, err := publicKeyFromRawCerts(rawCerts)
	if err != nil {
		return err
	}
	if !pub.Equal(expected) {
		return fmt.Errorf("direct QUIC peer key mismatch")
	}
	return nil
}

func publicKeyFromRawCerts(rawCerts [][]byte) (ed25519.PublicKey, error) {
	if len(rawCerts) == 0 {
		return nil, fmt.Errorf("missing direct QUIC peer certificate")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil, fmt.Errorf("parse direct QUIC peer certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("direct QUIC peer certificate is not Ed25519")
	}
	return pub, nil
}

func peerIDFromTLSState(state tls.ConnectionState) string {
	if len(state.PeerCertificates) == 0 {
		return ""
	}
	pub, ok := state.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return ""
	}
	libp2pPub, err := libp2pcrypto.UnmarshalEd25519PublicKey(pub)
	if err != nil {
		return ""
	}
	pid, err := peer.IDFromPublicKey(libp2pPub)
	if err != nil {
		return ""
	}
	return pid.String()
}

func PublicKeyHexFromPrivate(priv ed25519.PrivateKey) (string, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("derive ed25519 public key")
	}
	return hex.EncodeToString(pub), nil
}

func quicConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:        idleTime,
		KeepAlivePeriod:       keepAlive,
		MaxIncomingStreams:    maxStreams,
		MaxIncomingUniStreams: -1,
	}
}

func localUDPAddrs(port string) []string {
	var out []string
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				out = append(out, net.JoinHostPort(ip4.String(), port))
			}
		}
	}
	if len(out) == 0 {
		out = append(out, net.JoinHostPort("127.0.0.1", port))
	}
	return out
}
