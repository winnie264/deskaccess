package netbackend

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/rdpanywhere/rdpanywhere/internal/node"
)

const (
	BackendLibp2pRelay   = "libp2p_relay"
	BackendLibp2pDHT     = "libp2p_dht"
	BackendIroh          = "iroh"
	BackendBitTorrentDHT = "bittorrent_dht"
)

// Target is the transport-specific addressing data needed to open a stream.
// Backends read only the fields they understand.
type Target struct {
	PeerID       string
	RelayAddrs   []string
	IrohTicket   string
	QUICEndpoint string
}

// PairingTarget is the backend-neutral input needed to open a DeskAccess
// pairing stream. Individual backends consume only the fields they understand.
type PairingTarget struct {
	Backend         string
	PeerID          string
	PublicKeyHex    string
	IrohTicket      string
	RelayAddrs      []string
	PresenceAddrs   []string
	StoredAddrs     []string
	DirectQUICAddrs []string
}

// PairingSession describes the opened pairing stream and transport metadata
// that should be persisted if authentication succeeds.
type PairingSession struct {
	Stream          io.ReadWriteCloser
	RelayAddrs      []string
	IrohTicket      string
	DirectQUICAddrs []string
	QUICEndpoint    string
}

// StreamBackend opens authenticated DeskAccess protocol streams. Pairing and
// tunnel managers consume this instead of knowing each concrete transport.
type StreamBackend interface {
	Name() string
	OpenPairing(ctx context.Context, target Target) (io.ReadWriteCloser, error)
	OpenTunnel(ctx context.Context, target Target) (io.ReadWriteCloser, error)
}

// PairingSessionBackend lets a backend own its pairing discovery and dial path.
type PairingSessionBackend interface {
	OpenPairingSession(ctx context.Context, target PairingTarget) (*PairingSession, error)
}

// DisplayAddrBackend is implemented by transports whose dial target contains
// backend-specific addressing details that should not be shown directly in UI.
type DisplayAddrBackend interface {
	ConnectionDisplayAddr(target Target) string
}

// LifecycleBackend is implemented by backends that own network listeners or
// background discovery work. The service calls Start/Stop when the selected
// network backend changes.
type LifecycleBackend interface {
	StreamBackend
	Start(ctx context.Context, backend string) error
	Stop(ctx context.Context) error
	Running() bool
}

// TicketBackend is implemented by backends that can produce transport endpoint
// material, such as iroh endpoint tickets carried inside a DeskAccess invite.
type TicketBackend interface {
	TicketContext(ctx context.Context) (string, error)
}

// TunnelCloser is implemented by backends that keep parent tunnel connections
// cached across app streams and need explicit cleanup when a user disconnects.
type TunnelCloser interface {
	CloseTunnel(peerID string, reason string) int
}

type Registry struct {
	mu       sync.RWMutex
	backends map[string]StreamBackend
}

func NewRegistry() *Registry {
	return &Registry{backends: make(map[string]StreamBackend)}
}

func (r *Registry) Register(backend StreamBackend, aliases ...string) {
	if r == nil || backend == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	names := append([]string{backend.Name()}, aliases...)
	for _, name := range names {
		if name == "" {
			continue
		}
		r.backends[name] = backend
	}
}

func (r *Registry) Unregister(names ...string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, name := range names {
		delete(r.backends, name)
	}
}

func (r *Registry) Get(name string) (StreamBackend, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	backend, ok := r.backends[name]
	return backend, ok
}

func (r *Registry) MustGet(name string) (StreamBackend, error) {
	backend, ok := r.Get(name)
	if !ok || backend == nil {
		return nil, fmt.Errorf("%s backend is not running", name)
	}
	return backend, nil
}

func (r *Registry) Start(ctx context.Context, name string) error {
	backend, err := r.MustGet(name)
	if err != nil {
		return err
	}
	lifecycle, ok := backend.(LifecycleBackend)
	if !ok {
		return nil
	}
	return lifecycle.Start(ctx, name)
}

func (r *Registry) Stop(ctx context.Context, name string) error {
	backend, ok := r.Get(name)
	if !ok || backend == nil {
		return nil
	}
	lifecycle, ok := backend.(LifecycleBackend)
	if !ok {
		return nil
	}
	return lifecycle.Stop(ctx)
}

func (r *Registry) OpenPairingSession(ctx context.Context, name string, target PairingTarget) (*PairingSession, error) {
	backend, err := r.MustGet(name)
	if err != nil {
		return nil, err
	}
	target.Backend = name
	if sessionBackend, ok := backend.(PairingSessionBackend); ok {
		return sessionBackend.OpenPairingSession(ctx, target)
	}
	stream, err := backend.OpenPairing(ctx, Target{
		PeerID:     target.PeerID,
		RelayAddrs: target.RelayAddrs,
		IrohTicket: target.IrohTicket,
	})
	if err != nil {
		return nil, err
	}
	return &PairingSession{
		Stream:          stream,
		RelayAddrs:      target.RelayAddrs,
		IrohTicket:      target.IrohTicket,
		DirectQUICAddrs: target.DirectQUICAddrs,
	}, nil
}

type Libp2pBackend struct {
	n *node.Node
}

func NewLibp2p(n *node.Node) *Libp2pBackend {
	return &Libp2pBackend{n: n}
}

func (b *Libp2pBackend) Name() string { return BackendLibp2pRelay }

func (b *Libp2pBackend) Start(ctx context.Context, backend string) error {
	if b == nil || b.n == nil {
		return fmt.Errorf("libp2p backend is not running")
	}
	return b.n.StartLibp2p(ctx, backend)
}

func (b *Libp2pBackend) Stop(ctx context.Context) error {
	if b == nil || b.n == nil {
		return nil
	}
	return b.n.StopLibp2p(ctx)
}

func (b *Libp2pBackend) Running() bool {
	return b != nil && b.n != nil && b.n.Libp2pRunning()
}

func (b *Libp2pBackend) OpenPairing(ctx context.Context, target Target) (io.ReadWriteCloser, error) {
	if b == nil || b.n == nil {
		return nil, fmt.Errorf("libp2p backend is not running")
	}
	return b.n.OpenPairing(ctx, target.PeerID, target.RelayAddrs)
}

func (b *Libp2pBackend) OpenPairingSession(ctx context.Context, target PairingTarget) (*PairingSession, error) {
	if b == nil || b.n == nil {
		return nil, fmt.Errorf("libp2p backend is not running")
	}
	relayAddrs := append([]string{}, target.RelayAddrs...)
	if len(relayAddrs) == 0 && target.Backend == BackendLibp2pDHT {
		addrs, err := b.n.FindIdentityAddrs(ctx, target.PublicKeyHex, target.PeerID)
		if err != nil {
			addrs, err = b.n.FindPeerAddrs(ctx, target.PeerID)
		}
		if err != nil {
			return nil, err
		}
		relayAddrs = addrs
	}
	if len(relayAddrs) == 0 {
		resolved, err := b.n.ResolveAddrs(ctx, target.PeerID, target.PresenceAddrs, target.StoredAddrs, nil)
		if err != nil {
			return nil, err
		}
		relayAddrs = resolved.RelayAddrs
	}
	stream, err := b.OpenPairing(ctx, Target{PeerID: target.PeerID, RelayAddrs: relayAddrs})
	if err != nil {
		return nil, err
	}
	return &PairingSession{Stream: stream, RelayAddrs: relayAddrs}, nil
}

func (b *Libp2pBackend) OpenTunnel(ctx context.Context, target Target) (io.ReadWriteCloser, error) {
	if b == nil || b.n == nil {
		return nil, fmt.Errorf("libp2p backend is not running")
	}
	return b.n.OpenTunnel(ctx, target.PeerID, target.RelayAddrs)
}

type IrohSidecarBackend struct {
	inner interface {
		TicketContext(ctx context.Context) (string, error)
		OpenPairing(ctx context.Context, ticket string) (io.ReadWriteCloser, error)
		OpenTunnel(ctx context.Context, ticket string) (io.ReadWriteCloser, error)
		CloseTunnel(peerID string, reason string) int
	}
}

func NewIrohSidecar(inner interface {
	TicketContext(ctx context.Context) (string, error)
	OpenPairing(ctx context.Context, ticket string) (io.ReadWriteCloser, error)
	OpenTunnel(ctx context.Context, ticket string) (io.ReadWriteCloser, error)
	CloseTunnel(peerID string, reason string) int
}) *IrohSidecarBackend {
	if inner == nil {
		return nil
	}
	return &IrohSidecarBackend{inner: inner}
}

func (b *IrohSidecarBackend) Name() string { return BackendIroh }

func (b *IrohSidecarBackend) TicketContext(ctx context.Context) (string, error) {
	if b == nil || b.inner == nil {
		return "", fmt.Errorf("iroh backend is not running")
	}
	return b.inner.TicketContext(ctx)
}

func (b *IrohSidecarBackend) OpenPairing(ctx context.Context, target Target) (io.ReadWriteCloser, error) {
	if b == nil || b.inner == nil {
		return nil, fmt.Errorf("iroh backend is not running")
	}
	return b.inner.OpenPairing(ctx, target.IrohTicket)
}

func (b *IrohSidecarBackend) OpenPairingSession(ctx context.Context, target PairingTarget) (*PairingSession, error) {
	if strings.TrimSpace(target.IrohTicket) == "" {
		return nil, fmt.Errorf("paired remote has no iroh endpoint ticket")
	}
	stream, err := b.OpenPairing(ctx, Target{PeerID: target.PeerID, IrohTicket: target.IrohTicket})
	if err != nil {
		return nil, err
	}
	return &PairingSession{Stream: stream, IrohTicket: target.IrohTicket}, nil
}

func (b *IrohSidecarBackend) OpenTunnel(ctx context.Context, target Target) (io.ReadWriteCloser, error) {
	if b == nil || b.inner == nil {
		return nil, fmt.Errorf("iroh backend is not running")
	}
	return b.inner.OpenTunnel(ctx, target.IrohTicket)
}

func (b *IrohSidecarBackend) CloseTunnel(peerID string, reason string) int {
	if b == nil || b.inner == nil {
		return 0
	}
	return b.inner.CloseTunnel(peerID, reason)
}
