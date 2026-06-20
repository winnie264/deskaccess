package netbackend

import (
	"context"
	"fmt"
	"io"
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

// StreamBackend opens authenticated DeskAccess protocol streams. Pairing and
// tunnel managers consume this instead of knowing each concrete transport.
type StreamBackend interface {
	Name() string
	OpenPairing(ctx context.Context, target Target) (io.ReadWriteCloser, error)
	OpenTunnel(ctx context.Context, target Target) (io.ReadWriteCloser, error)
}

// TicketBackend is implemented by backends that can produce invite endpoint
// material, such as iroh tickets.
type TicketBackend interface {
	TicketContext(ctx context.Context) (string, error)
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

type Libp2pBackend struct {
	n *node.Node
}

func NewLibp2p(n *node.Node) *Libp2pBackend {
	return &Libp2pBackend{n: n}
}

func (b *Libp2pBackend) Name() string { return BackendLibp2pRelay }

func (b *Libp2pBackend) OpenPairing(ctx context.Context, target Target) (io.ReadWriteCloser, error) {
	if b == nil || b.n == nil {
		return nil, fmt.Errorf("libp2p backend is not running")
	}
	return b.n.OpenPairing(ctx, target.PeerID, target.RelayAddrs)
}

func (b *Libp2pBackend) OpenTunnel(ctx context.Context, target Target) (io.ReadWriteCloser, error) {
	if b == nil || b.n == nil {
		return nil, fmt.Errorf("libp2p backend is not running")
	}
	return b.n.OpenTunnel(ctx, target.PeerID, target.RelayAddrs)
}

type IrohBackend struct {
	inner interface {
		TicketContext(ctx context.Context) (string, error)
		OpenPairing(ctx context.Context, ticket string) (io.ReadWriteCloser, error)
		OpenTunnel(ctx context.Context, ticket string) (io.ReadWriteCloser, error)
	}
}

func NewIroh(inner interface {
	TicketContext(ctx context.Context) (string, error)
	OpenPairing(ctx context.Context, ticket string) (io.ReadWriteCloser, error)
	OpenTunnel(ctx context.Context, ticket string) (io.ReadWriteCloser, error)
}) *IrohBackend {
	if inner == nil {
		return nil
	}
	return &IrohBackend{inner: inner}
}

func (b *IrohBackend) Name() string { return BackendIroh }

func (b *IrohBackend) TicketContext(ctx context.Context) (string, error) {
	if b == nil || b.inner == nil {
		return "", fmt.Errorf("iroh backend is not running")
	}
	return b.inner.TicketContext(ctx)
}

func (b *IrohBackend) OpenPairing(ctx context.Context, target Target) (io.ReadWriteCloser, error) {
	if b == nil || b.inner == nil {
		return nil, fmt.Errorf("iroh backend is not running")
	}
	return b.inner.OpenPairing(ctx, target.IrohTicket)
}

func (b *IrohBackend) OpenTunnel(ctx context.Context, target Target) (io.ReadWriteCloser, error) {
	if b == nil || b.inner == nil {
		return nil, fmt.Errorf("iroh backend is not running")
	}
	return b.inner.OpenTunnel(ctx, target.IrohTicket)
}

type DirectQUICBackend struct {
	inner interface {
		OpenPairing(ctx context.Context, endpoint string) (io.ReadWriteCloser, error)
		OpenTunnel(ctx context.Context, endpoint string) (io.ReadWriteCloser, error)
	}
}

func NewDirectQUIC(inner interface {
	OpenPairing(ctx context.Context, endpoint string) (io.ReadWriteCloser, error)
	OpenTunnel(ctx context.Context, endpoint string) (io.ReadWriteCloser, error)
}) *DirectQUICBackend {
	if inner == nil {
		return nil
	}
	return &DirectQUICBackend{inner: inner}
}

func (b *DirectQUICBackend) Name() string { return BackendBitTorrentDHT }

func (b *DirectQUICBackend) OpenPairing(ctx context.Context, target Target) (io.ReadWriteCloser, error) {
	if b == nil || b.inner == nil {
		return nil, fmt.Errorf("direct QUIC backend is not running")
	}
	return b.inner.OpenPairing(ctx, target.QUICEndpoint)
}

func (b *DirectQUICBackend) OpenTunnel(ctx context.Context, target Target) (io.ReadWriteCloser, error) {
	if b == nil || b.inner == nil {
		return nil, fmt.Errorf("direct QUIC backend is not running")
	}
	return b.inner.OpenTunnel(ctx, target.QUICEndpoint)
}
