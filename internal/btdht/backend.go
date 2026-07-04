package btdht

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/rdpanywhere/rdpanywhere/internal/netbackend"
)

// DirectQUICTransport is the direct UDP/QUIC stream transport paired with
// BitTorrent DHT discovery.
type DirectQUICTransport interface {
	OpenPairing(ctx context.Context, endpoint string) (io.ReadWriteCloser, error)
	OpenTunnel(ctx context.Context, endpoint string) (io.ReadWriteCloser, error)
}

// DirectQUICDiscoverer resolves BitTorrent DHT records into direct QUIC addrs.
type DirectQUICDiscoverer interface {
	LookupDirectQUIC(ctx context.Context, publicKeyHex string, expectedNodeID string) (relayAddrs []string, directQUICAddrs []string, err error)
}

// DirectQUICBackend owns the BitTorrent DHT-specific direct QUIC connect path.
type DirectQUICBackend struct {
	transport  DirectQUICTransport
	discoverer DirectQUICDiscoverer
}

func NewDirectQUICBackend(transport DirectQUICTransport) *DirectQUICBackend {
	if transport == nil {
		return nil
	}
	return &DirectQUICBackend{transport: transport}
}

func (b *DirectQUICBackend) Name() string { return netbackend.BackendBitTorrentDHT }

func (b *DirectQUICBackend) SetDiscoverer(discoverer DirectQUICDiscoverer) {
	if b == nil {
		return
	}
	b.discoverer = discoverer
}

func (b *DirectQUICBackend) OpenPairing(ctx context.Context, target netbackend.Target) (io.ReadWriteCloser, error) {
	if b == nil || b.transport == nil {
		return nil, fmt.Errorf("BitTorrent DHT direct QUIC backend is not running")
	}
	return b.transport.OpenPairing(ctx, target.QUICEndpoint)
}

func (b *DirectQUICBackend) OpenTunnel(ctx context.Context, target netbackend.Target) (io.ReadWriteCloser, error) {
	if b == nil || b.transport == nil {
		return nil, fmt.Errorf("BitTorrent DHT direct QUIC backend is not running")
	}
	return b.transport.OpenTunnel(ctx, target.QUICEndpoint)
}

func (b *DirectQUICBackend) OpenPairingSession(ctx context.Context, target netbackend.PairingTarget) (*netbackend.PairingSession, error) {
	if b == nil || b.transport == nil {
		return nil, fmt.Errorf("BitTorrent DHT direct QUIC backend is not running")
	}
	directAddrs := append([]string{}, target.DirectQUICAddrs...)
	relayAddrs := append([]string{}, target.RelayAddrs...)
	if len(directAddrs) == 0 && b.discoverer != nil && target.PublicKeyHex != "" {
		var err error
		relayAddrs, directAddrs, err = b.discoverer.LookupDirectQUIC(ctx, target.PublicKeyHex, target.PeerID)
		if err != nil {
			return nil, fmt.Errorf("BitTorrent DHT lookup failed: %w", err)
		}
	}
	orderedAddrs := orderDirectQUICAddrs(directAddrs)
	if len(orderedAddrs) == 0 {
		if target.PublicKeyHex == "" {
			return nil, fmt.Errorf("paired host is missing its public key")
		}
		return nil, fmt.Errorf("no direct QUIC address was found in BitTorrent DHT for %s", shortPeer(target.PeerID))
	}
	stream, endpoint, err := b.openFirstPairingStream(ctx, target.PeerID, target.PublicKeyHex, orderedAddrs)
	if err != nil {
		return nil, err
	}
	return &netbackend.PairingSession{
		Stream:          stream,
		RelayAddrs:      relayAddrs,
		DirectQUICAddrs: orderedAddrs,
		QUICEndpoint:    endpoint,
	}, nil
}

func (b *DirectQUICBackend) openFirstPairingStream(ctx context.Context, peerID string, publicKeyHex string, addrs []string) (io.ReadWriteCloser, string, error) {
	type result struct {
		stream   io.ReadWriteCloser
		endpoint string
		err      error
	}
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan result, len(addrs))
	var wg sync.WaitGroup
	started := 0
	for _, addr := range addrs {
		endpoint := directQUICEndpoint(publicKeyHex, addr)
		if endpoint == "" {
			continue
		}
		started++
		wg.Add(1)
		go func(addr string, endpoint string) {
			defer wg.Done()
			stream, err := b.OpenPairing(raceCtx, netbackend.Target{PeerID: peerID, QUICEndpoint: endpoint})
			select {
			case results <- result{stream: stream, endpoint: endpoint, err: err}:
			case <-raceCtx.Done():
				if stream != nil {
					_ = stream.Close()
				}
			}
		}(addr, endpoint)
	}
	if started == 0 {
		return nil, "", fmt.Errorf("discovered host addresses were invalid")
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var errs []string
	for res := range results {
		if res.err == nil && res.stream != nil {
			cancel()
			return res.stream, res.endpoint, nil
		}
		if res.stream != nil {
			_ = res.stream.Close()
		}
		addr := res.endpoint
		if _, parsedAddr, ok := strings.Cut(res.endpoint, "@"); ok {
			addr = parsedAddr
		}
		errs = append(errs, fmt.Sprintf("%s: %v", addr, res.err))
	}
	return nil, "", fmt.Errorf("discovered host addresses but direct UDP/QUIC failed; STUN may not work across this NAT pair: %s", strings.Join(errs, "; "))
}

func (b *DirectQUICBackend) ConnectionDisplayAddr(target netbackend.Target) string {
	endpoint := strings.TrimSpace(target.QUICEndpoint)
	if _, addr, ok := strings.Cut(endpoint, "@"); ok {
		return strings.TrimSpace(addr)
	}
	return endpoint
}

func directQUICEndpoint(publicKeyHex string, addr string) string {
	publicKeyHex = strings.ToLower(strings.TrimSpace(publicKeyHex))
	addr = strings.TrimSpace(addr)
	if publicKeyHex == "" || addr == "" {
		return ""
	}
	return publicKeyHex + "@" + addr
}

func orderDirectQUICAddrs(addrs []string) []string {
	seen := make(map[string]struct{}, len(addrs))
	public := make([]string, 0, len(addrs))
	private := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		if isPublicHostPort(addr) {
			public = append(public, addr)
		} else {
			private = append(private, addr)
		}
	}
	return append(public, private...)
}

func isPublicHostPort(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return true
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}

func shortPeer(peerID string) string {
	if len(peerID) <= 12 {
		return peerID
	}
	return peerID[:12]
}
