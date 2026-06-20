// Package dht wraps go-libp2p-kad-dht in client mode for two purposes:
//  1. Relay fallback — surfaces DHT routing-table peers that advertise
//     circuit relay v2 hop, used when all static relays are cooled off.
//  2. Cold-start presence — locates a known remote peer's current multiaddrs
//     before GossipSub has had time to propagate their announcement.
//
// The DHT runs in ModeClient (no serving, lighter weight) and bootstraps
// against the same Amino DHT nodes used as static relays.
package dht

import (
	"context"
	"fmt"
	"time"

	cid "github.com/ipfs/go-cid"
	kaddht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	mh "github.com/multiformats/go-multihash"

	"github.com/rdpanywhere/rdpanywhere/internal/config"
	"github.com/rdpanywhere/rdpanywhere/internal/logger"
)

var dlog = logger.For(logger.CompDHT)

// aminoBootstrap are Amino DHT nodes that both participate in routing and
// support circuit relay v2. Kept in sync with node.PublicRelays.
var aminoBootstrap = []string{
	"/ip4/147.75.80.110/tcp/4001/p2p/QmbFgm5zan8P6eWWmeyfncR5feYEMPbht5b1FW1C37aQ7y",
	"/ip4/147.75.80.110/udp/4001/quic-v1/p2p/QmbFgm5zan8P6eWWmeyfncR5feYEMPbht5b1FW1C37aQ7y",
	"/ip4/147.75.195.153/tcp/4001/p2p/QmW9m57aiBDHAkKj9nmFSEn7ZqrcF1fZS4bipsTCHburei",
	"/ip4/147.75.195.153/udp/4001/quic-v1/p2p/QmW9m57aiBDHAkKj9nmFSEn7ZqrcF1fZS4bipsTCHburei",
	"/ip4/147.75.70.221/tcp/4001/p2p/Qme8g49gm3q4Acp7xWBKg3nAa9fxZ1YmyDJdyGgoG6LsXh",
	"/ip4/147.75.70.221/udp/4001/quic-v1/p2p/Qme8g49gm3q4Acp7xWBKg3nAa9fxZ1YmyDJdyGgoG6LsXh",
}

// Client wraps an IpfsDHT in client mode.
type Client struct {
	h           host.Host
	kDHT        *kaddht.IpfsDHT
	identityCID cid.Cid
}

// New creates a DHT client according to cfg and starts background bootstrapping.
// Returns (nil, nil) when cfg.Mode is "disabled" — callers must handle nil.
// Bootstrapping is non-blocking; the routing table fills progressively.
func New(ctx context.Context, h host.Host, cfg config.DHTConfig) (*Client, error) {
	if cfg.Mode == "disabled" {
		dlog.Info("DHT disabled by config")
		return nil, nil
	}

	var addrs []string
	switch cfg.Mode {
	case "custom":
		addrs = cfg.Bootstrap
		dlog.Info("DHT: custom bootstrap only", "count", len(addrs))
	case "mixed":
		addrs = append(append([]string{}, aminoBootstrap...), cfg.Bootstrap...)
		dlog.Info("DHT: public + custom bootstrap", "total", len(addrs))
	default: // "public"
		addrs = aminoBootstrap
	}

	peers := parseMultiaddrs(addrs)
	kd, err := kaddht.New(ctx, h,
		kaddht.Mode(kaddht.ModeClient),
		kaddht.BootstrapPeers(peers...),
	)
	if err != nil {
		return nil, err
	}
	identityCID, err := identityProviderCID(h)
	if err != nil {
		return nil, err
	}
	c := &Client{h: h, kDHT: kd, identityCID: identityCID}
	go c.bootstrap(ctx)
	go c.publishLoop(ctx)
	return c, nil
}

func (c *Client) Close() error {
	if c == nil || c.kDHT == nil {
		return nil
	}
	return c.kDHT.Close()
}

func (c *Client) bootstrap(ctx context.Context) {
	if err := c.kDHT.Bootstrap(ctx); err != nil && ctx.Err() == nil {
		dlog.Warn("DHT bootstrap error", "err", err)
		return
	}
	dlog.Info("DHT bootstrapped", "routing_table_size", c.kDHT.RoutingTable().Size())
}

func (c *Client) publishLoop(ctx context.Context) {
	c.PublishNow(ctx)
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.PublishNow(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// PublishNow advertises this node's app identity in the public libp2p DHT.
// The DHT stores a provider record; the cert/attestation is still exchanged
// during the pairing handshake after the peer is found.
func (c *Client) PublishNow(ctx context.Context) {
	if c == nil || !c.identityCID.Defined() {
		return
	}
	started := time.Now()
	dlog.Info("libp2p DHT identity publish started", "cid", c.identityCID.String())
	publishCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if !c.WaitReady(publishCtx) {
		dlog.Warn("libp2p DHT identity publish skipped", "reason", "routing table not ready", "duration", time.Since(started).String())
		return
	}
	if err := c.kDHT.Provide(publishCtx, c.identityCID, true); err != nil && publishCtx.Err() == nil {
		dlog.Warn("libp2p DHT identity publish failed", "err", err, "duration", time.Since(started).String())
		return
	}
	dlog.Info("libp2p DHT identity provider published", "cid", c.identityCID.String(), "routing_table_size", c.kDHT.RoutingTable().Size(), "duration", time.Since(started).String())
}

// FindPeer walks the DHT to locate the current multiaddrs of a peer.
// Useful for cold-start presence: find a paired peer's relay addr before
// GossipSub has delivered their announcement.
func (c *Client) FindPeer(ctx context.Context, id peer.ID) (peer.AddrInfo, error) {
	started := time.Now()
	dlog.Info("libp2p DHT peer resolve started", "peer", short(id.String()))
	info, err := c.kDHT.FindPeer(ctx, id)
	if err != nil {
		dlog.Warn("libp2p DHT peer resolve failed", "peer", short(id.String()), "duration", time.Since(started).String(), "err", err)
		return peer.AddrInfo{}, err
	}
	dlog.Info("libp2p DHT peer resolved", "peer", short(id.String()), "addrs", len(info.Addrs), "duration", time.Since(started).String())
	return info, nil
}

// FindIdentityProvider locates the peer that published the app identity public
// key embedded in an invite URL.
func (c *Client) FindIdentityProvider(ctx context.Context, publicKey []byte, expected peer.ID) (peer.AddrInfo, error) {
	started := time.Now()
	providerCID, err := IdentityProviderCID(publicKey)
	if err != nil {
		return peer.AddrInfo{}, err
	}
	dlog.Info("libp2p DHT identity provider resolve started", "peer", short(expected.String()), "cid", providerCID.String())
	for info := range c.kDHT.FindProvidersAsync(ctx, providerCID, 8) {
		if info.ID == "" {
			continue
		}
		if expected != "" && info.ID != expected {
			dlog.Info("libp2p DHT identity provider ignored unexpected peer", "expected", short(expected.String()), "found", short(info.ID.String()))
			continue
		}
		if len(info.Addrs) > 0 {
			dlog.Info("libp2p DHT identity provider resolved", "peer", short(info.ID.String()), "addrs", len(info.Addrs), "duration", time.Since(started).String())
			return info, nil
		}
		peerInfo := c.h.Peerstore().PeerInfo(info.ID)
		if len(peerInfo.Addrs) > 0 {
			dlog.Info("libp2p DHT identity provider resolved from peerstore", "peer", short(info.ID.String()), "addrs", len(peerInfo.Addrs), "duration", time.Since(started).String())
			return peerInfo, nil
		}
		dlog.Info("libp2p DHT identity provider resolved without addrs", "peer", short(info.ID.String()), "duration", time.Since(started).String())
		return info, nil
	}
	dlog.Warn("libp2p DHT identity provider resolve failed", "peer", short(expected.String()), "cid", providerCID.String(), "duration", time.Since(started).String(), "err", "identity provider not found")
	return peer.AddrInfo{}, fmt.Errorf("identity provider not found")
}

// RelayPeers returns peers from the DHT routing table whose protocol set
// includes the circuit relay v2 hop protocol — candidates for relay use
// when the static relay list is exhausted or all cooled off.
func (c *Client) RelayPeers() []peer.AddrInfo {
	const hopProto = "/libp2p/circuit/relay/0.2.0/hop"
	var out []peer.AddrInfo
	for _, pid := range c.kDHT.RoutingTable().ListPeers() {
		protos, _ := c.h.Peerstore().GetProtocols(pid)
		for _, p := range protos {
			if string(p) == hopProto {
				info := c.h.Peerstore().PeerInfo(pid)
				if len(info.Addrs) > 0 {
					out = append(out, info)
				}
				break
			}
		}
	}
	return out
}

// RoutingTableSize returns the current number of peers in the routing table.
// Zero means bootstrapping is still in progress.
func (c *Client) RoutingTableSize() int {
	return c.kDHT.RoutingTable().Size()
}

// WaitReady blocks until the routing table has at least one peer or ctx is done.
// Useful for waiting before querying, with a caller-supplied timeout.
func (c *Client) WaitReady(ctx context.Context) bool {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if c.kDHT.RoutingTable().Size() > 0 {
			return true
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return false
		}
	}
}

func parseMultiaddrs(addrs []string) []peer.AddrInfo {
	var infos []peer.AddrInfo
	for _, s := range addrs {
		maddr, err := ma.NewMultiaddr(s)
		if err != nil {
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			continue
		}
		infos = append(infos, *info)
	}
	return infos
}

func identityProviderCID(h host.Host) (cid.Cid, error) {
	pub, err := h.Peerstore().PubKey(h.ID()).Raw()
	if err != nil {
		return cid.Undef, fmt.Errorf("read host public key: %w", err)
	}
	return IdentityProviderCID(pub)
}

// IdentityProviderCID maps the app identity public key to a stable DHT provider
// key. This lets invite links with no relay reservation resolve through the
// public libp2p DHT.
func IdentityProviderCID(publicKey []byte) (cid.Cid, error) {
	if len(publicKey) == 0 {
		return cid.Undef, fmt.Errorf("empty public key")
	}
	sum, err := mh.Sum(append([]byte("DeskAccess:identity:v1:"), publicKey...), mh.SHA2_256, -1)
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.Raw, sum), nil
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
