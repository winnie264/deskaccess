package node

import (
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/multiformats/go-multiaddr"
	"github.com/rdpanywhere/rdpanywhere/internal/config"
)

// NewFromHost wraps an existing libp2p host as a Node.
// Used in tests to create a node without a relay reservation.
// testRelayMask=0x01 makes RelayMask() return non-zero so GenerateURL
// succeeds without a real relay connection.
func NewFromHost(h host.Host, cfg *config.Config) *Node {
	stub, _ := multiaddr.NewMultiaddr(
		"/ip4/127.0.0.1/tcp/4001/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN" +
			"/p2p-circuit/p2p/" + h.ID().String(),
	)
	var addrs []multiaddr.Multiaddr
	if stub != nil {
		addrs = append(addrs, stub)
	}
	return &Node{
		Host:              h,
		PeerID:            h.ID(),
		cfg:               cfg,
		relayAddrs:        addrs,
		testRelayMask:     0x01, // bypass Connectedness check in tests
		allowLoopbackDial: true,
	}
}
