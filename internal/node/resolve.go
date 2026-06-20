package node

// resolve.go — finds the best set of dial addrs for a peer ID.
//
// Strategy (tried in order):
//  1. Live addrs from presence (most recent announcement — best)
//  2. Stored addrs from config (last known — good for 1-day idle)
//  3. BitTorrent DHT signed record (cold-start discovery)
//  4. All public relays with peer ID (only when relay backend is enabled)
//
// The peer ID is permanent (keypair-derived), so option 3 is a reliable
// fallback regardless of how long the client has been offline.
// All attempts run in parallel; first to respond wins.

import (
	"context"
	"fmt"
	"sync"
)

// log is inherited from node.go (same package)

// ResolveResult holds the winning addr set and how it was found.
type ResolveResult struct {
	RelayAddrs []string
	Source     string // "presence" | "stored" | "bittorrent-dht" | "all-relays"
}

// ResolveAddrs finds dial addrs for hostPeerID using the configured strategy.
// presenceAddrs: live addrs from GossipSub (nil if not available).
// storedAddrs:   last known addrs from config file.
func (n *Node) ResolveAddrs(
	ctx context.Context,
	hostPeerID string,
	presenceAddrs []string,
	storedAddrs []string,
	btDHTAddrs []string,
) (*ResolveResult, error) {

	// Build candidate sets in priority order
	type candidate struct {
		addrs  []string
		source string
	}

	var sets []candidate

	// Tier 1: fresh from presence pubsub
	if len(presenceAddrs) > 0 {
		sets = append(sets, candidate{presenceAddrs, "presence"})
	}

	// Tier 2: stored from config (may be stale but usually fine)
	if len(storedAddrs) > 0 {
		sets = append(sets, candidate{storedAddrs, "stored"})
	}

	// Tier 3: signed BitTorrent DHT mutable record.
	if len(btDHTAddrs) > 0 {
		sets = append(sets, candidate{btDHTAddrs, "bittorrent-dht"})
	}

	// Tier 4: reconstruct from ALL known relays only when relay backend is enabled.
	if n.relayEnabled() {
		allRelayAddrs := buildAllRelayAddrs(hostPeerID)
		if len(allRelayAddrs) > 0 {
			sets = append(sets, candidate{allRelayAddrs, "all-relays"})
		}
	}

	if len(sets) == 0 {
		return nil, fmt.Errorf("no dial addresses available for peer %s", hostPeerID[:12])
	}

	// Try all candidate sets in parallel; return the first set
	// that successfully establishes a connection.
	type result struct {
		c   candidate
		err error
	}

	resultCh := make(chan result, len(sets))
	cancelFuncs := make([]context.CancelFunc, len(sets))

	for i, set := range sets {
		setCtx, cancel := context.WithCancel(ctx)
		cancelFuncs[i] = cancel
		go func(c candidate, ctx context.Context) {
			err := n.probeConnection(ctx, hostPeerID, c.addrs)
			resultCh <- result{c, err}
		}(set, setCtx)
	}

	// Cancel all remaining probes once we have a winner
	defer func() {
		for _, cancel := range cancelFuncs {
			cancel()
		}
	}()

	var lastErr error
	for range sets {
		r := <-resultCh
		if r.err == nil {
			log.Info("peer resolved", "peer", hostPeerID[:12], "source", r.c.source)
			return &ResolveResult{
				RelayAddrs: r.c.addrs,
				Source:     r.c.source,
			}, nil
		}
		lastErr = r.err
		log.Debug("resolve attempt failed", "source", r.c.source, "peer", hostPeerID[:12], "err", r.err)
	}

	return nil, fmt.Errorf("could not reach %s via discovered addresses: %w", hostPeerID[:12], lastErr)
}

// probeConnection attempts a libp2p connection to hostPeerID via relayAddrs.
// Used to test which set of addrs is currently reachable.
func (n *Node) probeConnection(ctx context.Context, hostPeerID string, relayAddrs []string) error {
	info, err := n.buildAddrInfo(hostPeerID, relayAddrs)
	if err != nil {
		return err
	}
	return n.Host.Connect(ctx, info)
}

// buildAllRelayAddrs constructs circuit relay multiaddrs for ALL known relays.
// Since the host runs keepalive to all of them, at least one will respond
// regardless of which specific relay addrs are stored in the client's config.
func buildAllRelayAddrs(hostPeerID string) []string {
	addrs := make([]string, 0, len(PublicRelays))
	for _, relay := range PublicRelays {
		addrs = append(addrs, relay+"/p2p-circuit/p2p/"+hostPeerID)
	}
	return addrs
}

// BuildAllRelayAddrs is the exported version for use in pairing.
func BuildAllRelayAddrs(hostPeerID string) []string {
	return buildAllRelayAddrs(hostPeerID)
}

// parallelFirst runs fns concurrently and returns the index of the first to
// succeed. If all fail, returns -1 and the last error.
// Unused for now but useful for multi-relay probing optimisation.
func parallelFirst(ctx context.Context, fns []func(context.Context) error) (int, error) {
	type res struct {
		idx int
		err error
	}
	ch := make(chan res, len(fns))
	ctxs := make([]context.CancelFunc, len(fns))
	var wg sync.WaitGroup

	for i, fn := range fns {
		fctx, cancel := context.WithCancel(ctx)
		ctxs[i] = cancel
		wg.Add(1)
		go func(idx int, f func(context.Context) error, c context.Context) {
			defer wg.Done()
			err := f(c)
			ch <- res{idx, err}
		}(i, fn, fctx)
	}

	go func() { wg.Wait(); close(ch) }()

	defer func() {
		for _, c := range ctxs {
			c()
		}
	}()

	var lastErr error
	for r := range ch {
		if r.err == nil {
			return r.idx, nil
		}
		lastErr = r.err
	}
	return -1, lastErr
}
