package node

// Connection strategy — priority order for reaching a remote peer:
//
//  1. DIRECT (best)
//     Both peers have public IPs or are on the same LAN.
//     Zero relay involvement after discovery.
//     Latency: ~1ms LAN, ~10-50ms internet.
//
//  2. HOLE-PUNCHED (good — covers ~80% of home users)
//     Both behind NAT. DCUtR punches a UDP/TCP hole via the relay,
//     then the relay steps aside. RDP data flows P2P directly.
//     Relay only carries ~KB of signalling, not RDP traffic.
//     Latency: normal internet RTT.
//     Works: both behind home router NAT (full-cone, restricted-cone).
//     Fails: symmetric NAT (many corporate / CGNAT setups).
//
//  3. RELAY-PROXIED (fallback — for symmetric NAT / strict firewalls)
//     All RDP data flows through the relay.
//     Public relays: NOT suitable — data caps, rate limits, no SLA.
//     Own relay: suitable — no caps, full control.
//     This is why the product should ship a one-click relay deploy option.
//
// The public relay nodes in PublicRelays are ONLY used for strategies 1 & 2.
// Strategy 3 requires a self-hosted relay.
//
// Relay reservation keepalive (our 20-min loop) maintains REACHABILITY only —
// not a data pipe. The reservation says "I exist here, come find me."
// Once found, DCUtR upgrades to direct.
//
// Days-long operation:
//   - Reservation refresh every 20min ✓
//   - TCP/QUIC keepalive every 25s ✓
//   - Auto-reconnect on relay drop ✓
//   - After hole-punch: direct P2P, relay not in data path ✓
//   - Presence announces every 20s with fresh relay addrs ✓
//
// So: the daemon can run for days. The RELAY CONNECTION runs for days
// (just tiny keepalive packets). RDP SESSION data: direct P2P for ~80% of
// home users, relay fallback only for the rest — which needs own relay.
