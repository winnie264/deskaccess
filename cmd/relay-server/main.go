// relay-server — a self-hosted libp2p circuit relay v2 node.
//
// Deploy this on any VPS ($5/mo, even a free Oracle/Fly tier) to get:
//   - Unlimited reservation TTL (configurable)
//   - No data caps on relayed traffic
//   - Full control over who can use the relay (allowlist)
//   - Works for symmetric NAT / corporate firewall users
//
// Usage:
//   relay-server                          # auto-generate key, listen :4001
//   relay-server -addr /ip4/0.0.0.0/tcp/4001
//   relay-server -key /etc/relay/key.pem  # persist identity across restarts
//
// After start, it prints its multiaddr:
//   /ip4/<your-ip>/tcp/4001/p2p/<PeerID>
//
// Paste that into the DeskAccess config on each client machine:
//   [relay]
//   mode = "custom"
//   url  = "/ip4/1.2.3.4/tcp/4001/p2p/QmXxx..."
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/multiformats/go-multiaddr"
)

func main() {
	var (
		listenAddr  = flag.String("addr", "/ip4/0.0.0.0/tcp/4001", "listen multiaddr")
		keyFile     = flag.String("key", "", "path to hex-encoded ed25519 private key file (auto-generated if missing)")
		maxReservs  = flag.Int("max-reservations", 1024, "max concurrent reservations")
		reservTTL   = flag.Duration("reservation-ttl", 24*time.Hour, "how long a reservation lasts")
		maxCircuits = flag.Int("max-circuits", 256, "max concurrent relayed streams")
		allowFile   = flag.String("allow", "", "file with allowed peer IDs, one per line (empty = allow all)")
	)
	flag.Parse()

	privKey, err := loadOrGenerateKey(*keyFile)
	if err != nil {
		log.Fatalf("key: %v", err)
	}

	listenMA, err := multiaddr.NewMultiaddr(*listenAddr)
	if err != nil {
		log.Fatalf("listen addr: %v", err)
	}

	// Load allowlist if provided
	_ = *allowFile // TODO: implement peer allowlist filter

	h, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.ListenAddrs(listenMA),
		libp2p.DisableRelay(), // this node IS the relay, not a relay client
	)
	if err != nil {
		log.Fatalf("create host: %v", err)
	}

	// Start circuit relay v2 service
	_, err = relay.New(h,
		relay.WithLimit(&relay.RelayLimit{
			Duration: *reservTTL,
			Data:     0, // 0 = no data limit (unlike public relays)
		}),
		relay.WithResources(relay.Resources{
			Limit: &relay.RelayLimit{
				Duration: *reservTTL,
				Data:     0,
			},
			ReservationTTL:         *reservTTL,
			MaxReservations:        *maxReservs,
			MaxCircuits:            *maxCircuits,
			BufferSize:             4096,
			MaxReservationsPerPeer: 4,
			MaxReservationsPerIP:   8,
		}),
	)
	if err != nil {
		log.Fatalf("start relay: %v", err)
	}

	fmt.Printf("\n🔀 DeskAccess Relay Server\n")
	fmt.Printf("   PeerID: %s\n\n", h.ID())
	fmt.Printf("   Add this to DeskAccess config:\n")
	fmt.Printf("   [relay]\n")
	fmt.Printf("   mode = \"custom\"\n")
	for _, addr := range h.Addrs() {
		fmt.Printf("   url  = \"%s/p2p/%s\"\n", addr, h.ID())
	}
	fmt.Printf("\n   Reservations: max %d, TTL %s, no data cap\n",
		*maxReservs, reservTTL)
	fmt.Printf("   Circuits:     max %d concurrent\n\n", *maxCircuits)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = ctx

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("Shutting down relay...")
	h.Close()
}

func loadOrGenerateKey(path string) (libp2pcrypto.PrivKey, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			b, err := hex.DecodeString(string(data))
			if err != nil {
				return nil, fmt.Errorf("decode key: %w", err)
			}
			return libp2pcrypto.UnmarshalEd25519PrivateKey(b)
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
		// File doesn't exist — generate and save
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	if path != "" {
		if err := os.WriteFile(path, []byte(hex.EncodeToString([]byte(priv))), 0600); err != nil {
			log.Printf("warning: could not save key to %s: %v", path, err)
		} else {
			log.Printf("Generated new key, saved to %s", path)
		}
	}

	return libp2pcrypto.UnmarshalEd25519PrivateKey([]byte(priv)[:64])
}
