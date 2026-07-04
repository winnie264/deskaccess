package btdht

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rdpanywhere/rdpanywhere/internal/netbackend"
)

func TestDirectQUICConnectionDisplayAddrHidesPublicKey(t *testing.T) {
	backend := &DirectQUICBackend{}
	target := netbackend.Target{QUICEndpoint: "f168943bef9a91cf6e18b663961981bde4c0443605ceab17ad060f7b6e3250cf@192.168.1.102:50548"}

	if got := backend.ConnectionDisplayAddr(target); got != "192.168.1.102:50548" {
		t.Fatalf("ConnectionDisplayAddr = %q", got)
	}
}

func TestOrderDirectQUICAddrsPrefersPublicSTUNAddress(t *testing.T) {
	got := orderDirectQUICAddrs([]string{
		"192.168.1.102:45779",
		"10.137.110.232:45779",
		"122.169.20.70:45779",
	})
	if len(got) != 3 {
		t.Fatalf("ordered addrs = %v", got)
	}
	if got[0] != "122.169.20.70:45779" {
		t.Fatalf("first addr = %q, want public STUN addr", got[0])
	}
}

func TestOpenPairingSessionUsesFirstSuccessfulAddress(t *testing.T) {
	transport := &fakeDirectQUICTransport{
		delays: map[string]time.Duration{
			"pub@122.169.20.70:45779": 100 * time.Millisecond,
			"pub@192.168.1.102:45779": 5 * time.Millisecond,
		},
	}
	backend := NewDirectQUICBackend(transport)

	session, err := backend.OpenPairingSession(context.Background(), netbackend.PairingTarget{
		PeerID:          "12D3KooWTest",
		PublicKeyHex:    "pub",
		DirectQUICAddrs: []string{"122.169.20.70:45779", "192.168.1.102:45779"},
	})
	if err != nil {
		t.Fatalf("OpenPairingSession: %v", err)
	}
	defer session.Stream.Close()
	if session.QUICEndpoint != "pub@192.168.1.102:45779" {
		t.Fatalf("endpoint = %q, want fastest successful endpoint", session.QUICEndpoint)
	}
}

type fakeDirectQUICTransport struct {
	delays map[string]time.Duration
}

func (f *fakeDirectQUICTransport) OpenPairing(ctx context.Context, endpoint string) (io.ReadWriteCloser, error) {
	if delay := f.delays[endpoint]; delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}

func (f *fakeDirectQUICTransport) OpenTunnel(context.Context, string) (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("not used")
}
