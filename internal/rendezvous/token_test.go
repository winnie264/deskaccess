package rendezvous_test

import (
	"testing"
	"time"

	"github.com/rdpanywhere/rdpanywhere/internal/rendezvous"
)

func TestTokenEncodeDecodeRoundtrip(t *testing.T) {
	original := &rendezvous.Token{
		RelayMask:  0b00000101, // relays 0 and 2
		ExpiresAt:  time.Now().Add(15 * time.Minute).Truncate(time.Second),
		Mode:       1, // pairing
		Protocol:   rendezvous.ProtoRDP,
		TargetPort: 3389,
	}
	// Fill PubKey with recognisable bytes
	for i := range original.PubKey {
		original.PubKey[i] = byte(i)
	}
	for i := range original.InviteID {
		original.InviteID[i] = byte(0xa0 + i)
	}
	for i := range original.InviteSecret {
		original.InviteSecret[i] = byte(0x40 + i)
	}

	url := original.Encode()
	if url == "" {
		t.Fatal("Encode returned empty URL")
	}
	if len(url) < 30 {
		t.Fatalf("URL too short: %q", url)
	}
	if url[:len(rendezvous.URLScheme+"://")] != rendezvous.URLScheme+"://" {
		t.Fatalf("URL does not start with scheme: %q", url)
	}

	decoded, err := rendezvous.DecodeURL(url)
	if err != nil {
		t.Fatalf("DecodeURL error: %v", err)
	}

	if decoded.PubKey != original.PubKey {
		t.Errorf("PubKey mismatch\n  want %x\n  got  %x", original.PubKey, decoded.PubKey)
	}
	if decoded.RelayMask != original.RelayMask {
		t.Errorf("RelayMask: want %08b got %08b", original.RelayMask, decoded.RelayMask)
	}
	if decoded.InviteID != original.InviteID {
		t.Errorf("InviteID mismatch\n  want %x\n  got  %x", original.InviteID, decoded.InviteID)
	}
	if decoded.InviteSecret != original.InviteSecret {
		t.Errorf("InviteSecret mismatch\n  want %x\n  got  %x", original.InviteSecret, decoded.InviteSecret)
	}
	if !decoded.ExpiresAt.Equal(original.ExpiresAt) {
		t.Errorf("ExpiresAt: want %v got %v", original.ExpiresAt, decoded.ExpiresAt)
	}
	if decoded.Mode != original.Mode {
		t.Errorf("Mode: want %d got %d", original.Mode, decoded.Mode)
	}
	if decoded.Protocol != original.Protocol {
		t.Errorf("Protocol: want %v got %v", original.Protocol, decoded.Protocol)
	}
	if decoded.TargetPort != original.TargetPort {
		t.Errorf("TargetPort: want %d got %d", original.TargetPort, decoded.TargetPort)
	}
}

func TestTokenAllProtocols(t *testing.T) {
	tests := []struct {
		proto    rendezvous.Protocol
		port     uint16
		wantPort int
	}{
		{rendezvous.ProtoRDP, 0, 3389},    // 0 = use default
		{rendezvous.ProtoVNC, 5901, 5901}, // explicit port
		{rendezvous.ProtoSSH, 0, 22},      // 0 = use default
		{rendezvous.ProtoCustom, 8080, 8080},
	}
	for _, tc := range tests {
		t.Run(tc.proto.String(), func(t *testing.T) {
			tok := &rendezvous.Token{
				ExpiresAt:  time.Now().Add(time.Hour),
				Protocol:   tc.proto,
				TargetPort: tc.port,
			}
			url := tok.Encode()
			decoded, err := rendezvous.DecodeURL(url)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if decoded.Protocol != tc.proto {
				t.Errorf("protocol: want %v got %v", tc.proto, decoded.Protocol)
			}
			if decoded.Port() != tc.wantPort {
				t.Errorf("port: want %d got %d", tc.wantPort, decoded.Port())
			}
		})
	}
}

func TestTokenExpiry(t *testing.T) {
	future := &rendezvous.Token{
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if future.IsExpired() {
		t.Error("future token should not be expired")
	}

	past := &rendezvous.Token{
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	if !past.IsExpired() {
		t.Error("past token should be expired")
	}

	// Far-future = no expiry sentinel
	noExpiry := &rendezvous.Token{
		ExpiresAt: time.Now().Add(100 * 365 * 24 * time.Hour),
	}
	if noExpiry.IsExpired() {
		t.Error("no-expiry sentinel should never expire")
	}
}

func TestPairingTokenDoesNotExpireWhenFarFutureTimestampIsEncoded(t *testing.T) {
	tok := &rendezvous.Token{
		ExpiresAt: time.Now().Add(100 * 365 * 24 * time.Hour),
		Mode:      1,
	}
	decoded, err := rendezvous.DecodeURL(tok.Encode())
	if err != nil {
		t.Fatalf("DecodeURL: %v", err)
	}
	if decoded.ModeString() != "pairing" {
		t.Fatalf("mode = %s, want pairing", decoded.ModeString())
	}
	if decoded.IsExpired() {
		t.Fatal("pairing token should not expire")
	}
}

func TestTokenURLScheme(t *testing.T) {
	tok := &rendezvous.Token{ExpiresAt: time.Now().Add(time.Hour)}
	url := tok.Encode()

	_, err := rendezvous.DecodeURL("notascheme://garbage")
	if err == nil {
		t.Error("expected error for wrong scheme")
	}
	_, err = rendezvous.DecodeURL(url[:5]) // truncated
	if err == nil {
		t.Error("expected error for truncated URL")
	}
}

func TestTokenDecodeIgnoresQuery(t *testing.T) {
	tok := &rendezvous.Token{ExpiresAt: time.Now().Add(time.Hour)}
	url := tok.Encode() + "?iroh=endpointabc&addr=/ip4/127.0.0.1/tcp/1"
	if _, err := rendezvous.DecodeURL(url); err != nil {
		t.Fatalf("decode with query: %v", err)
	}
}
