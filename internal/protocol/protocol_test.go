package protocol

import (
	"bytes"
	"testing"
)

func TestSessionTokenAllowsBoundedMultipleUses(t *testing.T) {
	store := NewSessionStore()
	token, err := store.Issue("peer-a", 3389)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	for i := 0; i < SessionTokenMaxUses; i++ {
		peerID, err := store.Verify(token)
		if err != nil {
			t.Fatalf("Verify use %d error = %v", i+1, err)
		}
		if peerID != "peer-a" {
			t.Fatalf("Verify use %d peer = %q, want peer-a", i+1, peerID)
		}
	}
	if _, err := store.Verify(token); err == nil {
		t.Fatal("Verify after use limit unexpectedly succeeded")
	}
}

func TestSessionTokenCarriesTargetPortGrant(t *testing.T) {
	store := NewSessionStore()
	token, err := store.Issue("peer-a", 22)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	grant, err := store.VerifyGrant(token)
	if err != nil {
		t.Fatalf("VerifyGrant() error = %v", err)
	}
	if grant.PeerID != "peer-a" {
		t.Fatalf("PeerID = %q, want peer-a", grant.PeerID)
	}
	if grant.TargetPort != 22 {
		t.Fatalf("TargetPort = %d, want 22", grant.TargetPort)
	}
}

func TestWriteFrameHandlesShortWrites(t *testing.T) {
	var buf bytes.Buffer
	writer := shortWriter{w: &buf, max: 2}
	payload := PairRequest{
		Version: Version,
		Mode:    "pairing",
		Label:   "client",
	}
	if err := WriteFrame(writer, MsgPairRequest, payload); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	msgType, raw, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if msgType != MsgPairRequest {
		t.Fatalf("msgType = 0x%02x, want 0x%02x", msgType, MsgPairRequest)
	}
	var got PairRequest
	if err := Decode(raw, &got); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got.Label != payload.Label || got.Mode != payload.Mode {
		t.Fatalf("payload = %+v, want %+v", got, payload)
	}
}

type shortWriter struct {
	w   *bytes.Buffer
	max int
}

func (s shortWriter) Write(p []byte) (int, error) {
	if len(p) > s.max {
		p = p[:s.max]
	}
	return s.w.Write(p)
}
