package protocol

import "testing"

func TestSessionTokenCanBeVerifiedMultipleTimesBeforeExpiry(t *testing.T) {
	store := NewSessionStore()
	token, err := store.Issue("peer-a", 3389)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	for i := 0; i < 2; i++ {
		peerID, err := store.Verify(token)
		if err != nil {
			t.Fatalf("Verify(%d) error = %v", i, err)
		}
		if peerID != "peer-a" {
			t.Fatalf("Verify(%d) peer = %q, want peer-a", i, peerID)
		}
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
