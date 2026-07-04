// export_test.go — white-box test exports. Only compiled during go test.
package pairing

import (
	"time"

	"github.com/rdpanywhere/rdpanywhere/internal/rendezvous"
)

// TestVerifyAndConsume exposes the internal invite-proof verification logic.
func (m *Manager) TestVerifyAndConsume(tok *rendezvous.Token, remotePeerID string) error {
	proof := rendezvous.InviteProof(tok.InviteSecret[:], tok.InviteID[:], m.n.NodeID(), remotePeerID, tok.ModeString(), rendezvous.TimeWindow(time.Now()))
	_, err := m.verifyAndConsume(tok.InviteID[:], proof, remotePeerID, tok.ModeString())
	return err
}

func (m *Manager) NodeIDForTest() string {
	return m.n.NodeID()
}

// TestExpireInvite forcibly sets the expiry of a stored invite to the past.
// Used to test the expiry path without relying on negative TTL in GenerateURL.
func (m *Manager) TestExpireInvite(tok *rendezvous.Token) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if inv, ok := m.byInviteID[inviteKey(tok.InviteID[:])]; ok {
		inv.ExpiresAt = time.Now().Add(-time.Hour)
	}
}
