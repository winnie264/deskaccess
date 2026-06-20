// Package rendezvous provides local session code generation and peer ID
// formatting. No server is involved — codes are verified peer-to-peer.
package rendezvous

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// SessionCodeLength is the number of digits in a session code (defined in token.go as CodeLength).

// NewSessionCode generates a cryptographically random 6-digit numeric code.
// e.g. "482619" — can be read aloud over the phone.
func NewSessionCode() (string, error) {
	max := big.NewInt(1_000_000) // 000000 – 999999
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// FormatCode formats a 6-digit code with a dash: "482-619"
func FormatCode(code string) string {
	code = strings.TrimSpace(code)
	if len(code) != CodeLength { // CodeLength defined in token.go
		return code
	}
	return code[:3] + "-" + code[3:]
}

// NormaliseCode strips dashes and spaces.
func NormaliseCode(code string) string {
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, " ", "")
	return strings.TrimSpace(code)
}

// FormatMachineID formats a raw libp2p peer ID string into a readable
// display ID grouped every 4 chars: "12D3-KooW-ABCD-..."
// This is the permanent address users share once (like a phone number).
func FormatMachineID(peerID string) string {
	// peer IDs start with "12D3KooW" (CIDv1 base36, ed25519 inline)
	// Group every 4 chars for readability
	var b strings.Builder
	for i, c := range peerID {
		if i > 0 && i%4 == 0 {
			b.WriteRune('-')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// NormaliseMachineID strips formatting added by FormatMachineID.
func NormaliseMachineID(display string) string {
	return strings.ReplaceAll(display, "-", "")
}

// ShortMachineID returns the first 20 chars of the peer ID for compact display
// in the header / tray tooltip. Full ID still used for actual connections.
func ShortMachineID(peerID string) string {
	if len(peerID) > 20 {
		return peerID[:20] + "…"
	}
	return peerID
}
