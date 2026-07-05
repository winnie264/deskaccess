// Package rendezvous provides compact URL token encoding for peer connections.
//
// Token layout (88 bytes total):
//
//	[0:32]  ed25519 public key  → derive peer ID + verify host
//	[32]    relay bitmask       → bit N = relay N from PublicRelays list
//	[33:49] invite id           → random public lookup id
//	[49:81] invite secret       → random private capability secret
//	[81:85] expiry              → unix32 timestamp
//	[85]    flags               → high nibble = Protocol, low nibble = Mode
//	                              Protocol: 0=rdp  1=vnc  2=ssh  3=custom
//	                              Mode:     0=onetime  1=pairing
//	[86:88] target port         → uint16 big-endian (e.g. 3389, 5900, 22)
//	                              0 = use protocol default
//
// Encoded as base58btc → ~121 chars
// Full URL: deskaccess://<121chars>  ≈ 134 chars
package rendezvous

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	tokenBytes       = 88
	URLScheme        = "deskaccess"
	CodeLength       = 6
	InviteIDSize     = 16
	InviteSecretSize = 32
	ProofSize        = sha256.Size
	TimeWindowSecs   = 30
	maxUnix32        = int64(1<<32 - 1)
)

// Protocol identifies the remote service the tunnel connects to.
type Protocol byte

const (
	ProtoRDP    Protocol = 0 // Windows Remote Desktop (port 3389)
	ProtoVNC    Protocol = 1 // VNC (port 5900)
	ProtoSSH    Protocol = 2 // SSH (port 22)
	ProtoCustom Protocol = 3 // user-defined port
)

func (p Protocol) String() string {
	switch p {
	case ProtoRDP:
		return "rdp"
	case ProtoVNC:
		return "vnc"
	case ProtoSSH:
		return "ssh"
	default:
		return "custom"
	}
}

// DefaultPort returns the well-known port for a protocol.
func (p Protocol) DefaultPort() int {
	switch p {
	case ProtoRDP:
		return 3389
	case ProtoVNC:
		return 5900
	case ProtoSSH:
		return 22
	default:
		return 3389
	}
}

// ParseProtocol parses a string like "rdp", "vnc", "ssh" into a Protocol.
func ParseProtocol(s string) Protocol {
	switch strings.ToLower(s) {
	case "vnc":
		return ProtoVNC
	case "ssh":
		return ProtoSSH
	case "custom":
		return ProtoCustom
	default:
		return ProtoRDP
	}
}

// Token is the decoded in-memory form.
type Token struct {
	PubKey       [32]byte
	RelayMask    byte
	InviteID     [InviteIDSize]byte
	InviteSecret [InviteSecretSize]byte
	ExpiresAt    time.Time
	Mode         byte     // 0=onetime  1=pairing
	Protocol     Protocol // rdp / vnc / ssh / custom
	TargetPort   uint16   // 0 = use Protocol.DefaultPort()
}

// Port returns the effective target port (resolves 0 to protocol default).
func (t *Token) Port() int {
	if t.TargetPort == 0 {
		return t.Protocol.DefaultPort()
	}
	return int(t.TargetPort)
}

// Encode packs a Token into a deskaccess:// URL.
func (t *Token) Encode() string {
	buf := make([]byte, tokenBytes)
	copy(buf[0:32], t.PubKey[:])
	buf[32] = t.RelayMask
	copy(buf[33:49], t.InviteID[:])
	copy(buf[49:81], t.InviteSecret[:])
	expires := t.ExpiresAt.Unix()
	if expires < 0 {
		expires = 0
	}
	if expires > maxUnix32 {
		expires = maxUnix32
	}
	binary.BigEndian.PutUint32(buf[81:85], uint32(expires))
	buf[85] = (byte(t.Protocol) << 4) | (t.Mode & 0x0F)
	binary.BigEndian.PutUint16(buf[86:88], t.TargetPort)
	return URLScheme + "://" + base58Encode(buf)
}

// DecodeURL parses a deskaccess:// URL back into a Token.
func DecodeURL(url string) (*Token, error) {
	prefix, ok := urlPrefix(url)
	if !ok {
		return nil, fmt.Errorf("not a DeskAccess URL")
	}
	encoded := strings.TrimSpace(strings.TrimPrefix(url, prefix))
	encoded = strings.TrimLeft(encoded, "/")
	if beforeQuery, _, ok := strings.Cut(encoded, "?"); ok {
		encoded = beforeQuery
	}
	if beforeFragment, _, ok := strings.Cut(encoded, "#"); ok {
		encoded = beforeFragment
	}
	encoded = strings.Trim(encoded, "/")
	buf, err := base58Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode token: %w", err)
	}
	if len(buf) != tokenBytes {
		return nil, fmt.Errorf("invalid token length: got %d want %d", len(buf), tokenBytes)
	}

	t := &Token{}
	copy(t.PubKey[:], buf[0:32])
	t.RelayMask = buf[32]
	copy(t.InviteID[:], buf[33:49])
	copy(t.InviteSecret[:], buf[49:81])
	t.ExpiresAt = time.Unix(int64(binary.BigEndian.Uint32(buf[81:85])), 0)
	flags := buf[85]
	t.Protocol = Protocol(flags >> 4)
	t.Mode = flags & 0x0F
	t.TargetPort = binary.BigEndian.Uint16(buf[86:88])
	return t, nil
}

func urlPrefix(raw string) (string, bool) {
	prefix := URLScheme + "://"
	if strings.HasPrefix(strings.ToLower(raw), prefix) {
		return raw[:len(prefix)], true
	}
	return "", false
}

// IsExpired returns true if the token has passed its expiry.
func (t *Token) IsExpired() bool {
	if t.Mode == 1 {
		return false
	}
	if t.ExpiresAt.After(time.Now().Add(50 * 365 * 24 * time.Hour)) {
		return false // far-future sentinel = no expiry
	}
	return time.Now().After(t.ExpiresAt)
}

// ModeString returns "onetime" or "pairing".
func (t *Token) ModeString() string {
	if t.Mode == 1 {
		return "pairing"
	}
	return "onetime"
}

func TimeWindow(at time.Time) int64 {
	return at.Unix() / TimeWindowSecs
}

func InviteProof(secret []byte, inviteID []byte, hostPeerID string, clientPeerID string, mode string, window int64) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("deskaccess invite proof v1"))
	mac.Write([]byte{0})
	mac.Write(inviteID)
	mac.Write([]byte{0})
	mac.Write([]byte(hostPeerID))
	mac.Write([]byte{0})
	mac.Write([]byte(clientPeerID))
	mac.Write([]byte{0})
	mac.Write([]byte(mode))
	mac.Write([]byte{0})
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(window))
	mac.Write(buf[:])
	return mac.Sum(nil)
}

func EqualProof(a, b []byte) bool {
	return hmac.Equal(a, b)
}

// --- base58btc ---

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(input []byte) string {
	n := new(big.Int).SetBytes(input)
	zero, base, mod := big.NewInt(0), big.NewInt(58), new(big.Int)
	var result []byte
	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		result = append(result, base58Alphabet[mod.Int64()])
	}
	for _, b := range input {
		if b != 0 {
			break
		}
		result = append(result, base58Alphabet[0])
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return string(result)
}

func base58Decode(input string) ([]byte, error) {
	n := big.NewInt(0)
	base := big.NewInt(58)
	for _, c := range input {
		idx := strings.IndexRune(base58Alphabet, c)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 char: %c", c)
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(idx)))
	}
	decoded := n.Bytes()
	leading := 0
	for _, c := range input {
		if c != rune(base58Alphabet[0]) {
			break
		}
		leading++
	}
	result := make([]byte, leading+len(decoded))
	copy(result[leading:], decoded)
	return result, nil
}
