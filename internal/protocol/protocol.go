// Package protocol defines the wire protocol between DeskAccess peers.
//
// Two separate libp2p streams are used:
//
//  1. Pairing stream  (/DeskAccess/pairing/1.0.0)
//     Client → Host:   PairRequest  {version, invite_id, proof, mode, label}
//     Host   → Client: PairResponse {ok, message, host_label, session_token}
//     Stream closed after handshake.
//
//  2. Tunnel stream  (/DeskAccess/tunnel/1.0.0)
//     Client → Host:   TunnelHello  {method:"CONNECT", token, target_host, target_port}
//     Host   → Client: TunnelReady  {status:200, host_label} ← auth OK
//     or TunnelError  {reason}                              ← auth failed
//     After TunnelReady: raw TCP bytes, no framing, both directions.
//
// Frame format (handshake phase only):
//
//	┌──────────┬──────────────────┬─────────────────┐
//	│ 1B type  │ 4B length (BE)   │  N bytes JSON   │
//	└──────────┴──────────────────┴─────────────────┘
//
// Once the host writes TunnelReady the stream becomes a raw byte pipe.
package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// Version is the protocol version. Bump on breaking wire format changes.
const Version = 1

// MsgType identifies a handshake frame.
type MsgType byte

const (
	MsgPairRequest  MsgType = 0x01 // client → host  (pairing stream)
	MsgPairResponse MsgType = 0x02 // host   → client (pairing stream)
	MsgTunnelHello  MsgType = 0x03 // client → host  (tunnel stream)
	MsgTunnelReady  MsgType = 0x04 // host   → client: switch to raw
	MsgTunnelError  MsgType = 0x05 // host   → client: auth rejected
	MsgTunnelPing   MsgType = 0x06 // client → host  keepalive
	MsgTunnelPong   MsgType = 0x07 // host   → client keepalive ack
)

// MaxFrameSize caps handshake payloads. Raw data phase is uncapped.
// TPM attestation certificate chains are base64 encoded inside JSON and can
// exceed a few KB, so keep enough room for hardware-backed identities.
const MaxFrameSize = 256 * 1024

// SessionTokenTTL is how long a session token remains valid after issue.
// It only needs to bridge the pairing response to app TCP streams opened by
// the local proxy. RDP can open more than one TCP connection, so the token is
// short-lived and use-limited rather than single-use.
const SessionTokenTTL = 2 * time.Minute

// SessionTokenMaxUses bounds how many app TCP streams one authenticated
// pairing/reauth response can open. This keeps RDP's multi-connection behavior
// working without leaving a long-lived reusable capability behind.
const SessionTokenMaxUses = 16

// --- Handshake payloads ---

// TPMAttestation carries hardware attestation data in the handshake.
// Either peer may include this; the other can verify or ignore it.
type TPMAttestation struct {
	AKCert         []byte `json:"ak_cert"`          // Attestation Key cert, DER
	EKCert         []byte `json:"ek_cert"`          // Endorsement Key cert, DER
	ManufacturerCA []byte `json:"mfr_ca,omitempty"` // Manufacturer root CA, DER
	Manufacturer   string `json:"manufacturer"`     // "Infineon", "STMicro", etc.
	TPMVersion     string `json:"tpm_ver"`          // "2.0"
}

// IdentityProof proves possession of the private key behind the advertised
// machine identity. TPM proofs sign with the AK private key; software fallback
// proofs sign with the software identity key.
type IdentityProof struct {
	Backend       string `json:"backend"`              // "tpm" | "software"
	MachineID     string `json:"machine_id"`           // AK/SPKI thumbprint or software pubkey thumbprint
	PublicKey     []byte `json:"public_key,omitempty"` // software fallback public key
	NodePublicKey []byte `json:"node_public_key"`      // DeskAccess node public key; derives NodeID
	NodeSignature []byte `json:"node_signature"`       // node-key signature binding NodeID to this proof
	TimeWindow    int64  `json:"time_window"`          // freshness window
	Signature     []byte `json:"signature"`            // signature over the pairing transcript
}

// PairRequest is sent by the client on the pairing stream.
type PairRequest struct {
	Version     uint8           `json:"v"`
	NodeID      string          `json:"node_id,omitempty"` // DeskAccess/libp2p node id; transport peer id may differ for sidecars
	InviteID    []byte          `json:"invite_id,omitempty"`
	Proof       []byte          `json:"proof,omitempty"`
	Mode        string          `json:"mode"`               // "onetime" | "pairing" | "trusted"
	Label       string          `json:"label"`              // client machine name
	Protocol    string          `json:"protocol,omitempty"` // requested protocol for trusted reauth
	TargetPort  int             `json:"target_port,omitempty"`
	Attestation *TPMAttestation `json:"attest,omitempty"` // present if client has TPM
	Identity    *IdentityProof  `json:"identity,omitempty"`
}

// PairResponse is sent by the host on the pairing stream.
// SessionToken is a 16-byte random value the client must present on tunnel
// streams. It expires in SessionTokenTTL and is bound to the authenticated peer.
type PairResponse struct {
	OK           bool            `json:"ok"`
	Message      string          `json:"message"`
	HostLabel    string          `json:"host_label,omitempty"`
	SessionToken []byte          `json:"token,omitempty"`
	Protocol     string          `json:"protocol,omitempty"`
	TargetPort   int             `json:"target_port,omitempty"`
	IrohTicket   string          `json:"iroh_ticket,omitempty"`
	Attestation  *TPMAttestation `json:"attest,omitempty"`
	Identity     *IdentityProof  `json:"identity,omitempty"`
}

// TunnelHello is the first frame sent by the client on the tunnel stream.
// It follows HTTP CONNECT semantics: authenticate and request a single
// loopback target, then switch to raw TCP bytes after TunnelReady.
type TunnelHello struct {
	Version      uint8  `json:"v"`
	NodeID       string `json:"node_id,omitempty"` // DeskAccess/libp2p node id; transport peer id may differ for sidecars
	Method       string `json:"method,omitempty"`
	SessionToken []byte `json:"token"`
	TargetHost   string `json:"target_host,omitempty"`
	TargetPort   int    `json:"target_port,omitempty"`
	StreamID     string `json:"stream_id,omitempty"`
}

// TunnelReady is sent by the host when the session token is valid.
// After writing this frame the host switches to raw TCP proxy mode.
type TunnelReady struct {
	HostLabel string `json:"host_label"`
	Status    int    `json:"status,omitempty"`
	Message   string `json:"message,omitempty"`
}

// TunnelError is sent by the host when the token is invalid/expired.
type TunnelError struct {
	Reason string `json:"reason"`
}

type TunnelPing struct {
	TimeUnix int64 `json:"time_unix"`
}

type TunnelPong struct {
	TimeUnix int64 `json:"time_unix"`
}

// --- Frame I/O ---

// WriteFrame marshals payload as JSON and writes a typed frame to w.
func WriteFrame(w io.Writer, t MsgType, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal frame: %w", err)
	}
	if len(data) > MaxFrameSize {
		return fmt.Errorf("payload too large: %d > %d", len(data), MaxFrameSize)
	}
	var header [5]byte
	header[0] = byte(t)
	binary.BigEndian.PutUint32(header[1:], uint32(len(data)))
	if err := writeAll(w, header[:]); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if err := writeAll(w, data); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// ReadFrame reads the next typed frame from r.
// Returns (msgType, rawJSONPayload, error).
func ReadFrame(r io.Reader) (MsgType, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, fmt.Errorf("read header: %w", err)
	}
	t := MsgType(header[0])
	n := binary.BigEndian.Uint32(header[1:])
	if n > uint32(MaxFrameSize) {
		return 0, nil, fmt.Errorf("frame too large: %d bytes", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("read payload: %w", err)
	}
	return t, payload, nil
}

// Decode unmarshals a raw JSON payload into dst.
func Decode(payload []byte, dst any) error {
	return json.Unmarshal(payload, dst)
}

// --- Session token store ---

// SessionGrant is the host-side capability represented by a session token.
type SessionGrant struct {
	PeerID     string
	TargetPort int
}

// SessionStore issues and verifies short-lived session tokens.
// Tokens bridge the gap between the pairing handshake and the tunnel open.
type SessionStore struct {
	mu     sync.Mutex
	tokens map[string]sessionEntry
}

type sessionEntry struct {
	expiresAt time.Time
	grant     SessionGrant
	usesLeft  int
}

func NewSessionStore() *SessionStore {
	return &SessionStore{tokens: make(map[string]sessionEntry)}
}

// Issue generates a 16-byte session token for peerID, valid for SessionTokenTTL.
// targetPort binds the token to the selected app port from the invite.
func (s *SessionStore) Issue(peerID string, targetPort int) ([]byte, error) {
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("generate session token: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[string(token)] = sessionEntry{
		expiresAt: time.Now().Add(SessionTokenTTL),
		grant: SessionGrant{
			PeerID:     peerID,
			TargetPort: targetPort,
		},
		usesLeft: SessionTokenMaxUses,
	}
	s.sweep()
	return token, nil
}

// Verify checks the token and returns the peer ID it was issued for.
func (s *SessionStore) Verify(token []byte) (peerID string, err error) {
	grant, err := s.VerifyGrant(token)
	if err != nil {
		return "", err
	}
	return grant.PeerID, nil
}

// VerifyGrant checks the token and returns the full capability it represents.
func (s *SessionStore) VerifyGrant(token []byte) (SessionGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := string(token)
	e, ok := s.tokens[key]
	if !ok {
		return SessionGrant{}, fmt.Errorf("invalid session token")
	}
	if time.Now().After(e.expiresAt) {
		delete(s.tokens, key)
		return SessionGrant{}, fmt.Errorf("session token expired (must open tunnel within %s)", SessionTokenTTL)
	}
	if e.usesLeft <= 0 {
		delete(s.tokens, key)
		return SessionGrant{}, fmt.Errorf("session token use limit exceeded")
	}
	e.usesLeft--
	if e.usesLeft <= 0 {
		delete(s.tokens, key)
	} else {
		s.tokens[key] = e
	}
	return e.grant, nil
}

// sweep removes stale entries to keep the map bounded.
func (s *SessionStore) sweep() {
	now := time.Now()
	for k, e := range s.tokens {
		if now.After(e.expiresAt) {
			delete(s.tokens, k)
		}
	}
}
