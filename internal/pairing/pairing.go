// Package pairing handles single-URL connection flow.
//
// The user shares ONE URL, e.g.:
//
//	deskaccess://3mFgK9xQr2PzWbN8vTcY4hJsLd6AeUo1
//
// Multiple invites can be generated simultaneously. Each gets a unique invite ID
// so it can be listed, tracked, and revoked independently.
package pairing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/rdpanywhere/rdpanywhere/internal/btdht"
	"github.com/rdpanywhere/rdpanywhere/internal/config"
	"github.com/rdpanywhere/rdpanywhere/internal/identity"
	"github.com/rdpanywhere/rdpanywhere/internal/irohnet"
	"github.com/rdpanywhere/rdpanywhere/internal/logger"
	"github.com/rdpanywhere/rdpanywhere/internal/netbackend"
	"github.com/rdpanywhere/rdpanywhere/internal/node"
	"github.com/rdpanywhere/rdpanywhere/internal/protocol"
	"github.com/rdpanywhere/rdpanywhere/internal/quicnet"
	"github.com/rdpanywhere/rdpanywhere/internal/rendezvous"
)

var log = logger.For(logger.CompPairing)

const maxStoredInvites = 500

// invite tracks one generated URL end-to-end.
type invite struct {
	ID         string // short unique ID shown in the list
	InviteID   [rendezvous.InviteIDSize]byte
	Secret     [rendezvous.InviteSecretSize]byte
	Mode       string // "onetime" | "pairing"
	Protocol   string // "rdp" | "vnc" | "ssh" | "custom"
	TargetPort uint16 // 0 = protocol default
	Label      string // optional human label set by host ("For Alice", "Work laptop")
	URL        string // stored so idempotent re-generation can return the same link
	CreatedAt  time.Time
	ExpiresAt  time.Time // zero = no expiry
	Revoked    bool
	Used       bool
	UsedBy     string // client's machine label, filled on connect
	UsedByID   string // client's peer ID, used to clean trusted cert metadata
	UsedAt     time.Time
}

// active returns true if the invite can still be presented to a connecting peer.
func (inv *invite) active() bool {
	if inv.Revoked || inv.Used {
		return false
	}
	// far-future sentinel = no expiry
	if inv.ExpiresAt.After(time.Now().Add(99 * 365 * 24 * time.Hour)) {
		return true
	}
	return inv.ExpiresAt.IsZero() || time.Now().Before(inv.ExpiresAt)
}

func (inv *invite) Status() string {
	switch {
	case inv.Revoked:
		return "revoked"
	case inv.Used:
		return "used"
	case !inv.ExpiresAt.IsZero() && time.Now().After(inv.ExpiresAt):
		return "expired"
	default:
		return "pending"
	}
}

func (inv *invite) effectiveTargetPort() int {
	if inv == nil {
		return rendezvous.ProtoRDP.DefaultPort()
	}
	if inv.TargetPort != 0 {
		return int(inv.TargetPort)
	}
	return rendezvous.ParseProtocol(inv.Protocol).DefaultPort()
}

// InviteView is the JSON-safe summary sent to the UI.
type InviteView struct {
	ID        string    `json:"id"`
	Mode      string    `json:"mode"`
	Protocol  string    `json:"protocol"` // "rdp" | "vnc" | "ssh"
	Label     string    `json:"label"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedBy    string    `json:"used_by,omitempty"`
	UsedByID  string    `json:"used_by_id,omitempty"`
	UsedAt    time.Time `json:"used_at,omitempty"`
}

// presenceProvider is a narrow interface so pairing can get live peer addrs
// without a circular import on the full presence package.
type presenceProvider interface {
	GetPeerAddrs(nodeID string) []string
}

type dhtDiscoverer interface {
	Lookup(ctx context.Context, publicKeyHex string, expectedNodeID string) ([]string, error)
}

type btRecordDiscoverer interface {
	LookupRecord(ctx context.Context, publicKeyHex string, expectedNodeID string) (*btdht.Record, error)
}

// Manager handles URL generation (host) and connection (client).
type Manager struct {
	mu            sync.Mutex
	invites       map[string]*invite
	byInviteID    map[string]*invite
	sessions      *protocol.SessionStore
	n             *node.Node
	cfg           *config.Config
	presence      presenceProvider
	dhtDiscoverer dhtDiscoverer
	backends      *netbackend.Registry
	identity      *identity.Identity
}

func New(n *node.Node, cfg *config.Config) *Manager {
	m := &Manager{
		invites:    make(map[string]*invite),
		byInviteID: make(map[string]*invite),
		sessions:   protocol.NewSessionStore(),
		n:          n,
		cfg:        cfg,
		backends:   netbackend.NewRegistry(),
	}
	m.backends.Register(netbackend.NewLibp2p(n), netbackend.BackendLibp2pDHT)
	n.SetPairingHandler(m.handleIncoming)
	go m.sweepLoop()
	return m
}

// SetPresence injects the presence manager after construction (avoids circular dep).
func (m *Manager) SetPresence(p presenceProvider) {
	m.mu.Lock()
	m.presence = p
	m.mu.Unlock()
}

// SetDHTDiscoverer injects optional relay-address lookup over BitTorrent DHT.
func (m *Manager) SetDHTDiscoverer(d dhtDiscoverer) {
	m.mu.Lock()
	m.dhtDiscoverer = d
	m.mu.Unlock()
}

// SetIroh injects the go-iroh backend.
func (m *Manager) SetIroh(i interface {
	TicketContext(ctx context.Context) (string, error)
	OpenPairing(ctx context.Context, ticket string) (io.ReadWriteCloser, error)
	OpenTunnel(ctx context.Context, ticket string) (io.ReadWriteCloser, error)
}) {
	if i == nil {
		m.backends.Unregister(netbackend.BackendIroh)
		return
	}
	m.backends.Register(netbackend.NewIroh(i))
}

// SetBitTorrentQUIC injects the direct QUIC transport used by BitTorrent DHT.
func (m *Manager) SetBitTorrentQUIC(q interface {
	OpenPairing(ctx context.Context, endpoint string) (io.ReadWriteCloser, error)
	OpenTunnel(ctx context.Context, endpoint string) (io.ReadWriteCloser, error)
}) {
	if q == nil {
		m.backends.Unregister(netbackend.BackendBitTorrentDHT)
		return
	}
	m.backends.Register(netbackend.NewDirectQUIC(q))
}

// SetIdentity provides local identity metadata for pairing attestation.
func (m *Manager) SetIdentity(id *identity.Identity) {
	m.mu.Lock()
	m.identity = id
	m.mu.Unlock()
}

// Sessions exposes the session store so the tunnel manager can verify tokens.
func (m *Manager) Sessions() *protocol.SessionStore { return m.sessions }

func (m *Manager) currentIrohTicket(ctx context.Context) (string, error) {
	backend, ok := m.backends.Get(netbackend.BackendIroh)
	if !ok || backend == nil {
		return "", fmt.Errorf("iroh backend is not running")
	}
	ticketBackend, ok := backend.(netbackend.TicketBackend)
	if !ok {
		return "", fmt.Errorf("iroh backend cannot issue tickets")
	}
	return ticketBackend.TicketContext(ctx)
}

func (m *Manager) configuredTargetPort() int {
	if m == nil || m.cfg == nil {
		return rendezvous.ProtoRDP.DefaultPort()
	}
	if target := strings.TrimSpace(m.cfg.RDP.TargetAddr); target != "" {
		if idx := strings.LastIndex(target, ":"); idx >= 0 && idx < len(target)-1 {
			if port, err := strconv.Atoi(target[idx+1:]); err == nil && port > 0 && port <= 65535 {
				return port
			}
		}
	}
	return rendezvous.ParseProtocol(m.cfg.RDP.Protocol).DefaultPort()
}

func (m *Manager) configuredProtocol() string {
	if m == nil || m.cfg == nil {
		return rendezvous.ProtoRDP.String()
	}
	return rendezvous.ParseProtocol(m.cfg.RDP.Protocol).String()
}

// --- HOST SIDE: generate ---

// GenerateURL creates a URL and registers a tracked invite.
// mode: "onetime" | "pairing"
// ttl: access duration (0 = no expiry)
// label: optional human label ("For Alice")
// proto: "rdp" | "vnc" | "ssh" | "custom"
// GenerateURLWithAddrs is like GenerateURL but takes explicit relay addresses
// instead of reading live relay reservation addrs from the node.
// Used in integration tests to connect two in-process nodes without a relay.
func (m *Manager) GenerateURLWithAddrs(
	mode string,
	ttl time.Duration,
	label string,
	proto string,
	targetPort int,
	relayAddrs []string,
) (string, *InviteView, error) {
	return m.generateURL(mode, ttl, label, proto, targetPort, relayAddrs)
}

// GenerateURL creates a tracked invite URL.
// targetPort: 0 = use protocol default (3389/5900/22)
func (m *Manager) GenerateURL(mode string, ttl time.Duration, label string, proto string, targetPort int) (string, *InviteView, error) {
	return m.generateURL(mode, ttl, label, proto, targetPort, nil)
}

// generateURL is the shared implementation used by GenerateURL and GenerateURLWithAddrs.
// If relayAddrs is nil, it reads the live addrs from the node's relay reservations.
func (m *Manager) generateURL(mode string, ttl time.Duration, label string, proto string, targetPort int, relayAddrs []string) (string, *InviteView, error) {
	activeBackend := m.activeNetworkBackend()
	if relayAddrs == nil && m.cfg != nil {
		m.cfg.NormalizeNetworkBackend()
		activeBackend = m.activeNetworkBackend()
	}

	// Pairing links identify this machine certificate. Keep one active pairing
	// link for the selected backend instead of minting duplicates on each click.
	if mode == "pairing" && relayAddrs == nil {
		m.DeletePendingPairingInvitesExceptBackend(activeBackend)
		if url, view := m.findActivePairingInvite(activeBackend); url != "" {
			return url, view, nil
		}
	}

	// Idempotent: for until-revoked non-pairing invites (ttl==0), return the
	// existing active invite for the same mode+proto+port.
	if mode != "pairing" && ttl == 0 && relayAddrs == nil {
		if url, view := m.findActiveInvite(mode, proto, uint16(targetPort)); url != "" {
			return url, view, nil
		}
	}

	privKey, err := m.cfg.PrivateKeyBytes()
	if err != nil {
		return "", nil, fmt.Errorf("load key: %w", err)
	}

	var relayMask byte
	if relayAddrs == nil {
		log.Debug("generate invite backend selected",
			"backend", activeBackend,
			"mode", mode,
			"protocol", proto,
			"target_port", targetPort,
		)
		switch activeBackend {
		case "libp2p_dht", "bittorrent_dht", "iroh":
			// DHT invite links intentionally carry no relay bitmask. The
			// connecting client resolves the host through the selected backend.
			relayMask = 0
		case "libp2p_relay":
			relayMask = m.n.RelayMask()
			log.Debug("generate invite relay mask", "mask", relayMask)
			if relayMask == 0 {
				return "", nil, fmt.Errorf("not connected to any relay — check network")
			}
		default:
			// Treat unset/legacy config like the app default: iroh/DHT-style
			// invites carry no libp2p relay mask.
			relayMask = 0
		}
	} else {
		// Test/override path: explicit addrs provided — no relay needed
		relayMask = 0xFF // all relay bits set (will be ignored — addrs come from token)
	}

	var inviteID [rendezvous.InviteIDSize]byte
	if _, err := rand.Read(inviteID[:]); err != nil {
		return "", nil, err
	}
	var inviteSecret [rendezvous.InviteSecretSize]byte
	if _, err := rand.Read(inviteSecret[:]); err != nil {
		return "", nil, err
	}

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	} else {
		expiresAt = time.Now().Add(100 * 365 * 24 * time.Hour) // far-future = no expiry
	}

	modeByte := byte(0)
	if mode == "pairing" {
		modeByte = 1
	}

	pub := privKey.Public()
	var pubKeyBytes []byte
	switch p := pub.(type) {
	case ed25519.PublicKey:
		pubKeyBytes = []byte(p)
	case []byte:
		pubKeyBytes = p
	default:
		return "", nil, fmt.Errorf("unexpected public key type %T", pub)
	}
	t := &rendezvous.Token{
		RelayMask:    relayMask,
		InviteID:     inviteID,
		InviteSecret: inviteSecret,
		ExpiresAt:    expiresAt,
		Mode:         modeByte,
		Protocol:     rendezvous.ParseProtocol(proto),
		TargetPort:   uint16(targetPort),
	}
	copy(t.PubKey[:], pubKeyBytes[:32])

	displayID := newID()
	if label == "" {
		label = defaultLabel(mode, proto)
	}
	if proto == "" {
		proto = "rdp"
	}

	encodedURL := t.Encode()
	if relayAddrs == nil {
		encodedURL = withInviteBackend(encodedURL, activeBackend)
	}
	if relayAddrs != nil {
		encodedURL = withInviteAddrs(encodedURL, m.n.NodeID(), relayAddrs)
	}
	if relayAddrs == nil && activeBackend == "iroh" {
		irohBackend, err := m.backends.MustGet(netbackend.BackendIroh)
		if err != nil {
			return "", nil, fmt.Errorf("iroh backend is not running")
		}
		ticketBackend, ok := irohBackend.(netbackend.TicketBackend)
		if !ok {
			return "", nil, fmt.Errorf("iroh backend cannot create invite tickets")
		}
		ticketCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		ticket, err := ticketBackend.TicketContext(ticketCtx)
		cancel()
		if err != nil {
			return "", nil, fmt.Errorf("create iroh ticket: %w", err)
		}
		encodedURL = withIrohTicket(encodedURL, ticket)
	}

	inv := &invite{
		ID:         displayID,
		InviteID:   inviteID,
		Secret:     inviteSecret,
		Mode:       mode,
		Protocol:   proto,
		TargetPort: uint16(targetPort),
		Label:      label,
		URL:        encodedURL,
		CreatedAt:  time.Now(),
		ExpiresAt:  expiresAt,
	}

	m.mu.Lock()
	m.invites[displayID] = inv
	m.byInviteID[inviteKey(inviteID[:])] = inv
	m.mu.Unlock()

	// Return zero expiry to UI when "no expiry" was requested
	displayExpiry := expiresAt
	if ttl == 0 {
		displayExpiry = time.Time{}
	}

	view := inv.view()
	view.ExpiresAt = displayExpiry

	return encodedURL, &view, nil
}

// findActiveInvite returns the stored URL and view for an existing until-revoked
// invite matching mode+proto+port, or ("", nil) if none exists.
func (m *Manager) findActiveInvite(mode, proto string, targetPort uint16) (string, *InviteView) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, inv := range m.invites {
		if inv.Mode == mode && inv.Protocol == proto && inv.TargetPort == targetPort &&
			inv.URL != "" && inv.active() {
			view := inv.view()
			view.ExpiresAt = time.Time{} // hide far-future sentinel
			return inv.URL, &view
		}
	}
	return "", nil
}

func (m *Manager) findActivePairingInvite(backend string) (string, *InviteView) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, inv := range m.invites {
		if inv.Mode == "pairing" && inv.URL != "" && inv.active() && inviteStoredBackend(inv) == backend {
			view := inv.view()
			if inv.ExpiresAt.After(time.Now().Add(99 * 365 * 24 * time.Hour)) {
				view.ExpiresAt = time.Time{}
			}
			return inv.URL, &view
		}
	}
	return "", nil
}

// DeletePendingPairingInvitesExceptBackend removes unused active pairing links
// that were generated for a backend that is no longer selected.
func (m *Manager) DeletePendingPairingInvitesExceptBackend(backend string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	deleted := 0
	for id, inv := range m.invites {
		if inv.Mode != "pairing" || inv.Used || inv.Revoked || !inv.active() {
			continue
		}
		if inviteStoredBackend(inv) == backend {
			continue
		}
		delete(m.byInviteID, inviteKey(inv.InviteID[:]))
		delete(m.invites, id)
		deleted++
	}
	return deleted
}

func inviteStoredBackend(inv *invite) string {
	if inv == nil || inv.URL == "" {
		return ""
	}
	return InviteNetworkBackend(inv.URL)
}

// --- HOST SIDE: list & revoke ---

// ListInvites returns all invites sorted newest-first.
func (m *Manager) ListInvites() []InviteView {
	m.mu.Lock()
	defer m.mu.Unlock()

	views := make([]InviteView, 0, len(m.invites))
	for _, inv := range m.invites {
		v := inv.view()
		if inv.ExpiresAt.After(time.Now().Add(99 * 365 * 24 * time.Hour)) {
			v.ExpiresAt = time.Time{} // hide far-future sentinel from UI
		}
		views = append(views, v)
	}
	sort.Slice(views, func(i, j int) bool {
		return views[i].CreatedAt.After(views[j].CreatedAt)
	})
	return views
}

// RevokeInvite cancels an invite by ID and removes any peer trust metadata that
// was created by a used pairing invite.
func (m *Manager) RevokeInvite(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[id]
	if !ok {
		return fmt.Errorf("invite %q not found", id)
	}
	delete(m.byInviteID, inviteKey(inv.InviteID[:])) // prevent any future use
	delete(m.invites, id)
	if inv.Mode == "pairing" && inv.UsedByID != "" {
		m.cfg.RemoveTrustedPeer(inv.UsedByID)
		m.cfg.RemoveRemote(inv.UsedByID)
		if err := m.cfg.Save(); err != nil {
			return fmt.Errorf("save trust cleanup: %w", err)
		}
	}
	return nil
}

// RenameInvite updates the human label on an invite.
func (m *Manager) RenameInvite(id, label string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[id]
	if !ok {
		return fmt.Errorf("invite %q not found", id)
	}
	inv.Label = label
	return nil
}

// --- HOST SIDE: pairing stream handler ---

// handleIncoming runs on the HOST when a client opens a pairing stream.
// Uses protocol framing: reads PairRequest, writes PairResponse.
// On success issues a session token the client uses to open the tunnel stream.
func (m *Manager) handleIncoming(s network.Stream) {
	m.handleIncomingConn(s, s.Conn().RemotePeer().String(), "libp2p")
}

// HandleIrohIncoming runs the same pairing protocol over an iroh stream.
func (m *Manager) HandleIrohIncoming(conn io.ReadWriteCloser, remotePeerID string) {
	m.handleIncomingConn(conn, remotePeerID, netbackend.BackendIroh)
}

// HandleQUICIncoming runs the same pairing protocol over a direct QUIC stream.
func (m *Manager) HandleQUICIncoming(conn io.ReadWriteCloser, remotePeerID string) {
	m.handleIncomingConn(conn, remotePeerID, netbackend.BackendBitTorrentDHT)
}

func (m *Manager) handleIncomingConn(s io.ReadWriteCloser, remotePeerID string, transportBackend string) {
	started := time.Now()
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Error("pairing handler panic",
				"peer", shortPeer(remotePeerID),
				"panic", fmt.Sprint(recovered),
				"duration", time.Since(started).String(),
			)
			if err := protocol.WriteFrame(s, protocol.MsgPairResponse, protocol.PairResponse{
				OK: false, Message: "host pairing handler failed",
			}); err != nil {
				log.Warn("write panic rejection failed", "err", err, "peer", shortPeer(remotePeerID))
			}
		}
		if err := s.Close(); err != nil {
			log.Debug("pairing stream close failed", "peer", shortPeer(remotePeerID), "err", err)
		}
		log.Info("pairing stream closed", "peer", shortPeer(remotePeerID), "duration", time.Since(started).String())
	}()
	sessionProtocol := m.configuredProtocol()
	sessionTargetPort := m.configuredTargetPort()

	// Read PairRequest frame
	log.Info("waiting for pairing request frame", "peer", shortPeer(remotePeerID), "transport_backend", transportBackend)
	msgType, payload, err := protocol.ReadFrame(s)
	if err != nil {
		log.Error("read pairing frame", "peer", shortPeer(remotePeerID), "err", err)
		return
	}
	if msgType != protocol.MsgPairRequest {
		log.Warn("unexpected pairing msg type", "peer", shortPeer(remotePeerID), "type", fmt.Sprintf("0x%02x", msgType))
		return
	}
	var req protocol.PairRequest
	if err := protocol.Decode(payload, &req); err != nil {
		log.Error("decode pairing request", "peer", shortPeer(remotePeerID), "err", err)
		return
	}
	log.Info("pairing request received", "peer", shortPeer(remotePeerID), "mode", req.Mode, "label", req.Label, "version", req.Version, "transport_backend", transportBackend)
	if req.Version > protocol.Version {
		log.Warn("unsupported protocol version from peer", "version", req.Version)
		if err := protocol.WriteFrame(s, protocol.MsgPairResponse, protocol.PairResponse{
			OK: false, Message: fmt.Sprintf("unsupported protocol version %d", req.Version),
		}); err != nil {
			log.Warn("write pairing rejection failed", "err", err, "peer", shortPeer(remotePeerID))
		}
		return
	}
	if err := verifyIdentityProof(req.Identity, req.Attestation, "request", remotePeerID, m.n.NodeID(), req.InviteID, req.Proof, nil, req.Mode); err != nil {
		log.Warn("identity proof rejected", "peer", shortPeer(remotePeerID), "err", err)
		if err := protocol.WriteFrame(s, protocol.MsgPairResponse, protocol.PairResponse{
			OK: false, Message: "identity proof rejected: " + err.Error(),
		}); err != nil {
			log.Warn("write identity rejection failed", "err", err, "peer", shortPeer(remotePeerID))
		}
		return
	}

	if req.Mode == "trusted" {
		trusted, ok := m.cfg.TrustedPeer(remotePeerID)
		if !ok {
			log.Warn("trusted reauth rejected — not in trusted list", "peer", shortPeer(remotePeerID))
			if err := protocol.WriteFrame(s, protocol.MsgPairResponse, protocol.PairResponse{
				OK: false, Message: "peer not in trusted list — use an invite link first",
			}); err != nil {
				log.Warn("write trusted rejection failed", "err", err, "peer", shortPeer(remotePeerID))
			}
			return
		}
		if trusted.Protocol != "" {
			sessionProtocol = trusted.Protocol
		}
		if trusted.TargetPort > 0 {
			sessionTargetPort = trusted.TargetPort
		}
		log.Info("trusted reauth accepted",
			"peer", shortPeer(remotePeerID),
			"label", req.Label,
			"protocol", sessionProtocol,
			"target_port", sessionTargetPort)
		backend, hardware, vendor, version, rootThumbprint := identityInfoFromAttestation(req.Attestation)
		m.cfg.AddTrustedPeer(config.TrustedPeer{
			NodeID:            remotePeerID,
			Label:             req.Label,
			Protocol:          sessionProtocol,
			TargetPort:        sessionTargetPort,
			IdentityBackend:   backend,
			HardwareBacked:    hardware,
			TPMVendor:         vendor,
			TPMVersion:        version,
			TPMRootThumbprint: rootThumbprint,
		})
		m.cfg.Save()
	} else {
		// Invite code path
		inv, err := m.verifyAndConsume(req.InviteID, req.Proof, remotePeerID, req.Mode)
		if err != nil {
			log.Warn("invite proof rejected", "err", err, "peer", shortPeer(remotePeerID))
			if err := protocol.WriteFrame(s, protocol.MsgPairResponse, protocol.PairResponse{
				OK: false, Message: err.Error(),
			}); err != nil {
				log.Warn("write invite rejection failed", "err", err, "peer", shortPeer(remotePeerID))
			}
			return
		}
		sessionTargetPort = inv.effectiveTargetPort()
		sessionProtocol = rendezvous.ParseProtocol(inv.Protocol).String()
		log.Info("invite code accepted",
			"mode", req.Mode,
			"peer", shortPeer(remotePeerID),
			"label", req.Label,
			"invite", inv.ID,
			"protocol", sessionProtocol,
			"target_port", sessionTargetPort)

		// Record who used this invite
		m.mu.Lock()
		inv.UsedBy = req.Label
		inv.UsedByID = remotePeerID
		inv.UsedAt = time.Now()
		m.mu.Unlock()

		if req.Mode == "pairing" || req.Mode == "onetime" {
			backend, hardware, vendor, version, rootThumbprint := identityInfoFromAttestation(req.Attestation)
			m.cfg.AddTrustedPeer(config.TrustedPeer{
				NodeID:            remotePeerID,
				Label:             req.Label,
				Protocol:          sessionProtocol,
				TargetPort:        sessionTargetPort,
				IdentityBackend:   backend,
				HardwareBacked:    hardware,
				TPMVendor:         vendor,
				TPMVersion:        version,
				TPMRootThumbprint: rootThumbprint,
			})
			m.cfg.Save()
		}
	}

	// Issue a short-lived session token bound to the selected app port.
	// The client MUST open the tunnel stream within SessionTokenTTL.
	m.mu.Lock()
	sessionToken, err := m.sessions.Issue(remotePeerID, sessionTargetPort)
	m.mu.Unlock()
	if err != nil {
		log.Warn("session token issue failed", "peer", shortPeer(remotePeerID), "err", err)
		if writeErr := protocol.WriteFrame(s, protocol.MsgPairResponse, protocol.PairResponse{
			OK: false, Message: "failed to issue session token",
		}); writeErr != nil {
			log.Warn("write session-token failure failed", "err", writeErr, "peer", shortPeer(remotePeerID))
		}
		return
	}
	responseProof, err := m.localProof("response", m.n.NodeID(), remotePeerID, req.InviteID, req.Proof, sessionToken, req.Mode, rendezvous.TimeWindow(time.Now()))
	if err != nil {
		log.Warn("response identity proof signing failed", "peer", shortPeer(remotePeerID), "err", err)
		if writeErr := protocol.WriteFrame(s, protocol.MsgPairResponse, protocol.PairResponse{
			OK: false, Message: "failed to sign identity proof",
		}); writeErr != nil {
			log.Warn("write identity-proof failure failed", "err", writeErr, "peer", shortPeer(remotePeerID))
		}
		return
	}
	responseIrohTicket := ""
	if transportBackend == netbackend.BackendIroh {
		ticketCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		ticket, ticketErr := m.currentIrohTicket(ticketCtx)
		cancel()
		if ticketErr != nil {
			log.Warn("fresh iroh ticket unavailable for pairing response", "peer", shortPeer(remotePeerID), "err", ticketErr)
		} else {
			responseIrohTicket = ticket
		}
	}

	if err := protocol.WriteFrame(s, protocol.MsgPairResponse, protocol.PairResponse{
		OK:           true,
		Message:      "authenticated",
		HostLabel:    m.cfg.Node.Label,
		SessionToken: sessionToken,
		Protocol:     sessionProtocol,
		TargetPort:   sessionTargetPort,
		IrohTicket:   responseIrohTicket,
		Attestation:  m.localAttestation(),
		Identity:     responseProof,
	}); err != nil {
		log.Warn("write pairing response failed", "err", err, "peer", shortPeer(remotePeerID))
		return
	}
	log.Info("pairing response sent",
		"peer", shortPeer(remotePeerID),
		"mode", req.Mode,
		"transport_backend", transportBackend,
		"protocol", sessionProtocol,
		"target_port", sessionTargetPort,
		"fresh_iroh_ticket", responseIrohTicket != "",
		"token_ttl", protocol.SessionTokenTTL.String())
}

func (m *Manager) verifyAndConsume(inviteID []byte, proof []byte, remotePeerID string, mode string) (*invite, error) {
	if len(inviteID) != rendezvous.InviteIDSize {
		return nil, fmt.Errorf("invalid link")
	}
	if len(proof) != rendezvous.ProofSize {
		return nil, fmt.Errorf("invalid invite proof")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	inv, ok := m.byInviteID[inviteKey(inviteID)]
	if !ok {
		return nil, fmt.Errorf("invalid link")
	}
	if subtle.ConstantTimeCompare(inv.InviteID[:], inviteID) != 1 {
		return nil, fmt.Errorf("invalid link")
	}
	if inv.Revoked {
		return nil, fmt.Errorf("link has been revoked")
	}
	if inv.Used {
		return nil, fmt.Errorf("link already used")
	}
	if inv.Mode != "pairing" &&
		!inv.ExpiresAt.IsZero() &&
		inv.ExpiresAt.Before(time.Now().Add(99*365*24*time.Hour)) &&
		time.Now().After(inv.ExpiresAt) {
		delete(m.byInviteID, inviteKey(inv.InviteID[:]))
		return nil, fmt.Errorf("link has expired")
	}
	if mode != inv.Mode {
		return nil, fmt.Errorf("invite mode mismatch")
	}
	if !m.validInviteProofLocked(inv, proof, remotePeerID, mode, time.Now()) {
		return nil, fmt.Errorf("invalid invite proof")
	}

	inv.Used = true
	inv.UsedAt = time.Now()
	return inv, nil
}

func (m *Manager) validInviteProofLocked(inv *invite, proof []byte, remotePeerID string, mode string, now time.Time) bool {
	nowWindow := rendezvous.TimeWindow(now)
	hostPeerID := m.n.NodeID()
	valid := false
	for _, offset := range []int64{-1, 0, 1} {
		expected := rendezvous.InviteProof(inv.Secret[:], inv.InviteID[:], hostPeerID, remotePeerID, mode, nowWindow+offset)
		if rendezvous.EqualProof(proof, expected) {
			valid = true
		}
	}
	return valid
}

// --- CLIENT SIDE ---

// ConnectByURL parses a deskaccess:// URL and initiates connection.
func (m *Manager) ConnectByURL(ctx context.Context, rawURL string) (*ConnectResult, error) {
	inviteBackend := inviteBackendFromURL(rawURL)
	irohTicket := irohTicketFromURL(rawURL)
	explicitAddrs := inviteAddrsFromURL(rawURL)
	t, err := rendezvous.DecodeURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid link: %w", err)
	}
	if t.IsExpired() {
		return nil, fmt.Errorf("this link has expired — ask the host to generate a new one")
	}

	peerID, err := pubKeyToPeerID(t.PubKey[:])
	if err != nil {
		return nil, fmt.Errorf("derive peer ID: %w", err)
	}
	if len(explicitAddrs) > 0 {
		if explicitPeer := invitePeerFromURL(rawURL); explicitPeer != "" {
			peerID = explicitPeer
		}
	}
	publicKeyHex := hex.EncodeToString(t.PubKey[:])

	relayAddrs := explicitAddrs
	if len(relayAddrs) == 0 {
		relayAddrs = relayMaskToAddrs(t.RelayMask, peerID)
	}
	if inviteBackend == "" {
		if irohTicket != "" {
			inviteBackend = "iroh"
		} else if len(relayAddrs) > 0 {
			inviteBackend = netbackend.BackendLibp2pRelay
		} else {
			inviteBackend = m.activeNetworkBackend()
		}
	}
	useIroh := inviteBackend == "iroh" || irohTicket != ""
	var directQUICEndpoint string
	var directQUICAddrs []string
	if useIroh {
		if irohTicket == "" {
			return nil, fmt.Errorf("iroh invite is missing endpoint ticket")
		}
		if err := validateIrohTicket(irohTicket, t.PubKey[:]); err != nil {
			return nil, err
		}
	} else if inviteBackend == "bittorrent_dht" {
		m.mu.Lock()
		discoverer, _ := m.dhtDiscoverer.(btRecordDiscoverer)
		m.mu.Unlock()
		if discoverer != nil {
			rec, err := discoverer.LookupRecord(ctx, publicKeyHex, peerID)
			if err == nil {
				relayAddrs = rec.RelayAddrs
				directQUICAddrs = rec.DirectQUICAddrs
				if len(directQUICAddrs) > 0 {
					directQUICEndpoint = quicnet.Endpoint(publicKeyHex, directQUICAddrs[0])
				}
			} else {
				log.Debug("BitTorrent DHT direct record lookup failed", "peer", peerID[:12], "err", err)
			}
		}
	} else if len(relayAddrs) == 0 {
		var err error
		relayAddrs, err = m.resolveInviteAddrsForBackend(ctx, inviteBackend, peerID, publicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("no relay addresses in link and DHT discovery failed: %w", err)
		}
	}
	if !useIroh && directQUICEndpoint == "" && len(relayAddrs) == 0 {
		var err error
		relayAddrs, err = m.resolveInviteAddrsForBackend(ctx, inviteBackend, peerID, publicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("no direct QUIC or relay addresses discovered: %w", err)
		}
	}

	var pairingStream io.ReadWriteCloser
	if useIroh {
		backend, getErr := m.backends.MustGet(netbackend.BackendIroh)
		if getErr != nil {
			return nil, getErr
		}
		pairingStream, err = backend.OpenPairing(ctx, netbackend.Target{
			PeerID:     peerID,
			IrohTicket: irohTicket,
		})
	} else if directQUICEndpoint != "" {
		backend, getErr := m.backends.MustGet(netbackend.BackendBitTorrentDHT)
		if getErr != nil {
			return nil, getErr
		}
		pairingStream, err = backend.OpenPairing(ctx, netbackend.Target{
			PeerID:       peerID,
			QUICEndpoint: directQUICEndpoint,
		})
	} else {
		backendName := inviteBackend
		if backendName == "" {
			backendName = netbackend.BackendLibp2pRelay
		}
		backend, getErr := m.backends.MustGet(backendName)
		if getErr != nil {
			return nil, getErr
		}
		pairingStream, err = backend.OpenPairing(ctx, netbackend.Target{
			PeerID:     peerID,
			RelayAddrs: relayAddrs,
		})
	}
	if err != nil {
		if inviteBackend == netbackend.BackendLibp2pDHT {
			return nil, fmt.Errorf("libp2p DHT found the host, but direct dial failed; this usually means the host is behind NAT/firewall. Use an iroh or relay invite for this network: %w", err)
		}
		return nil, fmt.Errorf("cannot reach host (offline or all relays unreachable): %w", err)
	}
	defer pairingStream.Close()

	// Send PairRequest frame
	proof := rendezvous.InviteProof(t.InviteSecret[:], t.InviteID[:], peerID, m.n.NodeID(), t.ModeString(), rendezvous.TimeWindow(time.Now()))
	identityProof, err := m.localProof("request", m.n.NodeID(), peerID, t.InviteID[:], proof, nil, t.ModeString(), rendezvous.TimeWindow(time.Now()))
	if err != nil {
		return nil, fmt.Errorf("sign identity proof: %w", err)
	}
	if err := protocol.WriteFrame(pairingStream, protocol.MsgPairRequest, protocol.PairRequest{
		Version:     protocol.Version,
		InviteID:    t.InviteID[:],
		Proof:       proof,
		Mode:        t.ModeString(),
		Label:       m.cfg.Node.Label,
		Attestation: m.localAttestation(),
		Identity:    identityProof,
	}); err != nil {
		return nil, fmt.Errorf("send pair request: %w", err)
	}

	// Read PairResponse frame
	msgType, payload, err := readFrameWithContext(ctx, pairingStream)
	if err != nil {
		return nil, fmt.Errorf("read pair response: %w", err)
	}
	if msgType != protocol.MsgPairResponse {
		return nil, fmt.Errorf("unexpected response type 0x%02x", msgType)
	}
	var resp protocol.PairResponse
	if err := protocol.Decode(payload, &resp); err != nil {
		return nil, fmt.Errorf("decode pair response: %w", err)
	}
	if !resp.OK {
		return nil, fmt.Errorf("host rejected: %s", resp.Message)
	}
	if len(resp.SessionToken) == 0 {
		return nil, fmt.Errorf("host did not issue a session token")
	}
	if err := verifyIdentityProof(resp.Identity, resp.Attestation, "response", peerID, m.n.NodeID(), t.InviteID[:], proof, resp.SessionToken, t.ModeString()); err != nil {
		return nil, fmt.Errorf("host identity proof rejected: %w", err)
	}

	log.Info("pairing authenticated", "host", resp.HostLabel)
	effectiveIrohTicket := irohTicket
	if resp.IrohTicket != "" {
		if err := validateIrohTicket(resp.IrohTicket, t.PubKey[:]); err != nil {
			return nil, fmt.Errorf("host refreshed iroh ticket rejected: %w", err)
		}
		effectiveIrohTicket = resp.IrohTicket
		log.Info("refreshed iroh ticket received", "host", resp.HostLabel, "peer", shortPeer(peerID))
	}
	targetPort := resp.TargetPort
	if targetPort == 0 {
		targetPort = t.Port()
	}

	// Pairing mode: store host as a trusted remote
	if t.Mode == 1 {
		backend, hardware, vendor, version, rootThumbprint := identityInfoFromAttestation(resp.Attestation)
		m.cfg.AddRemote(config.RemoteConfig{
			Label:             resp.HostLabel,
			NodeID:            peerID,
			PublicKey:         hex.EncodeToString(t.PubKey[:]),
			Backend:           inviteBackend,
			Protocol:          t.Protocol.String(),
			TargetPort:        targetPort,
			RelayAddrs:        relayAddrs,
			IrohTicket:        effectiveIrohTicket,
			DirectQUICAddrs:   directQUICAddrs,
			IdentityBackend:   backend,
			HardwareBacked:    hardware,
			TPMVendor:         vendor,
			TPMVersion:        version,
			TPMRootThumbprint: rootThumbprint,
		})
		m.cfg.AddTrustedPeer(config.TrustedPeer{
			NodeID:            peerID,
			Label:             resp.HostLabel,
			Protocol:          t.Protocol.String(),
			TargetPort:        targetPort,
			IdentityBackend:   backend,
			HardwareBacked:    hardware,
			TPMVendor:         vendor,
			TPMVersion:        version,
			TPMRootThumbprint: rootThumbprint,
		})
		m.cfg.Save()
		log.Info("paired successfully", "host", resp.HostLabel, "peer", peerID[:12])
	}

	return &ConnectResult{
		PeerID:                 peerID,
		RelayAddrs:             relayAddrs,
		HostLabel:              resp.HostLabel,
		Mode:                   t.ModeString(),
		Protocol:               t.Protocol.String(),
		TargetPort:             targetPort,
		SessionToken:           resp.SessionToken,
		IrohTicket:             effectiveIrohTicket,
		BitTorrentQUICEndpoint: directQUICEndpoint,
	}, nil
}

// ReauthPaired reconnects to a previously paired remote without requiring a new
// invite code. Uses three-tier relay resolution so it works even after days of
// inactivity — presence addrs → stored addrs → try all known relays in parallel.
func (m *Manager) ReauthPaired(ctx context.Context, peerID string) (*ConnectResult, error) {
	return m.ReauthPairedWithBackend(ctx, peerID, "")
}

func (m *Manager) RemoteBackend(peerID string) string {
	for _, r := range m.cfg.Remotes {
		if r.NodeID == peerID {
			return strings.TrimSpace(r.Backend)
		}
	}
	return ""
}

func (m *Manager) ReauthPairedWithBackend(ctx context.Context, peerID string, preferredBackend string) (*ConnectResult, error) {
	// Tier 1: live addrs from presence (best — most recent)
	var presenceAddrs []string
	if m.presence != nil {
		presenceAddrs = m.presence.GetPeerAddrs(peerID)
	}

	// Tier 2: stored addrs from config (last known)
	var storedAddrs []string
	var storedQUICAddrs []string
	var publicKey string
	var publicKeyBytes []byte
	var irohTicket string
	storedProtocol := ""
	storedTargetPort := 0
	storedBackend := ""
	for _, r := range m.cfg.Remotes {
		if r.NodeID == peerID {
			storedAddrs = r.RelayAddrs
			storedQUICAddrs = r.DirectQUICAddrs
			publicKey = r.PublicKey
			irohTicket = r.IrohTicket
			storedProtocol = r.Protocol
			storedTargetPort = r.TargetPort
			storedBackend = r.Backend
			break
		}
	}
	backend := strings.TrimSpace(preferredBackend)
	if backend == "" {
		backend = strings.TrimSpace(storedBackend)
	}
	if backend == "" {
		backend = m.activeNetworkBackend()
	}

	if backend == "iroh" {
		if irohTicket == "" {
			return nil, fmt.Errorf("paired remote has no iroh ticket — use a fresh invite link")
		}
		if publicKey != "" {
			var err error
			publicKeyBytes, err = hex.DecodeString(publicKey)
			if err != nil {
				return nil, fmt.Errorf("decode stored public key: %w", err)
			}
			if err := validateIrohTicket(irohTicket, publicKeyBytes); err != nil {
				return nil, err
			}
		}
		irohBackend, getErr := m.backends.MustGet(netbackend.BackendIroh)
		if getErr != nil {
			return nil, getErr
		}
		log.Info("opening iroh pairing stream for trusted reauth", "peer", shortPeer(peerID))
		pairingStream, err := irohBackend.OpenPairing(ctx, netbackend.Target{
			PeerID:     peerID,
			IrohTicket: irohTicket,
		})
		if err != nil {
			log.Warn("open iroh pairing stream for trusted reauth failed", "peer", shortPeer(peerID), "has_ticket", irohTicket != "", "err", err)
			return nil, fmt.Errorf("cannot reach paired host via iroh (host may be offline, not running the iroh backend, or this saved iroh ticket is stale; create a fresh iroh pairing link from the host): %w", err)
		}
		return m.reauthOverStream(ctx, peerID, pairingStream, nil, irohTicket, nil, "", storedProtocol, storedTargetPort, backend, publicKey)
	}

	var btAddrs []string
	directQUICAddrs := storedQUICAddrs
	directQUICEndpoint := ""
	m.mu.Lock()
	discoverer := m.dhtDiscoverer
	recordDiscoverer, _ := m.dhtDiscoverer.(btRecordDiscoverer)
	m.mu.Unlock()
	if backend == "bittorrent_dht" && recordDiscoverer != nil && publicKey != "" {
		lookupCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		rec, err := recordDiscoverer.LookupRecord(lookupCtx, publicKey, peerID)
		cancel()
		if err != nil {
			log.Debug("BitTorrent DHT record lookup failed", "peer", peerID[:12], "err", err)
		} else {
			btAddrs = rec.RelayAddrs
			directQUICAddrs = rec.DirectQUICAddrs
		}
	} else if discoverer != nil && publicKey != "" {
		lookupCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		addrs, err := discoverer.Lookup(lookupCtx, publicKey, peerID)
		cancel()
		if err != nil {
			log.Debug("BitTorrent DHT lookup failed", "peer", peerID[:12], "err", err)
		} else {
			btAddrs = addrs
		}
	}
	if backend == "bittorrent_dht" && len(directQUICAddrs) > 0 && publicKey != "" {
		directQUICEndpoint = quicnet.Endpoint(publicKey, directQUICAddrs[0])
		quicBackend, getErr := m.backends.MustGet(netbackend.BackendBitTorrentDHT)
		if getErr != nil {
			return nil, getErr
		}
		pairingStream, err := quicBackend.OpenPairing(ctx, netbackend.Target{
			PeerID:       peerID,
			QUICEndpoint: directQUICEndpoint,
		})
		if err == nil {
			return m.reauthOverStream(ctx, peerID, pairingStream, nil, "", directQUICAddrs, directQUICEndpoint, storedProtocol, storedTargetPort, backend, publicKey)
		}
		log.Debug("direct QUIC reauth failed, falling back to relay", "peer", peerID[:12], "err", err)
	}

	// Resolve: tries all candidate tiers in parallel, first to connect wins
	resolved, err := m.n.ResolveAddrs(ctx, peerID, presenceAddrs, storedAddrs, btAddrs)
	if err != nil {
		if backend == netbackend.BackendLibp2pDHT {
			return nil, fmt.Errorf("libp2p DHT resolved this paired host, but direct dial failed; use an iroh or relay pairing for NATed networks: %w", err)
		}
		return nil, fmt.Errorf("cannot reach %s: %w", peerID[:12], err)
	}
	relayAddrs := resolved.RelayAddrs
	log.Info("reauth resolved", "peer", peerID[:12], "source", resolved.Source)

	libp2pBackendName := backend
	if libp2pBackendName != netbackend.BackendLibp2pDHT {
		libp2pBackendName = netbackend.BackendLibp2pRelay
	}
	libp2pBackend, getErr := m.backends.MustGet(libp2pBackendName)
	if getErr != nil {
		return nil, getErr
	}
	pairingStream, err := libp2pBackend.OpenPairing(ctx, netbackend.Target{
		PeerID:     peerID,
		RelayAddrs: relayAddrs,
	})
	if err != nil {
		if backend == netbackend.BackendLibp2pDHT {
			return nil, fmt.Errorf("libp2p DHT resolved this paired host, but direct pairing dial failed; use an iroh or relay pairing for NATed networks: %w", err)
		}
		return nil, fmt.Errorf("cannot reach paired host: %w", err)
	}
	return m.reauthOverStream(ctx, peerID, pairingStream, relayAddrs, "", nil, "", storedProtocol, storedTargetPort, backend, publicKey)
}

func (m *Manager) reauthOverStream(ctx context.Context, peerID string, pairingStream io.ReadWriteCloser, relayAddrs []string, irohTicket string, directQUICAddrs []string, quicEndpoint string, storedProtocol string, storedTargetPort int, networkBackend string, publicKey string) (*ConnectResult, error) {
	defer pairingStream.Close()

	// Send PairRequest with code=0 (trusted reauth — no invite code needed)
	log.Info("sending trusted reauth request", "peer", shortPeer(peerID))
	identityProof, err := m.localProof("request", m.n.NodeID(), peerID, nil, nil, nil, "trusted", rendezvous.TimeWindow(time.Now()))
	if err != nil {
		return nil, fmt.Errorf("sign identity proof: %w", err)
	}
	if err := protocol.WriteFrame(pairingStream, protocol.MsgPairRequest, protocol.PairRequest{
		Version:     protocol.Version,
		Mode:        "trusted",
		Label:       m.cfg.Node.Label,
		Attestation: m.localAttestation(),
		Identity:    identityProof,
	}); err != nil {
		log.Warn("send trusted reauth request failed", "peer", shortPeer(peerID), "err", err)
		return nil, fmt.Errorf("send reauth request: %w", err)
	}
	log.Info("trusted reauth request sent", "peer", shortPeer(peerID))

	const reauthResponseTimeout = 30 * time.Second
	clearDeadline := setReadDeadline(pairingStream, time.Now().Add(reauthResponseTimeout))
	log.Info("waiting for trusted reauth response", "peer", shortPeer(peerID), "timeout", reauthResponseTimeout.String())
	msgType, payload, err := readFrameWithContext(ctx, pairingStream)
	clearDeadline()
	if err != nil {
		log.Warn("read trusted reauth response failed", "peer", shortPeer(peerID), "err", err)
		return nil, fmt.Errorf("read reauth response: host did not answer within %s: %w", reauthResponseTimeout, err)
	}
	log.Info("trusted reauth response received", "peer", shortPeer(peerID), "msg_type", msgType)
	if msgType != protocol.MsgPairResponse {
		return nil, fmt.Errorf("unexpected response 0x%02x", msgType)
	}
	var resp protocol.PairResponse
	if err := protocol.Decode(payload, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("reauth rejected: %s", resp.Message)
	}
	if len(resp.SessionToken) == 0 {
		return nil, fmt.Errorf("host did not issue a session token")
	}
	if err := verifyIdentityProof(resp.Identity, resp.Attestation, "response", peerID, m.n.NodeID(), nil, nil, resp.SessionToken, "trusted"); err != nil {
		return nil, fmt.Errorf("host identity proof rejected: %w", err)
	}
	effectiveIrohTicket := irohTicket
	if resp.IrohTicket != "" {
		var publicKeyBytes []byte
		if len(publicKeyBytes) == 0 && publicKey != "" {
			var err error
			publicKeyBytes, err = hex.DecodeString(publicKey)
			if err != nil {
				return nil, fmt.Errorf("decode stored public key: %w", err)
			}
		}
		if len(publicKeyBytes) > 0 {
			if err := validateIrohTicket(resp.IrohTicket, publicKeyBytes); err != nil {
				return nil, fmt.Errorf("host refreshed iroh ticket rejected: %w", err)
			}
		}
		effectiveIrohTicket = resp.IrohTicket
		log.Info("refreshed iroh ticket received during trusted reauth", "peer", shortPeer(peerID))
	}
	resultProtocol := resp.Protocol
	if resultProtocol == "" {
		resultProtocol = storedProtocol
	}
	if resultProtocol == "" {
		resultProtocol = rendezvous.ProtoRDP.String()
	}
	resultTargetPort := resp.TargetPort
	if resultTargetPort == 0 {
		resultTargetPort = storedTargetPort
	}
	if resultTargetPort == 0 {
		resultTargetPort = rendezvous.ParseProtocol(resultProtocol).DefaultPort()
	}
	savedRemote := false
	if resp.Attestation != nil {
		identityBackend, hardware, vendor, version, rootThumbprint := identityInfoFromAttestation(resp.Attestation)
		m.cfg.AddRemote(config.RemoteConfig{
			Label:             resp.HostLabel,
			NodeID:            peerID,
			Backend:           networkBackend,
			Protocol:          resultProtocol,
			TargetPort:        resultTargetPort,
			RelayAddrs:        relayAddrs,
			IrohTicket:        effectiveIrohTicket,
			DirectQUICAddrs:   directQUICAddrs,
			IdentityBackend:   identityBackend,
			HardwareBacked:    hardware,
			TPMVendor:         vendor,
			TPMVersion:        version,
			TPMRootThumbprint: rootThumbprint,
		})
		m.cfg.AddTrustedPeer(config.TrustedPeer{
			NodeID:            peerID,
			Label:             resp.HostLabel,
			Protocol:          resultProtocol,
			TargetPort:        resultTargetPort,
			IdentityBackend:   identityBackend,
			HardwareBacked:    hardware,
			TPMVendor:         vendor,
			TPMVersion:        version,
			TPMRootThumbprint: rootThumbprint,
		})
		m.cfg.Save()
		savedRemote = true
	}
	if resp.IrohTicket != "" && !savedRemote {
		m.cfg.AddRemote(config.RemoteConfig{
			Label:      resp.HostLabel,
			NodeID:     peerID,
			Backend:    networkBackend,
			Protocol:   resultProtocol,
			TargetPort: resultTargetPort,
			IrohTicket: effectiveIrohTicket,
			RelayAddrs: relayAddrs,
		})
		m.cfg.Save()
	}

	return &ConnectResult{
		PeerID:                 peerID,
		RelayAddrs:             relayAddrs,
		IrohTicket:             effectiveIrohTicket,
		BitTorrentQUICEndpoint: quicEndpoint,
		HostLabel:              resp.HostLabel,
		Mode:                   "trusted",
		Protocol:               resultProtocol,
		TargetPort:             resultTargetPort,
		SessionToken:           resp.SessionToken,
	}, nil
}

func setReadDeadline(stream io.ReadWriteCloser, deadline time.Time) func() {
	type readDeadliner interface {
		SetReadDeadline(time.Time) error
	}
	if rd, ok := stream.(readDeadliner); ok {
		if err := rd.SetReadDeadline(deadline); err != nil {
			log.Debug("set stream read deadline failed", "err", err)
			return func() {}
		}
		return func() {
			if err := rd.SetReadDeadline(time.Time{}); err != nil {
				log.Debug("clear stream read deadline failed", "err", err)
			}
		}
	}
	log.Debug("stream read deadline unsupported")
	return func() {}
}

type frameResult struct {
	msgType protocol.MsgType
	payload []byte
	err     error
}

func readFrameWithContext(ctx context.Context, stream io.ReadWriteCloser) (protocol.MsgType, []byte, error) {
	if ctx == nil {
		return protocol.ReadFrame(stream)
	}
	done := make(chan frameResult, 1)
	go func() {
		msgType, payload, err := protocol.ReadFrame(stream)
		done <- frameResult{msgType: msgType, payload: payload, err: err}
	}()
	select {
	case result := <-done:
		return result.msgType, result.payload, result.err
	case <-ctx.Done():
		_ = stream.Close()
		select {
		case result := <-done:
			if result.err != nil {
				return 0, nil, fmt.Errorf("%w: %v", ctx.Err(), result.err)
			}
		case <-time.After(500 * time.Millisecond):
		}
		return 0, nil, ctx.Err()
	}
}

// ConnectResult is returned after a successful pairing handshake.
type ConnectResult struct {
	PeerID                 string
	RelayAddrs             []string
	IrohTicket             string
	BitTorrentQUICEndpoint string
	HostLabel              string
	Mode                   string
	Protocol               string // "rdp" | "vnc" | "ssh" | "custom"
	TargetPort             int    // resolved port (never 0)
	SessionToken           []byte
}

// DiscoveryStatus reports whether the active discovery backend can resolve a
// saved paired remote. It does not authenticate or open an app tunnel.
type DiscoveryStatus struct {
	Online bool
	Source string
	Addrs  []string
	Error  string
}

func (m *Manager) DiscoverRemote(ctx context.Context, remote config.RemoteConfig) DiscoveryStatus {
	backend := m.activeNetworkBackend()
	publicKey := strings.TrimSpace(remote.PublicKey)
	switch backend {
	case "iroh":
		ticket := strings.TrimSpace(remote.IrohTicket)
		if ticket == "" {
			return DiscoveryStatus{Source: "iroh", Error: "paired remote has no iroh ticket"}
		}
		if publicKey != "" {
			publicKeyBytes, err := hex.DecodeString(publicKey)
			if err != nil {
				return DiscoveryStatus{Source: "iroh", Error: "decode stored public key: " + err.Error()}
			}
			if err := validateIrohTicket(ticket, publicKeyBytes); err != nil {
				return DiscoveryStatus{Source: "iroh", Error: err.Error()}
			}
		}
		return DiscoveryStatus{Source: "iroh_cached_ticket", Addrs: []string{"iroh"}, Error: "iroh reachability is checked during connect"}
	case "libp2p_dht":
		if publicKey != "" {
			addrs, err := m.n.FindIdentityAddrs(ctx, publicKey, remote.NodeID)
			if err == nil && len(addrs) > 0 {
				return DiscoveryStatus{Online: true, Source: "libp2p_dht", Addrs: addrs}
			}
			if err != nil {
				return DiscoveryStatus{Source: "libp2p_dht", Error: err.Error()}
			}
		}
		addrs, err := m.n.FindPeerAddrs(ctx, remote.NodeID)
		if err == nil && len(addrs) > 0 {
			return DiscoveryStatus{Online: true, Source: "libp2p_dht", Addrs: addrs}
		}
		if err != nil {
			return DiscoveryStatus{Source: "libp2p_dht", Error: err.Error()}
		}
	case "bittorrent_dht":
		if publicKey == "" {
			return DiscoveryStatus{Source: "bittorrent_dht", Error: "paired remote has no public key"}
		}
		m.mu.Lock()
		discoverer, _ := m.dhtDiscoverer.(btRecordDiscoverer)
		m.mu.Unlock()
		if discoverer == nil {
			return DiscoveryStatus{Source: "bittorrent_dht", Error: "BitTorrent DHT discoverer is not running"}
		}
		rec, err := discoverer.LookupRecord(ctx, publicKey, remote.NodeID)
		if err != nil {
			return DiscoveryStatus{Source: "bittorrent_dht", Error: err.Error()}
		}
		addrs := append([]string{}, rec.DirectQUICAddrs...)
		addrs = append(addrs, rec.RelayAddrs...)
		if len(addrs) > 0 {
			return DiscoveryStatus{Online: true, Source: "bittorrent_dht", Addrs: addrs}
		}
		return DiscoveryStatus{Source: "bittorrent_dht", Error: "record has no reachable addresses"}
	case "libp2p_relay":
		return DiscoveryStatus{Source: "libp2p_relay", Addrs: append([]string{}, remote.RelayAddrs...)}
	}
	return DiscoveryStatus{Error: "unsupported discovery backend: " + backend}
}

// --- helpers ---

func (inv *invite) view() InviteView {
	return InviteView{
		ID:        inv.ID,
		Mode:      inv.Mode,
		Protocol:  inv.Protocol,
		Label:     inv.Label,
		Status:    inv.Status(),
		CreatedAt: inv.CreatedAt,
		ExpiresAt: inv.ExpiresAt,
		UsedBy:    inv.UsedBy,
		UsedByID:  inv.UsedByID,
		UsedAt:    inv.UsedAt,
	}
}

func (m *Manager) activeNetworkBackend() string {
	if m.cfg == nil {
		return "iroh"
	}
	return m.cfg.ActiveNetworkBackend()
}

func (m *Manager) irohEnabled() bool {
	return m.activeNetworkBackend() == "iroh"
}

func (m *Manager) libp2pDHTEnabled() bool {
	return m.activeNetworkBackend() == netbackend.BackendLibp2pDHT
}

func (m *Manager) bitTorrentDHTEnabled() bool {
	return m.activeNetworkBackend() == "bittorrent_dht"
}

func (m *Manager) resolveInviteAddrs(ctx context.Context, peerID string, publicKeyHex string) ([]string, error) {
	return m.resolveInviteAddrsForBackend(ctx, m.activeNetworkBackend(), peerID, publicKeyHex)
}

func (m *Manager) resolveInviteAddrsForBackend(ctx context.Context, backend string, peerID string, publicKeyHex string) ([]string, error) {
	var errs []string
	if backend == netbackend.BackendLibp2pDHT {
		log.Info("invite discovery using libp2p DHT identity provider", "peer", shortPeer(peerID))
		identityCtx, identityCancel := context.WithTimeout(ctx, 45*time.Second)
		addrs, err := m.n.FindIdentityAddrs(identityCtx, publicKeyHex, peerID)
		identityCancel()
		if err == nil {
			log.Info("invite peer resolved via libp2p DHT identity provider", "peer", peerID[:12], "addrs", len(addrs))
			return addrs, nil
		}
		errs = append(errs, "libp2p DHT identity provider: "+err.Error())

		log.Info("invite discovery using libp2p DHT peer lookup", "peer", shortPeer(peerID))
		lookupCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		addrs, err = m.n.FindPeerAddrs(lookupCtx, peerID)
		cancel()
		if err == nil && len(addrs) > 0 {
			log.Info("invite peer resolved via libp2p DHT", "peer", peerID[:12], "addrs", len(addrs))
			return addrs, nil
		}
		if err != nil {
			errs = append(errs, "libp2p DHT: "+err.Error())
		}
		if len(errs) == 0 {
			return nil, fmt.Errorf("libp2p DHT returned no direct addresses")
		}
		return nil, fmt.Errorf("%s", strings.Join(errs, "; "))
	}

	m.mu.Lock()
	discoverer := m.dhtDiscoverer
	m.mu.Unlock()
	if backend == "bittorrent_dht" && discoverer != nil && publicKeyHex != "" {
		log.Info("invite discovery using BitTorrent DHT", "peer", shortPeer(peerID), "public_key", shortPeer(publicKeyHex))
		lookupCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		addrs, err := discoverer.Lookup(lookupCtx, publicKeyHex, peerID)
		cancel()
		if err == nil && len(addrs) > 0 {
			log.Info("invite peer resolved via BitTorrent DHT", "peer", peerID[:12], "addrs", len(addrs))
			return addrs, nil
		}
		if err != nil {
			errs = append(errs, "BitTorrent DHT: "+err.Error())
		}
	}

	if len(errs) == 0 {
		return nil, fmt.Errorf("no discovery backend enabled for %s", backend)
	}
	return nil, fmt.Errorf("%s", strings.Join(errs, "; "))
}

func withIrohTicket(rawURL string, ticket string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set("iroh", ticket)
	u.RawQuery = q.Encode()
	return u.String()
}

func withInviteBackend(rawURL string, backend string) string {
	backend = strings.TrimSpace(backend)
	if backend == "" {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set("backend", backend)
	u.RawQuery = q.Encode()
	return u.String()
}

func withInviteAddrs(rawURL string, peerID string, addrs []string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	if peerID != "" {
		q.Set("peer", peerID)
	}
	for _, addr := range addrs {
		q.Add("addr", addr)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func irohTicketFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("iroh")
}

func inviteBackendFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	switch strings.TrimSpace(u.Query().Get("backend")) {
	case "libp2p_relay", "libp2p_dht", "bittorrent_dht", "iroh":
		return strings.TrimSpace(u.Query().Get("backend"))
	default:
		return ""
	}
}

// InviteNetworkBackend returns the backend requested by an invite URL, when
// one is encoded. If the URL carries an iroh ticket, iroh is required even for
// older links that did not include backend=iroh explicitly.
func InviteNetworkBackend(rawURL string) string {
	if backend := inviteBackendFromURL(rawURL); backend != "" {
		return backend
	}
	if irohTicketFromURL(rawURL) != "" {
		return "iroh"
	}
	return ""
}

// InvitePeerID returns the host peer ID encoded in an invite URL.
func InvitePeerID(rawURL string) string {
	explicitAddrs := inviteAddrsFromURL(rawURL)
	t, err := rendezvous.DecodeURL(rawURL)
	if err != nil {
		return ""
	}
	peerID, err := pubKeyToPeerID(t.PubKey[:])
	if err != nil {
		return ""
	}
	if len(explicitAddrs) > 0 {
		if explicitPeer := invitePeerFromURL(rawURL); explicitPeer != "" {
			return explicitPeer
		}
	}
	return peerID
}

func inviteAddrsFromURL(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	return u.Query()["addr"]
}

func invitePeerFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("peer")
}

func validateIrohTicket(ticket string, publicKey []byte) error {
	id, err := irohnet.TicketEndpointID(ticket)
	if err != nil {
		return fmt.Errorf("invalid iroh ticket: %w", err)
	}
	got := id.Bytes()
	if !strings.EqualFold(hex.EncodeToString(got[:]), hex.EncodeToString(publicKey)) {
		return fmt.Errorf("iroh ticket does not match invite identity")
	}
	return nil
}

func (m *Manager) localAttestation() *protocol.TPMAttestation {
	m.mu.Lock()
	id := m.identity
	m.mu.Unlock()
	return attestationForIdentity(id)
}

func (m *Manager) localProof(role string, signerPeer string, verifierPeer string, inviteID []byte, inviteProof []byte, sessionToken []byte, mode string, window int64) (*protocol.IdentityProof, error) {
	id := m.localProofIdentity()
	if id == nil {
		return nil, fmt.Errorf("identity unavailable")
	}
	proof := &protocol.IdentityProof{
		Backend:    string(id.Backend),
		MachineID:  id.MachineID(),
		TimeWindow: window,
	}
	if proof.Backend == "" {
		proof.Backend = string(identity.BackendSoftware)
	}
	if proof.Backend == string(identity.BackendSoftware) {
		proof.PublicKey = id.PublicKeyRaw()
	}
	if proof.MachineID == "" {
		return nil, fmt.Errorf("machine ID unavailable")
	}
	msg := identityProofMessage(role, signerPeer, verifierPeer, inviteID, inviteProof, sessionToken, mode, window)
	sig, err := id.SignProof(msg)
	if err != nil {
		return nil, err
	}
	proof.Signature = sig
	return proof, nil
}

func (m *Manager) localProofIdentity() *identity.Identity {
	m.mu.Lock()
	id := m.identity
	m.mu.Unlock()
	if id != nil && (id.Signer != nil || id.PrivKey != nil) {
		return id
	}
	priv, err := m.cfg.PrivateKeyBytes()
	if err != nil {
		return nil
	}
	key, err := libp2pcrypto.UnmarshalEd25519PrivateKey(priv)
	if err != nil {
		return nil
	}
	return &identity.Identity{PrivKey: key, Backend: identity.BackendSoftware}
}

func verifyIdentityProof(proof *protocol.IdentityProof, att *protocol.TPMAttestation, role string, signerPeer string, verifierPeer string, inviteID []byte, inviteProof []byte, sessionToken []byte, mode string) error {
	if proof == nil {
		return fmt.Errorf("missing identity proof")
	}
	now := rendezvous.TimeWindow(time.Now())
	validWindow := false
	for _, offset := range []int64{-1, 0, 1} {
		if proof.TimeWindow == now+offset {
			validWindow = true
			break
		}
	}
	if !validWindow {
		return fmt.Errorf("identity proof expired")
	}
	msg := identityProofMessage(role, signerPeer, verifierPeer, inviteID, inviteProof, sessionToken, mode, proof.TimeWindow)
	switch proof.Backend {
	case string(identity.BackendTPM):
		return identity.VerifyTPMProof(attestationBundle(att), proof.MachineID, msg, proof.Signature)
	case string(identity.BackendSoftware), "":
		return identity.VerifySoftwareProof(proof.PublicKey, proof.MachineID, msg, proof.Signature)
	default:
		return fmt.Errorf("unsupported identity proof backend %q", proof.Backend)
	}
}

func identityProofMessage(role string, signerPeer string, verifierPeer string, inviteID []byte, inviteProof []byte, sessionToken []byte, mode string, window int64) []byte {
	var out []byte
	appendString := func(s string) {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
		out = append(out, lenBuf[:]...)
		out = append(out, s...)
	}
	appendBytes := func(b []byte) {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))
		out = append(out, lenBuf[:]...)
		out = append(out, b...)
	}
	appendString("DeskAccess identity proof v1")
	appendString(role)
	appendString(signerPeer)
	appendString(verifierPeer)
	appendString(mode)
	appendBytes(inviteID)
	appendBytes(inviteProof)
	appendBytes(sessionToken)
	var win [8]byte
	binary.BigEndian.PutUint64(win[:], uint64(window))
	out = append(out, win[:]...)
	return out
}

func attestationBundle(att *protocol.TPMAttestation) *identity.AttestationBundle {
	if att == nil {
		return nil
	}
	return &identity.AttestationBundle{
		AKCert:         att.AKCert,
		EKCert:         att.EKCert,
		ManufacturerCA: att.ManufacturerCA,
		Manufacturer:   att.Manufacturer,
		TPMVersion:     att.TPMVersion,
	}
}

func attestationForIdentity(id *identity.Identity) *protocol.TPMAttestation {
	if id == nil || id.Attestation == nil {
		return nil
	}
	return &protocol.TPMAttestation{
		AKCert:         id.Attestation.AKCert,
		EKCert:         id.Attestation.EKCert,
		ManufacturerCA: id.Attestation.ManufacturerCA,
		Manufacturer:   id.Attestation.Manufacturer,
		TPMVersion:     id.Attestation.TPMVersion,
	}
}

func identityInfoFromAttestation(att *protocol.TPMAttestation) (string, bool, string, string, string) {
	if att == nil {
		return string(identity.BackendSoftware), false, "", "", ""
	}
	hardware := att.Manufacturer != "" || att.TPMVersion != "" || len(att.AKCert) > 0 || len(att.EKCert) > 0
	if hardware {
		vendor := strings.TrimSpace(att.Manufacturer)
		if vendor == "" {
			vendor = vendorFromTPMCerts(att)
		}
		return string(identity.BackendTPM), true, vendor, att.TPMVersion, tpmRootThumbprintFromAttestation(att)
	}
	return string(identity.BackendSoftware), false, "", "", ""
}

func tpmRootThumbprintFromAttestation(att *protocol.TPMAttestation) string {
	if att == nil || len(att.ManufacturerCA) == 0 {
		return ""
	}
	sum := sha256.Sum256(att.ManufacturerCA)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func vendorFromTPMCerts(att *protocol.TPMAttestation) string {
	for _, der := range [][]byte{att.EKCert, att.ManufacturerCA} {
		if len(der) == 0 {
			continue
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		if len(cert.Subject.Organization) > 0 {
			return strings.Join(cert.Subject.Organization, ", ")
		}
		if cert.Subject.CommonName != "" {
			return cert.Subject.CommonName
		}
		if len(cert.Issuer.Organization) > 0 {
			return strings.Join(cert.Issuer.Organization, ", ")
		}
		if cert.Issuer.CommonName != "" {
			return cert.Issuer.CommonName
		}
	}
	return ""
}

func defaultLabel(mode, proto string) string {
	p := strings.ToUpper(proto)
	if p == "" {
		p = "RDP"
	}
	if mode == "pairing" {
		return p + " Pairing invite"
	}
	return p + " one-time access"
}

func relayMaskToAddrs(mask byte, hostPeerID string) []string {
	var addrs []string
	for i, relay := range node.PublicRelays {
		if mask&(1<<uint(i)) != 0 {
			addrs = append(addrs, relay+"/p2p-circuit/p2p/"+hostPeerID)
		}
	}
	return addrs
}

func pubKeyToPeerID(pubKeyBytes []byte) (string, error) {
	pub, err := libp2pcrypto.UnmarshalEd25519PublicKey(pubKeyBytes)
	if err != nil {
		return "", err
	}
	pid, err := peer.IDFromPublicKey(pub)
	if err != nil {
		return "", err
	}
	return pid.String(), nil
}

func newID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b) // e.g. "a3f2b1c9"
}

func shortPeer(peerID string) string {
	if len(peerID) <= 12 {
		return peerID
	}
	return peerID[:12]
}

func inviteKey(id []byte) string {
	return hex.EncodeToString(id)
}

// ed25519PubKey is kept for backward compat but the actual assertion is done explicitly above

func (m *Manager) sweepLoop() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for _, inv := range m.invites {
			// Remove used/revoked/expired invites older than 24h (keep for audit trail)
			expired := !inv.ExpiresAt.IsZero() &&
				inv.ExpiresAt.Before(time.Now().Add(99*365*24*time.Hour)) &&
				now.After(inv.ExpiresAt)
			if expired {
				delete(m.byInviteID, inviteKey(inv.InviteID[:]))
			}
		}
		// Hard-cap: trim oldest when over limit
		if len(m.invites) > maxStoredInvites {
			type aged struct {
				id string
				t  time.Time
			}
			items := make([]aged, 0, len(m.invites))
			for id, inv := range m.invites {
				items = append(items, aged{id, inv.CreatedAt})
			}
			sort.Slice(items, func(i, j int) bool { return items[i].t.Before(items[j].t) })
			for _, item := range items[:len(items)-maxStoredInvites] {
				if inv, ok := m.invites[item.id]; ok {
					delete(m.byInviteID, inviteKey(inv.InviteID[:]))
					delete(m.invites, item.id)
				}
			}
		}
		m.mu.Unlock()
	}
}

// network.Stream import kept for SetPairingHandler signature
