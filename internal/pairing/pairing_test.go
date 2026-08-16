package pairing_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	urlpkg "net/url"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/rdpanywhere/rdpanywhere/internal/config"
	"github.com/rdpanywhere/rdpanywhere/internal/netbackend"
	"github.com/rdpanywhere/rdpanywhere/internal/node"
	"github.com/rdpanywhere/rdpanywhere/internal/pairing"
	"github.com/rdpanywhere/rdpanywhere/internal/rendezvous"
)

// ── test setup helpers ────────────────────────────────────────────────────────

func newTestConfig(t *testing.T, label string) *config.Config {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &config.Config{
		Node: config.NodeConfig{Label: label, PrivateKey: hex.EncodeToString(priv)},
		Network: config.NetworkConfig{
			ShareBackend: "libp2p_relay",
		},
		Relay: config.RelayConfig{
			Mode:    "custom",
			Servers: []string{"/ip4/127.0.0.1/tcp/4001/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"},
		},
		Iroh: config.IrohConfig{Mode: "disabled"},
		RDP:  config.RDPConfig{TargetAddr: "127.0.0.1:3389", Protocol: "rdp"},
	}
}

func newLibp2pHost(t *testing.T, cfgs ...*config.Config) host.Host {
	t.Helper()
	opts := []libp2p.Option{
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.DisableRelay(),
	}
	if len(cfgs) > 0 && cfgs[0] != nil {
		privBytes, err := cfgs[0].PrivateKeyBytes()
		if err != nil {
			t.Fatalf("priv key bytes: %v", err)
		}
		key, err := libp2pcrypto.UnmarshalEd25519PrivateKey(privBytes)
		if err != nil {
			t.Fatalf("unmarshal key: %v", err)
		}
		opts = append(opts, libp2p.Identity(key))
	}
	h, err := libp2p.New(
		opts...,
	)
	if err != nil {
		t.Fatalf("create libp2p host: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

// newTestNode wraps a libp2p host as a node.Node for tests.
// Returns a node that uses in-process loopback connections — no relay needed.
func newTestNode(t *testing.T, h host.Host, cfg *config.Config) *node.Node {
	t.Helper()
	privBytes, err := cfg.PrivateKeyBytes()
	if err != nil {
		t.Fatalf("priv key bytes: %v", err)
	}
	libp2pKey, err := libp2pcrypto.UnmarshalEd25519PrivateKey(privBytes)
	if err != nil {
		t.Fatalf("unmarshal key: %v", err)
	}
	_ = libp2pKey
	return node.NewFromHost(h, cfg)
}

func newManager(t *testing.T, cfg *config.Config) *pairing.Manager {
	t.Helper()
	h := newLibp2pHost(t, cfg)
	n := newTestNode(t, h, cfg)
	return pairing.New(n, cfg)
}

// ── token / URL generation tests ─────────────────────────────────────────────

func TestGenerateURL_OnetimeRDP(t *testing.T) {
	cfg := newTestConfig(t, "host-pc")
	mgr := newManager(t, cfg)

	url, view, err := mgr.GenerateURL("onetime", 15*time.Minute, "For Alice", "rdp", 3389)
	if err != nil {
		t.Fatalf("GenerateURL: %v", err)
	}

	// URL must be well-formed
	if url == "" {
		t.Fatal("URL is empty")
	}
	parsedURL, err := urlpkg.Parse(url)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	if got := parsedURL.Query().Get("v"); got != "1" {
		t.Fatalf("invite version = %q, want 1", got)
	}
	tok, err := rendezvous.DecodeURL(url)
	if err != nil {
		t.Fatalf("DecodeURL: %v", err)
	}

	// Token fields
	if tok.IsExpired() {
		t.Error("fresh token should not be expired")
	}
	if tok.ModeString() != "onetime" {
		t.Errorf("mode: want onetime, got %s", tok.ModeString())
	}
	if tok.Protocol != rendezvous.ProtoRDP {
		t.Errorf("protocol: want RDP, got %v", tok.Protocol)
	}
	if tok.Port() != 3389 {
		t.Errorf("port: want 3389, got %d", tok.Port())
	}
	if tok.InviteID == [rendezvous.InviteIDSize]byte{} {
		t.Error("invite id should be random")
	}
	if tok.InviteSecret == [rendezvous.InviteSecretSize]byte{} {
		t.Error("invite secret should be random")
	}

	// InviteView fields
	if view.Mode != "onetime" {
		t.Errorf("view.mode: want onetime, got %s", view.Mode)
	}
	if view.Label != "For Alice" {
		t.Errorf("view.label: want 'For Alice', got %s", view.Label)
	}
	if view.Protocol != "rdp" {
		t.Errorf("view.protocol: want rdp, got %s", view.Protocol)
	}
	if view.Status != "pending" {
		t.Errorf("view.status: want pending, got %s", view.Status)
	}
}

func TestConnectByURL_UnsupportedInviteVersionAsksUpgrade(t *testing.T) {
	cfg := newTestConfig(t, "client")
	mgr := newManager(t, cfg)
	rawURL, _, err := mgr.GenerateURL("onetime", 15*time.Minute, "", "rdp", 3389)
	if err != nil {
		t.Fatalf("GenerateURL: %v", err)
	}
	parsed, err := urlpkg.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse invite URL: %v", err)
	}
	q := parsed.Query()
	q.Set("v", "2")
	parsed.RawQuery = q.Encode()

	_, err = mgr.ConnectByURL(context.Background(), parsed.String())
	if err == nil {
		t.Fatal("ConnectByURL succeeded for unsupported invite version")
	}
	if !strings.Contains(err.Error(), "upgrade DeskAccess") {
		t.Fatalf("error = %q, want upgrade guidance", err.Error())
	}
}

func TestGenerateURL_PairingVNC(t *testing.T) {
	cfg := newTestConfig(t, "host")
	mgr := newManager(t, cfg)

	url, view, err := mgr.GenerateURL("pairing", time.Hour, "", "vnc", 5901)
	if err != nil {
		t.Fatalf("GenerateURL pairing: %v", err)
	}

	tok, _ := rendezvous.DecodeURL(url)
	if tok.Mode != 1 {
		t.Errorf("pairing mode byte: want 1, got %d", tok.Mode)
	}
	if tok.Protocol != rendezvous.ProtoVNC {
		t.Errorf("protocol: want VNC, got %v", tok.Protocol)
	}
	if tok.TargetPort != 5901 {
		t.Errorf("port: want 5901, got %d", tok.TargetPort)
	}
	if view.Protocol != "vnc" {
		t.Errorf("view protocol: want vnc, got %s", view.Protocol)
	}
}

func TestGenerateURL_SSH(t *testing.T) {
	cfg := newTestConfig(t, "host")
	mgr := newManager(t, cfg)

	url, _, err := mgr.GenerateURL("onetime", 30*time.Minute, "", "ssh", 22)
	if err != nil {
		t.Fatalf("GenerateURL ssh: %v", err)
	}
	tok, _ := rendezvous.DecodeURL(url)
	if tok.Protocol != rendezvous.ProtoSSH {
		t.Errorf("protocol: want SSH, got %v", tok.Protocol)
	}
	if tok.Port() != 22 {
		t.Errorf("port: want 22, got %d", tok.Port())
	}
}

func TestGenerateURL_NoExpiry(t *testing.T) {
	cfg := newTestConfig(t, "host")
	mgr := newManager(t, cfg)

	_, view, err := mgr.GenerateURL("pairing", 0, "forever", "rdp", 3389)
	if err != nil {
		t.Fatalf("no-expiry GenerateURL: %v", err)
	}
	if !view.ExpiresAt.IsZero() {
		t.Errorf("no-expiry view should have zero ExpiresAt, got %v", view.ExpiresAt)
	}
}

func TestGenerateURL_MultipleLinks(t *testing.T) {
	cfg := newTestConfig(t, "host")
	mgr := newManager(t, cfg)

	// Should be able to generate many links without errors
	seen := map[string]bool{}
	for i := 0; i < 10; i++ {
		url, _, err := mgr.GenerateURL("onetime", time.Hour, fmt.Sprintf("user%d", i), "rdp", 3389)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if seen[url] {
			t.Fatalf("duplicate URL generated at iteration %d", i)
		}
		seen[url] = true
	}
	// All 10 should appear in the invite list
	if got := len(mgr.ListInvites()); got != 10 {
		t.Errorf("invite list: want 10, got %d", got)
	}
}

func TestGenerateURL_PairingReusesActiveLinkForBackend(t *testing.T) {
	cfg := newTestConfig(t, "host")
	cfg.Network.ShareBackend = "bittorrent_dht"
	cfg.Relay.Mode = "disabled"
	cfg.BTDHT.Mode = "public"
	cfg.NormalizeNetworkBackend()
	mgr := newManager(t, cfg)

	firstURL, firstView, err := mgr.GenerateURL("pairing", time.Hour, "first", "rdp", 3389)
	if err != nil {
		t.Fatalf("first GenerateURL: %v", err)
	}
	secondURL, secondView, err := mgr.GenerateURL("pairing", time.Hour, "second", "rdp", 3389)
	if err != nil {
		t.Fatalf("second GenerateURL: %v", err)
	}

	if secondURL != firstURL {
		t.Fatalf("pairing URL was regenerated; first=%q second=%q", firstURL, secondURL)
	}
	if secondView.ID != firstView.ID {
		t.Fatalf("pairing invite ID = %q, want %q", secondView.ID, firstView.ID)
	}
	if got := len(mgr.ListInvites()); got != 1 {
		t.Fatalf("invite list = %d, want 1", got)
	}
}

func TestGenerateURL_PairingBackendChangeDeletesOldPendingLink(t *testing.T) {
	cfg := newTestConfig(t, "host")
	cfg.Network.ShareBackend = "bittorrent_dht"
	cfg.Relay.Mode = "disabled"
	cfg.BTDHT.Mode = "public"
	cfg.DHT.Mode = "public"
	cfg.NormalizeNetworkBackend()
	mgr := newManager(t, cfg)

	oldURL, _, err := mgr.GenerateURL("pairing", time.Hour, "bt", "rdp", 3389)
	if err != nil {
		t.Fatalf("bt GenerateURL: %v", err)
	}

	cfg.Network.ShareBackend = "libp2p_dht"
	cfg.NormalizeNetworkBackend()
	deleted := mgr.DeletePendingPairingInvitesExceptBackend(cfg.ActiveNetworkBackend())
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}

	newURL, _, err := mgr.GenerateURL("pairing", time.Hour, "dht", "rdp", 3389)
	if err != nil {
		t.Fatalf("dht GenerateURL: %v", err)
	}
	if newURL == oldURL {
		t.Fatal("backend change reused old pairing URL")
	}
	invites := mgr.ListInvites()
	if len(invites) != 1 {
		t.Fatalf("invite list = %d, want 1", len(invites))
	}
	if got := pairing.InviteNetworkBackend(newURL); got != "libp2p_dht" {
		t.Fatalf("new invite backend = %q, want libp2p_dht", got)
	}
}

// ── invite proof verification tests ───────────────────────────────────────────

func TestVerify_CorrectProof(t *testing.T) {
	cfg := newTestConfig(t, "host")
	mgr := newManager(t, cfg)

	url, _, err := mgr.GenerateURL("onetime", 15*time.Minute, "", "rdp", 3389)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	tok, _ := rendezvous.DecodeURL(url)

	if err := mgr.TestVerifyAndConsume(tok, "client-peer"); err != nil {
		t.Fatalf("correct proof should be accepted: %v", err)
	}
}

func TestVerify_OneTimeUseEnforced(t *testing.T) {
	cfg := newTestConfig(t, "host")
	mgr := newManager(t, cfg)

	url, _, _ := mgr.GenerateURL("onetime", 15*time.Minute, "", "rdp", 3389)
	tok, _ := rendezvous.DecodeURL(url)

	// First use: OK
	if err := mgr.TestVerifyAndConsume(tok, "client-peer"); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	// Second use: must fail
	if err := mgr.TestVerifyAndConsume(tok, "client-peer"); err == nil {
		t.Error("replay: second use of same invite proof should be rejected")
	}
}

func TestVerify_PairingInviteReusableUntilRevoked(t *testing.T) {
	cfg := newTestConfig(t, "host")
	mgr := newManager(t, cfg)

	url, _, err := mgr.GenerateURL("pairing", 15*time.Minute, "", "rdp", 3389)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	tok, _ := rendezvous.DecodeURL(url)

	if err := mgr.TestVerifyAndConsume(tok, "client-peer"); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if err := mgr.TestVerifyAndConsume(tok, "client-peer"); err != nil {
		t.Fatalf("second use of same pairing invite should be accepted: %v", err)
	}
	if err := mgr.TestVerifyAndConsume(tok, "other-peer"); err != nil {
		t.Fatalf("another machine should be able to use active pairing invite: %v", err)
	}
}

func TestVerify_WrongProof(t *testing.T) {
	cfg := newTestConfig(t, "host")
	mgr := newManager(t, cfg)

	url, _, _ := mgr.GenerateURL("onetime", 15*time.Minute, "", "rdp", 3389)
	tok, _ := rendezvous.DecodeURL(url)
	tok.InviteSecret[0] ^= 0xff
	if err := mgr.TestVerifyAndConsume(tok, "client-peer"); err == nil {
		t.Error("wrong proof should be rejected")
	}
}

func TestVerify_ExpiredInvite(t *testing.T) {
	cfg := newTestConfig(t, "host")
	mgr := newManager(t, cfg)

	// Generate with a normal TTL, then manually expire it
	url, _, _ := mgr.GenerateURL("onetime", time.Hour, "", "rdp", 3389)
	tok, _ := rendezvous.DecodeURL(url)

	mgr.TestExpireInvite(tok) // set expiry to past

	if err := mgr.TestVerifyAndConsume(tok, "client-peer"); err == nil {
		t.Error("expired invite should be rejected")
	}
}

func TestVerify_RevokedInvite(t *testing.T) {
	cfg := newTestConfig(t, "host")
	mgr := newManager(t, cfg)

	url, view, _ := mgr.GenerateURL("onetime", 15*time.Minute, "", "rdp", 3389)
	tok, _ := rendezvous.DecodeURL(url)

	// Revoke before use
	if err := mgr.RevokeInvite(view.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Verify should fail
	if err := mgr.TestVerifyAndConsume(tok, "client-peer"); err == nil {
		t.Error("revoked invite should be rejected")
	}
}

// ── invite registry tests ─────────────────────────────────────────────────────

func TestInviteList_Empty(t *testing.T) {
	cfg := newTestConfig(t, "host")
	mgr := newManager(t, cfg)
	if l := mgr.ListInvites(); len(l) != 0 {
		t.Errorf("want 0 invites initially, got %d", len(l))
	}
}

func TestInviteList_SortedNewestFirst(t *testing.T) {
	cfg := newTestConfig(t, "host")
	mgr := newManager(t, cfg)

	mgr.GenerateURL("onetime", time.Hour, "first", "rdp", 3389)
	time.Sleep(time.Millisecond) // ensure distinct timestamps
	mgr.GenerateURL("pairing", time.Hour, "second", "rdp", 3389)

	invites := mgr.ListInvites()
	if len(invites) != 2 {
		t.Fatalf("want 2, got %d", len(invites))
	}
	// Newest (second) should be first in list
	if invites[0].Label != "second" {
		t.Errorf("want newest first, got %s", invites[0].Label)
	}
}

func TestInviteRename(t *testing.T) {
	cfg := newTestConfig(t, "host")
	mgr := newManager(t, cfg)

	_, view, _ := mgr.GenerateURL("onetime", time.Hour, "Old", "rdp", 3389)
	if err := mgr.RenameInvite(view.ID, "New"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if mgr.ListInvites()[0].Label != "New" {
		t.Errorf("label not updated")
	}
}

func TestInviteRevoke_StatusChange(t *testing.T) {
	cfg := newTestConfig(t, "host")
	mgr := newManager(t, cfg)

	_, view, _ := mgr.GenerateURL("onetime", time.Hour, "", "rdp", 3389)
	if mgr.ListInvites()[0].Status != "pending" {
		t.Fatal("should be pending initially")
	}
	mgr.RevokeInvite(view.ID)
	if got := len(mgr.ListInvites()); got != 0 {
		t.Errorf("revoked invite should be deleted, got %d invites", got)
	}
}

func TestInviteRevoke_NotFound(t *testing.T) {
	cfg := newTestConfig(t, "host")
	mgr := newManager(t, cfg)
	if err := mgr.RevokeInvite("nonexistent-id"); err == nil {
		t.Error("revoking nonexistent invite should return error")
	}
}

func TestGeneratedInviteCarriesNetworkBackend(t *testing.T) {
	cfg := newTestConfig(t, "host")
	cfg.Network.ShareBackend = "bittorrent_dht"
	cfg.Iroh.Mode = "disabled"
	cfg.BTDHT.Mode = "public"
	cfg.NormalizeNetworkBackend()
	mgr := newManager(t, cfg)

	rawURL, _, err := mgr.GenerateURL("pairing", time.Hour, "", "rdp", 3389)
	if err != nil {
		t.Fatalf("GenerateURL: %v", err)
	}
	parsed, err := urlpkg.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse invite URL: %v", err)
	}
	if got := parsed.Query().Get("backend"); got != "bittorrent_dht" {
		t.Fatalf("backend = %q, want bittorrent_dht", got)
	}
}

func TestLibp2pDHTInviteDoesNotFallbackToOtherBackends(t *testing.T) {
	cfg := newTestConfig(t, "host")
	cfg.Network.ShareBackend = "libp2p_dht"
	cfg.Iroh.Mode = "disabled"
	cfg.DHT.Mode = "public"
	cfg.BTDHT.Mode = "disabled"
	cfg.Relay.Mode = "disabled"
	cfg.NormalizeNetworkBackend()
	n := newTestNode(t, newLibp2pHost(t, cfg), cfg)

	backend := netbackend.NewLibp2p(n)
	_, err := backend.OpenPairingSession(context.Background(), netbackend.PairingTarget{
		Backend:      netbackend.BackendLibp2pDHT,
		PeerID:       n.NodeID(),
		PublicKeyHex: "",
	})
	if err == nil {
		t.Fatal("expected DHT resolution to fail without falling back")
	}
}

// ── full pairing integration test ─────────────────────────────────────────────

// TestFullPairingFlow creates two in-process libp2p nodes, has the host generate
// a pairing URL, and the client connect using it. Verifies both sides store
// the correct state and the invite is marked used.
func TestFullPairingFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test — skipped in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// ── host setup ──────────────────────────────────────────────────────────
	hostCfg := newTestConfig(t, "home-pc")
	hostH := newLibp2pHost(t, hostCfg)
	hostN := node.NewFromHost(hostH, hostCfg)
	hostMgr := pairing.New(hostN, hostCfg)

	// ── admin/client setup ──────────────────────────────────────────────────
	adminCfg := newTestConfig(t, "admin-laptop")
	adminH := newLibp2pHost(t, adminCfg)
	adminN := node.NewFromHost(adminH, adminCfg)
	adminMgr := pairing.New(adminN, adminCfg)

	// Direct in-process connection (no relay needed for tests)
	hostInfo := peer.AddrInfo{ID: hostH.ID(), Addrs: hostH.Addrs()}
	if err := adminH.Connect(ctx, hostInfo); err != nil {
		t.Fatalf("connect: %v", err)
	}

	// ── host generates pairing URL ──────────────────────────────────────────
	// Inject loopback addrs directly so the client can reach the host
	// without going through a relay.
	// Convert multiaddrs to strings for GenerateURLWithAddrs
	var addrStrs []string
	for _, a := range hostH.Addrs() {
		addrStrs = append(addrStrs, a.String()+"/p2p/"+hostH.ID().String())
	}

	pairingURL, view, err := hostMgr.GenerateURLWithAddrs(
		"pairing", 15*time.Minute, "Test invite", "rdp", 3389, addrStrs,
	)
	if err != nil {
		t.Fatalf("GenerateURL: %v", err)
	}
	t.Logf("URL: %s", pairingURL)
	t.Logf("Invite: id=%s status=%s", view.ID, view.Status)

	// ── admin uses the URL ──────────────────────────────────────────────────
	result, err := adminMgr.ConnectByURL(ctx, pairingURL)
	if err != nil {
		t.Fatalf("ConnectByURL: %v", err)
	}

	// ── assertions ─────────────────────────────────────────────────────────
	if result.Mode != "pairing" {
		t.Errorf("mode: want pairing, got %s", result.Mode)
	}
	if result.HostLabel != "home-pc" {
		t.Errorf("host label: want 'home-pc', got %s", result.HostLabel)
	}

	// Admin should have stored home-pc as a remote
	if len(adminCfg.Remotes) != 1 {
		t.Fatalf("admin remotes: want 1, got %d", len(adminCfg.Remotes))
	}
	if adminCfg.Remotes[0].Label != "home-pc" {
		t.Errorf("remote label: want 'home-pc', got %q", adminCfg.Remotes[0].Label)
	}

	// Host should have stored admin as trusted
	if len(hostCfg.Trusted) != 1 {
		t.Fatalf("host trusted: want 1, got %d", len(hostCfg.Trusted))
	}
	if hostCfg.Trusted[0].Label != "admin-laptop" {
		t.Errorf("trusted label: want 'admin-laptop', got %q", hostCfg.Trusted[0].Label)
	}

	// Pairing invite should remain active, while recording the last paired label.
	invites := hostMgr.ListInvites()
	if len(invites) != 1 {
		t.Fatalf("invites: want 1, got %d", len(invites))
	}
	if invites[0].Status != "pending" {
		t.Errorf("invite status: want pending, got %s", invites[0].Status)
	}
	if invites[0].UsedBy != "admin-laptop" {
		t.Errorf("used_by: want 'admin-laptop', got %s", invites[0].UsedBy)
	}

	t.Logf("✓ Pairing complete: %s ↔ %s", adminCfg.Node.Label, hostCfg.Node.Label)
}

// TestFullPairingFlow_ReplayPrevented verifies the same URL cannot be used twice.
func TestFullPairingFlow_ReplayPrevented(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test — skipped in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	hostCfg := newTestConfig(t, "host")
	hostH := newLibp2pHost(t, hostCfg)
	hostMgr := pairing.New(node.NewFromHost(hostH, hostCfg), hostCfg)

	admin1Cfg := newTestConfig(t, "admin1")
	admin1H := newLibp2pHost(t, admin1Cfg)
	admin1Mgr := pairing.New(node.NewFromHost(admin1H, admin1Cfg), admin1Cfg)

	admin2Cfg := newTestConfig(t, "admin2")
	admin2H := newLibp2pHost(t, admin2Cfg)
	admin2Mgr := pairing.New(node.NewFromHost(admin2H, admin2Cfg), admin2Cfg)

	hostInfo := peer.AddrInfo{ID: hostH.ID(), Addrs: hostH.Addrs()}
	admin1H.Connect(ctx, hostInfo)
	admin2H.Connect(ctx, hostInfo)

	var addrStrs2 []string
	for _, a := range hostH.Addrs() {
		addrStrs2 = append(addrStrs2, a.String()+"/p2p/"+hostH.ID().String())
	}
	url, _, err := hostMgr.GenerateURLWithAddrs("onetime", 15*time.Minute, "", "rdp", 3389, addrStrs2)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// First use: success
	if _, err := admin1Mgr.ConnectByURL(ctx, url); err != nil {
		t.Fatalf("first connect: %v", err)
	}

	// Second use with same URL: must fail
	if _, err := admin2Mgr.ConnectByURL(ctx, url); err == nil {
		t.Error("replay attack: second use of same one-time URL should be rejected")
	} else {
		t.Logf("✓ Replay correctly rejected: %v", err)
	}
	if hostCfg.IsTrusted(admin1H.ID().String()) {
		t.Fatal("one-time invite user should not be added to host allowed list")
	}
	if hostCfg.IsTrusted(admin2H.ID().String()) {
		t.Fatal("rejected one-time invite user should not be added to host allowed list")
	}
}

func TestPairingInviteReusableAndTrustedReauthWorks(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test — skipped in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	hostCfg := newTestConfig(t, "host")
	hostH := newLibp2pHost(t, hostCfg)
	hostMgr := pairing.New(node.NewFromHost(hostH, hostCfg), hostCfg)

	adminCfg := newTestConfig(t, "admin")
	adminH := newLibp2pHost(t, adminCfg)
	adminMgr := pairing.New(node.NewFromHost(adminH, adminCfg), adminCfg)

	hostInfo := peer.AddrInfo{ID: hostH.ID(), Addrs: hostH.Addrs()}
	if err := adminH.Connect(ctx, hostInfo); err != nil {
		t.Fatalf("connect: %v", err)
	}

	var addrs []string
	for _, a := range hostH.Addrs() {
		addrs = append(addrs, a.String()+"/p2p/"+hostH.ID().String())
	}
	url, _, err := hostMgr.GenerateURLWithAddrs("pairing", 15*time.Minute, "", "vnc", 5901, addrs)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	first, err := adminMgr.ConnectByURL(ctx, url)
	if err != nil {
		t.Fatalf("first connect: %v", err)
	}
	if first.Protocol != "vnc" || first.TargetPort != 5901 {
		t.Fatalf("first target = %s/%d, want vnc/5901", first.Protocol, first.TargetPort)
	}
	if _, err := adminMgr.ConnectByURL(ctx, url); err != nil {
		t.Fatalf("same trusted peer should be able to reuse active pairing URL: %v", err)
	}
	paired, err := adminMgr.ReauthPaired(ctx, hostH.ID().String())
	if err != nil {
		t.Fatalf("paired reconnect should reauth without link: %v", err)
	}
	if paired.Protocol != "vnc" || paired.TargetPort != 5901 {
		t.Fatalf("paired reconnect target = %s/%d, want vnc/5901", paired.Protocol, paired.TargetPort)
	}
}
