package config

import (
	"testing"
	"time"
)

func TestDefaultNetworkBackendIsIroh(t *testing.T) {
	cfg := defaultConfig
	cfg.NormalizeNetworkBackend()

	if got := cfg.ActiveNetworkBackend(); got != "iroh" {
		t.Fatalf("ActiveNetworkBackend() = %q, want iroh", got)
	}
	if cfg.Iroh.Mode != "public" {
		t.Fatalf("Iroh.Mode = %q, want public", cfg.Iroh.Mode)
	}
	if cfg.Relay.Mode != "disabled" {
		t.Fatalf("Relay.Mode = %q, want disabled", cfg.Relay.Mode)
	}
}

func TestNormalizeNetworkBackendFallsBackToIroh(t *testing.T) {
	cfg := Config{}
	cfg.NormalizeNetworkBackend()

	if got := cfg.ActiveNetworkBackend(); got != "iroh" {
		t.Fatalf("ActiveNetworkBackend() = %q, want iroh", got)
	}
	if cfg.Iroh.Mode != "public" {
		t.Fatalf("Iroh.Mode = %q, want public", cfg.Iroh.Mode)
	}
}

func TestNormalizeNetworkBackendMigratesOldRelayDefaultToIroh(t *testing.T) {
	cfg := Config{
		Relay: RelayConfig{Mode: "public"},
		DHT:   DHTConfig{Mode: "disabled"},
		BTDHT: BTDHTConfig{Mode: "disabled"},
		Iroh:  IrohConfig{Mode: "disabled"},
	}
	cfg.NormalizeNetworkBackend()

	if got := cfg.ActiveNetworkBackend(); got != "iroh" {
		t.Fatalf("ActiveNetworkBackend() = %q, want iroh", got)
	}
	if cfg.Iroh.Mode != "public" {
		t.Fatalf("Iroh.Mode = %q, want public", cfg.Iroh.Mode)
	}
	if cfg.Relay.Mode != "public" {
		t.Fatalf("Relay.Mode = %q, want public", cfg.Relay.Mode)
	}
}

func TestNormalizeNetworkBackendPreservesIndependentBackends(t *testing.T) {
	cfg := Config{
		Network: NetworkConfig{ShareBackend: "iroh"},
		Relay:   RelayConfig{Mode: "custom", Servers: []string{"/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWExample"}},
		DHT:     DHTConfig{Mode: "public"},
		BTDHT:   BTDHTConfig{Mode: "public"},
		Iroh:    IrohConfig{Mode: "public"},
	}
	cfg.NormalizeNetworkBackend()

	if got := cfg.ActiveNetworkBackend(); got != "iroh" {
		t.Fatalf("ActiveNetworkBackend() = %q, want iroh", got)
	}
	if cfg.Relay.Mode != "custom" || cfg.DHT.Mode != "public" || cfg.BTDHT.Mode != "public" || cfg.Iroh.Mode != "public" {
		t.Fatalf("backend modes were not preserved: relay=%q dht=%q btdht=%q iroh=%q",
			cfg.Relay.Mode, cfg.DHT.Mode, cfg.BTDHT.Mode, cfg.Iroh.Mode)
	}
}

func TestTrustedPeerMergeUpdatesTPMRootThumbprint(t *testing.T) {
	cfg := Config{}
	cfg.AddTrustedPeer(TrustedPeer{
		NodeID:            "peer-1",
		Label:             "old",
		IdentityBackend:   "software",
		TPMRootThumbprint: "",
	})

	cfg.AddTrustedPeer(TrustedPeer{
		NodeID:            "peer-1",
		Label:             "new",
		IdentityBackend:   "tpm",
		HardwareBacked:    true,
		TPMVendor:         "Vendor TPM",
		TPMVersion:        "2.0",
		TPMRootThumbprint: "ABCDEF0123456789",
	})

	got, ok := cfg.TrustedPeer("peer-1")
	if !ok {
		t.Fatal("trusted peer not found")
	}
	if got.TPMRootThumbprint != "ABCDEF0123456789" {
		t.Fatalf("TPMRootThumbprint = %q, want ABCDEF0123456789", got.TPMRootThumbprint)
	}
	if !got.HardwareBacked || got.IdentityBackend != "tpm" || got.TPMVendor != "Vendor TPM" || got.TPMVersion != "2.0" {
		t.Fatalf("identity metadata not merged: %+v", got)
	}
}

func TestTrustedPeerMergeByTPMRootThumbprint(t *testing.T) {
	cfg := Config{}
	cfg.AddTrustedPeer(TrustedPeer{
		NodeID:            "peer-old",
		Label:             "old laptop",
		IdentityBackend:   "tpm",
		HardwareBacked:    true,
		TPMRootThumbprint: "ROOT123",
	})

	cfg.AddTrustedPeer(TrustedPeer{
		NodeID:            "peer-new",
		Label:             "new laptop name",
		Protocol:          "rdp",
		TargetPort:        3389,
		IdentityBackend:   "tpm",
		HardwareBacked:    true,
		TPMRootThumbprint: "ROOT123",
	})

	if len(cfg.Trusted) != 1 {
		t.Fatalf("trusted entries = %d, want 1: %+v", len(cfg.Trusted), cfg.Trusted)
	}
	got := cfg.Trusted[0]
	if got.NodeID != "peer-new" {
		t.Fatalf("NodeID = %q, want peer-new", got.NodeID)
	}
	if got.Label != "new laptop name" || got.Protocol != "rdp" || got.TargetPort != 3389 {
		t.Fatalf("trusted peer was not updated: %+v", got)
	}
}

func TestTrustedPeerMergeTracksLastConnectedWithoutResettingAddedAt(t *testing.T) {
	added := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	firstConnect := added.Add(time.Minute)
	secondConnect := added.Add(time.Hour)
	cfg := Config{}
	cfg.AddTrustedPeer(TrustedPeer{
		NodeID:          "peer-1",
		Label:           "admin laptop",
		AddedAt:         added,
		LastConnectedAt: firstConnect,
	})

	cfg.AddTrustedPeer(TrustedPeer{
		NodeID:          "peer-1",
		Label:           "admin laptop",
		LastConnectedAt: secondConnect,
	})

	got, ok := cfg.TrustedPeer("peer-1")
	if !ok {
		t.Fatal("trusted peer not found")
	}
	if !got.AddedAt.Equal(added) {
		t.Fatalf("AddedAt = %s, want %s", got.AddedAt, added)
	}
	if !got.LastConnectedAt.Equal(secondConnect) {
		t.Fatalf("LastConnectedAt = %s, want %s", got.LastConnectedAt, secondConnect)
	}
}

func TestRemoteMergeTracksLastConnectedWithoutResettingAddedAt(t *testing.T) {
	added := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	firstConnect := added.Add(time.Minute)
	secondConnect := added.Add(time.Hour)
	cfg := Config{}
	cfg.AddRemote(RemoteConfig{
		NodeID:          "peer-1",
		Label:           "office pc",
		AddedAt:         added,
		LastConnectedAt: firstConnect,
	})

	cfg.AddRemote(RemoteConfig{
		NodeID:          "peer-1",
		Label:           "office pc",
		LastConnectedAt: secondConnect,
	})

	if len(cfg.Remotes) != 1 {
		t.Fatalf("remotes = %d, want 1", len(cfg.Remotes))
	}
	got := cfg.Remotes[0]
	if !got.AddedAt.Equal(added) {
		t.Fatalf("AddedAt = %s, want %s", got.AddedAt, added)
	}
	if !got.LastConnectedAt.Equal(secondConnect) {
		t.Fatalf("LastConnectedAt = %s, want %s", got.LastConnectedAt, secondConnect)
	}
}

func TestRemoteServicesAreSeparatePerProtocolAndPort(t *testing.T) {
	cfg := Config{}
	cfg.AddRemote(RemoteConfig{NodeID: "peer-1", Label: "office rdp", Protocol: "rdp", TargetPort: 3389})
	cfg.AddRemote(RemoteConfig{NodeID: "peer-1", Label: "office vnc", Protocol: "vnc", TargetPort: 5900})
	cfg.AddRemote(RemoteConfig{NodeID: "peer-1", Label: "office rdp updated", Protocol: "rdp", TargetPort: 3389})

	if len(cfg.Remotes) != 2 {
		t.Fatalf("remotes = %d, want 2: %+v", len(cfg.Remotes), cfg.Remotes)
	}
	if cfg.Remotes[0].Label != "office rdp updated" {
		t.Fatalf("rdp label = %q, want updated", cfg.Remotes[0].Label)
	}
	if cfg.Remotes[1].Label != "office vnc" {
		t.Fatalf("vnc label = %q, want office vnc", cfg.Remotes[1].Label)
	}
}
