package service

import (
	"testing"

	"github.com/rdpanywhere/rdpanywhere/internal/config"
)

func TestShouldRunIrohSidecarBackendOnlyWhenActive(t *testing.T) {
	cfg := &config.Config{
		Network: config.NetworkConfig{ShareBackend: "libp2p_dht"},
		Iroh:    config.IrohConfig{Mode: "public"},
	}

	if shouldRunIrohSidecarBackend(cfg) {
		t.Fatal("iroh should not run when active backend is dht")
	}

	cfg.Network.ShareBackend = "iroh"
	if !shouldRunIrohSidecarBackend(cfg) {
		t.Fatal("iroh should run when active backend is iroh and mode is public")
	}

	cfg.Iroh.Mode = "disabled"
	if shouldRunIrohSidecarBackend(cfg) {
		t.Fatal("iroh should not run when iroh mode is disabled")
	}
}

func TestShouldRunBitTorrentDHTBackendOnlyWhenActive(t *testing.T) {
	cfg := &config.Config{
		Network: config.NetworkConfig{ShareBackend: "iroh"},
		BTDHT:   config.BTDHTConfig{Mode: "public"},
	}

	if shouldRunBitTorrentDHTBackend(cfg) {
		t.Fatal("BitTorrent DHT/direct QUIC should not run when active backend is iroh")
	}

	cfg.Network.ShareBackend = "bittorrent_dht"
	if !shouldRunBitTorrentDHTBackend(cfg) {
		t.Fatal("BitTorrent DHT/direct QUIC should run when active backend is bittorrent_dht and mode is public")
	}

	cfg.BTDHT.Mode = "disabled"
	if shouldRunBitTorrentDHTBackend(cfg) {
		t.Fatal("BitTorrent DHT/direct QUIC should not run when mode is disabled")
	}
}
