package service

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/kardianos/service"
	"github.com/rdpanywhere/rdpanywhere/internal/btdht"
	"github.com/rdpanywhere/rdpanywhere/internal/config"
	"github.com/rdpanywhere/rdpanywhere/internal/identity"
	"github.com/rdpanywhere/rdpanywhere/internal/ipc"
	"github.com/rdpanywhere/rdpanywhere/internal/irohnet"
	"github.com/rdpanywhere/rdpanywhere/internal/logger"
	"github.com/rdpanywhere/rdpanywhere/internal/netbackend"
	"github.com/rdpanywhere/rdpanywhere/internal/node"
	"github.com/rdpanywhere/rdpanywhere/internal/pairing"
	"github.com/rdpanywhere/rdpanywhere/internal/presence"
	"github.com/rdpanywhere/rdpanywhere/internal/quicnet"
	"github.com/rdpanywhere/rdpanywhere/internal/rdpcheck"
	"github.com/rdpanywhere/rdpanywhere/internal/tunnel"
	"github.com/rdpanywhere/rdpanywhere/internal/webui"
)

var slogService = logger.For(logger.CompService)

var svcConfig = &service.Config{
	Name:        "DeskAccess",
	DisplayName: "DeskAccess",
	Description: "Secure P2P RDP tunnel service",
}

// App satisfies the kardianos/service interface. It only holds the cancel
// function; all component lifetime is managed inside RunStack.
type App struct {
	cancel context.CancelFunc
}

func (a *App) Start(_ service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	go RunStack(ctx)
	return nil
}

func (a *App) Stop(_ service.Service) error {
	if a.cancel != nil {
		a.cancel()
	}
	return nil
}

// RunStack starts the full daemon: node, webUI, IPC server.
// Blocks until ctx is cancelled. Called by the OS service manager (via App)
// and directly by main.go for headless or debug in-process use.
func RunStack(ctx context.Context) {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	cfg.NormalizeNetworkBackend()
	slogService.Info("service stack starting",
		"share_backend", cfg.ActiveNetworkBackend(),
		"relay_mode", cfg.Relay.Mode,
		"dht_mode", cfg.DHT.Mode,
		"bittorrent_dht_mode", cfg.BTDHT.Mode,
		"iroh_mode", cfg.Iroh.Mode,
		"label", cfg.Node.Label,
		"log_file", logger.CurrentLogFile(),
	)

	id, err := identity.Load()
	if err != nil {
		log.Fatalf("load identity: %v", err)
	}
	identityBackend := "none"
	hardwareBacked := false
	tpmVendor := ""
	if id != nil {
		identityBackend = string(id.Backend)
		hardwareBacked = id.Backend == identity.BackendTPM
		if id.Attestation != nil {
			tpmVendor = id.Attestation.Manufacturer
		}
	}
	slogService.Info("identity loaded",
		"backend", identityBackend,
		"hardware_backed", hardwareBacked,
		"tpm_vendor", tpmVendor,
	)

	n, err := node.New(ctx, cfg)
	if err != nil {
		log.Fatalf("start node: %v", err)
	}
	defer n.Close()
	slogService.Info("node started",
		"node_id", n.NodeID(),
		"relay_count", len(n.RelayAddrs()),
		"share_backend", cfg.ActiveNetworkBackend(),
	)

	pairingMgr := pairing.New(n, cfg)
	pairingMgr.SetIdentity(id)

	privKey, err := cfg.PrivateKeyBytes()
	if err != nil {
		log.Printf("BitTorrent DHT disabled: load key failed: %v", err)
	}
	var quicBackend *quicnet.Backend
	if err == nil && shouldRunBitTorrentDHTBackend(cfg) {
		quicBackend, err = quicnet.New(ctx, cfg, privKey)
		if err != nil {
			log.Printf("direct QUIC init failed (non-fatal): %v", err)
		}
	}
	var btDHT *btdht.Client
	var networkMu sync.Mutex
	lastNetworkApplyError := ""
	if err == nil && shouldRunBitTorrentDHTBackend(cfg) {
		btDHT, err = btdht.New(ctx, cfg.BTDHT, privKey, n.NodeID(), func() string {
			return cfg.Node.Label
		}, n.RelayAddrs, func() []string {
			if quicBackend == nil {
				return nil
			}
			return quicBackend.Addrs()
		})
		if err != nil {
			log.Printf("BitTorrent DHT init failed (non-fatal): %v", err)
		}
	}
	if btDHT != nil {
		defer btDHT.Close()
		pairingMgr.SetDHTDiscoverer(btDHT)
	}
	if quicBackend != nil {
		defer quicBackend.Close()
		pairingMgr.SetBitTorrentQUIC(quicBackend)
	}

	var pres *presence.Manager
	if shouldRunLibp2pBackground(cfg) {
		pres, err = presence.New(ctx, n.Host, cfg, n.RelayAddrs, n.DHT())
		if err != nil {
			log.Printf("presence init failed (non-fatal): %v", err)
		}
		if pres != nil {
			pairingMgr.SetPresence(pres)
		}
	} else {
		slogService.Info("libp2p presence disabled for selected backend", "share_backend", cfg.ActiveNetworkBackend())
	}
	n.OnAddrsChange(func(_ []string) {
		n.PublishDHTIdentityNow(ctx)
		if pres != nil {
			pres.AnnounceNow(ctx)
		}
		if btDHT != nil {
			btDHT.PublishNow(ctx)
		}
	})

	tunnelMgr := tunnel.New(n, cfg, pres, pairingMgr.Sessions())
	if quicBackend != nil {
		tunnelMgr.SetBitTorrentQUIC(quicBackend)
		quicBackend.SetHandlers(pairingMgr.HandleQUICIncoming, tunnelMgr.HandleQUICIncoming)
		slogService.Info("direct QUIC backend ready", "addrs", quicBackend.Addrs())
	}

	var irohBackend *irohnet.Backend
	if shouldRunIrohBackend(cfg) {
		irohBackend, err = irohnet.New(ctx, cfg)
		if err != nil {
			log.Printf("iroh init failed (non-fatal): %v", err)
		}
		if irohBackend != nil {
			defer irohBackend.Close(context.Background())
			pairingMgr.SetIroh(irohBackend)
			tunnelMgr.SetIroh(irohBackend)
			irohBackend.SetHandlers(pairingMgr.HandleIrohIncoming, tunnelMgr.HandleIrohIncoming)
			slogService.Info("iroh backend ready", "endpoint_id", irohnet.LogValue(irohBackend))
		}
	}

	webUI := webui.New(cfg, n, pairingMgr, pres, tunnelMgr, id)
	webUI.SetNetworkStatusProvider(func() map[string]any {
		networkMu.Lock()
		defer networkMu.Unlock()

		status := n.NetworkStatus()
		status["share_backend"] = cfg.ActiveNetworkBackend()
		status["last_apply_error"] = lastNetworkApplyError
		if btDHT != nil {
			btStatus := btDHT.Status()
			if quicBackend != nil {
				btStatus["direct_quic"] = quicBackend.Status()
			}
			status["bittorrent_dht"] = btStatus
		} else {
			status["bittorrent_dht"] = map[string]any{
				"enabled": cfg.BTDHT.Mode != "" && cfg.BTDHT.Mode != "disabled",
				"running": false,
			}
		}
		if irohBackend != nil {
			status["iroh"] = irohBackend.Status()
		} else {
			status["iroh"] = map[string]any{
				"enabled": cfg.Iroh.Mode != "" && cfg.Iroh.Mode != "disabled",
				"running": false,
			}
		}
		return status
	})
	webUI.SetApplyNetworkConfig(func(applyCtx context.Context) error {
		networkMu.Lock()
		defer networkMu.Unlock()

		cfg.NormalizeNetworkBackend()
		slogService.Info("applying network settings",
			"share_backend", cfg.ActiveNetworkBackend(),
			"relay_mode", cfg.Relay.Mode,
			"dht_mode", cfg.DHT.Mode,
			"bittorrent_dht_mode", cfg.BTDHT.Mode,
			"iroh_mode", cfg.Iroh.Mode,
		)

		if err := n.ApplyNetworkConfig(applyCtx); err != nil {
			lastNetworkApplyError = err.Error()
			return err
		}
		lastNetworkApplyError = ""
		if pres != nil {
			pres.AnnounceNow(applyCtx)
		}

		if btDHT != nil {
			btDHT.Close()
			btDHT = nil
			pairingMgr.SetDHTDiscoverer(nil)
		}
		if quicBackend != nil {
			_ = quicBackend.Close()
			quicBackend = nil
			pairingMgr.SetBitTorrentQUIC(nil)
			tunnelMgr.SetBitTorrentQUIC(nil)
		}
		if shouldRunBitTorrentDHTBackend(cfg) {
			privKey, err := cfg.PrivateKeyBytes()
			if err != nil {
				lastNetworkApplyError = err.Error()
				slogService.Warn("BitTorrent DHT disabled after config apply: load key failed", "err", err)
			} else {
				nextQUIC, err := quicnet.New(ctx, cfg, privKey)
				if err != nil {
					lastNetworkApplyError = err.Error()
					slogService.Warn("direct QUIC apply failed", "err", err)
				} else if nextQUIC != nil {
					quicBackend = nextQUIC
					pairingMgr.SetBitTorrentQUIC(quicBackend)
					tunnelMgr.SetBitTorrentQUIC(quicBackend)
					quicBackend.SetHandlers(pairingMgr.HandleQUICIncoming, tunnelMgr.HandleQUICIncoming)
					slogService.Info("direct QUIC backend applied", "addrs", quicBackend.Addrs())
				}
				nextBT, err := btdht.New(ctx, cfg.BTDHT, privKey, n.NodeID(), func() string {
					return cfg.Node.Label
				}, n.RelayAddrs, func() []string {
					if quicBackend == nil {
						return nil
					}
					return quicBackend.Addrs()
				})
				if err != nil {
					lastNetworkApplyError = err.Error()
					slogService.Warn("BitTorrent DHT apply failed", "err", err)
				} else if nextBT != nil {
					btDHT = nextBT
					pairingMgr.SetDHTDiscoverer(btDHT)
					btDHT.PublishNow(applyCtx)
				}
			}
		}

		if irohBackend != nil {
			_ = irohBackend.Close(context.Background())
			irohBackend = nil
			pairingMgr.SetIroh(nil)
			tunnelMgr.SetIroh(nil)
		}
		if shouldRunIrohBackend(cfg) {
			nextIroh, err := irohnet.New(ctx, cfg)
			if err != nil {
				lastNetworkApplyError = err.Error()
				slogService.Warn("iroh apply failed", "err", err)
			} else if nextIroh != nil {
				irohBackend = nextIroh
				pairingMgr.SetIroh(irohBackend)
				tunnelMgr.SetIroh(irohBackend)
				irohBackend.SetHandlers(pairingMgr.HandleIrohIncoming, tunnelMgr.HandleIrohIncoming)
				slogService.Info("iroh backend applied", "endpoint_id", irohnet.LogValue(irohBackend))
			}
		}

		slogService.Info("network settings applied", "share_backend", cfg.ActiveNetworkBackend())
		return nil
	})
	webUI.SetEnsureNetworkBackend(func(ensureCtx context.Context, backend string) error {
		networkMu.Lock()
		defer networkMu.Unlock()

		slogService.Info("ensuring network backend for connect",
			"backend", backend,
			"share_backend", cfg.ActiveNetworkBackend(),
		)
		switch backend {
		case "iroh":
			if irohBackend != nil {
				return nil
			}
			oldMode := cfg.Iroh.Mode
			if cfg.Iroh.Mode == "" || cfg.Iroh.Mode == "disabled" {
				cfg.Iroh.Mode = "public"
			}
			nextIroh, err := irohnet.New(ctx, cfg)
			if oldMode == "" || oldMode == "disabled" {
				cfg.Iroh.Mode = oldMode
			}
			if err != nil {
				lastNetworkApplyError = err.Error()
				return err
			}
			if nextIroh == nil {
				return fmt.Errorf("iroh backend did not start")
			}
			irohBackend = nextIroh
			pairingMgr.SetIroh(irohBackend)
			tunnelMgr.SetIroh(irohBackend)
			irohBackend.SetHandlers(pairingMgr.HandleIrohIncoming, tunnelMgr.HandleIrohIncoming)
			if err := waitIrohReady(ensureCtx, irohBackend); err != nil {
				lastNetworkApplyError = err.Error()
				return err
			}
			slogService.Info("iroh backend started for connect", "endpoint_id", irohnet.LogValue(irohBackend))
			return nil

		case "bittorrent_dht":
			if cfg.BTDHT.Mode == "" || cfg.BTDHT.Mode == "disabled" {
				cfg.BTDHT.Mode = "public"
			}
			privKey, err := cfg.PrivateKeyBytes()
			if err != nil {
				lastNetworkApplyError = err.Error()
				return err
			}
			if quicBackend == nil {
				nextQUIC, err := quicnet.New(ctx, cfg, privKey)
				if err != nil {
					lastNetworkApplyError = err.Error()
					return err
				}
				if nextQUIC != nil {
					quicBackend = nextQUIC
					pairingMgr.SetBitTorrentQUIC(quicBackend)
					tunnelMgr.SetBitTorrentQUIC(quicBackend)
					quicBackend.SetHandlers(pairingMgr.HandleQUICIncoming, tunnelMgr.HandleQUICIncoming)
				}
			}
			if btDHT == nil {
				nextBT, err := btdht.New(ctx, cfg.BTDHT, privKey, n.NodeID(), func() string {
					return cfg.Node.Label
				}, n.RelayAddrs, func() []string {
					if quicBackend == nil {
						return nil
					}
					return quicBackend.Addrs()
				})
				if err != nil {
					lastNetworkApplyError = err.Error()
					return err
				}
				btDHT = nextBT
				pairingMgr.SetDHTDiscoverer(btDHT)
				if btDHT != nil {
					btDHT.PublishNow(ensureCtx)
				}
			}
			if btDHT != nil {
				if err := btDHT.WaitReady(ensureCtx); err != nil {
					lastNetworkApplyError = err.Error()
					return err
				}
			}
			return nil

		case "libp2p_dht":
			if cfg.DHT.Mode == "" || cfg.DHT.Mode == "disabled" {
				cfg.DHT.Mode = "public"
			}
			if n.DHT() == nil {
				if err := n.ApplyNetworkConfig(ensureCtx); err != nil {
					lastNetworkApplyError = err.Error()
					return err
				}
			}
			if err := n.WaitDHTReady(ensureCtx); err != nil {
				lastNetworkApplyError = err.Error()
				return err
			}
			return nil

		case "libp2p_relay":
			if cfg.Relay.Mode == "" || cfg.Relay.Mode == "disabled" {
				cfg.Relay.Mode = "public"
				if err := n.ApplyNetworkConfig(ensureCtx); err != nil {
					lastNetworkApplyError = err.Error()
					return err
				}
			}
			return nil
		default:
			return fmt.Errorf("unsupported backend %q", backend)
		}
	})
	go webUI.Start(ctx)
	slogService.Info("web ui starting", "listen", "http://127.0.0.1:18080")

	if err := ipc.Serve(ctx, func(req ipc.Request) ipc.Response {
		slogService.Debug("ipc request", "cmd", req.Cmd, "mode", req.Mode, "protocol", req.Protocol, "port", req.Port)
		switch req.Cmd {
		case "status":
			return ipc.Response{
				NodeID:     n.NodeID(),
				Label:      cfg.Node.Label,
				WebuiURL:   webUI.BaseURL(),
				RelayCount: len(n.RelayAddrs()),
				LogFile:    logger.CurrentLogFile(),
			}
		case "generate":
			if req.Mode != "onetime" && req.Mode != "pairing" {
				return ipc.Response{Error: "mode must be onetime or pairing"}
			}
			proto := req.Protocol
			if proto == "" {
				proto = cfg.RDP.Protocol
			}
			if proto == "" {
				proto = "rdp"
			}
			port := req.Port
			if port == 0 {
				port = rdpcheck.ParseProtocol(proto).DefaultPort()
			}
			ttl := time.Hour
			if req.Mode == "pairing" {
				ttl = 0
			}
			url, _, err := pairingMgr.GenerateURL(req.Mode, ttl, req.Label, proto, port)
			if err != nil {
				slogService.Warn("ipc generate failed", "err", err, "mode", req.Mode, "protocol", proto, "port", port, "share_backend", cfg.ActiveNetworkBackend())
				return ipc.Response{Error: err.Error()}
			}
			slogService.Info("ipc invite generated", "mode", req.Mode, "protocol", proto, "port", port, "share_backend", cfg.ActiveNetworkBackend())
			return ipc.Response{InviteURL: url}
		default:
			return ipc.Response{Error: "unknown command: " + req.Cmd}
		}
	}); err != nil {
		log.Printf("IPC server failed to start: %v", err)
	}
	slogService.Info("ipc server started")

	fmt.Printf("DeskAccess running. NodeID: %s\n", n.NodeID())
	<-ctx.Done()
	slogService.Info("service stack stopped")
}

func shouldRunIrohBackend(cfg *config.Config) bool {
	return cfg != nil && cfg.ActiveNetworkBackend() == "iroh" && cfg.Iroh.Mode != "" && cfg.Iroh.Mode != "disabled"
}

func shouldRunBitTorrentDHTBackend(cfg *config.Config) bool {
	return cfg != nil &&
		cfg.ActiveNetworkBackend() == netbackend.BackendBitTorrentDHT &&
		cfg.BTDHT.Mode != "" &&
		cfg.BTDHT.Mode != "disabled"
}

func shouldRunLibp2pBackground(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	return (cfg.Relay.Mode != "" && cfg.Relay.Mode != "disabled") ||
		(cfg.DHT.Mode != "" && cfg.DHT.Mode != "disabled")
}

func waitIrohReady(ctx context.Context, backend *irohnet.Backend) error {
	if backend == nil {
		return fmt.Errorf("iroh backend is not running")
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		status := backend.Status()
		if ready, _ := status["ready"].(bool); ready {
			return nil
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			if errText, _ := status["last_error"].(string); errText != "" {
				return fmt.Errorf("iroh backend not ready: %s", errText)
			}
			return fmt.Errorf("iroh backend not ready")
		}
	}
}

// RunService runs as a proper Windows service or systemd unit.
func RunService() error {
	a := &App{}
	svc, err := service.New(a, svcConfig)
	if err != nil {
		return err
	}
	return svc.Run()
}

// Install installs the binary as a system service.
func Install() error {
	a := &App{}
	svc, err := service.New(a, svcConfig)
	if err != nil {
		return err
	}
	return svc.Install()
}

// Uninstall removes the system service.
func Uninstall() error {
	a := &App{}
	svc, err := service.New(a, svcConfig)
	if err != nil {
		return err
	}
	return svc.Uninstall()
}
