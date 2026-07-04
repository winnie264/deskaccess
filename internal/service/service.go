package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/kardianos/service"
	"github.com/rdpanywhere/rdpanywhere/internal/btdht"
	"github.com/rdpanywhere/rdpanywhere/internal/config"
	"github.com/rdpanywhere/rdpanywhere/internal/identity"
	"github.com/rdpanywhere/rdpanywhere/internal/ipc"
	"github.com/rdpanywhere/rdpanywhere/internal/irohsidecar"
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
	done   chan struct{}
}

func (a *App) Start(_ service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.done = make(chan struct{})
	go func() {
		defer close(a.done)
		RunStack(ctx)
	}()
	return nil
}

func (a *App) Stop(_ service.Service) error {
	if a.cancel != nil {
		a.cancel()
	}
	if a.done != nil {
		select {
		case <-a.done:
		case <-time.After(10 * time.Second):
			slogService.Warn("service stack did not stop before timeout")
		}
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
	if n.Libp2pRunning() {
		pairingMgr.SetLibp2p(true)
		tunnelMgr.SetLibp2p(true)
		slogService.Info("libp2p backend registered", "share_backend", cfg.ActiveNetworkBackend())
	}
	if quicBackend != nil {
		tunnelMgr.SetBitTorrentQUIC(quicBackend)
		quicBackend.SetHandlers(pairingMgr.HandleQUICIncoming, tunnelMgr.HandleQUICIncoming)
		slogService.Info("direct QUIC backend ready", "addrs", quicBackend.Addrs())
	}

	var irohSidecar *irohsidecar.Backend
	backendRefs := make(map[string]map[string]struct{})
	backendRefCountLocked := func(backend string) int {
		return len(backendRefs[config.CanonicalNetworkBackend(backend)])
	}
	registerIrohSidecarLocked := func(next *irohsidecar.Backend, reason string) {
		irohSidecar = next
		pairingMgr.SetIroh(irohSidecar)
		tunnelMgr.SetIroh(irohSidecar)
		irohSidecar.SetHandlers(pairingMgr.HandleIrohIncoming, tunnelMgr.HandleIrohIncoming)
		slogService.Info("iroh sidecar backend ready", "reason", reason)
	}
	stopIrohSidecarLocked := func(reason string) {
		if irohSidecar == nil {
			return
		}
		slogService.Info("iroh sidecar backend stopping", "reason", reason)
		current := irohSidecar
		irohSidecar = nil
		pairingMgr.SetIroh(nil)
		tunnelMgr.SetIroh(nil)
		_ = current.Close(context.Background())
	}
	startIrohSidecarLocked := func(startCtx context.Context, reason string, allowEnable bool) error {
		if irohSidecar != nil {
			if irohSidecar.Running() {
				slogService.Info("iroh sidecar backend already running", "reason", reason)
				return nil
			}
			slogService.Warn("iroh sidecar backend is stopped; unregistering before restart", "reason", reason)
			stopIrohSidecarLocked(reason + " stopped backend cleanup")
		}
		oldMode := cfg.Iroh.Mode
		if allowEnable && (cfg.Iroh.Mode == "" || cfg.Iroh.Mode == "disabled") {
			cfg.Iroh.Mode = "public"
		}
		defer func() {
			if allowEnable && (oldMode == "" || oldMode == "disabled") {
				cfg.Iroh.Mode = oldMode
			}
		}()
		if cfg.Iroh.Mode == "" || cfg.Iroh.Mode == "disabled" {
			return fmt.Errorf("iroh backend is disabled")
		}
		slogService.Info("iroh sidecar backend starting", "reason", reason, "mode", cfg.Iroh.Mode)
		nextSidecar, err := irohsidecar.New(startCtx, cfg)
		if err != nil {
			var notFound *irohsidecar.NotFoundError
			if errors.As(err, &notFound) {
				lastNetworkApplyError = err.Error()
				slogService.Warn("iroh sidecar backend start failed: binary not found", "reason", reason, "searched", notFound.Searched)
			} else {
				lastNetworkApplyError = err.Error()
				slogService.Warn("iroh sidecar backend start failed", "reason", reason, "err", err)
			}
			return err
		}
		if nextSidecar == nil {
			lastNetworkApplyError = "iroh sidecar binary not found"
			return fmt.Errorf("iroh sidecar binary not found")
		}
		registerIrohSidecarLocked(nextSidecar, reason)
		lastNetworkApplyError = ""
		return nil
	}
	setBackendRefLocked := func(refCtx context.Context, backend string, key string, active bool, reason string) error {
		backend = config.CanonicalNetworkBackend(backend)
		if backend == "" || backend == "disabled" || key == "" {
			return nil
		}
		refs := backendRefs[backend]
		if refs == nil {
			refs = make(map[string]struct{})
			backendRefs[backend] = refs
		}
		_, had := refs[key]
		if active {
			refs[key] = struct{}{}
		} else {
			delete(refs, key)
		}
		count := len(refs)
		if count == 0 {
			delete(backendRefs, backend)
		}
		if active && !had {
			slogService.Info("backend reference acquired", "backend", backend, "key", key, "count", count, "reason", reason)
		} else if !active && had {
			slogService.Info("backend reference released", "backend", backend, "key", key, "count", count, "reason", reason)
		}
		if backend != netbackend.BackendIroh {
			return nil
		}
		if count > 0 {
			return startIrohSidecarLocked(refCtx, "backend reference "+reason, true)
		}
		stopIrohSidecarLocked("backend references released: " + reason)
		return nil
	}
	backendRunningLocked := func(backend string) bool {
		switch backend {
		case netbackend.BackendIroh:
			return irohSidecar != nil && irohSidecar.Running()
		case netbackend.BackendBitTorrentDHT:
			return btDHT != nil && quicBackend != nil
		case netbackend.BackendLibp2pDHT:
			return n.DHT() != nil
		case netbackend.BackendLibp2pRelay:
			return n.Libp2pRunning()
		default:
			return false
		}
	}
	ensureNetworkBackendLocked := func(ensureCtx context.Context, backend string, reason string) error {
		slogService.Info("ensuring network backend",
			"backend", backend,
			"share_backend", cfg.ActiveNetworkBackend(),
			"reason", reason,
		)
		switch backend {
		case netbackend.BackendIroh:
			return startIrohSidecarLocked(ensureCtx, reason, reason == "connect")

		case netbackend.BackendBitTorrentDHT:
			if cfg.BTDHT.Mode == "" || cfg.BTDHT.Mode == "disabled" {
				cfg.BTDHT.Mode = "public"
			}
			privKey, err := cfg.PrivateKeyBytes()
			if err != nil {
				lastNetworkApplyError = err.Error()
				return err
			}
			if quicBackend == nil {
				slogService.Info("direct QUIC backend starting", "reason", reason)
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
			} else {
				slogService.Info("direct QUIC backend already running", "reason", reason, "addrs", quicBackend.Addrs())
			}
			if btDHT == nil {
				slogService.Info("BitTorrent DHT backend starting", "reason", reason, "mode", cfg.BTDHT.Mode)
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
			} else {
				slogService.Info("BitTorrent DHT backend already running", "reason", reason)
			}
			if btDHT != nil {
				if err := btDHT.WaitReady(ensureCtx); err != nil {
					lastNetworkApplyError = err.Error()
					return err
				}
			}
			lastNetworkApplyError = ""
			return nil

		case netbackend.BackendLibp2pDHT:
			if cfg.DHT.Mode == "" || cfg.DHT.Mode == "disabled" {
				cfg.DHT.Mode = "public"
			}
			if n.DHT() == nil {
				if err := n.StartLibp2p(ensureCtx, netbackend.BackendLibp2pDHT); err != nil {
					lastNetworkApplyError = err.Error()
					return err
				}
				pairingMgr.SetLibp2p(n.Libp2pRunning())
				tunnelMgr.SetLibp2p(n.Libp2pRunning())
			}
			if err := n.WaitDHTReady(ensureCtx); err != nil {
				lastNetworkApplyError = err.Error()
				return err
			}
			lastNetworkApplyError = ""
			return nil

		case netbackend.BackendLibp2pRelay:
			if cfg.Relay.Mode == "" || cfg.Relay.Mode == "disabled" {
				cfg.Relay.Mode = "public"
			}
			if err := n.StartLibp2p(ensureCtx, netbackend.BackendLibp2pRelay); err != nil {
				lastNetworkApplyError = err.Error()
				return err
			}
			pairingMgr.SetLibp2p(n.Libp2pRunning())
			tunnelMgr.SetLibp2p(n.Libp2pRunning())
			lastNetworkApplyError = ""
			return nil
		default:
			return fmt.Errorf("unsupported backend %q", backend)
		}
	}
	defer func() {
		networkMu.Lock()
		defer networkMu.Unlock()
		stopIrohSidecarLocked("service shutdown")
	}()
	if cfg.ActiveNetworkBackend() == netbackend.BackendIroh {
		if err := setBackendRefLocked(ctx, netbackend.BackendIroh, "selected", true, "startup selected backend"); err != nil {
			log.Printf("iroh sidecar init failed (non-fatal): %v", err)
		}
	}
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			networkMu.Lock()
			activeBackend := cfg.ActiveNetworkBackend()
			shouldRetry := activeBackend != "" &&
				activeBackend != "disabled" &&
				!backendRunningLocked(activeBackend)
			if !shouldRetry {
				networkMu.Unlock()
				continue
			}
			retryCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
			err := ensureNetworkBackendLocked(retryCtx, activeBackend, "background retry")
			cancel()
			if err != nil {
				slogService.Warn("network backend background retry failed", "backend", activeBackend, "err", err)
			}
			networkMu.Unlock()
		}
	}()

	webUI := webui.New(cfg, n, pairingMgr, pres, tunnelMgr, id)
	networkStatus := func() map[string]any {
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
		if irohSidecar != nil {
			irohStatus := irohSidecar.Status()
			irohStatus["references"] = backendRefCountLocked(netbackend.BackendIroh)
			status["iroh"] = irohStatus
		} else {
			status["iroh"] = map[string]any{
				"enabled":    cfg.Iroh.Mode != "" && cfg.Iroh.Mode != "disabled",
				"running":    false,
				"sidecar":    true,
				"references": backendRefCountLocked(netbackend.BackendIroh),
			}
		}
		return status
	}
	webUI.SetNetworkStatusProvider(networkStatus)
	webUI.SetNetworkRefreshProvider(func(refreshCtx context.Context) (map[string]any, error) {
		networkMu.Lock()
		activeBackend := cfg.ActiveNetworkBackend()
		currentSidecar := irohSidecar
		networkMu.Unlock()

		var refreshErr error
		switch activeBackend {
		case "iroh":
			if currentSidecar != nil {
				_, refreshErr = currentSidecar.Refresh(refreshCtx)
			} else {
				refreshErr = fmt.Errorf("iroh sidecar backend is not running")
			}
		default:
			slogService.Info("manual network refresh has no active probe", "share_backend", activeBackend)
		}
		return networkStatus(), refreshErr
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
		pairingMgr.SetLibp2p(n.Libp2pRunning())
		tunnelMgr.SetLibp2p(n.Libp2pRunning())
		lastNetworkApplyError = ""
		if pres != nil {
			pres.AnnounceNow(applyCtx)
		}

		if btDHT != nil {
			slogService.Info("BitTorrent DHT backend stopping", "reason", "network settings apply")
			btDHT.Close()
			btDHT = nil
			pairingMgr.SetDHTDiscoverer(nil)
			slogService.Info("BitTorrent DHT backend stopped", "reason", "network settings apply")
		}
		if quicBackend != nil {
			slogService.Info("direct QUIC backend stopping", "reason", "network settings apply")
			_ = quicBackend.Close()
			quicBackend = nil
			pairingMgr.SetBitTorrentQUIC(nil)
			tunnelMgr.SetBitTorrentQUIC(nil)
			slogService.Info("direct QUIC backend stopped", "reason", "network settings apply")
		}
		if shouldRunBitTorrentDHTBackend(cfg) {
			privKey, err := cfg.PrivateKeyBytes()
			if err != nil {
				lastNetworkApplyError = err.Error()
				slogService.Warn("BitTorrent DHT disabled after config apply: load key failed", "err", err)
			} else {
				slogService.Info("direct QUIC backend starting", "reason", "network settings apply")
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
				slogService.Info("BitTorrent DHT backend starting", "reason", "network settings apply", "mode", cfg.BTDHT.Mode)
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

		if cfg.ActiveNetworkBackend() == netbackend.BackendIroh {
			if err := setBackendRefLocked(applyCtx, netbackend.BackendIroh, "selected", true, "network settings apply"); err != nil {
				lastNetworkApplyError = err.Error()
				slogService.Warn("iroh sidecar apply failed", "err", err)
			}
		} else {
			_ = setBackendRefLocked(applyCtx, netbackend.BackendIroh, "selected", false, "network settings apply")
		}

		slogService.Info("network settings applied", "share_backend", cfg.ActiveNetworkBackend())
		return nil
	})
	webUI.SetEnsureNetworkBackend(func(ensureCtx context.Context, backend string) error {
		networkMu.Lock()
		defer networkMu.Unlock()
		return ensureNetworkBackendLocked(ensureCtx, backend, "connect")
	})
	webUI.SetBackendReferenceHooks(
		func(refCtx context.Context, backend string, key string, reason string) error {
			networkMu.Lock()
			defer networkMu.Unlock()
			return setBackendRefLocked(refCtx, backend, key, true, reason)
		},
		func(backend string, key string, reason string) {
			networkMu.Lock()
			defer networkMu.Unlock()
			_ = setBackendRefLocked(context.Background(), backend, key, false, reason)
		},
	)
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

func shouldRunIrohSidecarBackend(cfg *config.Config) bool {
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
	switch cfg.ActiveNetworkBackend() {
	case netbackend.BackendLibp2pRelay:
		return cfg.Relay.Mode != "" && cfg.Relay.Mode != "disabled"
	case netbackend.BackendLibp2pDHT:
		return cfg.DHT.Mode != "" && cfg.DHT.Mode != "disabled"
	default:
		return false
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
