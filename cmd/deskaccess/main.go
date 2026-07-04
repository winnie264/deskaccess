package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rdpanywhere/rdpanywhere/internal/logger"

	"github.com/rdpanywhere/rdpanywhere/internal/btdht"
	"github.com/rdpanywhere/rdpanywhere/internal/config"
	"github.com/rdpanywhere/rdpanywhere/internal/ipc"
	"github.com/rdpanywhere/rdpanywhere/internal/irohsidecar"
	"github.com/rdpanywhere/rdpanywhere/internal/node"
	"github.com/rdpanywhere/rdpanywhere/internal/pairing"
	"github.com/rdpanywhere/rdpanywhere/internal/quicnet"
	"github.com/rdpanywhere/rdpanywhere/internal/service"
	"github.com/rdpanywhere/rdpanywhere/internal/tray"
	"github.com/rdpanywhere/rdpanywhere/internal/tunnel"
)

// Two-process model:
//
//	Daemon process  (--service flag, started by OS service manager):
//	  node + webUI + IPC server — no tray, no display needed
//
//	Tray process    (default, started at user login via autostart):
//	  IPC client + systray — no daemon, talks to service via OS-secured IPC
//	  Windows: named pipe  \\.\pipe\DeskAccess  (IU + SYSTEM ACL)
//	  Linux:   Unix socket $XDG_RUNTIME_DIR/DeskAccess.sock  (chmod 0600)

func main() {
	var (
		svcInstall   = flag.Bool("install", false, "Install as system service")
		svcUninstall = flag.Bool("uninstall", false, "Uninstall system service")
		runSvc       = flag.Bool("service", false, "Run as system service (called by OS)")
		standalone   = flag.Bool("standalone", false, "Run backend and web UI in this process")
		connectURL   = flag.String("connect", "", "Connect to a remote via deskaccess:// URL")
		generate     = flag.Bool("generate", false, "Generate a pairing invite via running service")
		protocol     = flag.String("protocol", "", "Invite protocol: rdp, ssh, vnc, or custom")
		port         = flag.Int("port", 0, "Invite target port (0 = protocol default)")
		label        = flag.String("label", "", "Invite label")
		showID       = flag.Bool("id", false, "Print this machine's NodeID and exit")
		debug        = flag.Bool("debug", false, "Enable debug logging")
		logFile      = flag.String("log", logger.LogFile(), "Log file path (empty = stderr only)")
	)
	flag.Parse()
	if *connectURL == "" && flag.NArg() > 0 && isInviteURLArg(flag.Arg(0)) {
		*connectURL = flag.Arg(0)
	}

	if err := logger.Init(*logFile, *debug); err != nil {
		log.Fatalf("logger: %v", err)
	}
	logger.ConfigureLibp2pLogs(*debug)
	slog.Info("DeskAccess starting",
		"version", "0.1.0",
		"debug", *debug,
		"log_file", logger.CurrentLogFile(),
	)

	switch {
	case *svcInstall:
		if err := service.Install(); err != nil {
			log.Fatalf("install service: %v", err)
		}
		fmt.Println("Service installed.")

	case *svcUninstall:
		if err := service.Uninstall(); err != nil {
			log.Fatalf("uninstall service: %v", err)
		}
		fmt.Println("Service uninstalled.")

	case *runSvc:
		// Running as Windows Service / systemd — no UI
		if err := service.RunService(); err != nil {
			log.Fatalf("run service: %v", err)
		}

	case *standalone:
		runStandalone()

	case *connectURL != "":
		// Client mode: connect to remote via invite URL
		runClient(*connectURL)

	case *generate:
		generateInvite(*protocol, *port, *label)

	case *showID:
		cfg, err := config.Load()
		if err != nil {
			log.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		n, err := node.New(ctx, cfg)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("NodeID:", n.NodeID())

	default:
		if isPlainInteractiveCLI() {
			printDashboardURL()
			return
		}
		if tray.HasDisplay() {
			if activateExistingInstance() {
				return
			}
			// Tray process: IPC client only — requires the daemon to be running.
			runTray()
		} else if tray.HasDesktopDisplay() && openDashboardFromService() {
			return
		} else {
			// Headless machine: run the full daemon directly (no tray, no service manager).
			runDaemon()
		}
	}
}

func isInviteURLArg(arg string) bool {
	lower := strings.ToLower(arg)
	return strings.HasPrefix(lower, "deskaccess:")
}

func isPlainInteractiveCLI() bool {
	if len(os.Args) != 1 {
		return false
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func printDashboardURL() {
	st, err := ipc.Query(ipc.Request{Cmd: "status"})
	if err != nil {
		log.Fatalf("service not reachable: %v", err)
	}
	if st == nil || st.Error != "" {
		if st != nil && st.Error != "" {
			log.Fatal(st.Error)
		}
		log.Fatal("service did not return a dashboard URL")
	}
	if st.WebuiURL == "" {
		log.Fatal("service did not return a dashboard URL")
	}
	fmt.Println(st.WebuiURL)
}

func generateInvite(protocol string, port int, label string) {
	resp, err := ipc.Query(ipc.Request{
		Cmd:      "generate",
		Mode:     "pairing",
		Protocol: protocol,
		Port:     port,
		Label:    label,
	})
	if err != nil {
		log.Fatalf("service not reachable: %v", err)
	}
	if resp.Error != "" {
		log.Fatal(resp.Error)
	}
	fmt.Println(resp.InviteURL)
}

func activateExistingInstance() bool {
	st, err := ipc.Query(ipc.Request{Cmd: "status"})
	if err != nil || st == nil || st.WebuiURL == "" {
		return false
	}
	tray.ShowDashboard(st.WebuiURL)
	return true
}

func openDashboardFromService() bool {
	st, err := ipc.Query(ipc.Request{Cmd: "status"})
	if err != nil || st == nil || st.WebuiURL == "" {
		return false
	}
	tray.ShowDashboard(st.WebuiURL)
	return true
}

// runTray is the tray process. It connects to the daemon via IPC.
// If no daemon is reachable (e.g. during debugging), it starts the daemon
// stack in-process as background goroutines so a single `go run` is enough.
func runTray() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stackDone chan struct{}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; cancel() }()

	if _, err := ipc.Query(ipc.Request{Cmd: "status"}); err != nil {
		// Daemon not found — start it in-process (debug / no-service-installed mode).
		log.Println("daemon not reachable via IPC — starting in-process")
		stackDone = make(chan struct{})
		go func() {
			defer close(stackDone)
			service.RunStack(ctx)
		}()
		waitForDaemon(ctx)
	}

	t := tray.New(ctx)
	t.Run() // blocks on main thread (required by OS)
	cancel()
	waitForStackShutdown(stackDone)
}

// waitForDaemon polls the IPC socket until the daemon is ready or ctx is done.
func waitForDaemon(ctx context.Context) {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := ipc.Query(ipc.Request{Cmd: "status"}); err == nil {
			return
		}
		select {
		case <-time.After(250 * time.Millisecond):
		case <-ctx.Done():
			return
		}
	}
	log.Println("warning: daemon IPC not ready after 15s — tray may show errors")
}

// runDaemon is the standalone daemon entry point (headless / no service manager).
// Delegates entirely to service.RunStack so the IPC server is always started.
func runDaemon() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; cancel() }()

	service.RunStack(ctx)
}

func runStandalone() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; cancel() }()

	stackDone := make(chan struct{})
	go func() {
		defer close(stackDone)
		service.RunStack(ctx)
	}()
	waitForDaemon(ctx)

	st, err := ipc.Query(ipc.Request{Cmd: "status"})
	if err != nil {
		log.Fatalf("standalone backend started but dashboard is not reachable: %v", err)
	}
	if st == nil || st.Error != "" || st.WebuiURL == "" {
		if st != nil && st.Error != "" {
			log.Fatal(st.Error)
		}
		log.Fatal("standalone backend did not return a dashboard URL")
	}
	fmt.Println(st.WebuiURL)
	if tray.HasDesktopDisplay() {
		tray.ShowDashboard(st.WebuiURL)
	}
	<-ctx.Done()
	waitForStackShutdown(stackDone)
}

func waitForStackShutdown(done <-chan struct{}) {
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		log.Println("warning: daemon stack did not stop before timeout")
	}
}

func runClient(rawURL string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; cancel() }()

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	n, err := node.New(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer n.Close()

	// Use pairing.Manager to handle URL parsing + pairing handshake
	pairingMgr := pairing.New(n, cfg)
	tunnelMgr := tunnel.New(n, cfg, nil, pairingMgr.Sessions())
	useBitTorrentDHT := pairing.InviteNetworkBackend(rawURL) == "bittorrent_dht"
	privKey, keyErr := cfg.PrivateKeyBytes()
	var quicBackend *quicnet.Backend
	if keyErr == nil && useBitTorrentDHT {
		quicBackend, err = quicnet.New(ctx, cfg, privKey)
		if err != nil {
			log.Printf("direct QUIC init failed (non-fatal): %v", err)
		}
	}
	if quicBackend != nil {
		defer quicBackend.Close()
		pairingMgr.SetBitTorrentQUIC(quicBackend)
		tunnelMgr.SetBitTorrentQUIC(quicBackend)
		quicBackend.SetHandlers(pairingMgr.HandleQUICIncoming, tunnelMgr.HandleQUICIncoming)
	}
	if keyErr == nil && useBitTorrentDHT {
		btDHT, err := btdht.New(ctx, cfg.BTDHT, privKey, n.NodeID(), func() string {
			return cfg.Node.Label
		}, n.RelayAddrs, func() []string {
			if quicBackend == nil {
				return nil
			}
			return quicBackend.Addrs()
		})
		if err != nil {
			log.Printf("BitTorrent DHT init failed (non-fatal): %v", err)
		} else if btDHT != nil {
			defer btDHT.Close()
			pairingMgr.SetDHTDiscoverer(btDHT)
		}
	}
	irohBackend, err := irohsidecar.New(ctx, cfg)
	if err != nil {
		log.Printf("iroh sidecar init failed (non-fatal): %v", err)
	}
	if irohBackend != nil {
		defer irohBackend.Close(context.Background())
		pairingMgr.SetIroh(irohBackend)
		tunnelMgr.SetIroh(irohBackend)
		irohBackend.SetHandlers(pairingMgr.HandleIrohIncoming, tunnelMgr.HandleIrohIncoming)
	}

	result, err := pairingMgr.ConnectByURL(ctx, rawURL)
	if err != nil {
		log.Fatalf("connect failed: %v", err)
	}

	var localAddr string
	var connErr error
	if result.BitTorrentQUICEndpoint != "" {
		localAddr, connErr = tunnelMgr.ConnectBitTorrentQUIC(ctx, result.PeerID, result.BitTorrentQUICEndpoint, result.SessionToken, result.TargetPort)
	} else if result.IrohTicket != "" {
		localAddr, connErr = tunnelMgr.ConnectIroh(ctx, result.PeerID, result.IrohTicket, result.SessionToken, result.TargetPort)
	} else {
		localAddr, connErr = tunnelMgr.Connect(ctx, result.PeerID, result.RelayAddrs, result.SessionToken, result.TargetPort)
	}
	if connErr != nil {
		log.Fatalf("tunnel failed: %v", connErr)
	}

	slog.Info("tunnel ready", "addr", localAddr, "host", result.HostLabel)
	launch := tunnel.LaunchRDP(localAddr)
	if !launch.Launched {
		fmt.Printf("Tunnel ready at %s — connect your RDP client manually\n", localAddr)
	}

	<-ctx.Done()
}
