package irohsidecar

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rdpanywhere/rdpanywhere/internal/config"
	"github.com/rdpanywhere/rdpanywhere/internal/logger"
)

const (
	defaultDynamicListen   = "127.0.0.1:0"
	defaultStartTimeout    = 30 * time.Second
	defaultControlTimeout  = 2 * time.Minute
	sidecarBinaryBaseName  = "deskaccess-iroh-sidecar"
	sidecarReadyFilePrefix = "deskaccess-iroh-sidecar-ready-"
	TicketPrefix           = "iroh-sidecar-v1:"
)

var log = logger.For(logger.Component("iroh_sidecar"))

var ErrIncompatibleTicket = errors.New("iroh ticket was not created by the sidecar backend")

type NotFoundError struct {
	Searched []string
}

func (e *NotFoundError) Error() string {
	if e == nil || len(e.Searched) == 0 {
		return "iroh sidecar binary not found"
	}
	return "iroh sidecar binary not found; expected deskaccess-iroh-sidecar next to DeskAccess or in a bundled sidecars/bin directory"
}

type Handler func(conn io.ReadWriteCloser, remotePeerID string)

type Backend struct {
	baseURL          string
	client           *http.Client
	command          string
	startProcessFunc func(context.Context, string) error

	mu             sync.RWMutex
	pairingHandler Handler
	tunnelHandler  Handler
	pairingLn      net.Listener
	tunnelLn       net.Listener
	cmd            *exec.Cmd
	cmdDone        chan error
	closed         bool
	lastErr        string
	endpointID     string
}

func New(ctx context.Context, cfg *config.Config) (*Backend, error) {
	if cfg == nil || cfg.Iroh.Mode == "" || cfg.Iroh.Mode == "disabled" {
		return nil, nil
	}
	command, searched, ok := findBundledSidecar()
	if !ok {
		return nil, &NotFoundError{Searched: searched}
	}
	return newWithCommand(ctx, command)
}

func newWithCommand(ctx context.Context, command string) (*Backend, error) {
	b := &Backend{client: &http.Client{Timeout: defaultControlTimeout}, command: command}
	if err := b.startProcess(ctx, command); err != nil {
		return nil, err
	}
	if err := b.waitReady(ctx); err != nil {
		_ = b.Close(context.Background())
		return nil, err
	}
	if err := b.startCallbacks(ctx); err != nil {
		_ = b.Close(context.Background())
		return nil, err
	}
	log.Info("iroh sidecar backend started", "url", b.baseURL, "endpoint_id", b.endpointID)
	return b, nil
}

func newWithURL(ctx context.Context, baseURL string) (*Backend, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid iroh sidecar url %q: %w", baseURL, err)
	}
	b := &Backend{
		baseURL: baseURL,
		client:  &http.Client{Timeout: defaultControlTimeout},
	}
	if err := b.waitReady(ctx); err != nil {
		return nil, err
	}
	if err := b.startCallbacks(ctx); err != nil {
		_ = b.Close(context.Background())
		return nil, err
	}
	return b, nil
}

func (b *Backend) startProcess(ctx context.Context, command string) error {
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("iroh sidecar command is empty")
	}
	b.command = command
	readyFile, err := createReadyFile()
	if err != nil {
		return fmt.Errorf("create iroh sidecar ready file: %w", err)
	}
	readyPath := readyFile.Name()
	_ = readyFile.Close()
	_ = os.Remove(readyPath)

	args := []string{"--listen", defaultDynamicListen, "--ready-file", readyPath}
	if err := ctx.Err(); err != nil {
		return err
	}
	sidecarLogPath, logErr := prepareSidecarLogFile()
	if logErr != nil {
		log.Warn("iroh sidecar log file setup failed", "err", logErr)
	}
	cmd := exec.Command(command, args...)
	cmd.Env = sidecarEnv(os.Environ(), sidecarLogPath)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start iroh sidecar %q: %w", command, err)
	}
	b.cmd = cmd
	cmdDone := make(chan error, 1)
	b.cmdDone = cmdDone
	log.Info("iroh sidecar process started", "command", command, "args", args, "pid", cmd.Process.Pid, "log_file", sidecarLogPath)
	go func() {
		err := cmd.Wait()
		cmdDone <- err
		close(cmdDone)
		if err != nil {
			b.mu.RLock()
			closed := b.closed
			b.mu.RUnlock()
			if !closed {
				b.setLastError(err)
				log.Warn("iroh sidecar process exited", "err", err)
			}
			return
		}
		log.Info("iroh sidecar process exited")
	}()
	if err := b.waitReadyFile(ctx, readyPath); err != nil {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return err
	}
	return nil
}

func sidecarEnv(base []string, logPath string) []string {
	env := make([]string, 0, len(base)+2)
	for _, item := range base {
		key := item
		if idx := strings.IndexByte(item, '='); idx >= 0 {
			key = item[:idx]
		}
		if strings.EqualFold(key, "DESKACCESS_IROH_SIDECAR_LOG") || strings.EqualFold(key, "DESKACCESS_LOG_DIR") {
			continue
		}
		env = append(env, item)
	}
	if logPath != "" {
		env = append(env, "DESKACCESS_IROH_SIDECAR_LOG="+logPath)
		env = append(env, "DESKACCESS_LOG_DIR="+filepath.Dir(logPath))
	}
	return env
}

func prepareSidecarLogFile() (string, error) {
	var lastErr error
	for _, path := range sidecarLogCandidates() {
		if strings.TrimSpace(path) == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			lastErr = fmt.Errorf("%s: %w", path, err)
			continue
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", path, err)
			continue
		}
		fmt.Fprintf(f, `{"time":%q,"level":"INFO","msg":"iroh sidecar log bootstrap","component":"iroh_sidecar","log_file":%q}`+"\n", time.Now().Format(time.RFC3339Nano), path)
		_ = f.Close()
		return path, nil
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("no iroh sidecar log file path available")
}

func sidecarLogCandidates() []string {
	var candidates []string
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		for _, existing := range candidates {
			if existing == path {
				return
			}
		}
		candidates = append(candidates, path)
	}
	add(os.Getenv("DESKACCESS_IROH_SIDECAR_LOG"))
	if dir := os.Getenv("DESKACCESS_LOG_DIR"); dir != "" {
		add(filepath.Join(dir, "deskaccess-iroh-sidecar.log"))
	}
	if current := logger.CurrentLogFile(); current != "" {
		add(filepath.Join(filepath.Dir(current), "deskaccess-iroh-sidecar.log"))
	}
	if runtime.GOOS == "windows" {
		if dir := os.Getenv("ProgramData"); dir != "" {
			add(filepath.Join(dir, "DeskAccess", "deskaccess-iroh-sidecar.log"))
		}
		if dir := os.Getenv("APPDATA"); dir != "" {
			add(filepath.Join(dir, "DeskAccess", "deskaccess-iroh-sidecar.log"))
		}
		if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
			add(filepath.Join(dir, "DeskAccess", "deskaccess-iroh-sidecar.log"))
		}
	} else {
		add(filepath.Join(string(filepath.Separator), "var", "lib", "deskaccess", "deskaccess-iroh-sidecar.log"))
		if dir := os.Getenv("XDG_STATE_HOME"); dir != "" {
			add(filepath.Join(dir, "DeskAccess", "deskaccess-iroh-sidecar.log"))
		}
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			add(filepath.Join(home, ".local", "share", "DeskAccess", "deskaccess-iroh-sidecar.log"))
		}
	}
	if dir, err := os.Getwd(); err == nil {
		add(filepath.Join(dir, ".deskaccess-logs", "deskaccess-iroh-sidecar.log"))
	}
	return candidates
}

func createReadyFile() (*os.File, error) {
	var lastErr error
	for _, dir := range runtimeDirCandidates() {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			lastErr = fmt.Errorf("%s: %w", dir, err)
			continue
		}
		f, err := os.CreateTemp(dir, sidecarReadyFilePrefix+"*.json")
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", dir, err)
			continue
		}
		return f, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no writable runtime directory found")
}

func runtimeDirCandidates() []string {
	var dirs []string
	if dir := os.Getenv("DESKACCESS_RUNTIME_DIR"); dir != "" {
		dirs = append(dirs, dir)
	}
	if runtime.GOOS == "windows" {
		if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
			dirs = append(dirs, filepath.Join(dir, "DeskAccess", "run"))
		}
		if dir := os.Getenv("APPDATA"); dir != "" {
			dirs = append(dirs, filepath.Join(dir, "DeskAccess", "run"))
		}
	} else {
		if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
			dirs = append(dirs, filepath.Join(dir, "DeskAccess"))
		}
		if dir, err := os.UserCacheDir(); err == nil {
			dirs = append(dirs, filepath.Join(dir, "DeskAccess", "run"))
		}
		if home, err := os.UserHomeDir(); err == nil {
			dirs = append(dirs,
				filepath.Join(home, ".local", "share", "DeskAccess", "run"),
				filepath.Join(home, ".config", "DeskAccess", "run"),
			)
		}
	}
	if dir, err := os.Getwd(); err == nil {
		dirs = append(dirs, filepath.Join(dir, ".deskaccess-run"))
	}
	return dirs
}

func findBundledSidecar() (string, []string, bool) {
	name := sidecarBinaryBaseName
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	var roots []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		roots = append(roots,
			dir,
			filepath.Join(dir, "sidecars"),
			filepath.Join(dir, "bin"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		roots = append(roots,
			filepath.Join(wd, "sidecars", "iroh-sidecar", "target", "release"),
			filepath.Join(wd, "sidecars", "iroh-sidecar", "target", "debug"),
			filepath.Join(wd, "build"),
		)
	}
	var searched []string
	for _, root := range roots {
		path := filepath.Join(root, name)
		searched = append(searched, path)
		if isExecutableFile(path) {
			return path, searched, true
		}
	}
	return "", searched, false
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func (b *Backend) waitReadyFile(ctx context.Context, path string) error {
	defer os.Remove(path)
	waitCtx, cancel := context.WithTimeout(ctx, defaultStartTimeout)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			var ready sidecarReadyFile
			if err := json.Unmarshal(data, &ready); err != nil {
				return fmt.Errorf("parse iroh sidecar ready file: %w", err)
			}
			ready.URL = strings.TrimRight(strings.TrimSpace(ready.URL), "/")
			if ready.URL == "" {
				return fmt.Errorf("iroh sidecar ready file missing url")
			}
			if _, err := url.ParseRequestURI(ready.URL); err != nil {
				return fmt.Errorf("invalid iroh sidecar ready url %q: %w", ready.URL, err)
			}
			b.baseURL = ready.URL
			b.endpointID = ready.EndpointID
			return nil
		}
		if err != nil && !os.IsNotExist(err) {
			last = err
		}
		select {
		case <-ticker.C:
		case <-waitCtx.Done():
			if last != nil {
				return fmt.Errorf("iroh sidecar did not write ready file: %w", last)
			}
			return fmt.Errorf("iroh sidecar did not write ready file")
		}
	}
}

func (b *Backend) startCallbacks(ctx context.Context) error {
	pairingLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen pairing callback: %w", err)
	}
	tunnelLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = pairingLn.Close()
		return fmt.Errorf("listen tunnel callback: %w", err)
	}
	b.pairingLn = pairingLn
	b.tunnelLn = tunnelLn
	go b.acceptLoop(ctx, pairingLn, "pairing")
	go b.acceptLoop(ctx, tunnelLn, "tunnel")
	return b.registerHandlers(ctx)
}

func (b *Backend) registerHandlers(ctx context.Context) error {
	if b == nil || b.pairingLn == nil || b.tunnelLn == nil {
		return fmt.Errorf("iroh sidecar callback listeners are not running")
	}
	return b.post(ctx, "/handlers", handlersRequest{
		PairingAddr: b.pairingLn.Addr().String(),
		TunnelAddr:  b.tunnelLn.Addr().String(),
		PairingALPN: "DeskAccess/pairing/iroh/1",
		TunnelALPN:  "DeskAccess/tunnel/iroh/1",
	}, nil)
}

func (b *Backend) waitReady(ctx context.Context) error {
	waitCtx, cancel := context.WithTimeout(ctx, defaultStartTimeout)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		status, err := b.fetchStatus(waitCtx)
		if err == nil && status.Running {
			b.endpointID = status.EndpointID
			b.setLastError(nil)
			return nil
		}
		if err != nil {
			last = err
		}
		select {
		case <-ticker.C:
		case <-waitCtx.Done():
			if last != nil {
				b.setLastError(last)
				return fmt.Errorf("iroh sidecar not ready: %w", last)
			}
			return fmt.Errorf("iroh sidecar not ready")
		}
	}
}

func (b *Backend) SetHandlers(pairing Handler, tunnel Handler) {
	b.mu.Lock()
	b.pairingHandler = pairing
	b.tunnelHandler = tunnel
	b.mu.Unlock()
}

func (b *Backend) TicketContext(ctx context.Context) (string, error) {
	var resp ticketResponse
	if err := b.post(ctx, "/ticket", nil, &resp); err != nil {
		b.setLastError(err)
		return "", err
	}
	b.endpointID = resp.EndpointID
	b.setLastError(nil)
	return resp.Ticket, nil
}

func (b *Backend) OpenPairing(ctx context.Context, ticket string) (io.ReadWriteCloser, error) {
	if err := b.ensureRunning(ctx); err != nil {
		return nil, err
	}
	return b.openStream(ctx, "pairing", ticket)
}

func (b *Backend) OpenTunnel(ctx context.Context, ticket string) (io.ReadWriteCloser, error) {
	if err := b.ensureRunning(ctx); err != nil {
		return nil, err
	}
	return b.openStream(ctx, "tunnel", ticket)
}

func (b *Backend) ensureRunning(ctx context.Context) error {
	if b == nil {
		return fmt.Errorf("iroh sidecar backend is not running")
	}
	if b.Running() {
		return nil
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return fmt.Errorf("iroh sidecar backend is closed")
	}
	command := b.command
	b.mu.Unlock()
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("iroh sidecar command is unknown")
	}

	restartCtx, cancel := context.WithTimeout(ctx, defaultStartTimeout)
	defer cancel()
	log.Warn("iroh sidecar is stopped; restarting before stream open")
	startProcess := b.startProcess
	if b.startProcessFunc != nil {
		startProcess = b.startProcessFunc
	}
	if err := startProcess(restartCtx, command); err != nil {
		b.setLastError(err)
		return fmt.Errorf("restart iroh sidecar: %w", err)
	}
	if err := b.waitReady(restartCtx); err != nil {
		b.setLastError(err)
		return fmt.Errorf("wait for restarted iroh sidecar: %w", err)
	}
	if err := b.registerHandlers(restartCtx); err != nil {
		b.setLastError(err)
		return fmt.Errorf("register restarted iroh sidecar handlers: %w", err)
	}
	log.Info("iroh sidecar restarted", "url", b.baseURL, "endpoint_id", b.endpointID)
	b.setLastError(nil)
	return nil
}

func (b *Backend) openStream(ctx context.Context, kind string, ticket string) (io.ReadWriteCloser, error) {
	if !IsTicket(ticket) {
		return nil, ErrIncompatibleTicket
	}
	var resp openResponse
	started := time.Now()
	log.Info("opening iroh sidecar stream", "kind", kind, "timeout", defaultControlTimeout.String())
	if err := b.post(ctx, "/open", openRequest{Kind: kind, Ticket: ticket}, &resp); err != nil {
		b.setLastError(err)
		log.Warn("open iroh sidecar stream failed", "kind", kind, "duration", time.Since(started).String(), "err", err)
		return nil, err
	}
	log.Info("iroh sidecar stream ready", "kind", kind, "duration", time.Since(started).String(), "path", resp.Path, "remote_addr", resp.RemoteAddr)
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", resp.Addr)
	if err != nil {
		b.setLastError(err)
		return nil, fmt.Errorf("dial iroh sidecar stream %s: %w", resp.Addr, err)
	}
	b.setLastError(nil)
	return &streamConn{Conn: conn, path: resp.Path, remoteAddr: resp.RemoteAddr}, nil
}

func IsTicket(ticket string) bool {
	_, err := TicketEndpointID(ticket)
	return err == nil
}

func TicketEndpointID(ticket string) (string, error) {
	ticket = strings.TrimSpace(ticket)
	encoded, ok := strings.CutPrefix(ticket, TicketPrefix)
	if !ok {
		return "", ErrIncompatibleTicket
	}
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode iroh sidecar ticket: %w", err)
	}
	var parsed struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", fmt.Errorf("parse iroh sidecar ticket: %w", err)
	}
	if strings.TrimSpace(parsed.ID) == "" {
		return "", fmt.Errorf("iroh sidecar ticket missing endpoint id")
	}
	return strings.TrimSpace(parsed.ID), nil
}

func (b *Backend) CloseTunnel(peerID string, reason string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var resp closeTunnelResponse
	if err := b.post(ctx, "/close_tunnel", closeTunnelRequest{PeerID: peerID, Reason: reason}, &resp); err != nil {
		b.setLastError(err)
		log.Warn("iroh sidecar close tunnel failed", "peer", short(peerID), "err", err)
		return 0
	}
	return resp.Closed
}

func (b *Backend) Refresh(ctx context.Context) (map[string]any, error) {
	status, err := b.fetchStatus(ctx)
	if err != nil {
		b.setLastError(err)
		return b.Status(), err
	}
	b.endpointID = status.EndpointID
	b.setLastError(nil)
	return b.Status(), nil
}

func (b *Backend) Status() map[string]any {
	status, err := b.fetchStatus(context.Background())
	if err == nil {
		b.endpointID = status.EndpointID
		return map[string]any{
			"enabled":      true,
			"running":      status.Running,
			"ready":        status.Ready,
			"endpoint_id":  status.EndpointID,
			"relay_urls":   status.RelayURLs,
			"direct_addrs": status.DirectAddrs,
			"last_error":   status.LastError,
			"sidecar":      true,
			"url":          b.baseURL,
		}
	}
	b.setLastError(err)
	b.mu.RLock()
	lastErr := b.lastErr
	endpointID := b.endpointID
	b.mu.RUnlock()
	return map[string]any{
		"enabled":     true,
		"running":     false,
		"ready":       false,
		"endpoint_id": endpointID,
		"last_error":  lastErr,
		"sidecar":     true,
		"url":         b.baseURL,
	}
}

func (b *Backend) Running() bool {
	if b == nil {
		return false
	}
	b.mu.RLock()
	closed := b.closed
	cmdDone := b.cmdDone
	b.mu.RUnlock()
	if closed {
		return false
	}
	if cmdDone != nil {
		select {
		case <-cmdDone:
			return false
		default:
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := b.fetchStatus(ctx)
	if err != nil {
		b.setLastError(err)
		return false
	}
	return true
}

func (b *Backend) Close(ctx context.Context) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	pairingLn := b.pairingLn
	tunnelLn := b.tunnelLn
	cmd := b.cmd
	cmdDone := b.cmdDone
	b.mu.Unlock()
	if pairingLn != nil {
		_ = pairingLn.Close()
	}
	if tunnelLn != nil {
		_ = tunnelLn.Close()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	_ = b.post(shutdownCtx, "/shutdown", nil, nil)
	cancel()
	if cmd == nil || cmd.Process == nil || cmdDone == nil {
		return nil
	}
	select {
	case <-cmdDone:
		return nil
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
	}
	select {
	case <-cmdDone:
	case <-time.After(2 * time.Second):
	}
	return nil
}

func (b *Backend) acceptLoop(ctx context.Context, ln net.Listener, kind string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				b.mu.RLock()
				closed := b.closed
				b.mu.RUnlock()
				if !closed {
					log.Warn("iroh sidecar callback listener stopped", "kind", kind, "err", err)
				}
			}
			return
		}
		go b.handleCallback(conn, kind)
	}
}

func (b *Backend) handleCallback(conn net.Conn, kind string) {
	reader := bufio.NewReader(conn)
	meta, err := readCallbackMeta(reader)
	if err != nil {
		log.Warn("iroh sidecar callback metadata failed", "kind", kind, "err", err)
		_ = conn.Close()
		return
	}
	b.mu.RLock()
	handler := b.pairingHandler
	if kind == "tunnel" {
		handler = b.tunnelHandler
	}
	b.mu.RUnlock()
	if handler == nil {
		log.Warn("iroh sidecar callback closed without handler", "kind", kind, "peer", short(meta.PeerID))
		_ = conn.Close()
		return
	}
	handler(&streamConn{Conn: &bufferedConn{Conn: conn, reader: reader}, path: meta.Path, remoteAddr: meta.RemoteAddr}, meta.PeerID)
}

func readCallbackMeta(r *bufio.Reader) (callbackMeta, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return callbackMeta{}, err
	}
	var meta callbackMeta
	if err := json.Unmarshal(bytes.TrimSpace(line), &meta); err != nil {
		return callbackMeta{}, err
	}
	if strings.TrimSpace(meta.PeerID) == "" {
		return callbackMeta{}, fmt.Errorf("missing peer_id")
	}
	return meta, nil
}

func (b *Backend) fetchStatus(ctx context.Context) (statusResponse, error) {
	var resp statusResponse
	err := b.get(ctx, "/status", &resp)
	return resp, err
}

func (b *Backend) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.baseURL+path, nil)
	if err != nil {
		return err
	}
	return b.do(req, out)
}

func (b *Backend) post(ctx context.Context, path string, in any, out any) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.baseURL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return b.do(req, out)
}

func (b *Backend) do(req *http.Request, out any) error {
	resp, err := b.client.Do(req)
	if err != nil {
		if b.client != nil && b.client.Timeout > 0 && isTimeoutError(err) {
			return fmt.Errorf("sidecar %s %s timed out after %s: %w", req.Method, req.URL.Path, b.client.Timeout, err)
		}
		return fmt.Errorf("sidecar %s %s failed: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
		return fmt.Errorf("sidecar %s %s: %s: %s", req.Method, req.URL.Path, resp.Status, strings.TrimSpace(string(data)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	type timeout interface {
		Timeout() bool
	}
	if te, ok := err.(timeout); ok && te.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded")
}

func (b *Backend) setLastError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		b.lastErr = ""
		return
	}
	b.lastErr = err.Error()
}

type handlersRequest struct {
	PairingAddr string `json:"pairing_addr"`
	TunnelAddr  string `json:"tunnel_addr"`
	PairingALPN string `json:"pairing_alpn,omitempty"`
	TunnelALPN  string `json:"tunnel_alpn,omitempty"`
}

type ticketResponse struct {
	Ticket     string `json:"ticket"`
	EndpointID string `json:"endpoint_id,omitempty"`
}

type openRequest struct {
	Kind   string `json:"kind"`
	Ticket string `json:"ticket"`
}

type openResponse struct {
	Addr       string `json:"addr"`
	Path       string `json:"path,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`
}

type closeTunnelRequest struct {
	PeerID string `json:"peer_id"`
	Reason string `json:"reason,omitempty"`
}

type closeTunnelResponse struct {
	Closed int `json:"closed"`
}

type statusResponse struct {
	Running     bool   `json:"running"`
	Ready       bool   `json:"ready"`
	EndpointID  string `json:"endpoint_id,omitempty"`
	RelayURLs   int    `json:"relay_urls,omitempty"`
	DirectAddrs int    `json:"direct_addrs,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}

type sidecarReadyFile struct {
	URL        string `json:"url"`
	Addr       string `json:"addr,omitempty"`
	EndpointID string `json:"endpoint_id,omitempty"`
}

type callbackMeta struct {
	PeerID     string `json:"peer_id"`
	Path       string `json:"path,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`
}

type streamConn struct {
	net.Conn
	path       string
	remoteAddr string
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *streamConn) WriteChunkSize() int {
	return 32 * 1024
}

func (c *streamConn) ConnectionPath() string {
	if c == nil || strings.TrimSpace(c.path) == "" {
		return "unknown"
	}
	return c.path
}

func (c *streamConn) ConnectionRemoteAddr() string {
	if c == nil {
		return ""
	}
	return c.remoteAddr
}

func (c *streamConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

func (c *streamConn) AbortClose() error {
	return c.Close()
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
