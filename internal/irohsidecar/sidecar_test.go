package irohsidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rdpanywhere/rdpanywhere/internal/config"
)

func TestBackendTicketAndOpenTunnelUseSidecarHTTP(t *testing.T) {
	var handlersRegistered atomic.Bool
	var openedKind string
	var openedTicket string

	streamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen stream: %v", err)
	}
	defer streamLn.Close()
	go func() {
		conn, err := streamLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("hello"))
	}()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/handlers":
			handlersRegistered.Store(true)
			w.WriteHeader(http.StatusNoContent)
		case "/status":
			_ = json.NewEncoder(w).Encode(statusResponse{Running: true, Ready: true, EndpointID: "ep-1"})
		case "/ticket":
			_ = json.NewEncoder(w).Encode(ticketResponse{Ticket: TicketPrefix + "ticket-1", EndpointID: "ep-1"})
		case "/open":
			var req openRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			openedKind = req.Kind
			openedTicket = req.Ticket
			_ = json.NewEncoder(w).Encode(openResponse{Addr: streamLn.Addr().String(), Path: "direct", RemoteAddr: "127.0.0.1:4242"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	backend, err := newWithURL(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("newWithURL: %v", err)
	}
	defer backend.Close(context.Background())
	if !handlersRegistered.Load() {
		t.Fatal("sidecar handlers were not registered")
	}

	ticket, err := backend.TicketContext(context.Background())
	if err != nil {
		t.Fatalf("TicketContext: %v", err)
	}
	if ticket != TicketPrefix+"ticket-1" {
		t.Fatalf("ticket = %q, want %sticket-1", ticket, TicketPrefix)
	}
	stream, err := backend.OpenTunnel(context.Background(), ticket)
	if err != nil {
		t.Fatalf("OpenTunnel: %v", err)
	}
	defer stream.Close()
	if openedKind != "tunnel" || openedTicket != TicketPrefix+"ticket-1" {
		t.Fatalf("open request kind/ticket = %q/%q", openedKind, openedTicket)
	}
	data, err := io.ReadAll(io.LimitReader(stream, 5))
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("stream data = %q, want hello", data)
	}
	if got := stream.(interface{ ConnectionPath() string }).ConnectionPath(); got != "direct" {
		t.Fatalf("ConnectionPath = %q, want direct", got)
	}
}

func TestBackendRejectsNonSidecarTicketBeforeOpen(t *testing.T) {
	var openCalled atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/handlers":
			w.WriteHeader(http.StatusNoContent)
		case "/status":
			_ = json.NewEncoder(w).Encode(statusResponse{Running: true, Ready: true})
		case "/open":
			openCalled.Store(true)
			http.Error(w, "should not be called", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	backend, err := newWithURL(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("newWithURL: %v", err)
	}
	defer backend.Close(context.Background())

	_, err = backend.OpenTunnel(context.Background(), "legacy-ticket-from-pi")
	if err != ErrIncompatibleTicket {
		t.Fatalf("OpenTunnel err = %v, want %v", err, ErrIncompatibleTicket)
	}
	if openCalled.Load() {
		t.Fatal("sidecar /open was called for a non-sidecar ticket")
	}
}

func TestBackendRunningReflectsControlStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/handlers":
			w.WriteHeader(http.StatusNoContent)
		case "/status":
			_ = json.NewEncoder(w).Encode(statusResponse{Running: true, Ready: true})
		default:
			http.NotFound(w, r)
		}
	}))

	backend, err := newWithURL(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("newWithURL: %v", err)
	}
	if !backend.Running() {
		t.Fatal("backend should report running while sidecar status responds")
	}

	srv.Close()
	if backend.Running() {
		t.Fatal("backend should report stopped after sidecar status stops responding")
	}
}

func TestBackendOpenRestartsStoppedSidecar(t *testing.T) {
	var handlersRegistered atomic.Int32
	var openCalled atomic.Bool

	streamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen stream: %v", err)
	}
	defer streamLn.Close()
	go func() {
		conn, err := streamLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("ok"))
	}()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/handlers":
			handlersRegistered.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case "/status":
			_ = json.NewEncoder(w).Encode(statusResponse{Running: true, Ready: true, EndpointID: "ep-restarted"})
		case "/open":
			openCalled.Store(true)
			_ = json.NewEncoder(w).Encode(openResponse{Addr: streamLn.Addr().String(), Path: "direct"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	backend := &Backend{
		baseURL: srv.URL,
		client:  &http.Client{Timeout: defaultControlTimeout},
		command: "fake-sidecar",
		cmdDone: closedErrorChan(),
	}
	pairingLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen pairing callback: %v", err)
	}
	defer pairingLn.Close()
	tunnelLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tunnel callback: %v", err)
	}
	defer tunnelLn.Close()
	backend.pairingLn = pairingLn
	backend.tunnelLn = tunnelLn

	restarted := false
	backend.startProcessFunc = func(ctx context.Context, command string) error {
		restarted = true
		backend.cmdDone = nil
		return nil
	}

	stream, err := backend.OpenTunnel(context.Background(), TicketPrefix+"ticket")
	if err != nil {
		t.Fatalf("OpenTunnel: %v", err)
	}
	defer stream.Close()
	if !restarted {
		t.Fatal("backend did not restart stopped sidecar")
	}
	if !openCalled.Load() {
		t.Fatal("sidecar /open was not called after restart")
	}
	if handlersRegistered.Load() != 1 {
		t.Fatalf("handlers registered %d times, want 1", handlersRegistered.Load())
	}
}

func closedErrorChan() chan error {
	ch := make(chan error)
	close(ch)
	return ch
}

func TestBackendCallbackDispatchesIncomingTunnel(t *testing.T) {
	var handlerAddr string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/handlers":
			var req handlersRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			handlerAddr = req.TunnelAddr
			w.WriteHeader(http.StatusNoContent)
		case "/status":
			_ = json.NewEncoder(w).Encode(statusResponse{Running: true, Ready: true})
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	backend, err := newWithURL(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("newWithURL: %v", err)
	}
	defer backend.Close(context.Background())

	got := make(chan string, 1)
	backend.SetHandlers(nil, func(conn io.ReadWriteCloser, remotePeerID string) {
		defer conn.Close()
		buf := make([]byte, 4)
		n, _ := conn.Read(buf)
		got <- fmt.Sprintf("%s:%s", remotePeerID, string(buf[:n]))
	})

	conn, err := net.Dial("tcp", handlerAddr)
	if err != nil {
		t.Fatalf("dial callback: %v", err)
	}
	_, _ = conn.Write([]byte(`{"peer_id":"peer-1","path":"relay"}` + "\n" + "ping"))
	_ = conn.Close()

	if msg := <-got; msg != "peer-1:ping" {
		t.Fatalf("callback got %q, want peer-1:ping", msg)
	}
}

func TestWaitReadyFileSetsDynamicURL(t *testing.T) {
	f, err := os.CreateTemp("", "sidecar-ready-test-*.json")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	path := f.Name()
	_ = f.Close()
	_ = os.Remove(path)
	defer os.Remove(path)

	backend := &Backend{}
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = os.WriteFile(path, []byte(`{"url":"http://127.0.0.1:4567","endpoint_id":"ep-1"}`), 0600)
	}()
	err = backend.waitReadyFile(context.Background(), path)
	if err != nil {
		t.Fatalf("waitReadyFile: %v", err)
	}
	if backend.baseURL != "http://127.0.0.1:4567" || backend.endpointID != "ep-1" {
		t.Fatalf("backend url/id = %q/%q", backend.baseURL, backend.endpointID)
	}
}

func TestCreateReadyFileUsesDeskAccessRuntimeDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DESKACCESS_RUNTIME_DIR", dir)

	f, err := createReadyFile()
	if err != nil {
		t.Fatalf("createReadyFile: %v", err)
	}
	path := f.Name()
	_ = f.Close()
	defer os.Remove(path)

	if filepath.Dir(path) != dir {
		t.Fatalf("ready file dir = %q, want %q", filepath.Dir(path), dir)
	}
}

func TestNewReturnsNotFoundErrorWhenSidecarMissing(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{}
	cfg.Iroh.Mode = "public"
	t.Setenv("PATH", "")
	_, err := New(ctx, cfg)
	if err == nil {
		t.Fatal("New returned nil error for missing sidecar")
	}
	var notFound *NotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("New error = %T %v, want NotFoundError", err, err)
	}
	if len(notFound.Searched) == 0 {
		t.Fatal("NotFoundError searched paths is empty")
	}
}

func TestRustSidecarBackendPairingRoundTrip(t *testing.T) {
	if os.Getenv("RUN_IROH_SIDECAR_TEST") != "1" {
		t.Skip("set RUN_IROH_SIDECAR_TEST=1 to run the Rust sidecar integration test")
	}
	command := testSidecarCommand(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	host, err := newWithCommand(ctx, command)
	if err != nil {
		t.Fatalf("start host sidecar: %v", err)
	}
	defer host.Close(context.Background())
	client, err := newWithCommand(ctx, command)
	if err != nil {
		t.Fatalf("start client sidecar: %v", err)
	}
	defer client.Close(context.Background())

	got := make(chan string, 1)
	host.SetHandlers(func(conn io.ReadWriteCloser, remotePeerID string) {
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			got <- "read error: " + err.Error()
			return
		}
		if string(buf) != "ping" {
			got <- "unexpected request: " + string(buf)
			return
		}
		if _, err := conn.Write([]byte("pong")); err != nil {
			got <- "write error: " + err.Error()
			return
		}
		got <- "ok:" + remotePeerID
	}, nil)

	ticket, err := host.TicketContext(ctx)
	if err != nil {
		t.Fatalf("host ticket: %v", err)
	}
	stream, err := client.OpenPairing(ctx, ticket)
	if err != nil {
		t.Fatalf("open pairing stream: %v", err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("response = %q, want pong", buf)
	}
	select {
	case msg := <-got:
		if len(msg) < 3 || msg[:3] != "ok:" {
			t.Fatalf("host handler result: %s", msg)
		}
	case <-ctx.Done():
		t.Fatalf("host handler did not complete: %v", ctx.Err())
	}
}

func testSidecarCommand(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("DESKACCESS_IROH_SIDECAR_BIN"); path != "" {
		if isExecutableFile(path) {
			return path
		}
		t.Fatalf("DESKACCESS_IROH_SIDECAR_BIN does not exist: %s", path)
	}
	name := sidecarBinaryBaseName
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	candidates := []string{
		filepath.Join("..", "..", "sidecars", "iroh-sidecar", "target", "release", name),
		filepath.Join("..", "..", "sidecars", "iroh-sidecar", "target", runtime.GOARCH+"-pc-windows-msvc", "release", name),
		filepath.Join("..", "..", "sidecars", "iroh-sidecar", "target", "x86_64-pc-windows-msvc", "release", name),
		filepath.Join("..", "..", "sidecars", "iroh-sidecar", "target", "debug", name),
	}
	for _, candidate := range candidates {
		if isExecutableFile(candidate) {
			abs, err := filepath.Abs(candidate)
			if err != nil {
				return candidate
			}
			return abs
		}
	}
	t.Fatalf("Rust sidecar binary not found; build it with cargo build --manifest-path sidecars/iroh-sidecar/Cargo.toml --release")
	return ""
}
