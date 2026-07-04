// Package logger provides structured logging for DeskAccess.
// Uses Go 1.21+ log/slog — no external dependency.
//
// Log levels:
//
//	DEBUG  — detailed trace (relay pings, presence beats, token checks)
//	INFO   — normal lifecycle events (connected, paired, launched)
//	WARN   — recoverable issues (relay dropped, validation fallback)
//	ERROR  — failures requiring attention (tunnel failed, service unavailable)
package logger

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	logging "github.com/ipfs/go-log/v2"
)

// Component identifies the subsystem emitting a log entry.
type Component string

const (
	CompNode     Component = "node"
	CompRelay    Component = "relay"
	CompPairing  Component = "pairing"
	CompTunnel   Component = "tunnel"
	CompPresence Component = "presence"
	CompService  Component = "service"
	CompWebUI    Component = "webui"
	CompDCUTR    Component = "dcutr"
	CompDHT      Component = "dht"
)

var (
	// Default logger — replaced by Init().
	Default       = slog.New(&swapHandler{})
	logPath       string
	logFileHandle *os.File
	logMu         sync.RWMutex
	stderrWriter  io.Writer = os.Stderr
	target                  = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
)

// SuppressLibp2pLogs reduces libp2p's internal go-log/v2 verbosity to WARN.
// go-libp2p-kad-dht emits thousands of DEBUG/INFO entries during DHT
// bootstrapping via a separate logging system (ipfs/go-log/v2). Left at the
// default level these entries queue faster than they drain and can stall the
// Go scheduler, causing the UI to become unresponsive.
func SuppressLibp2pLogs() {
	logging.SetAllLoggers(logging.LevelWarn)
}

// Tail returns the last maxLines from the active log file.
func Tail(maxLines int) ([]string, error) {
	if logPath == "" {
		return nil, fmt.Errorf("file logging is disabled")
	}
	if maxLines <= 0 {
		maxLines = 200
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		return nil, err
	}
	const maxBytes = 512 * 1024
	if len(data) > maxBytes {
		data = data[len(data)-maxBytes:]
		if i := bytes.IndexByte(data, '\n'); i >= 0 && i+1 < len(data) {
			data = data[i+1:]
		}
	}
	raw := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	if len(raw) > maxLines {
		raw = raw[len(raw)-maxLines:]
	}
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		if len(bytes.TrimSpace(line)) > 0 {
			out = append(out, string(line))
		}
	}
	return out, nil
}

// ConfigureLibp2pLogs keeps noisy libp2p internals quiet by default and enables
// them when app debug logging is requested.
func ConfigureLibp2pLogs(debug bool) {
	if debug {
		logging.SetAllLoggers(logging.LevelDebug)
		return
	}
	SuppressLibp2pLogs()
}

// Init configures the global logger. Call once at startup.
// logFile: path to log file (empty = stderr only).
// debug:   whether to include DEBUG level entries.
func Init(logFile string, debug bool) error {
	if runtime.GOOS != "windows" {
		if env := firstEnv("DESKACCESS_LOG", "DeskAccess_LOG"); env != "" {
			logFile = env
		}
	}
	if envBool(firstEnv("DESKACCESS_DEBUG", "DeskAccess_DEBUG")) {
		debug = true
	}
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}

	var writers []io.Writer
	var openedFile *os.File
	var openedPath string

	if logFile != "" {
		f, path, err := openLogFile(logFile)
		if err != nil {
			writers = append(writers, &memoryBootstrapWriter{err: err})
		} else {
			writeBootstrapLine(f, path, debug)
			writers = append(writers, f)
			openedFile = f
			openedPath = path
		}
	}
	writers = append(writers, stderrWriter)

	handler := slog.NewJSONHandler(bestEffortMultiWriter(writers...), &slog.HandlerOptions{
		Level:     level,
		AddSource: debug, // include file:line in debug mode
	})

	logMu.Lock()
	oldFile := logFileHandle
	logPath = openedPath
	logFileHandle = openedFile
	if oldFile != nil && oldFile != openedFile {
		_ = oldFile.Close()
	}
	target = handler
	logMu.Unlock()
	slog.SetDefault(Default)
	log.SetFlags(0)
	log.SetOutput(&stdLogWriter{})
	slog.Info("logger initialized", "debug", debug, "log_file", logPath)
	return nil
}

// For returns a logger scoped to a component.
func For(comp Component) *slog.Logger {
	return Default.With("component", string(comp))
}

// --- convenience wrappers ---

func Info(comp Component, msg string, args ...any) {
	Default.Info(msg, append([]any{"component", string(comp)}, args...)...)
}

func Debug(comp Component, msg string, args ...any) {
	Default.Debug(msg, append([]any{"component", string(comp)}, args...)...)
}

func Warn(comp Component, msg string, args ...any) {
	Default.Warn(msg, append([]any{"component", string(comp)}, args...)...)
}

func Error(comp Component, msg string, args ...any) {
	Default.Error(msg, append([]any{"component", string(comp)}, args...)...)
}

// Err wraps an error with component context.
func Err(comp Component, msg string, err error, args ...any) {
	Default.Error(msg, append([]any{"component", string(comp), "err", err}, args...)...)
}

// Event logs a structured lifecycle event — useful for audit trails.
func Event(comp Component, event string, args ...any) {
	Default.Info("event",
		append([]any{
			"component", string(comp),
			"event", event,
			"ts", time.Now().UTC().Format(time.RFC3339),
		}, args...)...)
}

// Wrap wraps an error with a message prefix (like fmt.Errorf but shorter).
func Wrap(msg string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", msg, err)
}

// Wrapf creates a new error from a message (no wrapped error).
func Wrapf(msg string, args ...any) error {
	return fmt.Errorf(msg, args...)
}

// LogFile returns the default log file path for this platform.
func LogFile() string {
	switch runtime.GOOS {
	case "windows":
		if dir := os.Getenv("ProgramData"); dir != "" {
			return filepath.Join(dir, "DeskAccess", "DeskAccess.log")
		}
		if dir := os.Getenv("APPDATA"); dir != "" {
			return filepath.Join(dir, "DeskAccess", "DeskAccess.log")
		}
		if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
			return filepath.Join(dir, "DeskAccess", "DeskAccess.log")
		}
		return filepath.Join("DeskAccess.log")
	default:
		return filepath.Join(string(filepath.Separator), "var", "lib", "deskaccess", "DeskAccess.log")
	}
}

func openLogFile(preferred string) (*os.File, string, error) {
	var lastErr error
	for _, path := range logFileCandidates(preferred) {
		if path == "" {
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
		return f, path, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no log file path configured")
	}
	return nil, "", lastErr
}

func writeBootstrapLine(f *os.File, path string, debug bool) {
	fmt.Fprintf(f,
		`{"time":%q,"level":"INFO","msg":"logger bootstrap","debug":%t,"log_file":%q}`+"\n",
		time.Now().Format(time.RFC3339Nano),
		debug,
		path,
	)
	_ = f.Sync()
}

func logFileCandidates(preferred string) []string {
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
	add(preferred)
	if runtime.GOOS == "windows" {
		if dir := os.Getenv("ProgramData"); dir != "" {
			add(filepath.Join(dir, "DeskAccess", "DeskAccess.log"))
		}
		if dir := os.Getenv("APPDATA"); dir != "" {
			add(filepath.Join(dir, "DeskAccess", "DeskAccess.log"))
		}
		if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
			add(filepath.Join(dir, "DeskAccess", "DeskAccess.log"))
		}
	} else {
		add(filepath.Join(string(filepath.Separator), "var", "lib", "deskaccess", "DeskAccess.log"))
		if stateHome := os.Getenv("XDG_STATE_HOME"); stateHome != "" {
			add(filepath.Join(stateHome, "DeskAccess", "DeskAccess.log"))
		}
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			add(filepath.Join(home, ".local", "state", "DeskAccess", "DeskAccess.log"))
			add(filepath.Join(home, ".local", "share", "DeskAccess", "DeskAccess.log"))
		}
	}
	return candidates
}

// CurrentLogFile returns the active log file path, if file logging is enabled.
func CurrentLogFile() string { return logPath }

// Startup logs the initial banner.
func Startup(version, peerID, nodeLabel string) {
	slog.Info("DeskAccess starting",
		"version", version,
		"peer_id", peerID,
		"label", nodeLabel,
		"os", runtime.GOOS,
		"arch", runtime.GOARCH,
	)
}

type stdLogWriter struct{}

func (w *stdLogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		Default.Info(msg, "component", "stdlib")
	}
	return len(p), nil
}

type memoryBootstrapWriter struct {
	err  error
	once sync.Once
}

func (w *memoryBootstrapWriter) Write(p []byte) (int, error) {
	w.once.Do(func() {
		if w.err != nil {
			fmt.Fprintf(os.Stderr, "DeskAccess logging file disabled: %v\n", w.err)
		}
	})
	return len(p), nil
}

type bestEffortWriter struct {
	writers []io.Writer
}

func bestEffortMultiWriter(writers ...io.Writer) io.Writer {
	out := make([]io.Writer, 0, len(writers))
	for _, w := range writers {
		if w != nil {
			out = append(out, w)
		}
	}
	return &bestEffortWriter{writers: out}
}

func (w *bestEffortWriter) Write(p []byte) (int, error) {
	var firstErr error
	wrote := false
	for _, writer := range w.writers {
		if _, err := writer.Write(p); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		wrote = true
	}
	if wrote {
		return len(p), nil
	}
	if firstErr != nil {
		return 0, firstErr
	}
	return len(p), nil
}

func envBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "y", "on", "debug":
		return true
	default:
		return false
	}
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v
		}
	}
	return ""
}

type swapHandler struct {
	attrs  []slog.Attr
	groups []string
}

func (h *swapHandler) Enabled(ctx context.Context, level slog.Level) bool {
	logMu.RLock()
	defer logMu.RUnlock()
	return target.Enabled(ctx, level)
}

func (h *swapHandler) Handle(ctx context.Context, r slog.Record) error {
	logMu.RLock()
	base := target
	logMu.RUnlock()
	var handler slog.Handler = base
	for _, group := range h.groups {
		handler = handler.WithGroup(group)
	}
	if len(h.attrs) > 0 {
		handler = handler.WithAttrs(h.attrs)
	}
	return handler.Handle(ctx, r)
}

func (h *swapHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := &swapHandler{
		attrs:  append([]slog.Attr{}, h.attrs...),
		groups: append([]string{}, h.groups...),
	}
	next.attrs = append(next.attrs, attrs...)
	return next
}

func (h *swapHandler) WithGroup(name string) slog.Handler {
	next := &swapHandler{
		attrs:  append([]slog.Attr{}, h.attrs...),
		groups: append([]string{}, h.groups...),
	}
	next.groups = append(next.groups, name)
	return next
}

// contextKey for request-scoped loggers.
type contextKey struct{}

// WithContext attaches a logger to a context.
func WithContext(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, contextKey{}, l)
}

// FromContext retrieves the logger from a context, falling back to Default.
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(contextKey{}).(*slog.Logger); ok {
		return l
	}
	return Default
}
