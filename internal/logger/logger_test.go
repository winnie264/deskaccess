package logger

import (
	"bytes"
	"errors"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitWritesLogFile(t *testing.T) {
	resetForTest(t)

	logPath := filepath.Join(t.TempDir(), "nested", "DeskAccess.log")
	if err := Init(logPath, false); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer closeActiveLogForTest(t)
	if CurrentLogFile() != logPath {
		t.Fatalf("CurrentLogFile() = %q, want %q", CurrentLogFile(), logPath)
	}

	slog.Info("logger test slog write", "case", "slog")
	log.Print("logger test stdlib write")

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", logPath, err)
	}
	content := string(data)
	for _, want := range []string{
		"logger bootstrap",
		"logger initialized",
		"logger test slog write",
		"logger test stdlib write",
		`"component":"stdlib"`,
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("log file missing %q\ncontent:\n%s", want, content)
		}
	}
}

func TestTailReadsActiveLogFile(t *testing.T) {
	resetForTest(t)

	logPath := filepath.Join(t.TempDir(), "DeskAccess.log")
	if err := Init(logPath, false); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer closeActiveLogForTest(t)
	slog.Info("tail line one")
	slog.Info("tail line two")

	lines, err := Tail(1)
	if err != nil {
		t.Fatalf("Tail() error = %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("Tail(1) returned %d lines, want 1: %#v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "tail line two") {
		t.Fatalf("Tail(1) = %q, want latest line", lines[0])
	}
}

func TestInitWritesLogFileWhenStderrFails(t *testing.T) {
	resetForTest(t)
	stderrWriter = failingWriter{}
	t.Cleanup(func() { stderrWriter = os.Stderr })

	logPath := filepath.Join(t.TempDir(), "DeskAccess.log")
	if err := Init(logPath, false); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer closeActiveLogForTest(t)

	slog.Info("logger survives broken stderr")

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", logPath, err)
	}
	content := string(data)
	if !strings.Contains(content, "logger survives broken stderr") {
		t.Fatalf("log file missing slog line after stderr failure\ncontent:\n%s", content)
	}
}

func TestBestEffortWriterReturnsSuccessWhenAnyWriterSucceeds(t *testing.T) {
	var buf bytes.Buffer
	w := bestEffortMultiWriter(&buf, failingWriter{})

	n, err := w.Write([]byte("still logged"))
	if err != nil {
		t.Fatalf("Write() error = %v, want nil when one writer succeeds", err)
	}
	if n != len("still logged") {
		t.Fatalf("Write() = %d, want %d", n, len("still logged"))
	}
	if got := buf.String(); got != "still logged" {
		t.Fatalf("buffer = %q, want logged content", got)
	}
}

func closeActiveLogForTest(t *testing.T) {
	t.Helper()
	logMu.Lock()
	defer logMu.Unlock()
	if logFileHandle != nil {
		if err := logFileHandle.Close(); err != nil {
			t.Fatalf("close active log: %v", err)
		}
		logFileHandle = nil
	}
	logPath = ""
	target = slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelInfo})
}

func resetForTest(t *testing.T) {
	t.Helper()

	logMu.Lock()
	if logFileHandle != nil {
		_ = logFileHandle.Close()
		logFileHandle = nil
	}
	target = slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelInfo})
	logPath = ""
	logMu.Unlock()

	t.Cleanup(func() {
		logMu.Lock()
		if logFileHandle != nil {
			_ = logFileHandle.Close()
			logFileHandle = nil
		}
		logPath = ""
		logMu.Unlock()
	})

	log.SetFlags(0)
	log.SetOutput(os.Stderr)
	stderrWriter = os.Stderr
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	t.Setenv("DESKACCESS_LOG", "")
	t.Setenv("DeskAccess_LOG", "")
	t.Setenv("DESKACCESS_DEBUG", "")
	t.Setenv("DeskAccess_DEBUG", "")
}

type failingWriter struct{}

func (failingWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("stderr unavailable")
}
