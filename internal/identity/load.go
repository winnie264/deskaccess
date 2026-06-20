package identity

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
)

// Load returns this machine's best available identity.
// It prefers TPM hardware identity, then falls back to a software key so the app
// can still run on machines without TPM support.
func Load() (*Identity, error) {
	dir := identityDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("identity dir: %w", err)
	}

	id, err := LoadOrCreateTPM(dir)
	if err == nil {
		return id, nil
	}
	slog.Warn("identity: TPM unavailable, falling back to software identity", "err", err)
	return LoadOrCreateSoftware(filepath.Join(dir, "identity.key"))
}

func identityDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "DeskAccess")
	default:
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "DeskAccess")
	}
}
