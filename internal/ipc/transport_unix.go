//go:build !windows

package ipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const systemSocketPath = "/run/deskaccess/DeskAccess.sock"

func userSocketPath() string {
	// XDG_RUNTIME_DIR is a per-user tmpfs directory owned by the user (mode 0700).
	// It is the right home for sockets that must not be readable by other users.
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "DeskAccess.sock")
	}
	// Fallback: /tmp/DeskAccess-<uid>.sock  — uid in name prevents collisions
	// between users; chmod 0600 below prevents cross-user reads.
	return fmt.Sprintf("/tmp/DeskAccess-%d.sock", os.Getuid())
}

func listenSocketPath() string {
	if p := os.Getenv("DESKACCESS_IPC_SOCKET"); p != "" {
		return p
	}
	if _, err := os.Stat(filepath.Dir(systemSocketPath)); err == nil {
		return systemSocketPath
	}
	return userSocketPath()
}

func dialSocketPaths() []string {
	if p := os.Getenv("DESKACCESS_IPC_SOCKET"); p != "" {
		return []string{p}
	}
	paths := []string{userSocketPath(), systemSocketPath}
	seen := make(map[string]bool, len(paths))
	out := paths[:0]
	for _, p := range paths {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func listen() (net.Listener, error) {
	path := listenSocketPath()
	os.MkdirAll(filepath.Dir(path), 0700)
	os.Remove(path) // clean up stale socket from a previous crash
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if path == systemSocketPath {
		os.Chmod(path, 0660) // owner + deskaccess group can request dashboard URLs
	} else {
		os.Chmod(path, 0600) // kernel enforces: owner process only
	}
	return l, nil
}

func dial() (net.Conn, error) {
	var errs []string
	for _, path := range dialSocketPaths() {
		conn, err := net.Dial("unix", path)
		if err == nil {
			return conn, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", path, err))
	}
	return nil, fmt.Errorf("all IPC sockets failed: %s", strings.Join(errs, "; "))
}
