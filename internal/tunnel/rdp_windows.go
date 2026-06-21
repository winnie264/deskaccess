//go:build windows

package tunnel

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func launchRDP(localAddr string) error {
	loopbackAddr := loopbackClientAddr(localAddr)
	return launchMstscDirect(loopbackAddr)
}

func launchMstscDirect(localAddr string) error {
	fmt.Printf("tunnel: launching mstsc /v:%s\n", localAddr)
	return exec.Command(mstscPath(), fmt.Sprintf("/v:%s", localAddr)).Start()
}

func rdpClientName() string { return "mstsc" }

func mstscPath() string {
	if systemRoot := os.Getenv("SystemRoot"); systemRoot != "" {
		path := filepath.Join(systemRoot, "System32", "mstsc.exe")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	if path, err := exec.LookPath("mstsc.exe"); err == nil {
		return path
	}
	return "mstsc.exe"
}

// splitHostPort splits "127.0.0.1:13389" into ("127.0.0.1", "13389").
func splitHostPort(addr string) (host, port string) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:]
		}
	}
	return addr, "3389"
}
