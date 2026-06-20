//go:build windows

package tunnel

import (
	"fmt"
	"os/exec"
)

func launchRDP(localAddr string) error {
	loopbackAddr := loopbackClientAddr(localAddr)
	return launchMstscDirect(loopbackAddr)
}

func launchMstscDirect(localAddr string) error {
	fmt.Printf("tunnel: launching mstsc /v:%s\n", localAddr)
	return exec.Command("mstsc", fmt.Sprintf("/v:%s", localAddr)).Start()
}

func rdpClientName() string { return "mstsc" }

// splitHostPort splits "127.0.0.1:13389" into ("127.0.0.1", "13389").
func splitHostPort(addr string) (host, port string) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:]
		}
	}
	return addr, "3389"
}
