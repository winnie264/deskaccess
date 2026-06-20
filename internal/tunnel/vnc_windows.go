//go:build windows

package tunnel

import (
	"fmt"
	"os/exec"
)

func launchVNC(localAddr string) error {
	// Try common Windows VNC viewers
	for _, bin := range []string{"tvnviewer", "vncviewer", "ultravnc_viewer"} {
		if path, err := exec.LookPath(bin); err == nil {
			fmt.Printf("tunnel: launching %s → %s\n", bin, localAddr)
			return exec.Command(path, localAddr).Start()
		}
	}
	return fmt.Errorf("no VNC viewer found (install TightVNC, UltraVNC, or RealVNC)")
}

func vncClientName() string {
	for _, bin := range []string{"tvnviewer", "vncviewer", "ultravnc_viewer"} {
		if _, err := exec.LookPath(bin); err == nil {
			return bin
		}
	}
	return "none"
}

func launchSSH(localAddr string) error {
	host, port := splitHostPort(localAddr)
	fmt.Printf("tunnel: opening SSH terminal → %s\n", localAddr)
	// Open Windows Terminal or cmd with ssh
	for _, term := range []string{"wt", "cmd"} {
		if path, err := exec.LookPath(term); err == nil {
			return exec.Command(path, "ssh", fmt.Sprintf("-p %s %s", port, host)).Start()
		}
	}
	return exec.Command("cmd", "/C", "start", "ssh",
		fmt.Sprintf("-p"), port, host).Start()
}
