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
	sshArgs := []string{
		"ssh",
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=3",
		"-p", port,
		host,
	}
	// Open Windows Terminal or cmd with ssh
	if path, err := exec.LookPath("wt"); err == nil {
		return exec.Command(path, sshArgs...).Start()
	}
	if path, err := exec.LookPath("cmd"); err == nil {
		args := append([]string{"/C", "start", ""}, sshArgs...)
		return exec.Command(path, args...).Start()
	}
	return fmt.Errorf("no terminal found to launch ssh")
}
