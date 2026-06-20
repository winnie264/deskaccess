//go:build linux

package tunnel

import (
	"fmt"
	"os"
	"os/exec"
)

func launchVNC(localAddr string) error {
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		fmt.Printf("tunnel: VNC tunnel ready at %s\n", localAddr)
		fmt.Printf("  Connect with: vncviewer %s\n", localAddr)
		return nil
	}
	for _, bin := range []string{"xtigervncviewer", "vncviewer", "remmina"} {
		if path, err := exec.LookPath(bin); err == nil {
			fmt.Printf("tunnel: launching %s → %s\n", bin, localAddr)
			if bin == "remmina" {
				return exec.Command(path, "-c", "vnc://"+localAddr).Start()
			}
			return exec.Command(path, localAddr).Start()
		}
	}
	return fmt.Errorf("no VNC viewer found\n  sudo apt install tigervnc-viewer")
}

func vncClientName() string {
	for _, bin := range []string{"xtigervncviewer", "vncviewer"} {
		if _, err := exec.LookPath(bin); err == nil {
			return bin
		}
	}
	return "none"
}

func launchSSH(localAddr string) error {
	host, port := splitHostPort(localAddr)
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		fmt.Printf("tunnel: SSH tunnel ready — run: ssh -p %s %s\n", port, host)
		return nil
	}
	// Try to open a terminal with SSH
	for _, term := range []string{"gnome-terminal", "xterm", "konsole", "xfce4-terminal"} {
		if path, err := exec.LookPath(term); err == nil {
			var cmd *exec.Cmd
			switch term {
			case "gnome-terminal":
				cmd = exec.Command(path, "--", "ssh", "-p", port, host)
			default:
				cmd = exec.Command(path, "-e", fmt.Sprintf("ssh -p %s %s", port, host))
			}
			return cmd.Start()
		}
	}
	// Fallback: just exec ssh directly (will use existing terminal)
	fmt.Printf("tunnel: SSH → run: ssh -p %s %s\n", port, host)
	return nil
}
