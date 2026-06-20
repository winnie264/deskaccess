//go:build linux

package tunnel

import (
	"fmt"
	"os"
	"os/exec"
)

// rdpClients lists Linux RDP clients tried in order of preference.
// xfreerdp is the best CLI client; remmina is GUI; gnome-connections is modern GNOME.
var rdpClients = []rdpLauncher{
	{
		bin:  "xfreerdp",
		args: func(addr string) []string {
			host, port := splitHostPort(addr)
			return []string{
				fmt.Sprintf("/v:%s", host),
				fmt.Sprintf("/port:%s", port),
				"/dynamic-resolution",
				"/smart-sizing",
				"/sound",
				"/clipboard",
				"+home-drive",
			}
		},
	},
	{
		bin:  "xfreerdp3", // newer distros package it as xfreerdp3
		args: func(addr string) []string {
			host, port := splitHostPort(addr)
			return []string{
				fmt.Sprintf("/v:%s", host),
				fmt.Sprintf("/port:%s", port),
				"/dynamic-resolution",
			}
		},
	},
	{
		bin:  "remmina",
		args: func(addr string) []string {
			return []string{"-c", fmt.Sprintf("rdp://%s", addr)}
		},
	},
	{
		bin:  "gnome-connections", // GNOME 42+
		args: func(addr string) []string {
			return []string{fmt.Sprintf("rdp://%s", addr)}
		},
	},
}

type rdpLauncher struct {
	bin  string
	args func(addr string) []string
}

func launchRDP(localAddr string) error {
	// Headless (Pi, server): no display — just print
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		fmt.Printf("tunnel: RDP tunnel ready at %s\n", localAddr)
		fmt.Printf("  Connect with: xfreerdp /v:%s\n", localAddr)
		return nil
	}

	// Desktop Linux: try each client in order
	for _, client := range rdpClients {
		path, err := exec.LookPath(client.bin)
		if err != nil {
			continue
		}
		args := client.args(localAddr)
		cmd := exec.Command(path, args...)
		if err := cmd.Start(); err != nil {
			continue
		}
		fmt.Printf("tunnel: launched %s → %s\n", client.bin, localAddr)
		return nil
	}

	// No RDP client found — tell the user
	fmt.Printf("tunnel: no RDP client found. Install xfreerdp:\n")
	fmt.Printf("  sudo apt install freerdp2-x11   # Debian/Ubuntu/Pi\n")
	fmt.Printf("  sudo dnf install freerdp         # Fedora\n")
	fmt.Printf("  sudo pacman -S freerdp           # Arch\n")
	fmt.Printf("  Then connect to: %s\n", localAddr)
	return fmt.Errorf("no RDP client installed (tried: xfreerdp, remmina, gnome-connections)")
}

func rdpClientName() string {
	for _, c := range rdpClients {
		if _, err := exec.LookPath(c.bin); err == nil {
			return c.bin
		}
	}
	return "none"
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
