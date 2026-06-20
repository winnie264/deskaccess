// Package rdpcheck detects the local platform's RDP server and client
// availability, and provides setup instructions when something is missing.
package rdpcheck

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Protocol describes what the tunnel is carrying.
type Protocol string

const (
	ProtoRDP    Protocol = "rdp" // TCP 3389
	ProtoVNC    Protocol = "vnc" // TCP 5900
	ProtoSSH    Protocol = "ssh" // TCP 22
	ProtoCustom Protocol = "custom"
)

// ParseProtocol parses a string into a Protocol.
func ParseProtocol(s string) Protocol {
	switch strings.ToLower(s) {
	case "vnc":
		return ProtoVNC
	case "ssh":
		return ProtoSSH
	case "custom":
		return ProtoCustom
	default:
		return ProtoRDP
	}
}

// DefaultPort returns the default port for a protocol.
func (p Protocol) DefaultPort() int {
	switch p {
	case ProtoVNC:
		return 5900
	case ProtoSSH:
		return 22
	default:
		return 3389
	}
}

// Status is the result of checking a machine's readiness.
type Status struct {
	// Server side (host being accessed)
	ServerListening bool   // something is listening on the target port
	ServerPort      int
	ServerProtocol  Protocol
	ServerSetupCmd  string // command to install/enable the server if missing

	// Client side (machine doing the accessing)
	ClientBin       string // path to the RDP/VNC/SSH client binary
	ClientAvailable bool
	ClientInstallCmd string // how to install the client if missing

	OS              string // "windows" | "linux" | "darwin"
	IsHeadless      bool   // no display — client won't launch GUI
}

// CheckHost checks the host side: is anything listening on the target port?
func CheckHost(port int) *Status {
	s := &Status{
		OS:         runtime.GOOS,
		ServerPort: port,
	}
	s.ServerListening = portListening(port)
	s.ServerProtocol = guessProtocol(port)

	if !s.ServerListening {
		s.ServerSetupCmd = serverSetupCmd(runtime.GOOS, port)
	}
	return s
}

// CheckClient checks the client side: is there an RDP/VNC/SSH client installed?
func CheckClient(proto Protocol) *Status {
	s := &Status{
		OS:             runtime.GOOS,
		ServerProtocol: proto,
		IsHeadless:     isHeadless(),
	}

	bin, available := findClient(proto)
	s.ClientBin = bin
	s.ClientAvailable = available
	if !available {
		s.ClientInstallCmd = clientInstallCmd(runtime.GOOS, proto)
	}
	return s
}

// portListening returns true if something is accepting connections on localhost:port.
func portListening(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func guessProtocol(port int) Protocol {
	switch port {
	case 3389:
		return ProtoRDP
	case 5900, 5901, 5902:
		return ProtoVNC
	case 22:
		return ProtoSSH
	default:
		return ProtoRDP
	}
}

func isHeadless() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	// Linux/Pi headless detection
	return headlessCheck()
}

func findClient(proto Protocol) (string, bool) {
	candidates := clientCandidates(runtime.GOOS, proto)
	for _, bin := range candidates {
		if path, err := exec.LookPath(bin); err == nil {
			return path, true
		}
	}
	return "", false
}

func clientCandidates(os string, proto Protocol) []string {
	switch proto {
	case ProtoRDP:
		switch os {
		case "windows":
			return []string{"mstsc"}
		case "linux":
			return []string{"xfreerdp", "xfreerdp3", "remmina", "gnome-connections"}
		case "darwin":
			return []string{"/Applications/Microsoft Remote Desktop.app/Contents/MacOS/msrdp", "remmina"}
		}
	case ProtoVNC:
		switch os {
		case "windows":
			return []string{"tvnviewer", "vncviewer"}
		case "linux":
			return []string{"vncviewer", "tigervnc", "xtigervncviewer", "remmina"}
		case "darwin":
			return []string{"open"} // macOS Screen Sharing built-in
		}
	case ProtoSSH:
		return []string{"ssh"}
	}
	return nil
}

func serverSetupCmd(os string, port int) string {
	proto := guessProtocol(port)
	switch proto {
	case ProtoRDP:
		switch os {
		case "windows":
			return "Settings → System → Remote Desktop → Enable Remote Desktop"
		case "linux":
			return "sudo apt install xrdp && sudo systemctl enable --now xrdp"
		}
	case ProtoVNC:
		switch os {
		case "linux":
			return "sudo apt install tigervnc-standalone-server && vncserver :1"
		case "windows":
			return "Install TightVNC: https://tightvnc.com"
		}
	case ProtoSSH:
		switch os {
		case "linux":
			return "sudo systemctl enable --now ssh"
		case "windows":
			return "Settings → Apps → Optional Features → OpenSSH Server"
		}
	}
	return ""
}

func clientInstallCmd(os string, proto Protocol) string {
	switch proto {
	case ProtoRDP:
		switch os {
		case "linux":
			return "sudo apt install freerdp2-x11   # Debian/Ubuntu/Pi\n" +
				"sudo dnf install freerdp          # Fedora\n" +
				"sudo pacman -S freerdp            # Arch"
		case "darwin":
			return "Install 'Microsoft Remote Desktop' from the Mac App Store"
		}
	case ProtoVNC:
		switch os {
		case "linux":
			return "sudo apt install tigervnc-viewer"
		case "darwin":
			return "Built-in: Finder → Go → Connect to Server → vnc://address"
		}
	}
	return ""
}
