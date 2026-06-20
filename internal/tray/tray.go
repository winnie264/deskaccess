//go:build !(linux && (arm || arm64))

package tray

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"github.com/getlantern/systray"
	"github.com/rdpanywhere/rdpanywhere/internal/assets"
	"github.com/rdpanywhere/rdpanywhere/internal/ipc"
)

// HasDisplay returns true if a GUI environment is available.
func HasDisplay() bool {
	switch runtime.GOOS {
	case "windows":
		return true
	case "linux", "freebsd":
		return displayEnvSet()
	default:
		return false
	}
}

type Tray struct {
	ctx context.Context
}

func New(ctx context.Context) *Tray {
	return &Tray{ctx: ctx}
}

// Run starts the systray — blocks until quit. Call only if HasDisplay() == true.
func (t *Tray) Run() {
	systray.Run(t.onReady, t.onExit)
}

func (t *Tray) onReady() {
	systray.SetIcon(iconData())
	systray.SetTitle("DeskAccess")
	systray.SetTooltip("DeskAccess — connecting to service...")

	mOpenUI := systray.AddMenuItem("Open Dashboard", "Open DeskAccess dashboard")
	mOpenUI.SetIcon(iconData())

	systray.AddSeparator()

	mNodeID := systray.AddMenuItem("Connecting...", "Waiting for service")
	mNodeID.Disable()

	systray.AddSeparator()

	mOneTime := systray.AddMenuItem("Generate One-Time Link", "Create a temporary access link")
	mPairing := systray.AddMenuItem("Generate Pairing Link", "Pair a new admin device")

	systray.AddSeparator()

	mQuit := systray.AddMenuItem("Quit", "Stop DeskAccess tray")

	// Poll the daemon via IPC on a ticker; update tray status.
	statusCh := make(chan *ipc.Response, 1)
	go func() {
		poll := func() {
			if st, err := ipc.Query(ipc.Request{Cmd: "status"}); err == nil {
				statusCh <- st
			}
		}
		poll() // immediate first poll
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				poll()
			case <-t.ctx.Done():
				return
			}
		}
	}()

	var lastStatus *ipc.Response
	dashAutoOpened := false

	for {
		select {
		case st := <-statusCh:
			lastStatus = st
			short := st.NodeID
			if len(short) > 16 {
				short = short[:16] + "..."
			}
			mNodeID.SetTitle("NodeID: " + short)
			systray.SetTooltip(fmt.Sprintf("DeskAccess — %s", st.Label))
			// Auto-open the dashboard on first successful status.
			if !dashAutoOpened && st.WebuiURL != "" {
				dashAutoOpened = true
				openDashboard(st.WebuiURL)
			}

		case <-mOneTime.ClickedCh:
			resp, err := ipc.Query(ipc.Request{Cmd: "generate", Mode: "onetime"})
			if err != nil || resp.Error != "" {
				fmt.Println("Error generating one-time link:", err)
				continue
			}
			copyToClipboard(resp.InviteURL)
			fmt.Println("One-time link copied:", resp.InviteURL)

		case <-mPairing.ClickedCh:
			resp, err := ipc.Query(ipc.Request{Cmd: "generate", Mode: "pairing"})
			if err != nil || resp.Error != "" {
				fmt.Println("Error generating pairing link:", err)
				continue
			}
			copyToClipboard(resp.InviteURL)
			fmt.Println("Pairing link copied:", resp.InviteURL)

		case <-mOpenUI.ClickedCh:
			// Request a fresh status to get a fresh single-use launch token.
			st, err := ipc.Query(ipc.Request{Cmd: "status"})
			if err != nil {
				if lastStatus != nil {
					st = lastStatus
				} else {
					fmt.Println("Service not reachable:", err)
					continue
				}
			}
			openDashboard(st.WebuiURL)

		case <-mQuit.ClickedCh:
			systray.Quit()
			return

		case <-t.ctx.Done():
			systray.Quit()
			return
		}
	}
}

func (t *Tray) onExit() {}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	}
	if cmd != nil {
		cmd.Start()
	}
}

func copyToClipboard(text string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "echo", text, "|", "clip")
	case "linux":
		cmd = exec.Command("bash", "-c", fmt.Sprintf("echo -n '%s' | xclip -selection clipboard", text))
	}
	if cmd != nil {
		cmd.Run()
	}
}

// iconData returns platform-appropriate tray icon bytes.
func iconData() []byte {
	if runtime.GOOS == "windows" {
		return assets.DeskviewIconICO
	}
	return assets.DeskviewIcon32
}
