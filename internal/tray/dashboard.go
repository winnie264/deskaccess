package tray

import "sync"

// Only one dashboard window at a time — clicking "Open Dashboard" while one is
// already open is a no-op rather than spawning a second window.
var (
	dashMu   sync.Mutex
	dashOpen bool
)

// openDashboard opens the web UI in an embedded window (WebView2 on Windows,
// system browser fallback on other platforms). Non-blocking — the window runs
// in its own goroutine. Calling again while a window is already open is a
// no-op; the token is not wasted.
func openDashboard(url string) {
	if FocusDashboardWindow() {
		return
	}

	dashMu.Lock()
	if dashOpen {
		dashMu.Unlock()
		return
	}
	dashOpen = true
	dashMu.Unlock()

	go func() {
		defer func() {
			dashMu.Lock()
			dashOpen = false
			dashMu.Unlock()
		}()
		showDashboard(url)
	}()
}

// ShowDashboard opens the dashboard and blocks until the window is closed.
// It is used by a second app launch to show the existing service UI, then exit
// without starting another tray instance.
func ShowDashboard(url string) {
	if FocusDashboardWindow() {
		return
	}
	showDashboard(url)
}
