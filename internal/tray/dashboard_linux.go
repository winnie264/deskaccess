//go:build !windows

package tray

// showDashboard on Linux opens the system browser.
// WebKitGTK (the Linux WebView equivalent) requires GTK on the main thread,
// which conflicts with the systray event loop already owning it.
func showDashboard(url string, closeToTray bool) {
	openBrowser(url)
}
