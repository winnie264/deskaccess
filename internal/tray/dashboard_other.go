//go:build !windows

package tray

func FocusDashboardWindow() bool {
	return false
}
