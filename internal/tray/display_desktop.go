//go:build windows || linux

package tray

func HasDesktopDisplay() bool {
	return displayEnvSet()
}
