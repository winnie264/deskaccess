//go:build windows

package tray

func displayEnvSet() bool {
	return true // Windows always has a display context
}
