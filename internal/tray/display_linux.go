//go:build linux

package tray

import "os"

func displayEnvSet() bool {
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}
