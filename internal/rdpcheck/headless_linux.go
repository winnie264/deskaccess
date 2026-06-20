//go:build linux

package rdpcheck

import "os"

func headlessCheck() bool {
	return os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == ""
}
