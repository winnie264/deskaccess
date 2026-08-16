//go:build windows

package main

import (
	"fmt"
	"syscall"
)

var (
	shell32                 = syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdminForCLI = shell32.NewProc("IsUserAnAdmin")
)

func requireInviteGeneratePrivilege() error {
	ret, _, err := procIsUserAnAdminForCLI.Call()
	if ret == 0 {
		if err != syscall.Errno(0) {
			return fmt.Errorf("invite generation from --generate requires an elevated administrator process: %w", err)
		}
		return fmt.Errorf("invite generation from --generate requires an elevated administrator process")
	}
	return nil
}
