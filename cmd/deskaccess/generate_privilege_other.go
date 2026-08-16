//go:build !windows

package main

func requireInviteGeneratePrivilege() error {
	return nil
}
