//go:build !windows

package ipc

import "net"

func authorizeClient(conn net.Conn) error {
	return nil
}
