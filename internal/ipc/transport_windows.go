//go:build windows

package ipc

import (
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

const pipeName = `\\.\pipe\DeskAccess`

// listen creates the named pipe. The security descriptor grants:
//
//	SY  = SYSTEM (service account)          — full access
//	BA  = Built-in Administrators           — full access
//	IU  = Interactive Users (logged-in users) — read + write
//
// Other local users are implicitly denied. The OS enforces this — no
// application-level secret is required.
func listen() (net.Listener, error) {
	return winio.ListenPipe(pipeName, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)",
	})
}

func dial() (net.Conn, error) {
	timeout := 3 * time.Second
	return winio.DialPipe(pipeName, &timeout)
}
