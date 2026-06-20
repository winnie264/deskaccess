// Package ipc provides the IPC channel between the daemon process and the
// tray process. The transport is platform-specific:
//   - Windows: named pipe  \\.\pipe\DeskAccess
//     Security descriptor grants access to SYSTEM + Administrators +
//     Interactive Users (any currently logged-in user). The OS enforces this —
//     no application-level secret is needed.
//   - Linux/other: Unix socket in $XDG_RUNTIME_DIR with mode 0600.
//     The kernel enforces owner-only access.
//
// Protocol: newline-delimited JSON request → response over the transport.
package ipc

import (
	"context"
	"encoding/json"
	"net"
)

// Request is sent by the tray to the daemon.
type Request struct {
	Cmd      string `json:"cmd"`                // "status" | "generate"
	Mode     string `json:"mode,omitempty"`     // "onetime" | "pairing" (for "generate")
	Protocol string `json:"protocol,omitempty"` // "rdp" | "vnc" | "ssh" | "custom"
	Port     int    `json:"port,omitempty"`     // 0 = protocol default
	Label    string `json:"label,omitempty"`    // optional invite label
}

// Response is sent by the daemon to the tray.
type Response struct {
	// Populated for cmd=status
	NodeID     string `json:"node_id,omitempty"`
	Label      string `json:"label,omitempty"`
	WebuiURL   string `json:"webui_url,omitempty"` // fresh single-use launch token
	RelayCount int    `json:"relay_count,omitempty"`
	LogFile    string `json:"log_file,omitempty"`

	// Populated for cmd=generate
	InviteURL string `json:"invite_url,omitempty"`

	Error string `json:"error,omitempty"`
}

// Handler processes IPC requests on the daemon side.
type Handler func(Request) Response

// Serve starts the IPC server and calls h for every incoming request.
// Returns immediately; runs in background goroutines until ctx is cancelled.
func Serve(ctx context.Context, h Handler) error {
	l, err := listen()
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	go func() {
		defer l.Close()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go serveConn(conn, h)
		}
	}()
	return nil
}

func serveConn(conn net.Conn, h Handler) {
	defer conn.Close()
	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}
	json.NewEncoder(conn).Encode(h(req))
}

// Query sends req to the daemon and returns its response.
func Query(req Request) (*Response, error) {
	conn, err := dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
