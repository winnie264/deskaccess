//go:build windows

package ipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	processQueryLimitedInfo  = 0x1000
	maxProcessImagePathChars = 32768
)

var (
	kernel32IPC                      = syscall.NewLazyDLL("kernel32.dll")
	procGetNamedPipeClientProcessID  = kernel32IPC.NewProc("GetNamedPipeClientProcessId")
	procOpenProcessIPC               = kernel32IPC.NewProc("OpenProcess")
	procQueryFullProcessImageNameIPC = kernel32IPC.NewProc("QueryFullProcessImageNameW")
	procCloseHandleIPC               = kernel32IPC.NewProc("CloseHandle")
	currentExecutablePathForIPC, _   = os.Executable()
	currentExecutableCleanPathForIPC = strings.ToLower(filepath.Clean(currentExecutablePathForIPC))
)

func authorizeClient(conn net.Conn) error {
	pid, err := pipeClientPID(conn)
	if err != nil {
		return err
	}
	path, err := processImagePath(pid)
	if err != nil {
		return fmt.Errorf("inspect client process %d: %w", pid, err)
	}
	if strings.ToLower(filepath.Clean(path)) != currentExecutableCleanPathForIPC {
		return fmt.Errorf("untrusted process pid=%d path=%q", pid, path)
	}
	return nil
}

func pipeClientPID(conn net.Conn) (uint32, error) {
	fdConn, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return 0, fmt.Errorf("named pipe connection does not expose a handle")
	}
	var pid uint32
	ret, _, err := procGetNamedPipeClientProcessID.Call(
		fdConn.Fd(),
		uintptr(unsafe.Pointer(&pid)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("GetNamedPipeClientProcessId: %w", err)
	}
	if pid == 0 {
		return 0, fmt.Errorf("GetNamedPipeClientProcessId returned pid 0")
	}
	return pid, nil
}

func processImagePath(pid uint32) (string, error) {
	h, _, err := procOpenProcessIPC.Call(processQueryLimitedInfo, 0, uintptr(pid))
	if h == 0 {
		return "", err
	}
	defer procCloseHandleIPC.Call(h)
	buf := make([]uint16, maxProcessImagePathChars)
	size := uint32(len(buf))
	ret, _, err := procQueryFullProcessImageNameIPC.Call(
		h,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		return "", err
	}
	return syscall.UTF16ToString(buf[:size]), nil
}
