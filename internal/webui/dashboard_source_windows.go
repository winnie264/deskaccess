//go:build windows

package webui

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	afInet                   = 2
	tcpTableOwnerPIDAll      = 5
	processQueryLimitedInfo  = 0x1000
	invalidHandleValue       = ^uintptr(0)
	th32csSnapProcess        = 0x00000002
	maxProcessImagePathChars = 32768
)

var (
	iphlpapi                           = syscall.NewLazyDLL("iphlpapi.dll")
	kernel32                           = syscall.NewLazyDLL("kernel32.dll")
	procGetExtendedTCPTable            = iphlpapi.NewProc("GetExtendedTcpTable")
	procOpenProcess                    = kernel32.NewProc("OpenProcess")
	procQueryFullProcessImageNameW     = kernel32.NewProc("QueryFullProcessImageNameW")
	procCloseHandle                    = kernel32.NewProc("CloseHandle")
	procCreateToolhelp32Snapshot       = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW                = kernel32.NewProc("Process32FirstW")
	procProcess32NextW                 = kernel32.NewProc("Process32NextW")
	currentExecutablePathForWebUI, _   = os.Executable()
	currentExecutableNameForWebUI      = strings.ToLower(filepath.Base(currentExecutablePathForWebUI))
	currentExecutableCleanPathForWebUI = strings.ToLower(filepath.Clean(currentExecutablePathForWebUI))
)

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type processEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

func allowDashboardSource(r *http.Request) bool {
	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		webLog.Warn("dashboard source check failed to parse remote address", "remote_addr", r.RemoteAddr, "err", err)
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		webLog.Warn("dashboard source rejected non-loopback address", "remote_addr", r.RemoteAddr)
		return false
	}
	remotePort, err := net.LookupPort("tcp", port)
	if err != nil {
		webLog.Warn("dashboard source check failed to parse port", "remote_addr", r.RemoteAddr, "err", err)
		return false
	}
	pid, err := tcpOwnerPID(remotePort)
	if err != nil {
		webLog.Warn("dashboard source check failed to find TCP owner", "remote_addr", r.RemoteAddr, "remote_port", remotePort, "err", err)
		return false
	}
	if pidBelongsToDeskAccess(pid) {
		return true
	}
	webLog.Warn("dashboard source rejected non-DeskAccess process", "remote_addr", r.RemoteAddr, "remote_port", remotePort, "pid", pid)
	return false
}

func tcpOwnerPID(remotePort int) (uint32, error) {
	var size uint32
	ret, _, _ := procGetExtendedTCPTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		1,
		afInet,
		tcpTableOwnerPIDAll,
		0,
	)
	if size == 0 {
		return 0, fmt.Errorf("GetExtendedTcpTable size failed: %d", ret)
	}
	buf := make([]byte, size)
	ret, _, err := procGetExtendedTCPTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		afInet,
		tcpTableOwnerPIDAll,
		0,
	)
	if ret != 0 {
		return 0, fmt.Errorf("GetExtendedTcpTable failed: %w", err)
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
	base := uintptr(unsafe.Pointer(&buf[4]))
	for i := uint32(0); i < count; i++ {
		row := (*mibTCPRowOwnerPID)(unsafe.Pointer(base + uintptr(i)*rowSize))
		if tcpPort(row.LocalPort) == 18080 && tcpPort(row.RemotePort) == remotePort {
			return row.OwningPID, nil
		}
	}
	return 0, fmt.Errorf("no TCP owner for remote port %d", remotePort)
}

func tcpPort(raw uint32) int {
	return int((raw&0xff)<<8 | (raw>>8)&0xff)
}

func pidBelongsToDeskAccess(pid uint32) bool {
	if processPathMatchesDeskAccess(pid) {
		return true
	}
	parents := processParentMap()
	seen := map[uint32]bool{}
	for {
		if seen[pid] {
			return false
		}
		seen[pid] = true
		parent, ok := parents[pid]
		if !ok || parent == 0 || parent == pid {
			return false
		}
		if processPathMatchesDeskAccess(parent) {
			return true
		}
		pid = parent
	}
}

func processPathMatchesDeskAccess(pid uint32) bool {
	path, err := processImagePath(pid)
	if err != nil || path == "" {
		return false
	}
	clean := strings.ToLower(filepath.Clean(path))
	if currentExecutableCleanPathForWebUI != "" && clean == currentExecutableCleanPathForWebUI {
		return true
	}
	return strings.ToLower(filepath.Base(clean)) == currentExecutableNameForWebUI
}

func processImagePath(pid uint32) (string, error) {
	h, _, err := procOpenProcess.Call(processQueryLimitedInfo, 0, uintptr(pid))
	if h == 0 {
		return "", err
	}
	defer procCloseHandle.Call(h)
	buf := make([]uint16, maxProcessImagePathChars)
	size := uint32(len(buf))
	ret, _, err := procQueryFullProcessImageNameW.Call(
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

func processParentMap() map[uint32]uint32 {
	parents := make(map[uint32]uint32)
	snap, _, _ := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snap == invalidHandleValue || snap == 0 {
		return parents
	}
	defer procCloseHandle.Call(snap)
	var pe processEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	ret, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&pe)))
	for ret != 0 {
		parents[pe.ProcessID] = pe.ParentProcessID
		ret, _, _ = procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&pe)))
	}
	return parents
}
