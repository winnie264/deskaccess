//go:build windows

package tray

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
)

const swMaximize = 3

var (
	user32                  = syscall.NewLazyDLL("user32.dll")
	shell32                 = syscall.NewLazyDLL("shell32.dll")
	procFindWindowW         = user32.NewProc("FindWindowW")
	procShowWindow          = user32.NewProc("ShowWindow")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procSendMessageW        = user32.NewProc("SendMessageW")
	procExtractIconExW      = shell32.NewProc("ExtractIconExW")
)

const (
	wmSetIcon  = 0x0080
	iconSmall  = 0
	iconBig    = 1
	iconSmall2 = 2
)

// showDashboard opens the UI in an embedded WebView2 window.
// WebView2 runtime is pre-installed on Windows 10 20H2+ and Windows 11.
// Falls back to the system browser on older Windows.
//
// runtime.LockOSThread is required: WebView2 uses COM/STA which must stay
// on the same OS thread for the full lifetime of the window. Without it the
// Windows message pump drops events under scheduler pressure (DHT goroutines,
// etc.) and the window appears to hang.
func showDashboard(url string) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if FocusDashboardWindow() {
		return
	}

	w := webview2.New(false)
	if w == nil {
		openBrowser(url)
		return
	}
	defer w.Destroy()
	w.SetTitle("DeskAccess")
	w.SetSize(1200, 820, webview2.HintNone)
	setWindowIcon(w.Window())
	maximizeWindow(w.Window())
	w.Navigate(url)
	w.Run()
}

func setWindowIcon(hwnd unsafe.Pointer) {
	if hwnd == nil {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	exePtr, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return
	}
	var largeIcon uintptr
	var smallIcon uintptr
	ret, _, _ := procExtractIconExW.Call(
		uintptr(unsafe.Pointer(exePtr)),
		0,
		uintptr(unsafe.Pointer(&largeIcon)),
		uintptr(unsafe.Pointer(&smallIcon)),
		1,
	)
	if ret == 0 {
		return
	}
	hwndPtr := uintptr(hwnd)
	if smallIcon != 0 {
		procSendMessageW.Call(hwndPtr, wmSetIcon, iconSmall, smallIcon)
		procSendMessageW.Call(hwndPtr, wmSetIcon, iconSmall2, smallIcon)
	}
	if largeIcon != 0 {
		procSendMessageW.Call(hwndPtr, wmSetIcon, iconBig, largeIcon)
	}
}

func maximizeWindow(hwnd unsafe.Pointer) {
	if hwnd == nil {
		return
	}
	showAndFocusWindow(uintptr(hwnd))
}

// FocusDashboardWindow brings an existing dashboard window to the front.
// This is used by second app launches so they activate the existing UI instead
// of creating another WebView process/window.
func FocusDashboardWindow() bool {
	title, err := syscall.UTF16PtrFromString("DeskAccess")
	if err != nil {
		return false
	}
	hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(title)))
	if hwnd == 0 {
		return false
	}
	showAndFocusWindow(hwnd)
	return true
}

func showAndFocusWindow(hwnd uintptr) {
	procShowWindow.Call(hwnd, swMaximize)
	procSetForegroundWindow.Call(hwnd)
}
