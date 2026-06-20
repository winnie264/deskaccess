package assets

import _ "embed"

// DeskviewIconICO is the Windows app/tray icon.
//
//go:embed deskview.ico
var DeskviewIconICO []byte

// DeskviewIcon32 is the app icon used for tray/status UI.
//
//go:embed deskview-32.png
var DeskviewIcon32 []byte
