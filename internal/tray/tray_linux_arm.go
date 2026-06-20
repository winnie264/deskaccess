//go:build linux && arm

package tray

import "context"

// HasDisplay is intentionally false on Raspberry Pi/Linux ARM builds so the
// main binary runs as a headless daemon and does not link GTK/appindicator tray
// dependencies.
func HasDisplay() bool { return false }

type Tray struct {
	ctx context.Context
}

func New(ctx context.Context) *Tray {
	return &Tray{ctx: ctx}
}

func (t *Tray) Run() {
	<-t.ctx.Done()
}

func openBrowser(string) {}

func copyToClipboard(string) {}
