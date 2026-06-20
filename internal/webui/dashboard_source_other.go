//go:build !windows

package webui

import "net/http"

func allowDashboardSource(r *http.Request) bool {
	return true
}
