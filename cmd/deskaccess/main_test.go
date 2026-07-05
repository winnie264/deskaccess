package main

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func TestDashboardURLWithConnectPreservesNestedInviteQuery(t *testing.T) {
	invite := "deskaccess://abc123/?backend=iroh&iroh_ticket=iroh-sidecar-v1%3Axyz&v=1"
	got := dashboardURLWithConnect("http://127.0.0.1:18080/?token=tok", invite)

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse dashboard URL: %v", err)
	}
	if u.Query().Get("token") != "tok" {
		t.Fatalf("token query missing in %q", got)
	}
	encoded := u.Query().Get("connect_b64")
	if encoded == "" {
		t.Fatalf("connect_b64 query missing in %q", got)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode connect_b64: %v", err)
	}
	if string(decoded) != invite {
		t.Fatalf("decoded invite = %q, want %q", decoded, invite)
	}
}
