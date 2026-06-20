package tunnel

import (
	"net"
	"testing"

	"github.com/rdpanywhere/rdpanywhere/internal/config"
)

func TestListenLocalTunnelFallsBackWhenPreferredPortBusy(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy preferred port: %v", err)
	}
	defer occupied.Close()

	ln, err := listenLocalTunnel(occupied.Addr().String())
	if err != nil {
		t.Fatalf("listenLocalTunnel: %v", err)
	}
	defer ln.Close()

	if ln.Addr().String() == occupied.Addr().String() {
		t.Fatalf("expected dynamic fallback port, got same addr %s", ln.Addr())
	}
}

func TestListenLocalTunnelDefaultsToDynamicLoopback(t *testing.T) {
	ln, err := listenLocalTunnel("")
	if err != nil {
		t.Fatalf("listenLocalTunnel: %v", err)
	}
	defer ln.Close()

	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("host: want 127.0.0.1, got %s", host)
	}
	if port == "0" || port == "" {
		t.Fatalf("expected assigned port, got %q", port)
	}
}

func TestTargetAddrForPortUsesRequestedLoopbackPort(t *testing.T) {
	m := &Manager{cfg: &config.Config{RDP: config.RDPConfig{TargetAddr: "127.0.0.1:3389"}}}

	if got := m.targetAddrForPort(22); got != "127.0.0.1:22" {
		t.Fatalf("targetAddrForPort(22) = %q, want 127.0.0.1:22", got)
	}
}

func TestTargetAddrForPortFallsBackToConfig(t *testing.T) {
	m := &Manager{cfg: &config.Config{RDP: config.RDPConfig{TargetAddr: "127.0.0.1:5900"}}}

	if got := m.targetAddrForPort(0); got != "127.0.0.1:5900" {
		t.Fatalf("targetAddrForPort(0) = %q, want config target", got)
	}
}

func TestLoopbackClientAddrForcesWildcardToLoopback(t *testing.T) {
	for _, in := range []string{"0.0.0.0:40000", "[::]:40000", ":40000"} {
		if got := loopbackClientAddr(in); got != "127.0.0.1:40000" {
			t.Fatalf("loopbackClientAddr(%q) = %q, want 127.0.0.1:40000", in, got)
		}
	}
}

func TestLoopbackClientAddrKeepsLoopbackPort(t *testing.T) {
	if got := loopbackClientAddr("127.0.0.1:45000"); got != "127.0.0.1:45000" {
		t.Fatalf("loopbackClientAddr = %q", got)
	}
}

func TestConnectTargetAllowsOnlyLoopbackHosts(t *testing.T) {
	for _, host := range []string{"", "127.0.0.1", "localhost", "::1", "[::1]"} {
		if !isLoopbackHost(host) {
			t.Fatalf("isLoopbackHost(%q) = false, want true", host)
		}
	}
	for _, host := range []string{"192.168.1.10", "10.0.0.5", "example.com"} {
		if isLoopbackHost(host) {
			t.Fatalf("isLoopbackHost(%q) = true, want false", host)
		}
	}
}
