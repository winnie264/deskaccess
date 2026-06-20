package rdpcheck

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// ScanResult is a port that responded during scanning.
type ScanResult struct {
	Port    int
	Latency time.Duration
}

// ScanPorts probes a list of TCP ports on localhost in parallel.
// Returns only the ports that are open, sorted by port number.
func ScanPorts(ports []int) []ScanResult {
	type result struct {
		port    int
		latency time.Duration
		open    bool
	}

	ch := make(chan result, len(ports))
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			start := time.Now()
			conn, err := net.DialTimeout("tcp",
				fmt.Sprintf("127.0.0.1:%d", p), 400*time.Millisecond)
			latency := time.Since(start)
			if err != nil {
				ch <- result{port: p, open: false}
				return
			}
			conn.Close()
			ch <- result{port: p, latency: latency, open: true}
		}(port)
	}

	wg.Wait()
	close(ch)

	var open []ScanResult
	for r := range ch {
		if r.open {
			open = append(open, ScanResult{Port: r.port, Latency: r.latency})
		}
	}
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open
}

// PortsForProtocol returns the candidate ports to scan for a protocol.
func PortsForProtocol(p Protocol) []int {
	switch p {
	case ProtoRDP:
		return []int{3389}
	case ProtoSSH:
		return []int{22, 2222}
	case ProtoVNC:
		// VNC displays :0 through :5 → ports 5900–5905
		return []int{5900, 5901, 5902, 5903, 5904, 5905}
	case ProtoCustom:
		// No candidates — user must enter manually
		return nil
	default:
		return []int{3389}
	}
}
