package recon

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/vulnverified/sweep/internal/engine"
)

func TestPortScan_DetectsOpenPort(t *testing.T) {
	// Start a TCP listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	// Accept connections in background.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	port := addr.Port

	dnsRecords := []engine.DNSResult{
		{Host: "localhost", IPs: []string{"127.0.0.1"}},
	}

	results, err := PortScan(context.Background(), dnsRecords, []int{port}, 5, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}

	if results[0].Port != port {
		t.Errorf("port = %d, want %d", results[0].Port, port)
	}
	if results[0].IP != "127.0.0.1" {
		t.Errorf("ip = %q, want 127.0.0.1", results[0].IP)
	}
}

func TestPortScan_ClosedPort(t *testing.T) {
	// Find a port that's definitely closed.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	closedPort := addr.Port
	ln.Close() // Close it immediately.

	dnsRecords := []engine.DNSResult{
		{Host: "localhost", IPs: []string{"127.0.0.1"}},
	}

	results, err := PortScan(context.Background(), dnsRecords, []int{closedPort}, 5, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("got %d results for closed port, want 0", len(results))
	}
}

func TestPortScan_RespectsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	dnsRecords := []engine.DNSResult{
		{Host: "localhost", IPs: []string{"127.0.0.1"}},
	}

	results, err := PortScan(ctx, dnsRecords, []int{80, 443}, 5, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// With cancelled context, should get no results.
	if len(results) != 0 {
		t.Errorf("got %d results with cancelled context, want 0", len(results))
	}
}

// Silence unused import.
var _ = strconv.Itoa
