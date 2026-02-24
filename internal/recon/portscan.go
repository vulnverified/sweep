package recon

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/vulnverified/sweep/internal/engine"
)

// PortScan performs TCP connect scanning on the given hosts and ports.
// Returns only open ports. Closed/filtered ports are silently skipped.
func PortScan(ctx context.Context, dnsRecords []engine.DNSResult, ports []int, concurrency int, timeout time.Duration) ([]engine.PortResult, error) {
	type target struct {
		host string
		ip   string
		port int
	}

	// Build work items: host x port combinations.
	var targets []target
	for _, r := range dnsRecords {
		if len(r.IPs) == 0 {
			continue
		}
		ip := r.IPs[0]
		for _, port := range ports {
			targets = append(targets, target{host: r.Host, ip: ip, port: port})
		}
	}

	work := make(chan target, len(targets))
	for _, t := range targets {
		work <- t
	}
	close(work)

	var (
		mu      sync.Mutex
		results []engine.PortResult
	)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := net.Dialer{Timeout: timeout}

			for t := range work {
				select {
				case <-ctx.Done():
					return
				default:
				}

				addr := fmt.Sprintf("%s:%d", t.ip, t.port)
				conn, err := dialer.DialContext(ctx, "tcp", addr)
				if err != nil {
					continue
				}
				conn.Close()

				mu.Lock()
				results = append(results, engine.PortResult{
					Host: t.host,
					IP:   t.ip,
					Port: t.port,
				})
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return results, nil
}
