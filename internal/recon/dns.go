package recon

import (
	"context"
	"net"
	"strings"
	"sync"

	"github.com/vulnverified/sweep/internal/engine"
)

// DNSResolve performs A/AAAA and CNAME resolution for the given hosts.
// Returns resolved records and detected dangling CNAMEs.
func DNSResolve(ctx context.Context, hosts []string, concurrency int) ([]engine.DNSResult, []engine.DanglingCNAME, error) {
	work := make(chan string, len(hosts))
	for _, h := range hosts {
		work <- h
	}
	close(work)

	var (
		mu        sync.Mutex
		results   []engine.DNSResult
		danglings []engine.DanglingCNAME
	)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range work {
				select {
				case <-ctx.Done():
					return
				default:
				}

				record := engine.DNSResult{Host: host}

				// Check CNAME first.
				cname, err := net.DefaultResolver.LookupCNAME(ctx, host)
				if err == nil {
					cname = strings.TrimSuffix(strings.ToLower(cname), ".")
					if cname != host && cname != "" {
						record.CNAME = cname
					}
				}

				// Resolve A/AAAA records.
				ips, err := net.DefaultResolver.LookupHost(ctx, host)
				if err != nil {
					// Host didn't resolve — check if it's a dangling CNAME.
					if record.CNAME != "" {
						dangling := checkDangling(host, record.CNAME, err)
						if dangling != nil {
							mu.Lock()
							danglings = append(danglings, *dangling)
							mu.Unlock()
						}
					}
					continue
				}

				record.IPs = deduplicateStrings(ips)

				mu.Lock()
				results = append(results, record)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return results, danglings, nil
}

// LiveHostsFromDNS extracts unique hostnames that resolved successfully.
func LiveHostsFromDNS(records []engine.DNSResult) []string {
	var hosts []string
	for _, r := range records {
		if len(r.IPs) > 0 {
			hosts = append(hosts, r.Host)
		}
	}
	return hosts
}

// IPForHost returns the first resolved IP for a host, or empty string.
func IPForHost(records []engine.DNSResult, host string) string {
	for _, r := range records {
		if r.Host == host && len(r.IPs) > 0 {
			return r.IPs[0]
		}
	}
	return ""
}

func deduplicateStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
