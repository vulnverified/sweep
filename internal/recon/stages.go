package recon

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vulnverified/sweep/internal/engine"
)

// Enumerator implements engine.SubdomainEnumerator using multiple passive sources
// and optional DNS zone transfer testing.
type Enumerator struct {
	UserAgent string
	Progress  engine.ProgressReporter
	AXFR      bool

	mu            sync.Mutex
	zoneTransfers []engine.ZoneTransfer
	warnings      []string
}

// GetZoneTransfers implements engine.ZoneTransferProvider.
func (e *Enumerator) GetZoneTransfers() []engine.ZoneTransfer {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.zoneTransfers
}

// GetWarnings implements engine.WarningProvider.
func (e *Enumerator) GetWarnings() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.warnings
}

// Enumerate discovers subdomains via crt.sh, DNS brute-force, HackerTarget,
// AlienVault OTX, and optionally DNS zone transfers — all in parallel.
func (e *Enumerator) Enumerate(ctx context.Context, domain string, concurrency int) ([]engine.Subdomain, error) {
	// Map of hostname -> list of source names, for deduplication.
	hostSources := make(map[string][]string)

	// Always include the root domain.
	hostSources[strings.ToLower(domain)] = []string{"root"}

	var wg sync.WaitGroup

	// crt.sh enumeration.
	wg.Add(1)
	go func() {
		defer wg.Done()
		hosts, err := CrtshEnumerate(ctx, domain, e.UserAgent)
		if err != nil {
			if e.Progress != nil {
				e.Progress.Warn(fmt.Sprintf("crt.sh: %s", err))
			}
			return
		}
		e.mu.Lock()
		for _, h := range hosts {
			hostSources[h] = append(hostSources[h], "crt.sh")
		}
		e.mu.Unlock()
		if e.Progress != nil {
			e.Progress.Detail(fmt.Sprintf("crt.sh: %d subdomains", len(hosts)))
		}
	}()

	// DNS brute-force.
	bruteConcurrency := concurrency / 2
	if bruteConcurrency < 1 {
		bruteConcurrency = 1
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		hosts, err := BruteEnumerate(ctx, domain, bruteConcurrency)
		if err != nil {
			if e.Progress != nil {
				e.Progress.Warn(fmt.Sprintf("brute-force: %s", err))
			}
			return
		}
		e.mu.Lock()
		for _, h := range hosts {
			hostSources[h] = append(hostSources[h], "brute")
		}
		e.mu.Unlock()
		if e.Progress != nil {
			e.Progress.Detail(fmt.Sprintf("brute-force: %d subdomains", len(hosts)))
		}
	}()

	// HackerTarget enumeration.
	wg.Add(1)
	go func() {
		defer wg.Done()
		hosts, err := HackertargetEnumerate(ctx, domain, e.UserAgent)
		if err != nil {
			if e.Progress != nil {
				e.Progress.Warn(fmt.Sprintf("hackertarget: %s", err))
			}
			e.mu.Lock()
			e.warnings = append(e.warnings, fmt.Sprintf("hackertarget: %s", err))
			e.mu.Unlock()
			return
		}
		e.mu.Lock()
		for _, h := range hosts {
			hostSources[h] = append(hostSources[h], "hackertarget")
		}
		e.mu.Unlock()
		if e.Progress != nil {
			e.Progress.Detail(fmt.Sprintf("hackertarget: %d subdomains", len(hosts)))
		}
	}()

	// AlienVault OTX enumeration.
	wg.Add(1)
	go func() {
		defer wg.Done()
		hosts, err := OTXEnumerate(ctx, domain, e.UserAgent)
		if err != nil {
			if e.Progress != nil {
				e.Progress.Warn(fmt.Sprintf("otx: %s", err))
			}
			e.mu.Lock()
			e.warnings = append(e.warnings, fmt.Sprintf("otx: %s", err))
			e.mu.Unlock()
			return
		}
		e.mu.Lock()
		for _, h := range hosts {
			hostSources[h] = append(hostSources[h], "otx")
		}
		e.mu.Unlock()
		if e.Progress != nil {
			e.Progress.Detail(fmt.Sprintf("otx: %d subdomains", len(hosts)))
		}
	}()

	// DNS zone transfer (opt-in).
	if e.AXFR {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ztResult, err := AttemptZoneTransfers(ctx, domain)
			if err != nil {
				if e.Progress != nil {
					e.Progress.Warn(fmt.Sprintf("zone transfer: %s", err))
				}
				e.mu.Lock()
				e.warnings = append(e.warnings, fmt.Sprintf("zone transfer: %s", err))
				e.mu.Unlock()
				return
			}

			e.mu.Lock()
			e.zoneTransfers = ztResult.Transfers
			for _, h := range ztResult.Hostnames {
				hostSources[h] = append(hostSources[h], "axfr")
			}

			// Add warning for successful zone transfers.
			successCount := 0
			for _, zt := range ztResult.Transfers {
				if zt.Success {
					successCount++
				}
			}
			if successCount > 0 {
				e.warnings = append(e.warnings, fmt.Sprintf(
					"zone transfer enabled on %d of %d nameservers",
					successCount, len(ztResult.Transfers),
				))
			}
			e.mu.Unlock()

			if e.Progress != nil {
				e.Progress.Detail(fmt.Sprintf("zone transfer: %d nameservers tested, %d vulnerable",
					len(ztResult.Transfers), successCount))
			}
		}()
	}

	wg.Wait()

	if len(hostSources) == 0 {
		return nil, fmt.Errorf("all subdomain sources failed for %s", domain)
	}

	// Convert map to sorted slice.
	var subdomains []engine.Subdomain
	for host, sources := range hostSources {
		subdomains = append(subdomains, engine.Subdomain{
			Host:    host,
			Sources: deduplicateSources(sources),
		})
	}
	sort.Slice(subdomains, func(i, j int) bool {
		return subdomains[i].Host < subdomains[j].Host
	})

	return subdomains, nil
}

func deduplicateSources(ss []string) []string {
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

// Resolver implements engine.DNSResolver.
type Resolver struct{}

// Resolve performs DNS resolution and dangling CNAME detection.
func (r *Resolver) Resolve(ctx context.Context, hosts []string, concurrency int) ([]engine.DNSResult, []engine.DanglingCNAME, error) {
	return DNSResolve(ctx, hosts, concurrency)
}

// Scanner implements engine.PortScanner.
type Scanner struct{}

// Scan performs TCP connect scanning using already-resolved DNS records.
func (s *Scanner) Scan(ctx context.Context, dnsRecords []engine.DNSResult, ports []int, concurrency int, timeout time.Duration) ([]engine.PortResult, error) {
	return PortScan(ctx, dnsRecords, ports, concurrency, timeout)
}

// Prober implements engine.HTTPProber.
type Prober struct {
	UserAgent string
	// probeData is stored here for fingerprinting to access.
	mu        sync.Mutex
	ProbeData map[string]*probeData
}

// Probe probes open ports for HTTP services.
func (p *Prober) Probe(ctx context.Context, targets []engine.PortResult, concurrency int, timeout time.Duration) ([]engine.HTTPService, error) {
	result, err := HTTPProbe(ctx, targets, concurrency, timeout, p.UserAgent)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.ProbeData = result.ProbeData
	p.mu.Unlock()

	return result.Services, nil
}

// Fingerprinter implements engine.TechFingerprinter.
type Fingerprinter struct {
	Prober *Prober // reference to access probe data
}

// Fingerprint applies technology fingerprinting to HTTP services.
func (f *Fingerprinter) Fingerprint(services []engine.HTTPService) {
	var pd map[string]*probeData
	if f.Prober != nil {
		f.Prober.mu.Lock()
		pd = f.Prober.ProbeData
		f.Prober.mu.Unlock()
	}
	FingerprintServices(services, pd)
}
