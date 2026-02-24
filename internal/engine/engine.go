package engine

import (
	"context"
	"fmt"
	"time"
)

// Config holds the runtime configuration for a sweep run.
type Config struct {
	Target      string
	Ports       []int
	Timeout     time.Duration
	Concurrency int
	UserAgent   string
}

// Stages holds the injectable stage implementations.
type Stages struct {
	Enumerator    SubdomainEnumerator
	Resolver      DNSResolver
	Scanner       PortScanner
	Prober        HTTPProber
	Fingerprinter TechFingerprinter
}

// ProgressReporter is called by the engine to report stage progress.
type ProgressReporter interface {
	Stage(num, total int, msg string)
	Detail(msg string)
	Warn(msg string)
}

const totalStages = 5

// Run executes the full sweep pipeline.
func Run(ctx context.Context, cfg Config, stages Stages, progress ProgressReporter) (*ScanResult, error) {
	result := &ScanResult{
		Target:    cfg.Target,
		StartedAt: time.Now(),
	}

	// Stage 1: Subdomain enumeration.
	progress.Stage(1, totalStages, "Enumerating subdomains...")
	subdomains, err := stages.Enumerator.Enumerate(ctx, cfg.Target, cfg.Concurrency)
	if err != nil {
		return nil, fmt.Errorf("subdomain enumeration failed: %w", err)
	}
	if len(subdomains) == 0 {
		return nil, fmt.Errorf("no subdomains discovered for %s", cfg.Target)
	}
	result.Subdomains = subdomains
	progress.Detail(fmt.Sprintf("Found %d unique subdomains", len(subdomains)))

	// Check optional interfaces for zone transfers and warnings.
	if ztp, ok := stages.Enumerator.(ZoneTransferProvider); ok {
		result.ZoneTransfers = ztp.GetZoneTransfers()
	}
	if wp, ok := stages.Enumerator.(WarningProvider); ok {
		result.Warnings = wp.GetWarnings()
	}

	// Collect all hostnames for DNS resolution.
	var hosts []string
	for _, s := range subdomains {
		hosts = append(hosts, s.Host)
	}

	// Stage 2: DNS resolution.
	progress.Stage(2, totalStages, "Resolving DNS records...")
	dnsRecords, danglingCNAMEs, err := stages.Resolver.Resolve(ctx, hosts, cfg.Concurrency)
	if err != nil {
		progress.Warn(fmt.Sprintf("DNS resolution error: %s", err))
	}
	result.DNSRecords = dnsRecords
	result.DanglingCNAMEs = danglingCNAMEs

	liveHostCount := 0
	for _, r := range dnsRecords {
		if len(r.IPs) > 0 {
			liveHostCount++
		}
	}
	progress.Detail(fmt.Sprintf("%d hosts resolved, %d dangling CNAMEs detected", liveHostCount, len(danglingCNAMEs)))

	if liveHostCount == 0 {
		progress.Warn("No live hosts found, skipping port scan and HTTP probe")
		result.CompletedAt = time.Now()
		result.DurationSecs = result.CompletedAt.Sub(result.StartedAt).Seconds()
		result.Summary = buildSummary(result)
		return result, nil
	}

	// Stage 3: Port scanning.
	progress.Stage(3, totalStages, fmt.Sprintf("Scanning %d ports across %d hosts...", len(cfg.Ports), liveHostCount))
	openPorts, err := stages.Scanner.Scan(ctx, dnsRecords, cfg.Ports, cfg.Concurrency, cfg.Timeout)
	if err != nil {
		progress.Warn(fmt.Sprintf("Port scan error: %s", err))
	}
	result.OpenPorts = openPorts
	progress.Detail(fmt.Sprintf("Found %d open ports", len(openPorts)))

	if len(openPorts) == 0 {
		progress.Warn("No open ports found, skipping HTTP probe")
		result.CompletedAt = time.Now()
		result.DurationSecs = result.CompletedAt.Sub(result.StartedAt).Seconds()
		result.Summary = buildSummary(result)
		return result, nil
	}

	// Stage 4: HTTP probing.
	httpConcurrency := cfg.Concurrency / 2
	if httpConcurrency < 1 {
		httpConcurrency = 1
	}
	progress.Stage(4, totalStages, fmt.Sprintf("Probing %d open ports for HTTP services...", len(openPorts)))
	services, err := stages.Prober.Probe(ctx, openPorts, httpConcurrency, cfg.Timeout)
	if err != nil {
		progress.Warn(fmt.Sprintf("HTTP probe error: %s", err))
	}
	result.HTTPServices = services
	progress.Detail(fmt.Sprintf("Found %d HTTP services", len(services)))

	// Stage 5: Tech fingerprinting.
	if len(services) > 0 {
		progress.Stage(5, totalStages, "Fingerprinting technologies...")
		stages.Fingerprinter.Fingerprint(services)

		techCount := 0
		for _, svc := range services {
			techCount += len(svc.Technologies)
		}
		result.HTTPServices = services
		progress.Detail(fmt.Sprintf("Identified %d technology instances", techCount))
	}

	result.CompletedAt = time.Now()
	result.DurationSecs = result.CompletedAt.Sub(result.StartedAt).Seconds()
	result.Summary = buildSummary(result)

	return result, nil
}

func buildSummary(result *ScanResult) Summary {
	liveHosts := make(map[string]bool)
	for _, r := range result.DNSRecords {
		if len(r.IPs) > 0 {
			liveHosts[r.Host] = true
		}
	}

	techSet := make(map[string]bool)
	for _, svc := range result.HTTPServices {
		for _, t := range svc.Technologies {
			techSet[t.Name] = true
		}
	}

	zoneTransferCount := 0
	for _, zt := range result.ZoneTransfers {
		if zt.Success {
			zoneTransferCount++
		}
	}

	return Summary{
		SubdomainsFound:   len(result.Subdomains),
		LiveHosts:         len(liveHosts),
		OpenPortCount:     len(result.OpenPorts),
		HTTPServiceCount:  len(result.HTTPServices),
		TechCount:         len(techSet),
		DanglingCNAMEs:    len(result.DanglingCNAMEs),
		ZoneTransferCount: zoneTransferCount,
	}
}
