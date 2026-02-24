package engine

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Mock implementations for testing.

type mockEnumerator struct {
	subdomains    []Subdomain
	err           error
	zoneTransfers []ZoneTransfer
	warnings      []string
}

func (m *mockEnumerator) Enumerate(ctx context.Context, domain string, concurrency int) ([]Subdomain, error) {
	return m.subdomains, m.err
}

func (m *mockEnumerator) GetZoneTransfers() []ZoneTransfer {
	return m.zoneTransfers
}

func (m *mockEnumerator) GetWarnings() []string {
	return m.warnings
}

type mockResolver struct {
	records   []DNSResult
	dangling  []DanglingCNAME
	err       error
}

func (m *mockResolver) Resolve(ctx context.Context, hosts []string, concurrency int) ([]DNSResult, []DanglingCNAME, error) {
	return m.records, m.dangling, m.err
}

type mockScanner struct {
	ports []PortResult
	err   error
}

func (m *mockScanner) Scan(ctx context.Context, dnsRecords []DNSResult, ports []int, concurrency int, timeout time.Duration) ([]PortResult, error) {
	return m.ports, m.err
}

type mockProber struct {
	services []HTTPService
	err      error
}

func (m *mockProber) Probe(ctx context.Context, targets []PortResult, concurrency int, timeout time.Duration) ([]HTTPService, error) {
	return m.services, m.err
}

type mockFingerprinter struct {
	techs []Technology
}

func (m *mockFingerprinter) Fingerprint(services []HTTPService) {
	for i := range services {
		services[i].Technologies = m.techs
	}
}

type noopProgress struct{}

func (p *noopProgress) Stage(num, total int, msg string) {}
func (p *noopProgress) Detail(msg string)                {}
func (p *noopProgress) Warn(msg string)                  {}

func TestEngine_FullPipeline(t *testing.T) {
	stages := Stages{
		Enumerator: &mockEnumerator{
			subdomains: []Subdomain{
				{Host: "example.com", Sources: []string{"root"}},
				{Host: "www.example.com", Sources: []string{"crt.sh"}},
			},
		},
		Resolver: &mockResolver{
			records: []DNSResult{
				{Host: "example.com", IPs: []string{"1.2.3.4"}},
				{Host: "www.example.com", IPs: []string{"1.2.3.5"}},
			},
		},
		Scanner: &mockScanner{
			ports: []PortResult{
				{Host: "example.com", IP: "1.2.3.4", Port: 443},
				{Host: "www.example.com", IP: "1.2.3.5", Port: 80},
			},
		},
		Prober: &mockProber{
			services: []HTTPService{
				{URL: "https://example.com:443", Host: "example.com", IP: "1.2.3.4", Port: 443, Scheme: "https", StatusCode: 200, Title: "Example"},
				{URL: "http://www.example.com:80", Host: "www.example.com", IP: "1.2.3.5", Port: 80, Scheme: "http", StatusCode: 200},
			},
		},
		Fingerprinter: &mockFingerprinter{
			techs: []Technology{{Name: "nginx", Category: "web-server"}},
		},
	}

	cfg := Config{
		Target:      "example.com",
		Ports:       []int{80, 443},
		Timeout:     2 * time.Second,
		Concurrency: 10,
	}

	result, err := Run(context.Background(), cfg, stages, &noopProgress{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Target != "example.com" {
		t.Errorf("target = %q, want %q", result.Target, "example.com")
	}
	if len(result.Subdomains) != 2 {
		t.Errorf("subdomains = %d, want 2", len(result.Subdomains))
	}
	if len(result.DNSRecords) != 2 {
		t.Errorf("dns records = %d, want 2", len(result.DNSRecords))
	}
	if len(result.OpenPorts) != 2 {
		t.Errorf("open ports = %d, want 2", len(result.OpenPorts))
	}
	if len(result.HTTPServices) != 2 {
		t.Errorf("http services = %d, want 2", len(result.HTTPServices))
	}
	if result.Summary.SubdomainsFound != 2 {
		t.Errorf("summary subdomains = %d, want 2", result.Summary.SubdomainsFound)
	}
	if result.Summary.LiveHosts != 2 {
		t.Errorf("summary live hosts = %d, want 2", result.Summary.LiveHosts)
	}

	// Verify fingerprinting was applied.
	for _, svc := range result.HTTPServices {
		if len(svc.Technologies) != 1 || svc.Technologies[0].Name != "nginx" {
			t.Errorf("expected nginx tech on %s, got %v", svc.URL, svc.Technologies)
		}
	}

	// Verify timing.
	if result.DurationSecs <= 0 {
		t.Error("duration should be positive")
	}
}

func TestEngine_NoSubdomains_ReturnsError(t *testing.T) {
	stages := Stages{
		Enumerator: &mockEnumerator{
			err: fmt.Errorf("all sources failed"),
		},
	}

	cfg := Config{Target: "example.com", Ports: []int{80}, Timeout: time.Second, Concurrency: 5}
	_, err := Run(context.Background(), cfg, stages, &noopProgress{})
	if err == nil {
		t.Fatal("expected error when no subdomains found")
	}
}

func TestEngine_NoLiveHosts_SkipsLaterStages(t *testing.T) {
	stages := Stages{
		Enumerator: &mockEnumerator{
			subdomains: []Subdomain{{Host: "dead.example.com", Sources: []string{"brute"}}},
		},
		Resolver: &mockResolver{
			records: []DNSResult{}, // No live hosts.
		},
		Scanner: &mockScanner{
			ports: []PortResult{{Host: "should-not-be-called", IP: "0.0.0.0", Port: 80}},
		},
	}

	cfg := Config{Target: "example.com", Ports: []int{80}, Timeout: time.Second, Concurrency: 5}
	result, err := Run(context.Background(), cfg, stages, &noopProgress{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Scanner should not have been called, so open ports should be empty.
	if len(result.OpenPorts) != 0 {
		t.Errorf("expected 0 open ports when no live hosts, got %d", len(result.OpenPorts))
	}
}

func TestEngine_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	stages := Stages{
		Enumerator: &mockEnumerator{
			subdomains: nil,
			err:        context.Canceled,
		},
	}

	cancel()

	cfg := Config{Target: "example.com", Ports: []int{80}, Timeout: time.Second, Concurrency: 5}
	_, err := Run(ctx, cfg, stages, &noopProgress{})
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
}

func TestEngine_ZoneTransfers(t *testing.T) {
	stages := Stages{
		Enumerator: &mockEnumerator{
			subdomains: []Subdomain{
				{Host: "example.com", Sources: []string{"root"}},
				{Host: "www.example.com", Sources: []string{"axfr"}},
			},
			zoneTransfers: []ZoneTransfer{
				{Nameserver: "ns1.example.com", Success: true, Records: 42},
				{Nameserver: "ns2.example.com", Success: false},
			},
			warnings: []string{"zone transfer enabled on 1 of 2 nameservers"},
		},
		Resolver: &mockResolver{
			records: []DNSResult{
				{Host: "example.com", IPs: []string{"1.2.3.4"}},
				{Host: "www.example.com", IPs: []string{"1.2.3.5"}},
			},
		},
		Scanner: &mockScanner{
			ports: []PortResult{{Host: "example.com", IP: "1.2.3.4", Port: 443}},
		},
		Prober: &mockProber{
			services: []HTTPService{{URL: "https://example.com:443", Host: "example.com", StatusCode: 200}},
		},
		Fingerprinter: &mockFingerprinter{},
	}

	cfg := Config{Target: "example.com", Ports: []int{443}, Timeout: time.Second, Concurrency: 5}
	result, err := Run(context.Background(), cfg, stages, &noopProgress{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.ZoneTransfers) != 2 {
		t.Fatalf("expected 2 zone transfers, got %d", len(result.ZoneTransfers))
	}
	if result.Summary.ZoneTransferCount != 1 {
		t.Errorf("summary zone transfers = %d, want 1", result.Summary.ZoneTransferCount)
	}
	if len(result.Warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(result.Warnings))
	}
}

func TestEngine_DanglingCNAMEs(t *testing.T) {
	stages := Stages{
		Enumerator: &mockEnumerator{
			subdomains: []Subdomain{
				{Host: "example.com", Sources: []string{"root"}},
				{Host: "old.example.com", Sources: []string{"crt.sh"}},
			},
		},
		Resolver: &mockResolver{
			records: []DNSResult{
				{Host: "example.com", IPs: []string{"1.2.3.4"}},
			},
			dangling: []DanglingCNAME{
				{Host: "old.example.com", CNAME: "old.herokuapp.com", Status: "NXDOMAIN"},
			},
		},
		Scanner: &mockScanner{
			ports: []PortResult{{Host: "example.com", IP: "1.2.3.4", Port: 443}},
		},
		Prober: &mockProber{
			services: []HTTPService{{URL: "https://example.com:443", Host: "example.com", StatusCode: 200}},
		},
		Fingerprinter: &mockFingerprinter{},
	}

	cfg := Config{Target: "example.com", Ports: []int{443}, Timeout: time.Second, Concurrency: 5}
	result, err := Run(context.Background(), cfg, stages, &noopProgress{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.DanglingCNAMEs) != 1 {
		t.Fatalf("expected 1 dangling CNAME, got %d", len(result.DanglingCNAMEs))
	}
	if result.DanglingCNAMEs[0].Host != "old.example.com" {
		t.Errorf("dangling host = %q, want %q", result.DanglingCNAMEs[0].Host, "old.example.com")
	}
	if result.Summary.DanglingCNAMEs != 1 {
		t.Errorf("summary dangling = %d, want 1", result.Summary.DanglingCNAMEs)
	}
}
