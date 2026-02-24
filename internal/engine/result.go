// Package engine orchestrates the sweep recon pipeline.
package engine

import (
	"context"
	"time"
)

// ScanResult is the top-level output of a sweep run.
type ScanResult struct {
	Target         string          `json:"target"`
	StartedAt      time.Time       `json:"started_at"`
	CompletedAt    time.Time       `json:"completed_at"`
	DurationSecs   float64         `json:"duration_secs"`
	Subdomains     []Subdomain     `json:"subdomains"`
	DNSRecords     []DNSResult     `json:"dns_records"`
	OpenPorts      []PortResult    `json:"open_ports"`
	HTTPServices   []HTTPService   `json:"http_services"`
	DanglingCNAMEs []DanglingCNAME `json:"dangling_cnames,omitempty"`
	ZoneTransfers  []ZoneTransfer  `json:"zone_transfers,omitempty"`
	Warnings       []string        `json:"warnings,omitempty"`
	Summary        Summary         `json:"summary"`
}

// Subdomain represents a discovered subdomain and its discovery sources.
type Subdomain struct {
	Host    string   `json:"host"`
	Sources []string `json:"sources"`
}

// DNSResult holds resolved DNS records for a host.
type DNSResult struct {
	Host  string   `json:"host"`
	IPs   []string `json:"ips"`
	CNAME string   `json:"cname,omitempty"`
}

// PortResult represents an open port on a host.
type PortResult struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// HTTPService represents a probed HTTP service.
type HTTPService struct {
	URL           string       `json:"url"`
	Host          string       `json:"host"`
	IP            string       `json:"ip"`
	Port          int          `json:"port"`
	Scheme        string       `json:"scheme"`
	StatusCode    int          `json:"status_code"`
	Title         string       `json:"title,omitempty"`
	Server        string       `json:"server,omitempty"`
	ContentLength int64        `json:"content_length"`
	Technologies  []Technology `json:"technologies,omitempty"`
}

// Technology represents a detected technology.
type Technology struct {
	Name     string `json:"name"`
	Category string `json:"category"`
}

// DanglingCNAME represents a potential subdomain takeover candidate.
type DanglingCNAME struct {
	Host   string `json:"host"`
	CNAME  string `json:"cname"`
	Status string `json:"status"`
}

// ZoneTransfer represents the result of an AXFR attempt against a nameserver.
type ZoneTransfer struct {
	Nameserver string `json:"nameserver"`
	Success    bool   `json:"success"`
	Records    int    `json:"records,omitempty"`
}

// Summary provides aggregate counts for the scan.
type Summary struct {
	SubdomainsFound   int `json:"subdomains_found"`
	LiveHosts         int `json:"live_hosts"`
	OpenPortCount     int `json:"open_port_count"`
	HTTPServiceCount  int `json:"http_service_count"`
	TechCount         int `json:"tech_count"`
	DanglingCNAMEs    int `json:"dangling_cnames"`
	ZoneTransferCount int `json:"zone_transfers"`
}

// SubdomainEnumerator discovers subdomains for a domain.
type SubdomainEnumerator interface {
	Enumerate(ctx context.Context, domain string, concurrency int) ([]Subdomain, error)
}

// DNSResolver resolves hostnames to IPs and detects dangling CNAMEs.
type DNSResolver interface {
	Resolve(ctx context.Context, hosts []string, concurrency int) ([]DNSResult, []DanglingCNAME, error)
}

// PortScanner scans for open TCP ports.
type PortScanner interface {
	Scan(ctx context.Context, dnsRecords []DNSResult, ports []int, concurrency int, timeout time.Duration) ([]PortResult, error)
}

// HTTPProber probes open ports for HTTP services.
type HTTPProber interface {
	Probe(ctx context.Context, targets []PortResult, concurrency int, timeout time.Duration) ([]HTTPService, error)
}

// TechFingerprinter identifies technologies from HTTP responses.
type TechFingerprinter interface {
	Fingerprint(services []HTTPService) // mutates in place
}

// ZoneTransferProvider is an optional interface that SubdomainEnumerator
// implementations can satisfy to report zone transfer results.
type ZoneTransferProvider interface {
	GetZoneTransfers() []ZoneTransfer
}

// WarningProvider is an optional interface that SubdomainEnumerator
// implementations can satisfy to report non-fatal warnings.
type WarningProvider interface {
	GetWarnings() []string
}
