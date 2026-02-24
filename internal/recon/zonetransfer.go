package recon

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/vulnverified/sweep/internal/engine"
)

const (
	axfrDialTimeout = 10 * time.Second
	axfrReadTimeout = 30 * time.Second
)

// ZoneTransferResult holds the output of AXFR testing for a domain.
type ZoneTransferResult struct {
	Transfers []engine.ZoneTransfer
	Hostnames []string
}

// AttemptZoneTransfers looks up NS records for the domain and attempts
// AXFR against each nameserver. Returns discovered hostnames and transfer results.
func AttemptZoneTransfers(ctx context.Context, domain string) (*ZoneTransferResult, error) {
	nameservers, err := net.DefaultResolver.LookupNS(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("NS lookup for %s: %w", domain, err)
	}
	if len(nameservers) == 0 {
		return nil, fmt.Errorf("no NS records for %s", domain)
	}

	result := &ZoneTransferResult{}
	seen := make(map[string]bool)

	for _, ns := range nameservers {
		// Respect context cancellation between nameserver attempts.
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		nsHost := strings.TrimSuffix(ns.Host, ".")

		transfer := engine.ZoneTransfer{
			Nameserver: nsHost,
		}

		hostnames, err := attemptAXFR(ctx, domain, nsHost)
		if err != nil {
			// AXFR failure is expected for most domains — not an error.
			result.Transfers = append(result.Transfers, transfer)
			continue
		}

		transfer.Success = true
		transfer.Records = len(hostnames)
		result.Transfers = append(result.Transfers, transfer)

		for _, h := range hostnames {
			if !seen[h] {
				seen[h] = true
				result.Hostnames = append(result.Hostnames, h)
			}
		}
	}

	return result, nil
}

// attemptAXFR performs a DNS zone transfer against a single nameserver.
func attemptAXFR(_ context.Context, domain, nameserver string) ([]string, error) {
	transfer := &dns.Transfer{
		DialTimeout: axfrDialTimeout,
		ReadTimeout: axfrReadTimeout,
	}

	msg := new(dns.Msg)
	msg.SetAxfr(dns.Fqdn(domain))

	nsAddr := net.JoinHostPort(nameserver, "53")

	channel, err := transfer.In(msg, nsAddr)
	if err != nil {
		return nil, fmt.Errorf("AXFR to %s: %w", nameserver, err)
	}

	seen := make(map[string]bool)
	var hostnames []string
	domainSuffix := "." + strings.ToLower(domain)

	for envelope := range channel {
		if envelope.Error != nil {
			return nil, fmt.Errorf("AXFR envelope from %s: %w", nameserver, envelope.Error)
		}
		for _, rr := range envelope.RR {
			name := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
			if name == "" {
				continue
			}
			if !strings.HasSuffix(name, domainSuffix) && name != strings.ToLower(domain) {
				continue
			}
			if !seen[name] {
				seen[name] = true
				hostnames = append(hostnames, name)
			}
		}
	}

	return hostnames, nil
}
