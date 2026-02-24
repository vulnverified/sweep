package output

import (
	"fmt"
	"io"

	"github.com/vulnverified/sweep/internal/engine"
)

// Version is set via ldflags at build time.
var Version = "dev"

// WriteHeader prints the sweep banner.
func WriteHeader(w io.Writer, noColor bool) {
	if noColor {
		fmt.Fprintf(w, "sweep %s — https://vulnverified.com\n\n", Version)
	} else {
		fmt.Fprintf(w, "\033[1msweep %s\033[0m — https://vulnverified.com\n\n", Version)
	}
}

// WriteSummary prints the post-scan summary with optional CTA.
func WriteSummary(w io.Writer, result *engine.ScanResult, showCTA, noColor bool) {
	s := result.Summary

	fmt.Fprintln(w)
	if noColor {
		fmt.Fprintf(w, "Target: %s\n", result.Target)
		fmt.Fprintf(w, "Subdomains: %d discovered, %d live\n", s.SubdomainsFound, s.LiveHosts)
		fmt.Fprintf(w, "Open ports: %d across %d hosts\n", s.OpenPortCount, s.LiveHosts)
	} else {
		fmt.Fprintf(w, "\033[1mTarget:\033[0m %s\n", result.Target)
		fmt.Fprintf(w, "\033[1mSubdomains:\033[0m %d discovered, %d live\n", s.SubdomainsFound, s.LiveHosts)
		fmt.Fprintf(w, "\033[1mOpen ports:\033[0m %d across %d hosts\n", s.OpenPortCount, s.LiveHosts)
	}

	if s.ZoneTransferCount > 0 {
		fmt.Fprintln(w)
		vulnerableNS := 0
		totalNS := len(result.ZoneTransfers)
		for _, zt := range result.ZoneTransfers {
			if zt.Success {
				vulnerableNS++
			}
		}
		if noColor {
			fmt.Fprintf(w, "! Zone transfer enabled (%d of %d nameservers vulnerable)\n", vulnerableNS, totalNS)
		} else {
			fmt.Fprintf(w, "\033[33m!\033[0m Zone transfer enabled (%d of %d nameservers vulnerable)\n", vulnerableNS, totalNS)
		}
		for _, zt := range result.ZoneTransfers {
			if zt.Success {
				fmt.Fprintf(w, "  %s (%d records)\n", zt.Nameserver, zt.Records)
			}
		}
	}

	if s.DanglingCNAMEs > 0 {
		fmt.Fprintln(w)
		if noColor {
			fmt.Fprintf(w, "! %d potential dangling CNAMEs (possible subdomain takeover)\n", s.DanglingCNAMEs)
		} else {
			fmt.Fprintf(w, "\033[33m!\033[0m %d potential dangling CNAMEs (possible subdomain takeover)\n", s.DanglingCNAMEs)
		}
		for _, dc := range result.DanglingCNAMEs {
			fmt.Fprintf(w, "  %s -> %s (%s)\n", dc.Host, dc.CNAME, dc.Status)
		}
	}

	if showCTA {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Found %d exposed services across %d hosts.\n", s.HTTPServiceCount, s.LiveHosts)
		if noColor {
			fmt.Fprintln(w, "What's actually exploitable? -> https://vulnverified.com")
		} else {
			fmt.Fprintln(w, "What's actually exploitable? \033[1m->\033[0m \033[4mhttps://vulnverified.com\033[0m")
		}
	}
}
