package recon

import (
	"errors"
	"net"
	"strings"

	"github.com/vulnverified/sweep/internal/engine"
)

// danglingPatterns are CNAME targets known to be vulnerable to subdomain takeover
// when the CNAME points to a service that no longer exists.
var danglingPatterns = []string{
	".s3.amazonaws.com",
	".azurewebsites.net",
	".github.io",
	".herokuapp.com",
	".cloudfront.net",
	".elasticbeanstalk.com",
	".trafficmanager.net",
	".blob.core.windows.net",
	".azureedge.net",
	".pantheonsite.io",
	".netlify.app",
	".ghost.io",
	".myshopify.com",
	".surge.sh",
}

// checkDangling checks if a failed DNS resolution represents a potential dangling CNAME.
// Returns nil if the CNAME target doesn't match any known takeover-susceptible patterns.
func checkDangling(host, cname string, lookupErr error) *engine.DanglingCNAME {
	cnameLower := strings.ToLower(cname)

	matchesPattern := false
	for _, pattern := range danglingPatterns {
		if strings.HasSuffix(cnameLower, pattern) {
			matchesPattern = true
			break
		}
	}
	if !matchesPattern {
		return nil
	}

	status := classifyDNSError(lookupErr)
	if status == "" {
		return nil
	}

	return &engine.DanglingCNAME{
		Host:   host,
		CNAME:  cname,
		Status: status,
	}
}

// classifyDNSError returns "NXDOMAIN" or "SERVFAIL" based on the DNS error type.
func classifyDNSError(err error) string {
	if err == nil {
		return ""
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return "NXDOMAIN"
		}
		return "SERVFAIL"
	}

	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "no such host") {
		return "NXDOMAIN"
	}
	if strings.Contains(errStr, "server misbehaving") {
		return "SERVFAIL"
	}

	return ""
}
