package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	otxBaseURL    = "https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns"
	otxTimeout    = 15 * time.Second
	otxMaxBody    = 10 * 1024 * 1024 // 10MB
	otxRetryDelay = 3 * time.Second
)

type otxResponse struct {
	PassiveDNS []otxEntry `json:"passive_dns"`
}

type otxEntry struct {
	Hostname string `json:"hostname"`
}

// OTXEnumerate queries AlienVault OTX passive DNS for subdomains.
// Returns discovered hostnames (lowercase, deduplicated).
// Non-fatal: returns nil on failure so the pipeline can continue with other sources.
func OTXEnumerate(ctx context.Context, domain, userAgent string) ([]string, error) {
	url := fmt.Sprintf(otxBaseURL, domain)

	body, err := otxFetch(ctx, url, userAgent)
	if err != nil {
		return nil, fmt.Errorf("otx fetch for %s: %w", domain, err)
	}

	return parseOTXResponse(body, domain)
}

func otxFetch(ctx context.Context, url, userAgent string) ([]byte, error) {
	body, err := otxDoRequest(ctx, url, userAgent)
	if err == nil {
		return body, nil
	}

	// Don't retry on rate limit.
	if strings.Contains(err.Error(), "429") {
		return nil, err
	}

	// Retry once after delay for server errors.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(otxRetryDelay):
	}

	return otxDoRequest(ctx, url, userAgent)
}

func otxDoRequest(ctx context.Context, url, userAgent string) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, otxTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("otx rate limited (429)")
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("otx returned status %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("otx returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, otxMaxBody))
	if err != nil {
		return nil, fmt.Errorf("otx read body: %w", err)
	}

	return body, nil
}

// parseOTXResponse extracts hostnames from the OTX passive DNS JSON response.
func parseOTXResponse(body []byte, domain string) ([]string, error) {
	var resp otxResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("otx JSON parse: %w", err)
	}

	seen := make(map[string]bool)
	var hosts []string

	for _, entry := range resp.PassiveDNS {
		host := strings.ToLower(strings.TrimSpace(entry.Hostname))
		if host == "" {
			continue
		}

		// Must be a subdomain of the target.
		if !strings.HasSuffix(host, "."+domain) && host != domain {
			continue
		}

		if !seen[host] {
			seen[host] = true
			hosts = append(hosts, host)
		}
	}

	return hosts, nil
}
