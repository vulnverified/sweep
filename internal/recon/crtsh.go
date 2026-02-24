// Package recon implements the individual sweep reconnaissance stages.
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
	crtshBaseURL    = "https://crt.sh/?q=%%25.%s&output=json"
	crtshTimeout    = 30 * time.Second
	crtshMaxBody    = 50 * 1024 * 1024 // 50MB
	crtshRetryDelay = 3 * time.Second
)

type crtshEntry struct {
	NameValue string `json:"name_value"`
}

// CrtshEnumerate queries crt.sh Certificate Transparency logs for subdomains.
// Returns discovered hostnames (lowercase, deduplicated, no wildcards).
// Non-fatal: returns nil on failure so the pipeline can continue with other sources.
func CrtshEnumerate(ctx context.Context, domain string, userAgent string) ([]string, error) {
	url := fmt.Sprintf(crtshBaseURL, domain)

	body, err := crtshFetch(ctx, url, userAgent)
	if err != nil {
		return nil, fmt.Errorf("crt.sh fetch for %s: %w", domain, err)
	}

	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.sh JSON parse for %s: %w", domain, err)
	}

	seen := make(map[string]bool)
	var hosts []string

	for _, entry := range entries {
		// name_value can contain multiple names separated by newlines.
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			if name == "" {
				continue
			}
			// Skip wildcards.
			if strings.HasPrefix(name, "*.") {
				name = strings.TrimPrefix(name, "*.")
			}
			// Must be a subdomain of the target.
			if !strings.HasSuffix(name, "."+domain) && name != domain {
				continue
			}
			if !seen[name] {
				seen[name] = true
				hosts = append(hosts, name)
			}
		}
	}

	return hosts, nil
}

func crtshFetch(ctx context.Context, url, userAgent string) ([]byte, error) {
	body, err := crtshDoRequest(ctx, url, userAgent)
	if err == nil {
		return body, nil
	}

	// If it's a rate limit error, don't retry.
	if strings.Contains(err.Error(), "429") {
		return nil, err
	}

	// Retry once after delay for server errors.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(crtshRetryDelay):
	}

	return crtshDoRequest(ctx, url, userAgent)
}

func crtshDoRequest(ctx context.Context, url, userAgent string) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, crtshTimeout)
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
		return nil, fmt.Errorf("crt.sh rate limited (429)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, crtshMaxBody))
	if err != nil {
		return nil, fmt.Errorf("crt.sh read body: %w", err)
	}

	return body, nil
}
