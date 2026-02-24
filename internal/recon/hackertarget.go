package recon

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	hackertargetBaseURL    = "https://api.hackertarget.com/hostsearch/?q=%s"
	hackertargetTimeout    = 10 * time.Second
	hackertargetMaxBody    = 5 * 1024 * 1024 // 5MB
	hackertargetRetryDelay = 2 * time.Second
	hackertargetRateMsg    = "API count exceeded"
)

// HackertargetEnumerate queries the HackerTarget API for subdomains.
// Returns discovered hostnames (lowercase, deduplicated).
// Non-fatal: returns nil on failure so the pipeline can continue with other sources.
func HackertargetEnumerate(ctx context.Context, domain, userAgent string) ([]string, error) {
	url := fmt.Sprintf(hackertargetBaseURL, domain)

	body, err := hackertargetFetch(ctx, url, userAgent)
	if err != nil {
		return nil, fmt.Errorf("hackertarget fetch for %s: %w", domain, err)
	}

	return parseHackertargetResponse(body, domain), nil
}

func hackertargetFetch(ctx context.Context, url, userAgent string) (string, error) {
	body, err := hackertargetDoRequest(ctx, url, userAgent)
	if err == nil {
		return body, nil
	}

	// Don't retry on rate limit.
	if strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), hackertargetRateMsg) {
		return "", err
	}

	// Retry once after delay for server errors.
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(hackertargetRetryDelay):
	}

	return hackertargetDoRequest(ctx, url, userAgent)
}

func hackertargetDoRequest(ctx context.Context, url, userAgent string) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, hackertargetTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return "", fmt.Errorf("hackertarget rate limited (429)")
	}
	if resp.StatusCode >= 500 {
		return "", fmt.Errorf("hackertarget returned status %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hackertarget returned status %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, hackertargetMaxBody))
	if err != nil {
		return "", fmt.Errorf("hackertarget read body: %w", err)
	}

	body := string(raw)

	// HackerTarget returns a plain text error message when rate limited.
	if strings.Contains(body, hackertargetRateMsg) {
		return "", fmt.Errorf("hackertarget: %s", hackertargetRateMsg)
	}

	return body, nil
}

// parseHackertargetResponse parses the plain-text "host,ip" response format.
func parseHackertargetResponse(body, domain string) []string {
	seen := make(map[string]bool)
	var hosts []string

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Format: host,ip
		parts := strings.SplitN(line, ",", 2)
		host := strings.ToLower(strings.TrimSpace(parts[0]))
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

	return hosts
}
