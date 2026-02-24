package recon

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/vulnverified/sweep/internal/engine"
)

var titleRegex = regexp.MustCompile(`(?i)<title[^>]*>\s*([^<]+)\s*</title>`)

const httpProbeMaxBody = 1024 * 1024 // 1MB for title + fingerprinting

// HTTPProbeResult contains both the HTTP services and raw data for fingerprinting.
type HTTPProbeResult struct {
	Services  []engine.HTTPService
	ProbeData map[string]*probeData // keyed by URL
}

// HTTPProbe probes open ports for HTTP/HTTPS services.
// For ports 443, 8443, 9443: tries HTTPS first.
// For all others: tries HTTP first, falls back to HTTPS.
func HTTPProbe(ctx context.Context, openPorts []engine.PortResult, concurrency int, timeout time.Duration, userAgent string) (*HTTPProbeResult, error) {
	work := make(chan engine.PortResult, len(openPorts))
	for _, p := range openPorts {
		work <- p
	}
	close(work)

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	var (
		mu     sync.Mutex
		result = &HTTPProbeResult{
			ProbeData: make(map[string]*probeData),
		}
	)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pr := range work {
				select {
				case <-ctx.Done():
					return
				default:
				}

				svc, pd := probePort(ctx, client, pr, userAgent)
				if svc == nil {
					continue
				}

				mu.Lock()
				result.Services = append(result.Services, *svc)
				if pd != nil {
					result.ProbeData[svc.URL] = pd
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return result, nil
}

// tlsFirstPorts are ports where HTTPS should be tried before HTTP.
var tlsFirstPorts = map[int]bool{
	443: true, 8443: true, 9443: true, 6443: true, 1443: true, 4443: true,
}

func probePort(ctx context.Context, client *http.Client, pr engine.PortResult, userAgent string) (*engine.HTTPService, *probeData) {
	schemes := []string{"http", "https"}
	if tlsFirstPorts[pr.Port] {
		schemes = []string{"https", "http"}
	}

	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s:%d", scheme, pr.Host, pr.Port)
		svc, pd := probeURL(ctx, client, url, pr, scheme, userAgent)
		if svc != nil {
			return svc, pd
		}
	}
	return nil, nil
}

func probeURL(ctx context.Context, client *http.Client, url string, pr engine.PortResult, scheme, userAgent string) (*engine.HTTPService, *probeData) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, httpProbeMaxBody))
	bodyStr := string(body)

	svc := &engine.HTTPService{
		URL:           url,
		Host:          pr.Host,
		IP:            pr.IP,
		Port:          pr.Port,
		Scheme:        scheme,
		StatusCode:    resp.StatusCode,
		Server:        resp.Header.Get("Server"),
		ContentLength: resp.ContentLength,
	}

	// Extract page title.
	if matches := titleRegex.FindSubmatch(body); len(matches) > 1 {
		svc.Title = strings.TrimSpace(string(matches[1]))
	}

	// Build probe data for fingerprinting.
	headers := make(map[string]string)
	for name, vals := range resp.Header {
		if len(vals) > 0 {
			headers[strings.ToLower(name)] = vals[0]
		}
	}

	var cookieNames []string
	for _, c := range resp.Cookies() {
		cookieNames = append(cookieNames, c.Name)
	}

	pd := &probeData{
		headers: headers,
		body:    bodyStr,
		cookies: cookieNames,
	}

	return svc, pd
}
