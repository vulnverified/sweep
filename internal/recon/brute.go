package recon

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/vulnverified/sweep/internal/wordlist"
)

// BruteEnumerate performs DNS brute-force subdomain enumeration using the embedded wordlist.
// Returns hostnames that resolved successfully.
func BruteEnumerate(ctx context.Context, domain string, concurrency int) ([]string, error) {
	words := wordlist.Subdomains()
	if len(words) == 0 {
		return nil, fmt.Errorf("empty subdomain wordlist")
	}

	type workItem struct {
		subdomain string
	}

	work := make(chan workItem, len(words))
	for _, w := range words {
		work <- workItem{subdomain: fmt.Sprintf("%s.%s", w, domain)}
	}
	close(work)

	var (
		mu    sync.Mutex
		found []string
	)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range work {
				select {
				case <-ctx.Done():
					return
				default:
				}

				ips, err := net.DefaultResolver.LookupHost(ctx, item.subdomain)
				if err != nil {
					continue
				}
				if len(ips) == 0 {
					continue
				}

				host := strings.ToLower(item.subdomain)
				mu.Lock()
				found = append(found, host)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return found, nil
}
