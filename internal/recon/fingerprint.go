package recon

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"
	"sync"

	"github.com/vulnverified/sweep/internal/engine"
)

//go:embed fingerprints.json
var fingerprintsJSON []byte

// FingerprintRule defines a pattern-matching rule for technology detection.
type FingerprintRule struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Headers  []headerMatch  `json:"headers,omitempty"`
	Body     []string       `json:"body,omitempty"`
	Cookies  []string       `json:"cookies,omitempty"`
}

type headerMatch struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	regex   *regexp.Regexp
}

var (
	fingerprintRules []FingerprintRule
	fingerprintOnce  sync.Once
)

func loadFingerprints() {
	fingerprintOnce.Do(func() {
		if err := json.Unmarshal(fingerprintsJSON, &fingerprintRules); err != nil {
			return
		}
		// Pre-compile header regexes.
		for i := range fingerprintRules {
			for j := range fingerprintRules[i].Headers {
				h := &fingerprintRules[i].Headers[j]
				if h.Pattern != "" {
					h.regex, _ = regexp.Compile("(?i)" + h.Pattern)
				}
			}
		}
	})
}

// FingerprintServices applies technology fingerprinting to HTTP services.
// Modifies services in place by populating the Technologies field.
func FingerprintServices(services []engine.HTTPService, probeResults map[string]*probeData) {
	loadFingerprints()

	for i := range services {
		svc := &services[i]
		var techs []engine.Technology

		data := probeResults[svc.URL]
		if data == nil {
			// Fallback: fingerprint from headers only.
			data = &probeData{
				headers: map[string]string{},
			}
			if svc.Server != "" {
				data.headers["server"] = svc.Server
			}
		}

		for _, rule := range fingerprintRules {
			if matchesRule(rule, data) {
				techs = append(techs, engine.Technology{
					Name:     rule.Name,
					Category: rule.Category,
				})
			}
		}

		svc.Technologies = techs
	}
}

// probeData holds the raw HTTP response data for fingerprinting.
type probeData struct {
	headers map[string]string // lowercase header name → value
	body    string
	cookies []string // cookie names
}

func matchesRule(rule FingerprintRule, data *probeData) bool {
	// Check header patterns.
	for _, hm := range rule.Headers {
		headerName := strings.ToLower(hm.Name)
		headerVal, exists := data.headers[headerName]
		if !exists {
			continue
		}
		if hm.regex != nil && hm.regex.MatchString(headerVal) {
			return true
		}
		if hm.Pattern == "" && headerVal != "" {
			return true
		}
	}

	// Check body substrings.
	bodyLower := strings.ToLower(data.body)
	for _, substr := range rule.Body {
		if strings.Contains(bodyLower, strings.ToLower(substr)) {
			return true
		}
	}

	// Check cookie names.
	for _, cookieName := range rule.Cookies {
		cookieLower := strings.ToLower(cookieName)
		for _, c := range data.cookies {
			if strings.ToLower(c) == cookieLower {
				return true
			}
		}
	}

	return false
}
