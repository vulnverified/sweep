package recon

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/vulnverified/sweep/internal/engine"
)

func TestFingerprintServices_DetectsTechnologies(t *testing.T) {
	tests := []struct {
		name     string
		data     *probeData
		wantTech []string
	}{
		{
			name: "nginx from Server header",
			data: &probeData{
				headers: map[string]string{"server": "nginx/1.24.0"},
			},
			wantTech: []string{"nginx"},
		},
		{
			name: "WordPress from body",
			data: &probeData{
				headers: map[string]string{},
				body:    `<link rel="stylesheet" href="/wp-content/themes/theme/style.css">`,
			},
			wantTech: []string{"WordPress"},
		},
		{
			name: "Cloudflare from CF-RAY header",
			data: &probeData{
				headers: map[string]string{"cf-ray": "abc123"},
			},
			wantTech: []string{"Cloudflare"},
		},
		{
			name: "Express/Node.js from X-Powered-By",
			data: &probeData{
				headers: map[string]string{"x-powered-by": "Express"},
			},
			wantTech: []string{"Node.js"},
		},
		{
			name: "Next.js from body",
			data: &probeData{
				headers: map[string]string{},
				body:    `<script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>`,
			},
			wantTech: []string{"React", "Next.js"},
		},
		{
			name: "Laravel from cookies",
			data: &probeData{
				headers: map[string]string{},
				cookies: []string{"laravel_session"},
			},
			wantTech: []string{"Laravel"},
		},
		{
			name: "PHP from X-Powered-By",
			data: &probeData{
				headers: map[string]string{"x-powered-by": "PHP/8.2.0"},
			},
			wantTech: []string{"PHP"},
		},
		{
			name: "no match",
			data: &probeData{
				headers: map[string]string{"server": "CustomServer/1.0"},
				body:    "<html><body>Hello</body></html>",
			},
			wantTech: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			services := []engine.HTTPService{
				{URL: "http://test.com", Host: "test.com"},
			}

			probeResults := map[string]*probeData{
				"http://test.com": tt.data,
			}

			FingerprintServices(services, probeResults)

			if tt.wantTech == nil {
				if len(services[0].Technologies) != 0 {
					t.Errorf("expected no techs, got %v", services[0].Technologies)
				}
				return
			}

			techNames := make(map[string]bool)
			for _, tech := range services[0].Technologies {
				techNames[tech.Name] = true
			}

			for _, want := range tt.wantTech {
				if !techNames[want] {
					t.Errorf("missing tech %q in %v", want, services[0].Technologies)
				}
			}
		})
	}
}

func TestFingerprintDB_ValidJSON(t *testing.T) {
	var rules []FingerprintRule
	if err := json.Unmarshal(fingerprintsJSON, &rules); err != nil {
		t.Fatalf("invalid fingerprints.json: %v", err)
	}

	if len(rules) < 40 {
		t.Errorf("expected at least 40 rules, got %d", len(rules))
	}

	// Verify all header regexes compile.
	for _, rule := range rules {
		for _, h := range rule.Headers {
			if h.Pattern != "" {
				if _, err := regexp.Compile("(?i)" + h.Pattern); err != nil {
					t.Errorf("rule %q: invalid regex %q: %v", rule.Name, h.Pattern, err)
				}
			}
		}
	}
}

func TestFingerprintDB_HasRequiredCategories(t *testing.T) {
	loadFingerprints()

	categories := make(map[string]int)
	for _, rule := range fingerprintRules {
		categories[rule.Category]++
	}

	requiredCategories := []string{"web-server", "language", "framework", "cms", "cdn-waf"}
	for _, cat := range requiredCategories {
		if categories[cat] == 0 {
			t.Errorf("missing required category: %s", cat)
		}
	}
}
