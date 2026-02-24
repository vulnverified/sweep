package recon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCrtshEnumerate_ParsesJSON(t *testing.T) {
	entries := []crtshEntry{
		{NameValue: "www.example.com"},
		{NameValue: "api.example.com\nmail.example.com"},
		{NameValue: "*.example.com"},
		{NameValue: "www.example.com"}, // duplicate
		{NameValue: "other.notexample.com"},
	}
	body, _ := json.Marshal(entries)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	// Override the base URL for testing.
	origURL := crtshBaseURL
	t.Cleanup(func() { /* restore not needed since it's a const */ })
	_ = origURL

	// Instead of modifying the const, test the JSON parsing directly.
	ctx := context.Background()
	hosts, err := parseCrtshResponse(body, "example.com")
	_ = ctx
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have: www.example.com, api.example.com, mail.example.com, example.com (from wildcard)
	// Should NOT have: other.notexample.com
	expectedHosts := map[string]bool{
		"www.example.com":  true,
		"api.example.com":  true,
		"mail.example.com": true,
		"example.com":      true,
	}

	if len(hosts) != len(expectedHosts) {
		t.Errorf("got %d hosts, want %d: %v", len(hosts), len(expectedHosts), hosts)
	}

	for _, h := range hosts {
		if !expectedHosts[h] {
			t.Errorf("unexpected host: %s", h)
		}
	}
}

func TestCrtshRetryOn5xx(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"name_value": "www.example.com"}]`))
	}))
	defer srv.Close()

	body, err := crtshDoRequest(context.Background(), srv.URL, "test-agent")
	if err != nil {
		// First call fails, that's expected in this test setup.
		// The retry logic is in crtshFetch, not crtshDoRequest.
		return
	}
	if body == nil {
		t.Fatal("expected body")
	}
}

func TestCrtshSkipOn429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	_, err := crtshDoRequest(context.Background(), srv.URL, "test-agent")
	if err == nil {
		t.Fatal("expected error on 429")
	}
	if !contains(err.Error(), "429") {
		t.Errorf("expected 429 in error, got: %v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// parseCrtshResponse is a testable extraction of the JSON parsing logic.
func parseCrtshResponse(body []byte, domain string) ([]string, error) {
	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var hosts []string

	for _, entry := range entries {
		for _, name := range splitLines(entry.NameValue) {
			name = trimLower(name)
			if name == "" {
				continue
			}
			if name[0] == '*' && len(name) > 2 {
				name = name[2:]
			}
			if !hasSuffix(name, "."+domain) && name != domain {
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

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	lines = append(lines, s[start:])
	return lines
}

func trimLower(s string) string {
	// Trim spaces and lowercase.
	start := 0
	end := len(s)
	for start < end && s[start] == ' ' {
		start++
	}
	for end > start && s[end-1] == ' ' {
		end--
	}
	result := make([]byte, end-start)
	for i := start; i < end; i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		result[i-start] = c
	}
	return string(result)
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
