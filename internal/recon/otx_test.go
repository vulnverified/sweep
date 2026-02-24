package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOTXParsesResponse(t *testing.T) {
	body := []byte(`{
		"passive_dns": [
			{"hostname": "www.example.com"},
			{"hostname": "api.example.com"},
			{"hostname": "mail.example.com"},
			{"hostname": "other.notexample.com"},
			{"hostname": "www.example.com"},
			{"hostname": ""}
		]
	}`)

	hosts, err := parseOTXResponse(body, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := map[string]bool{
		"www.example.com":  true,
		"api.example.com":  true,
		"mail.example.com": true,
	}

	if len(hosts) != len(expected) {
		t.Errorf("got %d hosts, want %d: %v", len(hosts), len(expected), hosts)
	}

	for _, h := range hosts {
		if !expected[h] {
			t.Errorf("unexpected host: %s", h)
		}
	}
}

func TestOTXHTTPIntegration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"passive_dns": [{"hostname": "www.example.com"}, {"hostname": "api.example.com"}]}`))
	}))
	defer srv.Close()

	body, err := otxDoRequest(context.Background(), srv.URL, "test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hosts, err := parseOTXResponse(body, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 2 {
		t.Errorf("got %d hosts, want 2", len(hosts))
	}
}

func TestOTXRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	_, err := otxDoRequest(context.Background(), srv.URL, "test-agent")
	if err == nil {
		t.Fatal("expected error on 429")
	}
}

func TestOTXEmptyPassiveDNS(t *testing.T) {
	body := []byte(`{"passive_dns": []}`)
	hosts, err := parseOTXResponse(body, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("expected 0 hosts, got %d", len(hosts))
	}
}

func TestOTXInvalidJSON(t *testing.T) {
	body := []byte(`not json`)
	_, err := parseOTXResponse(body, "example.com")
	if err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}
