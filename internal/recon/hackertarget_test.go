package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHackertargetParsesResponse(t *testing.T) {
	body := `www.example.com,1.2.3.4
api.example.com,5.6.7.8
mail.example.com,9.10.11.12
other.notexample.com,13.14.15.16
www.example.com,1.2.3.4`

	hosts := parseHackertargetResponse(body, "example.com")

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

func TestHackertargetHTTPIntegration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("www.example.com,1.2.3.4\napi.example.com,5.6.7.8\n"))
	}))
	defer srv.Close()

	// Test the request/parse path via the internal function.
	body, err := hackertargetDoRequest(context.Background(), srv.URL, "test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hosts := parseHackertargetResponse(body, "example.com")
	if len(hosts) != 2 {
		t.Errorf("got %d hosts, want 2", len(hosts))
	}
}

func TestHackertargetRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("error API count exceeded"))
	}))
	defer srv.Close()

	_, err := hackertargetDoRequest(context.Background(), srv.URL, "test-agent")
	if err == nil {
		t.Fatal("expected error on rate limit")
	}
}

func TestHackertarget429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	_, err := hackertargetDoRequest(context.Background(), srv.URL, "test-agent")
	if err == nil {
		t.Fatal("expected error on 429")
	}
}

func TestHackertargetEmptyLines(t *testing.T) {
	body := `www.example.com,1.2.3.4

api.example.com,5.6.7.8

`
	hosts := parseHackertargetResponse(body, "example.com")
	if len(hosts) != 2 {
		t.Errorf("got %d hosts, want 2: %v", len(hosts), hosts)
	}
}
