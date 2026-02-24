package recon

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vulnverified/sweep/internal/engine"
)

func TestHTTPProbe_ExtractsMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("X-Powered-By", "Express")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head><title>Test Page</title></head><body>hello</body></html>`))
	}))
	defer srv.Close()

	port := srv.Listener.Addr().(*net.TCPAddr).Port

	openPorts := []engine.PortResult{
		{Host: "127.0.0.1", IP: "127.0.0.1", Port: port},
	}

	result, err := HTTPProbe(context.Background(), openPorts, 2, 5*time.Second, "test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Services) != 1 {
		t.Fatalf("got %d services, want 1", len(result.Services))
	}

	svc := result.Services[0]
	if svc.StatusCode != 200 {
		t.Errorf("status = %d, want 200", svc.StatusCode)
	}
	if svc.Title != "Test Page" {
		t.Errorf("title = %q, want %q", svc.Title, "Test Page")
	}
	if svc.Server != "nginx/1.24.0" {
		t.Errorf("server = %q, want %q", svc.Server, "nginx/1.24.0")
	}
}

func TestHTTPProbe_HandlesNonHTTP(t *testing.T) {
	// Port with nothing listening (closed immediately).
	openPorts := []engine.PortResult{
		{Host: "127.0.0.1", IP: "127.0.0.1", Port: 1},
	}

	result, err := HTTPProbe(context.Background(), openPorts, 2, 500*time.Millisecond, "test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Services) != 0 {
		t.Errorf("got %d services for non-HTTP port, want 0", len(result.Services))
	}
}
