package recon

import (
	"net"
	"testing"
)

func TestCheckDangling_MatchesKnownPatterns(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		cname      string
		err        error
		wantNil    bool
		wantStatus string
	}{
		{
			name:       "herokuapp NXDOMAIN",
			host:       "blog.example.com",
			cname:      "old-blog.herokuapp.com",
			err:        &net.DNSError{IsNotFound: true, Name: "old-blog.herokuapp.com"},
			wantStatus: "NXDOMAIN",
		},
		{
			name:       "s3 bucket NXDOMAIN",
			host:       "assets.example.com",
			cname:      "assets-bucket.s3.amazonaws.com",
			err:        &net.DNSError{IsNotFound: true, Name: "assets-bucket.s3.amazonaws.com"},
			wantStatus: "NXDOMAIN",
		},
		{
			name:       "github.io SERVFAIL",
			host:       "docs.example.com",
			cname:      "example.github.io",
			err:        &net.DNSError{IsNotFound: false, Name: "example.github.io", Err: "server misbehaving"},
			wantStatus: "SERVFAIL",
		},
		{
			name:       "azurewebsites NXDOMAIN",
			host:       "app.example.com",
			cname:      "myapp.azurewebsites.net",
			err:        &net.DNSError{IsNotFound: true, Name: "myapp.azurewebsites.net"},
			wantStatus: "NXDOMAIN",
		},
		{
			name:       "netlify NXDOMAIN",
			host:       "site.example.com",
			cname:      "example-site.netlify.app",
			err:        &net.DNSError{IsNotFound: true, Name: "example-site.netlify.app"},
			wantStatus: "NXDOMAIN",
		},
		{
			name:    "non-matching pattern",
			host:    "cdn.example.com",
			cname:   "cdn.someother.com",
			err:     &net.DNSError{IsNotFound: true},
			wantNil: true,
		},
		{
			name:    "no error - not dangling",
			host:    "ok.example.com",
			cname:   "ok.herokuapp.com",
			err:     nil,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkDangling(tt.host, tt.cname, tt.err)
			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.Host != tt.host {
				t.Errorf("host = %q, want %q", result.Host, tt.host)
			}
			if result.CNAME != tt.cname {
				t.Errorf("cname = %q, want %q", result.CNAME, tt.cname)
			}
			if result.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", result.Status, tt.wantStatus)
			}
		})
	}
}

func TestDanglingPatterns_AllPresent(t *testing.T) {
	expectedPatterns := []string{
		".s3.amazonaws.com",
		".azurewebsites.net",
		".github.io",
		".herokuapp.com",
		".cloudfront.net",
		".elasticbeanstalk.com",
		".trafficmanager.net",
		".blob.core.windows.net",
		".azureedge.net",
		".pantheonsite.io",
		".netlify.app",
		".ghost.io",
		".myshopify.com",
		".surge.sh",
	}

	patternSet := make(map[string]bool)
	for _, p := range danglingPatterns {
		patternSet[p] = true
	}

	for _, expected := range expectedPatterns {
		if !patternSet[expected] {
			t.Errorf("missing dangling pattern: %s", expected)
		}
	}

	if len(danglingPatterns) != len(expectedPatterns) {
		t.Errorf("got %d patterns, want %d", len(danglingPatterns), len(expectedPatterns))
	}
}
