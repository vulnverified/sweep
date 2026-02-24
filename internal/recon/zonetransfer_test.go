package recon

import (
	"testing"

	"github.com/vulnverified/sweep/internal/engine"
)

func TestZoneTransferResult_EmptyNameservers(t *testing.T) {
	result := &ZoneTransferResult{}

	if len(result.Transfers) != 0 {
		t.Errorf("expected 0 transfers, got %d", len(result.Transfers))
	}
	if len(result.Hostnames) != 0 {
		t.Errorf("expected 0 hostnames, got %d", len(result.Hostnames))
	}
}

func TestZoneTransferResult_FailedTransfer(t *testing.T) {
	result := &ZoneTransferResult{
		Transfers: []engine.ZoneTransfer{
			{Nameserver: "ns1.example.com", Success: false},
			{Nameserver: "ns2.example.com", Success: false},
		},
	}

	successCount := 0
	for _, zt := range result.Transfers {
		if zt.Success {
			successCount++
		}
	}
	if successCount != 0 {
		t.Errorf("expected 0 successful transfers, got %d", successCount)
	}
}

func TestZoneTransferResult_SuccessfulTransfer(t *testing.T) {
	result := &ZoneTransferResult{
		Transfers: []engine.ZoneTransfer{
			{Nameserver: "ns1.example.com", Success: true, Records: 42},
			{Nameserver: "ns2.example.com", Success: false},
		},
		Hostnames: []string{"www.example.com", "mail.example.com"},
	}

	successCount := 0
	for _, zt := range result.Transfers {
		if zt.Success {
			successCount++
		}
	}
	if successCount != 1 {
		t.Errorf("expected 1 successful transfer, got %d", successCount)
	}
	if len(result.Hostnames) != 2 {
		t.Errorf("expected 2 hostnames, got %d", len(result.Hostnames))
	}
}
