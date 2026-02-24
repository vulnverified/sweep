package ports

import "testing"

func TestTop100_Sorted(t *testing.T) {
	for i := 1; i < len(Top100); i++ {
		if Top100[i] <= Top100[i-1] {
			t.Errorf("ports not sorted: %d at index %d <= %d at index %d", Top100[i], i, Top100[i-1], i-1)
		}
	}
}

func TestTop100_NoDuplicates(t *testing.T) {
	seen := make(map[int]bool)
	for _, p := range Top100 {
		if seen[p] {
			t.Errorf("duplicate port: %d", p)
		}
		seen[p] = true
	}
}

func TestTop100_ValidRange(t *testing.T) {
	for _, p := range Top100 {
		if p < 1 || p > 65535 {
			t.Errorf("port %d out of range", p)
		}
	}
}

func TestTop100_HasCommonPorts(t *testing.T) {
	commonPorts := []int{22, 80, 443, 3306, 5432, 8080, 8443}
	portSet := make(map[int]bool)
	for _, p := range Top100 {
		portSet[p] = true
	}

	for _, p := range commonPorts {
		if !portSet[p] {
			t.Errorf("missing common port: %d", p)
		}
	}
}
