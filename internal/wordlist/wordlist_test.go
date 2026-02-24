package wordlist

import "testing"

func TestSubdomains_NonEmpty(t *testing.T) {
	words := Subdomains()
	if len(words) == 0 {
		t.Fatal("subdomain wordlist is empty")
	}
	if len(words) < 500 {
		t.Errorf("expected at least 500 entries, got %d", len(words))
	}
}

func TestSubdomains_NoDuplicates(t *testing.T) {
	words := Subdomains()
	seen := make(map[string]bool)
	for _, w := range words {
		if seen[w] {
			t.Errorf("duplicate entry: %s", w)
		}
		seen[w] = true
	}
}

func TestSubdomains_NoEmptyLines(t *testing.T) {
	words := Subdomains()
	for _, w := range words {
		if w == "" {
			t.Error("found empty entry in wordlist")
		}
	}
}
