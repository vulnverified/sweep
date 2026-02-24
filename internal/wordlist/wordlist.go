// Package wordlist provides an embedded subdomain brute-force wordlist.
package wordlist

import (
	"bufio"
	"embed"
	"strings"
)

//go:embed subdomains.txt
var subdomainsFS embed.FS

// Subdomains returns the embedded subdomain wordlist as a string slice.
// Lines are trimmed and empty lines/comments are skipped.
func Subdomains() []string {
	data, err := subdomainsFS.ReadFile("subdomains.txt")
	if err != nil {
		return nil
	}

	var words []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		words = append(words, line)
	}
	return words
}
