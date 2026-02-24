// Package output handles all sweep CLI output formatting.
package output

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// Progress writes stage progress updates to stderr.
type Progress struct {
	w       io.Writer
	verbose bool
	silent  bool
	mu      sync.Mutex
	start   time.Time
}

// NewProgress creates a progress reporter.
func NewProgress(w io.Writer, verbose, silent bool) *Progress {
	return &Progress{
		w:       w,
		verbose: verbose,
		silent:  silent,
		start:   time.Now(),
	}
}

// Stage prints a stage header like "[1/5] Enumerating subdomains..."
func (p *Progress) Stage(num, total int, msg string) {
	if p.silent {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, "[%d/%d] %s\n", num, total, msg)
}

// Detail prints verbose detail (only in verbose mode).
func (p *Progress) Detail(msg string) {
	if !p.verbose || p.silent {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, "  %s\n", msg)
}

// Warn prints a warning to stderr.
func (p *Progress) Warn(msg string) {
	if p.silent {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, "  ! %s\n", msg)
}

// Complete prints the final duration.
func (p *Progress) Complete() {
	if p.silent {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	elapsed := time.Since(p.start)
	fmt.Fprintf(p.w, "\nCompleted in %.1fs\n", elapsed.Seconds())
}
