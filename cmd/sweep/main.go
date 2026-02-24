package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnverified/sweep/internal/engine"
	"github.com/vulnverified/sweep/internal/output"
	"github.com/vulnverified/sweep/internal/recon"
	"github.com/vulnverified/sweep/pkg/ports"
)

// Set via ldflags at build time.
var version = "dev"

func main() {
	output.Version = version

	var (
		jsonOutput  bool
		portsList   string
		timeout     time.Duration
		concurrency int
		noColor     bool
		silent      bool
		verbose     bool
		axfr        bool
	)

	rootCmd := &cobra.Command{
		Use:   "sweep <domain>",
		Short: "Sweep your attack surface",
		Long:  "External attack surface recon — subdomain enumeration, DNS resolution, port scanning, HTTP probing, and tech fingerprinting.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := strings.ToLower(strings.TrimSpace(args[0]))
			if domain == "" {
				return fmt.Errorf("domain is required")
			}

			// Respect NO_COLOR env var.
			if _, ok := os.LookupEnv("NO_COLOR"); ok {
				noColor = true
			}

			// Parse custom ports if provided.
			scanPorts := ports.Top100
			if portsList != "" {
				parsed, err := parsePorts(portsList)
				if err != nil {
					return fmt.Errorf("invalid --ports: %w", err)
				}
				scanPorts = parsed
			}

			userAgent := fmt.Sprintf("sweep/%s (+https://github.com/vulnverified/sweep)", version)

			cfg := engine.Config{
				Target:      domain,
				Ports:       scanPorts,
				Timeout:     timeout,
				Concurrency: concurrency,
				UserAgent:   userAgent,
			}

			// Set up context with signal handling for clean Ctrl+C.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt)
			go func() {
				<-sigCh
				fmt.Fprintln(os.Stderr, "\nInterrupted, cleaning up...")
				cancel()
			}()

			// Wire up stages.
			prober := &recon.Prober{UserAgent: userAgent}
			stages := engine.Stages{
				Enumerator: &recon.Enumerator{
					UserAgent: userAgent,
					AXFR:      axfr,
					Progress:  nil, // set below
				},
				Resolver:      &recon.Resolver{},
				Scanner:       &recon.Scanner{},
				Prober:        prober,
				Fingerprinter: &recon.Fingerprinter{Prober: prober},
			}

			// Progress output.
			showProgress := !jsonOutput && !silent
			progress := output.NewProgress(os.Stderr, verbose, !showProgress)

			// Set progress on enumerator for per-source detail.
			stages.Enumerator.(*recon.Enumerator).Progress = progress

			// Print header.
			if showProgress {
				output.WriteHeader(os.Stderr, noColor)
			}

			// Run the pipeline.
			result, err := engine.Run(ctx, cfg, stages, progress)
			if err != nil {
				return err
			}

			if showProgress {
				progress.Complete()
			}

			// Output results.
			if jsonOutput {
				return output.WriteJSON(os.Stdout, result)
			}

			showCTA := !silent
			output.WriteTable(os.Stdout, result, noColor)
			output.WriteSummary(os.Stdout, result, showCTA, noColor)

			return nil
		},
	}

	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output structured JSON to stdout")
	rootCmd.Flags().StringVar(&portsList, "ports", "", "Comma-separated port list (default: top 100)")
	rootCmd.Flags().DurationVar(&timeout, "timeout", 2*time.Second, "Per-connection timeout")
	rootCmd.Flags().IntVar(&concurrency, "concurrency", 25, "Max concurrent connections")
	rootCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable terminal colors")
	rootCmd.Flags().BoolVar(&silent, "silent", false, "Results only, no progress or CTA")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose per-source progress")
	rootCmd.Flags().BoolVar(&axfr, "axfr", false, "Test for DNS zone transfers")

	rootCmd.Version = version
	rootCmd.SetVersionTemplate("sweep {{.Version}}\n")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// parsePorts parses a comma-separated list of port numbers.
func parsePorts(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	var result []int
	seen := make(map[int]bool)

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		port, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port %d out of range (1-65535)", port)
		}
		if !seen[port] {
			seen[port] = true
			result = append(result, port)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no valid ports specified")
	}
	return result, nil
}
