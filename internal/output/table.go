package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/vulnverified/sweep/internal/engine"
)

// WriteTable renders the HTTP services as a styled terminal table.
func WriteTable(w io.Writer, result *engine.ScanResult, noColor bool) {
	if len(result.HTTPServices) == 0 {
		fmt.Fprintln(w, "\nNo HTTP services discovered.")
		return
	}

	// Group services by host for compact display.
	type hostRow struct {
		host   string
		ip     string
		ports  []string
		techs  []string
		cdns   []string
		title  string
		status int
	}

	hostMap := make(map[string]*hostRow)
	var hostOrder []string

	for _, svc := range result.HTTPServices {
		row, exists := hostMap[svc.Host]
		if !exists {
			row = &hostRow{host: svc.Host, ip: svc.IP}
			hostMap[svc.Host] = row
			hostOrder = append(hostOrder, svc.Host)
		}
		portStr := fmt.Sprintf("%d", svc.Port)
		if !containsStr(row.ports, portStr) {
			row.ports = append(row.ports, portStr)
		}
		for _, t := range svc.Technologies {
			if t.Category == "cdn-waf" {
				if !containsStr(row.cdns, t.Name) {
					row.cdns = append(row.cdns, t.Name)
				}
			} else {
				if !containsStr(row.techs, t.Name) {
					row.techs = append(row.techs, t.Name)
				}
			}
		}
		if row.title == "" && svc.Title != "" {
			row.title = svc.Title
		}
		if row.status == 0 {
			row.status = svc.StatusCode
		}
	}

	// Build table rows.
	var rows [][]string
	for _, host := range hostOrder {
		row := hostMap[host]
		techStr := strings.Join(row.techs, ", ")
		if len(row.cdns) > 0 {
			cdnStr := strings.Join(row.cdns, ", ")
			if techStr != "" {
				techStr += " (" + cdnStr + ")"
			} else {
				techStr = "(" + cdnStr + ")"
			}
		}
		title := truncate(row.title, 30)
		rows = append(rows, []string{
			row.host,
			row.ip,
			strings.Join(row.ports, ","),
			truncate(techStr, 40),
			title,
		})
	}

	// Sort by host.
	sort.Slice(rows, func(i, j int) bool {
		return rows[i][0] < rows[j][0]
	})

	fmt.Fprintln(w)

	if noColor {
		writeSimpleTable(w, rows)
		return
	}

	headers := []string{"Host", "IP", "Ports", "Technologies", "Title"}

	t := table.New().
		Headers(headers...).
		Border(lipgloss.RoundedBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("240"))).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))
			}
			return lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
		})

	for _, row := range rows {
		t.Row(row...)
	}

	fmt.Fprintln(w, t.Render())
}

func writeSimpleTable(w io.Writer, rows [][]string) {
	headers := []string{"Host", "IP", "Ports", "Technologies", "Title"}

	// Calculate column widths.
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Print header.
	for i, h := range headers {
		if i > 0 {
			fmt.Fprint(w, " | ")
		}
		fmt.Fprintf(w, "%-*s", widths[i], h)
	}
	fmt.Fprintln(w)

	// Separator.
	for i, width := range widths {
		if i > 0 {
			fmt.Fprint(w, "-+-")
		}
		fmt.Fprint(w, strings.Repeat("-", width))
	}
	fmt.Fprintln(w)

	// Rows.
	for _, row := range rows {
		for i, cell := range row {
			if i > 0 {
				fmt.Fprint(w, " | ")
			}
			fmt.Fprintf(w, "%-*s", widths[i], cell)
		}
		fmt.Fprintln(w)
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
