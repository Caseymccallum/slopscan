// Package report renders scan results for a person to read.
//
// Every verdict is printed with the evidence that produced it, and every injection finding is
// printed as a quote, because the output of a security tool is only useful if the reader can
// disagree with it line by line. Colour is used sparingly and only to rank, never to inform.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Caseymccallum/slopscan/internal/injection"
	"github.com/Caseymccallum/slopscan/internal/risk"
)

// Server is one server's full scan, ready to print.
type Server struct {
	ID       string
	Source   string
	Tools    []risk.Assessment
	Findings map[string][]injection.Finding
}

// Write prints a full report for one server.
func Write(w io.Writer, server Server) error {
	weight := 0.0
	destructive := 0
	for _, tool := range server.Tools {
		weight += tool.Weight
		if tool.Category == risk.Destructive {
			destructive++
		}
	}

	if _, err := fmt.Fprintf(w, "%s  (%d tools, %d destructive, risk score %.1f)\n  source: %s\n\n",
		server.ID, len(server.Tools), destructive, weight, server.Source); err != nil {
		return err
	}

	for _, tool := range server.Tools {
		if _, err := fmt.Fprintf(w, "  %-28s %-12s %.2f  [%s]\n",
			tool.Tool, tool.Category, tool.Weight, tool.Confidence); err != nil {
			return err
		}
		for _, reason := range tool.Reasons {
			if _, err := fmt.Fprintf(w, "      - %s\n", reason); err != nil {
				return err
			}
		}
		for _, finding := range server.Findings[tool.Tool] {
			if _, err := fmt.Fprintf(w, "      ! %s/%s: %q\n",
				finding.Severity, finding.Kind, finding.Quote); err != nil {
				return err
			}
		}
	}
	return nil
}

// Summary prints one line per server, riskiest first - the fleet view.
func WriteSummary(w io.Writer, servers []Server) error {
	sort.Slice(servers, func(i, j int) bool {
		return riskOf(servers[i]) > riskOf(servers[j])
	})
	for _, server := range servers {
		if _, err := fmt.Fprintf(w, "%-40s %3d tools  risk %6.1f  %s\n",
			truncate(server.ID, 40), len(server.Tools), riskOf(server), verdict(server)); err != nil {
			return err
		}
	}
	return nil
}

func riskOf(server Server) float64 {
	weight := 0.0
	for _, tool := range server.Tools {
		weight += tool.Weight
	}
	return weight
}

// verdict is the one-word reading of a server: what a person needs to know first.
func verdict(server Server) string {
	for _, tool := range server.Tools {
		if tool.Category == risk.Destructive {
			return "destroys data"
		}
	}
	if injection.Worst(flatten(server.Findings)) == "high" {
		return "prompt injection in metadata"
	}
	for _, tool := range server.Tools {
		if tool.Category == risk.Financial {
			return "touches money"
		}
		if tool.Category == risk.Execute {
			return "runs commands"
		}
	}
	return "reads only"
}

func flatten(findings map[string][]injection.Finding) []injection.Finding {
	all := []injection.Finding{}
	for _, list := range findings {
		all = append(all, list...)
	}
	return all
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return strings.TrimSpace(value[:max-1]) + "…"
}