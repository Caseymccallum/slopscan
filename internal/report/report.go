// Package report renders scan results for a person to read.
//
// Every verdict is printed with the evidence that produced it, and every injection finding is
// printed as a quote, because the output of a security tool is only useful if the reader can
// disagree with it line by line. Colour is used sparingly and only to rank, never to inform.
//
// The machine-readable forms (WriteJSON, WriteDriftJSON) carry the same information as the prose -
// a pipeline and a person are two readers of one report, not two reports.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Caseymccallum/slopscan/internal/drift"
	"github.com/Caseymccallum/slopscan/internal/injection"
	"github.com/Caseymccallum/slopscan/internal/risk"
)

// Server is one server's full scan, ready to print.
type Server struct {
	ID       string                       `json:"id"`
	Source   string                       `json:"source"`
	Tools    []risk.Assessment            `json:"tools"`
	Findings map[string][]injection.Finding `json:"findings"`
}

// WriteJSON emits the same report Write prints, as one JSON document - for CI, for a dashboard,
// for whatever reads reports instead of people. One document, one newline, no progress chatter:
// a pipeline should never have to guess which lines were the report.
func WriteJSON(w io.Writer, server Server) error {
	encoded, err := json.Marshal(server)
	if err != nil {
		return err
	}
	_, err = w.Write(append(encoded, '\n'))
	return err
}

// WriteDriftJSON emits a drift comparison as one JSON document, carrying the same fields the prose
// report argues from - including `breaking`, which is the signal a pipeline acts on.
func WriteDriftJSON(w io.Writer, comparison drift.Report) error {
	encoded, err := json.Marshal(comparison)
	if err != nil {
		return err
	}
	_, err = w.Write(append(encoded, '\n'))
	return err
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
			if _, err := fmt.Fprintf(w, "      ! %s %s/%s: %q\n",
				finding.OWASP, finding.Severity, finding.Kind, finding.Quote); err != nil {
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

// WriteDrift prints a drift comparison: what changed against the pinned baseline, and what it
// means. Changes are listed breaking-first within their tools, because a removed tool is a
// different kind of news than a new one.
func WriteDrift(w io.Writer, report drift.Report) error {
	if _, err := fmt.Fprintf(w, "\nvs pinned baseline: DRIFTED (score %d/100)\n", report.Score); err != nil {
		return err
	}
	for _, change := range report.Changes {
		marker := "+"
		if change.Breaking {
			marker = "!"
		}
		if _, err := fmt.Fprintf(w, "  %s %-24s %-20s %s\n",
			marker, change.Tool, change.Kind, change.Detail); err != nil {
			return err
		}
	}
	if report.Breaking {
		_, err := fmt.Fprintf(w, "  A breaking change means code or an agent relying on the old tool surface is now silently wrong. Re-review before trusting this server.\n")
		return err
	}
	_, err := fmt.Fprintf(w, "  Additions only: nothing existing depends on the new tools, but nothing reviewed them either.\n")
	return err
}