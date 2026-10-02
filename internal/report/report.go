// Package report renders scan results for a person to read.
//
// Every verdict is printed with the evidence that produced it, and every injection finding is
// printed as a quote, because the output of a security tool is only useful if the reader can
// disagree with it line by line. Colour is used sparingly and only to rank, never to inform.
//
// The machine-readable forms (WriteJSON, WriteDriftJSON, WriteSARIF) carry the same information as
// the prose - a pipeline and a person are two readers of one report, not two reports.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Caseymccallum/slopscan/internal/catalogue"
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

	if _, err := fmt.Fprintf(w, "%s  (%d %s, %d destructive, risk score %.1f)\n  source: %s\n\n",
		server.ID, len(server.Tools), entryWord(server.Tools), destructive, weight, server.Source); err != nil {
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
		if _, err := fmt.Fprintf(w, "%-40s %3d %s  risk %6.1f  %s\n",
			truncate(server.ID, 40), len(server.Tools), entryWord(server.Tools), riskOf(server), verdict(server)); err != nil {
			return err
		}
	}
	return nil
}

// entryWord is the honest count noun: a server listing prompts and resources has entries, not
// only tools, and a report that miscounts what it read is a report a reader learns to distrust.
func entryWord(assessments []risk.Assessment) string {
	for _, assessment := range assessments {
		if assessment.Category == risk.Context {
			return "entries"
		}
	}
	return "tools"
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

// HistoryView is one observation on a timeline, with what changed since the one before it.
type HistoryView struct {
	ScannedAt time.Time `json:"scannedAt"`
	Tools     int       `json:"tools"`
	Risk      float64   `json:"risk"`
	Surface   string    `json:"surface"`
	// Changes is the drift against the previous observation; empty for the first. Derived at
	// render time from the stored definitions, so the timeline cannot disagree with itself.
	Changes []drift.Change `json:"changes"`
}

// HistoryReport is one server's whole timeline, ready to print or send.
type HistoryReport struct {
	ID string `json:"id"`
	// Summary is the verdict at the end of the timeline: what the current scan says.
	Summary     string        `json:"summary"`
	Observations []HistoryView `json:"observations"`
}

// BuildHistory turns stored observations into a report view, comparing each with the one before.
func BuildHistory(id string, observations []catalogue.Observation) HistoryReport {
	report := HistoryReport{ID: id, Observations: []HistoryView{}}
	for index, observation := range observations {
		view := HistoryView{
			ScannedAt: observation.ScannedAt,
			Tools:     observation.Tools,
			Risk:      observation.Risk,
			Surface:   observation.Surface,
			Changes:   []drift.Change{},
		}
		if index > 0 {
			comparison := drift.Compare(observations[index-1].Definitions, observation.Definitions)
			view.Changes = comparison.Changes
		}
		report.Observations = append(report.Observations, view)
	}
	if len(observations) > 0 {
		report.Summary = HistorySummary(observations[len(observations)-1])
	}
	return report
}

// HistorySummary is the one-word reading of an observation, the same vocabulary the fleet view
// uses - so a timeline entry and a `db list` line say the same thing about the same moment.
func HistorySummary(observation catalogue.Observation) string {
	destructive := false
	weight := 0.0
	for _, tool := range observation.Definitions {
		if risk.Classify(tool).Category == risk.Destructive {
			destructive = true
		}
		weight += risk.Classify(tool).Weight
	}
	if destructive {
		return "destroys data"
	}
	if weight > 0 {
		return fmt.Sprintf("risk %.1f", weight)
	}
	return "reads only"
}

// WriteHistory prints the timeline: one line per observation, with the changes between them
// indented underneath - the answer to "when did this change?", in the order it happened.
func WriteHistory(w io.Writer, report HistoryReport) error {
	if len(report.Observations) == 0 {
		_, err := fmt.Fprintf(w, "%s: no observations recorded.\n", report.ID)
		return err
	}
	if _, err := fmt.Fprintf(w, "%s  (%d observations)\n\n", report.ID, len(report.Observations)); err != nil {
		return err
	}
	for index, observation := range report.Observations {
		note := "first observation"
		if index > 0 {
			if len(observation.Changes) == 0 {
				note = "unchanged"
			} else {
				note = "CHANGED"
			}
		}
		if _, err := fmt.Fprintf(w, "  %s  %3d tools  risk %5.1f  surface %s  %s\n",
			observation.ScannedAt.Format(time.RFC3339), observation.Tools, observation.Risk,
			shortHash(observation.Surface), note); err != nil {
			return err
		}
		for _, change := range observation.Changes {
			marker := "+"
			if change.Breaking {
				marker = "!"
			}
			if _, err := fmt.Fprintf(w, "      %s %-28s %-20s %s\n",
				marker, change.Tool, change.Kind, change.Detail); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintf(w, "\nNow: %s.\n", report.Summary)
	return err
}

// shortHash trims a fingerprint to a readable identity: enough to tell two surfaces apart at a
// glance, not enough to be noise.
func shortHash(surface string) string {
	if len(surface) <= 12 {
		return surface
	}
	return surface[:12]
}

// WriteHistoryJSON emits the same timeline as one JSON document - for CI, for a dashboard, for
// whatever reads reports instead of people.
func WriteHistoryJSON(w io.Writer, report HistoryReport) error {
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = w.Write(append(encoded, '\n'))
	return err
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