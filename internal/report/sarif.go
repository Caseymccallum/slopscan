package report

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/Caseymccallum/slopscan/internal/drift"
	"github.com/Caseymccallum/slopscan/internal/injection"
)

// SARIF 2.1.0 output: the format GitHub code scanning and every other security platform ingests.
// This is how a scan stops being a terminal scroll and becomes an alert a reviewer triages in the
// same queue as the rest of their security work.
//
// The mapping is deliberately boring: one finding = one result, one finding kind = one rule, and
// the quote is the message. Nothing is rescored here - `security-severity` values are display
// buckets for the host's ranking (high/medium/low), not computed CVSS: evidence over scores
// applies to the standards world too.

// sarifLog is the SARIF document root.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	Properties       sarifProperties `json:"properties"`
}

type sarifProperties struct {
	Tags            []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifLogical struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// SARIFInput is one finding ready to become an alert: what was found, where, and on what artifact.
type SARIFInput struct {
	// RuleID is the finding kind - one rule per kind, shared across results.
	RuleID string
	// Level is high, medium or low - mapped to SARIF error/warning/note.
	Level string
	// Message is the finding's quote: the evidence, verbatim.
	Message string
	// Artifact is the file the finding came from (the tools.json, the client config).
	Artifact string
	// Subject is the tool or config entry the finding is about.
	Subject string
	// OWASP is the risk code, carried as a rule tag.
	OWASP string
}

// BuildSARIF assembles one SARIF run from findings. Results are ordered artifact, subject, rule -
// deterministically, so two scans of the same surface produce the same document and any platform
// deduplicating alerts sees one alert, not one per run.
func BuildSARIF(version string, inputs []SARIFInput) sarifLog {
	sorted := append([]SARIFInput(nil), inputs...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Artifact != sorted[j].Artifact {
			return sorted[i].Artifact < sorted[j].Artifact
		}
		if sorted[i].Subject != sorted[j].Subject {
			return sorted[i].Subject < sorted[j].Subject
		}
		return sorted[i].RuleID < sorted[j].RuleID
	})

	rules := []sarifRule{}
	ruleIndex := map[string]bool{}
	results := []sarifResult{}
	for _, input := range sorted {
		if !ruleIndex[input.RuleID] {
			ruleIndex[input.RuleID] = true
			tags := []string{"security"}
			if input.OWASP != "" {
				tags = append(tags, "owasp"+input.OWASP)
			}
			rules = append(rules, sarifRule{
				ID:               input.RuleID,
				ShortDescription: sarifMessage{Text: input.RuleID},
				Properties: sarifProperties{
					Tags:            tags,
					SecuritySeverity: securitySeverity(input.Level),
				},
			})
		}
		result := sarifResult{
			RuleID:  input.RuleID,
			Level:   sarifLevel(input.Level),
			Message: sarifMessage{Text: input.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: input.Artifact},
				},
			}},
		}
		if input.Subject != "" {
			result.Locations[0].LogicalLocations = []sarifLogical{{Name: input.Subject, Kind: "member"}}
		}
		results = append(results, result)
	}

	return sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "slopscan",
				InformationURI: "https://github.com/Caseymccallum/slopscan",
				Version:        version,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

// sarifLevel maps severity to SARIF's three levels. Low is note: real to a reader, not a gate.
func sarifLevel(severity string) string {
	switch severity {
	case "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity is the host's display bucket (GitHub ranks 9.0+ critical, 7.0+ high, 4.0+
// medium). These are fixed ranks for the tool's own severities - never a computed CVSS.
func securitySeverity(severity string) string {
	switch severity {
	case "high":
		return "8.0"
	case "medium":
		return "5.5"
	default:
		return "3.0"
	}
}

// WriteSARIF emits one SARIF document: one run, one newline, no progress chatter - the same
// discipline as WriteJSON, because a pipeline must never have to guess which lines were the report.
func WriteSARIF(w io.Writer, version string, inputs []SARIFInput) error {
	encoded, err := json.Marshal(BuildSARIF(version, inputs))
	if err != nil {
		return err
	}
	_, err = w.Write(append(encoded, '\n'))
	return err
}

// SARIFInputsFromServer converts a scan's findings into SARIF inputs. The artifact is the source
// the tools came from (the tools.json, the config file) and the subject is the tool - which is
// what a reviewer wants to see next to an alert.
func SARIFInputsFromServer(source string, server Server) []SARIFInput {
	inputs := []SARIFInput{}
	for _, tool := range sortedToolNames(server.Findings) {
		for _, finding := range server.Findings[tool] {
			inputs = append(inputs, SARIFInput{
				RuleID:   finding.Kind,
				Level:    finding.Severity,
				Message:  finding.Quote,
				Artifact: source,
				Subject:  tool,
				OWASP:    finding.OWASP,
			})
		}
	}
	return inputs
}

// SARIFInputsFromDrift turns a drift comparison into results: a rug pull is an alert like any
// other, and CI that gates on the exit code still deserves to see *what* broke in the same queue.
// Drift is the MCP03 threat's delivery mechanism (see THREAT-MODEL), so it carries that code.
func SARIFInputsFromDrift(source string, comparison drift.Report) []SARIFInput {
	inputs := []SARIFInput{}
	for _, change := range comparison.Changes {
		level := "medium"
		if change.Breaking {
			level = "high"
		}
		inputs = append(inputs, SARIFInput{
			RuleID:   "drift/" + change.Kind,
			Level:    level,
			Message:  change.Detail,
			Artifact: source,
			Subject:  change.Tool,
			OWASP:    "MCP03",
		})
	}
	return inputs
}

func sortedToolNames(findings map[string][]injection.Finding) []string {
	names := make([]string, 0, len(findings))
	for name := range findings {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}