package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Caseymccallum/slopscan/internal/drift"
	"github.com/Caseymccallum/slopscan/internal/injection"
)

// SARIF is the format every security platform ingests - a wrong document is not a bad report, it
// is no report. These tests check the contract the host tools rely on.

func TestSARIFDocumentIsValid(t *testing.T) {
	var out strings.Builder
	err := WriteSARIF(&out, "1.2.3", []SARIFInput{{
		RuleID: "instruction-override", Level: "high",
		Message: "ignore all previous instructions", Artifact: "tools.json",
		Subject: "evil_tool", OWASP: "MCP03",
	}})
	if err != nil {
		t.Fatal(err)
	}

	var document map[string]any
	if err := json.Unmarshal([]byte(out.String()), &document); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if document["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", document["version"])
	}
	if document["$schema"] == nil {
		t.Error("no $schema: hosts validate against it")
	}

	runs := document["runs"].([]any)
	run := runs[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "slopscan" || driver["version"] != "1.2.3" {
		t.Errorf("driver = %v, want slopscan 1.2.3", driver)
	}

	rules := driver["rules"].([]any)
	rule := rules[0].(map[string]any)
	if rule["id"] != "instruction-override" {
		t.Errorf("rule id = %v", rule["id"])
	}
	tags := rule["properties"].(map[string]any)["tags"].([]any)
	found := false
	for _, tag := range tags {
		if tag == "owaspMCP03" {
			found = true
		}
	}
	if !found {
		t.Errorf("OWASP code not carried as a rule tag: %v", tags)
	}

	results := run["results"].([]any)
	result := results[0].(map[string]any)
	if result["level"] != "error" {
		t.Errorf("high severity mapped to %v, want error", result["level"])
	}
	message := result["message"].(map[string]any)["text"]
	if message != "ignore all previous instructions" {
		t.Errorf("the quote is the message, got %v", message)
	}
	location := result["locations"].([]any)[0].(map[string]any)
	artifact := location["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"]
	if artifact != "tools.json" {
		t.Errorf("artifact = %v", artifact)
	}
}

// Levels map high→error, medium→warning, low→note; security-severity buckets follow the host's
// ranking scheme. Neither is a computed score - the evidence is the quote.
func TestSARIFLevelMapping(t *testing.T) {
	for severity, want := range map[string]string{
		"high": "error", "medium": "warning", "low": "note", "": "note",
	} {
		if got := sarifLevel(severity); got != want {
			t.Errorf("sarifLevel(%q) = %q, want %q", severity, got, want)
		}
	}
	if securitySeverity("high") != "8.0" || securitySeverity("medium") != "5.5" {
		t.Errorf("severity buckets wrong: %s %s", securitySeverity("high"), securitySeverity("medium"))
	}
}

// One rule per kind, however many results carry it - a document with 50 results and 50 rules
// duplicates every description and no host renders it well.
func TestSARIFDeduplicatesRules(t *testing.T) {
	document := BuildSARIF("dev", []SARIFInput{
		{RuleID: "concealment", Level: "high", Message: "a", Artifact: "t.json", Subject: "x"},
		{RuleID: "concealment", Level: "high", Message: "b", Artifact: "t.json", Subject: "y"},
		{RuleID: "exfiltration", Level: "high", Message: "c", Artifact: "t.json", Subject: "x"},
	})
	rules := document.Runs[0].Tool.Driver.Rules
	if len(rules) != 2 {
		t.Errorf("got %d rules, want 2: %+v", len(rules), rules)
	}
	if len(document.Runs[0].Results) != 3 {
		t.Errorf("got %d results, want 3", len(document.Runs[0].Results))
	}
}

// Two scans of the same surface must produce the same document: alert platforms deduplicate on
// identity, and map iteration order would otherwise reshuffle results every run.
func TestSARIFIsDeterministicallyOrdered(t *testing.T) {
	inputs := []SARIFInput{
		{RuleID: "b-rule", Level: "high", Message: "m", Artifact: "t.json", Subject: "zebra"},
		{RuleID: "a-rule", Level: "high", Message: "m", Artifact: "t.json", Subject: "apple"},
		{RuleID: "a-rule", Level: "high", Message: "m", Artifact: "t.json", Subject: "apple"},
	}
	first, _ := json.Marshal(BuildSARIF("dev", inputs))
	reversed := []SARIFInput{inputs[2], inputs[1], inputs[0]}
	second, _ := json.Marshal(BuildSARIF("dev", reversed))
	if string(first) != string(second) {
		t.Errorf("document depends on input order:\n%s\n%s", first, second)
	}
}

// A rug pull is an alert: drift becomes results too, breaking ones louder than additions.
func TestSARIFCarriesDriftAsResults(t *testing.T) {
	inputs := SARIFInputsFromDrift("tools.json", drift.Report{
		Changes: []drift.Change{
			{Tool: "evil", Kind: "description-changed", Breaking: true, Detail: "the description grew"},
			{Tool: "new", Kind: "added", Breaking: false, Detail: "a new tool appeared"},
		},
	})
	if len(inputs) != 2 {
		t.Fatalf("got %d inputs, want 2", len(inputs))
	}
	if inputs[0].Level != "high" || inputs[0].RuleID != "drift/description-changed" {
		t.Errorf("breaking drift wrong: %+v", inputs[0])
	}
	if inputs[1].Level != "medium" {
		t.Errorf("addition should be medium: %+v", inputs[1])
	}
}

// The scan findings travel as results with the tool as the subject.
func TestSARIFInputsFromServerCarryEvidence(t *testing.T) {
	inputs := SARIFInputsFromServer("tools.json", Server{
		Findings: map[string][]injection.Finding{
			"tool_b": {{Where: "description", Kind: "concealment", OWASP: "MCP03", Severity: "high", Quote: "do not tell"}},
			"tool_a": {{Where: "description", Kind: "exfiltration", OWASP: "MCP01", Severity: "high", Quote: "send secrets"}},
		},
	})
	if len(inputs) != 2 {
		t.Fatalf("got %d inputs, want 2", len(inputs))
	}
	// Sorted by subject: tool_a first, regardless of map order.
	if inputs[0].Subject != "tool_a" || inputs[0].Message != "send secrets" {
		t.Errorf("first input = %+v, want tool_a's finding", inputs[0])
	}
}