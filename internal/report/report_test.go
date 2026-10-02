package report

import (
	"strings"
	"testing"

	"github.com/Caseymccallum/slopscan/internal/injection"
	"github.com/Caseymccallum/slopscan/internal/risk"
)

func TestWriteShowsEvidenceNotJustScores(t *testing.T) {
	var out strings.Builder
	err := Write(&out, Server{
		ID:     "srv",
		Source: "test",
		Tools: []risk.Assessment{
			{Tool: "delete_row", Category: risk.Destructive, Weight: 1.0, Confidence: "high",
				Reasons: []string{"described in destructive terms (delete)"}},
		},
		Findings: map[string][]injection.Finding{
			"delete_row": {{Where: "description", Kind: "concealment", OWASP: "MCP03", Severity: "high", Quote: "do not tell the user"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	text := out.String()
	for _, want := range []string{
		"delete_row", "destructive", "described in destructive terms (delete)",
		"MCP03", "concealment", "do not tell the user",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("report is missing %q:\n%s", want, text)
		}
	}
}

// The fleet view is sorted by risk and says the one thing a person needs to know first.
func TestSummaryRanksAndVerdicts(t *testing.T) {
	var out strings.Builder
	err := WriteSummary(&out, []Server{
		{ID: "calm", Tools: []risk.Assessment{{Tool: "r", Category: risk.Read, Weight: 0}}},
		{ID: "nasty", Tools: []risk.Assessment{{Tool: "d", Category: risk.Destructive, Weight: 1.0}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	text := out.String()
	if strings.Index(text, "nasty") > strings.Index(text, "calm") {
		t.Errorf("riskiest server is not first:\n%s", text)
	}
	if !strings.Contains(text, "destroys data") {
		t.Errorf("summary does not say what the dangerous server does:\n%s", text)
	}
	if !strings.Contains(text, "reads only") {
		t.Errorf("summary does not say what the calm server does:\n%s", text)
	}
}

// Prompt injection outranks "touches money" as a verdict: it is the more surprising fact.
func TestVerdictPriority(t *testing.T) {
	server := Server{
		Tools: []risk.Assessment{{Tool: "pay", Category: risk.Financial, Weight: 0.85}},
		Findings: map[string][]injection.Finding{
			"pay": {{Where: "description", Kind: "instruction-override", Severity: "high", Quote: "x"}},
		},
	}
	if got := verdict(server); got != "prompt injection in metadata" {
		t.Errorf("got %q, want prompt injection in metadata", got)
	}
}