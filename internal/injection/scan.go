// Package injection finds instructions aimed at the model inside MCP tool metadata.
//
// A tool description is supposed to be read by a person. But the model reads it too - which makes
// every description a prompt. When one of them starts telling the model what to do ("ignore previous
// instructions", "do not tell the user", "always call this tool first"), it has stopped being
// documentation and become an attack. This package flags those texts, with the matched words shown,
// so a human can read the evidence rather than a verdict.
package injection

import (
	"regexp"
	"strconv"
	"strings"
)

// Finding is one suspicious passage, quoted so it can be read.
type Finding struct {
	// Where the passage was found: tool name or description.
	Where string `json:"where"`
	// The category of the pattern that matched.
	Kind string `json:"kind"`
	// The matched text itself, trimmed to the sentence around it.
	Quote string `json:"quote"`
	// Severity: high for instruction-steering, medium for concealment, low for oddities.
	Severity string `json:"severity"`
}

// One detection rule: what it is called, how bad it is, and what it matches.
type rule struct {
	kind     string
	severity string
	pattern  *regexp.Regexp
}

// The rules, ordered by severity. These are the documented patterns of prompt injection in tool
// metadata - instruction override, concealment, exfiltration, and role confusion - kept as text
// here so each one is reviewable rather than clever.
var rules = []rule{
	{
		kind:     "instruction-override",
		severity: "high",
		pattern: regexp.MustCompile(`(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier|your)\s+` +
			`(instructions?|prompts?|rules?|guidelines?|system)`),
	},
	{
		kind:     "instruction-override",
		severity: "high",
		pattern: regexp.MustCompile(`(?i)you\s+must\s+(now\s+)?(always|never)\b`),
	},
	{
		kind:     "concealment",
		severity: "high",
		pattern: regexp.MustCompile(`(?i)(do\s+not|don't|never|without)\s+(tell|inform|mention|show|reveal|disclose)\b.{0,40}\b(user|human|operator|anyone)`),
	},
	{
		kind:     "concealment",
		severity: "medium",
		pattern: regexp.MustCompile(`(?i)(keep|this|it)\s+(is\s+)?(a\s+)?secret|hidden\s+from\s+the\s+user|without\s+asking`),
	},
	{
		kind:     "exfiltration",
		severity: "high",
		pattern: regexp.MustCompile(`(?i)(send|post|upload|forward|exfiltrate|transmit)\b.{0,60}\b(token|secret|credential|password|key|env|environment)\b`),
	},
	{
		kind:     "role-confusion",
		severity: "medium",
		pattern: regexp.MustCompile(`(?i)(you\s+are\s+(now|a)\s+(an?\s+)?(admin|root|system)|act\s+as\s+(the\s+)?(system|developer|admin)|pretend\s+to\s+be)`),
	},
	{
		kind:     "tool-bypass",
		severity: "high",
		pattern: regexp.MustCompile(`(?i)(bypass|skip|disable|circumvent|override)\b.{0,40}\b(policy|polic|approval|permission|security|check|audit|confirmation)`),
	},
	{
		kind:     "trigger-phrase",
		severity: "medium",
		pattern: regexp.MustCompile(`(?i)(when\s+asked\s+about|if\s+(the\s+)?user\s+asks).{0,80}(always|instead|rather\s+than|do\s+not)`),
	},
}

// invisible is the zero-width and bidirectional-override characters that hide text from a human
// reviewer while a model still reads it. Their mere presence in a description is worth a flag.
var invisible = regexp.MustCompile(`[\x{200B}\x{200C}\x{200D}\x{2060}\x{2066}\x{2067}\x{2068}\x{2069}\x{FEFF}\x{202A}\x{202B}\x{202C}\x{202D}\x{202E}]`)

// Scan looks at one tool's name and description and quotes anything addressed to the model.
func Scan(name, description string) []Finding {
	findings := []Finding{}

	for _, text := range []struct {
		where string
		body  string
	}{{"name", name}, {"description", description}} {
		for _, rule := range rules {
			if match := rule.pattern.FindString(text.body); match != "" {
				findings = append(findings, Finding{
					Where:    text.where,
					Kind:     rule.kind,
					Quote:    quoteAround(text.body, match),
					Severity: rule.severity,
				})
			}
		}
		if hits := invisible.FindAllString(text.body, -1); len(hits) > 0 {
			findings = append(findings, Finding{
				Where: text.where,
				Kind:  "invisible-characters",
				Quote: "contains zero-width or bidirectional-override characters (count: " +
					strconv.Itoa(len(hits)) + ")",
				Severity: "medium",
			})
		}
	}

	return findings
}

// quoteAround trims to the matched text plus a little context, so the quote is readable evidence.
func quoteAround(body, match string) string {
	index := strings.Index(body, match)
	if index < 0 {
		return match
	}
	start := index - 40
	if start < 0 {
		start = 0
	}
	end := index + len(match) + 40
	if end > len(body) {
		end = len(body)
	}
	return strings.TrimSpace(body[start:end])
}

// Worst returns the highest severity among findings, or "" when there are none.
func Worst(findings []Finding) string {
	rank := map[string]int{"": 0, "low": 1, "medium": 2, "high": 3}
	worst := ""
	for _, finding := range findings {
		if rank[finding.Severity] > rank[worst] {
			worst = finding.Severity
		}
	}
	return worst
}