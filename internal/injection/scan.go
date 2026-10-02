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
	// The OWASP MCP Top 10 risk this finding belongs to (MCP01-MCP10), so it can be compared
	// with findings from other tools and audits in the field's shared vocabulary.
	OWASP string `json:"owasp"`
	// The matched text itself, trimmed to the sentence around it.
	Quote string `json:"quote"`
	// Severity: high for instruction-steering, medium for concealment, low for oddities.
	Severity string `json:"severity"`
}

// One detection rule: what it is called, how bad it is, what OWASP MCP risk it names, and what it
// matches. The OWASP code is the vocabulary the whole MCP-security field compares findings in.
type rule struct {
	kind     string
	severity string
	owasp    string
	pattern  *regexp.Regexp
}

// The rules, ordered by severity. These are the documented patterns of prompt injection in tool
// metadata - instruction override, concealment, exfiltration, and role confusion - plus the shapes
// 2026's supply-chain campaigns actually used (Deadbugz: credential-harvest instructions gated
// behind a call counter). Kept as text here so each one is reviewable rather than clever.
var rules = []rule{
	{
		kind:     "instruction-override",
		severity: "high",
		owasp:    "MCP03",
		pattern: regexp.MustCompile(`(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier|your)\s+` +
			`(instructions?|prompts?|rules?|guidelines?|system)`),
	},
	{
		kind:     "instruction-override",
		severity: "high",
		owasp:    "MCP03",
		pattern:  regexp.MustCompile(`(?i)you\s+must\s+(now\s+)?(always|never)\b`),
	},
	{
		kind:     "concealment",
		severity: "high",
		owasp:    "MCP03",
		pattern:  regexp.MustCompile(`(?i)(do\s+not|don't|never|without)\s+(tell|inform|mention|show|reveal|disclose)\b.{0,40}\b(user|human|operator|anyone)`),
	},
	{
		kind:     "concealment",
		severity: "medium",
		owasp:    "MCP03",
		pattern:  regexp.MustCompile(`(?i)(keep|this|it)\s+(is\s+)?(a\s+)?secret|hidden\s+from\s+the\s+user|without\s+asking`),
	},
	{
		kind:     "exfiltration",
		severity: "high",
		owasp:    "MCP01",
		pattern:  regexp.MustCompile(`(?i)(send|post|upload|forward|exfiltrate|transmit)\b.{0,60}\b(token|secret|credential|password|key|env|environment)\b`),
	},
	{
		// The Deadbugz payload, in the campaign's own shape: not "send us the secrets" but
		// "search for SSH keys, cloud credentials, shell history" - instructions to hunt for
		// secrets, which reads as diligence in a tool description and is anything but.
		kind:     "credential-harvest",
		severity: "high",
		owasp:    "MCP01",
		pattern: regexp.MustCompile(`(?i)(search|look|scan|check|read|collect|gather|harvest|grab|enumerate)\b.{0,50}\b` +
			`(ssh\s*keys?|\.ssh|id_rsa|id_ed25519|cloud\s*credentials?|shell\s*history|\.bash_history|\.zsh_history|` +
			`aws\s*credentials|\.aws\b|\.env\b|private\s*keys?|wallet|keystore|browser\s*(passwords?|cookies?))`),
	},
	{
		// The Deadbugz trigger: behaviour gated on how many times a tool has been called. No
		// legitimate tool description counts the caller's calls. The clause after the count is the
		// payload verb ("start including", "search for", "then send"), so the rule waits for both.
		kind:     "runtime-gating",
		severity: "high",
		owasp:    "MCP03",
		pattern: regexp.MustCompile(`(?i)(after|on|once|following)\s+(the\s+)?(first|second|third|fourth|fifth|\d+|several|multiple|repeated)?\s*` +
			`(call|invocation|use|run|request)s?\b.{0,60}(then|start|begin|switch|activate|enable|change|search|look|include|send|forward|read|check|gather|collect)`),
	},
	{
		// Tool shadowing: a description claiming authority over another tool ("this replaces X",
		// "instead of using Y") - the metadata version of impersonating a colleague.
		kind:     "tool-shadowing",
		severity: "high",
		owasp:    "MCP03",
		pattern: regexp.MustCompile(`(?i)(instead\s+of|rather\s+than|replaces?|overrides?|supersedes?|takes?\s+precedence)\b.{0,40}\b` +
			`(the\s+)?(other\s+)?tool|call\s+me\s+(directly|instead)|always\s+prefer\s+this`),
	},
	{
		kind:     "role-confusion",
		severity: "medium",
		owasp:    "MCP06",
		pattern:  regexp.MustCompile(`(?i)(you\s+are\s+(now|a)\s+(an?\s+)?(admin|root|system)|act\s+as\s+(the\s+)?(system|developer|admin)|pretend\s+to\s+be)`),
	},
	{
		kind:     "tool-bypass",
		severity: "high",
		owasp:    "MCP02",
		pattern:  regexp.MustCompile(`(?i)(bypass|skip|disable|circumvent|override)\b.{0,40}\b(policy|polic|approval|permission|security|check|audit|confirmation)`),
	},
	{
		kind:     "trigger-phrase",
		severity: "medium",
		owasp:    "MCP06",
		pattern:  regexp.MustCompile(`(?i)(when\s+asked\s+about|if\s+(the\s+)?user\s+asks).{0,80}(always|instead|rather\s+than|do\s+not)`),
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
					OWASP:    rule.owasp,
					Quote:    quoteAround(text.body, match),
					Severity: rule.severity,
				})
			}
		}
		if hits := invisible.FindAllString(text.body, -1); len(hits) > 0 {
			findings = append(findings, Finding{
				Where: text.where,
				Kind:  "invisible-characters",
				OWASP: "MCP03",
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