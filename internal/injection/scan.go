// Package injection finds instructions aimed at the model inside MCP tool metadata.
//
// A tool description is supposed to be read by a person. But the model reads it too - which makes
// every description a prompt. When one of them starts telling the model what to do ("ignore previous
// instructions", "do not tell the user", "always call this tool first"), it has stopped being
// documentation and become an attack. This package flags those texts, with the matched words shown,
// so a human can read the evidence rather than a verdict.
package injection

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Finding is one suspicious passage, quoted so it can be read.
type Finding struct {
	// Where the passage was found: tool name, description, or input schema.
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
		pattern:  regexp.MustCompile(`(?i)(send|post|upload|forward|exfiltrate|transmit)\b.{0,60}\b(tokens?|secrets?|credentials?|passwords?|keys?|env|environment)\b`),
	},
	{
		// The Deadbugz payload, in the campaign's own shape: not "send us the secrets" but
		// "search for SSH keys, cloud credentials, shell history" - instructions to hunt for
		// secrets, which reads as diligence in a tool description and is anything but.
		kind:     "credential-harvest",
		severity: "high",
		owasp:    "MCP01",
		pattern: regexp.MustCompile(`(?i)\b(search|look|scan|check|read|collect|gather|harvest|grab|enumerate)\w*\b.{0,50}\b` +
			`(ssh\s*keys?|\.ssh|id_rsa|id_ed25519|cloud\s*credentials?|shell\s*history|\.bash_history|\.zsh_history|` +
			`aws\s*credentials|\.aws\b|\.env\b|private\s*keys?|wallet|keystore|browser\s*(passwords?|cookies?))`),
	},
	{
		// The Deadbugz trigger: behaviour gated on how many times a tool has been called. No
		// legitimate tool description counts the caller's calls. The clause after the count is the
		// payload verb ("start including", "search for", "then send"), so the rule waits for both -
		// and the verb needs a word boundary before it, or "already" reads as "read".
		kind:     "runtime-gating",
		severity: "high",
		owasp:    "MCP03",
		pattern: regexp.MustCompile(`(?i)\b(after|on|once|following)\s+(?:the\s+|a\s+|your\s+)?` +
			`(?:first|second|third|fourth|fifth|\d+|several|multiple|repeated|few|initial|subsequent)?\s*` +
			`(call|invocation|use|run|request)s?\b.{0,60}\b(then|start|begin|switch|activate|enable|change|search|look|include|send|forward|read|check|gather|collect)`),
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
	{
		// Prompt overwrite: a description presenting itself AS the system's own instructions -
		// "this is the system prompt", "master instructions:". On the prompts surface this is
		// the attack's whole shape: the entry a client loads into the model's context claiming
		// to be the authority above every other instruction. MCP10 - context injection - is
		// what this is, wherever it is found.
		kind:     "prompt-overwrite",
		severity: "high",
		owasp:    "MCP10",
		pattern: regexp.MustCompile(`(?i)(this|it)\s+is\s+the\s+(system|master|official)\s+(prompt|instructions?|persona)|` +
			`^(system|master)\s+(prompt|instructions?)\s*[:\-]|^(you\s+are\s+the\s+assistant|act\s+as\s+the\s+system)\b`),
	},
}

// invisible is the zero-width and bidirectional-override characters that hide text from a human
// reviewer while a model still reads it. Their mere presence in a description is worth a flag.
var invisible = regexp.MustCompile(`[\x{200B}\x{200C}\x{200D}\x{2060}\x{2066}\x{2067}\x{2068}\x{2069}\x{FEFF}\x{202A}\x{202B}\x{202C}\x{202D}\x{202E}]`)

// The write-sink rule is structural rather than textual: it needs the input schema to see that a
// caller controls a file path, and the description to see that nothing bounds the write. This is
// the metadata-level shape of 2026's path-traversal CVEs (CVE-2026-27825 and its three siblings):
// a file path built from caller-controlled input, written without a directory-boundary check.
// Scanners historically test the read side - "can it leak /etc/passwd" - and miss the write side,
// where the blast radius actually lives. Every real exploit this year landed there.

// pathParamNames are schema property names that hand a caller a filesystem location.
var pathParamNames = map[string]bool{
	"path": true, "file_path": true, "filepath": true, "file": true, "filename": true,
	"file_name": true, "destination": true, "dest": true, "dest_path": true, "target": true,
	"target_path": true, "output": true, "output_path": true, "save_path": true, "write_path": true,
	"save_to": true, "location": true, "dir": true, "directory": true, "folder": true,
}

// materializeVerbs are words saying the tool puts content somewhere on disk - the write half of
// the traversal class. "written" is included because descriptions say "written to".
var materializeVerbs = regexp.MustCompile(`(?i)\b(writes?|written|saving|saves?|storing|stores?|` +
	`created|creates?|copies|copying|moves?|moving|uploads?|uploading|downloads?|downloading|` +
	`exports?|exporting|dumps?|persists?|appends?|attachments?)\b`)

// boundaryWords are the contract saying where a write may go. Their presence is the fix the CVE
// write-ups ask for - a stated directory boundary - so a tool that states one is not flagged.
var boundaryWords = regexp.MustCompile(`(?i)\b(within|confined to|restricted to|limited to|inside|` +
	`relative to|beneath|underneath)\b|\b(workspace|sandbox|base|root|allowed|configured|chosen|` +
	`upload|output|destination|target)\s+(directory|dir|folder|path|location|root)|` +
	`\b(directory|dir|folder|path|location)\s+(only|must|may not|cannot|is rejected|is refused)|` +
	`\boutside\b.{0,30}\b(reject|refuse|denied|error|fail|not allowed)`)

// ScanTool is Scan plus the checks that need the input schema. Anything assessing a real tool
// definition should call this one; Scan stays for callers that only have text.
func ScanTool(name, description string, schema map[string]any) []Finding {
	return append(Scan(name, description), scanWritePath(name, description, schema)...)
}

// scanWritePath flags a caller-controlled path that the description never bounds: a materializing
// verb, a path-shaped parameter, and no stated boundary. All three must hold, so a plain read_file
// is quiet and a write tool that names its directory is quiet - only the unbounded write sinks of
// the 2026 CVEs are flagged, at medium: the metadata cannot prove the server skips validation,
// only that the contract never promised it. That is worth a reviewer's minute, not a verdict.
func scanWritePath(name, description string, schema map[string]any) []Finding {
	paths := pathParams(schema)
	if len(paths) == 0 {
		return nil
	}
	// Underscores are word characters, so "download" has no boundary inside download_attachment.
	// Naming a tool in snake_case must not hide its verbs from the verb check.
	text := strings.ReplaceAll(name+" "+description, "_", " ")
	if !materializeVerbs.MatchString(text) {
		return nil
	}
	// The boundary may be stated in the description or in the schema's own property text; both are
	// the contract, and either one is the fix.
	if boundaryWords.MatchString(description) || boundaryWords.MatchString(schemaText(schema)) {
		return nil
	}
	return []Finding{{
		Where:    "inputSchema",
		Kind:     "unchecked-path-write",
		OWASP:    "MCP02",
		Quote: "writes to a caller-controlled path (" + strings.Join(paths, ", ") +
			") and the description never says where the write may go",
		Severity: "medium",
	}}
}

// pathParams lists the schema property names that take a filesystem location, in schema order.
func pathParams(schema map[string]any) []string {
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		return nil
	}
	found := []string{}
	for name := range properties {
		if pathParamNames[strings.ToLower(name)] {
			found = append(found, name)
		}
	}
	sort.Strings(found)
	return found
}

// schemaText renders the schema as text so property descriptions can be read for boundary words.
func schemaText(schema map[string]any) string {
	raw, err := json.Marshal(schema)
	if err != nil {
		return ""
	}
	return string(raw)
}

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