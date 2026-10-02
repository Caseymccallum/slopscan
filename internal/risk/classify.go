// Package risk classifies MCP tools by what they can actually do.
//
// The classification is deliberately explainable: every verdict carries the reasons that produced
// it, because a score nobody can question is a score nobody should trust. The scheme follows the
// six categories the ecosystem's own audits use - read, write, execute, destructive, financial,
// other - so a verdict here can be compared against them.
//
// Two signals are combined: the tool's own words (name and description) and the shape of its input
// schema. Either alone lies sometimes - "update" is safe or not depending on its parameters, and a
// description is marketing - but together they give a verdict that can be defended line by line.
package risk

import "strings"

// Category is what a tool can do to the systems behind it.
type Category string

const (
	Read        Category = "read"
	Write       Category = "write"
	Execute     Category = "execute"
	Destructive Category = "destructive"
	Financial   Category = "financial"
	Other       Category = "other"
	// Context is what a prompt or resource does: it enters the model's context. It cannot act
	// on the systems behind it, so its weight is zero - the risk it carries is the text itself,
	// and the findings report that. This is the honest category for the surfaces no classifier
	// can classify: their danger is not capability.
	Context Category = "context"
)

func (c Category) String() string { return string(c) }

// Weight is the risk weight of a category on the scale the ecosystem's audits use: 0.0 for
// read-only, 1.0 for destructive. Context weighs nothing because it can do nothing - by itself.
func (c Category) Weight() float64 {
	switch c {
	case Read:
		return 0.0
	case Context:
		return 0.0
	case Write:
		return 0.35
	case Other:
		return 0.3
	case Execute:
		return 0.7
	case Financial:
		return 0.85
	case Destructive:
		return 1.0
	}
	return 0.3
}

// Precedence, most dangerous first: a tool that deletes AND reads is classified by the deletion.
var precedence = []Category{Destructive, Financial, Execute, Write, Read}

// The verbs of each category. Matched as whole words against name and description, so "preload"
// does not read and "forcer" does not force.
var verbs = map[Category][]string{
	Destructive: {
		"delete", "drop", "destroy", "purge", "wipe", "remove", "erase", "truncate",
		"force-push", "force push", "force_delete", "kill", "terminate", "shred", "unlink",
		"rmdir", "rm", "revoke", "deprovision", "reset",
	},
	Financial: {
		"charge", "payment", "pay", "refund", "transfer", "withdraw", "purchase", "buy",
		"subscribe", "billing", "invoice", "payout", "order", "trade", "sell", "checkout",
		"transaction", "fund",
	},
	Execute: {
		"exec", "execute", "shell", "command", "run", "spawn", "eval", "bash", "powershell",
		"script", "compile", "deploy", "publish", "invoke", "call_tool", "sql",
	},
	Write: {
		"create", "write", "update", "set", "insert", "add", "put", "post", "patch", "edit",
		"modify", "append", "upload", "move", "rename", "copy", "send", "store", "save",
		"configure", "apply", "merge", "commit", "assign", "schedule", "register",
	},
	Read: {
		"read", "get", "list", "fetch", "search", "query", "find", "show", "describe",
		"download", "view", "check", "lookup", "stat", "grep", "tail", "export",
		"diff", "compare", "monitor", "watch",
	},
}

// Input-schema properties that speak to what a tool does, whatever its words claim.
var schemaSignals = map[string]string{
	"force":       "input schema accepts a force flag",
	"confirm":     "input schema accepts a confirm flag (a guard)",
	"dry_run":     "input schema accepts a dry_run flag (a guard)",
	"recursive":   "input schema accepts a recursive flag",
	"command":     "input schema takes a raw command string",
	"cmd":         "input schema takes a raw command string",
	"shell":       "input schema takes a raw shell string",
	"sql":         "input schema takes raw SQL",
	"script":      "input schema takes a script body",
	"expression":  "input schema takes an expression to evaluate",
	"path":        "input schema takes a filesystem path",
	"file_path":   "input schema takes a filesystem path",
	"table":       "input schema names a database table",
	"account":     "input schema names a financial account",
	"amount":      "input schema takes a monetary amount",
	"card":        "input schema takes card details",
	"destination": "input schema names a destination to write to",
	"url":         "input schema takes a URL to act on",
}

// schemaEscalates are properties that make a tool an execution surface whatever it calls itself.
var schemaEscalates = map[string]bool{
	"command": true, "cmd": true, "shell": true, "sql": true, "script": true, "expression": true,
}

// guardedFlags are properties that let a caller ask first. They note a guard; they never lower the
// category, because a guard is optional by nature.
var guardedFlags = map[string]bool{"confirm": true, "dry_run": true}

// Assessment is one tool's verdict, with the evidence that produced it.
type Assessment struct {
	Tool       string   `json:"tool"`
	Category   Category `json:"category"`
	Weight     float64  `json:"weight"`
	Reasons    []string `json:"reasons"`
	Confidence string   `json:"confidence"` // high, medium, low
}

// Tool is what the scanner needs to know about an MCP tool.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	// Surface is which listing the entry came from: "" for tools (the default, everywhere
	// tools exist), "prompt" and "resource" for the other metadata surfaces a server offers.
	// All three carry names and descriptions that reach the model; only one is callable.
	Surface string `json:"surface,omitempty"`
	// URI is where a resource lives (or its template) - its address is part of its identity,
	// and a changed address is a changed surface even when the words stay put.
	URI string `json:"uri,omitempty"`
}

// OfSurface is the assessment for an entry no capability classifier can classify: a prompt or a
// resource's danger is the text it carries, not what it does - so it is Context, weight zero,
// with its surface named and the text assessed by the injection scan like everything else.
func OfSurface(tool Tool) Assessment {
	kind := tool.Surface
	if kind == "" {
		kind = "entry"
	}
	return Assessment{
		Tool:       tool.Name,
		Category:   Context,
		Weight:     0,
		Reasons:    []string{"a " + kind + " enters the model's context; its risk is its text, which the findings report"},
		Confidence: "high",
	}
}

// Classify decides one tool's category and explains why.
//
// The words give the category; the schema can only escalate it and name guards. A tool called
// "tidy_up" with a `command` parameter is treated as what its schema reveals, and a tool that calls
// itself "delete_everything (irreversible)" is not downgraded by a friendly description.
func Classify(tool Tool) Assessment {
	text := strings.ToLower(tool.Name + " " + tool.Description)
	reasons := []string{}

	category := Other
	matched := false
	for _, candidate := range precedence {
		for _, verb := range verbs[candidate] {
			if !hasWord(text, verb) {
				continue
			}
			category = candidate
			reasons = append(reasons, "described in "+candidate.String()+" terms ("+verb+")")
			matched = true
			break
		}
		if matched {
			break
		}
	}

	guarded := false
	for _, property := range schemaProperties(tool.InputSchema) {
		signal, known := schemaSignals[property]
		if !known {
			continue
		}
		reasons = append(reasons, signal)
		if guardedFlags[property] {
			guarded = true
		}
		if !matched && schemaEscalates[property] {
			category = Execute
			matched = true
		}
	}

	if guarded {
		reasons = append(reasons, "a guard flag exists, but guards are optional by nature")
	}

	confidence := "medium"
	switch {
	case len(reasons) == 0:
		confidence = "low"
		reasons = append(reasons, "nothing in its name, description or schema says what it does")
	case matched && len(reasons) > 1:
		confidence = "high"
	}

	return Assessment{
		Tool:       tool.Name,
		Category:   category,
		Weight:     category.Weight(),
		Reasons:    reasons,
		Confidence: confidence,
	}
}

// hasWord matches a verb as a whole word, so "preload" is not "read". Compound verbs (with a dash,
// space or underscore) match as substrings, because they only ever appear whole.
func hasWord(text, verb string) bool {
	if strings.ContainsAny(verb, "-_ ") {
		return strings.Contains(text, verb)
	}
	for _, word := range strings.FieldsFunc(text, func(r rune) bool {
		return r < 'a' || r > 'z'
	}) {
		if word == verb {
			return true
		}
	}
	return false
}

// schemaProperties lists the property names of a tool's input schema, lowercased.
func schemaProperties(schema map[string]any) []string {
	if schema == nil {
		return nil
	}
	raw, ok := schema["properties"].(map[string]any)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(raw))
	for name := range raw {
		names = append(names, strings.ToLower(name))
	}
	return names
}