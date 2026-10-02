// Package drift compares a tool surface against a pinned baseline and says what changed.
//
// This exists because of how tool definitions are trusted: an agent re-reads them every session and
// believes them again every time, so a server that behaved well at review can change its story
// later - the rug-pull, weaponised as a supply-chain attack (Deadbugz, August 2026) and also just
// ordinary breakage when a server redeploys without a version bump. One scan cannot see a change;
// only the difference between two scans can. That makes drift detection temporal by nature, which
// is why the baseline lives in the catalogue and every new scan is measured against it.
//
// The classification borrows the ecosystem's own rule of thumb: a tool that disappears or changes
// shape is a breaking change (code that depended on it silently breaks), while a new tool is not
// (nothing was relying on it yet). A changed description is called out separately, because that is
// the exact shape of the attack - the name stays, the words the model reads are rewritten.
package drift

import (
	"encoding/json"
	"sort"

	"github.com/Caseymccallum/slopscan/internal/risk"
)

// Change is one difference between a baseline and a current surface.
type Change struct {
	Tool string `json:"tool"`
	// Kind: added, removed, renamed, description-changed, schema-changed.
	Kind string `json:"kind"`
	// Breaking is true when existing callers would silently break or be misled.
	Breaking bool `json:"breaking"`
	// Detail is a human-readable account of what changed, for the report.
	Detail string `json:"detail"`
}

// Report is the full comparison of two surfaces.
type Report struct {
	// Unchanged is how many tools are byte-identical to the baseline.
	Unchanged int `json:"unchanged"`
	Changes   []Change `json:"changes"`
	// Score follows the community rubric: 100 unchanged, 90 non-breaking additions only,
	// 30 or below when something broke or changed shape.
	Score int `json:"score"`
	// Drifted is true when anything changed at all.
	Drifted bool `json:"drifted"`
	// Breaking is true when any change is breaking.
	Breaking bool `json:"breaking"`
}

// Compare measures `current` against `baseline`. Both are what the server said, at two times.
func Compare(baseline, current []risk.Tool) Report {
	before := index(baseline)
	after := index(current)

	report := Report{Score: 100}

	for name, oldTool := range before {
		newTool, stillThere := after[name]
		if !stillThere {
			report.Changes = append(report.Changes, Change{
				Tool: name, Kind: "removed", Breaking: true,
				Detail: "the tool is gone; anything that called it now fails or falls back",
			})
			continue
		}

		if oldTool.Description != newTool.Description {
			report.Changes = append(report.Changes, Change{
				Tool: name, Kind: "description-changed", Breaking: true,
				Detail: describeDescriptionChange(oldTool.Description, newTool.Description),
			})
		}
		if !sameSchema(oldTool.InputSchema, newTool.InputSchema) {
			report.Changes = append(report.Changes, Change{
				Tool: name, Kind: "schema-changed", Breaking: true,
				Detail: "the input schema changed shape; arguments built against the old one may no longer be accepted",
			})
		}
		if oldTool.Description == newTool.Description && sameSchema(oldTool.InputSchema, newTool.InputSchema) {
			report.Unchanged++
		}
	}

	for name := range after {
		if _, existed := before[name]; !existed {
			report.Changes = append(report.Changes, Change{
				Tool: name, Kind: "added", Breaking: false,
				Detail: "a new tool appeared that the baseline never saw; nothing reviewed it",
			})
		}
	}

	sort.Slice(report.Changes, func(i, j int) bool {
		return report.Changes[i].Tool < report.Changes[j].Tool
	})

	for _, change := range report.Changes {
		report.Drifted = true
		if change.Breaking {
			report.Breaking = true
			report.Score = 30
		} else if report.Score > 90 {
			report.Score = 90
		}
	}

	return report
}

// sameSchema compares two input schemas by their canonical JSON - key order is not a difference.
func sameSchema(a, b map[string]any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}

// index maps tool name to tool. Duplicate names keep the first, and the report says nothing was
// lost: a server listing one name twice is already malformed, and the first listing is what an
// agent would bind to.
func index(tools []risk.Tool) map[string]risk.Tool {
	byName := make(map[string]risk.Tool, len(tools))
	for _, tool := range tools {
		if _, seen := byName[tool.Name]; !seen {
			byName[tool.Name] = tool
		}
	}
	return byName
}

// describeDescriptionChange says what happened to a description in terms a person can act on.
// A longer description with new instructions is the attack shape, so growth is named as such.
func describeDescriptionChange(oldText, newText string) string {
	switch {
	case len(newText) > len(oldText):
		return "the description grew - new text in a tool description is instructions to the model, and nothing reviewed them"
	case len(newText) < len(oldText):
		return "the description shrank - information the reviewer saw is gone"
	default:
		return "the description was rewritten in place - same length of rope, different words for the model"
	}
}