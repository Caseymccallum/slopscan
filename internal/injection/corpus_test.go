package injection

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The corpus is the rule set's reputation: real attack shapes with the findings they must produce,
// and ordinary tools that must produce nothing. A new rule is proved by adding an attack entry it
// catches; a rule that overreaches is caught by the clean guards. Both halves are load-bearing -
// a scanner that flags everything is as useless as one that flags nothing.
//
// Entries land here from anywhere: fixtures written during development, campaigns documented by
// researchers, and (the hope) misses reported by users. Each file names its source, because "why
// does this rule exist" should be answerable from the fixture alone.

type corpusTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type corpusFile struct {
	Source string       `json:"source"`
	Tool   *corpusTool  `json:"tool"`  // one attack-shaped tool
	Tools  []corpusTool `json:"tools"` // or a set of ordinary tools
	Expect []string     `json:"expect"`
}

func TestCorpus(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "corpus", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 3 {
		t.Fatalf("corpus has %d entries; expected the attack shapes and the clean guards", len(files))
	}

	for _, path := range files {
		path := path
		t.Run(strings.TrimSuffix(filepath.Base(path), ".json"), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var entry corpusFile
			if err := json.Unmarshal(raw, &entry); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			if entry.Source == "" {
				t.Errorf("%s: no source named; every fixture should say why it exists", path)
			}

			tools := entry.Tools
			if entry.Tool != nil {
				tools = append(tools, *entry.Tool)
			}
			if len(tools) == 0 {
				t.Fatalf("%s: no tools in the fixture", path)
			}

			kinds := map[string]bool{}
			for _, tool := range tools {
				for _, finding := range Scan(tool.Name, tool.Description) {
					kinds[finding.Kind] = true
				}
			}

			if len(entry.Expect) == 0 {
				if len(kinds) > 0 {
					t.Errorf("clean fixture was flagged: %v", kinds)
				}
				return
			}
			for _, want := range entry.Expect {
				if !kinds[want] {
					t.Errorf("expected %q to be found, got %v", want, kinds)
				}
			}
		})
	}
}