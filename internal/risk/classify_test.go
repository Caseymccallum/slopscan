package risk

import "testing"

func tool(name, description string, properties ...string) Tool {
	schema := map[string]any{"properties": map[string]any{}}
	props := schema["properties"].(map[string]any)
	for _, property := range properties {
		props[property] = map[string]any{"type": "string"}
	}
	return Tool{Name: name, Description: description, InputSchema: schema}
}

func TestClassifyByWords(t *testing.T) {
	cases := []struct {
		tool     Tool
		category Category
	}{
		{tool("read_file", "Read the contents of a file"), Read},
		{tool("list_directory", "List entries in a directory"), Read},
		{tool("create_ticket", "Create a new issue"), Write},
		{tool("update_record", "Update an existing record"), Write},
		{tool("run_command", "Execute a shell command"), Execute},
		{tool("delete_row", "Delete a row from a table"), Destructive},
		{tool("drop_table", "Drop a database table"), Destructive},
		{tool("process_payment", "Charge a card on file"), Financial},
		{tool("emit_confetti", "Celebrate a milestone"), Other},
	}
	for _, c := range cases {
		if got := Classify(c.tool); got.Category != c.category {
			t.Errorf("%s: got %s, want %s", c.tool.Name, got.Category, c.category)
		}
	}
}

// A tool that both reads and deletes is classified by the deletion: the dangerous reading is the
// one that matters.
func TestPrecedencePrefersDanger(t *testing.T) {
	got := Classify(tool("delete_and_read", "Delete a record and read it back"))
	if got.Category != Destructive {
		t.Errorf("got %s, want %s", got.Category, Destructive)
	}
}

// "preload" is not "read", and "forcer" is not "force": verbs match as whole words.
func TestVerbsAreWholeWords(t *testing.T) {
	if got := Classify(tool("preload_cache", "Warm up the cache")); got.Category == Read {
		t.Errorf("preload misread as read: got %s", got.Category)
	}
}

// A tool whose words say nothing is escalated by its schema: a command input is an execution
// surface whatever the name claims.
func TestSchemaEscalates(t *testing.T) {
	got := Classify(tool("tidy_up", "Tidy things up", "command"))
	if got.Category != Execute {
		t.Errorf("got %s, want %s", got.Category, Execute)
	}
}

// A guard flag is recorded but never lowers the category: guards are optional by nature.
func TestGuardsAreNotDowngrades(t *testing.T) {
	got := Classify(tool("delete_file", "Delete a file", "confirm"))
	if got.Category != Destructive {
		t.Errorf("guard downgraded a deletion: got %s", got.Category)
	}
	found := false
	for _, reason := range got.Reasons {
		if reason == "a guard flag exists, but guards are optional by nature" {
			found = true
		}
	}
	if !found {
		t.Errorf("guard was not recorded in the reasons: %v", got.Reasons)
	}
}

// Every verdict names its evidence: a score with no reasons is a score nobody can argue with.
func TestEveryVerdictExplainsItself(t *testing.T) {
	for _, c := range []Tool{
		tool("read_file", "Read a file"),
		tool("delete_row", "Delete a row"),
		tool("mystery", ""),
	} {
		if got := Classify(c); len(got.Reasons) == 0 {
			t.Errorf("%s: verdict with no reasons", c.Name)
		}
	}
}