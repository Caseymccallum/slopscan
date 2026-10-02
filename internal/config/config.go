// Package config reads the MCP server configurations that agents actually load - the mcpServers
// blocks of Claude Desktop, Cursor, Windsurf and VS Code - and checks what each entry launches
// before it launches.
//
// This is the input format everyone uses and most scanners ignore: their parsers model a bespoke
// serverUrl/transport schema nobody writes, so a real config parses to an empty object and the
// report says nothing true. Worse, rules written for network servers then fire at local ones -
// a stdio entry flagged as NO_AUTH, which is noise that hides the risks stdio actually carries:
// what the launch line runs, what it fetches unpinned, what secrets sit in its env, and what of
// the filesystem it hands over.
//
// The scoping is therefore deliberate: a stdio entry is checked for launch-line risk and no
// transport rule is ever applied to it (a local process has no transport to fail); a remote entry
// is checked for transport risk and its tool list is left to `scan` and `probe`. Each report says
// what was evaluated and what was not, because a scanner that quietly skips half the surface is
// worse than one that admits the gap.
package config

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Caseymccallum/slopscan/internal/registry"
)

// Entry is one server as the client configuration declares it: what will be launched, and with what.
type Entry struct {
	// Name is the key the agent will call the server by.
	Name string `json:"name"`
	// Type is stdio (a local process), http or sse (a remote endpoint), or unknown.
	Type string `json:"type"`
	// Command and Args are the launch line, for stdio entries.
	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
	// Env is the environment the entry sets - where plaintext secrets hide.
	Env map[string]string `json:"env,omitempty"`
	// URL is the endpoint, for remote entries.
	URL string `json:"url,omitempty"`
	// Headers are the request headers a remote entry sends - where its credentials live.
	Headers map[string]string `json:"headers,omitempty"`
}

// Finding is one risk in a config entry, quoted so it can be read - same shape as an injection
// finding, so the two reports are one report to whatever reads them.
type Finding struct {
	Where    string `json:"where"` // command, args, env.NAME, url
	Kind     string `json:"kind"`
	OWASP    string `json:"owasp"`
	Quote    string `json:"quote"` // never a secret value: names and shapes only
	Severity string `json:"severity"`
}

// EntryReport is one entry with what was found and what was evaluated.
type EntryReport struct {
	Entry    Entry     `json:"entry"`
	Findings []Finding `json:"findings"`
	Notes    []string  `json:"notes"`
}

// Load reads a client configuration file - JSON or YAML, both shapes the ecosystem writes.
func Load(path string, raw []byte) ([]Entry, error) {
	parsed, err := parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(parsed) == 0 {
		return nil, fmt.Errorf("%s: no \"mcpServers\" or \"servers\" block found - "+
			"this does not look like an MCP client configuration (Claude Desktop, Cursor, "+
			"Windsurf or VS Code shape)", path)
	}
	sort.Slice(parsed, func(i, j int) bool { return parsed[i].Name < parsed[j].Name })
	return parsed, nil
}

// parse understands the two shapes the ecosystem writes: {"mcpServers": {...}} (Claude Desktop,
// Cursor, Windsurf) and {"servers": {...}} (VS Code, which also names a type). JSON is decoded
// first with JSON semantics; YAML is the fallback for .yaml configs.
func parse(raw []byte) ([]Entry, error) {
	file := struct {
		MCPServers map[string]entrySpec `json:"mcpServers" yaml:"mcpServers"`
		Servers    map[string]entrySpec `json:"servers" yaml:"servers"`
	}{}
	if err := json.Unmarshal(raw, &file); err != nil {
		if yamlErr := yaml.Unmarshal(raw, &file); yamlErr != nil {
			return nil, fmt.Errorf("neither JSON nor YAML: %v", err)
		}
	}

	entries := []Entry{}
	for _, named := range []map[string]entrySpec{file.MCPServers, file.Servers} {
		for name, spec := range named {
			entry := Entry{
				Name:    name,
				Command: spec.Command,
				Env:     stringify(spec.Env),
				URL:     spec.URL,
				Headers: stringify(spec.Headers),
			}
			for _, arg := range spec.Args {
				entry.Args = append(entry.Args, fmt.Sprint(arg))
			}
			entry.Type = spec.Type
			switch {
			case entry.Command != "":
				entry.Type = "stdio"
			case entry.URL != "":
				if entry.Type == "" {
					entry.Type = "http"
				}
			case entry.Type == "":
				entry.Type = "unknown"
			}
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// entrySpec is one configuration entry in the wild: args and env values may be non-strings (JSON
// numbers, booleans), and a parser that fails on that reports nothing - so everything is taken as
// any and stringified.
type entrySpec struct {
	Type    string         `json:"type" yaml:"type"`
	Command string         `json:"command" yaml:"command"`
	Args    []any          `json:"args" yaml:"args"`
	Env     map[string]any `json:"env" yaml:"env"`
	URL     string         `json:"url" yaml:"url"`
	Headers map[string]any `json:"headers" yaml:"headers"`
}

func stringify(values map[string]any) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := map[string]string{}
	for key, value := range values {
		out[key] = fmt.Sprint(value)
	}
	return out
}

// Check examines one entry and quotes what it finds. Every check maps to the OWASP MCP Top 10 by
// what class of risk it is, not by where it was found.
func Check(entry Entry) []Finding {
	findings := []Finding{}
	findings = append(findings, checkLaunchExecution(entry)...)
	findings = append(findings, checkUnpinnedPackage(entry)...)
	findings = append(findings, checkBroadMount(entry)...)
	findings = append(findings, checkSecrets(entry)...)
	findings = append(findings, checkInsecureTransport(entry)...)
	return findings
}

// Notes says what was evaluated for this entry and what was deliberately not - the scoping honesty
// that a misleading report is worse than a quiet one.
func Notes(entry Entry) []string {
	if entry.Type == "stdio" {
		return []string{
			"evaluated: the launch line (command, args, env). Not evaluated: transport rules - " +
				"a local process has no transport to fail, and NO_AUTH on a stdio entry is noise.",
		}
	}
	return []string{
		"evaluated: the endpoint's transport. Not evaluated here: the tool list - `--probe` " +
			"fetches it over MCP (streamable HTTP or HTTP+SSE).",
	}
}

// launchExecution is the RCE shape of the launch line: a download piped into an interpreter, or a
// shell running a download. (CVE-2026-27825 reached RCE exactly this way - through a chain that
// started with "just fetch the attachment".)
var launchExecution = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(curl|wget|certutil|iwr|invoke-webrequest|bitsadmin)\b.{0,200}\|` +
		`\s*(sh|bash|zsh|dash|powershell|pwsh|cmd|python\w*|node)\b`),
	regexp.MustCompile(`(?i)\b(bash|sh|zsh|dash|powershell|pwsh|cmd)\b.{0,20}(-c|/c|-enc|-command)\b` +
		`.{0,20}\b(curl|wget|certutil|iwr|invoke-webrequest)\b`),
	regexp.MustCompile(`(?i)base64\s+(-d|--decode)\b.{0,60}\|\s*(sh|bash|zsh|python\w*|node)\b`),
}

func checkLaunchExecution(entry Entry) []Finding {
	if entry.Type != "stdio" {
		return nil
	}
	line := entry.Command + " " + strings.Join(entry.Args, " ")
	// One launch line is one decision: when several patterns catch the same line, quote the
	// longest match once rather than reporting the same risk twice.
	longest := ""
	for _, pattern := range launchExecution {
		if match := pattern.FindString(line); len(match) > len(longest) {
			longest = match
		}
	}
	if longest == "" {
		return nil
	}
	return []Finding{{
		Where:    "command",
		Kind:     "launch-execution",
		OWASP:    "MCP05",
		Quote:    longest,
		Severity: "high",
	}}
}

// runners fetch and execute a package at launch. Without a pinned version, every run installs
// whatever the registry serves under that name today - which is the supply-chain class (MCP04)
// and, for a name nothing publishes, the slopsquat's opening.
var runners = map[string]bool{
	"npx": true, "npx.cmd": true, "npx.ps1": true,
	"bunx": true, "bunx.cmd": true,
	"uvx": true, "uvx.exe": true, "pipx": true, "pipx.exe": true,
}

// movingTags are dist-tags: pointers, not versions. A package pinned to @latest is unpinned.
var movingTags = map[string]bool{
	"latest": true, "next": true, "beta": true, "dev": true, "canary": true,
	"rc": true, "nightly": true, "edge": true,
}

func checkUnpinnedPackage(entry Entry) []Finding {
	findings := []Finding{}
	for _, pkg := range Packages(entry) {
		if pinned(pkg.Runner, pkg.Spec) {
			continue
		}
		findings = append(findings, Finding{
			Where:    "args",
			Kind:     "unpinned-package",
			OWASP:    "MCP04",
			Quote: fmt.Sprintf("%s fetches and runs %q with no version pin - every run "+
				"installs whatever the registry serves under that name today", pkg.Runner, pkg.Spec),
			Severity: "medium",
		})
	}
	return findings
}

// Package is one registry package a launch line fetches and runs at start - the supply chain of
// a stdio server, one name at a time.
type Package struct {
	// Runner is the fetcher: npx, bunx, uvx, pipx.
	Runner string
	// Ecosystem is the registry family it fetches from: npm or pypi.
	Ecosystem string
	// Spec is the package as written in the args, version and all.
	Spec string
	// Name is the registry name alone: what a lookup should ask for.
	Name string
}

// Packages lists every registry package a launch line fetches. Local paths and bare binaries are
// not packages and are not listed - this is what the config *installs* when it starts.
func Packages(entry Entry) []Package {
	if entry.Type != "stdio" {
		return nil
	}
	packages := []Package{}
	tokens := append([]string{entry.Command}, entry.Args...)
	for index, token := range tokens {
		base := strings.ToLower(token)
		if !runners[base] {
			continue
		}
		rest := tokens[index+1:]
		if (base == "pipx" || base == "pipx.exe") && len(rest) > 0 && rest[0] == "run" {
			rest = rest[1:] // `pipx run pkg` - the spec follows the subcommand
		}
		spec := nextPackage(rest)
		if spec == "" || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") ||
			strings.HasPrefix(spec, `\`) {
			continue // a local path, not a registry fetch
		}
		ecosystem := "npm"
		if base == "uvx" || base == "uvx.exe" || base == "pipx" || base == "pipx.exe" {
			ecosystem = "pypi"
		}
		packages = append(packages, Package{
			Runner: base, Ecosystem: ecosystem, Spec: spec, Name: unversion(spec),
		})
	}
	return packages
}

// unversion strips the version constraint from a package spec, leaving the registry name exactly
// as written - `@scope/pkg@1.2.3` becomes `@scope/pkg`, `pkg==1.0` becomes `pkg`. Scoped npm names
// start with @, so the version is only ever the @ after the name, never the first one.
func unversion(spec string) string {
	if cut := strings.IndexAny(spec, "=<>!~["); cut >= 0 {
		return spec[:cut]
	}
	if at := strings.LastIndex(spec, "@"); at > 0 {
		return spec[:at]
	}
	return spec
}

// CheckNames looks up every package a launch line fetches and flags the ones no registry has ever
// heard of - the slopsquat: publish under a name nothing uses, wait for a config like this one to
// fetch it. This is the `names` check aimed at the moment it matters most: not "does this package
// exist in general" but "does what *this machine is about to install* exist".
//
// Lookups are per ecosystem (npm and PyPI answer differently); a lookup that could not complete is
// reported as such, never guessed at - a flaky registry is not evidence of malice.
func CheckNames(entry Entry, npm, pypi registry.Checker) []Finding {
	findings := []Finding{}
	checked := map[string]bool{}
	for _, pkg := range Packages(entry) {
		if checked[pkg.Name] {
			continue
		}
		checked[pkg.Name] = true

		checker := npm
		if pkg.Ecosystem == "pypi" {
			checker = pypi
		}
		result, err := checker.Exists(pkg.Name)
		if err != nil {
			findings = append(findings, Finding{
				Where:    "args",
				Kind:     "package-unverified",
				OWASP:    "MCP04",
				Quote:    fmt.Sprintf("could not verify %q exists (%s) - checked nothing is not the same as clean", pkg.Name, result.Error),
				Severity: "medium",
			})
			continue
		}
		if result.Exists {
			// Existence is not innocence: a typosquat exists by design - the attacker
			// published it. The shape of the name and the age of the package are the facts
			// a registry knows and a publisher cannot go back and rewrite.
			if neighbor, relation := registry.Near(pkg.Ecosystem, pkg.Name); neighbor != "" {
				findings = append(findings, Finding{
					Where:    "args",
					Kind:     "lookalike-name",
					OWASP:    "MCP04",
					Quote: fmt.Sprintf("%q is %s %q - the typosquat's shape; check who "+
						"published it and how long it has existed before trusting it",
						pkg.Name, relation, neighbor),
					Severity: "medium",
				})
			}
			if fresh := registry.Freshness(result, time.Now()); fresh != "" {
				findings = append(findings, Finding{
					Where:    "args",
					Kind:     "fresh-package",
					OWASP:    "MCP04",
					Quote: fmt.Sprintf("%q %s - inside the window a slopsquat lives in; a "+
						"name fetched days after it appeared is a name someone is waiting on",
						pkg.Name, fresh),
					Severity: "medium",
				})
			}
			continue
		}
		findings = append(findings, Finding{
			Where:    "args",
			Kind:     "unknown-package",
			OWASP:    "MCP04",
			Quote: fmt.Sprintf("%q is fetched at launch and no %s registry has ever heard of it - "+
				"exactly the shape of a slopsquat; publishing under that name is trivial once "+
				"something asks for it", pkg.Name, pkg.Ecosystem),
			Severity: "high",
		})
	}
	return findings
}

// nextPackage returns the first argument that is not a flag.
func nextPackage(args []string) string {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg
	}
	return ""
}

// pinned reports whether a package spec names one version. npm takes name@version (the version is
// after the last @, and a dist-tag is not a version); uvx/pipx take name==version.
var exactVersion = regexp.MustCompile(`==[0-9][^*]*$`)

func pinned(runner, spec string) bool {
	if runner == "uvx" || runner == "uvx.exe" || runner == "pipx" || runner == "pipx.exe" {
		return exactVersion.MatchString(spec)
	}
	at := strings.LastIndex(spec, "@")
	if at <= 0 {
		return false
	}
	version := spec[at+1:]
	return version != "" && !movingTags[strings.ToLower(version)]
}

// broadPaths are host paths no server should be handed whole: the root, a home, or the docker
// socket - which is root by another name.
var broadPaths = map[string]bool{
	"/": true, "~": true, "$HOME": true, "${HOME}": true, "%USERPROFILE%": true,
	"/home": true, "/Users": true, "/root": true, "/etc": true, "/var": true, "/private": true,
	"/var/run/docker.sock": true, "/run/docker.sock": true,
	"C:\\": true, "C:/": true,
}

// volumeFlag finds docker volume mounts in the args, capturing the host side.
var volumeFlag = regexp.MustCompile(`(?i)(?:^|\s)(?:-v|--volume)(?:=|\s+)(\S+)`)

func checkBroadMount(entry Entry) []Finding {
	if entry.Type != "stdio" {
		return nil
	}
	findings := []Finding{}
	line := strings.Join(entry.Args, " ")
	for _, groups := range volumeFlag.FindAllStringSubmatch(line, -1) {
		hostSide := groups[1]
		if colon := strings.Index(hostSide, ":"); colon >= 0 && !strings.HasPrefix(hostSide, `C:`) {
			hostSide = hostSide[:colon]
		}
		if !broadPaths[hostSide] && !strings.Contains(hostSide, "docker.sock") {
			continue
		}
		findings = append(findings, Finding{
			Where:    "args",
			Kind:     "broad-mount",
			OWASP:    "MCP02",
			Quote:    "mounts " + hostSide + " from the host - the server gets everything under it",
			Severity: "high",
		})
	}
	if strings.Contains(strings.ToLower(line), "--privileged") {
		findings = append(findings, Finding{
			Where:    "args",
			Kind:     "broad-mount",
			OWASP:    "MCP02",
			Quote:    "--privileged: the container is not a sandbox",
			Severity: "high",
		})
	}
	for _, arg := range entry.Args {
		if !broadPaths[arg] {
			continue
		}
		findings = append(findings, Finding{
			Where:    "args",
			Kind:     "broad-mount",
			OWASP:    "MCP02",
			Quote:    "hands the server " + arg + " - the whole tree under it",
			Severity: "medium",
		})
	}
	return findings
}

// secretName is an env key whose value is expected to be a credential.
var secretName = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[_-]?key|credential|auth)`)

// secretShape is a credential recognised by its own prefix, whatever the key is called.
var secretShape = regexp.MustCompile(`(?i)^(sk-[A-Za-z0-9]|ghp_|gho_|ghu_|ghs_|grs_|github_pat_|` +
	`xox[baprs]-|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.|-----BEGIN)`)

// placeholder is a value that names a secret instead of being one: ${VAR}, $VAR, {{input:...}}, %X%.
var placeholder = regexp.MustCompile(`^\$\{[^}]+\}$|^\$[A-Za-z_][A-Za-z0-9_]*$|^\{\{[^}]+\}\}$|^%[^%]+%$`)

func checkSecrets(entry Entry) []Finding {
	findings := []Finding{}
	for _, key := range sortedKeys(entry.Env) {
		if finding, ok := secretFinding("env."+key, "secret-env", key, entry.Env[key]); ok {
			findings = append(findings, finding)
		}
	}
	for _, key := range sortedKeys(entry.Headers) {
		if finding, ok := secretFinding("headers."+key, "secret-header", key, entry.Headers[key]); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

// secretFinding reports one literal credential in a config file - named, never echoed: a scanner
// that prints the secret it found has leaked it. A placeholder names a secret instead of being
// one, and is not a finding.
func secretFinding(where, kind, key, value string) (Finding, bool) {
	if strings.TrimSpace(value) == "" || placeholder.MatchString(value) {
		return Finding{}, false
	}
	if !secretShape.MatchString(value) && !secretName.MatchString(key) {
		return Finding{}, false
	}
	return Finding{
		Where:    where,
		Kind:     kind,
		OWASP:    "MCP01",
		Quote:    key + " holds a literal credential in plaintext config (value redacted)",
		Severity: "high",
	}, true
}

// localhost exempts loopback from the plain-HTTP rule: a dev server on 127.0.0.1 crosses no wire.
var localhost = regexp.MustCompile(`(?i)^(http://)(localhost|127\.0\.0\.1|\[::1\])([:/]|$)`)

func checkInsecureTransport(entry Entry) []Finding {
	if entry.Type == "stdio" || entry.URL == "" {
		return nil
	}
	if !strings.HasPrefix(strings.ToLower(entry.URL), "http://") || localhost.MatchString(entry.URL) {
		return nil
	}
	return []Finding{{
		Where:    "url",
		Kind:     "insecure-transport",
		OWASP:    "MCP07",
		Quote:    entry.URL + " speaks plain HTTP - tools, arguments and results cross it unencrypted",
		Severity: "medium",
	}}
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Redacted returns the entry with every flagged secret value replaced - for reports that print
// the entry itself. Findings redact their quotes; this closes the other half of the leak: a JSON
// report that carries the secret in its entry has leaked it into whatever log receives the report.
// Env values and headers are both covered: a credential in a header is still a credential.
func Redacted(entry Entry) Entry {
	out := Entry{
		Name: entry.Name, Type: entry.Type, Command: entry.Command,
		Args: entry.Args, URL: entry.URL,
		Env: redactMap(entry.Env), Headers: redactMap(entry.Headers),
	}
	return out
}

func redactMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, key := range sortedKeys(values) {
		value := values[key]
		switch {
		case strings.TrimSpace(value) == "" || placeholder.MatchString(value):
			out[key] = value
		case secretShape.MatchString(value) || secretName.MatchString(key):
			out[key] = "[redacted]"
		default:
			out[key] = value
		}
	}
	return out
}