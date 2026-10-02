# Changelog

All notable changes to slopscan. The format follows [Keep a Changelog](https://keepachangelog.com/),
and the versions move when behaviour a script could depend on changes - output wording alone does
not earn a version.

## [Unreleased]

### Added

- **`db history <id>`** - the timeline no other table can hold. A re-scan replaces the verdict, so
  after a rug pull "when did this change?" had no answer: now every scan appends an observation
  (timestamp, tool count, risk, surface fingerprint) and the report derives the changes between
  consecutive observations from the stored definitions - so the timeline and the drift command can
  never disagree. Unchanged scans store no copy of the tool list, so a watch loop does not grow the
  file. History is append-only and survives server replacement - the same no-cascade property the
  pinned baseline guards.
- **`slopscan config --check-names`**: the slopsquat check at the moment it matters - not "does
  this package exist in general" but "does what *this config is about to install* exist". Every
  package a launch line fetches (npx, bunx, uvx, pipx; versions stripped to the registry name) is
  looked up before anything installs it; a name no registry has ever heard of is flagged high
  (MCP04) with its remediation in the quote. A registry that cannot answer is reported as
  *unverified*, never as clean. Per-ecosystem endpoints (`--registry`, `--pypi-registry`).
- **`SECURITY.md`**: the reporting route, completing the supply-chain story the signed releases
  already deliver.
- **`slopscan config <mcp-config.json>`**: reads the `mcpServers`/`servers` blocks that Claude
  Desktop, Cursor, Windsurf and VS Code actually load - the format everyone uses and most scanners
  misparse into a wall of NO_AUTH noise. Checks what each entry launches: `curl | sh` and friends
  (MCP05), unpinned package fetches where `@latest` counts as unpinned (MCP04), plaintext secrets
  in env (MCP01, values redacted everywhere including JSON output), filesystem handovers of `/`, a
  home directory, or the docker socket (MCP02), plain-HTTP endpoints (MCP07). Transport rules
  never fire on a stdio entry; every report says what was evaluated and what was not. High
  findings exit 1 - a config is a gate. `--probe` also starts each stdio server with its declared
  env and runs the full scan/pin/drift pipeline against what it really exposes.
- **`unchecked-path-write` rule** (MCP02): the write-sink blind spot of 2026's path-traversal CVEs
  (CVE-2026-27825, CVSS 9.1, and three siblings) - a caller-controlled path parameter, a
  materializing verb, and a description that never states a directory boundary. The fix the
  write-ups ask for silences the rule, so the finding teaches its own remediation. Corpus entries
  cover both directions: the CVE shape, and bounded write tools that must stay quiet.
- **`slopscan policy <id>`**: writes a tapelog policy pack from a scan - hostile metadata denied,
  destructive/financial/execute confirmed, clean reads allowed, unlisted tools confirmed by
  default. The generated pack is accepted by tapelog's own `policy test` (verified against it):
  scan with slopscan, enforce with tapelog. Generated policy is a starting point to edit and test,
  and says so in its header.
- **`testdata/corpus/`**: the rules' standing reputation - documented attack shapes (the Deadbugz
  campaign, the postmark-mcp incident, tool shadowing, hidden instructions) with the findings they
  must produce, and clean guards that must produce none. The corpus caught real bugs on its first
  day: plurals ("tokens" not "token") escaping the exfiltration rule, and a missing word boundary
  in the runtime-gating rule. New rules and reported misses land here.
- **CI (`.github/workflows/ci.yml`)**: build, vet, race tests, govulncheck on Linux and Windows -
  plus a dogfood job that runs the built binary against the repo's own fixture and asserts the
  exit-code contract (clean re-scan exits 0, a removed tool exits 3).
- **Release engineering (`.goreleaser.yaml`, `.github/workflows/release.yml`)**: signed GitHub
  Releases on `v*` tags - 6 static binaries, cosign-signed checksums, one SBOM per archive, build
  provenance attestation. The release stamps the version via ldflags; a source build says "dev".
- `LICENSE` (MIT, as the README always claimed).

## [0.2.0] - 2026-10-01

### Added

- **Baseline pinning and drift detection** (`internal/drift`, `pin`, `drift`). `slopscan pin <id>`
  freezes the tool definitions in the catalogue as the reviewed baseline; every later `scan` and
  `probe` compares against it and prints what changed. `slopscan drift <id>` does the comparison on
  demand from the catalogue, for CI. Changes are classified as added / removed / renamed /
  description-changed / schema-changed, with breaking changes scored per the community rubric
  (100 unchanged, 90 additions only, 30 when something broke). A rewritten description is reported
  separately, because it is the exact shape of a rug pull.
- **`slopscan watch`**: continuous re-probing of a live server on an interval - the other half of
  the rug-pull mitigation. The first change to the tool surface ends the watch with the drift
  report printed and the run's exit code set (3 when breaking).
- **Exit code 3** for a breaking baseline change on `scan`, `probe`, `watch` and `drift`, distinct
  from exit 1 (something failed), so CI can tell a rug pull from a typo.
- **`--format json`** on every report-producing command: one JSON document per report carrying the
  same fields the prose argues from, including `breaking` on drift comparisons.
- **Injection rules for the 2026 campaign shapes** (`internal/injection`): `credential-harvest`
  (instructions to hunt SSH keys, cloud credentials, shell history - the Deadbugz payload),
  `runtime-gating` (behaviour gated on a call count - the Deadbugz trigger), and `tool-shadowing`
  (a description claiming authority over another tool).
- **OWASP MCP Top 10 codes on every finding** (MCP01-MCP10), printed in reports, so findings can be
  compared with other audits in the field's shared vocabulary.
- `risk.Fingerprint` / `risk.SurfaceFingerprint`: canonical-JSON SHA-256 fingerprints of tool
  definitions, stable across key order.
- `CHANGELOG.md`, `docs/DESIGN.md` (the decisions and the alternatives refused),
  `docs/THREAT-MODEL.md` (in scope, knowingly out of scope, assumptions).

### Fixed

- Findings no longer accumulate across re-scans of the same server: a re-scan is a new observation
  and replaces the old one's findings instead of doubling them.
- A pinned baseline survives a re-scan. (The baseline table once cascaded on the servers row, which
  a re-scan replaces - the upsert was wiping the very copy drift compares against.)

## [0.1.0] - 2026-10-01

### Added

- Classification of MCP tools into six risk categories (read, write, execute, destructive,
  financial, other) from tool names, descriptions and input-schema shape, every verdict carrying
  its reasons.
- Injection scanning of tool metadata: instruction override, concealment, exfiltration, role
  confusion, policy bypass, invisible characters - each finding quoted as evidence.
- `slopscan probe`: live MCP probing over stdio (handshake, `tools/list`, shutdown - no tool is
  ever called).
- `slopscan names`: package existence checks against a registry, for slopsquatting.
- The local catalogue (one SQLite file): servers, tools, findings, riskiest-first listing.
- `slopscan scan`, `slopscan db list`, `slopscan db show`, `slopscan version`.