# Changelog

All notable changes to slopscan. The format follows [Keep a Changelog](https://keepachangelog.com/),
and the versions move when behaviour a script could depend on changes - output wording alone does
not earn a version.

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