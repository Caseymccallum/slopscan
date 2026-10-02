# Security policy

## Reporting a vulnerability

A vulnerability in slopscan itself is worth more private treatment than a finding it misses.
Report it through GitHub's private vulnerability reporting on this repository (Security tab →
Report a vulnerability). If that route is unavailable, open an issue titled "SECURITY" without
detail and the maintainers will move the conversation somewhere private.

Expect an acknowledgement within a week. Please include the version (`slopscan version`) and,
when possible, a fixture that reproduces - every rule in this codebase was fixed by one.

## What counts as a vulnerability in slopscan

- **A missed detection** in a rule: an attack shape in tool metadata, a config, or a package name
  that the scanner calls clean. These are the reports this project wants most - the fixture suite
  is their natural home, and the rule that catches one is named after it forever.
- **A false positive that gates**: `config` exits 1 on high findings and `scan`/`watch` exit 3 on
  breaking drift - CI stops on those signals. A clean input that trips them is a bug worth
  reporting.
- **A leak in output**: findings and reports redact credential values by design. Any output path
  that echoes a secret it found (report, JSON, error message) is a vulnerability.
- **Anything in the release chain**: the signed artifacts, SBOMs and provenance attestations
  (`.goreleaser.yaml`, `.github/workflows/release.yml`).

## What does not

- A hostile MCP server behaving badly *at runtime* - that is tapelog's enforcement surface, and
  `docs/THREAT-MODEL.md` states the boundary plainly.
- A model obeying a convincing instruction: no scanner fixes that (see the threat model).

## Supported versions

Only the latest release receives fixes; this project is pre-1.0 and moves fast. Fixes land on
`main` with a test that names the missed shape.