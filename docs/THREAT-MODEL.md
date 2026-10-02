# Threat model

What slopscan defends against, what it knowingly does not, and what would defeat it. Read this
before trusting a clean report.

## What slopscan is

A pre-deployment reader of MCP tool metadata. It looks at what a server *says* - names,
descriptions, input schemas - and at what those sayings are made of. It never calls a tool, never
executes server code, and never fetches anything but a package registry's existence record.

## Threats in scope

| Threat | OWASP | How slopscan addresses it |
| --- | --- | --- |
| **Tool poisoning** - instructions embedded in tool descriptions aimed at the model | MCP03 | Injection scanning: every finding quoted, with its matched pattern named |
| **Credential harvesting** - descriptions instructing the agent to hunt secrets (the 2026 Deadbugz payload) | MCP01 | `credential-harvest` rule |
| **Runtime-gated behaviour** - benign until call N, then malicious (the Deadbugz trigger) | MCP03 | `runtime-gating` rule for metadata that counts calls; drift detection for what appears after the count - the metadata rewrite itself is caught whenever the tool list is re-read and compared |
| **Rug pulls / silent tool drift** - the surface changes after review | MCP03 | Pin + drift: the reviewed definitions are frozen, every later scan compares, breaking change exits 3 |
| **Slopsquatting** - packages published under names no registry knows (hallucinated or typosquatted) | MCP04 | `names` command: existence checked before install |
| **Dangerous capability hidden by friendly words** - "tidy_up" with a `shell` parameter | MCP05, MCP02 | Classification reads the schema, not just the name; words can escalate, never soften |
| **Tool shadowing** - one description claiming authority over another tool | MCP03 | `tool-shadowing` rule |

## What slopscan knowingly does not defend against

- **A server that lies in its tool list and behaves differently when called.** The list is the only
  contract slopscan reads. A server that advertises `read_text` and shells out regardless is
  detectable only at runtime - that is a job for a policy-enforcing proxy (tapelog) or a sandbox,
  not a reader of metadata.
- **A malicious server binary.** `probe` starts the server to ask it a question. Run probes of
  servers you do not trust in a container or VM - slopscan does not sandbox the process it spawns,
  and pretending otherwise would be the security theatre it exists to avoid.
- **Poisoned tool *results*.** Instructions delivered inside tool outputs (rather than tool
  definitions) reach the model at call time. Out of scope for a pre-deploy scanner; noted openly
  because the gap is real and the field is honest about it too.
- **The model itself.** No scanner can make a model refuse a convincing instruction. Slopscan's job
  is to make the instruction visible to the *human* reviewing the tool, with the passage quoted.
- **A pinned baseline nobody re-reads.** Drift detection compares scans; scheduling the re-probes
  is `watch`'s job (or a cron line calling `drift`). A pin without re-probes is a photograph of a
  door you never check again - the tool can make checking easy, but it cannot make you check.

## Assumptions

- The catalogue file is only as trustworthy as the machine it sits on; it is not itself signed.
  (Tapelog's hash-chained logs and checkpoints exist for that problem; keeping the two tools
  separate is a decision, see `DESIGN.md`.)
- Registry lookups trust TLS and the registry's answers. `names` proves a name exists; it says
  nothing about whether the thing published under it is benign.
- Regex rules can be evaded by text written to evade them. They are a first gate with zero false
  confidence, not a proof of cleanliness.

## Reporting

A finding slopscan misses is worth more than one it invents. Open an issue with the tool
definition quoted - the fixture suite is the natural home for it, and the rule that catches it will
name it forever.