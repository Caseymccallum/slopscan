# Design decisions

Why slopscan is built the way it is. Each decision records what was chosen and what was refused -
the refusals are the part that ages best.

## 1. The catalogue is the product

*Chosen:* every scan lands in one local SQLite file - servers, tools, raw definitions, findings,
pinned baselines - and every command reads and writes that file. A scanner whose output is a
terminal scroll is a scanner you run once; a catalogue is something you accumulate.

*Rejected:* a hosted dashboard with a free CLI in front of it. The MCP-security field already has
hosted audit services; the gap the research actually showed was local-first tooling whose data
never leaves the machine. Privacy is also what lets the catalogue hold *everything* you scanned,
rather than everything you will admit to a vendor.

## 2. Evidence over scores

*Chosen:* every classification lists the words and schema properties that produced it; every
injection finding carries a quote of the matched passage. A verdict a reader can argue with is the
only verdict worth printing.

*Rejected:* a single numeric "trust score" as the headline. The field's hosted tools produce
letter grades (and cap them at D on critical findings, which is a score with extra steps). A score
hides the argument; slopscan prints the argument and leaves the score to drift detection, where the
number means something concrete (did the reviewed surface change?).

## 3. A file is a claim; the shape is the fact

*Chosen:* input schemas escalate a verdict - a tool called `tidy_up` with a `command` parameter is
an execution surface - and guards (`confirm`, `dry_run`) are recorded but never lower a category,
because guards are optional by nature. Names and descriptions can only escalate too: their words
are read, but never trusted to soften.

*Rejected:* letting a friendly description talk a verdict down. "Read-only helper" in the
description of a tool with a `shell` parameter is not evidence of safety; it is the attack.

## 4. The baseline changes only when a person re-pins

*Chosen:* `pin` freezes the current tool definitions; scans never touch the pinned copy. The
baseline table deliberately has no foreign key to the servers table - a re-scan replaces the
servers row (that is what "a new observation supersedes the old one" means), and a cascade would
have silently wiped the baseline on every scan. A test now guards this property.

*Rejected:* auto-updating the baseline on every scan - which is indistinguishable from having no
baseline at all, since the attack *is* the change. Rejected equally: an in-memory fingerprint store
that resets when the process restarts (the approach commercial SDKs take, and the reason their
"rug pull detection" misses anything that crosses a restart).

## 5. Drift is breaking or not, and the distinction is what a caller can act on

*Chosen:* removals, renames, description rewrites and schema changes are breaking (code or an
agent relying on the old surface is now silently wrong); additions are drift but not breaking
(nothing depended on them yet). Breaking drift exits 3 on every command, so a script can tell a
rug pull from a typo without parsing output.

*Rejected:* a 0-100 drift score as the only output. The score exists (100/90/30, the community
rubric) but the machine-readable signal is the boolean: did the reviewed contract hold?

## 6. Injection rules are text, not a model

*Chosen:* named regular expressions, each with its OWASP code, each reviewable in one screen - plus
the specific shapes 2026's campaigns used (credential harvesting, runtime call-count gating, tool
shadowing) rather than only generic prompt-injection clichés. The regexes found real bugs in real
fixtures during development, including one rule that missed the campaign's own phrasing and was
broadened after the smoke test proved it.

*Rejected:* an LLM judge over tool descriptions, which is what Cisco's scanner layers on top of
rules. An LLM judge brings its own prompt-injection surface (a poisoned description is, by
construction, text aimed at a model), makes verdicts non-reproducible, and requires a network
dependency. Detection that can be reasoned about statically is the point.

## 7. A probe asks one question and calls nothing

*Chosen:* `probe` performs the MCP handshake, reads `tools/list`, and kills the server. What a
server *says* it can do is the safe question; asking it twice (the second time in anger) is
tapelog's job, not this one's.

*Rejected:* behavioural probing - invoking tools with canary inputs to see what they really do.
That runs untrusted code with real side effects, which is exactly the thing a scanner is supposed
to let you avoid. The one exception is `watch`, which re-asks the *same* safe question on an
interval - continuous re-probing being the other half of the CSA's prescribed mitigation. It stops
at the first change: the point of watching is to notice, not to accumulate.

## 8. Newlines are the protocol

*Chosen:* MCP's stdio transport is newline-delimited JSON-RPC; every message slopscan sends or
expects is one line. A fixture that once sent a pretty-printed multi-line `tools/list` hung its
own test - the hang *was* the finding: a server that pretty-prints is a server an agent cannot
read either.

*Rejected:* a buffered reader that accumulates JSON until braces balance. That would paper over
what is, per the spec, a broken server - and silently succeeding against broken servers is how
scanners learn to lie.

## 9. The config file is an attack surface, and scoping is printed

*Chosen:* `slopscan config` reads the `mcpServers`/`servers` blocks that Claude Desktop, Cursor,
Windsurf and VS Code actually load - the format everyone uses and most scanners misparse into an
empty object and a wall of NO_AUTH noise. Checks are scoped by entry type: stdio entries get
launch-line analysis (pipe-to-shell, unpinned package fetches, plaintext env secrets, broad
filesystem mounts) and never see a transport rule; remote entries get transport checks and say
openly that their tool list was not fetched. High findings exit 1: a config is a gate, like
`names` refusing a name that does not exist.

*Rejected:* running network rules against local processes, because "NO_AUTH" on a stdio entry is
noise engineered to look like rigor. Equally rejected: a silent pass over what was not evaluated -
every report names its own gap.

## 10. Test the write side

*Chosen:* the `unchecked-path-write` rule targets the shape shared by CVE-2026-27825 (CVSS 9.1) and
its three 2026 siblings: a caller-controlled path parameter, a materializing verb, and a
description that never states a directory boundary. The fix the write-ups ask for - state the
boundary - makes the finding go away, so the rule teaches its own remediation. Severity is
medium: metadata cannot prove the server skips validation, only that the contract never promised
it.

*Rejected:* flagging every tool with a path parameter. Read tools are quiet (the verb half must
hold), and bounded write tools are quiet - the corpus's clean guards enforce both directions,
because a scanner that flags everything is as useless as one that flags nothing.

## 11. The timeline is append-only, and the verdict is not

*Chosen:* every scan writes one history row - timestamp, tool count, risk, surface fingerprint -
even though the same scan replaces the verdict row above it. The definitions are stored only when
the surface differs from the previous observation (a watch loop must not grow the file by a copy
of the tool list every tick) and carried forward when it does not. Change lists are *derived at
read time* by comparing consecutive observations with the same `drift.Compare` the drift command
uses - one implementation of "what changed", so the timeline and the drift report cannot disagree.

*Rejected:* storing a change-events table alongside. An events table is a second source of truth
that can be half-written, orphaned or out of order; the timeline of raw observations is complete
by construction and cannot drift from itself. Rejected equally: a foreign key from history to
servers, which would let a re-scan delete the record of what the re-scan replaced - the past must
survive the present.

## 12. A config is a gate, and the supply chain is checked at the door

*Chosen:* `config --check-names` looks up every package a launch line fetches before anything
installs it - the `names` check aimed at the moment it matters. Versions are stripped to the
registry name exactly as written (this package never "fixes" a name); a name no registry knows is
the slopsquat and is flagged high. A registry that cannot answer is reported as *unverified*, never
as clean: "checked nothing" is not evidence.

*Rejected:* checking only explicitly pinned packages, or silently skipping the network step when a
flag is absent - the flag is explicit so nothing phones home by accident (decision 1), and when it
is asked for, every fetched name is checked, pinned or not.

## 13. Alerts are for the queue the team already watches

*Chosen:* `--format sarif` emits SARIF 2.1.0 - findings as results, finding kinds as OWASP-tagged
rules, drift events as `drift/*` results - in one deterministic document per run (sorted artifact,
subject, rule), so alert platforms deduplicating by identity see one alert, not one per run. A
finding that gates a run (config's exit 1, drift's exit 3) still emits its document *first*: CI
that stops on the exit code still needs to see what stopped it. `security-severity` values are
fixed display buckets for the host's ranking scheme, never computed CVSS - evidence over scores
holds in the standards world too.

*Rejected:* SARIF as a second findings pipeline with its own rules and severities. The document is
a projection of the same findings every other output prints - one implementation of what was
found, several renderings of it. Equally rejected: emitting on the happy path only, which trains
teams to trust an empty Security tab as "clean" when it really means "the gate fired and the alerts
were thrown away".

## 14. Existence is not innocence

*Chosen:* a name that exists is looked at harder, not waved through. The typosquat's problem is
precisely that the attacker published it - so the existence check answers "yes" to malware by
design. What a publisher cannot rewrite is the *shape* of the name (separator flips, dropped
letters, transpositions against a corpus of what squats are aimed at) and the *age* of the
package (a name registered days ago and fetched today is a name someone is waiting on). Both
facts come from the registry's own record and are quoted as facts - date, count, neighbour,
distance - never as a score.

*Rejected:* a reputation score or a "trust" rating. A number hides the argument, and this one
would be invented from the same two facts a reader can weigh themselves. Equally rejected:
*blocking* on similarity - `lodsh` might be a real package somebody published in good faith, and
medium-severity evidence is for a reviewer to judge. Only what is proven (a name no registry has
ever heard of) keeps the gate.

## 15. One handshake, three transports

*Chosen:* the probe speaks the same three messages - initialize, the ready notification,
tools/list - over stdio, streamable HTTP, and legacy HTTP+SSE. The remote paths honour session
headers (`Mcp-Session-Id`, the protocol version) and carry the auth headers the client
configuration declares; an endpoint that rejects POSTs is the signal to fall back to the older
stream-first transport. The promise holds on every wire: one question, no tool called, and tests
assert the exact message list against real HTTP servers.

*Rejected:* leaving remote entries unprobeable - the caveat every config report printed until now
was a gap, not a design. Equally rejected: growing the probe into a full MCP client with OAuth
flows and tool invocation. A server that demands an interactive login refuses the listing, and
that refusal is reported as an error - never as an empty clean list (the same honesty rule as the
registry's "unverified").