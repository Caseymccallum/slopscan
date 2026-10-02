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