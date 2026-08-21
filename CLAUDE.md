# Project context

Read this before working in `artifacts/`. It exists so a session starts with the
rules already loaded instead of rediscovering them.

## What this is

`artifacts/` is a machine-readable catalog of the endpoint traces left by AI
coding agents, local LLM runtimes, agentic workflow engines, and MCP components.
It answers: **what did this tool leave on the host, what does that prove, and in
what order do I collect it.**

It is deliberately *not* a living-off-the-land abuse catalog. LOLBAS and LOLRMM
answer "what can this be misused to do." This one is for the person doing the
acquisition, which is why every artifact carries `forensic_value` and
`evidence_type`, and every entry carries a `collection` block.

## Commands

Run everything from `artifacts/`. On Windows use `python`, on macOS/Linux
`python3`; the scripts themselves are cross-platform (pathlib throughout) and
write LF endings on every platform so the generated feeds stay byte-identical.

```bash
python scripts/validate.py                    # schema + sigma + confidence gate
python scripts/validate_techniques.py         # ATLAS/ATT&CK ids exist (--refresh re-pins)
python scripts/readme_counts.py               # README Contents block (--check gates it)
python scripts/normalize.py                   # collapse vocabulary drift
python scripts/export.py                      # regenerate docs/api feeds
python scripts/export_forensicartifacts.py    # Plaso / GRR / Timesketch format
python scripts/export_kape.py                 # KAPE targets (--check validates, writes nothing)
python scripts/export_velociraptor.py         # Velociraptor artifacts (--check likewise)
python scripts/normalize_notes.py             # note style (--check reports, writes nothing)
python scripts/data_sources.py                # telemetry coverage (--check audits only)
python scripts/verify_host.py                 # check catalogued paths on THIS machine
python ../collectors/gen_credential_targets.py     # collector targets, also CI-gated
python scripts/build_site.py --check          # site data contract, writes nothing
python scripts/build_site.py                  # regenerate docs/site (CI does this)
python ../artifacts/scripts/validate_mappings.py   # run this one from the repo root
python ../skills/agent-artifact-catalog/scripts/new_entry.py "Tool Name"
```

CI runs `validate.py`, `validate_mappings.py` and `build_site.py --check` on
every pull request. `validate_mappings.py` lives under `artifacts/scripts/` but
walks the repository root to find the `0N-*` rule directories, so run it from
there rather than from `artifacts/`.

`validate.py` is the gate CI runs. Never commit while it reports problems.
Always regenerate the feeds in the same commit as a catalog change, or CI fails
the staleness check. "The feeds" is five scripts, not two: `export.py`,
`export_forensicartifacts.py`, `export_kape.py`, `export_velociraptor.py` and
`collectors/gen_credential_targets.py`. The last one is easy to forget because it
lives outside `artifacts/` — an entry that adds a credential location and skips it
passes every local check and fails CI.

`validate_techniques.py` resolves every `atlas_techniques` and
`attack_techniques` id against pinned framework data in
`schema/technique-ids.json`. The JSON schema checks those ids by shape, so
`AML.T9999` and a technique MITRE deprecated three releases ago both pass it.
The pin is deliberate: a gate that followed upstream live would break the build
on a MITRE rename with no diff to explain it. `--refresh` re-pins and is the only
thing that touches the network, so a version bump lands in review as a diff.
Two upstream traps it already avoids, both of which return a plausible wrong
answer rather than an error - ATLAS ships a `dist/ATLAS.yaml` that declares
itself deprecated and carries fewer techniques than the current release, and the
ATLAS YAML uses anchors, so grepping it undercounts by about sixteen techniques
that never appear as literal text.

## Rules that are not negotiable

**Entry IDs are permanent.** `AIRT-0011` stays `AIRT-0011` forever, including
through a rename or an extraction into its own repo. Once a detection or report
cites an ID, renumbering silently breaks it. New entries take the next free ID.

**Confidence reflects provenance, not conviction.**
- `high` — verified on a live host, or documented by the vendor
- `medium` — multiple independent third-party sources agree
- `low` — single-source or inferred, and **must** carry `unverified: true`

The validator blocks a `confidence: high` entry that hides an unmarked
low-confidence artifact. Do not work around it by upgrading the artifact; either
verify it or downgrade the entry.

**`last_verified` exists at two levels.** The entry-level field says somebody
looked at the entry. It cannot say *how much* of it they looked at, and that gap
produced a real problem: AIRT-0002, AIRT-0011 and AIRT-0018 were checked on a
Windows host, stamped, and read as fully verified while their macOS rows had
never been touched. Rows now carry their own optional `last_verified`. Set it on
the rows you actually confirmed, and leave it off the rest - an absent row-level
date means that row has not been individually verified, whatever the entry says.

Two rules for it. Only stamp a row you confirmed *on a host or on the vendor's
page*, not one you reasoned about. And never stamp a row whose path the tool
merely shares with other software: `~/.aws` hits for AIRT-0033 on machines that
never ran the computer-use demo, so that row is deliberately left unstamped and
carries a note saying why.

**Take the ATLAS subtechnique only when the tool pins the layer.**
`validate_techniques.py --advise` reports every mapping whose parent has
subtechniques - 41 of them at the time of writing - and most of those should
stay parents. The corpus already draws the line in the right place. `letta.yml`
carries `AML.T0080.000` Memory because a memory-centric agent framework pins the
layer. `mcp_tool_poisoning.yar` maps to the parent `AML.T0110` even though the
Invariant Labs attack it detects is definition poisoning, because an MCP host's
config surface reaches all three of definition, implementation and runtime
response, and the host does not constrain which. The same reasoning keeps
AIRT-0011, AIRT-0038 and AIRT-0041 on the parent. Do not sweep the advisories
into subtechniques: a mapping that asserts a layer the entry does not constrain
is less true than the parent, not more precise. `--advise` exists to raise the
question per entry, not to produce a work queue.

**Omit rather than guess.** A missing field is honest. A guessed one becomes
somebody's broken detection during an actual incident.

**Notes are captions, not emphasis.** `description` and `notes` rows, plus
`abuse_potential`, follow one style: no shouted prose, sentence case, and a
terminal period only when the note is more than one sentence. `PLAINTEXT`
duplicates `storage: plaintext` and `HIGH-VALUE` duplicates `forensic_value`,
neither is filterable in the CSV feed, and 363 captions had drifted into four
styles before this was written down. `normalize_notes.py` applies it and
`validate.py` gates it. An ALL-CAPS token survives only if it is an identifier
or an acronym on the derived allowlist - which was derived by enumerating every
uppercase token in the corpus, because the first version guessed and turned CWD
into "cwd".

**Case studies carry their provenance.** A case study asserts things about
somebody else's incident, usually from a single reporting party, so
`confidence`, `basis` and at least one `references` entry are required, and
`build_site.py --check` fails without them. Where analysts disagree, record the
disagreement in `contested` rather than picking a side — the Mexico breach and
GTG-1002 are both in the catalog specifically because the argument about how
autonomous the AI was is the thing a responder has to be able to adjudicate.
Vendor disclosure of an incident is not the same as vendor documentation of a
path: an incident claim nobody else has corroborated is `medium`, whatever the
vendor's reputation.

**Every artifact class is a closed shape.** `artifacts.eventlog` shipped as
`array of object` with no `$defs` behind it, which meant the first rows written
would have set the convention by accident - the same way `artifact_type` reached
52 ad-hoc values before it was locked down. `eventlogArtifact` is now defined
like the other five. If you add a sixth class, define it before you populate it.

**Volatility and retention are derived, not authored.** `data_sources.py` owns
both. Volatility falls out of the row class and the artifact type, so 507 rows
cannot drift apart; the one authored input is `retention`, and a disk row that
carries one is promoted to `rotating` whatever its `artifact_type` says. Only
write `retention` where the tool documents a purge window - exactly one row
does. An absent retention means "until uninstall", which is honest; a guessed
one tells a responder they have longer than they do.

`docs/data-sources.yml` holds only the prose a machine cannot derive: how you
switch a source on, what it costs to keep, what you cannot answer without it.
Every count on the Data sources tab is computed at build time, and `audit()`
fails **both** directions - a row class, Sigma logsource category or event log
channel that maps to no source, and a source claiming coverage the corpus does
not supply. The second half matters as much as the first: an over-claiming
source makes an estate look better instrumented than it is. `validate.py` and
`build_site.py --check` both run it.

**An MCP block has five shapes, not one.** `mcpConfig` required `config_path`,
which assumed the only mechanism was a file on disk - and that is precisely why
25 `mcp_capable` entries carried an empty block. `mechanism` is now a closed
enum: `config-file` (collect the file), `database` (the self-hosted engines
register servers through their own UI and persist them - the collection step is
a query), `in-code` (a literal in a script; read the source, there is nothing to
collect), `server` (the tool *is* an MCP server, so go find the client config
that names it), `cloud` (tenant-side; stop looking on this disk). The locator
field is conditionally required, so a non-file row cannot ship without something
to grep for. Exporters that emit paths - forensicartifacts, KAPE, Velociraptor -
must skip everything except `config-file`, or an import name ships as a file path.

A `mcp_capable: true` claim with no block is not always a gap to fill. Ask
whether the tool hosts MCP at all first: Ollama, Aider and the Claude
computer-use demo all carried the claim and none is an MCP client. Three of 25
is a high enough hit rate that the capability question comes before the path
question. A wrong capability flag reads as a fact and is worse than a visible
hole. The check is a hard gate now that the count is zero.

**Controlled vocabularies.** `artifact_type`, `evidence_type`, `secret_type`,
and `storage` are closed enums in `schema/artifact.schema.json`. They exist
because the published CSV feed is meant to be filtered, and a field where `log`
and `logs` and `logfile` coexist cannot be. If something genuinely does not fit,
extend the schema, the template, and the skill together.

**Detections are Sigma only.** No SPL, no KQL, no XQL, no ES|QL, no EQL, no
vendor dialect of any kind. One rule converts to any SIEM, and shipping a vendor
dialect would both force a platform choice on everyone downstream and imply an
affiliation this project does not have. Verify with
`sigma convert -t splunk detections/sigma/<rule>.yml`.

This is the one rule most likely to be argued with, because "just add native
analytics for platform X" always looks like a free win to whoever uses platform
X. It is not. The maintainer works for a security vendor, and the project's
independence disclaimer (`README.md`) only holds while the detection content
stays neutral — a native dialect for any one vendor reads as capture regardless
of the rule's quality. pySigma already emits every dialect anyone needs, so the
capability is not lost by refusing to ship it; only the appearance of neutrality
would be. Do not name the employer anywhere in the repository either: the
disclaimer says "any employer" deliberately.

Converting to a specific backend inside CI is fine and is not shipping a
dialect — `validate.yml` converts to Elastic/lucene and `artifacts.yml` to
Splunk, purely to prove the rules parse. The backend choice there is arbitrary.

**Defensive content only.** Document where artifacts live and what they prove.
No exploit code, no working attack tooling, no step-by-step abuse instructions.

## What a restricted runner cannot verify

A documentation pass is not a substitute for a host, but it is not available
everywhere either. Claude Code sessions on the web run behind an egress policy,
and on the one this catalog has mostly been built from, **every vendor
documentation domain is blocked** - cursor.com, docs.anthropic.com,
modelcontextprotocol.io, docs.codeium.com, kiro.dev, docs.aws.amazon.com,
docs.tabnine.com, docs.openwebui.com, docs.vllm.ai. GitHub is reachable and
search is reachable; the docs themselves are not.

That matters for `last_verified`, which means "somebody checked this on this
date". A search engine's summary of a vendor page is not that check - it is a
third party's rendering of it, and this project has already been burned once by
trusting one (an aggregator gave Windsurf's MCP path as `~/.windsurf/mcp.json`
when the vendor documents `~/.codeium/windsurf/mcp_config.json`). Stamping
`last_verified` from a summary would inflate the exact field the staleness gate
was built around, which is worse than leaving the entry visibly unchecked.

So: verify from a network that can reach the vendor, or from the tool installed
on a host. Corroborating from a project's own GitHub repository is legitimate and
works from here - that is where several of these projects keep their docs - but
check that the repo really is the source rather than a README pointing at a site
you cannot open.

## When verifying paths on a real machine

This is the highest-value work available, because 20 entries are `medium` and 4
are `low` purely because they were sourced from documentation rather than from a
live host. `verification_worklist.py --summary` is the live count; the figures
in this sentence are a convenience copy and will drift.

**Check existence, permissions, and structure. Never read credential file
contents.** `~/.claude/.credentials.json`, `~/.codex/auth.json`, and
`~/.gemini/oauth_creds.json` hold live tokens. The forensic question is "does
this exist and what mode is it," and the secret itself must not end up in a
transcript, a commit, or a log.

Good:  `ls -la ~/.codex/`, `stat -f "%Sp" ~/.codex/auth.json`, `jq 'keys' file`
Avoid: `cat` on anything holding a token

When a documented path and reality disagree, that is the interesting result.
Record it in `docs/VERIFICATION.md` with the basis for the change, then update
the entry and raise its confidence, and set `last_verified` to the date you
checked. `docs/HOST_VERIFICATION.md` is the runbook and `scripts/verify_host.py`
does the sweep - it stats paths and never opens them, and checks registry keys
for existence without reading a value, so it cannot leak a token either way.
Registry coverage was added on 2026-08-14; before that the sweep silently
skipped every registry row while claiming to cover each locator.

A MISS from that script is not evidence a path is wrong. It cannot tell a wrong
path from an absent tool, and many of these paths are created lazily on first
run rather than at install time. Install the tool, run it once, then re-check.

## Current state

51 entries, 615 artifacts, 164 credential locations, 64 MCP config
locations, 12 endpoint Sigma rules, 14 case studies, 9 telemetry sources.
Validation clean.

Volatility across the 615 site rows: live 114 · rotating 53 · stable 448

Do not hand-maintain the numbers above. `scripts/readme_counts.py` generates the
same figures into `artifacts/README.md` and CI gates that block, so it is the
authority; this paragraph is a convenience copy and has drifted before.

Detection content maps to the OWASP LLM Top 10 **2026** list. Eight of the ten
IDs changed meaning between 2025 and 2026, so an ID quoted from an older report
names a different category here than it did there -
`scripts/remap_owasp_2026.py` holds the mapping table and the reasoning.

Detection content totals 68 rule files / 159 signatures across the nine attack-class
directories plus `artifacts/detections/`, all indexed in `MAPPINGS.md`.

Confidence: 27 high, 20 medium, 4 low.
Provenance: 51/51 entries carry a reference. AIRT-0034 was the last holdout and
sourcing it turned up a correction rather than a citation - Operator is EOL and
its only network indicator was a domain that had been sunset. 30/51 carry aliases.
50/51 carry `last_verified`, and `validate.py` lists the remaining one as never
verified rather than letting it look fresh.

That holdout is **AIRT-0007 Devin**, and `verification_worklist.py` annotates it
"cloud-hosted, no endpoint paths to check" - its three claims are a browser
session and two network indicators. So the never-verified count is structural
rather than a backlog, and driving it to zero is blocked on the Devin/Windsurf
scoping call below, not on effort.

Do not restore the framing this section used to carry, which described the
unverified set as entries that "could not be checked through a repository API".
That was wrong, and it was wrong in the direction that matters: it dressed up an
unworked backlog as a technical limit. Most of that set - Windsurf, Tabnine,
Kiro, Amazon Q, Open WebUI, vLLM - was ordinary installable software, and all of
it has since been verified. When an entry is unchecked, say nobody has checked
it.

**Cursor** and **Claude Desktop** left that list on 2026-08-14, verified on a
Windows host that had both installed. See `docs/VERIFICATION.md` for the full
set. A live host beats a vendor page for anything installable, but it is one
host, and the Claude Desktop pass is a standing warning about what that misses:
the first conclusion drawn from it was wrong, and only a documentation pass
caught it.

**The MSIX config question has no single answer, and do not let anyone give it
one.** Claude Desktop's packaged build is a sideloaded enterprise MSIX deployed
by Intune/DISM - not a Microsoft Store listing, and no Anthropic page documents a
config path for it. Its manifest declares the `unvirtualizedResources`
capability, which only *permits* the disabling elements; it disables **registry**
write virtualization globally, but for the filesystem it excludes exactly two
LocalAppData directories, so **filesystem virtualization stays active for
`%APPDATA%\Claude`**. Precedence is therefore decided by Windows per file and by
install history: the OS reads the container copy first and falls back to real
AppData, and a config that existed before the packaged install stays
unvirtualized. So `%APPDATA%\Claude\` wins on an upgraded host and the container
copy wins on a clean packaged install. Collect **both**, plus the manifest from
`WindowsApps`, and resolve per host. Container copies are not removed on
uninstall. Reasoning from `unvirtualizedResources` to "writes are not
virtualized" is the specific trap here - it was refuted five times over in
verification, and it is the error this catalog made first.
Risk: 11 critical, 27 high, 12 medium, 1 low.

## Site generation

`build_site.py` emits one self-contained vanilla-JS HTML file. No framework, no
CDN, no build step, never hand-edited. It is not committed; CI builds it at
deploy time. `site_data.py` loads everything *outside* the catalog proper —
detection rules, the ATLAS/OWASP indexes, case studies, the investigation guide
— while `build_site.py` owns the catalog rows themselves.

`docs/HANDOFF_REVIEW.md` records what was decided about the round-2 design
handoff and why, including which findings were declined and the two places the
review itself was wrong. Read it before re-opening any of those questions.

Three things worth not relearning:

- `docs/api/artifacts.csv` is a published feed. Never change an existing column
  in place; add new ones. Display-only reshaping belongs in the site build.
  `volatility` and `retention` were appended that way. The exporter's locator
  fallback (`path or key or indicator or name`) had no branch for `eventlog` and
  shipped 30 rows with an empty `artifact` column - it switches on the class
  now, so a seventh class fails loudly instead of quietly.
- Row **anchors**, not row indexes, are what picks and permalinks persist
  against. `--check` enforces that they are unique and URL-safe.
- "What it proves" is derived for registry, network and process rows, because
  the schema only declares `evidence_type` on disk artifacts. Derive inside the
  schema's enum, and prefer fixing the schema when it is next touched.

## What is next, in priority order

For counts, run `python artifacts/scripts/verification_worklist.py --summary`.
Numbers are not written down here on purpose - this section and issue #8 both
carried hardcoded totals that had silently drifted before anyone noticed.

**Two decisions are blocked on a human, not on effort.** Neither should be
resolved by whoever picks this up next without asking.

1. **AIRT-0007 Devin now overlaps AIRT-0006 Windsurf.** Cognition rebranded
   Windsurf's desktop app as Devin Desktop and `docs.windsurf.com` redirects to
   `docs.devin.ai`, so the two entries describe partly the same binary. Entry IDs
   are permanent, so how the two are split is a scoping call. Do not add rows to
   either until it is made. AIRT-0007 is the last never-verified entry and this
   is why.
2. **AIRT-0008 has vendor documentation contradicting vendor source.** The
   troubleshooting page gives the Windows CLI log directory as `%TEMP%\qlog\`;
   the vendor's own `crates/chat-cli/src/util/paths.rs` builds
   `%TEMP%\amazon-q\logs` on Windows and uses `qlog` only in the unix branch.
   Both are vendor sources. Settle it on a live host - committing to either on
   documentation alone is how a responder collects nothing.

**Then, in order of value:**

3. **Apply the rest of `docs/RESEARCH-2026-08-14.md`.** Roughly thirty candidate
   rows survived adversarial verification and were deliberately not committed,
   mostly for AIRT-0008, AIRT-0033 and AIRT-0018. Each carries its sourcing label
   and the URL it came from. Treat `inferred` rows as unverified regardless of
   how plausible they read. Note that the Cursor macOS target has research but
   **no** adversarial pass - its verifier died mid-run - so it is single-source.
4. **The decisive MSIX experiment.** Install Claude Desktop's MSIX on a Windows
   host with **no** pre-existing `%APPDATA%\Claude`, launch it once, and observe
   where `claude_desktop_config.json` is created. That settles whether the
   container copy wins on a clean packaged install, which is currently reasoned
   from Microsoft's documented mechanism rather than observed. It has not been
   run; do not let anyone tell you it has.
5. **macOS rows across the catalog.** Nothing has been host-verified on macOS.
   Row-level `last_verified` now makes that visible in the data rather than only
   in prose, so the gap is auditable - `grep -L last_verified` per row is the
   query. LM Studio has a known macOS discrepancy on record (bug-tracker #1371).
6. **Port the UI improvements into `build_site.py`.** A `/` search shortcut,
   active-filter chips, copy-path buttons and a sticky table header are all worth
   having. The site is generated and **never hand-edited**, so they go in the
   generator. Do not accept a hand-written `index.html` as a starting point: the
   one offered carried three catalogue claims that were wrong, including a
   `medium` MSIX row displayed as `High`.
7. **Quarterly re-verification.** Paths change between tool releases. A catalog
   nobody re-verifies decays into a liability, which is worse than one that never
   existed, because people trust it.

**The query that actually finds things** is not the medium-confidence list. It is
*entries with a HIT and an unexplained MISS on the same host* - a path that
misses while the tool is demonstrably present. That found the Cursor, LM Studio
and Open WebUI corrections. A staleness gate cannot see a wrong path, so a `high`
entry with a fresh `last_verified` can still be wrong: AIRT-0018 was checked the
previous day and had three wrong `high` paths.

## Reference

- `artifacts/README.md` — the catalog itself
- `skills/agent-artifact-catalog/SKILL.md` — the authoring workflow
- `artifacts/docs/VERIFICATION.md` — audit trail of every correction so far
- `artifacts/docs/REVERIFICATION.md` — the quarterly re-verification checklist
- `artifacts/docs/HOST_VERIFICATION.md` — how to verify paths on a real machine
- `artifacts/docs/HANDOFF_REVIEW.md` — what was decided about the site design
  handoff, what was declined, and why
- `artifacts/docs/EXTRACTION.md` — how to split this into its own repo, and when
- `CONTRIBUTING.md` — submission rules for entries, detections, and case studies
