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

This is the highest-value work available, because 13 entries are `medium` and 4
are `low` purely because they were sourced from documentation rather than from a
live host.

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
does the sweep - it stats paths and never opens them, so it cannot leak a token.

A MISS from that script is not evidence a path is wrong. It cannot tell a wrong
path from an absent tool, and many of these paths are created lazily on first
run rather than at install time. Install the tool, run it once, then re-check.

## Current state

51 entries, 340 artifacts, 156 credential locations, 61 MCP config
locations, 12 endpoint Sigma rules, 14 case studies, 9 telemetry sources.
Validation clean.

Volatility across the 557 site rows: live 106 · rotating 45 · stable 406

Detection content maps to the OWASP LLM Top 10 **2026** list. Eight of the ten
IDs changed meaning between 2025 and 2026, so an ID quoted from an older report
names a different category here than it did there -
`scripts/remap_owasp_2026.py` holds the mapping table and the reasoning.

Detection content totals 68 rule files / 159 signatures across the nine attack-class
directories plus `artifacts/detections/`, all indexed in `MAPPINGS.md`.

Confidence: 28 high, 19 medium, 4 low.
Provenance: 51/51 entries carry a reference. AIRT-0034 was the last holdout and
sourcing it turned up a correction rather than a citation - Operator is EOL and
its only network indicator was a domain that had been sunset. 28/51 carry aliases.
40/51 carry `last_verified`, and `validate.py` lists the other 11 as never
verified rather than letting them look fresh.

That set was previously described here as "vendor-hosted entries that could not
be checked through a repository API". That was wrong, and worth correcting
because this file loads into every session. Only three of the eleven are
vendor-hosted - Devin, Copilot Studio and the Claude computer-use demo. The rest
are installable software: **Cursor** and **Claude Desktop**, the two most widely
deployed entries in the catalog, plus Windsurf, Tabnine, Kiro, Amazon Q, Open
WebUI and vLLM. They are unverified because nobody has checked them, not because
they cannot be checked.
Risk: 11 critical, 24 high, 12 medium, 2 low.

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

1. **Verify the medium-confidence entries** against real installs. Note this
   buys row-level honesty rather than entry upgrades: most medium rows sit inside
   entries already rated `high`, so expect few confidence changes.
2. **Wave 3 tools** — see `artifacts/BACKLOG.md`. Prioritise the ones that open
   a listener or store plaintext credentials (vLLM, Warp, Letta, Docker Model
   Runner), because those produce findings rather than inventory.
3. **Quarterly re-verification.** Paths change between tool releases. A catalog
   nobody re-verifies decays into a liability, which is worse than one that never
   existed, because people trust it.

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
