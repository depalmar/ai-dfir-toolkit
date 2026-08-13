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
the staleness check.

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
the entry and raise its confidence.

## Current state

45 entries, 265 artifacts, 152 credential locations, 17 MCP config
locations, 12 endpoint Sigma rules, 14 case studies. Validation clean.

Detection content totals 68 rule files / 159 signatures across the nine attack-class
directories plus `artifacts/detections/`, all indexed in `MAPPINGS.md`.

Confidence: 28 high, 13 medium, 4 low.
Risk: 11 critical, 22 high, 10 medium, 2 low.

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
- `artifacts/docs/HANDOFF_REVIEW.md` — what was decided about the site design
  handoff, what was declined, and why
- `artifacts/docs/EXTRACTION.md` — how to split this into its own repo, and when
- `CONTRIBUTING.md` — submission rules for entries, detections, and case studies
