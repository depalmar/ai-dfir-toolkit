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
python ../skills/agent-artifact-catalog/scripts/new_entry.py "Tool Name"
```

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

**Controlled vocabularies.** `artifact_type`, `evidence_type`, `secret_type`,
and `storage` are closed enums in `schema/artifact.schema.json`. They exist
because the published CSV feed is meant to be filtered, and a field where `log`
and `logs` and `logfile` coexist cannot be. If something genuinely does not fit,
extend the schema, the template, and the skill together.

**Detections are Sigma only.** No SPL, no KQL, no vendor dialect. One rule
converts to any SIEM, and shipping a vendor dialect would both force a platform
choice on everyone downstream and imply an affiliation this project does not
have. Verify with `sigma convert -t splunk detections/sigma/<rule>.yml`.

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

44 entries, 258 artifacts, 23 credential locations, 17 MCP config locations,
12 Sigma rules, 3 case studies. Validation clean.

Confidence: 27 high, 13 medium, 4 low.
Risk: 11 critical, 21 high, 10 medium, 2 low.

## What is next, in priority order

1. **Verify the 13 medium-confidence entries** against real installs. Highest
   value, and only possible on a real machine.
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
- `artifacts/docs/EXTRACTION.md` — how to split this into its own repo, and when
- `PUBLISH_TODAY.md` — the publish runbook
