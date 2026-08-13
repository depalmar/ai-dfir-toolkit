# Quarterly re-verification checklist

The catalog's own documentation calls this the existential maintenance task:

> A catalog nobody re-verifies degrades quietly into a liability, which is worse
> than one that never existed, because people trust it.

The failure mode is silent. A stale path does not announce itself — it produces a
detection that never fires, or sends a responder to a directory that moved two
releases ago. This checklist exists so the pass is repeatable rather than
remembered, and so partial progress is still worth a pull request.

Cadence: **quarterly**. Monthly is not sustainable for a side project; annual is
too slow for this ecosystem's release pace.

## Before you start

Record the pass in `docs/VERIFICATION.md` as you go, not at the end. The audit
trail is the deliverable — an entry that changed without a recorded basis is
indistinguishable from an entry somebody guessed at.

## 1. Automated checks (5 minutes)

```bash
cd artifacts
python scripts/validate.py                  # schema, honesty gate, note style, refs coverage
python scripts/build_site.py --check        # site data contract, case-study provenance
python scripts/export_kape.py --check       # KAPE targets still render and agree with the catalog
python scripts/export_velociraptor.py --check
python ../artifacts/scripts/validate_mappings.py   # from the repo root
```

Then regenerate the feeds and confirm nothing drifted:

```bash
python scripts/export.py && python scripts/export_forensicartifacts.py
python scripts/export_kape.py && python scripts/export_velociraptor.py
git diff --stat docs/api          # empty means the feeds match the catalog
```

`validate.py` prints the provenance coverage every run. If the unsourced list has
grown, a new entry shipped without recording where its facts came from.

## 2. Lifecycle sweep (30 minutes, highest value per minute)

For every entry, confirm the project is still what the entry says it is. Renames
and shutdowns are the most common form of decay and the cheapest to catch:

- Is the repository still at the URL in `references`? Owners move.
  Recent examples: `block/goose` → `aaif-goose/goose`,
  `All-Hands-AI/OpenHands` → `OpenHands/OpenHands`.
- Is it archived, in maintenance mode, or shut down? Set `status` and say so in
  the description. The entry stays — an unmaintained tool is still installed on
  hosts and still leaves every artifact listed — but a reader must not be left to
  assume it is current.
- Has it been renamed? Add the former name to `aliases` so a search for it still
  lands somewhere.

## 3. Path verification (as much as you can do on a real host)

This can only be done on a real machine, which is why it is the work that most
needs volunteers. Check existence, permissions and structure:

```bash
ls -la ~/.codex/
stat -c "%a %n" ~/.codex/auth.json
jq 'keys' ~/.claude/settings.json
```

**Never read credential file contents.** `~/.claude/.credentials.json`,
`~/.codex/auth.json` and `~/.gemini/oauth_creds.json` hold live tokens. The
forensic question is "does this exist and what mode is it". Do not `cat` anything
holding a token.

Prioritise:

1. `confidence: high` entries — these are the ones consumers trust most, so drift
   hurts most.
2. Entries whose tool has shipped a major version since the last pass.
3. `medium` and `low` entries, where verification also raises confidence.

When a documented path and reality disagree, that is the interesting result.
Record it in `docs/VERIFICATION.md` with the basis, then update the entry.

## 4. Detection content

- Sigma rules still convert: `validate.py` covers parse; CI converts to a
  backend to prove it.
- YARA fixtures still match, and the benign control still does not:
  `tests/validate.sh`.
- Any rule referencing a path that moved in step 3 needs updating in the same
  pull request.

## 5. Case studies

- Do the `detections:` on each case still name rules that exist? `--check` gates
  this.
- Has anything in a `contested:` block been resolved since? An analytic
  disagreement that has since settled should be recorded as settled.
- Are any references dead? A vendor blog post that has been taken down is worth
  replacing with an archive link.

## 6. Record the pass

Add a section to `docs/VERIFICATION.md`:

```
## Verification Pass N - <month year>

| Scope | Field | Was | Now | Basis |
```

Include the entries you checked and found **unchanged**, not only the ones you
corrected. "Re-confirmed, no change" is a result, and without it the next pass
cannot tell what has already been looked at.

Finally, update the counts in `CLAUDE.md` under **Current state**.
