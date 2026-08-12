# Handoff Review — site UI enhancement (round 2)

Review of `design_handoff_catalog_site/README.md` before implementation. The spec
is strong: high-fidelity tokens, an explicit data contract, and the no-framework
constraint stated up front rather than discovered halfway through. The findings
below are things worth settling before code gets written, ordered by cost of
getting them wrong.

---

## 1. Do not mutate `artifacts.csv` — BLOCKING


The handoff says, under implementation order:

> keep `docs/api/artifacts.csv` in sync if the locator merges change it

**`artifacts.csv` is a published feed.** It is documented in the README as a
consumer API, it is attached to releases so people can pin a version, and the
whole reason exports exist is so the on-disk YAML can change without breaking
downstream users. Changing the `artifact` column from a bare path to
`"<key> → <value>"` is a breaking schema change to that feed, delivered silently
in a UI commit.

**Do the merging in `site_data.py` only.** The site needs a merged display
locator; the CSV consumer needs a stable column. Those are different needs and
should stay different fields.

If merged locators genuinely belong in the feed, add them as *new* columns
(`locator`, `evidence_type_list`) and leave `artifact` alone. Additive is safe,
in-place is not.

Same applies to `evidence_type`. Keep it pipe-joined in the CSV, keep it a list
in the site payload. `site_data.py` already does this.

---

## 2. Inlining every rule YAML body — reconsider, but the cost is smaller than stated

The handoff estimates 100–150 KB for inlined rule bodies and calls it "still fine
for one file." Two corrections, pulling in opposite directions:

**It is cheaper than it sounds.** YAML this repetitive compresses roughly 4:1, so
150 KB of source is ~40 KB over the wire with gzip, which GitHub Pages applies
automatically. As a JS string constant it never touches the DOM, so there is no
layout or parse cost beyond the initial script evaluation.

**But most of it is never read.** The drawer shows detection logic. Nobody opens
a drawer to read a rule's `author`, `references`, `falsepositives` preamble, or
licence header. Inlining whole files pays full weight for content the UI does not
surface.

**Recommendation:** inline the `detection:` and `logsource:` blocks only, plus
`level` and `description` which the drawer already displays separately. Link to
GitHub for the full file — which the drawer does anyway. That is roughly half the
payload for all of the value, and it makes the "Detection logic" block tighter to
read, since it is the logic rather than the logic buried in metadata.

Worth measuring rather than guessing: build it both ways and compare gzipped
size before committing to either.

---

## 3. The "15 missing files" finding is wrong — do not build the amber state

The handoff reports that MAPPINGS.md lists 15 `.yar`/`.rules` files absent from
the repo, and specifies an amber "missing" state in the Detections view with
GitHub links disabled.

**Verified against the repository on 2026-08-12: all 43 files referenced by
MAPPINGS.md exist.** Every `.yar` and every `.rules` file resolves. Directory
counts: `01-llm-prompt-injection` 8, `02-mcp-attacks` 5,
`03-model-supply-chain` 8, `04-ai-infrastructure` 9,
`05-copilot-assistant-abuse` 8, `06-rag-vector-db` 5 — 43 exactly, matching the
header count in MAPPINGS.md.

`scripts/validate_mappings.py` reports **0 dangling references**.

The likely cause of the false finding is that the design tool resolved references
against directory names it guessed rather than the real ones. MAPPINGS.md cites
**bare filenames**, not paths, and the actual directories are
`01-llm-prompt-injection`, `03-model-supply-chain`, `04-ai-infrastructure`,
`06-rag-vector-db` — not the `03-model-theft` / `04-c2` / `06-supply-chain`
shapes a reader might assume from the section headings.

**Do not implement the amber state.** It would be dead code guarding a condition
that does not exist, and worse, it would render 15 healthy rules as broken to
every visitor.

The real drift is one-directional and smaller: 12 unindexed rules (below).

---

## 3b. The real drift: 12 unindexed Sigma rules

`artifacts/detections/sigma/` holds 12 cross-tool endpoint rules that MAPPINGS.md
never indexes, and the osquery pack is likewise absent. Consequences:

- The ATLAS and OWASP coverage tables undercount. `AML.T0053` (AI Agent Tool
  Invocation) and `AML.T0110` (AI Agent Tool Poisoning) in particular are
  under-represented, since several endpoint rules map to them.
- MAPPINGS.md's header says "43 rule files"; the true figure is 55.
- The handoff's proposed "detections" header stat would ship wrong.

These rules are a different shape from the 43 — they are cross-tool and
endpoint-oriented rather than scoped to one attack class — so a separate
**"Endpoint (cross-tool)"** section is the right home, which is what the design
handoff already proposes for the Detections view. Give the osquery pack a line
too; it answers the inventory question the Sigma rules cannot.

## 4. `evidence_type` is empty on a third of rows — the handoff missed this

The drawer's "What it proves" section renders one chip per evidence type. But
only `disk` artifacts carry `evidence_type` in the schema. Registry, network, and
process artifacts do not.

That is **107 of 298 rows (36%)** where the section renders empty.

`site_data.py` now derives it deterministically from fields that already exist:

| Class | Derivation |
|---|---|
| registry | `configuration`, plus `persistence` when `persistence: true` |
| network | `program-presence`, plus `configuration` for listeners |
| process | `execution` + `program-presence`, plus `persistence` when set |
| credential | `credential-access` |
| mcp | `execution` + `persistence` |

Verified: 0 rows with empty evidence types.

**The durable fix is extending the schema** so these are declared rather than
inferred. Derivation is correct today because the source fields are unambiguous,
but a hand-authored registry artifact that proves something unusual cannot say so.
Worth doing when the schema is next touched.

---

## 5. `localStorage` keys carry dead branding

The handoff specifies `localStorage['aiart-theme']` and `localStorage['aiart-picks']`.

`aiart-` is a fossil of the AIRTIFACTS working name, which was dropped when the
catalog folded into this repo. Nothing in the project is called that any more.

Low stakes, but the site is already live, so renaming now silently discards
existing users' saved theme and picks. Either accept that (the audience is tiny
and it is day two), or read the old key once and migrate. Do not leave it
undecided — a stale prefix invites someone to "fix" it later, after the cost has
grown.

Suggestion: `aidfir-theme` / `aidfir-picks`, with a one-time migration read.

---

## 6. Accessibility items the handoff flags but leaves open

The spec is unusually good on accessibility — `aria-pressed` on facets,
`role="dialog"` on the drawer, keyboard-reachable rows, severity never encoded in
colour alone. Three items are listed as outstanding and should not be dropped:

- **`aria-sort` on sortable headers.** Cheap; a screen reader user otherwise has
  no idea the table is sorted, or by what.
- **Focus return to the originating row on drawer close.** Without it, closing
  the drawer dumps focus at the top of the document and the user loses their
  place in a 298-row table. This is the one that actually hurts.
- **The tablist semantics question.** The handoff is right: if the header link to
  the guide sits inside `role="tablist"` it must be a real tab or move out. A
  link inside a tablist breaks arrow-key navigation.

---

## 7. Facet counts excluding own-group selections — correct, and worth protecting

The spec calls for counts computed excluding that group's own selections, which
is standard faceted-search behaviour and the right call. It is also the single
easiest thing to regress during a refactor, because the naive implementation
(count the filtered set) looks correct until you select two values in one group
and watch every count drop to zero.

Worth a comment in the JS saying why the filter is applied group-wise, so nobody
"simplifies" it later.

---

## 8. Smaller notes

- **Search across 298 rows needs no debouncing.** The handoff already says only
  consider it past ~2k rows. Agreed — do not add it now.
- **Header stat "detections" depends on MAPPINGS being correct.** Fix the data
  before wiring the stat, or the number ships wrong.
- **`#rule/<file>` deep links** should use the repo-relative path, not the bare
  filename — two rule directories could plausibly hold the same filename.
- **Pre-paint theme script** is correct and easy to get wrong. It must be inline
  in `<head>` and set `data-theme` before the stylesheet resolves, or dark-mode
  users get a white flash on every navigation.
- **`prefers-reduced-motion`** is not mentioned. The drawer slides in; honour it.
- **The osquery pack** is mentioned as "at minimum a link." It deserves better —
  it is the inventory half of the detection story and answers a different question
  than the Sigma rules ("which hosts have this" vs "alert when this happens").

---

## Recommended order

The handoff's own implementation order is sound. One change: move the data fixes
ahead of everything visual.

0. **Add the 12 endpoint Sigma rules to MAPPINGS.md** and wire
   `validate_mappings.py` into CI so drift cannot recur. There are no dangling
   references to fix — see finding 3.
1. Wire in `site_data.py` — the data contract, anchors, derived evidence types.
   Confirm `python scripts/site_data.py --check` reports 0 problems.
2. Then the handoff's steps 2–10 as written.

Steps 0 and 1 are prerequisites for the header stats, the Detections view, and
the Mappings coverage tables all being *correct*. Building those views on drifted
data means rebuilding them.

---

## Resolution — August 2026

What was actually applied, including the two items deliberately left alone. The
review above is the reasoning; this section is the outcome, so a later reader
does not re-litigate a decision or re-implement something that was declined.

| Finding | Outcome |
|---|---|
| 1. Do not mutate `artifacts.csv` | **Held.** The published columns are untouched. Locator merging happens in `build_site.py:build_rows` only, so the feed and the site can disagree in shape without either breaking. |
| 2. Inline whole rule bodies | **As built.** The drawer inlines full bodies; measured cost is a 733 KB page, ~4:1 compressible, served once. Revisit if the corpus grows past a few hundred rules. |
| 3. "15 missing rule files" | **Confirmed wrong.** `validate_mappings.py` reports 0 dangling references against 55 files. No amber state was built. |
| 3b. 12 unindexed Sigma rules | **Fixed.** Added as `## 07 — Endpoint (cross-tool)` with the osquery pack noted. MAPPINGS now indexes 55 files / 126 signatures. |
| 4. Empty `evidence_type` on ~36% of rows | **Confirmed and fixed.** Reproduced exactly: 107 of 298 rows (network 52, process 37, registry 18) rendered an empty "what it proves". `build_site.py:evidence_for` now derives them, and `--check` enforces both that no row is empty and that no value falls outside the schema's `evidence_type` enum. Credential rows moved from `secret_type` to `credential-access`, with storage and secret type preserved in the description — `secret_type` answers "what is it", not "what does it prove". The durable fix, declaring `evidence_type` on the registry, network and process types in the schema, is still worth doing when the schema is next touched. |
| 5. `aiart-` localStorage prefix | **Renamed** to `aidfir-theme` / `aidfir-picks`, each reading the old key once so a returning visitor keeps their theme and picks. |
| 6. `aria-sort`, focus return, tablist | `aria-sort` and drawer focus return were **already implemented**. The tablist was **fixed**: the guide link is now a real tab, with roving tabindex, arrow/Home/End navigation, and `aria-controls` onto a `role="tabpanel"` container. |
| 7. Facet counts exclude own group | **As built**, with the rationale commented in the JS. |
| 8. `#rule/<file>` deep links | **Fixed.** Permalinks now use the repo-relative path; bare filenames still resolve, so links shared before this change keep working. `#guide` also deep-links now, which it silently did not before. |
| 8. `prefers-reduced-motion` | **Deliberately not added.** The review inherited this from the handoff's sliding drawer, but the drawer as implemented has no transition, and the page has no animation, transition, or smooth scroll anywhere. A media query here would guard a condition that does not exist — the same objection the review itself raises against the amber state in finding 3. Add it with the animation, if one is ever added. |

### Corrections to the review itself

**`site_data.py --check` does not exist.** The review's step 1 assumes the
`site_data.py` from the round-2 patch, which builds ROWS/TOOLS and validates
anchors. The repository moved past it: that logic now lives in `build_site.py`,
and `site_data.py` is the loader for everything *outside* the catalog — rules,
the ATLAS/OWASP indexes, case studies, the guide. Applying the patch copy would
have reverted working code. The data-contract check was added to
`build_site.py --check` instead, and that is what CI runs.

**MAPPINGS.md had seven pre-existing miscounts.** Indexing the 12 new rules also
required recounting, which surfaced hand-maintained errors unrelated to this
change: ATLAS `T0010` (10→8), `T0020` (4→3), `T0024` (7→6 before the new rules),
and OWASP `LLM03` (11→9), `LLM06` (5→4), `LLM07` (2→3), plus a missing `T0051`
row. Four rows were absent entirely — `T0051`, `T0053`, `T0081`, `T0082`. The
index is now derived from the tables and verified to match them exactly.
`AML.T0081` (Modify AI Agent Configuration) and `AML.T0082` (RAG Credential
Harvesting) were confirmed against MITRE ATLAS before being added; `AML.T0053`
was already confirmed in `VERIFICATION.md`.

**The proposed process-persistence derivation was wrong on this data.** The
review's version treats a process as persistent unless its `persistence` value
is exactly `none`, `no` or `-`. That field is free text, and the catalog holds
`None (user-invoked)`, `None - PORTABLE SINGLE BINARY` and `None` — so three
rows that explicitly state they do not persist would have been published as
proving persistence. The implemented version matches on the leading word.
Worth remembering the next time a derivation is written against a free-text
field: the enum-shaped values are the ones that will be tested, and the prose
ones are the ones that will be wrong.
