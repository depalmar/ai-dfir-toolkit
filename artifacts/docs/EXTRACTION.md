# Extracting this catalog into its own repository

The catalog lives inside `ai-dfir-toolkit` because that repo already exists and
is already maintained, and because a catalog nobody re-verifies degrades into a
liability. Fewer repos means the quarterly verification pass actually happens.

It is deliberately built so that decision can be reversed cheaply.

## Why it would be worth extracting

Split it out if any of these become true:

- **External contributors appear.** A steady stream of entry PRs from people
  outside the project justifies its own issue tracker and review cadence.
- **Upstream interest.** If ForensicArtifacts, a SIEM vendor, or another catalog
  wants to ingest the data on a schedule, a standalone repo with its own release
  tags is easier for them to depend on than a subdirectory.
- **Formal citation.** GitHub renders `CITATION.cff` only at repository root. If
  the catalog needs to be cited independently in published work rather than as
  part of the toolkit, it needs its own root.
- **Divergent cadence.** If catalog updates start blocking or being blocked by
  toolkit releases, they want separate version histories.

## Why it is cheap to do later

Everything the catalog needs is inside `artifacts/`:

- Scripts resolve paths relative to themselves (`Path(__file__).parent.parent`),
  so they work unchanged at any depth.
- The schema, template, validator, exporters, and CI job are all self-contained.
- `LICENSE-DATA` already scopes the data licence to this directory.
- Entry IDs use an opaque `AIRT-` prefix with no repository name in it.

## How to do it, preserving history

```bash
git subtree split --prefix=artifacts -b artifact-catalog
cd .. && git init ai-agent-artifacts && cd ai-agent-artifacts
git pull ../ai-dfir-toolkit artifact-catalog
```

Then:

1. Move `skills/agent-artifact-catalog/` across.
2. Move the CI workflow to `.github/workflows/` and drop the `working-directory`
   and path filter.
3. Add `CITATION.cff` at the new root.
4. Leave a pointer in `ai-dfir-toolkit/artifacts/README.md` so existing links
   still resolve.

## What must not change on extraction

**Entry IDs.** `AIRT-0011` stays `AIRT-0011` regardless of where the catalog
lives. Once a detection, report, or paper cites an ID, renumbering silently
breaks the reference. The prefix is opaque on purpose so it survives a move and
a rename.
