#!/usr/bin/env python3
"""Regenerate the index tables at the foot of MAPPINGS.md from the pinned frameworks.

    python scripts/sync_mappings.py           # rewrite the indexes in place
    python scripts/sync_mappings.py --check   # exit 1 if they are stale, write nothing

The per-rule tables above the indexes are curated by hand - which technique a
rule detects is a judgement. The indexes below them are not: they are a count of
those judgements plus a title lookup, and they had drifted. T0010.002 was titled
"Software Supply Chain" where ATLAS says "Data", T0018 "Poison AI Model" where
ATLAS says "Manipulate AI Model", and T0104 was still listed a release after ATLAS
folded it into T0115. A count and a lookup are exactly the kind of thing that
should be derived, so they are.

--check also enforces that every ATLAS id a rule tags itself with appears in its
MAPPINGS row (a parent tag is satisfied by one of its sub-techniques). The two
sources disagreed on a third of the multi-technique rules, and the site shows the
union, so a MAPPINGS row that omits a rule's own tag understates coverage in the
one table people read.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import site_data  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
MAPPINGS = ROOT.parent / "MAPPINGS.md"
MARKER = "## ATLAS Technique Index"

LLM_PROSE = """Remapped from the 2025 list on 2026-08-13, against the 2026 publication of
2026-08-04. Eight of the ten IDs changed meaning between the two editions, so a
2025 ID read as a 2026 one names the wrong category - `LLM03` was Supply Chain
and is now Excessive Agency. Categories with no rule are listed so the gaps are
visible rather than merely absent."""

ASI_PROSE = """The OWASP Top 10 for Agentic Applications (December 2025) names the risks that
exist because an application acts - holds tools, credentials and memory - rather
than only answers. The per-rule ASI values above are this project's assessment of
which risk a rule gives evidence of, not an OWASP mapping; OWASP publishes none
for detection content. A dash means the rule detects something the agentic list
does not cover, usually an adversary *using* AI rather than an agentic
application being attacked. The related LLM IDs are OWASP's own Appendix A cross-
map, which cites the 2025 list, translated to 2026 IDs through
`artifacts/schema/owasp.json`."""


def load_pins():
    tech = json.loads((ROOT / "schema" / "technique-ids.json").read_text(encoding="utf-8"))
    owasp = json.loads((ROOT / "schema" / "owasp.json").read_text(encoding="utf-8"))
    return tech, owasp


def atlas_title(atlas: dict, ident: str) -> str:
    name = atlas["techniques"].get(ident, "")
    parent, _, sub = ident.rpartition(".")
    if len(sub) == 3 and sub.isdigit() and parent in atlas["techniques"]:
        return f"{atlas['techniques'][parent]}: {name}"
    return name


def render(rows: dict, tech: dict, owasp: dict) -> str:
    atlas = tech["atlas"]
    counts: dict[str, int] = {}
    llm: dict[str, int] = {}
    asi: dict[str, int] = {}
    for row in rows.values():
        for raw in row["atlas"]:
            ident = site_data._norm_atlas(raw)
            if ident:
                counts[ident] = counts.get(ident, 0) + 1
        for raw in row["owasp"]:
            ident = site_data._norm_owasp(raw)
            if ident:
                llm[ident] = llm.get(ident, 0) + 1
        for raw in row.get("asi", []):
            ident = site_data._norm_asi(raw)
            if ident:
                asi[ident] = asi.get(ident, 0) + 1

    out = [MARKER, "",
           f"Titles are ATLAS {atlas['release']} names, generated from "
           f"`artifacts/schema/technique-ids.json` by `artifacts/scripts/sync_mappings.py`.",
           "", "| ATLAS ID | Title | Tactic | Rule count |",
           "|----------|-------|--------|------------|"]
    for ident in sorted(counts):
        tactics = ", ".join(atlas["tactics"].get(t, t)
                            for t in atlas.get("technique_tactics", {}).get(ident, []))
        out.append(f"| {ident[4:]:<8} | {atlas_title(atlas, ident)} | {tactics} | {counts[ident]} |")

    items = owasp["llm_2026"]["items"]
    out += ["", "## OWASP Top 10 for LLM Applications 2026 Index", "", LLM_PROSE, "",
            "| OWASP | Title | Rule count | Was in 2025 |",
            "|-------|-------|------------|-------------|"]
    for ident, it in items.items():
        was = it["was_2025"] + (f", {it['note']}" if it.get("note") else "")
        out.append(f"| {ident:<8} | {it['title']} | {llm.get(ident, 0)} | {was} |")

    ag = owasp["agentic_2026"]["items"]
    out += ["", "## OWASP Top 10 for Agentic Applications 2026 Index", "", ASI_PROSE, "",
            "| ASI | Title | Rule count | Related LLM (2026) |",
            "|-----|-------|------------|--------------------|"]
    for ident, it in ag.items():
        out.append(f"| {ident} | {it['title']} | {asi.get(ident, 0)} | "
                   f"{', '.join(it['related_llm_2026'])} |")
    return "\n".join(out) + "\n"


def tag_problems(rows: dict) -> list[str]:
    problems = []
    for rule in site_data.load_rules({}):
        row = rows.get(rule["file"])
        if row is None:
            problems.append(f"{rule['path']}: no row in MAPPINGS.md")
            continue
        listed = {site_data._norm_atlas(x) for x in row["atlas"]} - {""}
        for ident in rule["atlas"]:
            covered = ident in listed or any(x.startswith(ident + ".") for x in listed)
            if not covered:
                problems.append(f"{rule['path']}: tagged {ident} but its MAPPINGS row "
                                f"lists {', '.join(sorted(listed)) or 'nothing'}")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    tech, owasp = load_pins()
    rows, _, _ = site_data.load_mappings()
    text = MAPPINGS.read_text(encoding="utf-8")
    head = text[:text.index(MARKER)] if MARKER in text else text.rstrip() + "\n\n---\n\n"
    new = head + render(rows, tech, owasp)
    problems = tag_problems(rows)
    if args.check:
        if new != text:
            problems.append("MAPPINGS.md indexes are stale - run scripts/sync_mappings.py")
    elif new != text:
        with open(MAPPINGS, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(new)
        print("MAPPINGS.md indexes regenerated")
    for p in problems:
        print(f"[MAP]    {p}")
    print(f"{len(problems)} problem(s).")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
