#!/usr/bin/env python3
"""Hunts: what to go looking for where an alert would be wrong, or where no
rule exists.

Derived, never authored. A hunt comes from one of two places that already
exist, so the list cannot drift from the content it summarises:

  rule       A Sigma rule whose own `level` is low or informational. That is
             the author's statement that a match is not an alert: it needs a
             baseline, and somebody reads the results.
  behaviour  A `behavior` indicator on a case study. It describes what the
             activity looked like, in words, because there was no value to
             publish - which is exactly what a hunt is.

There are no queries here and there never will be. A rule hunt is a Sigma rule
and converts to any backend; a behaviour hunt is prose. Shipping a vendor query
dialect would break the rule this project is strictest about.

What is deliberately not derived: which rule "covers" a behaviour. A case links
rules, and a behaviour belongs to a case, but nothing in the data says a given
rule matches a given behaviour, so the page shows the case's rules as rules for
the case and says so.
"""

import hashlib
import re

HUNT_LEVELS = ("low", "informational")

_ANCHOR_OK = re.compile(r"^[A-Za-z0-9._-]+$")


def _flat(text):
    return re.sub(r"\s+", " ", str(text or "")).strip()


def build(rules, cases, sources):
    """The hunts the page shows, from the rules, cases and sources it loaded."""
    cases_by_rule = {}
    for c in cases:
        for f in c.get("detections") or []:
            cases_by_rule.setdefault(f, []).append(c["id"])
    sources_by_rule = {}
    for s in sources:
        for f in s.get("rules") or []:
            sources_by_rule.setdefault(f, []).append({"id": s["id"], "name": s["name"]})

    # What a case's hunts read, through the detections it links. Sigma only: a
    # YARA or Suricata rule has no log source, and the string the loader keeps
    # in that field for them is a description, not something to filter on.
    logsource_of = {r["file"]: r.get("logsource", "") for r in rules if r.get("format") == "Sigma"}

    rule_hunts = []
    for r in rules:
        if r.get("format") != "Sigma" or r.get("level") not in HUNT_LEVELS:
            continue
        rule_hunts.append({
            "anchor": "hunt-" + re.sub(r"[^A-Za-z0-9_-]", "-", r["file"].rsplit(".", 1)[0]),
            "title": r["title"],
            "file": r["file"],
            "path": r["path"],
            "level": r["level"],
            "look_for": _flat(r.get("description")),
            "logsource": r.get("logsource", ""),
            "category": r.get("category", ""),
            "sources": sources_by_rule.get(r["file"], []),
            "cases": cases_by_rule.get(r["file"], []),
        })
    rule_hunts.sort(key=lambda h: h["title"].lower())

    groups = []
    for c in sorted(cases, key=lambda c: (str(c.get("disclosed", "")), c["id"]), reverse=True):
        items = []
        for i in c.get("iocs") or []:
            if i.get("type") != "behavior":
                continue
            value = _flat(i.get("value"))
            digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:8]
            items.append({
                # Hashed from the text, not numbered: a permalink must not move
                # to a different behaviour when one is inserted above it.
                "anchor": f"hunt-{c['id'].lower()}-{digest}",
                "look_for": value,
                "why": _flat(i.get("description")),
            })
        if items:
            groups.append({
                "case": c["id"],
                "title": c.get("title", ""),
                "disclosed": str(c.get("disclosed", "")),
                "confidence": c.get("confidence", ""),
                "rules": list(c.get("detections") or []),
                # Derived, for the Reads filter. Not published in any feed.
                "logsources": sorted({logsource_of[f] for f in (c.get("detections") or [])
                                      if logsource_of.get(f)}),
                "items": items,
            })

    n_beh = sum(len(g["items"]) for g in groups)
    return {
        "rules": rule_hunts,
        "behaviours": groups,
        "stats": {
            "rule_hunts": len(rule_hunts),
            "behaviours": n_beh,
            "cases": len(groups),
            "cases_no_rule": sum(1 for g in groups if not g["rules"]),
            "total": len(rule_hunts) + n_beh,
        },
    }


def check(hunts, rules, cases):
    """Problems as strings. Anchors are what a permalink is stored against."""
    problems = []
    rule_files = {r["file"] for r in rules}
    case_ids = {c["id"] for c in cases}
    seen = {}
    anchors = [(h["anchor"], h["file"]) for h in hunts["rules"]]
    anchors += [(i["anchor"], g["case"]) for g in hunts["behaviours"] for i in g["items"]]
    for anchor, owner in anchors:
        if not _ANCHOR_OK.match(anchor):
            problems.append(f"[HUNT]    {owner}: anchor {anchor!r} is not URL-safe")
        if anchor in seen:
            problems.append(f"[HUNT]    {owner}: anchor {anchor} is also used by {seen[anchor]} - "
                            "two behaviours on one case have identical text")
        seen[anchor] = owner
    for h in hunts["rules"]:
        if h["file"] not in rule_files:
            problems.append(f"[HUNT]    {h['file']} is listed as a hunt but is not a loaded rule")
        for cid in h["cases"]:
            if cid not in case_ids:
                problems.append(f"[HUNT]    {h['file']} names case {cid}, which does not exist")
        if not h["look_for"]:
            problems.append(f"[HUNT]    {h['file']} has no description, so the hunt says nothing")
    known_ls = {r.get("logsource") for r in rules if r.get("format") == "Sigma" and r.get("logsource")}
    for g in hunts["behaviours"]:
        for ls in g.get("logsources", []):
            if ls not in known_ls:
                problems.append(f"[HUNT]    {g['case']} lists log source {ls!r}, which no loaded Sigma rule reads")
        for i in g["items"]:
            if not i["look_for"]:
                problems.append(f"[HUNT]    {g['case']} has a behaviour with no text")
    s = hunts["stats"]
    if s["total"] != len(anchors):
        problems.append("[HUNT]    the stats total disagrees with the number of hunts")
    return problems


if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import json
    import data_sources
    import site_data
    mapping_rows, _, _ = site_data.load_mappings()
    _rules = site_data.load_rules(mapping_rows)
    _cases = site_data.load_case_studies()
    _entries = json.loads((Path(__file__).resolve().parents[1] / "docs" / "api" / "catalog.json")
                          .read_text(encoding="utf-8"))
    _sources = data_sources.coverage(data_sources.load_sources(), _entries)["sources"]
    h = build(_rules, _cases, _sources)
    probs = check(h, _rules, _cases)
    s = h["stats"]
    print(f"{s['rule_hunts']} hunting rules, {s['behaviours']} behaviours from {s['cases']} cases "
          f"({s['cases_no_rule']} of those cases have no rule)")
    for p in probs:
        print(p)
    print(f"\n{len(probs)} problem(s).")
    sys.exit(1 if probs else 0)
