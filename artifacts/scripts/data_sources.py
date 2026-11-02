#!/usr/bin/env python3
"""Volatility per artifact, and the telemetry sources the catalog depends on.

Two questions the catalog could not previously answer:

  volatility   Will this artifact still be there when I get to the host, and
               what order do I collect in.
  sources      What did somebody have to switch on, before the incident, for
               this evidence to exist at all.

Both are derived rather than authored, for the same reason the KAPE and
Velociraptor exporters are: a hand-maintained coverage table is correct on the
day it is written and silently wrong afterwards. Volatility falls out of the row
class and the artifact type. Source coverage falls out of the catalog and the
rule corpus, matched against the prose in docs/data-sources.yml.

A source claims coverage through five derived dimensions, all matched against
the corpus rather than counted by hand:
  classes    row classes it makes visible, optionally narrowed by `os` so a
             macOS-only source is not credited with Windows rows
  sigma      Sigma logsource categories it satisfies
  eventlog   [channel, event_id] pairs
  hosts      hostnames (or parent domains) that network rows name - this is how
             a provider's own audit log is tied to the tools that talk to it
  locators   locator prefixes such as <repo>, for sources that only exist where
             a row is scoped to a checkout

`audit()` is the gate. It fails when:
  - an eventlog row's channel and ID map to no defined source
  - a Sigma logsource category in the rule corpus maps to no defined source
  - a catalog row class maps to no defined source, on any OS its rows name
  - a source claims coverage - a class, an OS, a category, a channel, a host, a
    locator - that nothing in the corpus actually uses

The last one matters as much as the others. A source that over-claims makes the
coverage numbers look better than the estate does, which is the failure this
whole file exists to prevent.

Usage:
    python scripts/data_sources.py            # coverage report
    python scripts/data_sources.py --check    # audit only, exit 1 on a problem
"""
from __future__ import annotations

import argparse
import glob
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT.parent

# Volatility, in RFC 3227 order: collect the top of this list first.
#
# It is a property of the artifact class, not of the tool, which is why it is
# derived here rather than being a 507th field for an author to get wrong. The
# one exception is a disk row carrying an explicit `retention` - a tool that
# documents its own purge window is rotating whatever its artifact_type says,
# and that promotion is the reason the retention field earns its place.
VOLATILITY_ORDER = ["live", "rotating", "stable"]

VOLATILITY_MEANING = {
    "live": "Exists only while the process or socket does. Gone at exit or "
            "reboot, leaving nothing behind. Collect during triage or not at all.",
    "rotating": "Persisted, but ageing out on a schedule somebody else set - log "
                "rotation, channel wrap, or the tool pruning its own history.",
    "stable": "Survives reboot. Removed by uninstall or by deliberate deletion, "
              "not by time.",
}

# Disk artifact types that age out on their own. Everything else on disk sits
# there until the tool is removed.
_ROTATING_DISK_TYPES = {"log", "session-artifact"}


def volatility_of(cls: str, row: dict) -> str:
    """Which volatility tier one catalog row sits in."""
    if cls in ("process", "network"):
        return "live"
    if cls == "eventlog":
        return "rotating"
    if cls == "disk":
        # A documented purge window overrides the type. See goose: a session
        # store is a data-dir by type and a 14-day window by behaviour.
        if row.get("retention"):
            return "rotating"
        return "rotating" if row.get("artifact_type") in _ROTATING_DISK_TYPES else "stable"
    # registry, credential, mcp-config
    return "stable"


def load_sources() -> list[dict]:
    doc = yaml.safe_load((ROOT / "docs" / "data-sources.yml").read_text(encoding="utf-8"))
    return doc.get("sources") or []


def load_entries() -> list[dict]:
    return [yaml.safe_load(Path(f).read_text(encoding="utf-8"))
            for f in sorted(glob.glob(str(ROOT / "catalog" / "*.yml")))]


def sigma_categories() -> dict[str, list[str]]:
    """Every Sigma logsource category in the repo -> the rule files using it.

    Walks the repository root rather than artifacts/detections, because the nine
    attack-class directories at the top level hold most of the corpus. Same
    reason validate_mappings.py runs from there.
    """
    out: dict[str, list[str]] = {}
    seen: set[str] = set()
    for pattern in ("**/*.yml", "**/*.yaml"):
        for f in glob.glob(str(REPO / pattern), recursive=True):
            if "/detections" not in f.replace("\\", "/") and "/sigma" not in f.replace("\\", "/"):
                continue
            if f in seen:
                continue
            seen.add(f)
            try:
                doc = yaml.safe_load(Path(f).read_text(encoding="utf-8"))
            except (yaml.YAMLError, UnicodeDecodeError):
                continue
            if not isinstance(doc, dict) or "logsource" not in doc:
                continue
            cat = (doc.get("logsource") or {}).get("category")
            if cat:
                out.setdefault(cat, []).append(Path(f).name)
    return out


HOST_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b")
LOCATOR_RE = re.compile(r"^<(\w+)>")


def _os_of(row: dict, entry: dict, cls: str = "") -> list[str]:
    # A registry key or an event log channel is a Windows artifact whatever the
    # entry's supported_os says; the row rarely repeats the platform.
    if cls in ("registry", "eventlog"):
        return ["windows"]
    declared = [str(o).lower() for o in (row.get("os") or entry.get("supported_os") or [])]
    return declared or ["any"]


def coverage(sources: list[dict], entries: list[dict]) -> dict:
    """Count what each source actually makes visible. Derived, never authored."""
    cats = sigma_categories()

    # Every row once, with the facets a source can match on: class, OS, the
    # hostnames a network row names, and the locator prefix a scoped row starts
    # with. eventlog rows also carry their channel and ID.
    rows: list[dict] = []
    for e in entries:
        for cls, items in (e.get("artifacts") or {}).items():
            for row in items or []:
                loc = str(row.get("path") or row.get("key") or row.get("indicator") or
                          row.get("channel") or row.get("name") or "")
                rows.append({"cls": cls, "tool": e["name"], "entry_id": e["id"],
                             "os": _os_of(row, e, cls),
                             "hosts": HOST_RE.findall(loc.lower()) if cls == "network" else [],
                             "locator": (LOCATOR_RE.match(loc) or [None, ""])[1],
                             "channel": (row.get("channel"), str(row.get("event_id")))
                             if cls == "eventlog" else None})
        for c in e.get("credentials") or []:
            loc = str(c.get("location") or "")
            rows.append({"cls": "credential", "tool": e["name"], "entry_id": e["id"],
                         "os": _os_of(c, e), "hosts": [],
                         "locator": (LOCATOR_RE.match(loc) or [None, ""])[1], "channel": None})
        for m in e.get("mcp") or []:
            loc = str(m.get("config_path") or "")
            rows.append({"cls": "mcp-config", "tool": e["name"], "entry_id": e["id"],
                         "os": _os_of(m, e), "hosts": [],
                         "locator": (LOCATOR_RE.match(loc) or [None, ""])[1], "channel": None})

    per_class: dict[str, int] = {}
    class_os: dict[str, set] = {}
    channels: dict[tuple, int] = {}
    hosts_seen: set[str] = set()
    locators_seen: set[str] = set()
    for r in rows:
        per_class[r["cls"]] = per_class.get(r["cls"], 0) + 1
        class_os.setdefault(r["cls"], set()).update(r["os"])
        if r["channel"]:
            channels[r["channel"]] = channels.get(r["channel"], 0) + 1
        hosts_seen.update(r["hosts"])
        if r["locator"]:
            locators_seen.add(r["locator"])

    def host_hit(claimed: str, names: list[str]) -> bool:
        c = claimed.lower()
        return any(h == c or h.endswith("." + c) for h in names)

    out = []
    for s in sources:
        cov = s.get("covers") or {}
        classes = cov.get("classes") or []
        os_filter = [str(o).lower() for o in cov.get("os") or []]
        hosts = cov.get("hosts") or []
        locators = cov.get("locators") or []
        hit = []
        for r in rows:
            by_class = r["cls"] in classes and (not os_filter or
                                                 set(os_filter) & set(r["os"]))
            by_host = any(host_hit(h, r["hosts"]) for h in hosts)
            by_loc = r["locator"] in locators if r["locator"] else False
            if by_class or by_host or by_loc:
                hit.append(r)
        class_rows: dict[str, int] = {}
        for r in hit:
            class_rows[r["cls"]] = class_rows.get(r["cls"], 0) + 1
        # An eventlog source is credited with the rows whose channel and ID it
        # names, on top of any class it covers. Both are real coverage and they
        # count different things, so they are reported separately.
        elog = sum(channels.get((c, str(i)), 0) for c, i in
                   (tuple(p) for p in cov.get("eventlog") or []))
        rules = sorted({f for cat in cov.get("sigma") or [] for f in cats.get(cat, [])})
        tools = sorted({(r["entry_id"], r["tool"]) for r in hit})
        out.append({**s, "n_rows": len(hit), "class_rows": class_rows,
                    "n_eventlog_rows": elog, "rules": rules, "n_rules": len(rules),
                    "n_tools": len(tools), "tools": [{"id": i, "name": n} for i, n in tools]})
    return {"sources": out, "per_class": per_class, "class_os": class_os,
            "channels": channels, "sigma_categories": cats,
            "hosts": hosts_seen, "locators": locators_seen}


def audit(cov: dict) -> list[str]:
    """Every way the source table and the corpus can disagree."""
    problems = []
    srcs = cov["sources"]

    claimed_classes = {c for s in srcs for c in (s.get("covers") or {}).get("classes") or []}
    claimed_cats = {c for s in srcs for c in (s.get("covers") or {}).get("sigma") or []}
    claimed_chans = {tuple(p) for s in srcs
                     for p in (s.get("covers") or {}).get("eventlog") or []}

    for cls in sorted(cov["per_class"]):
        # eventlog rows are attributed by channel and ID rather than by class,
        # which is the finer grain: two rows in the same class can need two
        # different things switched on. The per-channel check below covers them,
        # and crediting the class as well would double-count the same 30 rows.
        if cls == "eventlog":
            continue
        if cls not in claimed_classes:
            problems.append(f"row class {cls!r} maps to no data source - "
                            f"{cov['per_class'][cls]} rows are unattributed")
            continue
        # A class is covered per OS, not in the abstract: five Windows-only
        # sources claiming `process` left the macOS and Linux process rows
        # credited to Sysmon, which cannot see them.
        for os_name in sorted(cov["class_os"].get(cls, ())):
            if not any(cls in ((x.get("covers") or {}).get("classes") or []) and
                       (not (x.get("covers") or {}).get("os") or os_name == "any" or
                        os_name in [str(o).lower() for o in x["covers"]["os"]])
                       for x in srcs):
                problems.append(f"row class {cls!r} on {os_name} maps to no data source")
    for cat in sorted(cov["sigma_categories"]):
        if cat not in claimed_cats:
            problems.append(f"sigma logsource category {cat!r} maps to no data "
                            f"source ({len(cov['sigma_categories'][cat])} rule(s))")
    for chan, n in sorted(cov["channels"].items()):
        if (chan[0], str(chan[1])) not in {(a, str(b)) for a, b in claimed_chans}:
            problems.append(f"eventlog channel {chan[0]} EID {chan[1]} maps to no "
                            f"data source ({n} row(s))")

    # And the other direction: a source promising coverage nothing supplies.
    for s in srcs:
        cov_ = s.get("covers") or {}
        for cls in cov_.get("classes") or []:
            if cls not in cov["per_class"]:
                problems.append(f"{s['id']}: claims row class {cls!r}, which no "
                                f"catalog row uses")
        for cat in cov_.get("sigma") or []:
            if cat not in cov["sigma_categories"]:
                problems.append(f"{s['id']}: claims sigma category {cat!r}, which "
                                f"no rule uses")
        for pair in cov_.get("eventlog") or []:
            if (pair[0], str(pair[1])) not in {(a, str(b)) for a, b in cov["channels"]}:
                problems.append(f"{s['id']}: claims {pair[0]} EID {pair[1]}, which "
                                f"no catalog row uses")
        for os_name in cov_.get("os") or []:
            if str(os_name).lower() not in {o for v in cov["class_os"].values() for o in v}:
                problems.append(f"{s['id']}: claims OS {os_name!r}, which no catalog "
                                f"row names")
        if cov_.get("os") and not cov_.get("classes"):
            problems.append(f"{s['id']}: `os` narrows `classes`, and there are none")
        for host in cov_.get("hosts") or []:
            h = str(host).lower()
            if not any(x == h or x.endswith("." + h) for x in cov["hosts"]):
                problems.append(f"{s['id']}: claims host {host!r}, which no network "
                                f"row names")
        for loc in cov_.get("locators") or []:
            if loc not in cov["locators"]:
                problems.append(f"{s['id']}: claims locator <{loc}>, which no row "
                                f"starts with")
        if s.get("kind") not in ("eventlog", "file", "live", "network"):
            problems.append(f"{s['id']}: kind {s.get('kind')!r} is not one of "
                            f"eventlog, file, live, network")
        if s.get("volatility") not in VOLATILITY_ORDER:
            problems.append(f"{s['id']}: volatility {s.get('volatility')!r} is not "
                            f"one of {VOLATILITY_ORDER}")
        for field in ("enable", "retention", "without_it", "default_state"):
            if not (s.get(field) or "").strip():
                problems.append(f"{s['id']}: {field} is empty - a source with no "
                                f"{field} is a heading, not guidance")
        if not (s.get("references") or []):
            problems.append(f"{s['id']}: no reference. Same rule as a catalog "
                            f"entry: an unsourced claim about somebody's estate "
                            f"is a guess.")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="audit only, write nothing")
    args = ap.parse_args()

    entries = load_entries()
    cov = coverage(load_sources(), entries)

    vol: dict[str, int] = {}
    for e in entries:
        for cls, items in (e.get("artifacts") or {}).items():
            for row in items or []:
                v = volatility_of(cls, row)
                vol[v] = vol.get(v, 0) + 1
        for c in e.get("credentials") or []:
            vol["stable"] = vol.get("stable", 0) + 1
        for _ in e.get("mcp") or []:
            vol["stable"] = vol.get("stable", 0) + 1

    if not args.check:
        print(f"{len(cov['sources'])} data sources\n")
        for s in cov["sources"]:
            bits = []
            if s["n_rows"]:
                bits.append(f"{s['n_rows']} rows")
            if s["n_eventlog_rows"]:
                bits.append(f"{s['n_eventlog_rows']} eventlog rows")
            if s["n_rules"]:
                bits.append(f"{s['n_rules']} rules")
            if s["n_tools"]:
                bits.append(f"{s['n_tools']} tools")
            print(f"  {s['id']:26} {s['volatility']:9} {', '.join(bits) or 'prose only'}")
        print("\nvolatility: " + " · ".join(
            f"{k} {vol.get(k, 0)}" for k in VOLATILITY_ORDER))

    problems = audit(cov)
    for p in problems:
        print(f"[SOURCE] {p}")
    print(f"\n{len(problems)} problem(s).")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
