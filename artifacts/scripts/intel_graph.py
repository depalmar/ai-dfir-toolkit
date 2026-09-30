#!/usr/bin/env python3
"""The threat-intel layer: one entity graph, derived from files already in the repo.

    python scripts/intel_graph.py            # stats report
    python scripts/intel_graph.py --check    # gate, writes nothing
    python scripts/intel_graph.py --export   # write docs/api/intel.json, STIX, Maltego CSV

Sources, all authored elsewhere:
  artifacts/intel/actors/*.yml    who - attributed actors and named clusters
  artifacts/case-studies/*.yml    what happened, with indicators and response
  artifacts/catalog/*.yml         what the tools leave on a host
  rule files + MAPPINGS.md        what detects it
  schema/technique-ids.json       ATLAS / ATT&CK, pinned
  schema/owasp.json               OWASP LLM 2026 and Agentic 2026, pinned

Nothing an actor profile could contradict is authored on it. Its techniques,
victims, indicators, detections, first and last seen dates, and recovery steps
are derived here from the case studies and sightings that cite it. The same rule
as the catalog's volatility column: a hand-maintained copy is right on the day
it is written and silently wrong afterwards.

The cross-mapping the layer exists for is the chain

    actor -> technique -> rule that detects it
                       -> catalogued tool it abused -> artifact rows to collect

which answers, for a named adversary: what to hunt, with which rule, and what to
pull off the host, in volatility order.
"""
from __future__ import annotations

import argparse
import csv
import glob
import io
import json
import re
import sys
import uuid
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REPO = ROOT.parent
API = ROOT / "docs" / "api"
SCHEMA = ROOT / "schema"
sys.path.insert(0, str(HERE))

NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/depalmar/ai-dfir-toolkit")

# Indicator types that name one concrete thing a tool can match on. The rest -
# behaviour, pattern, config - are descriptions of what to look for, and making
# them graph nodes would join unrelated incidents on the word "behavior".
ATOMIC_IOC = {"file", "directory", "binary", "process", "commit", "domain", "ip",
              "url", "hash", "email", "package", "account", "mutex"}

VOL_RANK = {"live": 0, "rotating": 1, "stable": 2}

# ATLAS tactics that happen on the adversary's side of the wire: building
# capability, staging, researching. A technique confined to these leaves nothing
# on a defended host, so "no rule" there is a fact about telemetry, not a gap in
# this repository's content. Reported apart from real gaps so the coverage
# number does not ask for rules nobody could write.
OFF_HOST_TACTICS = {"AML.TA0001", "AML.TA0002", "AML.TA0003"}
FV_RANK = {"high": 0, "medium": 1, "low": 2, "": 3}


# --------------------------------------------------------------------------- load

def _yaml_files(pattern: str) -> list[tuple[Path, dict]]:
    out = []
    for f in sorted(glob.glob(str(pattern))):
        out.append((Path(f), yaml.safe_load(Path(f).read_text(encoding="utf-8")) or {}))
    return out


def load_sources(entries=None, rows=None, rules=None) -> dict:
    """Everything the graph is built from, in one dict. Import-light on purpose:
    build_site imports this module, so it must not import build_site at load -
    and build_site passes the entries, rows and rules it already built, so the
    page and the feeds are derived from one pass rather than two."""
    import site_data
    if entries is None:
        entries = [d for _, d in _yaml_files(ROOT / "catalog" / "*.yml")]
    if rows is None:
        import build_site
        rows = build_site.build_rows(entries)
    if rules is None:
        mapping_rows, _, _ = site_data.load_mappings()
        rules = site_data.load_rules(mapping_rows)
    return {
        "entries": entries,
        "rows": rows,
        "rules": rules,
        "cases_raw": _yaml_files(ROOT / "case-studies" / "*.yml"),
        "actors_raw": _yaml_files(ROOT / "intel" / "actors" / "*.yml"),
        "pin": json.loads((SCHEMA / "technique-ids.json").read_text(encoding="utf-8")),
        "owasp": json.loads((SCHEMA / "owasp.json").read_text(encoding="utf-8")),
        "vocab": json.loads((SCHEMA / "intel-vocab.json").read_text(encoding="utf-8")),
    }


# -------------------------------------------------------------------------- check

def _validator(name: str):
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    reg = Registry()
    for n in ("intel-vocab.json", "case-study.schema.json", "actor.schema.json"):
        doc = json.loads((SCHEMA / n).read_text(encoding="utf-8"))
        reg = reg.with_resource(n, Resource.from_contents(doc))
    schema = json.loads((SCHEMA / name).read_text(encoding="utf-8"))
    return Draft202012Validator(schema, registry=reg)


def check(src: dict) -> list[str]:
    """Every way the intel files can be wrong without a schema noticing."""
    problems: list[str] = []
    case_v, actor_v = _validator("case-study.schema.json"), _validator("actor.schema.json")
    tool_ids = {e["id"] for e in src["entries"]}
    rule_files = {r["file"] for r in src["rules"]}

    actor_ids: dict[str, str] = {}
    for path, a in src["actors_raw"]:
        for err in sorted(actor_v.iter_errors(a), key=lambda e: list(e.path)):
            loc = ".".join(str(p) for p in err.absolute_path) or "(root)"
            problems.append(f"[ACTOR]  {path.name}: {loc}: {err.message}")
        aid = a.get("id", "")
        # The file name carries the id, like the case studies, so a renumber
        # shows up as a rename in review instead of an edit inside a file.
        if aid and path.stem != aid.lower():
            problems.append(f"[ACTOR]  {path.name}: id {aid} does not match the file name")
        if aid in actor_ids:
            problems.append(f"[ACTOR]  {aid} is used by {actor_ids[aid]} and {path.name}")
        actor_ids[aid] = path.name
        for t in a.get("abuses") or []:
            if t not in tool_ids:
                problems.append(f"[ACTOR]  {aid}: abuses {t}, which is not a catalog entry")
        for s in a.get("sightings") or []:
            for t in s.get("abuses") or []:
                if t not in tool_ids:
                    problems.append(f"[ACTOR]  {aid}: sighting abuses {t}, not a catalog entry")

    linked: dict[str, list[dict]] = {}
    for path, c in src["cases_raw"]:
        for err in sorted(case_v.iter_errors(c), key=lambda e: list(e.path)):
            loc = ".".join(str(p) for p in err.absolute_path) or "(root)"
            problems.append(f"[CASE]   {path.name}: {loc}: {err.message}")
        cid = c.get("id", path.stem)
        if path.stem != str(cid).lower():
            problems.append(f"[CASE]   {path.name}: id {cid} does not match the file name")
        for link in c.get("actors") or []:
            ref = link.get("ref")
            if ref not in actor_ids:
                problems.append(f"[CASE]   {cid}: actor {ref} has no profile in intel/actors/")
            linked.setdefault(ref, []).append(link)
            # Same honesty rule as the catalog: a low link must say so.
            if link.get("link_confidence") == "low" and not link.get("unverified"):
                problems.append(f"[CASE]   {cid}: low-confidence link to {ref} must carry "
                                f"unverified: true")
        for d in c.get("detections") or []:
            if d not in rule_files:
                problems.append(f"[CASE]   {cid}: cites {d}, which is not a rule in this repo")

    # A profile rated high cannot rest on links that are all weaker than that.
    for path, a in src["actors_raw"]:
        if a.get("confidence") == "high":
            links = linked.get(a.get("id"), [])
            if links and all(l.get("link_confidence") == "low" for l in links):
                problems.append(f"[ACTOR]  {a['id']}: rated high, but every case link is low")
        # An actor with no case and no sighting is a name, not intelligence.
        if not linked.get(a.get("id")) and not (a.get("sightings") or []):
            problems.append(f"[ACTOR]  {a.get('id')}: no case study cites it and it has no "
                            f"sightings - there is nothing to derive a profile from")
    return problems


# -------------------------------------------------------------------------- build

def _atlas_parent(t: str) -> str:
    parent, _, sub = t.rpartition(".")
    return parent if len(sub) == 3 and sub.isdigit() else t


def _quarter(date: str) -> str:
    m = re.match(r"(\d{4})-(\d{2})", date or "")
    return f"{m.group(1)}-Q{(int(m.group(2)) - 1) // 3 + 1}" if m else ""


def build(src: dict) -> dict:
    """Actors with derived fields, cases, the entity graph, and stats."""
    pin, owasp, vocab = src["pin"], src["owasp"], src["vocab"]
    atlas = pin["atlas"]
    tools = {e["id"]: e for e in src["entries"]}
    rows_by_tool: dict[str, list[dict]] = {}
    for r in src["rows"]:
        rows_by_tool.setdefault(r["entry_id"], []).append(r)
    region_of = {c: reg for reg, cs in vocab["regions"].items() for c in cs}

    # Rules that detect a technique, exact or through the parent. A rule tagged
    # T0051 does detect T0051.000 in the sense that matters here - it fires on
    # the class - so a sub-technique counts as covered by its parent's rule.
    rules_for: dict[str, set[str]] = {}
    for r in src["rules"]:
        for t in r.get("atlas", []):
            rules_for.setdefault(t, set()).add(r["file"])

    def detecting(t: str) -> set[str]:
        return rules_for.get(t, set()) | rules_for.get(_atlas_parent(t), set())

    cases = []
    for _, c in src["cases_raw"]:
        affects = c.get("affects")
        affects = affects if isinstance(affects, list) else [affects or ""]
        cases.append({**c, "affects_ids": sorted({i for a in affects
                                                  for i in re.findall(r"AIRT-\d{4}", str(a))})})

    actors = []
    for _, a in src["actors_raw"]:
        aid = a["id"]
        mine = [c for c in cases if any(l.get("ref") == aid for l in c.get("actors") or [])]
        sightings = a.get("sightings") or []
        techs = sorted({t for c in mine for t in c.get("atlas") or []}
                       | {t for s in sightings for t in s.get("atlas") or []})
        attack_t = sorted({t for c in mine for t in c.get("attack") or []}
                          | {t for s in sightings for t in s.get("attack") or []})
        asi = sorted({x for c in mine for x in c.get("owasp_agentic") or []}
                     | {x for s in sightings for x in s.get("owasp_agentic") or []})
        victims = [c.get("victims") or {} for c in mine] + [s.get("victims") or {} for s in sightings]
        sectors = sorted({x for v in victims for x in v.get("sectors") or []})
        countries = sorted({x for v in victims for x in v.get("countries") or []})
        dates = sorted([str(c.get("disclosed")) for c in mine if c.get("disclosed")]
                       + [str(s["date"]) for s in sightings])
        abused = sorted(set(a.get("abuses") or [])
                        | {t for c in mine for t in c["affects_ids"]}
                        | {t for s in sightings for t in s.get("abuses") or []})
        cited = sorted({d for c in mine for d in c.get("detections") or []})
        hunt = []
        for t in techs:
            tac = atlas["technique_tactics"].get(t, [])
            hunt.append({"technique": t, "name": atlas["techniques"].get(t, ""),
                         "tactics": tac, "rules": sorted(detecting(t)),
                         "off_host": bool(tac) and set(tac) <= OFF_HOST_TACTICS})
        # What to pull off a host, for the tools this actor is reported to have
        # used or targeted: live first, then rotating, then stable, and within a
        # tier the high-value rows first - the collection order the catalog
        # already recommends, filtered to this adversary.
        collect = sorted(
            ({"anchor": r["anchor"], "tool": r["tool"], "entry_id": r["entry_id"],
              "cls": r["cls"], "artifact": r["artifact"], "vol": r["vol"],
              "forensic_value": r["forensic_value"]}
             for t in abused for r in rows_by_tool.get(t, [])),
            key=lambda r: (VOL_RANK.get(r["vol"], 9), FV_RANK.get(r["forensic_value"], 9),
                           r["entry_id"], r["anchor"]))
        recovery = [{"case": c["id"], **(ra if isinstance(ra, dict) else {"phase": "", "action": ra})}
                    for c in mine for ra in c.get("response_actions") or []]
        actors.append({
            **{k: a[k] for k in a},
            "cases": [c["id"] for c in mine],
            "links": [{"case": c["id"], **l} for c in mine for l in c.get("actors") or []
                      if l.get("ref") == aid],
            "derived": {
                "techniques": techs, "attack": attack_t, "owasp_agentic": asi,
                "tactics": sorted({ta for t in techs for ta in atlas["technique_tactics"].get(t, [])}),
                "sectors": sectors, "countries": countries,
                "regions": sorted({region_of[c] for c in countries if c in region_of}),
                "first_seen": dates[0] if dates else "", "last_seen": dates[-1] if dates else "",
                "tools": abused,
                "iocs": [{**i, "case": c["id"]} for c in mine for i in c.get("iocs") or []],
                "detections_cited": cited,
                "detections_by_technique": sorted({r for h in hunt for r in h["rules"]}),
                "gaps": [h["technique"] for h in hunt if not h["rules"] and not h["off_host"]],
                "off_host": [h["technique"] for h in hunt if not h["rules"] and h["off_host"]],
                "hunt": hunt, "collect": collect, "recovery": recovery,
            },
        })

    graph = _graph(actors, cases, src, tools, rows_by_tool, rules_for, region_of)
    stats = _stats(actors, cases, atlas, rules_for)
    out = {"actors": actors, "cases": cases, "graph": graph, "stats": stats,
           "atlas": {"release": atlas["release"], "tactic_order": atlas["tactic_order"],
                     "tactics": atlas["tactics"]}}
    out["analytics"] = analytics(out, atlas)
    return out


def _graph(actors, cases, src, tools, rows_by_tool, rules_for, region_of):
    nodes: dict[str, dict] = {}
    edges: set[tuple] = set()
    atlas = src["pin"]["atlas"]
    attack = src["pin"]["attack"]
    asi_items = src["owasp"]["agentic_2026"]["items"]

    def node(nid, ntype, label, **extra):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": ntype, "label": label, **extra}
        return nid

    def edge(a, b, rel, **extra):
        edges.add((a, b, rel, json.dumps(extra, sort_keys=True) if extra else ""))

    def tech(t):
        if t.startswith("AML."):
            n = node(f"atlas:{t}", "technique", f"{t} {atlas['techniques'].get(t, '')}".strip(),
                     framework="ATLAS")
            for ta in atlas["technique_tactics"].get(t, []):
                edge(n, node(f"tactic:{ta}", "tactic", f"{ta} {atlas['tactics'].get(ta, '')}"),
                     "in-tactic")
            return n
        return node(f"attack:{t}", "technique", f"{t} {attack['techniques'].get(t, '')}".strip(),
                    framework="ATT&CK")

    def place(v, owner):
        for s in v.get("sectors") or []:
            edge(owner, node(f"sector:{s}", "sector", s), "targets")
        for c in v.get("countries") or []:
            cn = node(f"country:{c}", "country", c)
            edge(owner, cn, "targets")
            if c in region_of:
                edge(cn, node(f"region:{region_of[c]}", "region", region_of[c]), "in-region")

    def tool(t):
        e = tools[t]
        n = node(f"tool:{t}", "tool", e["name"], entry_id=t)
        for r in rows_by_tool.get(t, []):
            edge(n, node(f"artifact:{r['anchor']}", "artifact", r["artifact"][:80],
                         anchor=r["anchor"], cls=r["cls"], vol=r["vol"]), "leaves")
        return n

    rule_nodes = set()

    def rule(f):
        rule_nodes.add(f)
        return node(f"rule:{f}", "rule", f)

    for a in actors:
        an = node(f"actor:{a['id']}", "actor", a["name"], actor_id=a["id"], actor_kind=a["kind"])
        for s in a.get("sightings") or []:
            for t in s.get("atlas") or []:
                edge(an, tech(t), "uses")
            for t in s.get("attack") or []:
                edge(an, tech(t), "uses")
            for x in s.get("owasp_agentic") or []:
                edge(an, node(f"asi:{x}", "asi", f"{x} {asi_items[x]['title']}"), "maps-to")
            for t in s.get("abuses") or []:
                edge(an, tool(t), "abuses")
            place(s.get("victims") or {}, an)
        for t in a.get("abuses") or []:
            edge(an, tool(t), "abuses")
        for m in a.get("malware") or []:
            edge(an, node(f"malware:{m.lower()}", "malware", m), "uses")
        for g in (a.get("external_ids") or {}).get("attack_group") or []:
            edge(an, node(f"group:{g}", "attack-group",
                          f"{g} {attack['groups'].get(g, {}).get('name', '')}".strip()), "same-as")

    for c in cases:
        cn = node(f"case:{c['id']}", "case", c["title"], case_id=c["id"],
                  confidence=c.get("confidence", ""))
        for l in c.get("actors") or []:
            edge(f"actor:{l['ref']}", cn, "attributed-to", confidence=l.get("link_confidence", ""))
        for t in (c.get("atlas") or []) + (c.get("attack") or []):
            edge(cn, tech(t), "uses")
        for x in c.get("owasp_agentic") or []:
            edge(cn, node(f"asi:{x}", "asi", f"{x} {asi_items[x]['title']}"), "maps-to")
        for t in c["affects_ids"]:
            if t in tools:
                edge(cn, tool(t), "affects")
        for d in c.get("detections") or []:
            edge(cn, rule(d), "detected-by")
        for i in c.get("iocs") or []:
            if i.get("type") == "malware":
                edge(cn, node(f"malware:{i['value'].lower()}", "malware", i["value"]), "uses")
            elif i.get("type") in ATOMIC_IOC:
                edge(cn, node(f"ioc:{i['type']}:{i['value']}", "ioc", i["value"],
                              ioc_type=i["type"]), "indicator")
        for k, vals in (c.get("external_ids") or {}).items():
            if k == "attack_campaign":
                for v in vals:
                    edge(cn, node(f"campaign:{v}", "attack-campaign",
                                  f"{v} {attack['campaigns'].get(v, {}).get('name', '')}".strip()),
                         "same-as")
        place(c.get("victims") or {}, cn)

    # Rules join the graph through the techniques already in it, so the graph
    # holds every rule that bears on an actor or case and no others.
    tech_nodes = {n["id"].split(":", 1)[1] for n in nodes.values()
                  if n["type"] == "technique" and n.get("framework") == "ATLAS"}
    for t in sorted(tech_nodes):
        for f in sorted(rules_for.get(t, set()) | rules_for.get(_atlas_parent(t), set())):
            edge(rule(f), f"atlas:{t}", "detects")

    out_edges = [{"source": a, "target": b, "rel": r, **(json.loads(x) if x else {})}
                 for a, b, r, x in sorted(edges)]
    return {"nodes": sorted(nodes.values(), key=lambda n: n["id"]), "edges": out_edges}


def _stats(actors, cases, atlas, rules_for):
    def tally(it):
        out: dict[str, int] = {}
        for x in it:
            out[x] = out.get(x, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))

    observed = sorted({t for a in actors for t in a["derived"]["techniques"]}
                      | {t for c in cases for t in c.get("atlas") or []})
    covered = [t for t in observed
               if rules_for.get(t) or rules_for.get(_atlas_parent(t))]
    off_host = [t for t in observed if t not in covered
                and set(atlas["technique_tactics"].get(t, [])) <= OFF_HOST_TACTICS
                and atlas["technique_tactics"].get(t)]
    tech_use: dict[str, dict] = {}
    for a in actors:
        for t in a["derived"]["techniques"]:
            tech_use.setdefault(t, {"actors": set(), "cases": set()})["actors"].add(a["id"])
    for c in cases:
        for t in c.get("atlas") or []:
            tech_use.setdefault(t, {"actors": set(), "cases": set()})["cases"].add(c["id"])
    return {
        "actors": len(actors), "cases": len(cases),
        "iocs": sum(len(c.get("iocs") or []) for c in cases),
        "atomic_iocs": sum(1 for c in cases for i in c.get("iocs") or []
                           if i.get("type") in ATOMIC_IOC),
        "techniques_observed": len(observed),
        "techniques_covered": len(covered),
        "techniques_off_host": len(off_host),
        "by_kind": tally(a["kind"] for a in actors),
        "by_nexus": tally(a.get("nexus") or "unstated" for a in actors),
        "by_motivation": tally(m for a in actors for m in a.get("motivation") or []),
        "by_sector": tally(s for a in actors for s in a["derived"]["sectors"]),
        "by_country": tally(c for a in actors for c in a["derived"]["countries"]),
        "by_region": tally(r for a in actors for r in a["derived"]["regions"]),
        "case_sectors": tally(s for c in cases for s in (c.get("victims") or {}).get("sectors") or []),
        "by_ioc_type": tally(i.get("type", "") for c in cases for i in c.get("iocs") or []),
        "cases_by_quarter": dict(sorted(tally(_quarter(str(c.get("disclosed", ""))) for c in cases
                                              if c.get("disclosed")).items())),
        "link_confidence": tally(l.get("link_confidence", "") for c in cases
                                 for l in c.get("actors") or []),
        "technique_use": {t: {"actors": sorted(v["actors"]), "cases": sorted(v["cases"]),
                              "rules": sorted(rules_for.get(t, set())
                                              | rules_for.get(_atlas_parent(t), set()))}
                          for t, v in sorted(tech_use.items())},
    }


# ---------------------------------------------------------------------- analytics
#
# Descriptive statistics over what the sources report - similarity, clusters,
# co-occurrence, cadence, a detection backlog. Deterministic, explainable, and
# computed here rather than in the browser so the numbers are reviewable in the
# feed. Twenty actors is a small corpus: these are for triage and hypothesis,
# never for attribution, and the page says so next to every one of them.

SIM_WEIGHTS = {"techniques": 0.4, "tools": 0.2, "sectors": 0.2, "ai_services": 0.1,
               "motivation": 0.1}
CLUSTER_MIN_SIM = 0.30


def _features(a: dict) -> dict[str, set]:
    d = a["derived"]
    techs = set(d["techniques"]) | {_atlas_parent(t) for t in d["techniques"]}
    return {"techniques": techs, "tools": set(d["tools"]), "sectors": set(d["sectors"]),
            "ai_services": {x.lower() for s in a.get("sightings") or []
                            for x in s.get("ai_services") or []},
            "motivation": set(a.get("motivation") or [])}


def _jaccard(x: set, y: set, idf: dict | None = None) -> float | None:
    """IDF-weighted Jaccard. A feature every actor has - "used a generative AI
    model" is in almost every sighting - says nothing about which actors are
    alike, so it is weighted down by log(1 + N/df), the way a search engine
    weights a common word. Plain Jaccard grouped half the corpus on that alone."""
    if not x and not y:
        return None
    w = (lambda k: idf.get(k, 1.0)) if idf else (lambda k: 1.0)
    return sum(w(k) for k in x & y) / sum(w(k) for k in x | y)


def similarity(fa: dict, fb: dict, idf: dict | None = None) -> tuple[float, dict]:
    num = den = 0.0
    shared = {}
    for f, w in SIM_WEIGHTS.items():
        j = _jaccard(fa[f], fb[f], (idf or {}).get(f))
        if j is None:
            continue          # neither side reports it: no evidence either way
        num += w * j
        den += w
        if fa[f] & fb[f]:
            shared[f] = sorted(fa[f] & fb[f])
    return (round(num / den, 3) if den else 0.0), shared


def _cluster(ids: list[str], sim: dict) -> list[list[str]]:
    """Average-linkage agglomerative clustering, stopped at CLUSTER_MIN_SIM.

    Deterministic: ties break on sorted ids, so the same corpus always gives the
    same clusters and a diff of the feed shows exactly what moved."""
    groups = [[i] for i in sorted(ids)]

    def link(a, b):
        return sum(sim[(x, y)] for x in a for y in b) / (len(a) * len(b))

    while True:
        best, pair = -1.0, None
        for i in range(len(groups)):
            for j in range(i + 1, len(groups)):
                v = link(groups[i], groups[j])
                if v > best:
                    best, pair = v, (i, j)
        if not pair or best < CLUSTER_MIN_SIM:
            break
        i, j = pair
        groups[i] = sorted(groups[i] + groups[j])
        del groups[j]
    return sorted((g for g in groups if len(g) > 1), key=lambda g: (-len(g), g))


def analytics(intel: dict, atlas: dict) -> dict:
    actors = intel["actors"]
    feats = {a["id"]: _features(a) for a in actors}
    ids = sorted(feats)
    import math
    idf = {}
    for f in SIM_WEIGHTS:
        df: dict[str, int] = {}
        for i in ids:
            for k in feats[i][f]:
                df[k] = df.get(k, 0) + 1
        idf[f] = {k: math.log(1 + len(ids) / v) for k, v in df.items()}
    sim, why = {}, {}
    for x in ids:
        for y in ids:
            if x == y:
                sim[(x, y)] = 1.0
                continue
            v, shared = similarity(feats[x], feats[y], idf)
            sim[(x, y)] = v
            why[(x, y)] = shared
    neighbours = {}
    for x in ids:
        ranked = sorted((y for y in ids if y != x), key=lambda y: (-sim[(x, y)], y))
        neighbours[x] = [{"actor": y, "score": sim[(x, y)], "shared": why[(x, y)]}
                         for y in ranked[:3] if sim[(x, y)] > 0]
    clusters = []
    for g in _cluster(ids, sim):
        common = {f: sorted(set.intersection(*(feats[i][f] for i in g)))
                  for f in SIM_WEIGHTS}
        # A cluster whose only shared evidence is off-host technique use - "asked
        # a chatbot for help" - reflects how thinly those actors are reported,
        # not a behavioural resemblance. Said so rather than hidden.
        shared_t = common.get("techniques") or []
        thin = (not any(common[f] for f in SIM_WEIGHTS if f != "techniques")
                and all(set(atlas["technique_tactics"].get(t, []) or ["x"]) <= OFF_HOST_TACTICS
                        for t in shared_t))
        clusters.append({"actors": g, "thin": thin, "cohesion": round(
            sum(sim[(a, b)] for a in g for b in g if a < b) / max(1, len(g) * (len(g) - 1) / 2), 3),
            "shared": {k: v for k, v in common.items() if v}})

    # Technique co-occurrence. One transaction per observation - a case study or
    # a sighting - because that is the unit a reporter published. Lift over 1
    # means two techniques turn up together more often than their separate
    # frequencies predict.
    tx = [set(c.get("atlas") or []) for c in intel["cases"]]
    tx += [set(s.get("atlas") or []) for a in actors for s in a.get("sightings") or []]
    tx = [t for t in tx if t]
    n = len(tx)
    freq: dict[str, int] = {}
    for t in tx:
        for x in t:
            freq[x] = freq.get(x, 0) + 1
    pairs: dict[tuple, int] = {}
    for t in tx:
        for a in sorted(t):
            for b in sorted(t):
                if a < b:
                    pairs[(a, b)] = pairs.get((a, b), 0) + 1
    cooc = []
    for (a, b), k in pairs.items():
        if k < 2:
            continue
        cooc.append({"a": a, "b": b, "support": k,
                     "confidence_ab": round(k / freq[a], 3), "confidence_ba": round(k / freq[b], 3),
                     "lift": round(k * n / (freq[a] * freq[b]), 2)})
    cooc.sort(key=lambda r: (-r["lift"], -r["support"], r["a"], r["b"]))

    # Timeline: every dated observation, and each actor's cadence.
    events = []
    for c in intel["cases"]:
        for l in c.get("actors") or [{"ref": ""}]:
            if c.get("disclosed"):
                events.append({"date": str(c["disclosed"]), "actor": l.get("ref", ""),
                               "kind": "case", "ref": c["id"], "techniques": c.get("atlas") or []})
    for a in actors:
        for s in a.get("sightings") or []:
            events.append({"date": str(s["date"]), "actor": a["id"], "kind": "sighting",
                           "ref": s["reporter"], "techniques": s.get("atlas") or []})
    events.sort(key=lambda e: (e["date"], e["actor"], e["kind"], e["ref"]))

    def days(d):
        from datetime import date
        parts = [int(x) for x in re.findall(r"\d+", d)[:3]] + [1, 1]
        return date(parts[0], parts[1], parts[2]).toordinal()

    cadence = {}
    for a in actors:
        ds = sorted({days(e["date"]) for e in events if e["actor"] == a["id"]})
        gaps = [b - x for x, b in zip(ds, ds[1:])]
        cadence[a["id"]] = {"events": len([e for e in events if e["actor"] == a["id"]]),
                            "span_days": (ds[-1] - ds[0]) if ds else 0,
                            "median_gap_days": sorted(gaps)[len(gaps) // 2] if gaps else None}

    # Detection backlog: techniques in use with no rule, weighted by how many
    # actors and cases use them. Off-host techniques are listed separately -
    # there is nothing to write a rule against.
    backlog = []
    for t, u in intel["stats"]["technique_use"].items():
        if u["rules"]:
            continue
        tac = atlas["technique_tactics"].get(t, [])
        backlog.append({"technique": t, "name": atlas["techniques"].get(t, ""),
                        "actors": len(u["actors"]), "cases": len(u["cases"]),
                        "score": 2 * len(u["actors"]) + len(u["cases"]),
                        "off_host": bool(tac) and set(tac) <= OFF_HOST_TACTICS})
    backlog.sort(key=lambda r: (r["off_host"], -r["score"], r["technique"]))

    tactic_obs: dict[str, int] = {}
    for t in tx:
        for ta in sorted({ta for x in t for ta in atlas["technique_tactics"].get(x, [])}):
            tactic_obs[ta] = tactic_obs.get(ta, 0) + 1

    return {
        "method": {"similarity": "IDF-weighted Jaccard over " + ", ".join(
            f"{k} ({v})" for k, v in SIM_WEIGHTS.items()) + "; facets neither side reports are skipped",
            "clusters": f"average-linkage agglomerative, stopped below similarity {CLUSTER_MIN_SIM}",
            "cooccurrence": f"{n} observations (case studies and sightings); pairs seen at least twice",
            "backlog": "score = 2 x actors + cases using the technique, rule-less techniques only"},
        "similarity": {"ids": ids, "matrix": [[sim[(x, y)] for y in ids] for x in ids]},
        "neighbours": neighbours, "clusters": clusters, "cooccurrence": cooc[:40],
        "events": events, "cadence": cadence, "backlog": backlog,
        "tactic_observations": tactic_obs, "observations": n,
    }


# ------------------------------------------------------------------------ exports

def _uid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NS, kind + ':' + key)}"


def _refang(v: str) -> str:
    return (v.replace("[.]", ".").replace("[:]", ":").replace("hxxps", "https")
            .replace("hxxp", "http"))


def _ts(date: str, fallback: str) -> str:
    d = str(date or fallback)
    if re.fullmatch(r"\d{4}", d):
        d += "-01-01"
    elif re.fullmatch(r"\d{4}-\d{2}", d):
        d += "-01"
    return d[:10] + "T00:00:00.000Z"


def _pattern(t: str, v: str) -> str | None:
    v = _refang(v).replace("\\", "\\\\").replace("'", "\\'")
    if t == "domain":
        return f"[domain-name:value = '{v}']"
    if t == "ip":
        return f"[{'ipv6-addr' if ':' in v else 'ipv4-addr'}:value = '{v}']"
    if t == "url":
        return f"[url:value = '{v}']"
    if t == "email":
        return f"[email-addr:value = '{v}']"
    if t == "hash" and re.fullmatch(r"[0-9a-fA-F]{64}", v):
        return f"[file:hashes.'SHA-256' = '{v.lower()}']"
    if t == "file" and "/" not in v and "\\" not in v:
        return f"[file:name = '{v}']"
    return None


def stix_bundle(intel: dict, pin: dict) -> dict:
    """STIX 2.1. Deterministic: ids are uuid5 of the repo's own ids, timestamps
    come from the data, so an unchanged catalog exports a byte-identical bundle."""
    stamp = _ts(max((str(c.get("disclosed", "")) for c in intel["cases"]), default="2026-01-01"), "")
    ident = _uid("identity", "producer")
    mark = _uid("marking-definition", "cc-by-4.0")
    common = {"spec_version": "2.1", "created_by_ref": ident, "object_marking_refs": [mark]}
    objs = [
        {"type": "identity", "spec_version": "2.1", "id": ident, "created": stamp, "modified": stamp,
         "name": "ai-dfir-toolkit", "identity_class": "organization",
         "description": "Open AI-agent artifact catalog and detection content."},
        {"type": "marking-definition", "spec_version": "2.1", "id": mark, "created": stamp,
         "definition_type": "statement", "name": "CC BY 4.0",
         "definition": {"statement": "Catalog data licensed CC BY 4.0 - ai-dfir-toolkit. "
                                     "Indicators are republished from the cited reports."}},
    ]
    seen = set()

    def add(o):
        if o["id"] not in seen:
            seen.add(o["id"])
            objs.append(o)
        return o["id"]

    def rel(src, tgt, kind, when):
        return add({"type": "relationship", **common, "id": _uid("relationship", f"{src}|{kind}|{tgt}"),
                    "created": when, "modified": when, "relationship_type": kind,
                    "source_ref": src, "target_ref": tgt})

    def attack_pattern(t, when):
        if t.startswith("AML."):
            name = pin["atlas"]["techniques"].get(t, t)
            ref = {"source_name": "mitre-atlas", "external_id": t,
                   "url": f"https://atlas.mitre.org/techniques/{t}"}
        else:
            name = pin["attack"]["techniques"].get(t, t)
            ref = {"source_name": "mitre-attack", "external_id": t,
                   "url": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/"}
        return add({"type": "attack-pattern", **common, "id": _uid("attack-pattern", t),
                    "created": when, "modified": when, "name": name, "external_references": [ref]})

    def target(v, owner, when):
        for s in v.get("sectors") or []:
            i = add({"type": "identity", **common, "id": _uid("identity", "sector:" + s),
                     "created": when, "modified": when, "name": s, "identity_class": "class",
                     "sectors": [s]})
            rel(owner, i, "targets", when)
        for c in v.get("countries") or []:
            loc = add({"type": "location", **common, "id": _uid("location", c), "created": when,
                       "modified": when, "name": c, "country": c})
            rel(owner, loc, "targets", when)

    tool_ids = {}
    for a in intel["actors"]:
        when = _ts(a["derived"]["first_seen"], stamp[:10])
        ext = [{"source_name": "ai-dfir-toolkit", "external_id": a["id"]}]
        for g in (a.get("external_ids") or {}).get("attack_group") or []:
            ext.append({"source_name": "mitre-attack", "external_id": g,
                        "url": f"https://attack.mitre.org/groups/{g}/"})
        ext += [{"source_name": r["title"][:120], "url": r["url"]} for r in a["references"]]
        iset = add({"type": "intrusion-set", **common, "id": _uid("intrusion-set", a["id"]),
                    "created": when, "modified": when, "name": a["name"],
                    "description": a["summary"],
                    "aliases": [x["name"] for x in a.get("aliases") or []] or None,
                    "confidence": {"high": 85, "medium": 50, "low": 15}[a["confidence"]],
                    "external_references": ext})
        objs[-1] = {k: v for k, v in objs[-1].items() if v is not None} if objs[-1]["id"] == iset else objs[-1]
        for t in a["derived"]["techniques"] + a["derived"]["attack"]:
            rel(iset, attack_pattern(t, when), "uses", when)
        for m in a.get("malware") or []:
            mal = add({"type": "malware", **common, "id": _uid("malware", m.lower()), "created": when,
                       "modified": when, "name": m, "is_family": True})
            rel(iset, mal, "uses", when)
        for t in a["derived"]["tools"]:
            tool_ids[t] = True
            tl = add({"type": "tool", **common, "id": _uid("tool", t), "created": when,
                      "modified": when, "name": t,
                      "external_references": [{"source_name": "ai-dfir-toolkit", "external_id": t}]})
            rel(iset, tl, "uses", when)
        for s in a.get("sightings") or []:
            target(s.get("victims") or {}, iset, _ts(s["date"], stamp[:10]))

    for c in intel["cases"]:
        when = _ts(c.get("disclosed"), stamp[:10])
        refs = [{"source_name": "ai-dfir-toolkit", "external_id": c["id"]}]
        for k, vals in (c.get("external_ids") or {}).items():
            for v in vals if isinstance(vals, list) else [vals]:
                if k == "attack_campaign":
                    refs.append({"source_name": "mitre-attack", "external_id": v,
                                 "url": f"https://attack.mitre.org/campaigns/{v}/"})
                elif k == "atlas_case_study":
                    refs.append({"source_name": "mitre-atlas", "external_id": v,
                                 "url": f"https://atlas.mitre.org/studies/{v}"})
                elif k == "cve":
                    refs.append({"source_name": "cve", "external_id": v})
        refs += [{"source_name": r["title"][:120], "url": r["url"]} for r in c.get("references") or []]
        members = []
        owners = [_uid("intrusion-set", l["ref"]) for l in c.get("actors") or []]
        for t in (c.get("atlas") or []) + (c.get("attack") or []):
            members.append(attack_pattern(t, when))
        for i in c.get("iocs") or []:
            p = _pattern(i.get("type", ""), str(i.get("value", "")))
            if not p:
                continue
            ind = add({"type": "indicator", **common, "id": _uid("indicator", f"{c['id']}|{p}"),
                       "created": when, "modified": when, "name": _refang(str(i["value"]))[:200],
                       "description": str(i.get("description", ""))[:1000],
                       "indicator_types": ["malicious-activity"], "pattern": p,
                       "pattern_type": "stix", "valid_from": when})
            members.append(ind)
            for o in owners:
                rel(ind, o, "indicates", when)
        for t in c["affects_ids"]:
            members.append(add({"type": "tool", **common, "id": _uid("tool", t), "created": when,
                                "modified": when, "name": t,
                                "external_references": [{"source_name": "ai-dfir-toolkit",
                                                         "external_id": t}]}))
        if owners:
            members += owners
        victims = c.get("victims") or {}
        if victims and owners:
            for o in owners:
                target(victims, o, when)
        members = sorted(set(members)) or [ident]
        add({"type": "report", **common, "id": _uid("report", c["id"]), "created": when,
             "modified": when, "name": c["title"], "description": c.get("summary", ""),
             "published": when, "report_types": ["threat-report"],
             "object_refs": members, "external_references": refs})
    return {"type": "bundle", "id": _uid("bundle", "ai-dfir-intel"), "objects": objs}


MALTEGO_TYPE = {
    "actor": "maltego.Phrase", "case": "maltego.Phrase", "tool": "maltego.Phrase",
    "artifact": "maltego.File", "rule": "maltego.File", "technique": "maltego.Phrase",
    "tactic": "maltego.Phrase", "asi": "maltego.Phrase", "malware": "maltego.Phrase",
    "sector": "maltego.Phrase", "country": "maltego.Location", "region": "maltego.Location",
    "attack-group": "maltego.Phrase", "attack-campaign": "maltego.Phrase",
}
MALTEGO_IOC = {"domain": "maltego.Domain", "ip": "maltego.IPv4Address", "url": "maltego.URL",
               "email": "maltego.EmailAddress", "hash": "maltego.Hash", "file": "maltego.File"}


def maltego_csv(graph: dict) -> tuple[str, str]:
    """Two CSVs for Maltego's table import: entities, then links. Standard entity
    types only, so the import needs no custom entity pack; the node's own type
    travels in a Category column for filtering once it is in."""
    ent, lnk = io.StringIO(), io.StringIO()
    w = csv.writer(ent, lineterminator="\n")
    w.writerow(["EntityType", "Value", "Category", "Label"])
    typ = {}
    for n in graph["nodes"]:
        t = MALTEGO_IOC.get(n.get("ioc_type", ""), MALTEGO_TYPE.get(n["type"], "maltego.Phrase"))
        typ[n["id"]] = (t, n["id"] if n["type"] != "ioc" else _refang(n["label"]))
        w.writerow([t, typ[n["id"]][1], n["type"], n["label"]])
    w = csv.writer(lnk, lineterminator="\n")
    w.writerow(["SourceType", "SourceValue", "TargetType", "TargetValue", "Relationship"])
    for e in graph["edges"]:
        if e["source"] in typ and e["target"] in typ:
            s, t = typ[e["source"]], typ[e["target"]]
            w.writerow([s[0], s[1], t[0], t[1], e["rel"]])
    return ent.getvalue(), lnk.getvalue()


def write_lf(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def export(intel: dict, pin: dict) -> list[Path]:
    public = {"atlas_release": intel["atlas"]["release"], "stats": intel["stats"],
              "analytics": intel["analytics"],
              "actors": intel["actors"], "cases": intel["cases"], "graph": intel["graph"]}
    ent, lnk = maltego_csv(intel["graph"])
    out = {
        API / "intel.json": json.dumps(public, indent=1, ensure_ascii=False, sort_keys=False) + "\n",
        API / "stix" / "ai-dfir-intel.json": json.dumps(stix_bundle(intel, pin), indent=1,
                                                        ensure_ascii=False) + "\n",
        API / "graph" / "maltego-entities.csv": ent,
        API / "graph" / "maltego-links.csv": lnk,
    }
    for p, text in out.items():
        write_lf(p, text)
    return list(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--export", action="store_true")
    args = ap.parse_args()
    src = load_sources()
    problems = check(src)
    for p in problems:
        print(p)
    if args.check:
        print(f"\n{len(problems)} problem(s).")
        return 1 if problems else 0
    intel = build(src)
    s = intel["stats"]
    print(f"{s['actors']} actors, {s['cases']} cases, {s['iocs']} indicators "
          f"({s['atomic_iocs']} atomic), {s['techniques_observed']} ATLAS techniques "
          f"observed, {s['techniques_covered']} with a rule, {s['techniques_off_host']} "
          f"off-host; graph "
          f"{len(intel['graph']['nodes'])} nodes / {len(intel['graph']['edges'])} edges")
    from datetime import date, timedelta
    cutoff = (date.today() - timedelta(days=365)).isoformat()
    for a in intel["actors"]:
        d = a["derived"]
        if d["gaps"]:
            print(f"  [GAP]    {a['id']} {a['name']}: no rule for {', '.join(d['gaps'])}")
        # Reported, not failed: an actor going quiet is information, not a defect.
        # But a profile nobody has looked at in a year should be looked at.
        if d["last_seen"] and d["last_seen"] < cutoff:
            print(f"  [STALE]  {a['id']} {a['name']}: last activity {d['last_seen']}, "
                  f"over a year ago - re-check the sources for newer reporting")
    if args.export:
        for p in export(intel, src["pin"]):
            print(f"wrote {p.relative_to(ROOT)}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
