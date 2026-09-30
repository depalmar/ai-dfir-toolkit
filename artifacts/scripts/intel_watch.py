#!/usr/bin/env python3
"""Poll threat-intel sources and file new items as GitHub issues for review.

    python scripts/intel_watch.py --dry-run                 # print candidates, touch nothing
    python scripts/intel_watch.py                           # open issues (needs GITHUB_TOKEN)
    python scripts/intel_watch.py --dry-run --kev-file kev.json --atlas-dir atlas-data/dist \\
        --avid-dir avid-db                                  # offline, from local mirrors

This is the half of the automation that never merges anything. A framework
refresh is mechanical and can merge itself (framework-refresh.yml); a new
incident, actor or advisory needs judgement - is it in scope, what does the
source actually say, who else corroborates it - so it arrives as an issue
labelled intel-candidate with facts and a link, and a person or a session with
vendor egress researches it before anything reaches the catalog.

Deduplication has no state file. Every candidate carries a stable key in its
title - "[intel] <source>:<id>" - and a key already present in any open or
closed intel-candidate issue is skipped. Closing an issue as not relevant is
therefore how you tell the watcher to stop raising it.

Each source fails on its own. A feed that has moved logs a warning and the run
continues, because one dead URL must not stop the other nine from reporting.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "intel" / "watch-sources.yml"
UA = {"User-Agent": "ai-dfir-toolkit-intel-watch (+https://github.com/depalmar/ai-dfir-toolkit)"}


def fetch(url: str, data: bytes | None = None, headers: dict | None = None) -> bytes:
    req = urllib.request.Request(url, data=data, headers={**UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


# Catalog names that are also ordinary words or platform names.
GENERIC = {"open source", "community", "various", "continue", "agent framework libraries",
           "github copilot", "copilot", "codex", "operator", "goose", "warp", "kiro", "jan.ai"}


def catalog_terms() -> tuple[set[str], dict]:
    terms, entries = set(), {}
    for f in glob.glob(str(ROOT / "catalog" / "*.yml")):
        e = yaml.safe_load(Path(f).read_text(encoding="utf-8"))
        entries[e["id"]] = e
        # Tool names and aliases, not vendors: "Microsoft" and "Google" as terms
        # matched every Windows and Chrome KEV entry - 420 candidates on a
        # three-week window, which is noise nobody would read.
        for t in [e.get("name", "")] + list(e.get("aliases") or []):
            for part in re.split(r"\s*/\s*", re.sub(r"\s*\(.*?\)", "", str(t))):
                part = part.strip()
                if len(part) >= 4 and part.lower() not in GENERIC:
                    terms.add(part.lower())
    return terms, entries


def hits(text: str, terms: set[str]) -> list[str]:
    low = text.lower()
    return sorted(t for t in terms if re.search(r"(?<![a-z0-9])" + re.escape(t) + r"(?![a-z0-9])", low))


# --------------------------------------------------------------------- sources
# Every source returns [{"key", "title", "date", "url", "facts": {...}}].

def src_kev(cfg, ctx):
    raw = Path(ctx["kev_file"]).read_bytes() if ctx.get("kev_file") else fetch(cfg["url"])
    kev = json.loads(raw)
    pinned = set(json.loads((ROOT / "schema" / "cve-status.json").read_text())["cves"])
    out = []
    for v in kev.get("vulnerabilities", []):
        text = f"{v.get('vendorProject', '')} {v.get('product', '')} {v.get('vulnerabilityName', '')}"
        h = hits(text, ctx["catalog_terms"])
        recent = v.get("dateAdded", "") >= ctx["since"]
        if (h and recent) or (v["cveID"] in pinned and recent):
            out.append({"key": v["cveID"], "title": f"{v['cveID']} {v.get('vendorProject')} "
                        f"{v.get('product')} added to CISA KEV", "date": v.get("dateAdded"),
                        "url": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
                        "facts": {"vendor": v.get("vendorProject"), "product": v.get("product"),
                                  "name": v.get("vulnerabilityName"), "due": v.get("dueDate"),
                                  "ransomware": v.get("knownRansomwareCampaignUse"),
                                  "catalog_match": ", ".join(h) or "cited CVE"}})
    return out


def src_atlas(cfg, ctx):
    pin = json.loads((ROOT / "schema" / "technique-ids.json").read_text())["atlas"]
    base = Path(ctx["atlas_dir"]) if ctx.get("atlas_dir") else None
    load = (lambda p: yaml.safe_load((base / p).read_text())) if base else \
        (lambda p: yaml.safe_load(fetch(cfg["url"] + p)))
    manifest = load("manifest.yaml")
    newest = max(manifest, key=lambda r: tuple(int(x) for x in str(r["release"]).split(".")))
    doc = load(newest["versions"][0]["path"])
    studies = doc.get("case-studies") or {}
    studies = studies.values() if isinstance(studies, dict) else studies
    out = []
    for cs in studies:
        if cs["id"] in pin.get("case_studies", {}):
            continue
        out.append({"key": cs["id"], "title": f"New ATLAS case study {cs['id']}: {cs.get('name', '')}",
                    "date": str(cs.get("date", "")),
                    "url": f"https://atlas.mitre.org/studies/{cs['id']}",
                    "facts": {"release": newest["release"], "type": cs.get("type", "")}})
    return out


def src_avid(cfg, ctx):
    d = Path(ctx["avid_dir"]) if ctx.get("avid_dir") else None
    if d is None:
        import subprocess
        import tempfile
        d = Path(tempfile.mkdtemp()) / "avid-db"
        subprocess.run(["git", "clone", "-q", "--depth", "1", cfg["url"], str(d)], check=True)
    out = []
    for f in sorted(d.glob("reports/*/AVID-*.json")):
        try:
            r = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        when = str(r.get("reported_date", ""))
        if when < ctx["since"]:
            continue
        impact = r.get("impact")
        impact = impact if isinstance(impact, dict) else {}
        domains = (impact.get("avid") or {}).get("risk_domain") or []
        text = json.dumps(r.get("problemtype", {})) + json.dumps(r.get("affects", {}))
        # Catalogued tools only. AVID is dominated by automated model-scanner
        # reports that all say "LLM", which the generic terms would match.
        h = hits(text, ctx["catalog_terms"])
        if "Security" in domains and h:
            rid = r.get("metadata", {}).get("report_id") or f.stem
            out.append({"key": rid, "title": f"AVID {rid}: " + str(
                (r.get("problemtype") or {}).get("description", {}).get("value", ""))[:120],
                "date": when, "url": f"https://avidml.org/database/{rid.lower()}",
                "facts": {"matched": ", ".join(h[:8]), "risk_domain": ", ".join(domains)}})
    return out


AIID_QUERY = """query($since: String) {
  incidents(filter: {date: {GTE: $since}}, sort: {incident_id: DESC}, pagination: {limit: 200}) {
    incident_id title date
    classifications { namespace attributes { short_name value_json } }
  }
}"""


def src_aiid(cfg, ctx):
    body = json.dumps({"query": AIID_QUERY, "variables": {"since": ctx["since"]}}).encode()
    data = json.loads(fetch(cfg["url"], body, {"Content-Type": "application/json"}))
    out = []
    for inc in (data.get("data") or {}).get("incidents") or []:
        domains = []
        for c in inc.get("classifications") or []:
            if "MIT" in str(c.get("namespace", "")):
                for a in c.get("attributes") or []:
                    domains += re.findall(r"\b\d\.\d\b", str(a.get("value_json", "")))
        h = hits(inc.get("title", ""), ctx["catalog_terms"] | ctx["match"])
        if h or set(domains) & set(cfg.get("mit_domains") or []):
            iid = inc["incident_id"]
            out.append({"key": str(iid), "title": f"AIID incident {iid}: {inc.get('title', '')[:120]}",
                        "date": inc.get("date", ""), "url": f"https://incidentdatabase.ai/cite/{iid}",
                        "facts": {"mit_domains": ", ".join(sorted(set(domains))) or "-",
                                  "matched": ", ".join(h[:8]) or "-",
                                  "licence": "AIID data is CC BY-SA 4.0 - record ids and links only"}})
    return out


def src_markdown_table(cfg, ctx):
    text = fetch(cfg["url"]).decode("utf-8", "replace")
    out = []
    for line in text.splitlines():
        if not line.startswith("|") or set(line) <= set("|-: "):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 3 or cells[0].lower() in ("date", ""):
            continue
        key = re.sub(r"[^a-z0-9]+", "-", (cells[0] + " " + cells[1]).lower()).strip("-")[:80]
        links = re.findall(r"\((https?://[^)]+)\)", line)
        out.append({"key": key, "title": f"OWASP ASI tracker: {cells[1][:120]}",
                    "date": cells[0], "url": links[0] if links else cfg["url"],
                    "facts": {"asi": ", ".join(sorted(set(re.findall(r"ASI\d{2}", line)))) or "-",
                              "licence": "OWASP content is CC BY-SA 4.0 - record ids and links only"}})
    return out


def src_feed(cfg, ctx):
    root = ET.fromstring(fetch(cfg["url"]))
    ns = {"a": "http://www.w3.org/2005/Atom"}
    items = [(i.findtext("title") or "", i.findtext("link") or "", i.findtext("pubDate") or "",
              i.findtext("description") or "") for i in root.iter("item")]
    items += [(e.findtext("a:title", namespaces=ns) or "",
               (e.find("a:link", ns).get("href") if e.find("a:link", ns) is not None else ""),
               e.findtext("a:updated", namespaces=ns) or "", e.findtext("a:summary", namespaces=ns) or "")
              for e in root.iter("{http://www.w3.org/2005/Atom}entry")]
    out = []
    for title, link, when, desc in items:
        d = _date(when)
        if d and d < ctx["since"]:
            continue
        h = hits(title + " " + re.sub(r"<[^>]+>", " ", desc), ctx["catalog_terms"] | ctx["match"])
        if h:
            out.append({"key": re.sub(r"[^a-z0-9]+", "-", link.lower())[-80:] or title[:60],
                        "title": title[:140], "date": d or when, "url": link,
                        "facts": {"matched": ", ".join(h[:8])}})
    return out


def src_ghsa(cfg, ctx):
    out = []
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {token}"} if token else {})}
    for eco, pkgs in (cfg.get("ecosystems") or {}).items():
        for pkg in pkgs:
            q = urllib.parse.urlencode({"ecosystem": eco, "affects": pkg, "type": "reviewed",
                                        "published": f">={ctx['since']}", "per_page": 50})
            for adv in json.loads(fetch(f"https://api.github.com/advisories?{q}", headers=headers)):
                out.append({"key": adv["ghsa_id"], "title": f"{adv['ghsa_id']} {pkg}: {adv.get('summary', '')[:110]}",
                            "date": str(adv.get("published_at", ""))[:10], "url": adv.get("html_url", ""),
                            "facts": {"package": f"{eco}:{pkg}", "severity": adv.get("severity"),
                                      "cve": adv.get("cve_id") or "-"}})
    return out


def _date(s: str) -> str:
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return datetime.strptime(s.strip(), fmt).date().isoformat()
        except ValueError:
            continue
    m = re.search(r"\d{4}-\d{2}-\d{2}", s or "")
    return m.group(0) if m else ""


SOURCES = {"kev": src_kev, "atlas": src_atlas, "avid": src_avid, "aiid": src_aiid,
           "markdown-table": src_markdown_table, "feed": src_feed, "ghsa": src_ghsa}


# ------------------------------------------------------------------------ issues

def existing_keys(repo: str, token: str) -> set[str]:
    keys, page = set(), 1
    while True:
        q = urllib.parse.urlencode({"labels": "intel-candidate", "state": "all", "per_page": 100, "page": page})
        batch = json.loads(fetch(f"https://api.github.com/repos/{repo}/issues?{q}",
                                 headers={"Authorization": f"Bearer {token}",
                                          "Accept": "application/vnd.github+json"}))
        for i in batch:
            m = re.match(r"\[intel\] (\S+)", i.get("title", ""))
            if m:
                keys.add(m.group(1))
        if len(batch) < 100:
            return keys
        page += 1


def issue_body(src: dict, c: dict) -> str:
    facts = "\n".join(f"| {k} | {v} |" for k, v in c["facts"].items())
    return f"""Raised automatically by `scripts/intel_watch.py` from **{src['id']}** ({src.get('note', '')}).

| Field | Value |
|---|---|
| Source date | {c.get('date') or '-'} |
| Link | {c['url']} |
{facts}

This is a lead, not a finding. Nothing here has been read beyond its title and
metadata. Before it reaches the catalog:

- [ ] Read the primary source, not a summary of it
- [ ] Decide scope: does it touch a catalogued tool, an agent runtime or MCP, or an actor in scope (attributed or named cluster)?
- [ ] Second, independent source found - or record it as single-source (`medium` at most)
- [ ] Adversarial pass: what would make this wrong? (RESEARCH-2026-08-14.md method)
- [ ] Licence: facts only from CC BY-SA sources (AIID, OWASP) - ids, dates, names, links; our own words
- [ ] If it becomes a case study: indicators, detections, `actors` links with `stated_confidence`, `victims` only as stated
- [ ] Gates: `validate.py`, `intel_graph.py --check`, `build_site.py --check`

Close as not planned to stop the watcher raising it again.
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--only", nargs="*", help="source ids to run")
    ap.add_argument("--since", help="ISO date; default is lookback_days from the config")
    ap.add_argument("--kev-file")
    ap.add_argument("--atlas-dir")
    ap.add_argument("--avid-dir")
    ap.add_argument("--max-issues", type=int, default=25,
                    help="cap per run, so a first run or a noisy source cannot flood the tracker")
    args = ap.parse_args()
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    terms, _ = catalog_terms()
    since = args.since or (date.today() - timedelta(days=int(cfg.get("lookback_days", 21)))).isoformat()
    ctx = {"since": since, "catalog_terms": terms,
           "match": {m.lower() for m in cfg.get("match") or []},
           "kev_file": args.kev_file, "atlas_dir": args.atlas_dir, "avid_dir": args.avid_dir}
    found, warnings = [], []
    for src in cfg["sources"]:
        if args.only and src["id"] not in args.only:
            continue
        try:
            for c in SOURCES[src["kind"]](src, ctx):
                found.append((src, c))
        except Exception as exc:  # one dead source must not stop the rest
            warnings.append(f"{src['id']}: {type(exc).__name__}: {str(exc)[:160]}")
    for w in warnings:
        print(f"::warning::{w}")

    token, repo = os.environ.get("GITHUB_TOKEN", ""), os.environ.get("GITHUB_REPOSITORY", "")
    have = existing_keys(repo, token) if (token and repo and not args.dry_run) else set()
    fresh = [(s, c) for s, c in found if f"{s['id']}:{c['key']}" not in have]
    print(f"{len(found)} candidate(s) since {since}, {len(fresh)} new")
    opened = 0
    for src, c in fresh:
        key = f"{src['id']}:{c['key']}"
        title = f"[intel] {key} - {c['title']}"[:240]
        if args.dry_run or not (token and repo):
            print(f"  {title}\n    {c['url']}")
            continue
        if opened >= args.max_issues:
            print(f"::notice::cap of {args.max_issues} reached; the rest will be raised next run")
            break
        fetch(f"https://api.github.com/repos/{repo}/issues",
              json.dumps({"title": title, "body": issue_body(src, c),
                          "labels": ["intel-candidate", f"source:{src['id']}"]}).encode(),
              {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
               "Content-Type": "application/json"})
        opened += 1
    if opened:
        print(f"opened {opened} issue(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
