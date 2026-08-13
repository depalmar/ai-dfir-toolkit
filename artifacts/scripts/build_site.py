#!/usr/bin/env python3
"""Build the browsable catalog site from the generated feeds.

    python scripts/build_site.py            # writes docs/site/
    python scripts/build_site.py --check    # verify the data contract, write nothing

The site is generated, never hand-edited. It reads docs/api/catalog.json, which
scripts/export.py regenerates from the YAML entries, so the page cannot drift
from the catalog: there is no independent copy of the content to fall stale.

Output is a single self-contained HTML file with the rows inlined as JSON. No
framework, no CDN, no external font, no build toolchain - one file to serve and
nothing to keep patched. It is deliberately not committed; CI builds it at
deploy time. The social-card image (docs/site-assets/card.png) is the one
static asset: branding rather than data - deliberately count-free - so
committing it cannot go stale. Dynamic counts live in og:description, which
this build writes.

UI per the design handoff (design_handoff_catalog_site): faceted filter rail
with exclude-own-group counts, artifact detail drawer with per-row permalinks,
a triage-ordered collection plan with clipboard export, token-driven dark mode
with a pre-paint theme script, and hash deep links (#<ENTRY>/<class>/<slug>).
"""
import html
import json
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import data_sources
import site_data  # noqa: E402  (same-directory build helper)

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / "docs" / "api"
ASSETS = ROOT / "docs" / "site-assets"
OUT = ROOT / "docs" / "site"

REPO = "https://github.com/depalmar/ai-dfir-toolkit"
SITE = "https://depalmar.github.io/ai-dfir-toolkit/"

FAVICON = (
    "data:image/svg+xml,"
    "%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E"
    "%3Crect width='32' height='32' rx='7' fill='%238a4b2a'/%3E"
    "%3Ctext x='16' y='22' font-family='monospace' font-size='15' fill='%23fff'"
    " text-anchor='middle'%3E~/%3C/text%3E%3C/svg%3E"
)

CAP_LABELS = [
    ("local_code_execution", "local code exec"),
    ("local_listener", "local listener"),
    ("plaintext_credentials", "plaintext creds"),
    ("mcp_capable", "MCP capable"),
]


def write_lf(path: Path, text: str) -> None:
    """LF on every platform, so output is byte-identical wherever it is built."""
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def slugify(s: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s[:56]


def aslist(v):
    if isinstance(v, list):
        return v
    return [v] if v else []


def evidence_for(kind, a):
    """What a row proves, for the classes the schema does not carry it on.

    Only diskArtifact declares evidence_type, which would leave every registry,
    network and process row - 107 of 298 - with an empty "what it proves"
    section. These derivations are deterministic from fields that already exist
    and stay inside the schema's evidence_type vocabulary, so the site is
    consistent with the feed rather than inventing a second one.

    The durable fix is declaring evidence_type on those three artifact types in
    the schema; until then a hand-authored artifact that proves something
    unusual cannot say so. See docs/HANDOFF_REVIEW.md.
    """
    declared = aslist(a.get("evidence_type"))
    if declared:
        return declared

    if kind == "registry":
        # A Run key proves persistence; every other value still proves config.
        return ["persistence", "configuration"] if a.get("persistence") else ["configuration"]

    if kind == "network":
        # A bound port proves the program is there and how it was configured.
        # 'ingress-(loopback)' is a listener too, just a loopback-scoped one.
        d = str(a.get("direction", "")).lower()
        if d.startswith(("listener", "ingress")):
            return ["program-presence", "configuration"]
        return ["program-presence"]

    if kind == "eventlog":
        # Every row here is a record that something ran, at a known time.
        return ["execution", "timeline"]

    if kind == "process":
        ev = ["execution", "program-presence"]
        # Free text, not an enum: 'None', 'None (user-invoked)' and
        # 'None - PORTABLE SINGLE BINARY' all mean no persistence, so match on
        # the leading word rather than the whole string.
        p = str(a.get("persistence", "")).strip().lower()
        if p and not p.startswith(("none", "no ", "-")):
            ev.append("persistence")
        return ev

    return []


def build_rows(entries):
    """Flatten the catalog into one row per artifact.

    Covers the same corpus as docs/api/artifacts.csv - disk, network, process
    and registry artifacts, plus credential locations and MCP configs. Locators
    are merged for display (registry key -> value, network indicator :port,
    MCP path -> key); the CSV feed keeps its raw columns - this flattening is
    the site's own, so the published feed stays stable.

    Each row gets a deterministic `anchor` (ENTRY/class/slug) computed here so
    permalinks are stable across builds; collisions get -2, -3 in row order.
    """
    rows = []
    for e in entries:
        eid = e["id"]
        # The schema declares `os` on disk, process and credential rows only, so
        # registry, network and MCP rows carry none - and a row with no OS matched
        # no OS facet, which silently hid every registry key, every listening port
        # and every MCP config the moment a reader clicked one. Inherit the entry's
        # supported_os rather than making blank rows match everything: a cloud-only
        # tool must not appear under `windows` just because its row is unlabelled.
        entry_os = aslist(e.get("supported_os"))
        for kind, items in (e.get("artifacts") or {}).items():
            for a in items:
                if kind == "registry":
                    loc = a.get("key", "")
                    if a.get("value"):
                        loc += " → " + str(a["value"])
                elif kind == "network":
                    loc = a.get("indicator", "")
                    if a.get("port"):
                        loc += " :" + str(a["port"])
                elif kind == "eventlog":
                    # Channel plus ID is the locator a responder types into a
                    # query bar, and it is unique per row within an entry.
                    loc = a.get("channel", "")
                    if a.get("event_id"):
                        loc += " EID " + str(a["event_id"])
                else:
                    loc = a.get("path") or a.get("name") or ""
                rows.append({
                    "entry_id": eid, "tool": e["name"], "cls": kind,
                    "artifact": loc,
                    "os": aslist(a.get("os")) or entry_os,
                    "forensic_value": a.get("forensic_value", ""),
                    "confidence": a.get("confidence", ""),
                    "evidence": evidence_for(kind, a),
                    "unverified": bool(a.get("unverified")),
                    "description": a.get("description", ""),
                    # Event log rows depend on configuration that is off by
                    # default. Without this a reader takes the row as evidence
                    # waiting to be collected, when on most hosts it is absent.
                    "requires": a.get("requires", ""),
                    # Will it still be there when you get to the host. Derived
                    # from the class and the artifact type rather than authored,
                    # for the same reason evidence_type is derived above: 507
                    # hand-set copies of one rule drift, one function does not.
                    "vol": data_sources.volatility_of(kind, a),
                    "retention": a.get("retention", ""),
                })
        for c in (e.get("credentials") or []):
            rows.append({
                "entry_id": eid, "tool": e["name"], "cls": "credential",
                "artifact": c.get("location", ""),
                "os": aslist(c.get("os")) or entry_os,
                "forensic_value": "high",
                "confidence": c.get("confidence", ""),
                # secret_type answers "what is it", not "what does it prove",
                # and mixing the two vocabularies in one field is what makes a
                # feed unfilterable. It moves into the description instead.
                "evidence": ["credential-access"],
                "unverified": bool(c.get("unverified")),
                "description": " · ".join(x for x in (
                    ": ".join(y for y in (c.get("storage"), c.get("secret_type")) if y),
                    c.get("description", "")) if x),
                # The file survives reboot. The token inside it may already have
                # rotated, which is a different question and belongs to the
                # description rather than to volatility.
                "vol": data_sources.volatility_of("credential", c),
                "retention": "",
            })
        for m in (e.get("mcp") or []):
            loc = m.get("config_path", "")
            if m.get("config_key"):
                loc += " → " + str(m["config_key"])
            rows.append({
                "entry_id": eid, "tool": e["name"], "cls": "mcp-config",
                "artifact": loc,
                "os": entry_os,
                "forensic_value": "high",
                "confidence": "high",
                "evidence": ["execution", "persistence"],
                "unverified": False,
                "description": m.get("notes", ""),
                "vol": data_sources.volatility_of("mcp-config", m),
                "retention": "",
            })
    seen = {}
    for r in rows:
        base = f"{r['entry_id']}/{r['cls']}/{slugify(r['artifact'])}"
        n = seen.get(base, 0) + 1
        seen[base] = n
        r["anchor"] = base if n == 1 else f"{base}-{n}"
    return rows


def build_tools(entries, rows):
    """Per-tool summary keyed by entry id - the drawer and Tools view context."""
    counts = {}
    for r in rows:
        counts[r["entry_id"]] = counts.get(r["entry_id"], 0) + 1
    tools = []
    for e in entries:
        caps = e.get("capabilities") or {}
        labels = [label for key, label in CAP_LABELS if caps.get(key)]
        # "no default auth" is derived from the data, never hardcoded
        for a in (e.get("artifacts") or {}).get("network", []):
            if str(a.get("authentication", "")).strip().lower() == "none":
                labels.append("no default auth")
                break
        tools.append({
            "entry_id": e["id"],
            "tool": e["name"],
            "slug": slugify(e["name"]),
            # Former and alternate names. Carried on the tool rather than on
            # each of its rows, because 45 entries is a much smaller payload
            # than 434 rows and the row search can look it up.
            "aliases": aslist(e.get("aliases")),
            # Where the entry's facts came from. The catalog says confidence
            # reflects provenance, so the provenance has to be visible.
            "refs": [{"title": str(r.get("title", "")), "url": str(r.get("url", ""))}
                     for r in (e.get("references") or []) if isinstance(r, dict)],
            "status": e.get("status", ""),
            "verified": e.get("last_verified", ""),
            "vendor": e.get("vendor", ""),
            "category": e.get("category", ""),
            "risk": e.get("risk", ""),
            "confidence": e.get("confidence", ""),
            "os": aslist(e.get("supported_os")),
            "triage": (e.get("collection") or {}).get("triage_priority", ""),
            "guidance": (e.get("collection") or {}).get("guidance", ""),
            "description": e.get("description", ""),
            "abuse": e.get("abuse_potential", ""),
            "techniques": aslist(e.get("atlas_techniques")) + aslist(e.get("attack_techniques")),
            "caps": labels,
            "n": counts.get(e["id"], 0),
        })
    return tools


CSS = """
:root{
  --bg:#fbfbfa; --panel:#ffffff; --panel-2:#fbfbfa; --hover:#faf7f4;
  --ink:#1c1b19; --muted:#6b6862; --faint:#a09b90;
  --line:#e4e1db; --line-soft:#f0ede8; --field-line:#ddd8d0;
  --accent:#8a4b2a; --accent-hover:#753d21; --accent-soft:#f2e9e2;
  --accent-soft-2:#ecdfd4; --accent-border:#e0cfc1;
  --on-accent:#ffffff; --on-tone:#ffffff;
  --crit:#a12b2b; --high:#b4611c; --med:#8a7320; --low:#5c7a4a;
  --val-strong:#1f6f6a; --val-mid:#5d8f8b; --val-bg:#e8f2f0;
  --conf-strong:#3d5a80; --conf-mid:#6b7f96; --conf-bg:#eef2f7;
  --alert-bg:#fdf6f2; --alert-line:#f0ded1;
  --toast-bg:#1c1b19; --toast-ink:#fbfbfa; --toast-muted:#a09b90;
  --shadow:rgba(28,27,25,.09); --shadow-soft:rgba(28,27,25,.05);
}
:root[data-theme=dark]{
  --bg:#121110; --panel:#1a1917; --panel-2:#211f1c; --hover:#262320;
  --ink:#f1eee9; --muted:#a9a39a; --faint:#7c766e;
  --line:#302d29; --line-soft:#262320; --field-line:#3b3733;
  --accent:#e9a97d; --accent-hover:#f6bd93; --accent-soft:#2d2118;
  --accent-soft-2:#3a2b20; --accent-border:#553a29;
  --on-accent:#1a1310; --on-tone:#151210;
  --crit:#f28c85; --high:#eaa965; --med:#d9c364; --low:#a6d18c;
  --val-strong:#7fd0c7; --val-mid:#6f9b96; --val-bg:#152a29;
  --conf-strong:#9ec0e0; --conf-mid:#7e94ab; --conf-bg:#1b2530;
  --alert-bg:#251a16; --alert-line:#452a20;
  --toast-bg:#f1eee9; --toast-ink:#151210; --toast-muted:#6b6862;
  --shadow:rgba(0,0,0,.55); --shadow-soft:rgba(0,0,0,.4);
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme=light]):not([data-theme=dark]){
    --bg:#121110; --panel:#1a1917; --panel-2:#211f1c; --hover:#262320;
    --ink:#f1eee9; --muted:#a9a39a; --faint:#7c766e;
    --line:#302d29; --line-soft:#262320; --field-line:#3b3733;
    --accent:#e9a97d; --accent-hover:#f6bd93; --accent-soft:#2d2118;
    --accent-soft-2:#3a2b20; --accent-border:#553a29;
    --on-accent:#1a1310; --on-tone:#151210;
    --crit:#f28c85; --high:#eaa965; --med:#d9c364; --low:#a6d18c;
    --val-strong:#7fd0c7; --val-mid:#6f9b96; --val-bg:#152a29;
    --conf-strong:#9ec0e0; --conf-mid:#7e94ab; --conf-bg:#1b2530;
    --alert-bg:#251a16; --alert-line:#452a20;
    --toast-bg:#f1eee9; --toast-ink:#151210; --toast-muted:#6b6862;
    --shadow:rgba(0,0,0,.55); --shadow-soft:rgba(0,0,0,.4);
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  -webkit-text-size-adjust:100%}
:root[data-theme=dark] body{
  background:var(--bg) radial-gradient(900px 420px at 18% -8%,#1d1a17 0%,transparent 70%) fixed}
a{color:var(--accent)}
button{font:inherit;color:inherit;cursor:pointer}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
p{text-wrap:pretty}

/* ---- header ---- */
.hdr{position:sticky;top:0;z-index:20;background:var(--bg);
  border-bottom:1px solid var(--line)}
.hdr-in{max-width:1440px;margin:0 auto;padding:14px 28px 0}
.hdr-top{display:flex;flex-wrap:wrap;gap:10px 24px;align-items:flex-start}
.hdr-id{flex:1 1 340px;min-width:0}
.h1row{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.dot{width:9px;height:9px;border-radius:50%;background:var(--accent);flex:none}
h1{margin:0;font-size:19px;font-weight:600;letter-spacing:-.01em}
.pill{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;color:var(--muted);
  background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:2px 8px}
.sub{margin:5px 0 0;font-size:13.5px;color:var(--muted);max-width:62ch}
.hdr-right{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
/* Visible only once focused: the filter rail has six facet groups, one listing
   45 tools, and a keyboard user otherwise tabs through all of it to reach a row. */
.skip{position:absolute;left:-9999px;top:0;z-index:100;background:var(--accent);
  color:var(--on-accent);padding:10px 16px;border-radius:0 0 8px 0;font-size:13px}
.skip:focus{left:0}
main.content{min-width:0}
/* The unverified count keeps the warning colour it had as a stat: it is the one
   figure on the page a reader should feel rather than merely read. */
#unvBtn .n{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;
  background:var(--alert-bg);color:var(--crit);border-radius:20px;padding:1px 6px;
  margin-left:5px;font-variant-numeric:tabular-nums}
#unvBtn[aria-pressed=true] .n{background:var(--on-accent);color:var(--crit)}
#themeBtn{background:var(--panel);border:1px solid var(--line);border-radius:8px;
  padding:7px 11px;font-size:12.5px;color:var(--muted)}
#themeBtn:hover{color:var(--ink);border-color:var(--accent)}
.tabs{display:flex;gap:2px;margin-top:8px}
.tabs button{background:none;border:0;border-bottom:2px solid transparent;
  padding:9px 14px;font-size:13.5px;color:var(--muted);display:flex;gap:7px;align-items:center}
.tabs button[aria-selected=true]{color:var(--ink);font-weight:600;border-bottom-color:var(--accent)}
.tabs .n{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;background:var(--line-soft);
  border-radius:20px;padding:1px 7px;color:var(--muted)}
/* Set apart visually - pushed right, no count - but it is a real tab, because a
   link inside role=tablist breaks arrow-key navigation. */
.tabs .guidelink{margin-left:auto;font-size:12.5px;border:1px solid var(--accent-border);
  background:var(--accent-soft);color:var(--accent);border-radius:999px;padding:6px 14px;
  align-self:center;font-weight:600}
.tabs .guidelink:hover{background:var(--accent-soft-2);border-color:var(--accent)}
.tabs .guidelink[aria-selected=true]{background:var(--accent);border-color:var(--accent);
  color:var(--on-accent);border-bottom-color:var(--accent)}
.exportgrp{display:flex;align-items:center;gap:6px;margin-left:auto}
.exportlbl{font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
.ghlink{font-size:12.5px;text-decoration:none;color:var(--muted);
  border:1px solid var(--line);background:var(--panel);border-radius:8px;padding:7px 11px}
.ghlink:hover{color:var(--ink);border-color:var(--accent)}

/* ---- shell ---- */
.shell{max-width:1440px;margin:0 auto;padding:20px 28px 90px;display:grid;
  grid-template-columns:224px minmax(0,1fr);gap:24px;align-items:start}
.shell.nocol{grid-template-columns:minmax(0,1fr)}
.shell.nocol>aside{display:none}

/* ---- filter rail ---- */
aside .railhead{display:flex;justify-content:space-between;align-items:baseline;margin:2px 0 10px}
aside .railhead b{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
aside .railhead a{font-size:12px;cursor:pointer}
.railscroll{position:sticky;top:150px;max-height:calc(100vh - 180px);overflow:auto;
  padding-right:4px}
.fgroup{margin:0 0 16px}
.fgroup h3{margin:0;font-size:11px;letter-spacing:.06em;text-transform:uppercase;
  color:var(--faint);font-weight:600}
details.fgroup>summary{display:flex;align-items:center;gap:6px;cursor:pointer;
  list-style:none;padding:2px 8px 5px 0;border-radius:6px}
details.fgroup>summary::-webkit-details-marker{display:none}
/* Caret ahead of the label, rotating on open, so the affordance is visible
   without the browser's default triangle fighting the uppercase heading. */
details.fgroup>summary::before{content:"";width:0;height:0;flex:none;
  border-left:4px solid var(--faint);border-top:3.5px solid transparent;
  border-bottom:3.5px solid transparent;transition:transform .12s ease}
details.fgroup[open]>summary::before{transform:rotate(90deg)}
details.fgroup>summary:hover h3{color:var(--muted)}
/* A collapsed group with active filters has to say so, or a reader sees a short
   result list and no visible reason for it. */
.fon{font-family:ui-monospace,Menlo,monospace;font-size:10px;background:var(--accent-soft);
  border:1px solid var(--accent-border);color:var(--accent);border-radius:20px;
  padding:0 6px;margin-left:auto}
.fbtn{display:flex;width:100%;justify-content:space-between;gap:8px;align-items:center;
  background:none;border:1px solid transparent;border-radius:7px;padding:5px 8px;
  font-size:12.5px;color:var(--ink);text-align:left}
.fbtn .c{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--faint)}
.fbtn:hover{background:var(--accent-soft)}
.fbtn[aria-pressed=true]{background:var(--accent-soft);border-color:var(--accent-border);
  color:var(--accent);font-weight:500}
details.railfold{display:none}

/* ---- controls ---- */
.controls{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 10px}
.controls[hidden],.meta-row[hidden],.tgl[hidden]{display:none!important}
.search{position:relative;flex:1 1 320px}
.search .glyph{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--faint)}
.search input{width:100%;background:var(--panel);color:var(--ink);border:1px solid var(--line);
  border-radius:8px;padding:9px 12px 9px 30px;font:inherit}
.search input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.tgl{background:var(--panel);border:1px solid var(--line);border-radius:8px;
  padding:8px 12px;font-size:12.5px;color:var(--muted)}
.tgl:hover{color:var(--ink)}
.tgl[aria-pressed=true]{background:var(--accent-soft);border-color:var(--crit);color:var(--crit)}
.tgl.plain[aria-pressed=true]{border-color:var(--accent);color:var(--accent)}
.meta-row{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:0 0 10px}
.count{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--muted)}
.chip{display:inline-flex;gap:6px;align-items:center;background:var(--accent-soft);
  border:1px solid var(--accent-border);color:var(--accent);border-radius:20px;
  padding:2px 9px;font-size:11.5px;cursor:pointer}
.chip:hover{background:var(--accent-soft-2)}
.chip s{text-decoration:none;color:var(--faint)}

/* ---- badges ---- */
.badge{display:inline-block;padding:1px 8px;border-radius:20px;font-size:11px;
  font-weight:500;white-space:nowrap;border:1px solid currentColor;background:transparent}
.badge.fill{border-color:transparent;color:var(--on-tone)}
.b-crit{color:var(--crit)} .b-high{color:var(--high)} .b-med{color:var(--med)} .b-low{color:var(--low)}
.badge.fill.b-crit{background:var(--crit)} .badge.fill.b-high{background:var(--high)}
.badge.fill.b-med{background:var(--med)} .badge.fill.b-low{background:var(--low)}
.badge.dashed{border-style:dashed}
/* Strength, not severity. One hue, three weights: high reads as solid, low as
   faint, and neither reads as an alarm. The label is part of the badge because
   a bare "medium" cannot say which scale it is on. */
.badge.str{border-color:var(--str-line);color:var(--str-ink);background:var(--str-bg);
  padding:1px 8px 1px 6px}
.badge.str i{font-style:normal;color:var(--faint);font-size:10px;letter-spacing:.05em;
  text-transform:uppercase;margin-right:5px}
.badge.str.sc-value{--str-strong:var(--val-strong);--str-mid:var(--val-mid);
  --str-strong-bg:var(--val-bg)}
.badge.str.sc-conf{--str-strong:var(--conf-strong);--str-mid:var(--conf-mid);
  --str-strong-bg:var(--conf-bg)}
.s-high{--str-line:var(--str-strong);--str-ink:var(--str-strong);--str-bg:var(--str-strong-bg)}
.s-med{--str-line:var(--str-mid);--str-ink:var(--str-mid);--str-bg:transparent}
.s-low{--str-line:var(--line);--str-ink:var(--faint);--str-bg:transparent}
.clspill{display:inline-block;border:1px solid var(--line);border-radius:5px;
  background:var(--panel-2);color:var(--muted);font-size:11px;padding:1px 7px;white-space:nowrap}
.unv{font-size:10px;text-transform:uppercase;letter-spacing:.06em;font-weight:600;color:var(--crit)}

/* ---- table ---- */
.tablewrap{border:1px solid var(--line);border-radius:10px;background:var(--panel);overflow:hidden}
.tablescroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;min-width:940px}
th,td{text-align:left;vertical-align:top;border-bottom:1px solid var(--line-soft)}
th{position:sticky;top:0;z-index:2;background:var(--panel-2);cursor:pointer;
  font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;font-weight:600;
  color:var(--muted);white-space:nowrap;padding:8px 11px}
th .dir{color:var(--accent)}
th:hover,th:focus-visible{color:var(--ink);outline:none}
td{padding:10px 11px;font-size:13px}
.dense td{padding:5px 10px}
tbody tr{cursor:pointer}
tbody tr:hover{background:var(--hover)}
tbody tr.sel{background:var(--accent-soft)}
tr:last-child td{border-bottom:0}
td .path{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}
td .id{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--muted);white-space:nowrap}
td .note{font-size:12.5px;color:var(--muted);max-width:38ch;display:inline-block}
.pick{width:17px;height:17px;border-radius:5px;border:1px solid var(--field-line);
  background:var(--panel);display:inline-flex;align-items:center;justify-content:center;
  font-size:12px;color:transparent;padding:0}
.pick[aria-pressed=true]{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
.pick.all{border-style:dashed}
.pick.all[aria-pressed=true]{border-style:solid}
.pick:hover{border-color:var(--accent)}
th .pick.all{vertical-align:middle}
.empty{padding:44px 20px;text-align:center;color:var(--muted)}
.empty button{display:block;margin:12px auto 0}

/* ---- cards (phone) ---- */
.cards{display:none;flex-direction:column;gap:10px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:12px 14px;cursor:pointer}
.card .top{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-bottom:7px}
.card .top b{margin-right:auto;font-size:14px}
.card .path{display:block;font-family:ui-monospace,Menlo,monospace;font-size:12px;
  word-break:break-all;background:var(--panel-2);border:1px solid var(--line-soft);
  border-radius:6px;padding:7px 9px;margin:0 0 7px}
.card .meta{font-size:11.5px;color:var(--muted)}

/* ---- tools view ---- */
.toolgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px}
.tool{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:16px;
  display:flex;flex-direction:column;gap:10px;cursor:pointer;text-align:left}
.tool:hover{border-color:var(--accent)}
.tool .trow{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}
.tool .tname{font-size:14.5px;font-weight:600}
.tool .tsub{font-size:12px;color:var(--muted)}
.tool p{margin:0;font-size:12.5px;color:var(--muted)}
.tool .capchips{display:flex;flex-wrap:wrap;gap:5px}
.tool .capchips i{font-style:normal;font-size:11px;background:var(--panel-2);
  border:1px solid var(--line-soft);border-radius:5px;padding:1px 7px;color:var(--muted)}
.tool .tfoot{display:flex;flex-wrap:wrap;gap:5px 14px;border-top:1px solid var(--line-soft);
  padding-top:9px;font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--muted)}

/* ---- drawer ---- */
.drawer{position:fixed;top:0;right:0;bottom:0;width:420px;max-width:92vw;z-index:40;
  background:var(--panel);border-left:1px solid var(--line);
  box-shadow:-14px 0 34px var(--shadow);overflow:auto;display:flex;flex-direction:column}
.drawer[hidden]{display:none}
.dhead{position:sticky;top:0;background:var(--panel);border-bottom:1px solid var(--line);
  padding:13px 18px;display:flex;justify-content:space-between;gap:10px;align-items:center;z-index:2}
.dhead b{font-size:14px}
.dhead .x{width:28px;height:28px;border-radius:7px;border:1px solid var(--line);
  background:none;color:var(--faint);flex:none}
.dhead .x:hover{color:var(--ink);border-color:var(--accent)}
.dbody{padding:16px 18px;display:flex;flex-direction:column;gap:16px}
.dsec h4{margin:0 0 7px;font-size:11px;letter-spacing:.06em;text-transform:uppercase;
  color:var(--faint);font-weight:600}
.locator{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all;
  background:var(--panel-2);border-radius:8px;padding:10px}
.badgerow{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.evrow{display:flex;flex-wrap:wrap;gap:5px;margin:0 0 8px}
/* Volatility gets its own palette again, for the reason confidence and forensic
   value did: it is a third scale, and reusing either ramp would make "live" read
   as a severity. Cool-to-warm by urgency of collection instead. */
.badge.vol{border-radius:5px;padding:1px 7px;font-size:11px;border:1px solid}
.badge.vol i{font-style:normal;opacity:.6;margin-right:5px;font-size:10px;text-transform:uppercase;letter-spacing:.03em}
.v-live{background:#fdf0ec;border-color:#e9b9a8;color:#8a3c1c}
.v-rotating{background:#fbf5e6;border-color:#e0cd9a;color:#7a5c15}
.v-stable{background:#eef3f7;border-color:#b9cbd9;color:#2f5570}
:root[data-theme=dark] .v-live,html:not([data-theme=light]) .v-live{background:#3a1d12;border-color:#7a4128;color:#f0b193}
:root[data-theme=dark] .v-rotating,html:not([data-theme=light]) .v-rotating{background:#332a12;border-color:#6d5a24;color:#e6cd8c}
:root[data-theme=dark] .v-stable,html:not([data-theme=light]) .v-stable{background:#18262f;border-color:#33556b;color:#a8c9dd}
.volwhy{margin:8px 0 0;font-size:12px;color:var(--muted)}
.dsrc{margin:10px 0 0;font-size:12px;color:var(--muted)}
.dsrc b{display:block;margin-bottom:5px;color:var(--ink);font-size:11px;
  text-transform:uppercase;letter-spacing:.04em}
.srcjump{display:block;width:100%;text-align:left;background:var(--panel-2);
  border:1px solid var(--line);border-radius:7px;padding:6px 9px;margin-bottom:5px;
  color:var(--ink);font-size:12px;cursor:pointer}
.srcjump:hover{border-color:var(--accent);background:var(--accent-soft-2)}
/* --- data sources view --- */
.srcintro{margin:0 0 16px;font-size:13.5px;color:var(--muted);max-width:70ch}
.vollegend{display:grid;gap:7px;margin-top:12px}
.vollegend>div{display:grid;grid-template-columns:130px 1fr;gap:10px;align-items:start;font-size:12.5px}
.src{background:var(--panel);border:1px solid var(--line);border-radius:11px;
  padding:16px;margin-bottom:12px}
.srchead{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;
  flex-wrap:wrap;margin-bottom:12px}
.src h3{margin:0;font-size:15px}
.srcsub{margin-top:3px;font-size:12px;color:var(--muted)}
.srcgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}
.srcgrid h5{margin:0 0 5px;font-size:10.5px;text-transform:uppercase;
  letter-spacing:.05em;color:var(--faint)}
.srcgrid p{margin:0;font-size:12.5px;line-height:1.55}
.srcloss p{color:var(--ink)}
.srcloss h5{color:var(--med)}
.srcfoot{display:flex;flex-wrap:wrap;gap:7px;align-items:center;margin-top:14px;
  padding-top:12px;border-top:1px solid var(--line-soft)}
.srcstat{background:var(--panel-2);border:1px solid var(--line);border-radius:20px;
  padding:3px 11px;font-size:11.5px;color:var(--muted);cursor:pointer}
.srcstat b{color:var(--ink);font-family:ui-monospace,Menlo,monospace}
.srcstat:hover{border-color:var(--accent)}
.srcstat.flat{cursor:default}
.srcstat.flat:hover{border-color:var(--line)}
.srcref{font-size:11.5px;color:var(--muted);text-decoration:none;
  border-bottom:1px dotted var(--line)}
.srcref:hover{color:var(--accent)}
@media(max-width:640px){.vollegend>div{grid-template-columns:1fr;gap:3px}}
.requires{margin:8px 0 0;padding:8px 10px;font-size:12px;color:var(--muted);
  background:var(--alert-bg);border:1px solid var(--alert-line);
  border-left:3px solid var(--med);border-radius:8px}
.requires b{color:var(--med)}
.ev{font-size:11px;background:var(--accent-soft);border:1px solid var(--accent-border);
  color:var(--accent);border-radius:5px;padding:1px 7px}
.dsec p{margin:0;font-size:12.5px;color:var(--muted)}
.alert{background:var(--alert-bg);border:1px solid var(--alert-line);
  border-left:3px solid var(--crit);border-radius:8px;padding:10px;margin-top:8px;
  font-size:12.5px;color:var(--muted)}
.alert b{color:var(--crit)}
.tech{display:flex;flex-wrap:wrap;gap:5px}
.tech i{font-style:normal;font-family:ui-monospace,Menlo,monospace;font-size:11px;
  background:var(--panel-2);border:1px solid var(--line-soft);border-radius:5px;
  padding:1px 7px;color:var(--muted)}
.linkrow{display:flex;gap:8px}
.linkrow input{flex:1;min-width:0;font-family:ui-monospace,Menlo,monospace;font-size:11.5px;
  color:var(--muted);background:var(--panel-2);border:1px solid var(--line-soft);
  border-radius:7px;padding:7px 9px}
.btn{border-radius:8px;padding:8px 13px;font-size:12.5px;border:1px solid var(--line);
  background:var(--panel);color:var(--ink)}
.btn:hover{border-color:var(--accent)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
.btn.primary:hover{background:var(--accent-hover)}
.btn.outline-accent{background:none;border-color:var(--accent);color:var(--accent)}
.dfoot{display:flex;gap:8px;padding:0 18px 18px}

/* ---- plan ---- */
.planhead{display:flex;flex-wrap:wrap;gap:10px;justify-content:space-between;align-items:flex-end;
  margin:0 0 14px}
.planhead h2{margin:0 0 4px;font-size:16px}
.planhead p{margin:0;font-size:12.5px;color:var(--muted)}
.planhead .acts{display:flex;gap:8px}
.plan-empty{border:1px dashed var(--field-line);border-radius:11px;padding:48px 20px;
  text-align:center;color:var(--muted)}
.pgroup{border:1px solid var(--line);border-radius:11px;background:var(--panel);
  overflow:hidden;margin:0 0 14px}
.pgroup .ghead{display:flex;gap:10px;align-items:center;background:var(--panel-2);
  border-bottom:1px solid var(--line-soft);padding:9px 14px}
.pgroup .ghead b{font-size:13.5px}
.pgroup .ghead .n{margin-left:auto;font-family:ui-monospace,Menlo,monospace;
  font-size:11px;color:var(--muted)}
.prow{display:flex;gap:10px;align-items:baseline;padding:6px 14px;
  border-bottom:1px solid var(--line-soft)}
.prow .rm{border:0;background:none;color:var(--faint);padding:0 2px}
.prow .rm:hover{color:var(--crit)}
.prow .path{flex:1;font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}
.pgroup .gfoot{padding:9px 14px;font-size:12px;color:var(--muted);background:var(--panel-2);
  border-top:1px solid var(--line-soft)}

/* ---- toast ---- */
.toast{position:fixed;left:50%;transform:translateX(-50%);bottom:20px;z-index:50;
  background:var(--toast-bg);color:var(--toast-ink);border-radius:11px;
  padding:10px 12px 10px 16px;display:flex;gap:12px;align-items:center;
  box-shadow:0 10px 30px var(--shadow);font-size:13px}
.toast[hidden]{display:none}
.toast button{background:none;border:1px solid var(--toast-muted);border-radius:7px;
  color:var(--toast-ink);padding:5px 10px;font-size:12px}
.toast a{color:var(--toast-muted);cursor:pointer;font-size:12px}

/* ---- detections ---- */
.rulegrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px}
.rule{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:15px;
  display:flex;flex-direction:column;gap:9px;cursor:pointer;text-align:left}
.rule:hover{border-color:var(--accent)}
.rule .rtop{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}
.rule .rname{font-size:14px;font-weight:600}
.rule .rfile{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:var(--muted);
  word-break:break-all}
.rule p{margin:0;font-size:12.5px;color:var(--muted)}
.rule .rfoot{display:flex;flex-wrap:wrap;gap:5px;border-top:1px solid var(--line-soft);
  padding-top:9px}
.fmt{font-size:10.5px;letter-spacing:.05em;text-transform:uppercase;font-weight:600;
  border-radius:5px;padding:1px 7px;background:var(--panel-2);border:1px solid var(--line);
  color:var(--muted)}
.tchip{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;background:var(--accent-soft);
  border:1px solid var(--accent-border);color:var(--accent);border-radius:5px;padding:1px 6px;
  cursor:pointer}
.tchip:hover{background:var(--accent-soft-2)}
pre.yaml{margin:0;background:var(--panel-2);border:1px solid var(--line-soft);border-radius:8px;
  padding:10px;overflow:auto;max-height:340px;font-family:ui-monospace,Menlo,monospace;
  font-size:11.5px;line-height:1.45;white-space:pre;color:var(--ink)}
.fplist{margin:0;padding-left:17px;font-size:12.5px;color:var(--muted)}

/* ---- mappings ---- */
.idxwrap{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:22px}
.idx h2{margin:0 0 3px;font-size:15px}
.idx .isub{margin:0 0 11px;font-size:12.5px;color:var(--muted)}
.irow{display:grid;grid-template-columns:96px minmax(0,1fr) 36px;gap:10px;align-items:center;
  padding:7px 9px;border-radius:8px;cursor:pointer;border:1px solid transparent}
.irow:hover{background:var(--accent-soft);border-color:var(--accent-border)}
.irow .iid{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:var(--accent)}
.irow .ittl{font-size:12.5px}
.irow .icount{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:var(--muted);
  text-align:right}
.bar{grid-column:1/-1;height:4px;border-radius:3px;background:var(--line-soft);overflow:hidden}
.bar i{display:block;height:100%;background:var(--accent);border-radius:3px}

/* ---- case studies ---- */
.csgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:14px}
.cs{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:16px;
  display:flex;flex-direction:column;gap:10px}
.cs .cshead{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}
.cs .csname{font-size:14.5px;font-weight:600}
.cs .csmeta{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--muted)}
.cs p{margin:0;font-size:12.5px;color:var(--muted)}
.cs h5{margin:0;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
.iocs{display:flex;flex-wrap:wrap;gap:5px}
.ioc{font-family:ui-monospace,Menlo,monospace;font-size:11px;background:var(--panel-2);
  border:1px solid var(--line-soft);border-radius:5px;padding:2px 7px;color:var(--ink);
  word-break:break-all}
.cs ol{margin:0;padding-left:17px;font-size:12.5px;color:var(--muted)}

/* ---- case studies, full view ---- */
.csfull{background:var(--panel);border:1px solid var(--line);border-radius:11px;
  padding:20px 22px;margin:0 0 16px}
.csfull .cshead{display:flex;justify-content:space-between;align-items:flex-start;
  gap:14px;margin:0 0 10px;flex-wrap:wrap}
.csfull .csname{font-size:16px;font-weight:600}
.csfull .csjump{flex:none;white-space:nowrap}
.cssum{margin:0 0 16px;font-size:13.5px;color:var(--ink);max-width:88ch}
/* Two columns because indicators and response answer different questions - what
   to look for, and what to do - and a responder reads one or the other. */
.csbody{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(0,1fr);gap:24px}
.csbody h5{margin:0 0 9px;display:flex;align-items:center;gap:7px}
.csbody h5 .n{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;
  background:var(--line-soft);border-radius:20px;padding:1px 7px;color:var(--muted)}
.iocgrp{margin:0 0 11px}
.iockind{font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;
  color:var(--faint);margin:0 0 4px}
.csfull .iocs{flex-direction:column;align-items:flex-start;gap:4px}
.csfull .ioc{display:block;width:100%;word-break:break-all;padding:5px 9px;line-height:1.35}
.csfull .ioc em{display:block;font-style:normal;font-family:system-ui,sans-serif;
  font-size:11px;color:var(--muted);margin-top:2px}
.csact{margin:0;padding-left:18px;font-size:12.5px;color:var(--ink)}
.csact li{margin:0 0 6px}
.muted{margin:0;font-size:12.5px;color:var(--muted)}
@media(max-width:820px){.csbody{grid-template-columns:minmax(0,1fr);gap:16px}}
/* Detections sit above the ATLAS/sources footer because they are the actionable
   half - "here is the incident" is context, "here is the rule that catches it"
   is the next move. */
.csdet{margin:14px 0 0;padding:14px 0 0;border-top:1px solid var(--line-soft)}
.csdet h5{margin:0 0 8px;font-size:11px;letter-spacing:.06em;text-transform:uppercase;
  color:var(--faint);display:flex;align-items:center;gap:7px}
.csdet h5 .n{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;
  background:var(--line-soft);border-radius:20px;padding:1px 7px;color:var(--muted)}
.detrow{display:flex;flex-wrap:wrap;gap:6px}
.detchip{font-family:ui-monospace,Menlo,monospace;font-size:11px;background:var(--accent-soft);
  border:1px solid var(--accent-border);color:var(--accent);border-radius:5px;
  padding:3px 8px;cursor:pointer}
.detchip:hover{background:var(--accent-soft-2);border-color:var(--accent)}
.tbadges{display:flex;align-items:center;gap:6px;flex:none}
.caselink{display:block;width:100%;text-align:left;background:var(--panel-2);
  border:1px solid var(--line);border-radius:7px;padding:7px 9px;margin:0 0 6px;
  font-size:12.5px;color:var(--accent);cursor:pointer}
.caselink:hover{border-color:var(--accent);background:var(--accent-soft)}
.drefs{margin:0;padding-left:17px;font-size:12.5px}
.drefs li{margin:0 0 5px;color:var(--muted)}
.dsec h4 .n{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;
  background:var(--line-soft);border-radius:20px;padding:1px 7px;color:var(--muted)}
.tverify{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--faint);
  margin:0 0 6px}
.talias{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--faint);
  margin:0 0 6px;word-break:break-word}
.statuspill{font-size:10.5px;letter-spacing:.04em;text-transform:uppercase;font-weight:600;
  border:1px solid var(--crit);color:var(--crit);border-radius:20px;padding:1px 8px;
  white-space:nowrap}
.casebadge{font-size:10.5px;letter-spacing:.04em;text-transform:uppercase;font-weight:600;
  background:var(--accent);color:var(--on-accent);border-radius:20px;padding:2px 8px;
  white-space:nowrap}
.csconf{margin:8px 0 0;font-size:12px;color:var(--faint);
  font-family:ui-monospace,Menlo,monospace}
.csjumps{display:flex;flex-wrap:wrap;gap:6px;justify-content:flex-end}
/* Provenance sits directly under the summary, so a reader meets the evidence
   standard before the indicators rather than after them. */
.csprov{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;margin:0 0 14px}
.csbasis{font-size:12px;color:var(--muted);flex:1 1 320px;min-width:0}
.csdispute{background:var(--alert-bg);border:1px solid var(--alert-line);
  border-left:3px solid var(--crit);border-radius:8px;padding:10px;font-size:12.5px;
  color:var(--muted);margin:0 0 14px}
.csdispute b{color:var(--crit)}
.csfoot{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,2fr);gap:24px;
  margin:14px 0 0;padding:14px 0 0;border-top:1px solid var(--line-soft)}
.csfoot h5{margin:0 0 8px;font-size:11px;letter-spacing:.06em;text-transform:uppercase;
  color:var(--faint);display:flex;align-items:center;gap:7px}
.csfoot h5 .n{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;
  background:var(--line-soft);border-radius:20px;padding:1px 7px;color:var(--muted)}
.csatlas{display:flex;flex-direction:column;align-items:flex-start}
.tech{font-family:ui-monospace,Menlo,monospace;font-size:11px;background:var(--panel-2);
  border:1px solid var(--line-soft);border-radius:5px;padding:2px 7px;margin:0 4px 4px 0;
  text-decoration:none}
.csrefs ul{margin:0;padding-left:17px;font-size:12.5px}
.csrefs li{margin:0 0 5px;color:var(--muted)}
@media(max-width:820px){.csfoot{grid-template-columns:minmax(0,1fr);gap:16px}}
.lesson{background:var(--alert-bg);border:1px solid var(--alert-line);
  border-left:3px solid var(--accent);border-radius:8px;padding:10px;font-size:12.5px;
  color:var(--muted)}
.lesson b{color:var(--accent)}
.sechead{margin:26px 0 12px;font-size:15px}

/* ---- guide ---- */
.guidewrap{display:grid;grid-template-columns:250px minmax(0,1fr);gap:26px;align-items:start}
.gtoc{position:sticky;top:150px;max-height:calc(100vh - 180px);overflow:auto}
.gtoc h4{margin:0 0 8px;font-size:11px;letter-spacing:.06em;text-transform:uppercase;
  color:var(--muted)}
.gtoc a{display:block;padding:3px 7px;border-radius:6px;font-size:12.5px;text-decoration:none;
  color:var(--ink)}
.gtoc a:hover{background:var(--accent-soft);color:var(--accent)}
.gtoc a.sub{padding-left:16px;font-size:12px;color:var(--muted)}
.gbody{background:var(--panel);border:1px solid var(--line);border-radius:11px;
  padding:24px 28px;max-width:none;overflow-wrap:break-word}
/* Levels are shifted down one by site_data._demote_headings so the page keeps a
   single h1; these sizes track the guide's own hierarchy, not the tag numbers. */
.gbody h2{font-size:20px;margin:26px 0 10px;padding-top:10px;border-top:1px solid var(--line-soft)}
.gbody h2:first-child{margin-top:0;border-top:0;padding-top:0}
.gbody h3{font-size:16.5px;margin:22px 0 8px}
.gbody h4{font-size:14px;margin:18px 0 6px}
.gbody p,.gbody li{font-size:13.5px;color:var(--ink)}
.gbody p{margin:0 0 10px}
.gbody ul,.gbody ol{margin:0 0 10px;padding-left:20px}
.gbody code{background:var(--panel-2);border:1px solid var(--line-soft);border-radius:4px;
  padding:1px 5px;font-size:12px}
/* Wide code and tables scroll inside their own box; the page never does. */
.gbody pre{background:var(--panel-2);border:1px solid var(--line-soft);border-radius:8px;
  padding:11px;overflow-x:auto;max-width:100%}
.gbody pre code{background:none;border:0;padding:0;font-size:11.5px;line-height:1.5;
  display:block;width:max-content;min-width:100%}
.gbody table{border-collapse:collapse;margin:0 0 12px;font-size:12.5px;
  display:block;width:max-content;min-width:100%;max-width:100%;overflow-x:auto}
.gbody th,.gbody td{border:1px solid var(--line-soft);padding:6px 9px;text-align:left}
.gbody th{background:var(--panel-2);color:var(--muted)}
.gbody blockquote{margin:0 0 10px;padding-left:12px;border-left:3px solid var(--accent-border);
  color:var(--muted)}
.gbody a{overflow-wrap:anywhere}
.gtop{display:flex;flex-wrap:wrap;gap:10px;justify-content:space-between;align-items:baseline;
  margin:0 0 14px}
.gtop h2{margin:0;font-size:16px}
.gtop p{margin:3px 0 0;font-size:12.5px;color:var(--muted)}

/* ---- guide diagrams ---- */
/* The diagrams carry their own light fills and dark text from the guide's
   classDefs, so they keep a light card in both themes rather than being
   recoloured into illegibility. */
figure.mmd{margin:0 0 14px;background:#fbfbfa;border:1px solid var(--line);
  border-radius:9px;padding:14px;overflow-x:auto;
  /* Mermaid labels resolve to currentColor, which would inherit the page's
     light ink in dark mode and vanish against these light node fills. */
  color:#1f2328}
/* Mermaid puts node text in <p> inside a foreignObject, which .gbody p would
   otherwise paint with the page ink - light, on a light node fill. */
figure.mmd .nodeLabel,figure.mmd .edgeLabel,figure.mmd .label,
figure.mmd text,figure.mmd tspan,figure.mmd p,figure.mmd span,
figure.mmd div{fill:#1f2328;color:#1f2328}
figure.mmd p{margin:0;font-size:inherit}
figure.mmd .edgeLabel rect,figure.mmd .labelBkg{fill:#fbfbfa}
figure.mmd svg{max-width:100%;height:auto;display:block;margin:0 auto}

/* ---- footer ---- */
footer{max-width:1440px;margin:0 auto;padding:0 28px 40px;display:grid;
  grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px;
  color:var(--muted);font-size:12.5px}
footer p{margin:0}

@media(max-width:900px){
  .hdr{position:static}
  .shell{grid-template-columns:minmax(0,1fr);padding:16px 14px 90px;gap:14px}
  .hdr-in{padding:12px 14px 0}
  .railscroll{display:none}
  details.railfold{display:block;border:1px solid var(--line);border-radius:9px;
    background:var(--panel);padding:9px 12px}
  details.railfold summary{cursor:pointer;font-size:12.5px;color:var(--muted)}
  details.railfold .foldbody{display:flex;gap:14px;overflow-x:auto;padding-top:10px}
  details.railfold .fgroup{min-width:150px;flex:none}
  footer{padding:0 14px 40px}
}
@media(max-width:900px){
  .guidewrap{grid-template-columns:minmax(0,1fr)}
  .gtoc{position:static;max-height:none;border:1px solid var(--line);border-radius:9px;
    background:var(--panel);padding:12px}
  .gbody{padding:16px}
  /* Five tabs plus the guide link exceed a phone's width: scroll the strip,
     not the page. */
  .tabs{overflow-x:auto;scrollbar-width:none}
  .tabs::-webkit-scrollbar{display:none}
  .tabs button,.tabs .guidelink{flex:none;white-space:nowrap}
  .tabs .guidelink{margin-left:6px}
}
@media(max-width:620px){
  .tablewrap{display:none}
  .cards{display:flex}
  .drawer{width:100vw;max-width:100vw}
  .idxwrap{grid-template-columns:minmax(0,1fr)}
}
"""

JS = r"""
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const RANK={critical:0,p1:0,high:1,p2:1,medium:2,p3:2,low:3};
// Two scales, deliberately not sharing a palette.
//
// "high" means opposite things depending on the field, and the page used one
// red-to-green severity ramp for all of them - so a well-sourced artifact and a
// dangerous tool both rendered in the same warning orange, and a reader had no
// way to tell which question a bare badge was answering. Severity (risk, triage
// priority) keeps the alarm ramp. Strength (confidence, forensic value) gets a
// neutral ramp where high reads as solid rather than as a warning, because a
// high-confidence artifact is good news.
const TONE={critical:'b-crit',p1:'b-crit',high:'b-high',p2:'b-high',medium:'b-med',p3:'b-med',low:'b-low'};
const STRENGTH={high:'s-high',medium:'s-med',low:'s-low'};
const TOOLMAP=Object.fromEntries(TOOLS.map(t=>[t.entry_id,t]));
const ROWMAP=Object.fromEntries(ROWS.map(r=>[r.anchor,r]));
const SRCMAP=Object.fromEntries(SOURCES.map(s=>[s.id,s]));
const VOL_ORDER=Object.fromEntries(VOL_TIERS.map((v,i)=>[v,i]));
// class -> the sources that make it visible, so a row can name its own
// dependencies without the catalog carrying a second copy of the mapping.
const SOURCES_FOR=(()=>{const m={};
  for(const s of SOURCES)for(const c of s.covers.classes||[])(m[c]=m[c]||[]).push(s.id);
  return m})();
const GROUPS={cls:'Artifact class',vol:'Volatility',os:'Operating system',fv:'Forensic value',conf:'Confidence',tool:'Tool'};
const FIELD={cls:r=>[r.cls],vol:r=>[r.vol],os:r=>r.os,fv:r=>[r.forensic_value],conf:r=>[r.confidence],tool:r=>[r.tool]};
const OPTIONS={
  cls:[...new Set(ROWS.map(r=>r.cls))].sort(),
  // Collection order, not alphabetical: this facet is the one place the page
  // states which rows stop existing first.
  vol:VOL_TIERS,
  os:['windows','macos','linux'],
  fv:['high','medium','low'],
  conf:['high','medium','low'],
  tool:TOOLS.map(t=>t.tool).sort((a,b)=>a.localeCompare(b)),
};

// Keyed by repo-relative path: two rule directories could hold the same
// filename, and a permalink that cannot tell them apart is a silent wrong
// answer. RULEFILE keeps bare-filename links from before this change working.
const RULEMAP=Object.fromEntries(RULES.map(r=>[r.path,r]));
const RULEFILE=Object.fromEntries(RULES.map(r=>[r.file,r]));
const RGROUPS={fmt:'Format',rcat:'Category',ratlas:'ATLAS technique',rowasp:'OWASP LLM'};
const RFIELD={fmt:r=>[r.format],rcat:r=>[r.category],ratlas:r=>r.atlas,rowasp:r=>r.owasp};
const ROPTIONS={
  fmt:[...new Set(RULES.map(r=>r.format))].sort(),
  rcat:[...new Set(RULES.map(r=>r.category))].sort(),
  ratlas:[...new Set(RULES.flatMap(r=>r.atlas))].sort(),
  rowasp:[...new Set(RULES.flatMap(r=>r.owasp))].sort(),
};

let view='catalog', query='', unvOnly=false, dense=false,
    sortKey='entry_id', sortDir=1, sel=null, selRule=null, lastFocus=null;
const filters={cls:[],vol:[],os:[],fv:[],conf:[],tool:[]};
const rfilters={fmt:[],rcat:[],ratlas:[],rowasp:[]};
// 'aiart-' was the AIRTIFACTS working name, dropped when the catalog folded
// into this repo. Read the old key once so anyone who saved picks under it
// keeps them, then write only the current key from here on.
const PICKS_KEY='aidfir-picks', PICKS_KEY_OLD='aiart-picks';
const picks=new Set((()=>{
  try{
    const raw=localStorage.getItem(PICKS_KEY)??localStorage.getItem(PICKS_KEY_OLD);
    const v=JSON.parse(raw||'[]');
    // Anchors are stable across builds, row indexes are not - but an artifact
    // can still be removed from the catalog, so drop anchors that no longer resolve.
    return Array.isArray(v)?v.filter(a=>ROWMAP[a]):[];
  }catch(e){return[]}
})());
function savePicks(){try{localStorage.setItem(PICKS_KEY,JSON.stringify([...picks]))}catch(e){}}

function badge(v,filled,prefix){
  if(!v)return'';
  return `<span class="badge ${filled?'fill ':''}${TONE[v]||''}">${prefix?esc(prefix)+' ':''}${esc(v)}</span>`;
}
// Strength badges always carry their label. An unlabelled "medium" next to
// another unlabelled "medium" is the ambiguity this is meant to remove.
function sBadge(v,label,bare,scale){
  if(!v)return'';
  return `<span class="badge str ${scale||'sc-conf'} ${STRENGTH[v]||''}"
    title="${esc(label)}: ${esc(v)}"
    >${bare?'':`<i>${esc(label)}</i>`}${esc(v)}</span>`;
}
// bare inside the table only: the column header already names the scale there,
// and repeating it in every cell is noise. Everywhere else the badge travels
// without a header, so it carries its own label.
const fvBadge=(v,bare)=>sBadge(v,'value',bare,'sc-value');
const confBadge=(v,bare)=>sBadge(v,'sourcing',bare,'sc-conf');
const riskBadge=(v,p)=>badge(v,v==='critical',p);
const triageBadge=v=>badge(v,true,'triage');

function rowMatches(r,skip){
  if(unvOnly&&!r.unverified)return false;
  for(const g of Object.keys(filters)){
    if(g===skip)continue;
    const want=filters[g];
    if(!want.length)continue;
    const have=FIELD[g](r).filter(Boolean);
    if(!have.length)return false;
    if(!have.some(v=>want.includes(v)))return false;
  }
  if(!query)return true;
  // Aliases come from the tool, so searching "oobabooga" or "OpenDevin" finds
  // the rows for the entry that is now filed under a different name.
  const t=TOOLMAP[r.entry_id];
  const hay=(r.artifact+' '+r.tool+' '+r.description+' '+r.cls+' '+r.entry_id+' '+
    r.evidence.join(' ')+' '+(t&&t.aliases?t.aliases.join(' '):'')).toLowerCase();
  return hay.includes(query);
}
function filteredRows(){
  const out=ROWS.filter(r=>rowMatches(r,null));
  out.sort((a,b)=>{
    const x=a[sortKey],y=b[sortKey];
    if(RANK[x]!==undefined&&RANK[y]!==undefined&&RANK[x]!==RANK[y])
      return (RANK[x]-RANK[y])*sortDir;
    return String(x??'').localeCompare(String(y??''),undefined,{numeric:true})*sortDir;
  });
  return out;
}

/* ---------- rail ---------- */
// Collapsed facet groups, remembered. The Tool group alone is 45 options, so a
// reader who filters by class every time was scrolling past a list they never
// use. Default open, because a collapsed filter a reader has not opened is a
// filter they do not know exists.
const FOLD_KEY='aidfir-folds';
const folded=new Set((()=>{try{return JSON.parse(localStorage.getItem(FOLD_KEY))||[]}
  catch(e){return[]}})());
function saveFolds(){try{localStorage.setItem(FOLD_KEY,JSON.stringify([...folded]))}catch(e){}}
function fgroup(key,title,body,picked){
  return `<details class="fgroup" data-f="${esc(key)}"${folded.has(key)?'':' open'}>
    <summary><h3>${esc(title)}</h3>${picked?`<span class="fon">${picked}</span>`:''}</summary>
    ${body}</details>`;
}
function railHTML(){
  return Object.keys(GROUPS).map(g=>{
    const counts={};
    for(const r of ROWS){
      if(!rowMatches(r,g))continue;
      for(const v of FIELD[g](r).filter(Boolean))counts[v]=(counts[v]||0)+1;
    }
    const body=OPTIONS[g].map(v=>{
      const on=filters[g].includes(v);
      return `<button class="fbtn" data-g="${g}" data-v="${esc(v)}" aria-pressed="${on}">
        <span>${esc(v)}</span><span class="c">${counts[v]||0}</span></button>`;
    }).join('');
    return fgroup(g,GROUPS[g],body,filters[g].length);
  }).join('');
}
function renderRail(){
  const h=view==='rules'?ruleRailHTML():railHTML();
  $('#rail').innerHTML=h;
  $('#railfold .foldbody').innerHTML=h;
  // Both rails render the same markup, so record the state rather than the node.
  $$('details.fgroup').forEach(d=>d.addEventListener('toggle',()=>{
    d.open?folded.delete(d.dataset.f):folded.add(d.dataset.f);
    saveFolds();
  }));
  $$('.fbtn').forEach(b=>b.onclick=()=>{
    const g=b.dataset.g||b.dataset.rg;
    const set=b.dataset.rg?rfilters:filters;
    const a=set[g],i=a.indexOf(b.dataset.v);
    i<0?a.push(b.dataset.v):a.splice(i,1);
    update();
  });
}

/* ---------- chips ---------- */
function chipsHTML(){
  const chips=[];
  for(const g of Object.keys(filters))
    for(const v of filters[g])
      chips.push(`<button class="chip" data-g="${g}" data-v="${esc(v)}">${esc(v)} <s>&#10005;</s></button>`);
  if(unvOnly)chips.push('<button class="chip" data-unv="1">unverified only <s>&#10005;</s></button>');
  return chips.join('');
}

/* ---------- table & cards ---------- */
const COLS=[['','pick'],['ID','entry_id'],['Tool','tool'],['Class','cls'],['Artifact','artifact'],
  ['OS','os'],['Value','forensic_value'],['Conf','confidence'],['Notes','description']];
function tableHTML(rows){
  if(!rows.length)return `<div class="empty">Nothing matches those filters.
    <button class="btn" onclick="resetAll()">Reset filters</button></div>`;
  // Select-all sits at the head of the column it acts on, which is where a
  // reader looks for it - not stranded at the right edge of the toolbar.
  const anchors=rows.map(r=>r.anchor);
  const allPicked=anchors.length&&anchors.every(a=>picks.has(a));
  return `<div class="tablescroll"><table><thead><tr>`+COLS.map(([l,k])=>{
    if(k==='pick')return `<th><button class="pick all" id="pickAllCol"
      aria-pressed="${allPicked}"
      aria-label="${allPicked?'Remove all shown from':'Add all shown to'} the collection plan"
      title="${allPicked?'Remove':'Pick'} all ${anchors.length} shown">&#10003;</button></th>`;
    const sorted=sortKey===k, dir=sorted?(sortDir>0?'ascending':'descending'):'none';
    return `<th data-k="${k}" tabindex="0" aria-sort="${dir}">${l}${sorted?`<span class="dir"> ${sortDir>0?'↑':'↓'}</span>`:''}</th>`;
  }).join('')+`</tr></thead><tbody>`+rows.map(r=>`
    <tr data-a="${esc(r.anchor)}" tabindex="0" class="${sel===r.anchor?'sel':''}">
      <td><button class="pick" data-a="${esc(r.anchor)}" aria-pressed="${picks.has(r.anchor)}"
        aria-label="Add to collection plan">&#10003;</button></td>
      <td><span class="id">${esc(r.entry_id)}</span></td>
      <td>${esc(r.tool)}</td>
      <td><span class="clspill">${esc(r.cls)}</span></td>
      <td><span class="path">${esc(r.artifact)}</span>${r.unverified?' <span class="unv">unverified</span>':''}</td>
      <td>${esc(r.os.join(', '))}</td>
      <td>${fvBadge(r.forensic_value,true)}</td>
      <td>${confBadge(r.confidence,true)}</td>
      <td><span class="note">${esc(r.description)}</span></td>
    </tr>`).join('')+'</tbody></table></div>';
}
function cardsHTML(rows){
  if(!rows.length)return `<div class="empty">Nothing matches those filters.
    <button class="btn" onclick="resetAll()">Reset filters</button></div>`;
  return rows.map(r=>`
    <div class="card" data-a="${esc(r.anchor)}" tabindex="0">
      <div class="top"><b>${esc(r.tool)}</b><span class="clspill">${esc(r.cls)}</span>
        ${fvBadge(r.forensic_value)}${confBadge(r.confidence)}</div>
      <span class="path">${esc(r.artifact)}</span>
      <div class="meta">${esc(r.entry_id)}${r.os.length?' &middot; '+esc(r.os.join(', ')):''}${r.unverified?' &middot; <span class="unv">unverified</span>':''}</div>
    </div>`).join('');
}

/* ---------- tools ---------- */
// Which tools have a documented incident. Six of forty-five, so it reads as a
// distinction rather than as decoration - which is the whole reason it is worth
// putting on the card instead of burying it in the drawer.
const CASES_BY_TOOL=(()=>{
  const by={};
  for(const c of CASES)for(const id of c.affects_ids||[])(by[id]=by[id]||[]).push(c);
  return by;
})();
function toolsHTML(){
  return '<div class="toolgrid">'+TOOLS.map(t=>{
  const cs=CASES_BY_TOOL[t.entry_id]||[];
  return `
    <button class="tool" data-t="${esc(t.tool)}" data-id="${esc(t.entry_id)}">
      <div class="trow"><div><div class="tname">${esc(t.tool)}</div>
        <div class="tsub">${esc(t.vendor)} &middot; ${esc(t.category)}</div></div>
        <div class="tbadges">${t.status&&t.status!=='active'?
          `<span class="statuspill">${esc(t.status)}</span>`:''}${cs.length?`<span class="casebadge"
          title="${esc(cs.map(c=>c.title).join(' · '))}">${cs.length} case${
          cs.length>1?'s':''}</span>`:''}${riskBadge(t.risk,'risk')}</div></div>
      ${t.aliases&&t.aliases.length?`<div class="talias">also ${
        esc(t.aliases.join(' · '))}</div>`:''}
      <p>${esc(t.description)}</p>
      ${t.caps.length?`<div class="capchips">${t.caps.map(c=>`<i>${esc(c)}</i>`).join('')}</div>`:''}
      <div class="tfoot"><span>${t.n} artifacts</span>${t.triage?`<span>triage ${esc(t.triage)}</span>`:''}
        <span>${esc(t.os.join(' · '))}</span></div>
    </button>`}).join('')+'</div>';
}

/* ---------- data sources ---------- */
// The catalog answers "what did this tool leave behind". This view answers the
// question that comes first: whether any of it will still be there, and what
// somebody had to switch on before the incident for it to exist at all.
//
// Every count below is derived at build time by scripts/data_sources.py, and
// its audit fails the build if a source claims coverage the corpus does not
// supply, or if a rule or a row maps to no source. Nothing here is typed twice.
function sourcesHTML(){
  const list=[...SOURCES].sort((a,b)=>
    (VOL_ORDER[a.volatility]-VOL_ORDER[b.volatility])||b.n_rows-a.n_rows);
  return `<div class="srcintro">
    <p>Ordered by how fast the evidence disappears, not by how useful it is. A
    source further down this page is not less important - it is just still going
    to be there tomorrow.</p>
    <div class="vollegend">${VOL_TIERS.map(v=>
      `<div><span class="badge vol v-${v}"><i>volatility</i>${v}</span>
       <span>${esc(VOL_MEANING[v])}</span></div>`).join('')}</div>
  </div>`+list.map(s=>`
    <section class="src" id="src-${esc(s.id)}">
      <div class="srchead">
        <div><h3>${esc(s.name)}</h3>
          <div class="srcsub">${esc(s.kind)} &middot; ${esc(s.default_state)}</div></div>
        <div class="badgerow"><span class="badge vol v-${esc(s.volatility)}"
          ><i>volatility</i>${esc(s.volatility)}</span>${confBadge(s.confidence)}</div>
      </div>
      <div class="srcgrid">
        <div><h5>Turn it on</h5><p>${esc(s.enable)}</p></div>
        <div><h5>Keep it</h5><p>${esc(s.retention)}</p></div>
        <div class="srcloss"><h5>Without it you cannot answer</h5><p>${esc(s.without_it)}</p></div>
      </div>
      <div class="srcfoot">
        ${s.n_eventlog_rows?`<button class="srcstat" data-cls="eventlog"
          ><b>${s.n_eventlog_rows}</b> event log rows</button>`:''}
        ${(s.covers.classes||[]).map(c=>`<button class="srcstat" data-cls="${esc(c)}"
          ><b>${CLS_COUNT[c]||0}</b> ${esc(c)} rows</button>`).join('')}
        ${s.n_rules?`<button class="srcstat" data-rules="${esc(s.id)}"
          ><b>${s.n_rules}</b> detection rule${s.n_rules>1?'s':''}</button>`:''}
        ${s.n_tools?`<span class="srcstat flat"><b>${s.n_tools}</b> tools affected</span>`:''}
        ${(s.references||[]).map(r=>`<a class="srcref" href="${esc(r.url)}"
          target="_blank" rel="noopener">${esc(r.title)} &#8599;</a>`).join('')}
      </div>
    </section>`).join('');
}

/* ---------- plan ---------- */
function planGroups(){
  const by={};
  for(const a of picks){const r=ROWMAP[a];if(!r)continue;(by[r.entry_id]=by[r.entry_id]||[]).push(r)}
  const groups=Object.entries(by).map(([id,rows])=>({t:TOOLMAP[id],rows}));
  groups.sort((a,b)=>(RANK[a.t.triage]??9)-(RANK[b.t.triage]??9)||a.t.tool.localeCompare(b.t.tool));
  // Volatility outranks forensic value inside a tool, which is the whole point
  // of recording it: a high-value config file is still there after the reboot
  // that took the process list with it. Value breaks the tie.
  for(const g of groups)g.rows.sort((a,b)=>
    (VOL_ORDER[a.vol]??9)-(VOL_ORDER[b.vol]??9)||
    (RANK[a.forensic_value]??9)-(RANK[b.forensic_value]??9));
  return groups;
}
function planHTML(){
  const groups=planGroups();
  const head=`<div class="planhead"><div><h2>Collection plan</h2>
    <p>Picked artifacts grouped by tool, tools ordered by triage priority and
    rows within each tool by how fast they disappear. Work top to bottom.</p></div>
    <div class="acts"><button class="btn" id="cpLinks">Copy permalinks</button>
    <button class="btn primary" id="cpList">Copy as triage list</button></div></div>`;
  if(!groups.length)return head+`<div class="plan-empty">Nothing picked yet.
    Tick artifacts in the catalog to build a collection plan.</div>`;
  return head+groups.map(g=>`
    <div class="pgroup"><div class="ghead">${triageBadge(g.t.triage)}<b>${esc(g.t.tool)}</b>
      <span class="n">${g.rows.length} path${g.rows.length>1?'s':''}</span></div>
    ${g.rows.map(r=>`<div class="prow">
      <button class="rm" data-a="${esc(r.anchor)}" aria-label="Remove">&#10005;</button>
      <span class="path">${esc(r.artifact)}</span>${fvBadge(r.forensic_value)}</div>`).join('')}
    ${g.t.guidance?`<div class="gfoot">${esc(g.t.guidance)}</div>`:''}</div>`).join('');
}
function planText(){
  return planGroups().map(g=>
    `# ${g.t.tool} (${g.t.triage||'-'})\n`+g.rows.map(r=>r.artifact).join('\n')
  ).join('\n\n');
}
function planLinks(){
  const base=location.origin==='null'?'':location.origin+location.pathname;
  return planGroups().flatMap(g=>g.rows.map(r=>base+'#'+r.anchor)).join('\n');
}

/* ---------- drawer ---------- */
function drawerHTML(r){
  const t=TOOLMAP[r.entry_id]||{};
  const base=location.origin==='null'?'':location.origin+location.pathname;
  return `<div class="dhead"><b>${esc(r.tool)} <span class="mono" style="color:var(--faint);font-size:11px">${esc(r.entry_id)}</span></b>
    <button class="x" id="dClose" aria-label="Close">&#10005;</button></div>
  <div class="dbody">
    <div class="dsec"><h4>Locator</h4><div class="locator">${esc(r.artifact)}</div>
      <div class="badgerow">${fvBadge(r.forensic_value)}
      ${confBadge(r.confidence)}
      ${r.unverified?'<span class="badge dashed b-crit">unverified</span>':''}</div></div>
    <div class="dsec"><h4>What it proves</h4>
      ${r.evidence.length?`<div class="evrow">${r.evidence.map(e=>`<span class="ev">${esc(e)}</span>`).join('')}</div>`:''}
      ${r.description?`<p>${esc(r.description)}</p>`:''}
      ${r.requires?`<div class="requires"><b>Requires.</b> ${esc(r.requires)}</div>`:''}</div>
    <div class="dsec"><h4>Tool context</h4>
      <div class="tverify">${t.verified?`last verified ${esc(t.verified)}`
        :'never verified against a host or a current release'}</div>
      ${t.status&&t.status!=='active'?`<div class="badgerow" style="margin:0 0 8px"
        ><span class="statuspill">${esc(t.status)}</span></div>`:''}
      ${t.aliases&&t.aliases.length?`<p class="talias">also ${esc(t.aliases.join(' · '))}</p>`:''}
      <p>${esc(t.description||'')}</p>
      ${t.abuse?`<div class="alert"><b>Abuse potential.</b> ${esc(t.abuse)}</div>`:''}</div>
    ${(CASES_BY_TOOL[r.entry_id]||[]).length?`<div class="dsec"><h4>Documented incidents</h4>
      ${CASES_BY_TOOL[r.entry_id].map(c=>
        `<button class="caselink" data-cs="${esc(c.id)}">${esc(c.title)}</button>`).join('')}</div>`:''}
    <div class="dsec"><h4>Collection order</h4>
      <div class="badgerow" style="margin:0 0 8px">${triageBadge(t.triage)}${riskBadge(t.risk,'risk')}
        <span class="badge vol v-${esc(r.vol)}" title="Volatility: ${esc(VOL_MEANING[r.vol]||'')}"
          ><i>volatility</i>${esc(r.vol)}</span></div>
      <p class="volwhy">${esc(VOL_MEANING[r.vol]||'')}</p>
      ${r.retention?`<div class="requires"><b>Retention.</b> ${esc(r.retention)} - this window is the tool's own, and it runs whether or not anyone is investigating.</div>`:''}
      ${(SOURCES_FOR[r.cls]||[]).length?`<div class="dsrc"><b>Depends on</b>
        ${(SOURCES_FOR[r.cls]).map(id=>`<button class="srcjump" data-src="${esc(id)}">${esc(SRCMAP[id].name)}</button>`).join('')}</div>`:''}
      ${t.guidance?`<p>${esc(t.guidance)}</p>`:''}</div>
    ${t.techniques&&t.techniques.length?`<div class="dsec"><h4>Mapped techniques</h4>
      <div class="tech">${t.techniques.map(x=>
        /^AML\./.test(x)?`<span class="tchip" data-tech="${esc(x)}">${esc(x)}</span>`
                        :`<i>${esc(x)}</i>`).join('')}</div></div>`:''}
    ${(t.refs||[]).length?`<div class="dsec"><h4>Sources <span class="n">${t.refs.length}</span></h4>
      <ul class="drefs">${t.refs.map(r=>`<li><a href="${esc(r.url)}" target="_blank"
        rel="noopener">${esc(r.title||r.url)}</a></li>`).join('')}</ul></div>`:''}
    <div class="dsec"><h4>Permalink</h4><div class="linkrow">
      <input readonly value="#${esc(r.anchor)}" aria-label="Permalink">
      <button class="btn" id="dCopyLink" data-v="${esc(base+'#'+r.anchor)}">copy link</button></div></div>
  </div>
  <div class="dfoot">
    <button class="btn ${picks.has(r.anchor)?'outline-accent':'primary'}" id="dPick">
      ${picks.has(r.anchor)?'Remove from collection plan':'Add to collection plan'}</button>
    <button class="btn" id="dCopyPath" data-v="${esc(r.artifact)}">copy path</button>
  </div>`;
}
function openDrawer(anchor,fromEl){
  sel=anchor; lastFocus=fromEl||document.activeElement;
  const r=ROWMAP[anchor]; if(!r)return;
  const d=$('#drawer');
  d.innerHTML=drawerHTML(r);
  d.hidden=false;
  d.setAttribute('aria-label',r.tool+' '+r.artifact);
  history.replaceState(null,'','#'+anchor);
  $('#dClose').onclick=closeDrawer;
  $('#dClose').focus();
  $('#dCopyLink').onclick=e=>copy(e.target.dataset.v,e.target);
  $('#dCopyPath').onclick=e=>copy(e.target.dataset.v,e.target);
  $('#dPick').onclick=()=>{togglePick(anchor);openDrawer(anchor,lastFocus)};
  $$('#drawer .caselink').forEach(b=>b.onclick=()=>{
    closeDrawer();view='cases';update();
    const el=document.getElementById('cs-'+b.dataset.cs);
    if(el)el.scrollIntoView({block:'start'});
  });
  $$('#drawer .srcjump').forEach(b=>b.onclick=()=>{
    closeDrawer();view='sources';update();
    const el=document.getElementById('src-'+b.dataset.src);
    if(el)el.scrollIntoView({block:'start'});
  });
  wireTechChips();
  renderMain();
}
function closeDrawer(){
  // Remember what to return focus to before re-rendering detaches it: the row
  // element itself does not survive renderMain(), so restore by anchor.
  const back=lastFocus&&lastFocus.dataset?(lastFocus.dataset.a||lastFocus.dataset.f):null;
  sel=null; selRule=null; $('#drawer').hidden=true;
  history.replaceState(null,'',location.pathname+location.search);
  renderMain();
  const el=back?document.querySelector(`[data-a="${CSS.escape(back)}"],[data-f="${CSS.escape(back)}"]`):null;
  if(el)el.focus();
  else if(lastFocus&&document.contains(lastFocus))lastFocus.focus();
}

/* ---------- clipboard ---------- */
function copy(text,btn){
  const done=()=>{if(!btn)return;const old=btn.textContent;btn.textContent='copied';
    setTimeout(()=>{btn.textContent=old},1600)};
  if(navigator.clipboard&&window.isSecureContext){
    navigator.clipboard.writeText(text).then(done,()=>fallbackCopy(text,done));
  }else fallbackCopy(text,done);
}
function fallbackCopy(text,done){
  const ta=document.createElement('textarea');
  ta.value=text;ta.style.position='fixed';ta.style.opacity='0';
  document.body.appendChild(ta);ta.select();
  try{document.execCommand('copy')}catch(e){}
  ta.remove();done();
}

/* ---------- picks ---------- */
function togglePick(a){picks.has(a)?picks.delete(a):picks.add(a);savePicks();update()}

/* ---------- detections ---------- */
function ruleMatches(r,skip){
  for(const g of Object.keys(rfilters)){
    if(g===skip)continue;
    const want=rfilters[g];
    if(!want.length)continue;
    const have=RFIELD[g](r).filter(Boolean);
    if(!have.length)return false;
    if(!have.some(v=>want.includes(v)))return false;
  }
  if(!query)return true;
  const hay=(r.title+' '+r.file+' '+r.description+' '+r.category+' '+r.format+' '+
    r.atlas.join(' ')+' '+r.owasp.join(' ')+' '+r.logsource).toLowerCase();
  return hay.includes(query);
}
// A data source covers a named set of rule files, which is not a facet and not
// a substring - the search box could only ever match one of the five. This is
// the same shape as `filters`, just keyed by filename, and it clears with them.
let ruleSet=null;
const filteredRules=()=>RULES.filter(r=>
  (!ruleSet||ruleSet.has(r.file))&&ruleMatches(r,null));

function ruleRailHTML(){
  return Object.keys(RGROUPS).map(g=>{
    const counts={};
    for(const r of RULES){
      if(!ruleMatches(r,g))continue;
      for(const v of RFIELD[g](r).filter(Boolean))counts[v]=(counts[v]||0)+1;
    }
    const opts=ROPTIONS[g].filter(v=>counts[v]||rfilters[g].includes(v));
    if(!opts.length)return'';
    const body=opts.map(v=>{
      const on=rfilters[g].includes(v);
      return `<button class="fbtn" data-rg="${g}" data-v="${esc(v)}" aria-pressed="${on}">
        <span>${esc(v)}</span><span class="c">${counts[v]||0}</span></button>`;
    }).join('');
    return fgroup('r:'+g,RGROUPS[g],body,rfilters[g].length);
  }).join('');
}
function rulesHTML(rules){
  if(!rules.length)return `<div class="empty">No rules match those filters.
    <button class="btn" onclick="resetAll()">Reset filters</button></div>`;
  return '<div class="rulegrid">'+rules.map(r=>`
    <button class="rule" data-f="${esc(r.path)}">
      <div class="rtop"><div><div class="rname">${esc(r.title)}</div>
        <div class="rfile">${esc(r.file)}</div></div>
        ${r.level?badge(r.level,r.level==='critical'):''}</div>
      ${r.description?`<p>${esc(r.description.split('\n')[0])}</p>`:''}
      <div class="rfoot"><span class="fmt">${esc(r.format)}</span>
        ${r.atlas.map(a=>`<span class="tchip">${esc(a)}</span>`).join('')}
        ${r.owasp.map(o=>`<span class="tchip">${esc(o)}</span>`).join('')}</div>
    </button>`).join('')+'</div>';
}
function ruleDrawerHTML(r){
  const base=location.origin==='null'?'':location.origin+location.pathname;
  return `<div class="dhead"><b>${esc(r.title)}</b>
    <button class="x" id="dClose" aria-label="Close">&#10005;</button></div>
  <div class="dbody">
    <div class="dsec"><h4>Rule file</h4><div class="locator">${esc(r.path)}</div>
      <div class="badgerow"><span class="fmt">${esc(r.format)}</span>
        ${r.level?badge(r.level,r.level==='critical','level'):''}
        ${r.status?badge(r.status,false):''}</div></div>
    ${r.description?`<div class="dsec"><h4>What it detects</h4><p>${esc(r.description)}</p></div>`:''}
    ${r.logsource?`<div class="dsec"><h4>Telemetry</h4><p>${esc(r.logsource)}</p></div>`:''}
    ${(r.atlas.length||r.owasp.length)?`<div class="dsec"><h4>Mapped techniques</h4>
      <div class="tech">${r.atlas.map(a=>`<span class="tchip" data-tech="${esc(a)}">${esc(a)}</span>`).join('')}
      ${r.owasp.map(o=>`<span class="tchip" data-owasp="${esc(o)}">${esc(o)}</span>`).join('')}</div></div>`:''}
    ${r.falsepositives.length?`<div class="dsec"><h4>False positives</h4>
      <ul class="fplist">${r.falsepositives.map(f=>`<li>${esc(f)}</li>`).join('')}</ul></div>`:''}
    <div class="dsec"><h4>Detection logic</h4><pre class="yaml">${esc(r.body)}</pre></div>
    <div class="dsec"><h4>Permalink</h4><div class="linkrow">
      <input readonly value="#rule/${esc(r.path)}" aria-label="Permalink">
      <button class="btn" id="dCopyLink" data-v="${esc(base+'#rule/'+r.path)}">copy link</button></div></div>
  </div>
  <div class="dfoot">
    <a class="btn primary" href="${REPO_URL}/blob/main/${esc(r.path)}" target="_blank" rel="noopener">View on GitHub</a>
    <button class="btn" id="dCopyPath" data-v="${esc(r.path)}">copy path</button>
  </div>`;
}
function openRuleDrawer(key,fromEl){
  const r=RULEMAP[key]||RULEFILE[key]; if(!r)return;
  selRule=r.path; lastFocus=fromEl||document.activeElement;
  const d=$('#drawer');
  d.innerHTML=ruleDrawerHTML(r);
  d.hidden=false;
  d.setAttribute('aria-label','Detection rule '+r.title);
  history.replaceState(null,'','#rule/'+r.path);
  $('#dClose').onclick=closeDrawer;
  $('#dClose').focus();
  $('#dCopyLink').onclick=e=>copy(e.target.dataset.v,e.target);
  $('#dCopyPath').onclick=e=>copy(e.target.dataset.v,e.target);
  wireTechChips();
}
function wireTechChips(){
  $$('#drawer .tchip[data-tech],#drawer .tchip[data-owasp]').forEach(c=>c.onclick=()=>{
    const t=c.dataset.tech,o=c.dataset.owasp;
    closeDrawer();
    resetRuleFilters();
    if(t)rfilters.ratlas=[t]; else rfilters.rowasp=[o];
    view='rules'; update();
  });
}
function resetRuleFilters(){for(const g of Object.keys(rfilters))rfilters[g]=[];
  ruleSet=null;query='';$('#q').value=''}

/* ---------- mappings ---------- */
function indexHTML(title,sub,items,key){
  const max=Math.max(1,...items.map(i=>i.count));
  return `<div class="idx"><h2>${esc(title)}</h2><p class="isub">${esc(sub)}</p>`+
    items.map(i=>`<div class="irow" data-idx="${key}" data-v="${esc(i.id)}"
        role="button" tabindex="0">
      <span class="iid">${esc(i.raw)}</span><span class="ittl">${esc(i.title)}</span>
      <span class="icount">${i.count}</span>
      <span class="bar"><i style="width:${Math.round(i.count/max*100)}%"></i></span>
    </div>`).join('')+'</div>';
}
function mappingsHTML(){
  return `<div class="gtop"><div><h2>Technique coverage</h2>
    <p>Rule counts per MITRE ATLAS technique and OWASP LLM Top 10 category.
    Click any row to see the rules that cover it.</p></div></div>
    <div class="idxwrap">
      ${indexHTML('MITRE ATLAS','Adversarial threat landscape for AI systems.',ATLAS_INDEX,'ratlas')}
      ${indexHTML('OWASP Top 10 for LLM Applications 2025','Application-layer risk categories.',OWASP_INDEX,'rowasp')}
    </div>`;
}

/* ---------- case studies ---------- */
// Indicators grouped by kind. A responder hunts one class at a time - files with
// a scanner, commits in version control, network indicators in a proxy log - so a
// flat list of mixed strings makes them do the sorting themselves.
const IOC_ORDER=['file','directory','binary','process','commit','domain','ip','url','hash','other'];
function iocGroups(iocs){
  const by={};
  for(const i of iocs){const k=(i.type||'other').toLowerCase(); (by[k]=by[k]||[]).push(i)}
  return Object.keys(by)
    .sort((a,b)=>{const x=IOC_ORDER.indexOf(a),y=IOC_ORDER.indexOf(b);
      return (x<0?99:x)-(y<0?99:y)||a.localeCompare(b)})
    .map(k=>({kind:k,items:by[k]}));
}
function caseStudiesHTML(){
  if(!CASES.length)return`<div class="empty">No case studies.</div>`;
  const byConf={};
  for(const c of CASES){const k=c.confidence||'unrated'; byConf[k]=(byConf[k]||0)+1}
  const tally=['high','medium','low','unrated'].filter(k=>byConf[k])
    .map(k=>`${byConf[k]} ${k}`).join(' · ');
  return `<div class="gtop"><div><h2>Case studies</h2>
    <p>Documented incidents and published research involving the tools in this
    catalog, with the indicators each left behind and what responders did about it.
    Every case records where its claims came from, because several of these rest on
    a single reporting party.</p>
    <p class="csconf">Provenance: ${esc(tally)}</p></div></div>`+
  CASES.map(c=>{
    const groups=iocGroups(c.iocs||[]);
    const n=(c.iocs||[]).length;
    // The affected tool is a link when the catalog knows it, because the useful
    // next move is always "show me every artifact this tool leaves". A case can
    // name more than one, and plenty name none the catalog covers.
    const known=(c.affects_ids||[]).map(id=>TOOLS.find(t=>t.entry_id===id)).filter(Boolean);
    const refs=c.references||[];
    return `
    <article class="csfull" id="cs-${esc(c.id)}">
      <div class="cshead">
        <div><div class="csname">${esc(c.title)}</div>
          <div class="csmeta">${esc(c.id)}${c.date_range?' · '+esc(c.date_range):''}${
            c.disclosed?' · disclosed '+esc(c.disclosed):''}</div></div>
        <div class="csjumps">
        ${known.length?known.map(k=>`<button class="btn csjump" data-t="${esc(k.tool)}"
          data-id="${esc(k.entry_id)}">${esc(k.tool)} artifacts &#8594;</button>`).join('')
        :c.affects?`<span class="fmt">${esc(c.affects)}</span>`:''}
        </div>
      </div>
      <p class="cssum">${esc(c.summary)}</p>
      ${c.confidence?`<div class="csprov">
        ${confBadge(c.confidence)}
        ${c.basis?`<span class="csbasis">${esc(c.basis)}</span>`:''}
      </div>`:''}
      ${c.contested?`<div class="csdispute"><b>Disputed.</b> ${esc(c.contested)}</div>`:''}
      <div class="csbody">
        <div class="cscol">
          <h5>Indicators <span class="n">${n}</span></h5>
          ${n?groups.map(g=>`<div class="iocgrp">
            <div class="iockind">${esc(g.kind)}</div>
            <div class="iocs">${g.items.map(i=>
              `<span class="ioc" title="${esc(i.description||'')}">${esc(i.value)}${
                i.description?`<em>${esc(i.description)}</em>`:''}</span>`).join('')}</div>
          </div>`).join(''):`<p class="muted">None published.</p>`}
        </div>
        <div class="cscol">
          <h5>Response</h5>
          ${(c.response_actions||[]).length?`<ol class="csact">${c.response_actions.map(a=>
            `<li>${esc(a)}</li>`).join('')}</ol>`:`<p class="muted">None recorded.</p>`}
        </div>
      </div>
      ${c.lesson?`<div class="lesson"><b>Lesson.</b> ${esc(c.lesson)}</div>`:''}
      ${(c.detections||[]).length?`<div class="csdet">
        <h5>Detections in this repo <span class="n">${c.detections.length}</span></h5>
        <div class="detrow">${c.detections.map(d=>
          `<button class="detchip" data-rule="${esc(d)}">${esc(d)}</button>`).join('')}</div>
      </div>`:''}
      ${(c.atlas||[]).length||refs.length?`<div class="csfoot">
        ${(c.atlas||[]).length?`<div class="csatlas"><h5>ATLAS</h5>${
          c.atlas.map(a=>`<a class="tech" href="https://atlas.mitre.org/techniques/${esc(a)}"
            target="_blank" rel="noopener">${esc(a)}</a>`).join('')}</div>`:''}
        ${refs.length?`<div class="csrefs"><h5>Sources <span class="n">${refs.length}</span></h5>
          <ul>${refs.map(r=>`<li><a href="${esc(r.url)}" target="_blank"
            rel="noopener">${esc(r.title||r.url)}</a></li>`).join('')}</ul></div>`:''}
      </div>`:''}
    </article>`}).join('');
}

/* ---------- guide ---------- */
function guideHTML(){
  const toc=GUIDE.toc.map(p=>
    `<a href="#g-${esc(p.anchor)}">${esc(p.title)}</a>`+
    p.sections.map(s=>`<a class="sub" href="#g-${esc(s.anchor)}">${esc(s.title)}</a>`).join('')
  ).join('');
  return `<div class="gtop"><div><h2>AI/ML DFIR Investigation Guide</h2>
    <p>Rendered from <code>${esc(GUIDE.source)}</code> at build time.</p></div>
    <a class="btn" href="${REPO_URL}/blob/main/${esc(GUIDE.source)}" target="_blank" rel="noopener">View on GitHub</a></div>
  <div class="guidewrap">
    <nav class="gtoc"><h4>Contents</h4>${toc}</nav>
    <div class="gbody">${GUIDE.html}</div>
  </div>`;
}

/* ---------- render ---------- */
function renderMain(){
  const shell=$('.shell');
  const railed=(view==='catalog'||view==='rules');
  shell.classList.toggle('nocol',!railed);
  $('#controls').hidden=!railed;
  $('#unvBtn').hidden=view!=='catalog';
  $('#denseBtn').hidden=view!=='catalog';
  $('#metaRow').hidden=!railed;
  $('#q').placeholder=view==='rules'?'Search rules, techniques, telemetry...'
                                    :'Search paths, tools, descriptions...';
  const main=$('#main');
  if(view==='rules'){
    const rules=filteredRules();
    $('#count').textContent=`${rules.length} of ${RULES.length} shown`;
    $('#chips').innerHTML=(ruleSet?`<button class="chip" data-rset="1"
      >${ruleSet.size} rule${ruleSet.size>1?'s':''} for one data source <s>&#10005;</s></button>`:'')
      +Object.keys(rfilters).flatMap(g=>rfilters[g].map(v=>
      `<button class="chip" data-rg="${g}" data-v="${esc(v)}">${esc(v)} <s>&#10005;</s></button>`)).join('');
    // One handler for every chip in this bar. The data-source chip is not a
    // facet, so it has no rfilters group - wiring it separately meant this
    // loop reassigned .onclick over the top of it and then threw on the
    // undefined group.
    $$('#chips .chip').forEach(c=>c.onclick=()=>{
      if(c.dataset.rset){ruleSet=null;update();return}
      const a=rfilters[c.dataset.rg],i=a.indexOf(c.dataset.v);
      if(i>=0)a.splice(i,1);
      update();
    });
    main.innerHTML=rulesHTML(rules);
    $$('#main .rule').forEach(el=>el.onclick=()=>openRuleDrawer(el.dataset.f,el));
    renderTabs();renderToast();return;
  }
  if(view==='mappings'){
    main.innerHTML=mappingsHTML();
    const go=el=>{
      resetRuleFilters();
      rfilters[el.dataset.idx]=[el.dataset.v];
      view='rules'; update();
    };
    $$('#main .irow').forEach(el=>{
      el.onclick=()=>go(el);
      el.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();go(el)}};
    });
    renderTabs();renderToast();return;
  }
  if(view==='sources'){
    main.innerHTML=sourcesHTML();
    // Every stat on a source card is a way into the rows or the rules it
    // covers, so the page reads as one catalog rather than as a second one.
    $$('#main .srcstat[data-cls]').forEach(b=>b.onclick=()=>{
      resetFilters();filters.cls=[b.dataset.cls];view='catalog';update();
    });
    $$('#main .srcstat[data-rules]').forEach(b=>b.onclick=()=>{
      resetRuleFilters();view='rules';
      ruleSet=new Set(SRCMAP[b.dataset.rules].rules);
      update();
    });
    renderTabs();renderToast();return;
  }
  if(view==='guide'){
    main.innerHTML=guideHTML();
    // Prefix rendered heading ids so guide anchors never collide with row anchors.
    $$('#main .gbody h2,#main .gbody h3').forEach(h=>{
      if(h.id&&!h.id.startsWith('g-'))h.id='g-'+h.id;
    });
    renderTabs();renderToast();return;
  }
  if(view==='catalog'){
    const rows=filteredRows();
    $('#count').textContent=`${rows.length} of ${ROWS.length} shown`;
    $('#chips').innerHTML=chipsHTML();
    $$('#chips .chip').forEach(c=>c.onclick=()=>{
      if(c.dataset.unv){unvOnly=false;$('#unvBtn').setAttribute('aria-pressed','false')}
      else{const a=filters[c.dataset.g],i=a.indexOf(c.dataset.v);if(i>=0)a.splice(i,1)}
      update();
    });
    main.innerHTML=`<div class="tablewrap ${dense?'dense':''}">${tableHTML(rows)}</div>
      <div class="cards">${cardsHTML(rows)}</div>`;
    const sortBy=k=>{if(sortKey===k)sortDir*=-1;else{sortKey=k;sortDir=1}renderMain()};
    $$('#main th[data-k]').forEach(th=>{
      th.onclick=()=>sortBy(th.dataset.k);
      th.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();sortBy(th.dataset.k)}};
    });
    $$('#main tbody tr,#main .card').forEach(el=>{
      const open=()=>openDrawer(el.dataset.a,el);
      el.onclick=open;
      el.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();open()}};
    });
    $$('#main .pick:not(.all)').forEach(p=>p.onclick=e=>{e.stopPropagation();togglePick(p.dataset.a)});
    const pa=$('#pickAllCol');
    if(pa)pa.onclick=e=>{e.stopPropagation();togglePickAll(e.currentTarget)};
  }else if(view==='cases'){
    main.innerHTML=caseStudiesHTML();
    $$('#main .csjump').forEach(b=>b.onclick=()=>{
      resetFilters();filters.tool=[b.dataset.t];view='catalog';
      history.replaceState(null,'','#'+b.dataset.id);
      update();
    });
    // Search rather than a filter facet: rule filenames are unique and the
    // detections rail facets by category and format, not by file.
    $$('#main .detchip').forEach(b=>b.onclick=()=>{
      resetFilters();view='rules';$('#q').value=b.dataset.rule;query=b.dataset.rule.toLowerCase();
      update();
    });
  }else if(view==='tools'){
    main.innerHTML=toolsHTML();
    $$('#main .tool').forEach(c=>c.onclick=()=>{
      resetFilters();filters.tool=[c.dataset.t];view='catalog';
      history.replaceState(null,'','#'+c.dataset.id);
      update();
    });
  }else{
    main.innerHTML=planHTML();
    const l=$('#cpLinks'),p=$('#cpList');
    if(l)l.onclick=()=>copy(planLinks(),l);
    if(p)p.onclick=()=>copy(planText(),p);
    $$('#main .rm').forEach(b=>b.onclick=()=>{picks.delete(b.dataset.a);savePicks();update()});
  }
  renderTabs();renderToast();
}
function renderTabs(){
  $$('.tabs button').forEach(b=>{
    const on=b.dataset.v===view;
    b.setAttribute('aria-selected',String(on));
    // Roving tabindex: one stop for the whole tablist, arrows move within it.
    b.tabIndex=on?0:-1;
    b.id='tab-'+b.dataset.v;
    b.setAttribute('aria-controls','main');
    const n=b.querySelector('.n');
    if(b.dataset.v==='plan'&&n)n.textContent=picks.size;
  });
  // All six views render into the one container, so the panel is labelled by
  // whichever tab is currently selected rather than there being six panels.
  $('#main').setAttribute('aria-labelledby','tab-'+view);
}
function renderToast(){
  const t=$('#toast');
  t.hidden=!picks.size||view==='plan';
  if(!t.hidden)$('#toastN').textContent=`${picks.size} artifact${picks.size>1?'s':''} picked`;
}
function update(){renderRail();renderMain()}

function resetFilters(){
  for(const g of Object.keys(filters))filters[g]=[];
  query='';$('#q').value='';
  unvOnly=false;$('#unvBtn').setAttribute('aria-pressed','false');
}
function resetAll(){resetFilters();resetRuleFilters();update()}
window.resetAll=resetAll;

/* ---------- hash routing ---------- */
function applyHash(){
  const h=decodeURIComponent(location.hash.slice(1));
  if(!h)return;
  if(h.startsWith('rule/')){
    const f=h.slice(5);
    if(RULEMAP[f]||RULEFILE[f]){view='rules';update();openRuleDrawer(f,null)}
    return;
  }
  if(h==='sources'){view='sources';update();return}
  if(h.startsWith('src-')){view='sources';update();
    const el=document.getElementById(h);if(el)el.scrollIntoView();return}
  if(h==='guide'){view='guide';update();return}
  if(h.startsWith('g-')){view='guide';update();
    const el=document.getElementById(h);if(el)el.scrollIntoView();return}
  if(ROWMAP[h]){view='catalog';update();openDrawer(h,null);return}
  const t=TOOLS.find(t=>t.entry_id.toLowerCase()===h.toLowerCase()||t.slug===h.toLowerCase());
  if(t){resetFilters();filters.tool=[t.tool];view='catalog';update()}
}

/* ---------- boot ---------- */
$('#q').addEventListener('input',e=>{query=e.target.value.trim().toLowerCase();update()});
$('#unvBtn').onclick=()=>{unvOnly=!unvOnly;$('#unvBtn').setAttribute('aria-pressed',String(unvOnly));update()};
$('#denseBtn').onclick=()=>{dense=!dense;
  $('#denseBtn').setAttribute('aria-pressed',String(dense));
  $('#denseBtn').textContent=dense?'Comfortable rows':'Compact rows';renderMain()};
/* ---------- export ---------- */
// Exports what is on screen, filters and sort included. A responder narrows to
// the tool and OS they are working and wants that list, not the whole catalog.
// Column order matches docs/api/artifacts.csv so the two read the same way, but
// this is a view export and is deliberately not that published feed.
const EXPORT_COLS=['entry_id','tool','cls','artifact','os','forensic_value',
                   'confidence','evidence','unverified','description'];
function csvCell(v){
  const s=Array.isArray(v)?v.join('|'):(v===undefined||v===null?'':String(v));
  // Quote when the value could otherwise break the row, and double any quote.
  return /[",\n\r]/.test(s)?'"'+s.replace(/"/g,'""')+'"':s;
}
function download(name,text,mime){
  const blob=new Blob([text],{type:mime+';charset=utf-8'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');
  a.href=url; a.download=name;
  document.body.appendChild(a); a.click(); a.remove();
  // Revoke on the next tick: revoking synchronously can cancel the download.
  setTimeout(()=>URL.revokeObjectURL(url),0);
}
function stamp(){return new Date().toISOString().slice(0,10)}
function flash(btn,msg){
  const old=btn.textContent; btn.textContent=msg;
  setTimeout(()=>{btn.textContent=old},1600);
}
function exportRows(){return filteredRows()}
$('#csvBtn').onclick=()=>{
  const rows=exportRows();
  const body=rows.map(r=>EXPORT_COLS.map(c=>csvCell(r[c])).join(',')).join('\n');
  download(`ai-dfir-catalog-${stamp()}.csv`, EXPORT_COLS.join(',')+'\n'+body+'\n','text/csv');
  flash($('#csvBtn'), `${rows.length} rows`);
};
$('#jsonBtn').onclick=()=>{
  const rows=exportRows();
  download(`ai-dfir-catalog-${stamp()}.json`, JSON.stringify({
    source:REPO_URL, exported:new Date().toISOString(),
    note:'Filtered view export from the catalog site. The published feed is docs/api/artifacts.csv.',
    count:rows.length, rows
  },null,2),'application/json');
  flash($('#jsonBtn'), `${rows.length} rows`);
};

// Same corpus the export uses, so "pick all shown" and "export" always agree on
// what "shown" means. Toggles: a second press on an already-complete selection
// drops those rows again, which is the only sane undo for a 400-row add.
function togglePickAll(btn){
  const anchors=exportRows().map(r=>r.anchor);
  const allPicked=anchors.length&&anchors.every(a=>picks.has(a));
  anchors.forEach(a=>allPicked?picks.delete(a):picks.add(a));
  savePicks();
  if(btn)flash(btn, `${allPicked?'removed':'picked'} ${anchors.length}`);
  update();
}
$('#pickAllBtn').onclick=e=>togglePickAll(e.currentTarget);

$$('.tabs button').forEach(b=>b.onclick=()=>{view=b.dataset.v;update()});
// Arrow-key navigation, which role=tablist promises and a plain button row
// does not provide on its own. Wrapping, plus Home/End, per the ARIA pattern.
$('.tabs').addEventListener('keydown',e=>{
  const keys={ArrowRight:1,ArrowLeft:-1,Home:0,End:0};
  if(!(e.key in keys))return;
  const tabs=$$('.tabs button'), i=tabs.indexOf(document.activeElement);
  if(i<0)return;
  e.preventDefault();
  const next=e.key==='Home'?0:e.key==='End'?tabs.length-1
    :(i+keys[e.key]+tabs.length)%tabs.length;
  view=tabs[next].dataset.v;update();tabs[next].focus();
});
$('#railReset').onclick=e=>{e.preventDefault();resetAll()};
$('#toastOpen').onclick=()=>{view='plan';renderMain()};
$('#toastClear').onclick=()=>{picks.clear();savePicks();update()};
$('#themeBtn').onclick=()=>{
  const cur=document.documentElement.dataset.theme==='dark'?'light':'dark';
  document.documentElement.dataset.theme=cur;
  try{localStorage.setItem('aidfir-theme',cur)}catch(e){}
  setThemeBtn();
};
function setThemeBtn(){
  const dark=document.documentElement.dataset.theme==='dark';
  $('#themeBtn').textContent=dark?'☀ Light':'☾ Dark';
  $('#themeBtn').setAttribute('aria-label',dark?'Switch to light theme':'Switch to dark theme');
}
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!$('#drawer').hidden)closeDrawer()});
window.addEventListener('hashchange',applyHash);
setThemeBtn();update();applyHash();
"""

THEME_BOOT = (
    # Default to light for first-time visitors; a stored choice still wins, and
    # the toggle continues to persist. (The prefers-color-scheme CSS block only
    # applies as a no-JS fallback, when no data-theme attribute gets set.)
    # 'aiart-' is the dropped AIRTIFACTS working name; fall back to it once so a
    # returning visitor's stored theme survives the rename.
    "(function(){try{var t=localStorage.getItem('aidfir-theme')"
    "||localStorage.getItem('aiart-theme')||'light';"
    "document.documentElement.dataset.theme=t}catch(e){}})();"
)


def check_cases(cases, tools, rules=()):
    """Case-study invariants. Returns a list of problems.

    A case study asserts things about somebody else's incident, mostly from a
    single reporting party, so the load-bearing field is provenance rather than
    the indicator list. An unsourced case is the thing that turns a catalog into
    a liability: a reader has no way to re-check it and no way to notice when
    the story changes. So confidence and at least one reference are required,
    and an id claimed in `affects` has to resolve to a real entry - the last
    time it did not, a case pointed at a renamed id and silently lost its link
    to the tool it describes.
    """
    problems = []
    ids = {t["entry_id"] for t in tools}
    rule_files = {r["file"] for r in rules}
    seen = set()
    for c in cases:
        cid = c["id"]
        if cid in seen:
            problems.append(f"[CASE]    {cid} is used by more than one file")
        seen.add(cid)
        if c["confidence"] not in ("high", "medium", "low"):
            problems.append(f"[CASE]    {cid} confidence '{c['confidence']}' "
                            f"is not high/medium/low")
        if not c["basis"]:
            problems.append(f"[CASE]    {cid} states a confidence with no basis")
        if not c["references"]:
            problems.append(f"[CASE]    {cid} has no references")
        for r in c["references"]:
            if not r["url"].startswith("https://"):
                problems.append(f"[CASE]    {cid} reference is not an https URL: {r['url']}")
        for eid in c["affects_ids"]:
            if eid not in ids:
                problems.append(f"[CASE]    {cid} affects {eid}, which is not a catalog entry")
        if not c["iocs"]:
            problems.append(f"[CASE]    {cid} publishes no indicators")
        for d in c["detections"]:
            if d not in rule_files:
                problems.append(f"[CASE]    {cid} cites detection {d}, which is not a rule "
                                f"in this repo")
    return problems


def check(rows, tools, rules, guide, cases=(), source_problems=()):
    """Assert the invariants the page depends on. Returns a problem count.

    Runs on every pull request, while the page itself is only built on push to
    main - so a change that breaks the data contract is caught before merge
    rather than after deploy. Writes nothing.

    Anchors are the load-bearing invariant: permalinks and saved picks are both
    stored against them, so a duplicate or a fragment-unsafe character silently
    sends a reader to the wrong row.
    """
    # Passed in rather than computed here so the printed count is the whole
    # count. A tail of extra failures under a "0 problem(s)" line is how a gate
    # gets read as green.
    problems = [f"[SOURCE]  {p}" for p in source_problems]
    ids = {t["entry_id"] for t in tools}

    seen = {}
    for r in rows:
        seen.setdefault(r["anchor"], []).append(r)
    for anchor, dupes in seen.items():
        if len(dupes) > 1:
            problems.append(f"[ANCHOR]  {anchor} used by {len(dupes)} rows")
    for r in rows:
        if not r["artifact"]:
            problems.append(f"[EMPTY]   {r['entry_id']} {r['cls']} row has no locator")
        if r["entry_id"] not in ids:
            problems.append(f"[ORPHAN]  {r['anchor']} has no tool entry")
        if re.search(r"[^A-Za-z0-9/_.\-]", r["anchor"]):
            problems.append(f"[SLUG]    {r['anchor']} is not URL-fragment safe")

    # Same failure mode as the OS facet below, one facet along: a row with a
    # volatility the facet does not offer is filtered out of every view of the
    # page and looks like it was never catalogued.
    for r in rows:
        if r.get("vol") not in data_sources.VOLATILITY_ORDER:
            problems.append(f"[VOL]     {r['anchor']} volatility "
                            f"{r.get('vol')!r} is not a facet option")

    # A row with no OS matches no OS facet, so it vanishes the moment a reader
    # clicks one. That is the worst failure mode this page has - not an error
    # message, a shorter list that looks complete.
    for r in rows:
        if not r["os"]:
            problems.append(f"[OS]      {r['anchor']} has no OS and is unreachable "
                            f"by any OS filter")

    # "What it proves" is derived for the classes the schema does not declare it
    # on, so both halves of that need guarding: every row says something, and
    # nothing says it in a vocabulary the schema does not know.
    enum = set()
    schema = ROOT / "schema" / "artifact.schema.json"
    if schema.exists():
        defs = json.loads(schema.read_text(encoding="utf-8")).get("$defs", {})
        ev = defs.get("diskArtifact", {}).get("properties", {}).get("evidence_type", {})
        enum = set(ev.get("items", {}).get("enum", []))
    for r in rows:
        if not r["evidence"]:
            problems.append(f"[PROVES]  {r['anchor']} has no evidence type")
        for value in r["evidence"] if enum else []:
            if value not in enum:
                problems.append(f"[VOCAB]   {r['anchor']} evidence '{value}' is not in the schema enum")

    # The rule loader discovers category directories rather than listing them,
    # because it used to list them and three whole categories went missing from
    # the page while every other document counted them. Compare what was loaded
    # against what is on disk, so that cannot recur quietly.
    on_disk = set()
    for d in ROOT.parent.iterdir():
        if d.is_dir() and re.match(r"^\d{2}-", d.name):
            on_disk |= {p.name for p in d.iterdir()
                        if p.suffix.lower() in (".yml", ".yaml", ".yar", ".rules")}
    sigma_dir = ROOT / "detections" / "sigma"
    if sigma_dir.is_dir():
        on_disk |= {p.name for p in sigma_dir.glob("*.yml")}
    loaded = {r["file"] for r in rules}
    for missing in sorted(on_disk - loaded):
        problems.append(f"[RULES]   {missing} is on disk but the site never loaded it")

    # A rule that parses to no title means an extractor broke on a real file.
    for rule in rules:
        if not rule.get("title"):
            problems.append(f"[RULE]    {rule.get('path', '?')} parsed without a title")

    # render_diagrams.py writes content-addressed SVGs; an edited diagram that
    # was never re-rendered would otherwise ship as raw mermaid source.
    for h in guide.get("missing_diagrams") or []:
        problems.append(f"[DIAGRAM] no rendered SVG for mermaid block {h}")

    problems += check_cases(cases, tools, rules)

    by_class = {}
    for r in rows:
        by_class[r["cls"]] = by_class.get(r["cls"], 0) + 1
    print(f"rows {len(rows)} · anchors unique {len(seen)} · tools {len(tools)} · "
          f"rules {len(rules)}")
    print("by class: " + ", ".join(f"{k} {v}" for k, v in sorted(by_class.items())))
    for line in problems:
        print(line)
    print(f"\n{len(problems)} problem(s).")
    return len(problems)


def main():
    entries = json.loads((API / "catalog.json").read_text(encoding="utf-8"))
    rows = build_rows(entries)
    tools = build_tools(entries, rows)

    # Everything outside the catalog proper: rules, indexes, case studies, guide.
    mapping_rows, atlas_index, owasp_index = site_data.load_mappings()
    rules = site_data.load_rules(mapping_rows)
    cases = site_data.load_case_studies()
    guide = site_data.load_guide()

    # Coverage is computed, never authored. audit() is also a hard gate in
    # validate.py; running it here too means a stale source table cannot reach
    # the deployed page even if somebody skips the validator.
    cov = data_sources.coverage(data_sources.load_sources(), entries)
    sources = cov["sources"]
    cls_count = cov["per_class"]

    if "--check" in sys.argv:
        return 1 if check(rows, tools, rules, guide, cases,
                          data_sources.audit(cov)) else 0

    n_cred = sum(1 for r in rows if r["cls"] == "credential")
    n_mcp = sum(1 for r in rows if r["cls"] == "mcp-config")
    n_art = len(rows) - n_cred - n_mcp
    n_unv = sum(1 for r in rows if r["unverified"])

    og_desc = (
        f"{len(tools)} tools, {n_art} artifacts, {n_cred} credential locations, "
        f"{n_mcp} MCP configs - install paths, plaintext token locations, listening "
        f"ports and process trees, each rated by forensic value and sourcing confidence."
    )

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Agent Artifact Catalog</title>
<meta name="description" content="{html.escape(og_desc)}">
<link rel="canonical" href="{SITE}">
<link rel="icon" href="{FAVICON}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="ai-dfir-toolkit">
<meta property="og:title" content="AI Agent Artifact Catalog">
<meta property="og:description" content="{html.escape(og_desc)}">
<meta property="og:url" content="{SITE}">
<meta property="og:image" content="{SITE}card.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<script>{THEME_BOOT}</script>
<style>{CSS}</style>
</head>
<body>
<a class="skip" href="#main">Skip to results</a>
<div class="hdr"><div class="hdr-in">
  <div class="hdr-top">
    <div class="hdr-id">
      <div class="h1row"><span class="dot"></span><h1>AI Agent Artifact Catalog</h1>
        <span class="pill">generated &middot; CC BY 4.0</span></div>
      <p class="sub">What AI coding agents, local model runtimes and MCP components leave
      on an endpoint, what each trace proves, and in what order to collect it.</p>
    </div>
    <div class="hdr-right">
      <a class="ghlink" href="{REPO}" target="_blank" rel="noopener"
         aria-label="View this project on GitHub">GitHub &#8599;</a>
      <button id="themeBtn" type="button"></button></div>
  </div>
  <nav class="tabs" role="tablist">
    <button role="tab" data-v="catalog">Catalog <span class="n">{len(rows)}</span></button>
    <button role="tab" data-v="tools">Tools <span class="n">{len(tools)}</span></button>
    <button role="tab" data-v="rules">Detections <span class="n">{len(rules)}</span></button>
    <button role="tab" data-v="mappings">Mappings <span class="n">{len(atlas_index) + len(owasp_index)}</span></button>
    <button role="tab" data-v="sources">Data sources <span class="n">{len(sources)}</span></button>
    <button role="tab" data-v="cases">Case studies <span class="n">{len(cases)}</span></button>
    <button role="tab" data-v="plan">Collection plan <span class="n">0</span></button>
    <button role="tab" class="guidelink" data-v="guide">Investigation guide &#8594;</button>
  </nav>
</div></div>

<div class="shell">
<aside>
  <div class="railhead"><b>Filters</b><a id="railReset" href="#">reset</a></div>
  <div class="railscroll" id="rail"></div>
  <details class="railfold" id="railfold"><summary>Filters</summary>
    <div class="foldbody"></div></details>
</aside>
<main class="content">
  <div class="controls" id="controls">
    <div class="search"><span class="glyph">&#8981;</span>
      <input id="q" type="search" placeholder="Search paths, tools, descriptions..."
        aria-label="Search the catalog"></div>
    <button class="tgl" id="unvBtn" type="button" aria-pressed="false">Unverified only
      <span class="n">{n_unv}</span></button>
    <button class="tgl plain" id="denseBtn" type="button" aria-pressed="false">Compact rows</button>
    <button class="tgl plain" id="pickAllBtn" type="button">Pick all shown</button>
    <div class="exportgrp" role="group" aria-label="Export the filtered rows">
      <span class="exportlbl">Export</span>
      <button class="tgl plain" id="csvBtn" type="button">CSV</button>
      <button class="tgl plain" id="jsonBtn" type="button">JSON</button>
    </div>
  </div>
  <div class="meta-row" id="metaRow"><span class="count" id="count"
    role="status" aria-live="polite" aria-atomic="true"></span>
    <span id="chips" style="display:contents"></span></div>
  <div id="main" role="tabpanel" tabindex="0"></div>
</main>
</div>

<div class="drawer" id="drawer" hidden role="dialog" aria-modal="false"></div>
<div class="toast" id="toast" hidden><span id="toastN"></span>
  <button id="toastOpen" type="button">Open collection plan</button>
  <a id="toastClear">clear</a></div>

<footer>
  <p><strong>Confidence reflects provenance, not conviction.</strong>
  <em>high</em> means verified on a live host or documented by the vendor,
  <em>medium</em> means multiple independent sources agree, and <em>low</em> means
  single-source or inferred. Anything single-sourced is flagged
  <span class="unv">unverified</span>. Paths move between tool releases, so treat
  this as a starting point and verify before you rely on it.</p>
  <p>Generated from the catalog source. Corrections welcome, especially if you can
  verify a path on a real host.
  <a href="{REPO}/tree/main/artifacts">Source</a> &middot;
  <a href="{REPO}/issues">Report an error</a> &middot;
  <a href="{REPO}/releases/latest">Download the feeds</a><br>
  Catalog data CC BY 4.0. Scripts and schema Apache-2.0.</p>
</footer>
<script>
const REPO_URL={json.dumps(REPO)};
const ROWS={json.dumps(rows, separators=(",", ":"))};
const TOOLS={json.dumps(tools, separators=(",", ":"))};
const RULES={json.dumps(rules, separators=(",", ":"))};
const ATLAS_INDEX={json.dumps(atlas_index, separators=(",", ":"))};
const OWASP_INDEX={json.dumps(owasp_index, separators=(",", ":"))};
const CASES={json.dumps(cases, separators=(",", ":"))};
const SOURCES={json.dumps(sources, separators=(",", ":"))};
const VOL_MEANING={json.dumps(data_sources.VOLATILITY_MEANING, separators=(",", ":"))};
const VOL_TIERS={json.dumps(data_sources.VOLATILITY_ORDER, separators=(",", ":"))};
const CLS_COUNT={json.dumps(cls_count, separators=(",", ":"))};
const GUIDE={json.dumps(guide, separators=(",", ":"))};
{JS}
</script>
</body>
</html>
"""

    OUT.mkdir(parents=True, exist_ok=True)
    write_lf(OUT / "index.html", page)
    write_lf(OUT / ".nojekyll", "")
    card = ASSETS / "card.png"
    if card.exists():
        shutil.copy2(card, OUT / "card.png")
    else:
        print("note: docs/site-assets/card.png missing - og:image will 404")
    size = (OUT / "index.html").stat().st_size
    print(f"{len(tools)} tools, {len(rows)} rows -> docs/site/index.html ({size // 1024} KB)")


if __name__ == "__main__":
    sys.exit(main() or 0)
