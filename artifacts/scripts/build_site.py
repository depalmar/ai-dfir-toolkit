#!/usr/bin/env python3
"""Build the browsable catalog site from the generated feeds.

    python scripts/build_site.py            # writes docs/site/

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
from pathlib import Path

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
                else:
                    loc = a.get("path") or a.get("name") or ""
                rows.append({
                    "entry_id": eid, "tool": e["name"], "cls": kind,
                    "artifact": loc,
                    "os": aslist(a.get("os")),
                    "forensic_value": a.get("forensic_value", ""),
                    "confidence": a.get("confidence", ""),
                    "evidence": aslist(a.get("evidence_type")),
                    "unverified": bool(a.get("unverified")),
                    "description": a.get("description", ""),
                })
        for c in (e.get("credentials") or []):
            rows.append({
                "entry_id": eid, "tool": e["name"], "cls": "credential",
                "artifact": c.get("location", ""),
                "os": aslist(c.get("os")),
                "forensic_value": "high",
                "confidence": c.get("confidence", ""),
                "evidence": aslist(c.get("secret_type")),
                "unverified": bool(c.get("unverified")),
                "description": c.get("description", ""),
            })
        for m in (e.get("mcp") or []):
            loc = m.get("config_path", "")
            if m.get("config_key"):
                loc += " → " + str(m["config_key"])
            rows.append({
                "entry_id": eid, "tool": e["name"], "cls": "mcp-config",
                "artifact": loc,
                "os": [],
                "forensic_value": "high",
                "confidence": "high",
                "evidence": ["execution", "persistence"],
                "unverified": False,
                "description": m.get("notes", ""),
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
.hdr-right{display:flex;gap:20px;align-items:flex-start;flex-wrap:wrap}
.stat{min-width:64px}
.stat b{display:block;font-family:ui-monospace,Menlo,monospace;font-size:20px;
  font-weight:600;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.stat span{font-size:11px;letter-spacing:.02em;text-transform:uppercase;color:var(--muted)}
#themeBtn{background:var(--panel);border:1px solid var(--line);border-radius:8px;
  padding:7px 11px;font-size:12.5px;color:var(--muted)}
#themeBtn:hover{color:var(--ink);border-color:var(--accent)}
.tabs{display:flex;gap:2px;margin-top:8px}
.tabs button{background:none;border:0;border-bottom:2px solid transparent;
  padding:9px 14px;font-size:13.5px;color:var(--muted);display:flex;gap:7px;align-items:center}
.tabs button[aria-selected=true]{color:var(--ink);font-weight:600;border-bottom-color:var(--accent)}
.tabs .n{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;background:var(--line-soft);
  border-radius:20px;padding:1px 7px;color:var(--muted)}

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
.fgroup h3{margin:0 0 5px;font-size:11px;letter-spacing:.06em;text-transform:uppercase;
  color:var(--faint);font-weight:600}
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
@media(max-width:620px){
  .tablewrap{display:none}
  .cards{display:flex}
  .drawer{width:100vw;max-width:100vw}
}
"""

JS = r"""
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const RANK={critical:0,p1:0,high:1,p2:1,medium:2,p3:2,low:3};
const TONE={critical:'b-crit',p1:'b-crit',high:'b-high',p2:'b-high',medium:'b-med',p3:'b-med',low:'b-low'};
const TOOLMAP=Object.fromEntries(TOOLS.map(t=>[t.entry_id,t]));
const ROWMAP=Object.fromEntries(ROWS.map(r=>[r.anchor,r]));
const GROUPS={cls:'Artifact class',os:'Operating system',fv:'Forensic value',conf:'Confidence',tool:'Tool'};
const FIELD={cls:r=>[r.cls],os:r=>r.os,fv:r=>[r.forensic_value],conf:r=>[r.confidence],tool:r=>[r.tool]};
const OPTIONS={
  cls:[...new Set(ROWS.map(r=>r.cls))].sort(),
  os:['windows','macos','linux'],
  fv:['high','medium','low'],
  conf:['high','medium','low'],
  tool:TOOLS.map(t=>t.tool).sort((a,b)=>a.localeCompare(b)),
};

let view='catalog', query='', unvOnly=false, dense=false,
    sortKey='entry_id', sortDir=1, sel=null, lastFocus=null;
const filters={cls:[],os:[],fv:[],conf:[],tool:[]};
const picks=new Set();

function badge(v,filled,prefix){
  if(!v)return'';
  return `<span class="badge ${filled?'fill ':''}${TONE[v]||''}">${prefix?esc(prefix)+' ':''}${esc(v)}</span>`;
}
const fvBadge=(v,p)=>badge(v,v==='high',p);
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
  const hay=(r.artifact+' '+r.tool+' '+r.description+' '+r.cls+' '+r.entry_id+' '+r.evidence.join(' ')).toLowerCase();
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
function railHTML(){
  return Object.keys(GROUPS).map(g=>{
    const counts={};
    for(const r of ROWS){
      if(!rowMatches(r,g))continue;
      for(const v of FIELD[g](r).filter(Boolean))counts[v]=(counts[v]||0)+1;
    }
    return `<div class="fgroup"><h3>${GROUPS[g]}</h3>`+OPTIONS[g].map(v=>{
      const on=filters[g].includes(v);
      return `<button class="fbtn" data-g="${g}" data-v="${esc(v)}" aria-pressed="${on}">
        <span>${esc(v)}</span><span class="c">${counts[v]||0}</span></button>`;
    }).join('')+'</div>';
  }).join('');
}
function renderRail(){
  const h=railHTML();
  $('#rail').innerHTML=h;
  $('#railfold .foldbody').innerHTML=h;
  $$('.fbtn').forEach(b=>b.onclick=()=>{
    const g=b.dataset.g,v=b.dataset.v,a=filters[g],i=a.indexOf(v);
    i<0?a.push(v):a.splice(i,1);
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
  return `<div class="tablescroll"><table><thead><tr>`+COLS.map(([l,k])=>{
    if(k==='pick')return '<th aria-hidden="true"></th>';
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
      <td>${fvBadge(r.forensic_value)}</td>
      <td>${badge(r.confidence,false)}</td>
      <td><span class="note">${esc(r.description)}</span></td>
    </tr>`).join('')+'</tbody></table></div>';
}
function cardsHTML(rows){
  if(!rows.length)return `<div class="empty">Nothing matches those filters.
    <button class="btn" onclick="resetAll()">Reset filters</button></div>`;
  return rows.map(r=>`
    <div class="card" data-a="${esc(r.anchor)}" tabindex="0">
      <div class="top"><b>${esc(r.tool)}</b><span class="clspill">${esc(r.cls)}</span>
        ${fvBadge(r.forensic_value)}${badge(r.confidence,false)}</div>
      <span class="path">${esc(r.artifact)}</span>
      <div class="meta">${esc(r.entry_id)}${r.os.length?' &middot; '+esc(r.os.join(', ')):''}${r.unverified?' &middot; <span class="unv">unverified</span>':''}</div>
    </div>`).join('');
}

/* ---------- tools ---------- */
function toolsHTML(){
  return '<div class="toolgrid">'+TOOLS.map(t=>`
    <button class="tool" data-t="${esc(t.tool)}" data-id="${esc(t.entry_id)}">
      <div class="trow"><div><div class="tname">${esc(t.tool)}</div>
        <div class="tsub">${esc(t.vendor)} &middot; ${esc(t.category)}</div></div>
        ${riskBadge(t.risk)}</div>
      <p>${esc(t.description)}</p>
      ${t.caps.length?`<div class="capchips">${t.caps.map(c=>`<i>${esc(c)}</i>`).join('')}</div>`:''}
      <div class="tfoot"><span>${t.n} artifacts</span>${t.triage?`<span>triage ${esc(t.triage)}</span>`:''}
        <span>${esc(t.os.join(' · '))}</span></div>
    </button>`).join('')+'</div>';
}

/* ---------- plan ---------- */
function planGroups(){
  const by={};
  for(const a of picks){const r=ROWMAP[a];if(!r)continue;(by[r.entry_id]=by[r.entry_id]||[]).push(r)}
  const groups=Object.entries(by).map(([id,rows])=>({t:TOOLMAP[id],rows}));
  groups.sort((a,b)=>(RANK[a.t.triage]??9)-(RANK[b.t.triage]??9)||a.t.tool.localeCompare(b.t.tool));
  for(const g of groups)g.rows.sort((a,b)=>(RANK[a.forensic_value]??9)-(RANK[b.forensic_value]??9));
  return groups;
}
function planHTML(){
  const groups=planGroups();
  const head=`<div class="planhead"><div><h2>Collection plan</h2>
    <p>Picked artifacts grouped by tool and ordered by triage priority. Work top to bottom.</p></div>
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
      <div class="badgerow">${fvBadge(r.forensic_value,'value')}
      ${badge(r.confidence,false,'conf')}
      ${r.unverified?'<span class="badge dashed b-crit">unverified</span>':''}</div></div>
    <div class="dsec"><h4>What it proves</h4>
      ${r.evidence.length?`<div class="evrow">${r.evidence.map(e=>`<span class="ev">${esc(e)}</span>`).join('')}</div>`:''}
      ${r.description?`<p>${esc(r.description)}</p>`:''}</div>
    <div class="dsec"><h4>Tool context</h4><p>${esc(t.description||'')}</p>
      ${t.abuse?`<div class="alert"><b>Abuse potential.</b> ${esc(t.abuse)}</div>`:''}</div>
    <div class="dsec"><h4>Collection order</h4>
      <div class="badgerow" style="margin:0 0 8px">${triageBadge(t.triage)}${riskBadge(t.risk,'risk')}</div>
      ${t.guidance?`<p>${esc(t.guidance)}</p>`:''}</div>
    ${t.techniques&&t.techniques.length?`<div class="dsec"><h4>Mapped techniques</h4>
      <div class="tech">${t.techniques.map(x=>`<i>${esc(x)}</i>`).join('')}</div></div>`:''}
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
  renderMain();
}
function closeDrawer(){
  sel=null; $('#drawer').hidden=true;
  history.replaceState(null,'',location.pathname+location.search);
  renderMain();
  if(lastFocus&&document.contains(lastFocus))lastFocus.focus();
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
function togglePick(a){picks.has(a)?picks.delete(a):picks.add(a);update()}

/* ---------- render ---------- */
function renderMain(){
  const shell=$('.shell');
  shell.classList.toggle('nocol',view!=='catalog');
  $('#controls').hidden=view!=='catalog';
  $('#metaRow').hidden=view!=='catalog';
  const main=$('#main');
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
    $$('#main .pick').forEach(p=>p.onclick=e=>{e.stopPropagation();togglePick(p.dataset.a)});
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
    $$('#main .rm').forEach(b=>b.onclick=()=>{picks.delete(b.dataset.a);update()});
  }
  renderTabs();renderToast();
}
function renderTabs(){
  $$('.tabs button').forEach(b=>{
    b.setAttribute('aria-selected',String(b.dataset.v===view));
    if(b.dataset.v==='plan')b.querySelector('.n').textContent=picks.size;
  });
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
function resetAll(){resetFilters();update()}
window.resetAll=resetAll;

/* ---------- hash routing ---------- */
function applyHash(){
  const h=decodeURIComponent(location.hash.slice(1));
  if(!h)return;
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
$$('.tabs button').forEach(b=>b.onclick=()=>{view=b.dataset.v;renderMain()});
$('#railReset').onclick=e=>{e.preventDefault();resetAll()};
$('#toastOpen').onclick=()=>{view='plan';renderMain()};
$('#toastClear').onclick=()=>{picks.clear();update()};
$('#themeBtn').onclick=()=>{
  const cur=document.documentElement.dataset.theme==='dark'?'light':'dark';
  document.documentElement.dataset.theme=cur;
  try{localStorage.setItem('aiart-theme',cur)}catch(e){}
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
    "(function(){try{var t=localStorage.getItem('aiart-theme');"
    "if(!t)t=matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';"
    "document.documentElement.dataset.theme=t}catch(e){}})();"
)


def main():
    entries = json.loads((API / "catalog.json").read_text(encoding="utf-8"))
    rows = build_rows(entries)
    tools = build_tools(entries, rows)

    n_cred = sum(1 for r in rows if r["cls"] == "credential")
    n_mcp = sum(1 for r in rows if r["cls"] == "mcp-config")
    n_art = len(rows) - n_cred - n_mcp
    n_unv = sum(1 for r in rows if r["unverified"])

    og_desc = (
        f"{len(tools)} tools, {n_art} artifacts, {n_cred} credential locations, "
        f"{n_mcp} MCP configs - install paths, plaintext token locations, listening "
        f"ports and process trees, each rated by forensic value and sourcing confidence."
    )

    stats = [(len(tools), "tools"), (n_art, "artifacts"), (n_cred, "creds"),
             (n_mcp, "MCP"), (n_unv, "unverified")]
    stats_html = "".join(
        f'<div class="stat"><b>{n}</b><span>{label}</span></div>' for n, label in stats)

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
<div class="hdr"><div class="hdr-in">
  <div class="hdr-top">
    <div class="hdr-id">
      <div class="h1row"><span class="dot"></span><h1>AI Agent Artifact Catalog</h1>
        <span class="pill">generated &middot; CC BY 4.0</span></div>
      <p class="sub">What AI coding agents, local model runtimes and MCP components leave
      on an endpoint, what each trace proves, and in what order to collect it.</p>
    </div>
    <div class="hdr-right">{stats_html}
      <button id="themeBtn" type="button"></button></div>
  </div>
  <nav class="tabs" role="tablist">
    <button role="tab" data-v="catalog">Artifacts <span class="n">{len(rows)}</span></button>
    <button role="tab" data-v="tools">Tools <span class="n">{len(tools)}</span></button>
    <button role="tab" data-v="plan">Collection plan <span class="n">0</span></button>
  </nav>
</div></div>

<div class="shell">
<aside>
  <div class="railhead"><b>Filters</b><a id="railReset" href="#">reset</a></div>
  <div class="railscroll" id="rail"></div>
  <details class="railfold" id="railfold"><summary>Filters</summary>
    <div class="foldbody"></div></details>
</aside>
<div>
  <div class="controls" id="controls">
    <div class="search"><span class="glyph">&#8981;</span>
      <input id="q" type="search" placeholder="Search paths, tools, descriptions..."
        aria-label="Search the catalog"></div>
    <button class="tgl" id="unvBtn" type="button" aria-pressed="false">Unverified only</button>
    <button class="tgl plain" id="denseBtn" type="button" aria-pressed="false">Compact rows</button>
  </div>
  <div class="meta-row" id="metaRow"><span class="count" id="count"></span>
    <span id="chips" style="display:contents"></span></div>
  <div id="main"></div>
</div>
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
const ROWS={json.dumps(rows, separators=(",", ":"))};
const TOOLS={json.dumps(tools, separators=(",", ":"))};
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
    main()
