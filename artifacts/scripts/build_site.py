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
        # Triage priority is authored on the entry's collection block, so no row
        # carried it and "show me the p1 paths on this host" was unaskable -
        # while the collection plan groups by exactly that. Inherited the same
        # way supported_os is, and for the same reason: the property is true of
        # the artifact, it is simply recorded once at the level where it applies
        # to all of them. MCP rows override it below because the schema lets an
        # individual MCP config carry its own.
        entry_triage = (e.get("collection") or {}).get("triage_priority", "")
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
                    "triage": entry_triage,
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
                "triage": entry_triage,
            })
        for m in (e.get("mcp") or []):
            # Only a config-file row has a path. A database, in-code, server or
            # cloud row carries an indicator instead - what to grep for or ask
            # for - and reading config_path alone gave those rows a locator of
            # " -> mcpServers", which is an arrow pointing at nothing.
            loc = m.get("config_path") or m.get("indicator") or ""
            if m.get("config_key") and m.get("config_path"):
                loc += " → " + str(m["config_key"])
            rows.append({
                "entry_id": eid, "tool": e["name"], "cls": "mcp-config",
                "artifact": loc,
                "os": entry_os,
                "forensic_value": "high",
                "confidence": m.get("confidence", "high"),
                "evidence": ["execution", "persistence"],
                "unverified": bool(m.get("unverified")),
                "mechanism": m.get("mechanism", ""),
                "description": m.get("notes", ""),
                "vol": data_sources.volatility_of("mcp-config", m),
                "retention": "",
                # The schema declares triage_priority on an MCP row as well as on
                # the entry, and where both exist the row's own is the specific
                # claim. Falls back to the entry's, so a row never ends up with
                # no priority at all.
                "triage": m.get("triage_priority") or entry_triage,
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
            # Also kept apart. The merged list is what the drawer renders, but the
            # coverage view has to count ATLAS against ATLAS rules and cannot tell
            # AML.T0053 from T1059 once they are in one array.
            "atlas": aslist(e.get("atlas_techniques")),
            "attack": aslist(e.get("attack_techniques")),
            "caps": labels,
            "n": counts.get(e["id"], 0),
        })
    return tools


CSS = """
:root{
  --bg:#fbfbfa; --panel:#ffffff; --panel-2:#fbfbfa; --hover:#faf7f4;
  --ink:#1c1b19; --muted:#6b6862; --faint:#a09b90;
  --line:#e4e1db; --line-soft:#f0ede8; --field-line:#ddd8d0;
  /* Deep umber, deliberately below the severity ramp in lightness and
     saturation. At #8a4b2a the accent was hue 21 / L35, four degrees from the
     `live` volatility badge (hue 17 / L33) and six from --high (hue 27) - so
     the one colour that means "interactive" was indistinguishable from two that
     mean "urgent". Same defect as confidence and forensic value both being blue. */
  --accent:#5e3a24; --accent-hover:#472a19; --accent-soft:#f2e9e2;
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
  /* Same separation as light mode, inverted: lighter and less saturated rather
     than darker. At #e9a97d the dark accent sat at hue 24 between --high (31)
     and the `live` badge (19) at a matching lightness - the identical collision.
     Contrast against the panel improves from 8.73 to 10.54 as a side effect. */
  --accent:#ddc4b0; --accent-hover:#ecd6c4; --accent-soft:#2d2118;
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
.unv{font-size:10px;text-transform:uppercase;letter-spacing:.06em;font-weight:600;
  color:var(--crit);cursor:help;border-bottom:1px dotted var(--crit)}
.unvnote{margin:0 0 12px;padding:9px 12px;font-size:12.5px;line-height:1.5;
  color:var(--muted);background:var(--alert-bg);border:1px solid var(--alert-line);
  border-radius:8px;max-width:88ch}
.unvwhy{margin:9px 0 0;font-size:12px;line-height:1.5;color:var(--muted)}

/* Keyboard focus. There was one :focus-visible rule in the whole stylesheet -
   on table headers - so tabbing through a page built almost entirely of buttons,
   chips and tiles showed nothing at all. WCAG 2.4.7. Declared once, globally,
   rather than per component, so a new control cannot be added without it. */
:where(button,a,input,select,summary,[tabindex]):focus-visible{
  outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
details.csfull>summary:focus-visible,details.src>summary:focus-visible{
  outline-offset:-2px}
tbody tr:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}

/* ---- plan identity ---- */
.planid{display:flex;flex-wrap:wrap;align-items:center;gap:7px;margin-bottom:10px}
.planid input,.planid select{border:1px solid var(--field-line);background:var(--panel);
  color:var(--ink);border-radius:7px;padding:5px 9px;font-size:12.5px;font-family:inherit}
.planid #pName{min-width:190px;font-weight:600}
.planid #pHost{min-width:150px}
.planid select{max-width:260px;cursor:pointer}
.pmeta{color:var(--faint);font-size:11.5px}

/* ---- table ---- */
.tablewrap{border:1px solid var(--line);border-radius:10px;background:var(--panel);overflow:hidden}
/* The height cap is what makes the sticky th below actually stick. overflow-x
   computes overflow-y to auto, so this element was already the scrollport - but
   with no height constraint it grew to content height, never scrolled
   vertically, and the header left the screen with the page. From about row 30
   the Value and Conf columns were unlabelled pills separated only by hue at
   11px, which is also why the bare-badge decision further down is safe again
   once this is capped: that comment's premise is "the column header already
   names the scale there", and the header has to be on screen for it to hold. */
.tablescroll{overflow-x:auto;overflow-y:auto;max-height:calc(100vh - 190px);min-height:320px}
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
/* Column widths, so the two prose-ish columns are not left fighting over the
   slack. Artifact holds paths that break anywhere, and with no widths at all it
   took whatever it wanted and squeezed Notes into a 38ch ribbon. */
col.k-pick{width:40px}
col.k-id{width:96px}
col.k-tool{width:132px}
col.k-cls{width:92px}
col.k-os{width:108px}
col.k-fv{width:74px}
col.k-conf{width:74px}
col.k-art{width:34%}
/* word-break:break-all lets a path shrink to a single character, so in auto
   layout the Artifact column surrendered everything to Notes and ended up
   narrower than the OS column. A floor on the cell stops the giveaway; the two
   prose columns then split what is left. */
td.artcell{min-width:300px}
td .path{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}
td .id{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--muted);white-space:nowrap}
/* Clamped to two lines. Measured over all 615 rows this takes the total table
   from 55353px to 46212px, the p90 row from 133px to 99px and the tallest row
   from 227px to 142px - so it cuts the scroll distance and the long tail.
   It does NOT raise rows-per-screen at the median, which stays at 79px: the
   median row is driven by the OS cell, where "windows, macos, linux" wraps to
   three lines and 57px in a narrow column. That is the next lever, not this one.
   Safe only because the full text stays one click away - drawerHTML renders
   r.description unclamped. The Notes column carries the operational caveats,
   and a responder who never opens the row must still be able to reach the
   sentence that changes what they collect. */
td .note{font-size:12.5px;color:var(--muted);display:-webkit-box;
  -webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.pick{width:24px;height:24px;border-radius:6px;border:1px solid var(--field-line);
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
.srcintro{margin:0;font-size:13.5px;color:var(--muted);max-width:70ch}
.vollegend{display:grid;gap:7px;margin-top:12px}
.vollegend>div{display:grid;grid-template-columns:130px 1fr;gap:10px;align-items:start;font-size:12.5px}
/* Same grid as the case studies. Reading order is still volatility order - the
   whole point of this view - because a grid fills left to right before it wraps,
   so `live` stays first however many columns fit. */
.srcgridwrap{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));
  gap:10px}
details.src{background:var(--panel);border:1px solid var(--line);border-radius:11px;
  padding:0;margin:0;overflow:hidden;display:flex;flex-direction:column}
details.src[open]{grid-column:1/-1}
details.src:not([open])>summary{flex:1}
@media(max-width:760px){.srcgridwrap{grid-template-columns:1fr}}
details.src>summary.srchead{display:flex;flex-direction:column;gap:9px;
  justify-content:space-between;align-items:stretch;
  padding:12px 14px 12px 30px;cursor:pointer;min-height:74px;
  list-style:none;position:relative;margin:0}
details.src[open]>summary.srchead{flex-direction:row;flex-wrap:wrap;
  align-items:center;gap:12px;min-height:0}
details.src>summary::-webkit-details-marker{display:none}
details.src>summary::before{content:'';position:absolute;left:13px;top:17px;
  width:0;height:0;border:5px solid transparent;border-left-color:var(--faint);
  transition:transform .12s}
details.src[open]>summary::before{top:50%;transform:translateY(-50%) rotate(90deg)}
details.src>summary:hover{background:var(--hover)}
details.src[open]>summary{border-bottom:1px solid var(--line-soft)}
.srcinner{padding:14px 16px 16px}
.srcstate{margin:0 0 14px;font-size:12.5px;color:var(--muted);max-width:78ch}
.srcstate b{color:var(--ink)}

.srcsub{margin-top:3px;font-size:12px;color:var(--muted)}
/* Cap the column count as well as the width. auto-fit alone kept adding columns
   on a wide screen until each one was a single ragged word, and three columns of
   prose stretched edge to edge is the opposite problem - both hurt to read. */
.srcgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));
  gap:18px;max-width:1100px}
.srcgrid p{max-width:52ch}
.srcgrid h4{margin:0 0 5px;font-size:10.5px;text-transform:uppercase;
  letter-spacing:.05em;color:var(--faint);font-weight:600}
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
.planhead p{max-width:84ch}
.plansum{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 14px;
  padding:10px 13px;background:var(--panel-2);border:1px solid var(--line);
  border-radius:9px;font-size:12.5px;color:var(--muted)}
.plansum b{color:var(--ink);font-family:ui-monospace,Menlo,monospace;margin-right:3px}
.plansum>span:not(.badge){white-space:nowrap}
.plancred{color:var(--med)}
.ptool{font-size:11.5px;color:var(--faint);margin-left:auto;padding-left:10px;
  white-space:nowrap}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:8px;overflow:hidden}
.segbtn{background:var(--panel);border:0;padding:6px 11px;font-size:12px;
  color:var(--muted);cursor:pointer}
.segbtn+.segbtn{border-left:1px solid var(--line)}
.segbtn.on{background:var(--accent);color:var(--on-accent)}
.segbtn:not(.on):hover{background:var(--hover);color:var(--ink)}
.btn.danger{color:var(--crit);border-color:var(--alert-line)}
.btn.danger:hover{background:var(--alert-bg);border-color:var(--crit)}
.btn.danger[data-armed="1"]{background:var(--crit);color:#fff;border-color:var(--crit)}
#backbar{margin:0 0 12px}
.backbtn{background:var(--panel);border:1px solid var(--line);border-radius:20px;
  padding:5px 13px;font-size:12.5px;color:var(--muted);cursor:pointer}
.backbtn:hover{border-color:var(--accent);color:var(--accent);background:var(--accent-soft)}
.clsgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:6px}
.clsrow{background:var(--panel-2);border:1px solid var(--line);border-radius:7px;
  padding:7px 9px;font-size:12px;color:var(--muted);cursor:pointer;text-align:left}
.clsrow b{color:var(--ink);font-family:ui-monospace,Menlo,monospace;margin-right:5px}
.clsrow:hover{border-color:var(--accent);background:var(--accent-soft)}
.tmeta{margin-top:7px;font-size:12px;color:var(--faint)}
.badge.vol i{font-style:normal;opacity:.6;margin-right:5px;font-size:10px}
.locrow{display:flex;gap:8px;align-items:stretch}
.locrow .locator{flex:1;min-width:0}
.copybtn{flex:none;align-self:stretch;font-size:11.5px;padding:0 11px}
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
pre.yaml.wrapped{white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere}
pre.yaml.grown{max-height:none}
.codetools{float:right;display:flex;gap:5px;text-transform:none;letter-spacing:0}
.minibtn{background:var(--panel);border:1px solid var(--line);border-radius:5px;
  padding:1px 8px;font-size:10.5px;color:var(--muted);cursor:pointer;
  text-transform:none;letter-spacing:0}
.minibtn:hover{border-color:var(--accent);color:var(--accent)}
.minibtn[aria-pressed=true]{background:var(--accent);border-color:var(--accent);
  color:var(--on-accent)}
.fplist{margin:0;padding-left:17px;font-size:12.5px;color:var(--muted)}

/* ---- mappings ---- */
.idxwrap{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:22px}
.idx h2{margin:0 0 3px;font-size:15px}
.idx .isub{margin:0 0 11px;font-size:12.5px;color:var(--muted)}
/* Four columns, not three. The expand caret was added as a new first child
   without widening the grid, so every cell shifted one place: the ID took the
   96px meant for it but the title landed in the 36px count column and wrapped
   down the right edge, and the count fell onto the next row. Column count and
   child count have to move together. */
.irow{display:grid;grid-template-columns:16px 92px minmax(0,1fr) 44px;gap:10px;
  align-items:center;
  padding:7px 9px;border-radius:8px;cursor:pointer;border:1px solid transparent}
.irow:hover{background:var(--accent-soft);border-color:var(--accent-border)}
.irow .iid{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:var(--accent)}
.irow .ittl{font-size:12.5px}
.irow .icount{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:var(--muted);
  text-align:right}
.irow .cvcaret{margin-right:0}
.irow.open .cvcaret{transform:rotate(90deg)}
.bar{grid-column:1/-1;height:4px;border-radius:3px;background:var(--line-soft);overflow:hidden}
.bar i{display:block;height:100%;background:var(--accent);border-radius:3px}

/* ---- case studies ---- */
/* --- case study grid + accordion ---
   Tiles rather than full-width bars: 14 one-line rows made the eye travel the
   whole page width for a title and left the right two thirds empty. Two or three
   columns fit the viewport, and the open one spans every column so the detail
   still gets full width to lay out its IOC and response columns in. */
.csgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));
  gap:10px}
/* Deliberately not align-items:start. Letting each tile size to its own content
   left the chip rows on different baselines across a row - a one-line "affects"
   beside a two-line one - which is what makes a grid hard to scan. Stretching to
   the row height and pushing the tally to the bottom lines them all up. */
details.csfull{padding:0;overflow:hidden;margin:0;display:flex;flex-direction:column}
details.csfull:not([open])>summary{flex:1}
details.csfull[open]{grid-column:1/-1}
details.csfull>summary.cshead{display:flex;flex-direction:column;gap:9px;
  align-items:stretch;padding:12px 14px 12px 30px;cursor:pointer;
  list-style:none;position:relative;margin:0;min-height:78px;
  justify-content:space-between}
details.csfull>summary::-webkit-details-marker{display:none}
details.csfull>summary::before{content:'';position:absolute;left:13px;top:17px;
  width:0;height:0;border:5px solid transparent;border-left-color:var(--faint);
  transition:transform .12s}
details.csfull[open]>summary::before{transform:rotate(90deg)}
details.csfull>summary:hover{background:var(--hover)}
details.csfull[open]>summary{border-bottom:1px solid var(--line-soft);
  min-height:0;flex-direction:row;flex-wrap:wrap;align-items:center;gap:12px}
details.csfull[open]>summary::before{top:50%;transform:translateY(-50%) rotate(90deg)}
.cstop{min-width:0}
/* One treatment for every card title on the site. There were four - case tile
   16px/600, source tile 15px/700, tool card 14.5px/600, rule card 14px/600 - and
   three of the four were divs rather than headings. The case tile was 16px only
   because two older .csname rules outlived the layout they were written for and
   overrode the tile rule silently. */
.cardname,.csname,.tool .tname,.rule .rname,.src h3{
  font-size:14.5px;font-weight:600;line-height:1.35;margin:0;color:var(--ink)}
/* Clamped, not truncated at a character count: three lines of the real summary
   is enough to decide whether to open a case, and a hard character cut lands
   mid-word on some and mid-sentence on all of them. */
.csbrief{margin:7px 0 0;font-size:12px;line-height:1.5;color:var(--muted);
  display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;
  overflow:hidden}
details.csfull[open] .csbrief{display:none}
.csaff{color:var(--accent);margin-top:1px}
/* One line, always the same order, so the tiles read as a column of facts
   rather than as ragged chip soup: indicators, rules, provenance, dispute. */
.cstally{display:flex;gap:5px;align-items:center;flex-wrap:wrap}
.csn{font-size:10.5px;color:var(--muted);background:var(--panel-2);
  border:1px solid var(--line);border-radius:20px;padding:1px 8px;white-space:nowrap}
.csinner{padding:14px 16px 16px}
.csinner .csjumps{margin-bottom:10px}
@media(max-width:760px){.csgrid{grid-template-columns:1fr}}
/* --- technique coverage --- */
.covwrap{border:1px solid var(--line);border-radius:11px;background:var(--panel);
  overflow:hidden;margin-bottom:18px;max-width:1120px}
/* Fixed, or the technique column takes every spare pixel and opens a third of a
   screen of nothing between a name and the numbers that belong to it. */
table.cov{width:100%;border-collapse:collapse;font-size:13px;table-layout:fixed}
table.cov col.c-num{width:64px}
table.cov col.c-exp{width:240px}
.cbhead{white-space:nowrap;font-weight:inherit}
.cbhead i{display:inline-block;width:14px;height:5px;border-radius:3px;
  margin:0 5px 0 0;vertical-align:middle}
.cbhead i.cbr{margin-left:14px}
/* The fills were scoped to .cbar and .covkey, so the legend in the header
   rendered as two invisible boxes and the column read as bare word soup. */
.cbhead i.cbt{background:var(--conf-strong)}
.cbhead i.cbr{background:var(--val-strong)}
table.cov th{text-align:left;background:var(--panel-2);color:var(--muted);
  font-size:10.5px;text-transform:uppercase;letter-spacing:.05em;
  padding:8px 12px;border-bottom:1px solid var(--line)}
table.cov td{padding:9px 12px;border-bottom:1px solid var(--line-soft);vertical-align:middle}
table.cov tr:last-child td{border-bottom:0}
table.cov .num{text-align:right;font-family:ui-monospace,Menlo,monospace}
table.cov tr.covrow td:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.covrow{cursor:pointer}
.covrow:hover{background:var(--hover)}
.covrow.open{background:var(--accent-soft)}
.cvcaret{display:inline-block;width:0;height:0;border:4px solid transparent;
  border-left-color:var(--faint);margin-right:8px;transition:transform .12s;
  vertical-align:middle}
.covrow.open .cvcaret{transform:rotate(90deg)}
.covdet td{background:var(--panel-2);padding:14px 14px 14px 34px}
.cdgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}
.cdgrid h3{margin:0 0 7px;font-size:10.5px;text-transform:uppercase;
  letter-spacing:.05em;color:var(--faint);font-weight:600}
.cdgrid .n{font-family:ui-monospace,Menlo,monospace;font-size:10px;
  background:var(--line-soft);border-radius:20px;padding:0 6px;color:var(--muted)}
.cdchip{display:block;width:100%;text-align:left;background:var(--panel);
  border:1px solid var(--line);border-radius:6px;padding:4px 8px;margin-bottom:4px;
  font-size:11.5px;color:var(--ink);cursor:pointer}
.cdchip[data-rule]{font-family:ui-monospace,Menlo,monospace;font-size:11px}
.cdchip:hover{border-color:var(--accent);background:var(--accent-soft)}
.iwrap{border-bottom:1px solid var(--line-soft)}
.iwrap:last-child{border-bottom:0}
.irow.open{background:var(--accent-soft)}
.idet{padding:10px 12px 14px 34px;background:var(--panel-2)}
.idet .cdchip{max-width:520px}
.idrill{margin-top:8px;font-size:11.5px}
.cdref{display:inline-block;margin-top:12px;font-size:11.5px;color:var(--muted);
  text-decoration:none;border-bottom:1px dotted var(--line)}
.cdref:hover{color:var(--accent)}
.covrow .iid{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--ink);
  margin-right:8px}
.covrow .ittl{color:var(--muted)}
.covrow .subs{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;
  color:var(--faint);margin-left:7px}
.thinflag{font-size:10px;text-transform:uppercase;letter-spacing:.04em;
  color:var(--med);border:1px dashed var(--med);border-radius:4px;
  padding:0 5px;margin-left:8px;opacity:.85}
.covlink{background:none;border:0;color:var(--accent);cursor:pointer;
  font-family:ui-monospace,Menlo,monospace;font-size:13px;padding:2px 4px;
  border-radius:4px;text-decoration:underline;text-underline-offset:2px}
.covlink:hover{background:var(--accent-soft)}
.cov .zero{color:var(--faint)}
.cbar{display:block;position:relative;height:14px;min-width:80px}
.cbar i{position:absolute;left:0;height:5px;border-radius:3px}
/* strong, not mid. The mid tokens are tuned for badge fills against a tinted
   background; side by side as two chart series they read as one colour in dark
   mode, where conf-mid #7e94ab and val-mid #6f9b96 are barely separable. */
.cbar .cbt{top:1px;background:var(--conf-strong)}
.cbar .cbr{top:8px;background:var(--val-strong)}
.covkey{padding:9px 12px;font-size:11.5px;color:var(--muted);
  background:var(--panel-2);border-top:1px solid var(--line);max-width:84ch}
.covkey i{display:inline-block;width:16px;height:5px;border-radius:3px;
  margin-right:5px;vertical-align:middle}
.covkey .cbt{background:var(--conf-strong)}
.covkey .cbr{background:var(--val-strong)}
.covnote{font-size:12.5px;color:var(--muted);margin-top:6px;max-width:84ch}
.gtop p{max-width:84ch}
@media(max-width:640px){table.cov .ittl{display:none}}
.cs{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:16px;
  display:flex;flex-direction:column;gap:10px}
.cs .cshead{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}

.cs .csmeta{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--muted)}
.cs p{margin:0;font-size:12.5px;color:var(--muted)}
.cs h4{margin:0;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
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
.csdet h4{margin:0 0 8px;font-size:11px;letter-spacing:.06em;text-transform:uppercase;
  color:var(--faint);display:flex;align-items:center;gap:7px}
.csdet h4 .n{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;
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
.csfoot h4{margin:0 0 8px;font-size:11px;letter-spacing:.06em;text-transform:uppercase;
  color:var(--faint);display:flex;align-items:center;gap:7px}
.csfoot h4 .n{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;
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
/* The text block grows to the full row, so with flex-wrap the button wrapped
   underneath and read as part of the prose. Pin it: text takes the slack, button
   keeps its size, both align to the top. */
.gtop>:first-child{flex:1 1 420px;min-width:0}
.gtop>.btn{flex:none;align-self:flex-start}
.gtop{display:flex;flex-wrap:wrap;gap:10px;justify-content:space-between;align-items:flex-start;
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
// What each MCP mechanism means for collection. Written out rather than left as
// a bare enum value, because 'cloud' has to read as "stop looking on this disk"
// and 'in-code' as "there is no config file to find - read the source".
const UNVERIFIED_MEANING='Single-sourced or inferred: the catalog could not '+
  'corroborate this against a second source and nobody has confirmed it on a '+
  'live host. It is not a claim that the path is wrong - it is a claim about '+
  'how well it is evidenced.';
const MECH_MEANING={
  'config-file':'A file on disk listing the servers. Collect it directly.',
  'database':"Registered through the tool's own UI or API and persisted to its database. The collection step is a query, not a file copy, and the database is usually a container volume.",
  'in-code':'Instantiated by a script. There is no config file to collect - the server list is a literal in the source, so read the source and its history.',
  'server':"This tool IS an MCP server, so it has no config of its own. The finding is the client config that names it - go and find that.",
  'cloud':'Configured tenant-side. Nothing on the endpoint answers this; the record comes from the account.',
};
// class -> the sources that make it visible, so a row can name its own
// dependencies without the catalog carrying a second copy of the mapping.
const SOURCES_FOR=(()=>{const m={};
  for(const s of SOURCES)for(const c of s.covers.classes||[])(m[c]=m[c]||[]).push(s.id);
  return m})();
// Triage first, because it is the one facet that answers "what do I collect
// before this host reboots" - the question the whole catalog is ordered around.
// It sat only in the collection plan, which a reader reaches after picking rows
// rather than before.
const GROUPS={triage:'Triage priority',cls:'Artifact class',mech:'MCP mechanism',vol:'Volatility',os:'Operating system',fv:'Forensic value',conf:'Confidence',tool:'Tool'};
const FIELD={triage:r=>[r.triage],cls:r=>[r.cls],mech:r=>[r.mechanism],vol:r=>[r.vol],os:r=>r.os,fv:r=>[r.forensic_value],conf:r=>[r.confidence],tool:r=>[r.tool]};
const OPTIONS={
  // Priority order, not alphabetical - p1 first is the point of the facet.
  triage:['p1','p2','p3'],
  cls:[...new Set(ROWS.map(r=>r.cls))].sort(),
  // How the servers are defined, which decides what collection even means:
  // copy a file, query a database, read source, or ask the tenant.
  mech:['config-file','database','in-code','server','cloud'],
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

/* ---------- navigation history ----------
   Every cross-view jump on this page - a coverage count into the catalog, a case
   into its tool's artifacts, a drawer into a data source - used to be one way.
   replaceState meant the browser Back button did nothing either, so the only
   route back was to work out which filters had been set and undo them by hand.
   A jump now pushes the state it left, restores it on popstate, and shows where
   Back goes so the affordance is not just a browser gesture people may not try. */
const VIEW_LABEL={catalog:'Catalog',tools:'Tools',rules:'Detections',
  mappings:'Mappings',sources:'Data sources',cases:'Case studies',
  plan:'Collection plan',guide:'Investigation guide'};
let navStack=[];
function snapshot(){
  return {view,query,unvOnly,
    filters:JSON.parse(JSON.stringify(filters)),
    rfilters:JSON.parse(JSON.stringify(rfilters)),
    ruleSet:ruleSet?[...ruleSet]:null,
    scroll:window.scrollY};
}
function restore(s){
  view=s.view;query=s.query;unvOnly=s.unvOnly;
  for(const k of Object.keys(filters))filters[k]=s.filters[k]||[];
  for(const k of Object.keys(rfilters))rfilters[k]=s.rfilters[k]||[];
  ruleSet=s.ruleSet?new Set(s.ruleSet):null;
  const q=$('#q');if(q)q.value=s.query||'';
  $('#unvBtn').setAttribute('aria-pressed',String(unvOnly));
  update();
  requestAnimationFrame(()=>window.scrollTo(0,s.scroll||0));
}
// Called by a jump BEFORE it mutates anything, so the stack holds where you were.
function pushNav(){
  navStack.push(snapshot());
  history.pushState({nav:navStack.length},'',location.hash||location.pathname);
}
function goBack(){
  const s=navStack.pop();
  if(s)restore(s);
}
window.addEventListener('popstate',()=>{if(navStack.length)goBack()});

let codeWrap=false, codeGrow=false, planMode='tool';
let view='catalog', query='', unvOnly=false, dense=false,
    // Was entry_id, which sorted first paint by the one field a responder never
    // needs. triage_priority is on every row since F09, so the table can open in
    // collection order instead.
    sortKey='triage', sortDir=1, sel=null, selRule=null, lastFocus=null;
const filters={triage:[],cls:[],mech:[],vol:[],os:[],fv:[],conf:[],tool:[]};
const rfilters={fmt:[],rcat:[],ratlas:[],rowasp:[]};
// 'aiart-' was the AIRTIFACTS working name, dropped when the catalog folded
// into this repo. Read the old key once so anyone who saved picks under it
// keeps them, then write only the current key from here on.
const PICKS_KEY='aidfir-picks', PICKS_KEY_OLD='aiart-picks';
// A plan is now a named thing rather than one anonymous array. An incident runs
// across several hosts and the plan for each is a different list; with a single
// slot the second host silently overwrote the first, and nothing on screen said
// which host a list belonged to once it was more than a day old.
//
// Plan = {id, name, host, created, updated, anchors:[]}
// PLANS_KEY holds {[id]: Plan}. picks stays exactly what it was - the active
// plan's anchors as a Set - so every call site that reads or mutates it is
// untouched, and only what happens underneath savePicks changed.
const PLANS_KEY='aidfir-plans', ACTIVE_KEY='aidfir-plan-active';
const nowISO=()=>new Date().toISOString();
const newPlanId=()=>'p'+Date.now().toString(36)+Math.random().toString(36).slice(2,6);
// Anchors are stable across builds, row indexes are not - but an artifact can
// still be removed from the catalog, so drop anchors that no longer resolve.
const liveAnchors=v=>Array.isArray(v)?v.filter(a=>ROWMAP[a]):[];

let plans=(()=>{
  try{
    const v=JSON.parse(localStorage.getItem(PLANS_KEY)||'null');
    if(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length)return v;
  }catch(e){}
  // One-time migration. The old key is read and kept, not deleted: if this
  // build is ever rolled back, the picks a responder made are still where the
  // previous build looks for them.
  const raw=localStorage.getItem(PICKS_KEY)??localStorage.getItem(PICKS_KEY_OLD);
  let anchors=[];
  try{anchors=liveAnchors(JSON.parse(raw||'[]'))}catch(e){}
  const id=newPlanId(), t=nowISO();
  return {[id]:{id,name:anchors.length?'Imported picks':'Untitled plan',
                host:'',created:t,updated:t,anchors}};
})();
let activeId=(()=>{
  const saved=localStorage.getItem(ACTIVE_KEY);
  if(saved&&plans[saved])return saved;
  return Object.keys(plans)[0];
})();
const activePlan=()=>plans[activeId];
function savePlans(){
  try{
    localStorage.setItem(PLANS_KEY,JSON.stringify(plans));
    localStorage.setItem(ACTIVE_KEY,activeId);
  }catch(e){}
}
const picks=new Set(liveAnchors((activePlan()||{}).anchors));
// Persist immediately. Everything else that writes is triggered by the reader
// doing something, so a freshly migrated plan existed only in memory until the
// first pick - and a reader who migrated, read, and closed the tab got a new
// plan id on every visit, with the name they had set on the previous one.
savePlans();
function savePicks(){
  const p=activePlan(); if(!p)return;
  p.anchors=[...picks]; p.updated=nowISO();
  savePlans();
  // Keep the legacy key in step so a rollback does not lose today's work.
  try{localStorage.setItem(PICKS_KEY,JSON.stringify([...picks]))}catch(e){}
}
function switchPlan(id){
  if(!plans[id]||id===activeId)return;
  activeId=id;
  picks.clear();
  liveAnchors(activePlan().anchors).forEach(a=>picks.add(a));
  savePlans(); update();
}
function createPlan(name){
  const id=newPlanId(), t=nowISO();
  plans[id]={id,name:name||'Untitled plan',host:'',created:t,updated:t,anchors:[]};
  activeId=id; picks.clear(); savePlans(); update();
}
// Clearing used to be unrecoverable from the toast - one click, no arming, no
// undo, and the plan was gone. The anchors are held here instead so the same
// click can be taken back.
let lastCleared=null;
function clearPicks(){
  if(!picks.size)return;
  lastCleared={id:activeId,anchors:[...picks]};
  picks.clear(); savePicks(); update();
}
function undoClear(){
  if(!lastCleared)return;
  if(plans[lastCleared.id])activeId=lastCleared.id;
  picks.clear();
  liveAnchors(lastCleared.anchors).forEach(a=>picks.add(a));
  lastCleared=null; savePicks(); update();
}

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
// Collection order, not ID order. Ties on the sort key fall through to
// volatility and then to entry id, so the default view reads triage first and
// then what stops existing soonest - which is the order the catalog is for.
// Without the tiebreak, sorting by triage left 513 p1 rows in whatever order
// they happened to be flattened in.
const volRank=r=>{const i=VOL_TIERS.indexOf(r.vol);return i<0?VOL_TIERS.length:i};
function cmpKey(k,a,b){
  const x=a[k],y=b[k];
  if(RANK[x]!==undefined&&RANK[y]!==undefined&&RANK[x]!==RANK[y])return RANK[x]-RANK[y];
  return String(x??'').localeCompare(String(y??''),undefined,{numeric:true});
}
function filteredRows(){
  const out=ROWS.filter(r=>rowMatches(r,null));
  out.sort((a,b)=>{
    const primary=cmpKey(sortKey,a,b)*sortDir;
    if(primary)return primary;
    return (volRank(a)-volRank(b))||cmpKey('entry_id',a,b);
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
  const KEYCOL={pick:'k-pick',entry_id:'k-id',tool:'k-tool',cls:'k-cls',
    artifact:'k-art',os:'k-os',forensic_value:'k-fv',confidence:'k-conf'};
  return `<div class="tablescroll"><table><colgroup>`
    +COLS.map(([,k])=>`<col class="${KEYCOL[k]||''}">`).join('')
    +`</colgroup><thead><tr>`+COLS.map(([l,k])=>{
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
      <td class="artcell"><span class="path">${esc(r.artifact)}</span>${r.unverified?` <span class="unv" title="${esc(UNVERIFIED_MEANING)}">unverified</span>`:''}</td>
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
      <div class="meta">${esc(r.entry_id)}${r.os.length?' &middot; '+esc(r.os.join(', ')):''}${r.unverified?` &middot; <span class="unv" title="${esc(UNVERIFIED_MEANING)}">unverified</span>`:''}</div>
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
      <div class="trow"><div><h3 class="tname">${esc(t.tool)}</h3>
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
  return `<div class="gtop"><div class="srcintro">
    <p>Ordered by how fast the evidence disappears, not by how useful it is. A
    source further down this page is not less important - it is just still going
    to be there tomorrow.</p>
    <div class="vollegend">${VOL_TIERS.map(v=>
      `<div><span class="badge vol v-${v}"><i>volatility</i>${v}</span>
       <span>${esc(VOL_MEANING[v])}</span></div>`).join('')}</div>
  </div>
  <button class="btn" id="srcAll" data-open="0">Expand all</button>
  </div>
  <div class="srcgridwrap">`+list.map(s=>`
    <details class="src" id="src-${esc(s.id)}">
      <summary class="srchead">
        <div><h3>${esc(s.name)}</h3>
          <div class="srcsub">${esc(s.kind)}${s.n_rows?` &middot; ${s.n_rows} rows`:''}${
            s.n_eventlog_rows?` &middot; ${s.n_eventlog_rows} event log rows`:''}${
            s.n_rules?` &middot; ${s.n_rules} rule${s.n_rules>1?'s':''}`:''}</div></div>
        <div class="badgerow"><span class="badge vol v-${esc(s.volatility)}"
          ><i>volatility</i>${esc(s.volatility)}</span>${confBadge(s.confidence)}</div>
      </summary>
      <div class="srcinner">
      <p class="srcstate"><b>By default.</b> ${esc(s.default_state)}</p>
      <div class="srcgrid">
        <div><h4>Turn it on</h4><p>${esc(s.enable)}</p></div>
        <div><h4>Keep it</h4><p>${esc(s.retention)}</p></div>
        <div class="srcloss"><h4>Without it you cannot answer</h4><p>${esc(s.without_it)}</p></div>
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
      </div>
    </details>`).join('')+'</div>';
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
  const rows=[...picks].map(a=>ROWMAP[a]).filter(Boolean);
  const vol={};
  for(const r of rows)vol[r.vol]=(vol[r.vol]||0)+1;
  const tools=new Set(rows.map(r=>r.entry_id)).size;
  const creds=rows.filter(r=>r.cls==='credential').length;
  const p=activePlan()||{name:'Untitled plan',host:'',updated:''};
  const others=Object.values(plans).sort((a,b)=>(b.updated||'').localeCompare(a.updated||''));
  // Name and host are inputs rather than a dialog: the plan is identified while
  // it is being built, not in a step someone skips. Both save on input, so there
  // is no state where a typed name is not yet the plan's name.
  const idbar=`<div class="planid">
    <input id="pName" value="${esc(p.name||'')}" placeholder="Plan name"
      aria-label="Plan name" maxlength="80">
    <input id="pHost" value="${esc(p.host||'')}" placeholder="Host"
      aria-label="Host this plan is for" maxlength="80">
    ${others.length>1?`<select id="pSwitch" aria-label="Switch plan">${others.map(o=>
      `<option value="${esc(o.id)}"${o.id===activeId?' selected':''}>${esc(o.name||'Untitled plan')}${
        o.host?' - '+esc(o.host):''} (${(o.anchors||[]).length})</option>`).join('')}</select>`:''}
    <button class="btn" id="pNew">New plan</button>
    ${p.updated?`<span class="pmeta">saved ${esc(p.updated.slice(0,16).replace('T',' '))}</span>`:''}
  </div>`;
  const head=`<div class="planhead"><div>${idbar}<h2>Collection plan</h2>
    <p>${planMode==='vol'
      ?'Grouped by how fast each artifact disappears, across every tool. This is the order to work in: everything in <b>live</b> is gone at the next reboot.'
      :'Grouped by tool, tools ordered by triage priority and rows within each tool by how fast they disappear.'}</p></div>
    <div class="acts">
      <div class="seg"><button class="segbtn${planMode==='tool'?' on':''}" data-mode="tool"
        >by tool</button><button class="segbtn${planMode==='vol'?' on':''}" data-mode="vol"
        >by volatility</button></div>
      <button class="btn" id="cpLinks">Copy permalinks</button>
      <button class="btn primary" id="cpList">Copy as triage list</button>
      <button class="btn danger" id="cpClear">Clear all</button></div></div>`;
  if(!rows.length)return head+`<div class="plan-empty">Nothing picked yet.
    Tick artifacts in the catalog to build a collection plan.</div>`;
  // A standing summary of what is in the plan, because the thing a responder
  // needs to know before starting is how much of it will not wait.
  const summary=`<div class="plansum">
    <span><b>${rows.length}</b> artifact${rows.length>1?'s':''}</span>
    <span><b>${tools}</b> tool${tools>1?'s':''}</span>
    ${VOL_TIERS.filter(v=>vol[v]).map(v=>
      `<span class="badge vol v-${v}"><i>${vol[v]}</i>${v}</span>`).join('')}
    ${creds?`<span class="plancred">${creds} credential location${creds>1?'s':''} -
      collect, then treat every value as exposed</span>`:''}</div>`;
  const body=planMode==='vol'
    ? planByVolatility().map(g=>`
      <div class="pgroup"><div class="ghead"><span class="badge vol v-${g.vol}"
        ><i>volatility</i>${g.vol}</span>
        <span class="n">${g.rows.length} path${g.rows.length>1?'s':''}</span></div>
      ${g.rows.map(r=>`<div class="prow">
        <button class="rm" data-a="${esc(r.anchor)}" aria-label="Remove">&#10005;</button>
        <span class="path">${esc(r.artifact)}</span>
        <span class="ptool">${esc(r.tool)}</span>${fvBadge(r.forensic_value)}</div>`).join('')}
      <div class="gfoot">${esc(VOL_MEANING[g.vol])}</div></div>`).join('')
    : planGroups().map(g=>`
      <div class="pgroup"><div class="ghead">${triageBadge(g.t.triage)}<b>${esc(g.t.tool)}</b>
        <span class="n">${g.rows.length} path${g.rows.length>1?'s':''}</span></div>
      ${g.rows.map(r=>`<div class="prow">
        <button class="rm" data-a="${esc(r.anchor)}" aria-label="Remove">&#10005;</button>
        <span class="path">${esc(r.artifact)}</span>
        <span class="badge vol v-${esc(r.vol)}"><i>vol</i>${esc(r.vol)}</span>
        ${fvBadge(r.forensic_value)}</div>`).join('')}
      ${g.t.guidance?`<div class="gfoot">${esc(g.t.guidance)}</div>`:''}</div>`).join('');
  return head+summary+body;
}
// Grouped by volatility rather than by tool. This is the ordering a responder
// actually works in: everything that dies at reboot, across every tool, before
// anything that survives it. Grouping by tool put a config file that will still
// be there next week ahead of a socket table that will not.
function planByVolatility(){
  const by={live:[],rotating:[],stable:[]};
  for(const a of picks){const r=ROWMAP[a];if(r)by[r.vol||'stable'].push(r)}
  for(const k of Object.keys(by))
    by[k].sort((a,b)=>(RANK[a.forensic_value]??9)-(RANK[b.forensic_value]??9)
      ||a.tool.localeCompare(b.tool));
  return VOL_TIERS.map(v=>({vol:v,rows:by[v]})).filter(g=>g.rows.length);
}
function planText(){
  if(planMode==='vol')return planByVolatility().map(g=>
    `# ${g.vol.toUpperCase()} - ${VOL_MEANING[g.vol]}\n`+
    g.rows.map(r=>`${r.artifact}    # ${r.tool}`).join('\n')
  ).join('\n\n');
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
    <div class="dsec"><h4>Locator</h4>
      <div class="locrow"><div class="locator">${esc(r.artifact)}</div>
        <button class="btn copybtn" id="dCopyLoc" data-v="${esc(r.artifact)}"
          aria-label="Copy locator">copy</button></div>
      <div class="badgerow">${fvBadge(r.forensic_value)}
      ${confBadge(r.confidence)}
      ${r.unverified?'<span class="badge dashed b-crit">unverified</span>':''}</div>
      ${r.unverified?`<p class="unvwhy">${esc(UNVERIFIED_MEANING)}</p>`:''}</div>
    <div class="dsec"><h4>What it proves</h4>
      ${r.evidence.length?`<div class="evrow">${r.evidence.map(e=>`<span class="ev">${esc(e)}</span>`).join('')}</div>`:''}
      ${r.description?`<p>${esc(r.description)}</p>`:''}
      ${r.requires?`<div class="requires"><b>Requires.</b> ${esc(r.requires)}</div>`:''}
      ${r.mechanism?`<div class="requires"><b>How it is defined.</b> ${
        esc(MECH_MEANING[r.mechanism]||r.mechanism)}</div>`:''}</div>
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
  $('#dCopyLoc').onclick=e=>copy(e.target.dataset.v,e.target);
  $('#dPick').onclick=()=>{togglePick(anchor);openDrawer(anchor,lastFocus)};
  $$('#drawer .caselink').forEach(b=>b.onclick=()=>{
    pushNav();closeDrawer();view='cases';update();
    // Cases are collapsed by default now, so a jump has to open its target -
    // otherwise the link scrolls to a closed summary and looks broken.
    const el=document.getElementById('cs-'+b.dataset.cs);
    if(el){el.open=true;el.scrollIntoView({block:'start'})}
  });
  $$('#drawer .srcjump').forEach(b=>b.onclick=()=>{
    pushNav();closeDrawer();view='sources';update();
    const el=document.getElementById('src-'+b.dataset.src);
    if(el){el.open=true;el.scrollIntoView({block:'start'})}
  });
  wireTechChips();
  renderMain();
}
function closeDrawer(){
  // Remember what to return focus to before re-rendering detaches it: the row
  // element itself does not survive renderMain(), so restore by anchor.
  const back=lastFocus&&lastFocus.dataset?(lastFocus.dataset.a||lastFocus.dataset.f):null;
  sel=null; selRule=null; $('#drawer').hidden=true;
  // Only clear the drawer's own anchor. This used to replaceState
  // unconditionally, which overwrote the entry pushNav had just pushed when a
  // drill started from inside a drawer - so the jump happened and Back had
  // nothing to go to.
  if(!navStack.length)history.replaceState(null,'',location.pathname+location.search);
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
      <div class="rtop"><div><h3 class="rname">${esc(r.title)}</h3>
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
    <div class="dsec"><h4>Rule file</h4>
      <div class="locrow"><div class="locator">${esc(r.path)}</div>
        <button class="btn copybtn" id="dCopyLoc" data-v="${esc(r.path)}"
          aria-label="Copy rule path">copy</button></div>
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
    <div class="dsec"><h4>Detection logic
      <span class="codetools"><button class="minibtn" id="wrapBtn" aria-pressed="false"
        >wrap</button><button class="minibtn" id="growBtn" aria-pressed="false"
        >expand</button></span></h4>
      <pre class="yaml" id="ruleBody">${esc(r.body)}</pre></div>
    <div class="dsec"><h4>Permalink</h4><div class="linkrow">
      <input readonly value="#rule/${esc(r.path)}" aria-label="Permalink">
      <button class="btn" id="dCopyLink" data-v="${esc(base+'#rule/'+r.path)}">copy link</button></div></div>
  </div>
  <div class="dfoot">
    <a class="btn primary" href="${REPO_URL}/blob/main/${esc(r.path)}" target="_blank" rel="noopener">View on GitHub</a>
  </div>`;
}
/* ---------- tool drawer ----------
   The tools grid answered "which tools are catalogued" and nothing else: a click
   filtered the catalog and the card's own question - what is this thing, what
   does it leave, how exposed is it - stayed unanswered. This assembles that from
   data the page already holds, and keeps the drill-down as an explicit action. */
function toolDrawerHTML(t){
  const rows=ROWS.filter(r=>r.entry_id===t.entry_id);
  const byCls={};
  for(const r of rows)byCls[r.cls]=(byCls[r.cls]||0)+1;
  const vol={};
  for(const r of rows)vol[r.vol]=(vol[r.vol]||0)+1;
  // Volatile, not "p1". triage_priority lives on the tool, not on the row, so
  // there is no p1 subset of these rows to offer - and volatility is the field
  // that actually answers "what do I lose if I reboot first", which is what the
  // Order of collection section above already ranks them by.
  const volatile=rows.filter(r=>r.vol&&r.vol!=='stable').length;
  const mech=[...new Set(rows.filter(r=>r.mechanism).map(r=>r.mechanism))];
  const unv=rows.filter(r=>r.unverified).length;
  const cs=CASES_BY_TOOL[t.entry_id]||[];
  return `<div class="dhead"><b>${esc(t.tool)} <span class="mono"
      style="color:var(--faint);font-size:11px">${esc(t.entry_id)}</span></b>
    <button class="x" id="dClose" aria-label="Close">&#10005;</button></div>
  <div class="dbody">
    <div class="dsec">
      <div class="badgerow">${riskBadge(t.risk,'risk')}${triageBadge(t.triage)}
        ${confBadge(t.confidence)}
        ${t.status&&t.status!=='active'?`<span class="statuspill">${esc(t.status)}</span>`:''}</div>
      <div class="tverify" style="margin-top:8px">${t.verified?`last verified ${esc(t.verified)}`
        :'never verified against a host or a current release'}</div>
      ${t.aliases&&t.aliases.length?`<p class="talias">also ${esc(t.aliases.join(' · '))}</p>`:''}
      <p>${esc(t.description||'')}</p>
      <div class="tmeta">${esc(t.vendor||'')} &middot; ${esc(t.category||'')} &middot; ${
        esc((t.os||[]).join(', '))}</div>
      ${t.caps.length?`<div class="capchips">${t.caps.map(c=>`<i>${esc(c)}</i>`).join('')}</div>`:''}
    </div>
    <div class="dsec"><h4>What it leaves <span class="n">${rows.length}</span></h4>
      <div class="clsgrid">${Object.entries(byCls).sort((a,b)=>b[1]-a[1]).map(([c,n])=>
        `<button class="clsrow" data-cls="${esc(c)}"><b>${n}</b> ${esc(c)}</button>`).join('')}</div>
      ${unv?`<p class="muted" style="margin:9px 0 0;font-size:12px">${unv} of these
        ${unv===1?'is':'are'} flagged unverified.</p>`:''}
      ${mech.length?`<p class="muted" style="margin:7px 0 0;font-size:12px">MCP is
        defined by ${esc(mech.join(', '))}.</p>`:''}
    </div>
    <div class="dsec"><h4>Order of collection</h4>
      <div class="badgerow">${['live','rotating','stable'].filter(v=>vol[v]).map(v=>
        `<span class="badge vol v-${v}"><i>${vol[v]}</i>${v}</span>`).join('')}</div>
      ${t.guidance?`<p style="margin-top:9px">${esc(t.guidance)}</p>`:''}</div>
    ${t.abuse?`<div class="dsec"><h4>Abuse potential</h4>
      <div class="alert">${esc(t.abuse)}</div></div>`:''}
    ${cs.length?`<div class="dsec"><h4>Documented incidents <span class="n">${cs.length}</span></h4>
      ${cs.map(c=>`<button class="caselink" data-cs="${esc(c.id)}">${esc(c.title)}</button>`).join('')}</div>`:''}
    ${(t.techniques||[]).length?`<div class="dsec"><h4>Mapped techniques</h4>
      <div class="tech">${t.techniques.map(x=>`<span class="tchip">${esc(x)}</span>`).join('')}</div></div>`:''}
    ${(t.refs||[]).length?`<div class="dsec"><h4>Sources <span class="n">${t.refs.length}</span></h4>
      <ul class="drefs">${t.refs.map(r=>`<li><a href="${esc(r.url)}" target="_blank"
        rel="noopener">${esc(r.title||r.url)}</a></li>`).join('')}</ul></div>`:''}
  </div>
  <div class="dfoot">
    ${volatile?`<button class="btn" id="dPickVol"
      title="Add the ${volatile} row${volatile===1?'':'s'} that do not survive a reboot or an agent restart"
      >Add volatile (${volatile})</button>`:''}
    <button class="btn" id="dPickAll">Add all ${rows.length}</button>
    <button class="btn primary" id="dAllRows">Show all ${rows.length} artifacts &#8594;</button>
  </div>`;
}
function openToolDrawer(id,fromEl){
  const t=TOOLMAP[id]; if(!t)return;
  lastFocus=fromEl||document.activeElement;
  const d=$('#drawer');
  d.innerHTML=toolDrawerHTML(t);
  d.hidden=false;
  d.setAttribute('aria-label',t.tool+' overview');
  $('#dClose').onclick=closeDrawer;
  $('#dClose').focus();
  const drill=cls=>{pushNav();closeDrawer();resetFilters();
    filters.tool=[t.tool];if(cls)filters.cls=[cls];
    view='catalog';update()};
  $('#dAllRows').onclick=()=>drill(null);
  // Tools -> a populated plan without going through the table. Reuses picks and
  // savePicks rather than introducing a second path into the plan, so anything
  // added here behaves exactly like a row ticked by hand. Add-only on purpose:
  // a button that silently un-picked on a second press would lose work, and the
  // plan already has per-row removal.
  const addRows=(pred,btn)=>{
    const target=ROWS.filter(r=>r.entry_id===t.entry_id).filter(pred);
    const added=target.filter(r=>!picks.has(r.anchor)).length;
    target.forEach(r=>picks.add(r.anchor));
    savePicks();update();
    btn.disabled=true;
    btn.textContent=added?`Added ${added}`:'Already in plan';
  };
  const bVol=$('#dPickVol');
  if(bVol)bVol.onclick=()=>addRows(r=>r.vol&&r.vol!=='stable',bVol);
  $('#dPickAll').onclick=()=>addRows(()=>true,$('#dPickAll'));
  $$('#drawer .clsrow').forEach(b=>b.onclick=()=>drill(b.dataset.cls));
  $$('#drawer .caselink').forEach(b=>b.onclick=()=>{
    pushNav();closeDrawer();view='cases';update();
    const el=document.getElementById('cs-'+b.dataset.cs);
    if(el){el.open=true;el.scrollIntoView({block:'start'})}
  });
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
  $('#dCopyLoc').onclick=e=>copy(e.target.dataset.v,e.target);
  // Rule bodies are long lines in a short box. Wrap trades horizontal scrolling
  // for height; expand drops the height cap. They are separate because a long
  // condition wants wrapping and a long rule wants room, and they are rarely the
  // same rule. Both preferences persist for the session.
  const body=$('#ruleBody');
  const sync=()=>{
    body.classList.toggle('wrapped',codeWrap);
    body.classList.toggle('grown',codeGrow);
    $('#wrapBtn').setAttribute('aria-pressed',String(codeWrap));
    $('#growBtn').setAttribute('aria-pressed',String(codeGrow));
    $('#growBtn').textContent=codeGrow?'collapse':'expand';
  };
  $('#wrapBtn').onclick=()=>{codeWrap=!codeWrap;sync()};
  $('#growBtn').onclick=()=>{codeGrow=!codeGrow;sync()};
  sync();
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
  // Which rules, not just how many. The count alone made every row a link to a
  // filtered list you had to leave the page to read.
  const rulesFor=id=>RULES.filter(r=>(r.owasp||[]).some(o=>o===id)).map(r=>r.file);
  return `<div class="idx"><h2>${esc(title)}</h2><p class="isub">${esc(sub)}</p>`+
    items.map(i=>{const files=rulesFor(i.id);return `<div class="iwrap">
      <div class="irow" data-idx="${key}" data-v="${esc(i.id)}" data-x="${esc(i.id)}"
        role="button" tabindex="0" aria-expanded="false">
      <span class="cvcaret"></span>
      <span class="iid">${esc(i.raw)}</span><span class="ittl">${esc(i.title)}</span>
      <span class="icount">${i.count}</span>
      <span class="bar"><i style="width:${Math.round(i.count/max*100)}%"></i></span>
      </div>
      <div class="idet" data-for="${esc(i.id)}" hidden>
        ${files.length?files.map(f=>`<button class="cdchip" data-rule="${esc(f)}"
          >${esc(f)}</button>`).join(''):'<p class="muted">No rule maps to this category.</p>'}
        <button class="btn idrill" data-idx="${key}" data-v="${esc(i.id)}"
          >Filter detections to this category &#8594;</button>
      </div></div>`}).join('')+'</div>';
}
// Coverage across all three corpora, not just the rules.
//
// The old view counted rules per technique and stopped there, which answered
// "what do we detect" and never "what do we say is out there". The catalog maps
// 29 tools to AML.T0053 and carries 4 rules for it; that ratio is the useful
// number and it was not on the page at all.
//
// Sub-techniques are rolled into their parent because the two corpora map at
// different depths: rules cite AML.T0051.000, entries cite AML.T0051. Counting
// them as separate rows split the evidence and understated both sides.
const PARENT=id=>String(id||'').split('.').slice(0,2).join('.');

function coverageRows(){
  const by={};
  const touch=id=>{const p=PARENT(id);
    return by[p]=by[p]||{id:p,title:'',subs:new Set(),rules:0,tools:0,cases:0,
      toolNames:[],ruleNames:[],caseNames:[]}};
  for(const i of ATLAS_INDEX){const r=touch(i.id);
    r.rules+=i.count; if(!r.title)r.title=i.title;
    if(PARENT(i.id)!==i.id)r.subs.add(i.id);
  }
  // The index carries counts; the rule corpus carries which rules they were.
  for(const rule of RULES)for(const a of rule.atlas||[]){
    const r=touch(a); if(!r.ruleNames.includes(rule.file))r.ruleNames.push(rule.file);
  }
  for(const t of TOOLS)for(const a of t.atlas||[]){
    const r=touch(a); r.tools++; r.toolNames.push(t.tool);
    if(PARENT(a)!==a)r.subs.add(a);
  }
  for(const c of CASES)for(const a of c.atlas||[]){
    const r=touch(a); r.cases++; r.caseNames.push(c);
    if(PARENT(a)!==a)r.subs.add(a);
  }
  // Exposure first: the techniques this catalog says the most tools exhibit are
  // the ones a reader should weigh their rule count against.
  return Object.values(by).sort((a,b)=>b.tools-a.tools||b.rules-a.rules
    ||a.id.localeCompare(b.id));
}

function coverageHTML(){
  const rows=coverageRows();
  const maxT=Math.max(1,...rows.map(r=>r.tools));
  const maxR=Math.max(1,...rows.map(r=>r.rules));
  // "Thin" is a ratio, not a threshold on either number alone: many tools and
  // few rules. Flagged rather than scored, because the right rule count for a
  // technique is a judgement and the page should not pretend otherwise.
  const thin=r=>r.tools>=5&&r.rules<=r.tools/3;
  return `<div class="gtop"><div><h2>Technique coverage</h2>
    <p>Every MITRE ATLAS technique this project touches, and how much of each
    corpus sits behind it: detection rules, catalogued tools that exhibit it, and
    documented incidents that used it. Sub-techniques are counted against their
    parent, because rules cite them and catalog entries cite the parent.</p>
    <p class="covnote">A technique with many tools and few rules is not
    necessarily under-covered - one good rule can cover a whole class. It is
    where to look first.</p></div></div>
    <div class="covwrap">
      <table class="cov">
      <colgroup><col><col class="c-num"><col class="c-num"><col class="c-num"
        ><col class="c-exp"></colgroup>
      <thead><tr>
        <th>Technique</th><th class="num">Rules</th><th class="num">Tools</th>
        <th class="num">Cases</th>
        <th class="cbhead"><i class="cbt"></i>tools <i class="cbr"></i>rules</th>
        </tr></thead><tbody>
        ${rows.map(r=>`<tr class="covrow${thin(r)?' thin':''}" data-t="${esc(r.id)}"
            role="button" tabindex="0" aria-expanded="false">
          <td><span class="cvcaret"></span><span class="iid">${esc(r.id)}</span>
            <span class="ittl">${esc(r.title||'')}</span>
            ${r.subs.size?`<span class="subs">${[...r.subs].sort().map(x=>
              esc(x.split('.').slice(2).join('.'))).map(x=>'.'+x).join(' ')}</span>`:''}
            ${thin(r)?'<span class="thinflag">thin</span>':''}</td>
          <td class="num">${r.rules?`<button class="covlink" data-atlas="${esc(r.id)}"
            >${r.rules}</button>`:'<span class="zero">0</span>'}</td>
          <td class="num">${r.tools?`<button class="covlink" data-tooltech="${esc(r.id)}"
            title="${esc(r.toolNames.join(', '))}${r.tools>3?' and more':''}"
            >${r.tools}</button>`:'<span class="zero">0</span>'}</td>
          <td class="num">${r.cases?`<button class="covlink" data-casetech="${esc(r.id)}"
            >${r.cases}</button>`:'<span class="zero">0</span>'}</td>
          <td><span class="cbar"
            ><i class="cbt" style="width:${Math.round(r.tools/maxT*100)}%"
              title="${r.tools} tool${r.tools===1?'':'s'} exhibit this, the most for any technique being ${maxT}"></i>
            <i class="cbr" style="width:${Math.round(r.rules/maxR*100)}%"
              title="${r.rules} rule${r.rules===1?'':'s'} cover this, the most for any technique being ${maxR}"></i></span></td>
        </tr>
        <tr class="covdet" data-for="${esc(r.id)}" hidden><td colspan="5">
          <div class="cdgrid">
            <div><h3>Rules <span class="n">${r.ruleNames.length}</span></h3>
              ${r.ruleNames.length?r.ruleNames.map(f=>
                `<button class="cdchip" data-rule="${esc(f)}">${esc(f)}</button>`).join('')
                :'<p class="muted">None in this repo.</p>'}</div>
            <div><h3>Tools <span class="n">${r.toolNames.length}</span></h3>
              ${r.toolNames.length?r.toolNames.map(t=>
                `<button class="cdchip" data-tool="${esc(t)}">${esc(t)}</button>`).join('')
                :'<p class="muted">No catalogued tool maps to this.</p>'}</div>
            <div><h3>Incidents <span class="n">${r.caseNames.length}</span></h3>
              ${r.caseNames.length?r.caseNames.map(c=>
                `<button class="cdchip" data-case="${esc(c.id)}">${esc(c.title)}</button>`).join('')
                :'<p class="muted">None documented here.</p>'}</div>
          </div>
          <a class="cdref" href="https://atlas.mitre.org/techniques/${esc(r.id)}"
            target="_blank" rel="noopener">${esc(r.id)} on MITRE ATLAS &#8599;</a>
        </td></tr>`).join('')}
      </tbody></table>
      <div class="covkey">Each bar is scaled against the largest value in its own
        column, so the two are compared with each other rather than to a shared
        scale - a technique with many tools and a short rules bar is the shape to
        look at.</div>
    </div>`;
}

function mappingsHTML(){
  return coverageHTML()+`<div class="idxwrap">
      ${indexHTML('OWASP Top 10 for LLM Applications 2026',
        'Application-layer risk categories, remapped to the 2026 list published 4 August 2026. '+
        'Rule counts only - the catalog maps tools to ATLAS, not to OWASP. Eight of the ten IDs '+
        'changed meaning between the 2025 and 2026 editions, so an ID quoted from an older report '+
        'may name a different category here than it did there.',
        OWASP_INDEX,'rowasp')}
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
    <p class="csconf">Provenance: ${esc(tally)}</p></div>
    <button class="btn" id="csAll" data-open="0">Expand all</button></div>
    <div class="csgrid">`+
  CASES.map(c=>{
    const groups=iocGroups(c.iocs||[]);
    const n=(c.iocs||[]).length;
    // The affected tool is a link when the catalog knows it, because the useful
    // next move is always "show me every artifact this tool leaves". A case can
    // name more than one, and plenty name none the catalog covers.
    const known=(c.affects_ids||[]).map(id=>TOOLS.find(t=>t.entry_id===id)).filter(Boolean);
    const refs=c.references||[];
    // A details element rather than 14 full articles stacked on one page. The
    // summary has to carry enough to decide whether to open it - tool, dates,
    // indicator count, provenance - because a row of bare titles just moves the
    // reading cost rather than removing it.
    return `
    <details class="csfull" id="cs-${esc(c.id)}">
      <summary class="cshead">
        <div class="cstop"><h3 class="csname">${esc(c.title)}</h3>
          <div class="csmeta">${esc(c.id)}${c.date_range?' · '+esc(c.date_range):''}${
            c.disclosed?' · disclosed '+esc(c.disclosed):''}</div>
          <div class="csmeta csaff">${known.length?esc(known.map(k=>k.tool).join(', ')):
            c.affects?esc(c.affects):''}</div>
          <p class="csbrief">${esc(c.summary)}</p></div>
        <div class="cstally">
          ${n?`<span class="csn" title="published indicators">${n} IOC${n>1?'s':''}</span>`:''}
          ${(c.detections||[]).length?`<span class="csn" title="detection rules in this repo"
            >${c.detections.length} rule${c.detections.length>1?'s':''}</span>`:''}
          ${c.confidence?confBadge(c.confidence):''}
          ${c.contested?'<span class="badge dashed b-crit">disputed</span>':''}
        </div>
      </summary>
      <div class="csinner">
      <div class="csjumps">
        ${known.length?known.map(k=>`<button class="btn csjump" data-t="${esc(k.tool)}"
          data-id="${esc(k.entry_id)}">${esc(k.tool)} artifacts &#8594;</button>`).join('')
        :''}
      </div>
      <p class="cssum">${esc(c.summary)}</p>
      ${c.confidence?`<div class="csprov">
        ${confBadge(c.confidence)}
        ${c.basis?`<span class="csbasis">${esc(c.basis)}</span>`:''}
      </div>`:''}
      ${c.contested?`<div class="csdispute"><b>Disputed.</b> ${esc(c.contested)}</div>`:''}
      <div class="csbody">
        <div class="cscol">
          <h4>Indicators <span class="n">${n}</span></h4>
          ${n?groups.map(g=>`<div class="iocgrp">
            <div class="iockind">${esc(g.kind)}</div>
            <div class="iocs">${g.items.map(i=>
              `<span class="ioc" title="${esc(i.description||'')}">${esc(i.value)}${
                i.description?`<em>${esc(i.description)}</em>`:''}</span>`).join('')}</div>
          </div>`).join(''):`<p class="muted">None published.</p>`}
        </div>
        <div class="cscol">
          <h4>Response</h4>
          ${(c.response_actions||[]).length?`<ol class="csact">${c.response_actions.map(a=>
            `<li>${esc(a)}</li>`).join('')}</ol>`:`<p class="muted">None recorded.</p>`}
        </div>
      </div>
      ${c.lesson?`<div class="lesson"><b>Lesson.</b> ${esc(c.lesson)}</div>`:''}
      ${(c.detections||[]).length?`<div class="csdet">
        <h4>Detections in this repo <span class="n">${c.detections.length}</span></h4>
        <div class="detrow">${c.detections.map(d=>
          `<button class="detchip" data-rule="${esc(d)}">${esc(d)}</button>`).join('')}</div>
      </div>`:''}
      ${(c.atlas||[]).length||refs.length?`<div class="csfoot">
        ${(c.atlas||[]).length?`<div class="csatlas"><h4>ATLAS</h4>${
          c.atlas.map(a=>`<a class="tech" href="https://atlas.mitre.org/techniques/${esc(a)}"
            target="_blank" rel="noopener">${esc(a)}</a>`).join('')}</div>`:''}
        ${refs.length?`<div class="csrefs"><h4>Sources <span class="n">${refs.length}</span></h4>
          <ul>${refs.map(r=>`<li><a href="${esc(r.url)}" target="_blank"
            rel="noopener">${esc(r.title||r.url)}</a></li>`).join('')}</ul></div>`:''}
      </div>`:''}
      </div>
    </details>`}).join('')+'</div>';
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
    renderTabs();renderToast();renderBack();return;
  }
  if(view==='mappings'){
    main.innerHTML=mappingsHTML();
    const go=el=>{
      pushNav();resetRuleFilters();
      rfilters[el.dataset.idx]=[el.dataset.v];
      view='rules'; update();
    };
    // The row expands; the button inside it is what jumps. Clicking a row used to
    // be the only behaviour, which made "what is in this category" unanswerable
    // without leaving the page first.
    const toggleIdx=el=>{
      const d=$(`#main .idet[data-for="${CSS.escape(el.dataset.x)}"]`);
      const open=d.hidden;
      d.hidden=!open;
      el.setAttribute('aria-expanded',String(open));
      el.classList.toggle('open',open);
    };
    $$('#main .irow').forEach(el=>{
      el.onclick=()=>toggleIdx(el);
      el.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();toggleIdx(el)}};
    });
    $$('#main .idrill').forEach(b=>b.onclick=()=>{pushNav();go(b)});
    $$('#main .idet .cdchip[data-rule]').forEach(b=>b.onclick=()=>{
      pushNav();resetRuleFilters();view='rules';
      $('#q').value=b.dataset.rule;query=b.dataset.rule.toLowerCase();update();
    });
    // Every count on a coverage row is a link into the corpus it counts, so the
    // table is a way in rather than a scoreboard. The rules filter matches
    // sub-techniques too, since that is the level rules are written at.
    const toggleCov=tr=>{
      const d=$(`#main .covdet[data-for="${CSS.escape(tr.dataset.t)}"]`);
      const open=d.hidden;
      d.hidden=!open;
      tr.setAttribute('aria-expanded',String(open));
      tr.classList.toggle('open',open);
    };
    $$('#main .covrow').forEach(tr=>{
      tr.onclick=e=>{if(!e.target.closest('.covlink'))toggleCov(tr)};
      tr.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();toggleCov(tr)}};
    });
    $$('#main .cdchip[data-rule]').forEach(b=>b.onclick=()=>{
      pushNav();resetRuleFilters();view='rules';
      $('#q').value=b.dataset.rule;query=b.dataset.rule.toLowerCase();update();
    });
    $$('#main .cdchip[data-tool]').forEach(b=>b.onclick=()=>{
      pushNav();resetFilters();filters.tool=[b.dataset.tool];view='catalog';update();
    });
    $$('#main .cdchip[data-case]').forEach(b=>b.onclick=()=>{
      pushNav();view='cases';update();
      const el=document.getElementById('cs-'+b.dataset.case);
      if(el){el.open=true;el.scrollIntoView({block:'start'})}
    });
    $$('#main .covlink[data-atlas]').forEach(b=>b.onclick=()=>{
      pushNav();resetRuleFilters();view='rules';
      const p=b.dataset.atlas;
      rfilters.ratlas=ROPTIONS.ratlas.filter(v=>v===p||v.startsWith(p+'.'));
      update();
    });
    $$('#main .covlink[data-tooltech]').forEach(b=>b.onclick=()=>{
      pushNav();resetFilters();view='catalog';
      const p=b.dataset.tooltech;
      filters.tool=TOOLS.filter(t=>(t.atlas||[]).some(a=>a===p||a.startsWith(p+'.')))
        .map(t=>t.tool);
      update();
    });
    $$('#main .covlink[data-casetech]').forEach(b=>b.onclick=()=>{
      pushNav();const p=b.dataset.casetech;
      view='cases';update();
      const hit=CASES.find(c=>(c.atlas||[]).some(a=>a===p||a.startsWith(p+'.')));
      if(hit){const d=document.getElementById('cs-'+hit.id);
        if(d){d.open=true;d.scrollIntoView({block:'start'})}}
    });
    renderTabs();renderToast();renderBack();return;
  }
  if(view==='sources'){
    main.innerHTML=sourcesHTML();
    // Every stat on a source card is a way into the rows or the rules it
    // covers, so the page reads as one catalog rather than as a second one.
    $$('#main .srcstat[data-cls]').forEach(b=>b.onclick=()=>{
      pushNav();resetFilters();filters.cls=[b.dataset.cls];view='catalog';update();
    });
    $$('#main .srcstat[data-rules]').forEach(b=>b.onclick=()=>{
      pushNav();resetRuleFilters();view='rules';
      ruleSet=new Set(SRCMAP[b.dataset.rules].rules);
      update();
    });
    const sa=$('#srcAll');
    if(sa)sa.onclick=()=>{
      const open=sa.dataset.open!=='1';
      $$('#main details.src').forEach(d=>d.open=open);
      sa.dataset.open=open?'1':'0';
      sa.textContent=open?'Collapse all':'Expand all';
    };
    renderTabs();renderToast();renderBack();return;
  }
  if(view==='guide'){
    main.innerHTML=guideHTML();
    // Prefix rendered heading ids so guide anchors never collide with row anchors.
    $$('#main .gbody h2,#main .gbody h3').forEach(h=>{
      if(h.id&&!h.id.startsWith('g-'))h.id='g-'+h.id;
    });
    renderTabs();renderToast();renderBack();return;
  }
  if(view==='catalog'){
    const rows=filteredRows();
    $('#count').textContent=`${rows.length} of ${ROWS.length} shown`;
    $('#chips').innerHTML=chipsHTML();
    $('#unvNote').hidden=!unvOnly;
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
      pushNav();resetFilters();filters.tool=[b.dataset.t];view='catalog';
      history.replaceState(null,'','#'+b.dataset.id);
      update();
    });
    // Search rather than a filter facet: rule filenames are unique and the
    // detections rail facets by category and format, not by file.
    $$('#main .detchip').forEach(b=>b.onclick=()=>{
      pushNav();resetFilters();view='rules';$('#q').value=b.dataset.rule;query=b.dataset.rule.toLowerCase();
      update();
    });
    const all=$('#csAll');
    if(all)all.onclick=()=>{
      const open=all.dataset.open!=='1';
      $$('#main details.csfull').forEach(d=>d.open=open);
      all.dataset.open=open?'1':'0';
      all.textContent=open?'Collapse all':'Expand all';
    };
  }else if(view==='tools'){
    main.innerHTML=toolsHTML();
    // A drawer, not a jump. Filtering the catalog by the tool discarded the
    // grid you were reading and answered a narrower question than the card
    // was asking - "what is this tool" rather than "list its paths". The
    // drill-down is still one click, from inside the drawer, where it is a
    // deliberate move rather than the only thing a click can do.
    $$('#main .tool').forEach(c=>c.onclick=()=>openToolDrawer(c.dataset.id,c));
  }else{
    main.innerHTML=planHTML();
    const l=$('#cpLinks'),p=$('#cpList');
    if(l)l.onclick=()=>copy(planLinks(),l);
    if(p)p.onclick=()=>copy(planText(),p);
    // Field edits persist without re-rendering: renderMain would rebuild the
    // input and take the caret with it on every keystroke.
    const nm=$('#pName'), hs=$('#pHost');
    if(nm)nm.oninput=()=>{const a=activePlan();if(a){a.name=nm.value;a.updated=nowISO();savePlans()}};
    if(hs)hs.oninput=()=>{const a=activePlan();if(a){a.host=hs.value;a.updated=nowISO();savePlans()}};
    const sw=$('#pSwitch'); if(sw)sw.onchange=()=>switchPlan(sw.value);
    const nw=$('#pNew'); if(nw)nw.onclick=()=>createPlan('');
    $$('#main .segbtn').forEach(b=>b.onclick=()=>{planMode=b.dataset.mode;renderMain()});
    const cl=$('#cpClear');
    // Two-step, because a plan is assembled one tick at a time across the whole
    // catalog and there is no undo for throwing it away.
    if(cl)cl.onclick=()=>{
      if(cl.dataset.armed!=='1'){cl.dataset.armed='1';cl.textContent='Clear all - sure?';
        setTimeout(()=>{if(cl.isConnected){cl.dataset.armed='0';cl.textContent='Clear all'}},4000);
        return}
      clearPicks();
    };
    $$('#main .rm').forEach(b=>b.onclick=()=>{picks.delete(b.dataset.a);savePicks();update()});
  }
  renderTabs();renderToast();renderBack();
}
function renderBack(){
  const el=$('#backbar');
  const s=navStack[navStack.length-1];
  el.hidden=!s;
  if(s)el.innerHTML=`<button class="backbtn" id="backBtn">&#8592; Back to ${
    esc(VIEW_LABEL[s.view]||s.view)}</button>`;
  const b=$('#backBtn');
  if(b)b.onclick=()=>{history.back();
    // popstate fires only if there is an entry to pop; if the page was loaded
    // straight into a jump there may not be, so fall back to the stack.
    setTimeout(()=>{if(navStack.length&&$('#backbar').firstChild===b)goBack()},60)};
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
    // A count of 0 is not a count, it is a label saying this tab is empty and
    // can be skipped - on the one tab whose whole job is to be filled. Every
    // other tab's badge counts a corpus that exists before the reader arrives;
    // this one counts their own work, so it appears once there is some. The tab
    // itself stays, and the empty state inside it carries the instruction.
    if(b.dataset.v==='plan'&&n){
      n.textContent=picks.size;
      n.hidden=!picks.size;
      b.title=picks.size?'':'Tick artifacts in the catalog to build a collection plan';
    }
  });
  // All six views render into the one container, so the panel is labelled by
  // whichever tab is currently selected rather than there being six panels.
  $('#main').setAttribute('aria-labelledby','tab-'+view);
}
function renderToast(){
  const t=$('#toast');
  // Stays up on an empty plan while an undo is available. Hiding it the instant
  // picks hit zero is what made clearing unrecoverable: the only affordance that
  // could take it back went away with the thing it would have restored.
  const undoable=!!lastCleared;
  t.hidden=(!picks.size&&!undoable)||view==='plan';
  if(t.hidden)return;
  const showUndo=!picks.size&&undoable;
  $('#toastN').textContent=showUndo
    ?`${lastCleared.anchors.length} cleared`
    :`${picks.size} artifact${picks.size>1?'s':''} picked`;
  $('#toastOpen').hidden=showUndo;
  $('#toastClear').hidden=showUndo;
  $('#toastUndo').hidden=!showUndo;
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
  if(h.startsWith('cs-')){view='cases';update();
    const el=document.getElementById(h);
    if(el){el.open=true;el.scrollIntoView({block:'start'})}
    return}
  if(h==='sources'){view='sources';update();return}
  if(h.startsWith('src-')){view='sources';update();
    const el=document.getElementById(h);
    if(el){el.open=true;el.scrollIntoView()}
    return}
  if(h==='guide'){view='guide';update();return}
  if(h.startsWith('g-')){view='guide';update();
    const el=document.getElementById(h);if(el)el.scrollIntoView();return}
  if(ROWMAP[h]){view='catalog';update();openDrawer(h,null);return}
  const t=TOOLS.find(t=>t.entry_id.toLowerCase()===h.toLowerCase()||t.slug===h.toLowerCase());
  if(t){resetFilters();filters.tool=[t.tool];view='catalog';update()}
}

/* ---------- boot ---------- */
$('#unvNote').textContent='Showing only unverified rows. '+UNVERIFIED_MEANING;
$('#unvBtn').title=UNVERIFIED_MEANING;
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
$('#toastClear').onclick=()=>{clearPicks();};
$('#toastUndo').onclick=()=>{undoClear()};
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
    <button role="tab" data-v="plan">Collection plan <span class="n" hidden></span></button>
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
  <div id="backbar" hidden></div>
  <div class="controls" id="controls">
    <div class="search"><span class="glyph">&#8981;</span>
      <input id="q" type="search" placeholder="Search paths, tools, descriptions..."
        aria-label="Search the catalog"></div>
    <button class="tgl" id="unvBtn" type="button" aria-pressed="false"
      aria-describedby="unvNote">Unverified only
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
  <p class="unvnote" id="unvNote" hidden></p>
  <div id="main" role="tabpanel" tabindex="0"></div>
</main>
</div>

<div class="drawer" id="drawer" hidden role="dialog" aria-modal="false"></div>
<div class="toast" id="toast" hidden><span id="toastN"></span>
  <button id="toastOpen" type="button">Open collection plan</button>
  <a id="toastClear">clear</a>
  <a id="toastUndo" hidden>undo</a></div>

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
