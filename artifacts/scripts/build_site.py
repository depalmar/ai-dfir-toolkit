#!/usr/bin/env python3
"""Build the browsable catalog site from the generated feeds.

    python scripts/build_site.py            # writes docs/site/index.html

The site is generated, never hand-edited. It reads docs/api/catalog.json, which
scripts/export.py regenerates from the YAML entries, so the page cannot drift
from the catalog: there is no independent copy of the content to fall stale.

Output is a single self-contained HTML file with the rows inlined as JSON. No
framework, no CDN, no build toolchain - one file to serve and nothing to keep
patched. It is deliberately not committed; CI builds it at deploy time.
"""
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / "docs" / "api"
OUT = ROOT / "docs" / "site"

REPO = "https://github.com/depalmar/ai-dfir-toolkit"

# Which field carries the "what you actually look for" value, per artifact class.
LOCATOR = {
    "disk": "path",
    "network": "indicator",
    "process": "name",
    "registry": "key",
}


def write_lf(path: Path, text: str) -> None:
    """LF on every platform, so output is byte-identical wherever it is built."""
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def build_rows(entries):
    """Flatten the catalog into one row per artifact.

    Mirrors the row set in docs/api/artifacts.csv - disk, network, process and
    registry artifacts, plus credential locations and MCP configs - so the site
    and the CSV feed describe the same corpus.
    """
    rows = []
    for e in entries:
        base = {
            "entry_id": e["id"],
            "tool": e["name"],
            "vendor": e.get("vendor", ""),
            "category": e.get("category", ""),
            "risk": e.get("risk", ""),
        }
        for kind, items in (e.get("artifacts") or {}).items():
            for a in items:
                rows.append({
                    **base,
                    "cls": kind,
                    "artifact": a.get(LOCATOR.get(kind, "path"), ""),
                    "os": a.get("os", ""),
                    "forensic_value": a.get("forensic_value", ""),
                    "evidence_type": a.get("evidence_type", ""),
                    "confidence": a.get("confidence", ""),
                    "unverified": bool(a.get("unverified")),
                    "description": a.get("description", ""),
                })
        for c in (e.get("credentials") or []):
            rows.append({
                **base,
                "cls": "credential",
                "artifact": c.get("location", ""),
                "os": c.get("os", ""),
                "forensic_value": "high",
                "evidence_type": c.get("secret_type", ""),
                "confidence": c.get("confidence", ""),
                "unverified": bool(c.get("unverified")),
                "description": c.get("description", ""),
            })
        for m in (e.get("mcp") or []):
            rows.append({
                **base,
                "cls": "mcp-config",
                "artifact": m.get("config_path", ""),
                "os": "",
                "forensic_value": "high",
                "evidence_type": "execution|persistence",
                "confidence": "high",
                "unverified": False,
                "description": m.get("notes", ""),
            })
    return rows


def build_tools(entries):
    """Per-tool summary, for the tools view."""
    return [{
        "entry_id": e["id"],
        "tool": e["name"],
        "vendor": e.get("vendor", ""),
        "category": e.get("category", ""),
        "risk": e.get("risk", ""),
        "confidence": e.get("confidence", ""),
        "os": e.get("supported_os", []),
        "caps": e.get("capabilities", {}),
        "triage": (e.get("collection") or {}).get("triage_priority", ""),
        "guidance": (e.get("collection") or {}).get("guidance", ""),
        "description": e.get("description", ""),
    } for e in entries]


CSS = """
:root{
  --bg:#fbfbfa; --panel:#fff; --ink:#1c1b19; --muted:#6b6862; --line:#e4e1db;
  --accent:#8a4b2a; --accent-soft:#f2e9e2;
  --crit:#a12b2b; --high:#b4611c; --med:#8a7320; --low:#5c7a4a;
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme=light]){
    --bg:#16150f; --panel:#1e1d17; --ink:#eceae4; --muted:#a09b90; --line:#33312a;
    --accent:#d99a6c; --accent-soft:#2c241d;
    --crit:#e07a7a; --high:#e0a061; --med:#ccb457; --low:#9dc182;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent)}
.wrap{max-width:1180px;margin:0 auto;padding:32px 20px 80px}
header h1{margin:0 0 6px;font-size:26px;letter-spacing:-.015em}
header p.sub{margin:0 0 20px;color:var(--muted);max-width:70ch}
.stats{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 24px;padding:0;list-style:none}
.stats li{background:var(--panel);border:1px solid var(--line);border-radius:7px;
  padding:8px 12px;font-size:13px}
.stats b{font-size:17px;display:block;font-variant-numeric:tabular-nums}
.stats span{color:var(--muted)}
.tabs{display:flex;gap:4px;margin:0 0 14px;border-bottom:1px solid var(--line)}
.tabs button{background:none;border:0;border-bottom:2px solid transparent;
  padding:8px 14px;font:inherit;color:var(--muted);cursor:pointer}
.tabs button[aria-selected=true]{color:var(--ink);border-bottom-color:var(--accent);font-weight:600}
.controls{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 12px}
.controls input,.controls select{background:var(--panel);color:var(--ink);
  border:1px solid var(--line);border-radius:7px;padding:8px 10px;font:inherit}
.controls input{flex:1 1 280px}
.count{color:var(--muted);font-size:13px;margin:0 0 10px;font-variant-numeric:tabular-nums}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:9px;background:var(--panel)}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{text-align:left;padding:9px 11px;border-bottom:1px solid var(--line);vertical-align:top}
th{position:sticky;top:0;background:var(--panel);font-size:12px;letter-spacing:.03em;
  text-transform:uppercase;color:var(--muted);cursor:pointer;white-space:nowrap;z-index:1}
th:hover{color:var(--ink)}
tbody tr:hover{background:var(--accent-soft)}
tr:last-child td{border-bottom:0}
code{font:12.5px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
code.id{white-space:nowrap;word-break:normal}
.controls span[hidden]{display:none!important}
.tag{display:inline-block;padding:1px 7px;border-radius:20px;font-size:11.5px;
  border:1px solid var(--line);white-space:nowrap}
.crit{color:var(--crit);border-color:currentColor}
.hi{color:var(--high);border-color:currentColor}
.md{color:var(--med);border-color:currentColor}
.lo{color:var(--low);border-color:currentColor}
.muted{color:var(--muted)}
.desc{max-width:44ch;color:var(--muted)}
.flag{color:var(--crit);font-weight:600;font-size:11px}
.empty{padding:36px;text-align:center;color:var(--muted)}
footer{margin-top:34px;padding-top:18px;border-top:1px solid var(--line);
  color:var(--muted);font-size:13px}
@media(max-width:620px){.desc{display:none}.wrap{padding:20px 14px 60px}}
"""

JS = """
const $=s=>document.querySelector(s);
let view='artifacts', sortKey='entry_id', sortDir=1;

const RANK={critical:0,high:1,medium:2,low:3,p1:0,p2:1,p3:2};
const cls=v=>({critical:'crit',high:'hi',medium:'md',low:'lo',p1:'crit',p2:'hi',p3:'md'}[v]||'muted');
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

function opts(sel,vals,label){
  sel.innerHTML='<option value="">'+label+'</option>'+
    vals.map(v=>`<option value="${esc(v)}">${esc(v)}</option>`).join('');
}
const uniq=(arr,k)=>[...new Set(arr.flatMap(r=>{
  const v=r[k]; return Array.isArray(v)?v:(v?[v]:[]);
}))].sort();

function cmp(a,b,k){
  const x=a[k],y=b[k];
  if(k in {risk:1,confidence:1,forensic_value:1,triage:1}||RANK[x]!==undefined&&RANK[y]!==undefined){
    const rx=RANK[x]??99, ry=RANK[y]??99;
    if(rx!==ry) return rx-ry;
  }
  return String(x??'').localeCompare(String(y??''),undefined,{numeric:true});
}

function filtered(){
  const q=$('#q').value.trim().toLowerCase();
  const f=k=>$('#f_'+k)?.value||'';
  const src = view==='artifacts'?ROWS:TOOLS;
  let out=src.filter(r=>{
    if(view==='artifacts'){
      if(f('cls')&&r.cls!==f('cls'))return false;
      if(f('conf')&&r.confidence!==f('conf'))return false;
      if(f('fv')&&r.forensic_value!==f('fv'))return false;
      if(f('os')&&r.os&&!String(r.os).includes(f('os')))return false;
      if(f('os')&&!r.os)return false;
    }else{
      if(f('risk')&&r.risk!==f('risk'))return false;
      if(f('cat')&&r.category!==f('cat'))return false;
    }
    if(!q)return true;
    return JSON.stringify(r).toLowerCase().includes(q);
  });
  out.sort((a,b)=>cmp(a,b,sortKey)*sortDir);
  return out;
}

const COLS={
  artifacts:[['entry_id','ID'],['tool','Tool'],['cls','Class'],['artifact','Artifact'],
    ['os','OS'],['forensic_value','Value'],['confidence','Conf'],['description','Notes']],
  tools:[['entry_id','ID'],['tool','Tool'],['vendor','Vendor'],['category','Category'],
    ['risk','Risk'],['confidence','Conf'],['triage','Triage'],['description','Notes']]
};

function cell(r,k){
  if(k==='artifact')return `<code>${esc(r.artifact)}</code>`+(r.unverified?' <span class="flag">UNVERIFIED</span>':'');
  if(k==='description')return `<span class="desc">${esc(r[k])}</span>`;
  if(['risk','confidence','forensic_value','triage'].includes(k))
    return r[k]?`<span class="tag ${cls(r[k])}">${esc(r[k])}</span>`:'';
  if(k==='cls')return `<span class="tag">${esc(r.cls)}</span>`;
  if(k==='os')return esc(Array.isArray(r.os)?r.os.join(', '):r.os);
  if(k==='entry_id')return `<code class="muted id">${esc(r.entry_id)}</code>`;
  return esc(r[k]);
}

function render(){
  const rows=filtered(), cols=COLS[view];
  $('#count').textContent=`${rows.length} of ${(view==='artifacts'?ROWS:TOOLS).length} shown`;
  if(!rows.length){$('#table').innerHTML='<p class="empty">Nothing matches those filters.</p>';return}
  $('#table').innerHTML=
    '<table><thead><tr>'+cols.map(([k,l])=>
      `<th data-k="${k}">${l}${sortKey===k?(sortDir>0?' \\u2191':' \\u2193'):''}</th>`).join('')+
    '</tr></thead><tbody>'+rows.map(r=>
      '<tr>'+cols.map(([k])=>`<td>${cell(r,k)}</td>`).join('')+'</tr>').join('')+
    '</tbody></table>';
  document.querySelectorAll('th').forEach(th=>th.onclick=()=>{
    const k=th.dataset.k;
    if(sortKey===k)sortDir*=-1; else {sortKey=k;sortDir=1}
    render();
  });
}

function setView(v){
  view=v; sortKey='entry_id'; sortDir=1;
  document.querySelectorAll('.tabs button').forEach(b=>
    b.setAttribute('aria-selected', String(b.dataset.v===v)));
  $('#filters_artifacts').hidden = v!=='artifacts';
  $('#filters_tools').hidden = v!=='tools';
  render();
}

opts($('#f_cls'),uniq(ROWS,'cls'),'All classes');
opts($('#f_conf'),['high','medium','low'],'Any confidence');
opts($('#f_fv'),['high','medium','low'],'Any forensic value');
opts($('#f_os'),['windows','macos','linux'],'Any OS');
opts($('#f_risk'),['critical','high','medium','low'],'Any risk');
opts($('#f_cat'),uniq(TOOLS,'category'),'All categories');
document.querySelectorAll('.controls input,.controls select').forEach(el=>{
  el.addEventListener('input',render);
});
document.querySelectorAll('.tabs button').forEach(b=>b.onclick=()=>setView(b.dataset.v));
setView('artifacts');
"""


def main():
    entries = json.loads((API / "catalog.json").read_text(encoding="utf-8"))
    rows = build_rows(entries)
    tools = build_tools(entries)

    n_cred = sum(1 for r in rows if r["cls"] == "credential")
    n_mcp = sum(1 for r in rows if r["cls"] == "mcp-config")
    n_art = len(rows) - n_cred - n_mcp
    n_sigma = len(json.loads((API / "detections.json").read_text(encoding="utf-8")))

    stats = [
        (len(tools), "tools"),
        (n_art, "artifacts"),
        (n_cred, "credential locations"),
        (n_mcp, "MCP configs"),
        (n_sigma, "Sigma rules"),
    ]

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Agent Artifact Catalog</title>
<meta name="description" content="What AI coding agents, local LLM runtimes and MCP components leave on an endpoint, what each trace proves, and in what order to collect it.">
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>AI Agent Artifact Catalog</h1>
  <p class="sub">What AI coding agents, local model runtimes and MCP components leave
  on an endpoint, what each trace proves, and in what order to collect it.
  Every artifact is rated by forensic value and by how well it is sourced.</p>
  <ul class="stats">
    {"".join(f'<li><b>{n}</b><span>{label}</span></li>' for n, label in stats)}
  </ul>
</header>

<nav class="tabs" role="tablist">
  <button data-v="artifacts" role="tab">Artifacts</button>
  <button data-v="tools" role="tab">Tools</button>
</nav>

<div class="controls">
  <input id="q" type="search" placeholder="Search paths, tools, descriptions...">
  <span id="filters_artifacts" style="display:contents">
    <select id="f_cls"></select><select id="f_os"></select>
    <select id="f_fv"></select><select id="f_conf"></select>
  </span>
  <span id="filters_tools" style="display:contents" hidden>
    <select id="f_risk"></select><select id="f_cat"></select>
  </span>
</div>

<p class="count" id="count"></p>
<div class="tablewrap" id="table"></div>

<footer>
  <p><strong>Confidence reflects provenance, not conviction.</strong>
  <em>high</em> means verified on a live host or documented by the vendor,
  <em>medium</em> means multiple independent sources agree, and <em>low</em> means
  single-source or inferred. Anything single-sourced is flagged
  <span class="flag">UNVERIFIED</span>. Paths move between tool releases, so treat
  this as a starting point and verify before you rely on it.</p>
  <p>Generated from the catalog source. Corrections welcome, especially if you can
  verify a path on a real host.
  <a href="{REPO}/tree/main/artifacts">Source</a> &middot;
  <a href="{REPO}/issues">Report an error</a> &middot;
  <a href="{REPO}/releases/latest">Download the feeds</a></p>
  <p>Catalog data CC BY 4.0. Scripts and schema Apache-2.0.</p>
</footer>
</div>
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
    size = (OUT / "index.html").stat().st_size
    print(f"{len(tools)} tools, {len(rows)} rows -> docs/site/index.html ({size // 1024} KB)")


if __name__ == "__main__":
    main()
