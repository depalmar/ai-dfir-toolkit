#!/usr/bin/env python3
"""Build the browsable catalog site from the generated feeds.

    python scripts/build_site.py            # writes docs/site/

The site is generated, never hand-edited. It reads docs/api/catalog.json, which
scripts/export.py regenerates from the YAML entries, so the page cannot drift
from the catalog: there is no independent copy of the content to fall stale.

Output is a single self-contained HTML file with the rows inlined as JSON. No
framework, no CDN, no build toolchain - one file to serve and nothing to keep
patched. It is deliberately not committed; CI builds it at deploy time. The
social-card image (docs/site-assets/card.png) is the one static asset: it is
branding rather than data - deliberately count-free - so committing it cannot
go stale. Dynamic counts live in the og:description, which this build writes.
"""
import html
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / "docs" / "api"
ASSETS = ROOT / "docs" / "site-assets"
OUT = ROOT / "docs" / "site"

REPO = "https://github.com/depalmar/ai-dfir-toolkit"
SITE = "https://depalmar.github.io/ai-dfir-toolkit/"

# Which field carries the "what you actually look for" value, per artifact class.
LOCATOR = {
    "disk": "path",
    "network": "indicator",
    "process": "name",
    "registry": "key",
}

FAVICON = (
    "data:image/svg+xml,"
    "%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E"
    "%3Crect width='32' height='32' rx='7' fill='%238a4b2a'/%3E"
    "%3Ctext x='16' y='22' font-family='monospace' font-size='15' fill='%23fff'"
    " text-anchor='middle'%3E~/%3C/text%3E%3C/svg%3E"
)


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
        "triage": (e.get("collection") or {}).get("triage_priority", ""),
        "guidance": (e.get("collection") or {}).get("guidance", ""),
        "description": e.get("description", ""),
    } for e in entries]


CSS = """
:root{
  --bg:#fbfbfa; --panel:#fff; --ink:#1c1b19; --muted:#6b6862; --line:#e4e1db;
  --accent:#8a4b2a; --accent-soft:#f4ece5;
  --c-crit:#8c1d18; --b-crit:#f7d5d0;
  --c-high:#7c3a00; --b-high:#f9e3c8;
  --c-med:#645200;  --b-med:#f4eec7;
  --c-low:#3c5a2e;  --b-low:#e4eeda;
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme=light]){
    --bg:#16150f; --panel:#1e1d17; --ink:#eceae4; --muted:#a09b90; --line:#33312a;
    --accent:#d99a6c; --accent-soft:#2c241d;
    --c-crit:#f2aba4; --b-crit:#48201c;
    --c-high:#eebb85; --b-high:#452f18;
    --c-med:#dcc972;  --b-med:#3c3414;
    --c-low:#b7d69c;  --b-low:#2b3a20;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  -webkit-text-size-adjust:100%}
a{color:var(--accent)}
.wrap{max-width:1180px;margin:0 auto;padding:30px 20px 80px}
.eyebrow{font-size:12px;letter-spacing:.09em;text-transform:uppercase;
  color:var(--accent);font-weight:600;margin:0 0 8px}
header h1{margin:0 0 8px;font-size:clamp(24px,4.4vw,30px);letter-spacing:-.015em}
header p.sub{margin:0 0 22px;color:var(--muted);max-width:68ch}
.stats{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 26px;padding:0;list-style:none}
.stats button,.stats a{display:block;width:100%;text-align:left;background:var(--panel);
  border:1px solid var(--line);border-radius:8px;padding:9px 13px;font:inherit;
  font-size:13px;color:inherit;cursor:pointer;text-decoration:none;transition:border-color .12s}
.stats button:hover,.stats a:hover{border-color:var(--accent)}
.stats b{font-size:19px;display:block;font-weight:650}
.stats span{color:var(--muted)}
.tabs{display:flex;gap:4px;margin:0 0 14px;border-bottom:1px solid var(--line)}
.tabs button{background:none;border:0;border-bottom:2px solid transparent;
  padding:8px 14px;font:inherit;color:var(--muted);cursor:pointer}
.tabs button[aria-selected=true]{color:var(--ink);border-bottom-color:var(--accent);font-weight:600}
.controls{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 12px}
.controls input,.controls select{background:var(--panel);color:var(--ink);
  border:1px solid var(--line);border-radius:7px;padding:8px 10px;font:inherit;min-height:40px}
.controls input{flex:1 1 260px}
.controls span[hidden]{display:none!important}
#reset{background:none;border:1px solid var(--line);border-radius:7px;color:var(--muted);
  font:inherit;padding:8px 12px;cursor:pointer}
#reset:hover{color:var(--ink);border-color:var(--accent)}
.count{color:var(--muted);font-size:13px;margin:0 0 10px;font-variant-numeric:tabular-nums}
.tablewrap{overflow:auto;max-height:74vh;border:1px solid var(--line);border-radius:9px;
  background:var(--panel)}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{text-align:left;padding:9px 11px;border-bottom:1px solid var(--line);vertical-align:top}
th{position:sticky;top:0;background:var(--panel);font-size:12px;letter-spacing:.03em;
  text-transform:uppercase;color:var(--muted);cursor:pointer;white-space:nowrap;z-index:1;
  box-shadow:0 1px 0 var(--line)}
th:hover,th:focus-visible{color:var(--ink);outline:none}
tbody tr.datarow{cursor:pointer}
tbody tr.datarow:hover{background:var(--accent-soft)}
tr.detail td{background:var(--accent-soft);font-size:13px;padding:12px 14px}
tr.detail dl{margin:0;display:grid;grid-template-columns:max-content 1fr;gap:4px 14px}
tr.detail dt{color:var(--muted)}
tr.detail dd{margin:0;overflow-wrap:anywhere}
tr:last-child td{border-bottom:0}
code{font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
code.id{white-space:nowrap;color:var(--muted)}
.tag{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11.5px;
  font-weight:600;white-space:nowrap;background:var(--panel);border:1px solid var(--line);
  color:var(--muted)}
.tag.crit{color:var(--c-crit);background:var(--b-crit);border-color:transparent}
.tag.hi{color:var(--c-high);background:var(--b-high);border-color:transparent}
.tag.md{color:var(--c-med);background:var(--b-med);border-color:transparent}
.tag.lo{color:var(--c-low);background:var(--b-low);border-color:transparent}
.muted{color:var(--muted)}
.desc{max-width:44ch;color:var(--muted)}
.flag{color:var(--c-crit);font-weight:700;font-size:10.5px;letter-spacing:.04em}
.empty{padding:36px;text-align:center;color:var(--muted)}
.cards{display:flex;flex-direction:column;gap:10px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:12px 14px}
.card .top{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-bottom:7px}
.card .top b{margin-right:auto;font-size:14.5px}
.card code{display:block;background:var(--accent-soft);border-radius:6px;
  padding:7px 9px;margin:0 0 7px}
.card .meta{font-size:12px;color:var(--muted);margin:0 0 4px}
.card p{margin:0;font-size:13px;color:var(--muted)}
footer{margin-top:34px;padding-top:18px;border-top:1px solid var(--line);
  color:var(--muted);font-size:13px}
@media(max-width:700px){
  .wrap{padding:20px 14px 60px}
  .stats{display:grid;grid-template-columns:1fr 1fr}
  .tablewrap{display:none}
}
@media(min-width:701px){.cards{display:none}}
"""

JS = """
const $=s=>document.querySelector(s);
let view='artifacts', sortKey='entry_id', sortDir=1, expanded=-1;
const mq=window.matchMedia('(max-width:700px)');

const RANK={critical:0,high:1,medium:2,low:3,p1:0,p2:1,p3:2};
const cls=v=>({critical:'crit',high:'hi',medium:'md',low:'lo',p1:'crit',p2:'hi',p3:'md'}[v]||'');
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const tag=(v,extra)=>v?`<span class="tag ${cls(v)}">${esc(v)}${extra||''}</span>`:'';
const osfmt=v=>esc(Array.isArray(v)?v.join(', '):v);

function opts(sel,vals,label){
  sel.innerHTML='<option value="">'+label+'</option>'+
    vals.map(v=>`<option value="${esc(v)}">${esc(v)}</option>`).join('');
}
const uniq=(arr,k)=>[...new Set(arr.flatMap(r=>{
  const v=r[k]; return Array.isArray(v)?v:(v?[v]:[]);
}))].sort();

function cmp(a,b,k){
  const x=a[k],y=b[k];
  if(RANK[x]!==undefined&&RANK[y]!==undefined){
    const rx=RANK[x],ry=RANK[y];
    if(rx!==ry)return rx-ry;
  }
  return String(x??'').localeCompare(String(y??''),undefined,{numeric:true});
}

function filtered(){
  const q=$('#q').value.trim().toLowerCase();
  const f=k=>$('#f_'+k)?.value||'';
  const src=view==='artifacts'?ROWS:TOOLS;
  let out=src.filter(r=>{
    if(view==='artifacts'){
      if(f('cls')&&r.cls!==f('cls'))return false;
      if(f('conf')&&r.confidence!==f('conf'))return false;
      if(f('fv')&&r.forensic_value!==f('fv'))return false;
      if(f('os')&&(!r.os||!String(r.os).includes(f('os'))))return false;
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
  if(['risk','confidence','forensic_value','triage'].includes(k))return tag(r[k]);
  if(k==='cls')return `<span class="tag">${esc(r.cls)}</span>`;
  if(k==='os')return osfmt(r.os);
  if(k==='entry_id')return `<code class="id">${esc(r.entry_id)}</code>`;
  return esc(r[k]);
}

function detailHTML(r,cols){
  const pairs=view==='artifacts'
    ?[['Entry',r.entry_id+' - '+r.tool+(r.vendor?' ('+r.vendor+')':'')],
      ['Evidence type',r.evidence_type],['OS',osfmt(r.os)],
      ['Entry risk',r.risk],['Sourcing',r.confidence+(r.unverified?' - UNVERIFIED, single source':'')],
      ['Notes',r.description]]
    :[['Entry',r.entry_id],['OS',osfmt(r.os)],['Collection guidance',r.guidance],
      ['Notes',r.description]];
  const dl=pairs.filter(([,v])=>v).map(([k,v])=>`<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('');
  return `<tr class="detail"><td colspan="${cols.length}"><dl>${dl}</dl></td></tr>`;
}

function cardHTML(r){
  if(view==='artifacts')
    return `<div class="card">
      <div class="top"><b>${esc(r.tool)}</b><span class="tag">${esc(r.cls)}</span>${tag(r.forensic_value)}${tag(r.confidence)}</div>
      <code>${esc(r.artifact)}</code>
      <div class="meta">${esc(r.entry_id)}${r.os?' &middot; '+osfmt(r.os):''}${r.evidence_type?' &middot; '+esc(r.evidence_type):''}${r.unverified?' &middot; <span class="flag">UNVERIFIED</span>':''}</div>
      ${r.description?`<p>${esc(r.description)}</p>`:''}
    </div>`;
  return `<div class="card">
    <div class="top"><b>${esc(r.tool)}</b>${tag(r.risk)}${tag(r.triage)}</div>
    <div class="meta">${esc(r.entry_id)} &middot; ${esc(r.vendor)} &middot; ${esc(r.category)}</div>
    ${r.description?`<p>${esc(r.description)}</p>`:''}
  </div>`;
}

function render(){
  const rows=filtered(), cols=COLS[view], total=(view==='artifacts'?ROWS:TOOLS).length;
  $('#count').textContent=`${rows.length} of ${total} shown`;
  const active=$('#q').value||[...document.querySelectorAll('.controls select')].some(s=>s.value&&!s.closest('[hidden]'));
  $('#reset').hidden=!active;
  if(!rows.length){
    $('#table').innerHTML='<p class="empty">Nothing matches those filters.</p>';
    $('#cards').innerHTML='<p class="empty">Nothing matches those filters.</p>';
    return;
  }
  if(mq.matches){
    $('#cards').innerHTML=rows.map(cardHTML).join('');
    $('#table').innerHTML='';
    return;
  }
  $('#cards').innerHTML='';
  $('#table').innerHTML=
    '<table><thead><tr>'+cols.map(([k,l])=>
      `<th data-k="${k}" tabindex="0" role="button" aria-label="Sort by ${l}">${l}${sortKey===k?(sortDir>0?' \\u2191':' \\u2193'):''}</th>`).join('')+
    '</tr></thead><tbody>'+rows.map((r,i)=>
      `<tr class="datarow" data-i="${i}">`+cols.map(([k])=>`<td>${cell(r,k)}</td>`).join('')+'</tr>'+
      (expanded===i?detailHTML(r,cols):'')
    ).join('')+'</tbody></table>';
  const sortBy=k=>{if(sortKey===k)sortDir*=-1;else{sortKey=k;sortDir=1}expanded=-1;render()};
  document.querySelectorAll('th').forEach(th=>{
    th.onclick=()=>sortBy(th.dataset.k);
    th.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();sortBy(th.dataset.k)}};
  });
  document.querySelectorAll('tr.datarow').forEach(tr=>tr.onclick=()=>{
    const i=+tr.dataset.i;
    expanded=expanded===i?-1:i;
    render();
  });
}

function setView(v){
  view=v; sortKey='entry_id'; sortDir=1; expanded=-1;
  document.querySelectorAll('.tabs button').forEach(b=>
    b.setAttribute('aria-selected', String(b.dataset.v===v)));
  $('#filters_artifacts').hidden = v!=='artifacts';
  $('#filters_tools').hidden = v!=='tools';
  render();
}

function reset(){
  $('#q').value='';
  document.querySelectorAll('.controls select').forEach(s=>s.value='');
  expanded=-1; render();
}

opts($('#f_cls'),uniq(ROWS,'cls'),'All classes');
opts($('#f_conf'),['high','medium','low'],'Any confidence');
opts($('#f_fv'),['high','medium','low'],'Any forensic value');
opts($('#f_os'),['windows','macos','linux'],'Any OS');
opts($('#f_risk'),['critical','high','medium','low'],'Any risk');
opts($('#f_cat'),uniq(TOOLS,'category'),'All categories');
document.querySelectorAll('.controls input,.controls select').forEach(el=>{
  el.addEventListener('input',()=>{expanded=-1;render()});
});
document.querySelectorAll('.tabs button').forEach(b=>b.onclick=()=>setView(b.dataset.v));
document.querySelectorAll('.stats [data-go]').forEach(el=>el.onclick=()=>{
  const [v,c]=el.dataset.go.split(':');
  reset(); if(view!==v)setView(v);
  if(c){$('#f_cls').value=c;render()}
});
$('#reset').onclick=reset;
mq.addEventListener('change',render);
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

    og_desc = (
        f"{len(tools)} tools, {n_art} artifacts, {n_cred} credential locations, "
        f"{n_mcp} MCP configs - install paths, plaintext token locations, listening "
        f"ports and process trees, each rated by forensic value and sourcing confidence."
    )

    tiles = [
        ("tools", len(tools), "tools", 'data-go="tools"'),
        ("artifacts", n_art, "artifacts", 'data-go="artifacts"'),
        ("credentials", n_cred, "credential locations", 'data-go="artifacts:credential"'),
        ("mcp", n_mcp, "MCP configs", 'data-go="artifacts:mcp-config"'),
    ]
    tiles_html = "".join(
        f'<li><button type="button" {attr}><b>{n}</b><span>{label}</span></button></li>'
        for _, n, label, attr in tiles
    ) + (
        f'<li><a href="{REPO}/tree/main/artifacts/detections/sigma">'
        f'<b>{n_sigma}</b><span>Sigma rules</span></a></li>'
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
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
<header>
  <p class="eyebrow">ai-dfir-toolkit &middot; reference data</p>
  <h1>AI Agent Artifact Catalog</h1>
  <p class="sub">What AI coding agents, local model runtimes and MCP components leave
  on an endpoint, what each trace proves, and in what order to collect it.
  Every artifact is rated by forensic value and by how well it is sourced.</p>
  <ul class="stats">
    {tiles_html}
  </ul>
</header>

<nav class="tabs" role="tablist">
  <button data-v="artifacts" role="tab">Artifacts</button>
  <button data-v="tools" role="tab">Tools</button>
</nav>

<div class="controls">
  <input id="q" type="search" placeholder="Search paths, tools, descriptions..." aria-label="Search the catalog">
  <span id="filters_artifacts" style="display:contents">
    <select id="f_cls" aria-label="Filter by artifact class"></select>
    <select id="f_os" aria-label="Filter by operating system"></select>
    <select id="f_fv" aria-label="Filter by forensic value"></select>
    <select id="f_conf" aria-label="Filter by confidence"></select>
  </span>
  <span id="filters_tools" style="display:contents" hidden>
    <select id="f_risk" aria-label="Filter by risk"></select>
    <select id="f_cat" aria-label="Filter by category"></select>
  </span>
  <button id="reset" type="button" hidden>Clear filters</button>
</div>

<p class="count" id="count"></p>
<div class="tablewrap" id="table"></div>
<div class="cards" id="cards"></div>

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
    card = ASSETS / "card.png"
    if card.exists():
        shutil.copy2(card, OUT / "card.png")
    else:
        print("note: docs/site-assets/card.png missing - og:image will 404")
    size = (OUT / "index.html").stat().st_size
    print(f"{len(tools)} tools, {len(rows)} rows -> docs/site/index.html ({size // 1024} KB)")


if __name__ == "__main__":
    main()
