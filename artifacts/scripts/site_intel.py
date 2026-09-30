"""Site views for the threat-intel layer, the entity graph and the triage-script builder.

Kept out of build_site.py because that file already holds the catalog's whole
page, and these three views share nothing with it but the drawer, the plan and
the design tokens. Everything here renders data that intel_graph.py and
triage_spec.py derived at build time; the browser computes counts for display,
never facts.
"""

CSS = r"""
:root{
  /* Categorical series, one per entity type. Deliberately not the severity ramp
     or the value/confidence scales: a node's colour says what it is, and must
     never read as how bad it is. Mid-lightness, spaced in hue. */
  --series-1:#5b6fa8; --series-2:#3f8f7f; --series-3:#a0662e; --series-4:#8a5a9e;
  --series-5:#6b8a3a; --series-6:#b0506a; --series-7:#4f8fb3; --series-8:#8c7b52;
  --gap:#b64a3c; --covered:#3f8f7f; --offhost:#9c968c;
}
:root[data-theme=dark]{
  --series-1:#93a6dc; --series-2:#7fc8b8; --series-3:#e0a56c; --series-4:#c49ad6;
  --series-5:#a9c774; --series-6:#e48da3; --series-7:#8fc7e6; --series-8:#cbbb8f;
  --gap:#ef8d7f; --covered:#7fc8b8; --offhost:#7c766e;
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme=light]):not([data-theme=dark]){
    --series-1:#93a6dc; --series-2:#7fc8b8; --series-3:#e0a56c; --series-4:#c49ad6;
    --series-5:#a9c774; --series-6:#e48da3; --series-7:#8fc7e6; --series-8:#cbbb8f;
    --gap:#ef8d7f; --covered:#7fc8b8; --offhost:#7c766e;
  }
}
.isec{margin:26px 0 8px}
.isec>h3{font-size:15px;margin:0 0 4px}
.isec>p.lede{margin:0 0 12px;color:var(--muted);max-width:78ch}
.istats{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin:14px 0}
.istat{border:1px solid var(--line);border-radius:10px;background:var(--panel);padding:10px 12px}
.istat b{display:block;font-size:22px;line-height:1.15}
.istat span{color:var(--muted);font-size:12px}
.agrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px}
.acard{border:1px solid var(--line);border-radius:10px;background:var(--panel);padding:11px 13px;
  text-align:left;display:flex;flex-direction:column;gap:5px}
.acard:hover{background:var(--hover)}
.acard .an{font-weight:600}
.acard .am{color:var(--muted);font-size:12px}
.kind{display:inline-block;border-radius:999px;padding:1px 8px;font-size:11px;border:1px solid var(--line)}
.kind.k-state-nexus{border-color:var(--series-1);color:var(--series-1)}
.kind.k-criminal{border-color:var(--series-6);color:var(--series-6)}
.kind.k-commercial{border-color:var(--series-3);color:var(--series-3)}
.kind.k-unattributed-cluster{border-color:var(--series-8);color:var(--series-8)}
.gapn{color:var(--gap);font-size:12px}
.seg.small .segbtn{font-size:12px;padding:3px 9px}
.matrix{display:flex;gap:6px;overflow-x:auto;padding-bottom:8px;margin-top:10px}
.mcol{min-width:132px;flex:1 0 132px}
.mhead{font-size:11px;font-weight:600;color:var(--muted);padding:4px 2px;border-bottom:2px solid var(--line);
  margin-bottom:4px;min-height:34px}
.mhead i{font-style:normal;color:var(--faint);font-weight:400}
.mcell{display:block;width:100%;text-align:left;border:1px solid var(--line-soft);border-radius:6px;
  padding:4px 6px;margin:0 0 3px;font-size:11px;line-height:1.3;background:var(--panel);color:var(--ink)}
.mcell.sub{margin-left:8px;width:calc(100% - 8px)}
.mcell .mid{display:block;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:10px;color:var(--muted)}
.mcell.zero{opacity:.45}
.mcell.sel{outline:2px solid var(--accent);outline-offset:1px}
.mcell.st-gap{border-color:var(--gap);box-shadow:inset 3px 0 0 var(--gap)}
.mcell.st-covered{box-shadow:inset 3px 0 0 var(--covered)}
.mcell.st-offhost{box-shadow:inset 3px 0 0 var(--offhost)}
.mlegend{display:flex;flex-wrap:wrap;gap:12px;font-size:12px;color:var(--muted);margin-top:6px}
.mlegend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
.tdetail{border:1px solid var(--line);border-radius:10px;background:var(--panel);padding:12px 14px;margin-top:10px}
.tdetail h4{margin:0 0 6px}
.linkrow2{display:flex;flex-wrap:wrap;gap:6px;margin:4px 0 8px}
.lchip{border:1px solid var(--line);background:var(--panel-2);border-radius:999px;padding:2px 9px;font-size:12px}
.lchip:hover{background:var(--hover)}
.bars{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px}
.barbox{border:1px solid var(--line);border-radius:10px;background:var(--panel);padding:10px 12px}
.barbox h4{margin:0 0 8px;font-size:13px}
.vbar{display:grid;grid-template-columns:150px 1fr 28px;gap:8px;align-items:center;font-size:12px;margin:3px 0}
.vbar .bl{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.vbar .bt{height:10px;border-radius:3px;background:var(--line-soft);overflow:hidden}
.vbar .bt i{display:block;height:100%;background:var(--series-1)}
.vbar .bn{text-align:right;color:var(--muted)}
.htable .lchip{display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  margin:0 0 3px;vertical-align:top}
.htable td:last-child{max-width:190px}
.qbars{display:flex;align-items:flex-end;gap:6px;height:120px;border-bottom:1px solid var(--line);padding-top:6px}
.qbar{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%;min-width:26px}
.qbar i{display:block;width:70%;background:var(--series-2);border-radius:3px 3px 0 0}
.qbar span{font-size:10px;color:var(--muted);margin-top:3px;white-space:nowrap}
.qbar b{font-size:11px}
.htable{width:100%;border-collapse:collapse;font-size:12px}
.hscroll{overflow-x:auto;max-width:100%}
.htable th,.htable td{border-bottom:1px solid var(--line-soft);padding:5px 6px;text-align:left;vertical-align:top}
.htable td.gap{color:var(--gap)}
.htable td.off{color:var(--faint)}
.phase{display:inline-block;font-size:10px;text-transform:uppercase;letter-spacing:.04em;border-radius:4px;
  padding:0 5px;border:1px solid var(--line);color:var(--muted)}
.ph-contain{border-color:var(--series-6);color:var(--series-6)}
.ph-eradicate{border-color:var(--series-3);color:var(--series-3)}
.ph-recover{border-color:var(--series-2);color:var(--series-2)}
.ph-harden{border-color:var(--series-1);color:var(--series-1)}
.sighting{border-left:3px solid var(--line);padding:2px 0 2px 9px;margin:6px 0}
.sighting .sm{font-size:11px;color:var(--muted)}
.vbar{border:0;background:none;width:100%;text-align:left;padding:2px 3px;border-radius:5px;color:var(--ink)}
.vbar:hover{background:var(--hover)}
.vbar.on,.qbar.on,.acard.on,.mhead.on{outline:2px solid var(--accent);outline-offset:1px}
.qbar{border:0;background:none;padding:0;color:var(--ink)}
.mhead{border:0;border-bottom:2px solid var(--line);background:none;width:100%;text-align:left;cursor:pointer}
.istat small{font-size:13px;color:var(--faint);font-weight:400}
.pivot{border:1px solid var(--accent-border);background:var(--accent-soft);border-radius:10px;padding:9px 12px;
  margin:12px 0;position:sticky;top:0;z-index:5}
.pchips,.pacts{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.pacts{margin-top:7px}
.tline{display:block}
.tline .tgrid{stroke:var(--line-soft)}
.tline .tax,.tline .tlab{fill:var(--muted);font-size:10px}
.tline .tlab{font-size:11px;fill:var(--ink)}
.tline .tspan{stroke:var(--line);stroke-width:2}
.tline .tcase{fill:var(--series-3);cursor:pointer}
.tline .tsight{fill:var(--series-1);cursor:pointer}
.tline .tcase:hover,.tline .tsight:hover,.tline :focus{stroke:var(--ink);stroke-width:2}
.hmap{border-collapse:collapse;font-size:11px}
.hmap th,.hmap td{border:1px solid var(--line-soft);padding:0;text-align:center;min-width:22px;height:22px}
.hmap thead th{height:auto;vertical-align:bottom}
.hmap tbody th{text-align:left;padding:1px 4px;white-space:nowrap}
.hmh{border:0;background:none;writing-mode:vertical-rl;transform:rotate(180deg);font-size:10px;
  font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--muted);padding:3px 0}
.hmap td.h-covered{background:color-mix(in srgb,var(--covered) 55%,var(--panel));color:var(--on-tone)}
.hmap td.h-gap{background:color-mix(in srgb,var(--gap) 60%,var(--panel));color:var(--on-tone)}
.hmap td.h-offhost{background:color-mix(in srgb,var(--offhost) 45%,var(--panel))}
.hmap.sim td{min-width:30px;font-size:10px;color:var(--ink)}
.vlab{writing-mode:vertical-rl;transform:rotate(180deg);font-size:10px;color:var(--muted);white-space:nowrap}
/* graph workbench */
.gwrap{display:grid;grid-template-columns:230px 1fr 280px;gap:10px;min-height:620px}
.gpane{border:1px solid var(--line);border-radius:10px;background:var(--panel);padding:10px;overflow:auto;max-height:78vh}
.gpane h4{margin:6px 0;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
#cy{border:1px solid var(--line);border-radius:10px;background:var(--panel-2);min-height:620px;height:78vh}
.gsearch{width:100%;padding:6px 8px;border:1px solid var(--field-line);border-radius:7px;background:var(--panel);color:var(--ink)}
.gres{display:flex;flex-direction:column;gap:2px;margin-top:6px}
.gres button,.nbl button{text-align:left;border:0;background:none;padding:3px 4px;border-radius:5px;font-size:12px}
.gres button:hover,.nbl button:hover{background:var(--hover)}
.tfilter{display:flex;flex-wrap:wrap;gap:4px}
.tfilter label{font-size:11px;border:1px solid var(--line);border-radius:999px;padding:1px 7px;cursor:pointer}
.tfilter input{margin:0 4px 0 0;vertical-align:-1px}
.gbtns{display:flex;flex-wrap:wrap;gap:5px;margin:6px 0}
.gbtns .btn{font-size:12px;padding:4px 8px}
.dot2{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px;vertical-align:0}
.nbl{display:flex;flex-direction:column}
.nbl .rel{font-size:11px;color:var(--faint);margin-top:6px}
.gnote{font-size:12px;color:var(--muted)}
/* triage builder */
.tbuild{border:1px solid var(--line);border-radius:10px;background:var(--panel);padding:12px 14px;margin:14px 0}
.tbuild h3{margin:0 0 4px;font-size:15px}
.tbuild .tcount{font-size:12px;color:var(--muted);margin:6px 0}
.tbuild pre{max-height:320px;overflow:auto;background:var(--panel-2);border:1px solid var(--line-soft);
  border-radius:8px;padding:8px;font-size:11px}
.fw{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:10px;margin-top:10px}
.fwc{border:1px solid var(--line-soft);border-radius:8px;padding:9px 11px;background:var(--panel-2)}
.fwc h4{margin:0 0 4px;font-size:13px}
.fwc p{margin:0 0 6px;font-size:12px;color:var(--muted)}
.fwc code{display:block;white-space:pre-wrap;word-break:break-all;font-size:11px;background:var(--panel);
  border:1px solid var(--line-soft);border-radius:6px;padding:6px}
@media (max-width:900px){
  .gwrap{grid-template-columns:1fr}
  #cy{height:60vh;min-height:420px}
  .gpane{max-height:none}
  .vbar{grid-template-columns:110px 1fr 24px}
}
"""

JS = r"""
/* ---------- threat intel ----------
   Everything on this view is derived by scripts/intel_graph.py from the actor
   profiles, the case studies, the catalog and the rule corpus. The page counts
   for display; it does not decide anything. */
const ACTORMAP=Object.fromEntries(INTEL.actors.map(a=>[a.id,a]));
const CASEMAP=Object.fromEntries(CASES.map(c=>[c.id,c]));
const ATL=INTEL.atlas;
const TNAME=id=>ATL.techniques[id]||'';
const KIND_LABEL={'state-nexus':'state nexus','criminal':'criminal','commercial':'commercial',
  'unattributed-cluster':'named cluster'};
let intelLayer='actors', techSel=null, matrixAll=false;
const RULES_FOR=(()=>{const m={};for(const r of RULES)for(const t of r.atlas)(m[t]=m[t]||new Set()).add(r.file);return m})();
const rulesFor=t=>new Set([...(RULES_FOR[t]||[]),...(RULES_FOR[t.split('.').slice(0,2).join('.')]||[])]);
const OFFHOST=new Set(INTEL.off_host_tactics);
const offHost=t=>{const ta=ATL.technique_tactics[t]||[];return ta.length&&ta.every(x=>OFFHOST.has(x))};
const AN=INTEL.analytics;
const quarterOf=d=>{const m=/^(\d{4})-(\d{2})/.exec(d||'');return m?`${m[1]}-Q${Math.floor((+m[2]-1)/3)+1}`:''};
const tacticsOf=ts=>[...new Set(ts.flatMap(t=>ATL.technique_tactics[t]||[]))];

/* Cross-filter. One facet set drives every chart, list and count on the view:
   click a bar, a matrix cell, a timeline mark or a cluster and everything else
   narrows to match. Facets that belong to actors (type, nexus, motivation,
   cluster) filter a case through the actors linked to it, so an unattributed
   case drops out of an actor-facet view rather than silently staying in. */
const IF={};
const IF_LABEL={sector:'sector',region:'region',country:'country',kind:'actor type',nexus:'nexus',
  motivation:'motivation',technique:'technique',tactic:'tactic',quarter:'quarter',cluster:'cluster',actor:'actor'};
const hasTech=(list,t)=>list.some(x=>x===t||x.startsWith(t+'.'));
function actorEvents(a){return AN.events.filter(e=>e.actor===a.id)}
function actorPasses(a){
  const d=a.derived;
  for(const [k,v] of Object.entries(IF)){
    if(k==='sector'&&!d.sectors.includes(v))return false;
    if(k==='region'&&!d.regions.includes(v))return false;
    if(k==='country'&&!d.countries.includes(v))return false;
    if(k==='kind'&&a.kind!==v)return false;
    if(k==='nexus'&&(a.nexus||'unstated')!==v)return false;
    if(k==='motivation'&&!(a.motivation||[]).includes(v))return false;
    if(k==='technique'&&!hasTech(d.techniques,v))return false;
    if(k==='tactic'&&!d.tactics.includes(v))return false;
    if(k==='quarter'&&!actorEvents(a).some(e=>quarterOf(e.date)===v))return false;
    if(k==='cluster'&&!(AN.clusters[+v]||{actors:[]}).actors.includes(a.id))return false;
    if(k==='actor'&&a.id!==v)return false;
  }
  return true;
}
const ACTOR_FACETS=new Set(['kind','nexus','motivation','cluster','actor']);
function casePasses(c){
  const v=c.victims||{};
  const regions=(v.countries||[]).map(x=>INTEL.region_of[x]).filter(Boolean);
  for(const [k,val] of Object.entries(IF)){
    if(k==='sector'&&!(v.sectors||[]).includes(val))return false;
    if(k==='region'&&!regions.includes(val))return false;
    if(k==='country'&&!(v.countries||[]).includes(val))return false;
    if(k==='technique'&&!hasTech(c.atlas||[],val))return false;
    if(k==='tactic'&&!tacticsOf(c.atlas||[]).includes(val))return false;
    if(k==='quarter'&&quarterOf(c.disclosed)!==val)return false;
  }
  if([...ACTOR_FACETS].some(k=>k in IF)){
    const linked=(c.actors||[]).map(l=>ACTORMAP[l.ref]).filter(Boolean);
    if(!linked.some(actorPasses))return false;
  }
  return true;
}
function fActors(){return INTEL.actors.filter(actorPasses)}
function fCases(){return CASES.filter(casePasses)}
function setIF(k,v){if(IF[k]===v)delete IF[k];else IF[k]=v;renderIntel()}
function techUse(t){
  const acts=fActors().filter(a=>a.derived.techniques.includes(t)).map(a=>a.id);
  const cs=fCases().filter(c=>(c.atlas||[]).includes(t)).map(c=>c.id);
  return {actors:acts,cases:cs,rules:[...rulesFor(t)]};
}
function techState(t){
  const u=techUse(t);
  if(!u.actors.length&&!u.cases.length)return u.rules.length?'covered':'';
  if(u.rules.length)return 'covered';
  return offHost(t)?'offhost':'gap';
}
function kindBadge(k){return `<span class="kind k-${esc(k)}">${esc(KIND_LABEL[k]||k)}</span>`}
function actorCard(a){
  const d=a.derived;
  return `<button class="acard" data-actor="${esc(a.id)}">
    <span class="an">${esc(a.name)}</span>
    <span>${kindBadge(a.kind)} ${a.nexus?`<span class="kind">${esc(a.nexus)}</span>`:''}
      ${(a.motivation||[]).map(m=>`<span class="kind">${esc(m)}</span>`).join(' ')}</span>
    <span class="am">${esc(a.id)} · ${a.cases.length} case${a.cases.length===1?'':'s'} ·
      ${(a.sightings||[]).length} sighting${(a.sightings||[]).length===1?'':'s'} ·
      ${d.first_seen?esc(d.first_seen)+' to '+esc(d.last_seen):'undated'}</span>
    <span class="am">${d.techniques.length} ATLAS technique${d.techniques.length===1?'':'s'} ·
      ${d.tools.length} catalogued tool${d.tools.length===1?'':'s'} ·
      ${d.iocs.length} indicator${d.iocs.length===1?'':'s'}</span>
    ${d.gaps.length?`<span class="gapn">${d.gaps.length} on-host technique${d.gaps.length>1?'s':''} with no rule</span>`:''}
  </button>`;
}
function tally(list){const o={};for(const x of list)o[x]=(o[x]||0)+1;
  return Object.fromEntries(Object.entries(o).sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0])))}
// A bar chart whose bars are filters. data-f/data-v carry the facet; the label
// map lets a bar read "state nexus" while filtering on "state-nexus".
function bars(title,facet,counts,color,label){
  const e=Object.entries(counts||{});
  if(!e.length)return `<div class="barbox"><h4>${esc(title)}</h4><p class="muted">None stated in the sources.</p></div>`;
  const max=Math.max(...e.map(x=>x[1]));
  return `<div class="barbox"><h4>${esc(title)}</h4>${e.slice(0,14).map(([k,n])=>
    `<button class="vbar${IF[facet]===k?' on':''}" data-f="${facet}" data-v="${esc(k)}"><span class="bl" title="${esc(k)}">${
      esc(label?label(k):k)}</span>
      <span class="bt"><i style="width:${(n/max*100).toFixed(1)}%;background:${color}"></i></span>
      <span class="bn">${n}</span></button>`).join('')}</div>`;
}
function matrixHTML(acts,cases){
  const use={};
  const add=(t,k,id)=>{(use[t]=use[t]||{actors:new Set(),cases:new Set()})[k].add(id)};
  for(const a of acts)for(const t of a.derived.techniques)add(t,'actors',a.id);
  for(const c of cases)for(const t of c.atlas||[])add(t,'cases',c.id);
  const layerCount=t=>{const u=use[t]||{actors:new Set(),cases:new Set()};
    return intelLayer==='actors'?u.actors.size:intelLayer==='cases'?u.cases.size:
      intelLayer==='rules'?rulesFor(t).size:(u.actors.size+u.cases.size)};
  const stateOf=t=>{const u=use[t];if(!u)return rulesFor(t).size?'covered':'';
    return rulesFor(t).size?'covered':offHost(t)?'offhost':'gap'};
  const all=Object.keys(ATL.techniques);
  const max=Math.max(1,...all.map(layerCount));
  const cols=ATL.tactic_order.map(ta=>{
    const ts=all.filter(t=>(ATL.technique_tactics[t]||[]).includes(ta))
      .filter(t=>matrixAll||layerCount(t)>0||(intelLayer==='gaps'&&use[t])).sort();
    const cells=ts.map(t=>{
      const n=layerCount(t), st=intelLayer==='gaps'?stateOf(t):'';
      const pct=intelLayer==='gaps'?0:Math.round(n/max*70);
      const bg=pct?`background:color-mix(in srgb, var(--series-1) ${pct}%, var(--panel))`:'';
      return `<button class="mcell${t.split('.').length>2?' sub':''}${n?'':' zero'}${st?' st-'+st:''}${
        techSel===t?' sel':''}" data-t="${esc(t)}" style="${bg}" title="${esc(t+' '+TNAME(t))}"
        ><span class="mid">${esc(t.replace('AML.',''))}${n?' · '+n:''}</span>${esc(TNAME(t))}</button>`}).join('');
    return `<div class="mcol"><button class="mhead${IF.tactic===ta?' on':''}" data-f="tactic" data-v="${esc(ta)}"
      title="Filter by this tactic">${esc(ATL.tactics[ta]||ta)} <i>${ts.length}</i></button>${
      cells||'<p class="muted" style="font-size:11px">none</p>'}</div>`;
  }).join('');
  return `<div class="matrix" role="group" aria-label="ATLAS matrix">${cols}</div>
    ${intelLayer==='gaps'?`<div class="mlegend"><span><i style="background:var(--gap)"></i>used, no rule</span>
      <span><i style="background:var(--covered)"></i>has a rule</span>
      <span><i style="background:var(--offhost)"></i>off-host: happens on the adversary's side, nothing to detect on an endpoint</span></div>`:''}
    ${techSel?techDetailHTML(techSel):''}`;
}
function techDetailHTML(t){
  const u=techUse(t);
  const tools=TOOLS.filter(x=>(x.atlas||[]).includes(t));
  const assoc=AN.cooccurrence.filter(r=>r.a===t||r.b===t).slice(0,6);
  return `<div class="tdetail"><h4>${esc(t)} ${esc(TNAME(t))}</h4>
    <p class="muted" style="margin:0 0 6px">${(ATL.technique_tactics[t]||[]).map(x=>esc(ATL.tactics[x]||x)).join(' · ')}
      · <a href="https://atlas.mitre.org/techniques/${esc(t)}" target="_blank" rel="noopener">ATLAS &#8599;</a>
      ${offHost(t)?' · off-host technique':''}
      · <button class="lchip" data-f="technique" data-v="${esc(t)}">${IF.technique===t?'clear filter':'filter everything to this technique'}</button></p>
    ${u.actors.length?`<b>Actors</b><div class="linkrow2">${u.actors.map(id=>
      `<button class="lchip" data-actor="${esc(id)}">${esc((ACTORMAP[id]||{}).name||id)}</button>`).join('')}</div>`:''}
    ${u.cases.length?`<b>Case studies</b><div class="linkrow2">${u.cases.map(id=>
      `<button class="lchip" data-case="${esc(id)}">${esc(id)}</button>`).join('')}</div>`:''}
    <b>Rules</b><div class="linkrow2">${u.rules.length?u.rules.map(f=>
      `<button class="lchip" data-rule="${esc(f)}">${esc(f)}</button>`).join(''):
      `<span class="muted">${offHost(t)?'None, and none expected: this happens off the endpoint.':'None. This is a coverage gap.'}</span>`}</div>
    ${tools.length?`<b>Catalogued tools mapped to it</b><div class="linkrow2">${tools.map(x=>
      `<button class="lchip" data-tool="${esc(x.entry_id)}">${esc(x.tool)}</button>`).join('')}</div>`:''}
    ${assoc.length?`<b>Reported alongside</b> <span class="muted" style="font-size:12px">(co-occurrence lift, ${AN.observations} observations)</span>
      <div class="linkrow2">${assoc.map(r=>{const o=r.a===t?r.b:r.a;return `<button class="lchip" data-tsel="${esc(o)}"
        >${esc(o)} ${esc(TNAME(o))} · lift ${r.lift}</button>`}).join('')}</div>`:''}
  </div>`;
}
// Timeline swimlane: one lane per actor, a mark per dated observation. Months on
// x. SVG by hand - no charting library, and it stays readable in both themes.
function timelineSVG(acts){
  const ev=AN.events.filter(e=>acts.some(a=>a.id===e.actor)&&(!IF.quarter||quarterOf(e.date)===IF.quarter));
  if(!ev.length)return '<p class="muted">No dated observations in this selection.</p>';
  const mon=d=>{const m=/^(\d{4})-(\d{2})/.exec(d);return m?(+m[1])*12+(+m[2]-1):0};
  const lo=Math.min(...ev.map(e=>mon(e.date))), hi=Math.max(...ev.map(e=>mon(e.date)))+1;
  const lanes=[...new Set(ev.map(e=>e.actor))].sort((x,y)=>
    Math.min(...ev.filter(e=>e.actor===x).map(e=>mon(e.date)))-Math.min(...ev.filter(e=>e.actor===y).map(e=>mon(e.date))));
  const L=150,W=Math.max(640,(hi-lo)*28+L+20),H=lanes.length*22+34;
  const X=m=>L+(m-lo)/(hi-lo)*(W-L-20);
  const ticks=[];for(let m=lo;m<=hi;m++)if(m%3===0)ticks.push(m);
  return `<div style="overflow-x:auto"><svg class="tline" width="${W}" height="${H}" role="img" aria-label="Activity timeline">
    ${ticks.map(m=>`<line x1="${X(m)}" x2="${X(m)}" y1="0" y2="${H-24}" class="tgrid"/>
      <text x="${X(m)}" y="${H-8}" class="tax" text-anchor="middle">${Math.floor(m/12)}-${String(m%12+1).padStart(2,'0')}</text>`).join('')}
    ${lanes.map((id,i)=>{const y=12+i*22,a=ACTORMAP[id]||{name:id||'unattributed'};
      const mine=ev.filter(e=>e.actor===id);const xs=mine.map(e=>X(mon(e.date)));
      return `<text x="4" y="${y+4}" class="tlab">${esc(a.name.slice(0,20))}</text>
        <line x1="${Math.min(...xs)}" x2="${Math.max(...xs)}" y1="${y}" y2="${y}" class="tspan"/>
        ${mine.map(e=>{const x=X(mon(e.date));const tip=esc(`${e.date} · ${a.name} · ${e.kind} ${e.ref} · ${e.techniques.join(', ')}`);
          return e.kind==='case'?`<rect x="${x-5}" y="${y-5}" width="10" height="10" class="tcase" data-actor="${esc(id)}" tabindex="0"><title>${tip}</title></rect>`
          :`<circle cx="${x}" cy="${y}" r="5" class="tsight" data-actor="${esc(id)}" tabindex="0"><title>${tip}</title></circle>`}).join('')}`}).join('')}
  </svg></div>
  <div class="mlegend"><span><i style="background:var(--series-3)"></i>case study</span>
    <span><i style="background:var(--series-1);border-radius:50%"></i>sighting (reported AI use)</span></div>`;
}
// Technique x actor heatmap: which adversaries share which techniques.
function heatmapHTML(acts){
  const tcount=tally(acts.flatMap(a=>a.derived.techniques));
  const ts=Object.keys(tcount).slice(0,24);
  if(!ts.length||!acts.length)return '<p class="muted">Nothing to compare in this selection.</p>';
  return `<div style="overflow-x:auto"><table class="hmap"><thead><tr><th></th>${ts.map(t=>
    `<th><button class="hmh" data-tsel="${esc(t)}" title="${esc(t+' '+TNAME(t))}">${esc(t.replace('AML.',''))}</button></th>`).join('')}</tr></thead>
    <tbody>${acts.map(a=>`<tr><th><button class="lchip" data-actor="${esc(a.id)}">${esc(a.name)}</button></th>${ts.map(t=>{
      const on=a.derived.techniques.includes(t), st=on?(rulesFor(t).size?'covered':offHost(t)?'offhost':'gap'):'';
      return `<td class="${on?'h-'+st:''}" title="${esc(a.name+' · '+t+' '+TNAME(t))}">${on?'&#9679;':''}</td>`}).join('')}</tr>`).join('')}</tbody></table></div>
    <div class="mlegend"><span><i style="background:var(--covered)"></i>has a rule</span><span><i style="background:var(--gap)"></i>no rule</span>
      <span><i style="background:var(--offhost)"></i>off-host</span></div>`;
}
function simHTML(acts){
  const ids=AN.similarity.ids.filter(id=>acts.some(a=>a.id===id));
  if(ids.length<2)return '<p class="muted">Pick a wider selection to compare actors.</p>';
  const idx=Object.fromEntries(AN.similarity.ids.map((x,i)=>[x,i]));
  const M=AN.similarity.matrix;
  return `<div style="overflow-x:auto"><table class="hmap sim"><thead><tr><th></th>${ids.map(id=>
    `<th><span class="vlab">${esc((ACTORMAP[id]||{}).name||id)}</span></th>`).join('')}</tr></thead>
    <tbody>${ids.map(r=>`<tr><th><button class="lchip" data-actor="${esc(r)}">${esc((ACTORMAP[r]||{}).name||r)}</button></th>${ids.map(c=>{
      const v=M[idx[r]][idx[c]];return `<td style="background:color-mix(in srgb, var(--series-4) ${r===c?0:Math.round(v*100)}%, var(--panel))"
        title="${esc((ACTORMAP[r]||{}).name+' ~ '+(ACTORMAP[c]||{}).name+': '+v)}">${r===c?'':v>=.2?v.toFixed(2).slice(1):''}</td>`}).join('')}</tr>`).join('')}</tbody></table></div>`;
}
function clustersHTML(){
  if(!AN.clusters.length)return '<p class="muted">No clusters at this threshold.</p>';
  return `<div class="agrid">${AN.clusters.map((c,i)=>`<button class="acard${IF.cluster===String(i)?' on':''}" data-f="cluster" data-v="${i}">
    <span class="an">Cluster ${i+1} <span class="kind">cohesion ${c.cohesion}</span>${c.thin?' <span class="kind">thin evidence</span>':''}</span>
    <span>${c.actors.map(id=>esc((ACTORMAP[id]||{}).name||id)).join(' · ')}</span>
    <span class="am">shared: ${Object.entries(c.shared).map(([k,v])=>esc(k.replace('_',' ')+' '+v.map(x=>(TOOLMAP[x]||{}).tool||x).join(', '))).join(' · ')}</span>
    ${c.thin?'<span class="am">Only off-host "used a model" evidence in common. This reflects how thinly these actors are reported, not how alike they behave.</span>':''}
  </button>`).join('')}</div>`;
}
function backlogHTML(){
  const on=AN.backlog.filter(b=>!b.off_host), off=AN.backlog.filter(b=>b.off_host);
  const row=b=>`<tr><td><button class="lchip" data-tsel="${esc(b.technique)}">${esc(b.technique)}</button> ${esc(b.name)}</td>
    <td>${b.actors}</td><td>${b.cases}</td><td><b>${b.score}</b></td></tr>`;
  return `<div class="hscroll"><table class="htable"><thead><tr><th>On-host technique with no rule</th><th>Actors</th><th>Cases</th><th>Priority</th></tr></thead>
    <tbody>${on.map(row).join('')||'<tr><td colspan="4" class="muted">None.</td></tr>'}</tbody></table></div>
    ${off.length?`<p class="muted" style="font-size:12px;margin-top:8px">Also rule-less, but off-host and so not a detection backlog item:
      ${off.map(b=>esc(b.technique.replace('AML.',''))).join(', ')}.</p>`:''}`;
}
function cooccHTML(){
  if(!AN.cooccurrence.length)return '<p class="muted">No technique pair is reported together twice yet.</p>';
  return `<div class="hscroll"><table class="htable"><thead><tr><th>Technique</th><th>Reported with</th><th>Together</th><th>Lift</th></tr></thead><tbody>${
    AN.cooccurrence.slice(0,12).map(r=>`<tr><td><button class="lchip" data-tsel="${esc(r.a)}">${esc(r.a)}</button> ${esc(TNAME(r.a))}</td>
      <td><button class="lchip" data-tsel="${esc(r.b)}">${esc(r.b)}</button> ${esc(TNAME(r.b))}</td>
      <td>${r.support}</td><td>${r.lift}</td></tr>`).join('')}</tbody></table></div>`;
}
function pivotHTML(acts,cases){
  const keys=Object.keys(IF);
  if(!keys.length)return '';
  const rules=new Set(acts.flatMap(a=>a.derived.detections_by_technique.concat(a.derived.detections_cited))
    .concat(cases.flatMap(c=>c.detections||[])));
  if(IF.technique)for(const f of rulesFor(IF.technique))rules.add(f);
  const collect=[...new Set(acts.flatMap(a=>a.derived.collect))].filter(x=>ROWMAP[x]);
  const lab=(k,v)=>k==='actor'?(ACTORMAP[v]||{}).name||v:k==='cluster'?'cluster '+(+v+1):k==='technique'?v+' '+TNAME(v):
    k==='tactic'?ATL.tactics[v]||v:k==='kind'?KIND_LABEL[v]||v:v;
  return `<div class="pivot"><div class="pchips">${keys.map(k=>`<button class="chip" data-f="${k}" data-v="${esc(IF[k])}"
    >${esc(IF_LABEL[k])}: ${esc(lab(k,IF[k]))} <s>&#10005;</s></button>`).join('')}
    <button class="chip" id="ifClear">clear all</button></div>
    <div class="pacts"><span class="muted">${acts.length} actor${acts.length===1?'':'s'} · ${cases.length} case${cases.length===1?'':'s'} match. Pivot:</span>
      ${cases.length?`<button class="btn" id="pvCases">${cases.length} case studies &#8594;</button>`:''}
      ${rules.size?`<button class="btn" id="pvRules">${rules.size} rules &#8594;</button>`:''}
      ${acts.length?`<button class="btn" id="pvGraph">graph ${acts.length} &#8594;</button>`:''}
      ${collect.length?`<button class="btn primary" id="pvPlan">add ${collect.length} rows to plan</button>`:''}</div></div>`;
}
function intelHTML(){
  const acts=fActors(), cases=fCases();
  const allAct=INTEL.actors;
  const observed=[...new Set(acts.flatMap(a=>a.derived.techniques).concat(cases.flatMap(c=>c.atlas||[])))];
  const off=observed.filter(t=>!rulesFor(t).size&&offHost(t)).length;
  const cov=observed.filter(t=>rulesFor(t).size).length;
  const atomic=cases.flatMap(c=>c.iocs||[]).filter(i=>INTEL.atomic_types.includes(i.type)).length;
  const sortA=[...acts].sort((a,b)=>(b.derived.last_seen||'').localeCompare(a.derived.last_seen||'')||a.name.localeCompare(b.name));
  const vic=cases.map(c=>c.victims||{});
  const q=tally(cases.map(c=>quarterOf(c.disclosed)).filter(Boolean));
  const qs=Object.keys(q).sort(), qmax=Math.max(1,...Object.values(q));
  const tacCount=tally(acts.flatMap(a=>a.derived.tactics).concat(cases.flatMap(c=>tacticsOf(c.atlas||[]))));
  const links=cases.flatMap(c=>(c.actors||[]).filter(l=>!IF.actor||l.ref===IF.actor).map(l=>l.link_confidence));
  const ivars=Object.keys(IF).length;
  return `<div class="gtop"><div><h2>Threat intel</h2>
    <p>Who is reported using AI tooling against whom, how, what it leaves on a host, and which
    rule in this repository catches it. Every chart below is a filter: click a bar, a tactic, a matrix
    cell, a timeline mark or a cluster, and the rest of the page narrows to match. Pivot out to the
    case studies, the rules, the graph or a collection plan from the bar that appears.</p></div>
    <div class="acts"><button class="btn" id="goGraph">Open the graph &#8594;</button>
    <a class="btn" href="${REPO_URL}/blob/main/artifacts/docs/api/stix/ai-dfir-intel.json" target="_blank" rel="noopener">STIX 2.1</a>
    <a class="btn" href="${REPO_URL}/tree/main/artifacts/docs/api/graph" target="_blank" rel="noopener">Maltego CSV</a></div></div>
  ${pivotHTML(acts,cases)}
  <div class="istats">
    <div class="istat"><b>${acts.length}${ivars?`<small>/${allAct.length}</small>`:''}</b><span>actors and named clusters</span></div>
    <div class="istat"><b>${cases.length}${ivars?`<small>/${CASES.length}</small>`:''}</b><span>case studies</span></div>
    <div class="istat"><b>${atomic}</b><span>atomic indicators</span></div>
    <div class="istat"><b>${observed.length}</b><span>ATLAS techniques observed</span></div>
    <div class="istat"><b>${cov}/${observed.length-off}</b><span>on-host techniques with a rule</span></div>
    <div class="istat"><b>${off}</b><span>off-host, nothing to detect on an endpoint</span></div>
    <div class="istat"><b>${Object.entries(tally(links)).map(([k,v])=>v+' '+k).join(' · ')||'-'}</b><span>attribution links by confidence</span></div>
  </div>
  <div class="isec"><h3>Timeline</h3><p class="lede">Every dated observation per actor: squares are case studies,
    dots are reported AI use. Hover for the techniques; click to open the profile.</p>
    ${timelineSVG(acts)}
    <div class="qbars" style="margin-top:14px">${qs.map(k=>`<button class="qbar${IF.quarter===k?' on':''}" data-f="quarter" data-v="${esc(k)}"
      title="${esc(k)}: ${q[k]} case${q[k]>1?'s':''}"><b>${q[k]}</b><i style="height:${(q[k]/qmax*85).toFixed(0)}%"></i><span>${esc(k)}</span></button>`).join('')}</div>
    <p class="muted" style="font-size:12px">Case studies by disclosure quarter. Click a quarter to filter.</p></div>
  <div class="isec"><h3>Actors <span class="n">${acts.length}</span></h3><p class="lede">Most recent activity first.
    A profile's techniques, victims, indicators and detections are derived from the cases and sightings that cite it.</p>
    <div class="agrid">${sortA.map(actorCard).join('')||'<p class="muted">No actor matches.</p>'}</div></div>
  <div class="isec"><h3>Attack map</h3><p class="lede">ATLAS ${esc(ATL.release)}, tactics in kill-chain order. Pick a
    layer; pick a technique for who uses it, what detects it and what is reported alongside it; click a tactic heading to filter.</p>
    <div class="seg small" role="group" aria-label="Matrix layer">${[['actors','Actors'],['cases','Cases'],
      ['rules','Rules'],['gaps','Coverage gaps']].map(([k,l])=>
      `<button class="segbtn${intelLayer===k?' on':''}" data-layer="${k}">${l}</button>`).join('')}</div>
    <label class="gnote" style="margin-left:10px"><input type="checkbox" id="mAll" ${matrixAll?'checked':''}>
      show every technique</label>
    ${matrixHTML(acts,cases)}</div>
  <div class="isec"><h3>Victimology and profile</h3><p class="lede">Only what the sources state. A blank sector is
    a source that did not say, not a sector nobody targeted. Sector, region and country here count case studies.</p>
    <div class="bars">${bars('Sector (cases)','sector',tally(vic.flatMap(x=>x.sectors||[])),'var(--series-1)')}
      ${bars('Region (cases)','region',tally(vic.flatMap(x=>(x.countries||[]).map(c=>INTEL.region_of[c]).filter(Boolean))),'var(--series-2)')}
      ${bars('Country (cases)','country',tally(vic.flatMap(x=>x.countries||[])),'var(--series-3)')}
      ${bars('Sector (actors)','sector',tally(acts.flatMap(a=>a.derived.sectors)),'var(--series-1)')}
      ${bars('Actor type','kind',tally(acts.map(a=>a.kind)),'var(--series-4)',k=>KIND_LABEL[k]||k)}
      ${bars('Stated nexus','nexus',tally(acts.map(a=>a.nexus||'unstated')),'var(--series-5)')}
      ${bars('Motivation','motivation',tally(acts.flatMap(a=>a.motivation||[])),'var(--series-6)')}
      ${bars('Tactics used','tactic',tacCount,'var(--series-7)',k=>ATL.tactics[k]||k)}</div></div>
  <div class="isec"><h3>Who shares which techniques</h3><p class="lede">Technique by actor for the current selection,
    coloured by whether this repository can detect it.</p>${heatmapHTML(sortA)}</div>
  <div class="isec"><h3>Detection backlog</h3><p class="lede">${esc(AN.method.backlog)}. The top of this list is
    where a new rule would cover the most reported activity.</p>${backlogHTML()}</div>
  <div class="isec"><h3>Similarity and clusters</h3><p class="lede">Unsupervised and descriptive:
    ${esc(AN.method.similarity)}; clusters are ${esc(AN.method.clusters)}. Built from what the sources
    report about ${allAct.length} actors, so it measures how alike the reporting is. It is a triage and hypothesis
    aid, never attribution.</p>
    ${clustersHTML()}<div style="margin-top:12px">${simHTML(sortA)}</div></div>
  <div class="isec"><h3>Techniques reported together</h3><p class="lede">${esc(AN.method.cooccurrence)}. Lift above 1
    means the pair appears together more often than chance, which makes the second a hunting lead when you find the first.</p>
    ${cooccHTML()}</div>`;
}
function wireIntelLinks(scope){
  $$(scope+' [data-actor]').forEach(b=>b.onclick=()=>openActorDrawer(b.dataset.actor,b));
  $$(scope+' [data-actor]').forEach(b=>{if(b.tagName!=='BUTTON')b.onkeydown=e=>{if(e.key==='Enter')openActorDrawer(b.dataset.actor,b)}});
  $$(scope+' .lchip[data-rule]').forEach(b=>b.onclick=()=>openRuleDrawer(b.dataset.rule,b));
  $$(scope+' .lchip[data-tool]').forEach(b=>b.onclick=()=>openToolDrawer(b.dataset.tool,b));
  $$(scope+' .lchip[data-case]').forEach(b=>b.onclick=()=>{
    pushNav();closeDrawer();view='cases';update();
    const el=document.getElementById('cs-'+b.dataset.case);
    if(el){el.open=true;el.scrollIntoView({block:'start'})}});
  $$(scope+' .lchip[data-anchor]').forEach(b=>b.onclick=()=>openDrawer(b.dataset.anchor,b));
}
function renderIntel(){
  const y=window.scrollY;
  $('#main').innerHTML=intelHTML();
  wireIntelLinks('#main');
  $$('#main [data-f]').forEach(b=>b.onclick=()=>setIF(b.dataset.f,b.dataset.v));
  $$('#main [data-tsel]').forEach(b=>b.onclick=()=>{techSel=b.dataset.tsel;renderIntel();
    const d=$('#main .tdetail');if(d)d.scrollIntoView({block:'center'})});
  $$('#main .segbtn[data-layer]').forEach(b=>b.onclick=()=>{intelLayer=b.dataset.layer;renderIntel()});
  const ma=$('#mAll');if(ma)ma.onchange=()=>{matrixAll=ma.checked;renderIntel()};
  $$('#main .mcell').forEach(b=>b.onclick=()=>{techSel=techSel===b.dataset.t?null:b.dataset.t;renderIntel()});
  const g=$('#goGraph');if(g)g.onclick=()=>{pushNav();view='graph';graphSeed=null;update()};
  const clr=$('#ifClear');if(clr)clr.onclick=()=>{for(const k of Object.keys(IF))delete IF[k];renderIntel()};
  const acts=fActors(),cases=fCases();
  const pc=$('#pvCases');if(pc)pc.onclick=()=>{pushNav();caseOnly=new Set(cases.map(c=>c.id));view='cases';update()};
  const pr=$('#pvRules');if(pr)pr.onclick=()=>{
    const rs=new Set(acts.flatMap(a=>a.derived.detections_by_technique.concat(a.derived.detections_cited)).concat(cases.flatMap(c=>c.detections||[])));
    if(IF.technique)for(const f of rulesFor(IF.technique))rs.add(f);
    pushNav();resetRuleFilters();ruleSet=new Set(RULES.filter(r=>rs.has(r.file)).map(r=>r.file));view='rules';update()};
  const pg=$('#pvGraph');if(pg)pg.onclick=()=>{pushNav();view='graph';graphSeed=null;
    history.replaceState(null,'','#graph/'+encodeURIComponent(acts.slice(0,40).map(a=>'actor:'+a.id).join('|')));update()};
  const pp=$('#pvPlan');if(pp)pp.onclick=()=>{const rows=[...new Set(acts.flatMap(a=>a.derived.collect))].filter(x=>ROWMAP[x]);
    const n=rows.filter(x=>!picks.has(x)).length;rows.forEach(x=>picks.add(x));savePicks();renderTabs();renderToast();
    pp.disabled=true;pp.textContent=n?`added ${n}`:'already in plan'};
  requestAnimationFrame(()=>window.scrollTo(0,y));
}
function actorDrawerHTML(a){
  const d=a.derived, base=location.origin==='null'?'':location.origin+location.pathname;
  const byTac={};
  for(const h of d.hunt){for(const ta of (h.tactics.length?h.tactics:['?']))(byTac[ta]=byTac[ta]||[]).push(h)}
  const order=[...ATL.tactic_order,'?'].filter(t=>byTac[t]);
  const collect=d.collect.map(x=>ROWMAP[x]).filter(Boolean);
  const vol={};for(const r of collect)vol[r.vol]=(vol[r.vol]||0)+1;
  const atomic=d.iocs.filter(i=>INTEL.atomic_types.includes(i.type));
  const behav=d.iocs.filter(i=>!INTEL.atomic_types.includes(i.type));
  return `<div class="dhead"><b>${esc(a.name)} <span class="mono" style="color:var(--faint);font-size:11px">${esc(a.id)}</span></b>
    <button class="x" id="dClose" aria-label="Close">&#10005;</button></div>
  <div class="dbody">
    <div class="dsec"><div class="badgerow">${kindBadge(a.kind)}${a.nexus?`<span class="kind">nexus ${esc(a.nexus)}</span>`:''}
      ${(a.motivation||[]).map(m=>`<span class="kind">${esc(m)}</span>`).join('')}${confBadge(a.confidence)}</div>
      ${(a.aliases||[]).length?`<p class="talias">also ${a.aliases.map(x=>esc(x.name)+' <span class="muted">('+esc(x.source)+')</span>').join(' · ')}</p>`:''}
      <p>${esc(a.summary)}</p>
      <p class="csbasis">${esc(a.basis)}</p>
      ${a.contested?`<div class="csdispute"><b>Disputed.</b> ${esc(a.contested)}</div>`:''}
      <div class="tmeta">${d.first_seen?`seen ${esc(d.first_seen)} to ${esc(d.last_seen)}`:'undated'}
        ${(a.external_ids||{}).attack_group?' · '+(a.external_ids.attack_group).map(g=>
          `<a href="https://attack.mitre.org/groups/${esc(g)}/" target="_blank" rel="noopener">ATT&amp;CK ${esc(g)}</a>`).join(' '):''}</div></div>
    ${a.links.length?`<div class="dsec"><h4>Attribution links <span class="n">${a.links.length}</span></h4>
      ${a.links.map(l=>`<div class="sighting"><button class="lchip" data-case="${esc(l.case)}">${esc(l.case)}</button>
        ${confBadge(l.link_confidence)} <span class="sm">${esc(l.role||'')} · by ${esc(l.attributed_by)}</span>
        ${l.stated_confidence?`<div class="sm">Stated: ${esc(l.stated_confidence)}</div>`:''}</div>`).join('')}</div>`:''}
    ${(a.sightings||[]).length?`<div class="dsec"><h4>Reported AI use <span class="n">${a.sightings.length}</span></h4>
      ${a.sightings.map(s=>`<div class="sighting"><div class="sm">${esc(s.date)} · ${esc(s.reporter)}
        ${(s.ai_services||[]).length?' · '+esc(s.ai_services.join(', ')):''}</div>${esc(s.summary)}
        <div class="sm"><a href="${esc(s.reference)}" target="_blank" rel="noopener">source &#8599;</a></div></div>`).join('')}</div>`:''}
    ${(AN.neighbours[a.id]||[]).length?`<div class="dsec"><h4>Most similar actors</h4>
      ${AN.neighbours[a.id].map(n=>`<div class="sighting"><button class="lchip" data-actor="${esc(n.actor)}">${esc((ACTORMAP[n.actor]||{}).name||n.actor)}</button>
        <span class="sm">similarity ${n.score} · shared ${Object.entries(n.shared).map(([k,v])=>esc(k.replace('_',' ')+': '+v.map(x=>(TOOLMAP[x]||{}).tool||x).join(', '))).join(' · ')}</span></div>`).join('')}
      <p class="muted" style="font-size:11px;margin:4px 0 0">Similarity of what is reported, for pivoting. Not attribution.</p></div>`:''}
    <div class="dsec"><h4>Hunt &#8594; detect <span class="n">${d.hunt.length}</span></h4>
      ${d.hunt.length?`<table class="htable"><thead><tr><th>Tactic</th><th>Technique</th><th>Rules in this repo</th></tr></thead><tbody>
      ${order.map(ta=>byTac[ta].map((h,i)=>`<tr>${i?'<td></td>':`<td>${esc(ATL.tactics[ta]||'')}</td>`}
        <td><span class="tchip" data-tech="${esc(h.technique)}">${esc(h.technique)}</span> ${esc(h.name)}</td>
        <td class="${h.rules.length?'':h.off_host?'off':'gap'}">${h.rules.length?h.rules.map(f=>
          `<button class="lchip" data-rule="${esc(f)}">${esc(f)}</button>`).join(' '):h.off_host?'off-host':'no rule'}</td></tr>`).join('')).join('')}
      </tbody></table>`:'<p class="muted">No techniques recorded.</p>'}
      ${(d.owasp_agentic||[]).length?`<p class="tmeta">OWASP Agentic: ${d.owasp_agentic.map(x=>esc(x+' '+(INTEL.asi[x]||''))).join(' · ')}</p>`:''}</div>
    <div class="dsec"><h4>Collect <span class="n">${collect.length}</span></h4>
      ${collect.length?`<p style="margin:0 0 6px">From the catalogued tools this actor is reported to have used or targeted:
        ${d.tools.map(t=>`<button class="lchip" data-tool="${esc(t)}">${esc((TOOLMAP[t]||{}).tool||t)}</button>`).join(' ')}</p>
        <div class="badgerow">${VOL_TIERS.filter(v=>vol[v]).map(v=>`<span class="badge vol v-${v}"><i>${vol[v]}</i>${v}</span>`).join('')}</div>
        <div class="linkrow2" style="max-height:170px;overflow:auto">${collect.slice(0,60).map(r=>
          `<button class="lchip" data-anchor="${esc(r.anchor)}" title="${esc(r.tool+' · '+r.vol)}">${esc(r.artifact.slice(0,60))}</button>`).join('')}</div>`
        :'<p class="muted">No catalogued tool is linked, so there is nothing tool-specific to collect. Use the case indicators.</p>'}</div>
    <div class="dsec"><h4>Indicators <span class="n">${d.iocs.length}</span></h4>
      ${atomic.length?`<p class="tmeta">${atomic.length} atomic, from ${[...new Set(atomic.map(i=>i.case))].map(esc).join(', ')}. Full list in the case study and the STIX feed.</p>
        <div class="iocs">${atomic.slice(0,24).map(i=>`<span class="ioc" title="${esc(i.description||'')}">${esc(i.value)}<em>${esc(i.type)}</em></span>`).join('')}</div>`:''}
      ${behav.length?`<ul class="fplist">${behav.slice(0,10).map(i=>`<li><b>${esc(i.type)}</b> ${esc(i.value)}</li>`).join('')}</ul>`:''}
      ${d.iocs.length?'':'<p class="muted">None published.</p>'}</div>
    ${d.recovery.length?`<div class="dsec"><h4>Response and recovery <span class="n">${d.recovery.length}</span></h4>
      <ol class="csact">${d.recovery.map(r=>`<li>${r.phase?`<span class="phase ph-${esc(r.phase)}">${esc(r.phase)}</span> `:''}${esc(r.action)}
        <span class="muted" style="font-size:11px">(${esc(r.case)})</span></li>`).join('')}</ol></div>`:''}
    ${(d.sectors.length||d.countries.length)?`<div class="dsec"><h4>Victimology</h4>
      <p>${d.sectors.map(esc).join(' · ')}${d.countries.length?' — '+d.countries.map(esc).join(', '):''}</p></div>`:''}
    <div class="dsec"><h4>Sources <span class="n">${a.references.length}</span></h4>
      <ul class="drefs">${a.references.map(r=>`<li><a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(r.title)}</a></li>`).join('')}</ul></div>
    <div class="dsec"><h4>Permalink</h4><div class="linkrow">
      <input readonly value="#actor/${esc(a.id)}" aria-label="Permalink">
      <button class="btn" id="dCopyLink" data-v="${esc(base+'#actor/'+a.id)}">copy link</button></div></div>
  </div>
  <div class="dfoot">
    <button class="btn" id="dGraph">Open in graph</button>
    ${collect.length?`<button class="btn primary" id="dPickActor">Add ${collect.length} to plan</button>`:''}
  </div>`;
}
function openActorDrawer(id,fromEl){
  const a=ACTORMAP[id]; if(!a)return;
  lastFocus=fromEl||document.activeElement;
  const d=$('#drawer');
  d.innerHTML=actorDrawerHTML(a);
  d.hidden=false;
  d.setAttribute('aria-label','Threat actor '+a.name);
  history.replaceState(null,'','#actor/'+a.id);
  $('#dClose').onclick=closeDrawer;
  $('#dClose').focus();
  $('#dCopyLink').onclick=e=>copy(e.target.dataset.v,e.target);
  wireIntelLinks('#drawer');
  wireTechChips();
  $('#dGraph').onclick=()=>{pushNav();closeDrawer();graphSeed='actor:'+a.id;view='graph';update()};
  const p=$('#dPickActor');
  if(p)p.onclick=()=>{
    const add=a.derived.collect.filter(x=>ROWMAP[x]&&!picks.has(x));
    a.derived.collect.forEach(x=>{if(ROWMAP[x])picks.add(x)});
    savePicks();update();p.disabled=true;p.textContent=add.length?`Added ${add.length}`:'Already in plan';
  };
}

/* ---------- graph workbench ----------
   A Maltego-style researcher view over the same derived graph the STIX and
   Maltego feeds export. Starts small - a seed and its neighbours - and grows by
   expansion, because 500 nodes at once is a hairball, not an investigation.
   Cytoscape is inlined as inert text and only evaluated the first time this view
   opens, so the catalog does not pay for it. */
const GNODE=Object.fromEntries(GRAPH.nodes.map(n=>[n.id,n]));
const GADJ=(()=>{const m={};for(const e of GRAPH.edges){
  (m[e.source]=m[e.source]||[]).push({id:e.target,rel:e.rel,dir:'out'});
  (m[e.target]=m[e.target]||[]).push({id:e.source,rel:e.rel,dir:'in'})}return m})();
const GTYPES=['actor','case','tool','artifact','rule','technique','tactic','asi','ioc','malware','sector','country','region','attack-group','attack-campaign'];
const GCOLOR={actor:'--series-6',case:'--series-3',tool:'--series-1',artifact:'--series-8',rule:'--series-2',
  technique:'--series-4',tactic:'--series-4',asi:'--series-5',ioc:'--series-7',malware:'--series-6',
  sector:'--series-5',country:'--series-7',region:'--series-7','attack-group':'--series-6','attack-campaign':'--series-3'};
const GSHAPE={actor:'hexagon',case:'round-rectangle',tool:'ellipse',artifact:'rectangle',rule:'diamond',
  technique:'triangle',tactic:'vee',asi:'star',ioc:'tag',malware:'octagon',sector:'barrel',country:'round-tag',
  region:'round-tag','attack-group':'hexagon','attack-campaign':'round-rectangle'};
let cy=null, graphSeed=null, gHidden=new Set(['artifact','tactic','region']), gPathMode=false, gPathFrom=null;
// cose's repulsion is in its own units - the default is 2048 per node pair, and
// anything under ~1e5 leaves labelled nodes stacked on each other.
const COSE=()=>({name:'cose',animate:false,fit:true,padding:40,nodeDimensionsIncludeLabels:true,
  nodeRepulsion:()=>450000,nodeOverlap:30,idealEdgeLength:()=>110,edgeElasticity:()=>80,gravity:.4,numIter:1500});
function cssVar(n){return getComputedStyle(document.documentElement).getPropertyValue(n).trim()||'#888'}
function loadCyto(){
  if(window.cytoscape)return true;
  const src=document.getElementById('cyto-src');
  if(!src)return false;
  const s=document.createElement('script');s.textContent=src.textContent;document.head.appendChild(s);
  return !!window.cytoscape;
}
function graphHTML(){
  return `<div class="gtop"><div><h2>Graph</h2>
    <p>Actors, cases, catalogued tools, rules, techniques and indicators as one graph. Double-click
    a node to expand it; select two and find the path between them. Artifact rows, tactics and regions
    are hidden until you ask for them, so the first view stays readable.</p></div>
    <div class="acts"><button class="btn" id="gBackIntel">&#8592; Threat intel</button></div></div>
  <div class="gwrap">
    <div class="gpane">
      <h4>Find</h4>
      <input class="gsearch" id="gq" type="search" placeholder="actor, tool, CVE, domain..." aria-label="Search the graph">
      <div class="gres" id="gres"></div>
      <h4>Show types</h4>
      <div class="tfilter">${GTYPES.map(t=>`<label><input type="checkbox" data-gt="${t}" ${gHidden.has(t)?'':'checked'}
        ><span class="dot2" style="background:var(${GCOLOR[t]})"></span>${esc(t)}</label>`).join('')}</div>
      <h4>Layout</h4>
      <div class="gbtns">${['cose','concentric','breadthfirst','circle'].map(l=>
        `<button class="btn" data-lay="${l}">${l}</button>`).join('')}</div>
      <h4>Actions</h4>
      <div class="gbtns">
        <button class="btn" id="gExpand">Expand selected</button>
        <button class="btn" id="gHide">Hide selected</button>
        <button class="btn" id="gPath" aria-pressed="false">Path: pick 2</button>
        <button class="btn" id="gAll">All actors</button>
        <button class="btn" id="gClear">Clear</button>
      </div>
      <h4>Export view</h4>
      <div class="gbtns"><button class="btn" id="gPng">PNG</button><button class="btn" id="gJson">JSON</button>
        <button class="btn" id="gCsv">Maltego CSV</button></div>
      <p class="gnote" id="gstat"></p>
    </div>
    <div id="cy" role="img" aria-label="Entity graph. Use the Find box and the neighbour list to navigate by keyboard."></div>
    <div class="gpane" id="ginfo"><p class="gnote">Select a node.</p></div>
  </div>`;
}
function gEls(ids){
  const els=[], have=new Set(ids);
  for(const id of ids){const n=GNODE[id];if(!n)continue;
    els.push({group:'nodes',data:{id,label:n.label.length>42?n.label.slice(0,40)+'…':n.label,type:n.type}})}
  for(const e of GRAPH.edges)if(have.has(e.source)&&have.has(e.target))
    els.push({group:'edges',data:{id:e.source+'>'+e.rel+'>'+e.target,source:e.source,target:e.target,rel:e.rel}});
  return els;
}
function gAdd(ids,center){
  const fresh=ids.filter(id=>GNODE[id]&&!gHidden.has(GNODE[id].type)&&cy.getElementById(id).empty());
  if(!fresh.length){gStat();return}
  const cur=cy.nodes().map(n=>n.id());
  const els=gEls([...cur,...fresh]).filter(e=>cy.getElementById(e.data.id).empty());
  const pos=center&&cy.getElementById(center).nonempty()?cy.getElementById(center).position():null;
  cy.add(els.map(e=>pos&&e.group==='nodes'?{...e,position:{x:pos.x+(Math.random()-.5)*160,y:pos.y+(Math.random()-.5)*160}}:e));
  cy.layout({...COSE(),randomize:false}).run();
  gStat();gHash();
}
function gExpand(id){gAdd((GADJ[id]||[]).map(x=>x.id),id)}
function gStat(){const s=$('#gstat');if(s)s.textContent=`${cy.nodes().length} nodes · ${cy.edges().length} edges on canvas`}
function gHash(){
  const ids=cy.nodes().map(n=>n.id());
  if(ids.length<=40)history.replaceState(null,'','#graph/'+encodeURIComponent(ids.join('|')));
}
function gInfo(id){
  const n=GNODE[id], box=$('#ginfo'); if(!n||!box)return;
  const nb=(GADJ[id]||[]);
  const byRel={};for(const x of nb)(byRel[x.rel+' ('+x.dir+')']=byRel[x.rel+' ('+x.dir+')']||[]).push(x.id);
  const open=n.type==='actor'?`<button class="btn" data-open="actor">Open profile</button>`:
    n.type==='rule'?`<button class="btn" data-open="rule">Open rule</button>`:
    n.type==='tool'?`<button class="btn" data-open="tool">Open tool</button>`:
    n.type==='artifact'?`<button class="btn" data-open="artifact">Open artifact</button>`:
    n.type==='case'?`<button class="btn" data-open="case">Open case study</button>`:
    n.type==='technique'&&n.framework==='ATLAS'?`<a class="btn" href="https://atlas.mitre.org/techniques/${esc(id.split(':')[1])}" target="_blank" rel="noopener">ATLAS &#8599;</a>`:'';
  box.innerHTML=`<h4>${esc(n.type)}</h4><p><b>${esc(n.label)}</b></p>
    <p class="gnote mono">${esc(id)}</p><div class="gbtns">${open}
    <button class="btn" data-exp="1">Expand (${nb.length})</button></div>
    <h4>Neighbours</h4><div class="nbl">${Object.entries(byRel).map(([rel,ids])=>
      `<span class="rel">${esc(rel)} · ${ids.length}</span>${ids.slice(0,30).map(x=>
        `<button data-add="${esc(x)}"><span class="dot2" style="background:var(${GCOLOR[(GNODE[x]||{}).type]||'--faint'})"></span>${
        esc(((GNODE[x]||{}).label||x).slice(0,60))}</button>`).join('')}`).join('')}</div>`;
  box.querySelector('[data-exp]').onclick=()=>gExpand(id);
  box.querySelectorAll('[data-add]').forEach(b=>b.onclick=()=>{const t=GNODE[b.dataset.add];
    if(t&&gHidden.has(t.type)){gHidden.delete(t.type);const cb=$(`#main input[data-gt="${t.type}"]`);if(cb)cb.checked=true}
    gAdd([b.dataset.add],id);cy.getElementById(b.dataset.add).select();gInfo(b.dataset.add)});
  const o=box.querySelector('[data-open]');
  if(o)o.onclick=()=>{const k=o.dataset.open, v=id.split(':').slice(1).join(':');
    if(k==='actor')openActorDrawer(v,o);else if(k==='rule')openRuleDrawer(v,o);
    else if(k==='tool')openToolDrawer(v,o);else if(k==='artifact')openDrawer(v,o);
    else{pushNav();view='cases';update();const el=document.getElementById('cs-'+v);if(el){el.open=true;el.scrollIntoView()}}};
}
function gPath(a,b){
  // Breadth-first over the full graph, not the canvas, so a path can surface
  // nodes nobody has expanded yet - which is usually the point of asking.
  const prev={[a]:null},q=[a];
  while(q.length){const x=q.shift();if(x===b)break;
    for(const y of (GADJ[x]||[]))if(!(y.id in prev)){prev[y.id]=x;q.push(y.id)}}
  if(!(b in prev))return null;
  const path=[];for(let x=b;x;x=prev[x])path.unshift(x);return path;
}
function renderGraph(){
  $('#main').innerHTML=graphHTML();
  $('#gBackIntel').onclick=()=>{view='intel';update()};
  if(!loadCyto()){$('#cy').innerHTML='<p class="gnote" style="padding:12px">Graph library unavailable in this build.</p>';return}
  const style=[
    {selector:'node',style:{'label':'data(label)','font-size':9,'color':cssVar('--ink'),'text-valign':'bottom',
      'text-margin-y':3,'width':18,'height':18,'border-width':1,'border-color':cssVar('--line'),
      'text-wrap':'ellipsis','text-max-width':110}},
    ...GTYPES.map(t=>({selector:`node[type="${t}"]`,style:{'background-color':cssVar(GCOLOR[t]),'shape':GSHAPE[t]}})),
    {selector:'node[type="actor"]',style:{'width':30,'height':30,'font-size':11,'font-weight':'bold'}},
    {selector:'node:selected',style:{'border-width':3,'border-color':cssVar('--accent')}},
    {selector:'node.path',style:{'border-width':4,'border-color':cssVar('--gap')}},
    {selector:'edge',style:{'width':1,'line-color':cssVar('--line'),'target-arrow-shape':'triangle',
      'target-arrow-color':cssVar('--line'),'curve-style':'bezier','arrow-scale':.6,'label':'data(rel)',
      'font-size':7,'color':cssVar('--faint'),'text-rotation':'autorotate'}},
    {selector:'edge.path',style:{'width':3,'line-color':cssVar('--gap'),'target-arrow-color':cssVar('--gap')}},
  ];
  cy=window.cytoscape({container:$('#cy'),elements:[],style,wheelSensitivity:.25,minZoom:.1,maxZoom:1.4});
  const fromHash=decodeURIComponent(location.hash.slice(1));
  let seed=[];
  if(fromHash.startsWith('graph/'))seed=fromHash.slice(6).split('|').filter(x=>GNODE[x]);
  if(!seed.length&&graphSeed&&GNODE[graphSeed])seed=[graphSeed,...(GADJ[graphSeed]||[]).map(x=>x.id)];
  if(!seed.length)seed=GRAPH.nodes.filter(n=>n.type==='actor').map(n=>n.id);
  seed.forEach(id=>{const t=(GNODE[id]||{}).type;if(t&&gHidden.has(t)&&seed.length<40)gHidden.delete(t)});
  cy.add(gEls(seed.filter(id=>!gHidden.has((GNODE[id]||{}).type))));
  cy.layout(COSE()).run();
  gStat();
  cy.on('dbltap','node',e=>gExpand(e.target.id()));
  cy.on('tap','node',e=>{const id=e.target.id();gInfo(id);
    if(gPathMode){if(!gPathFrom){gPathFrom=id;$('#gPath').textContent='Path: pick 2nd'}
      else{const p=gPath(gPathFrom,id);cy.elements().removeClass('path');
        if(p){gAdd(p,gPathFrom);p.forEach((x,i)=>{cy.getElementById(x).addClass('path');
          if(i)cy.edges().filter(ed=>(ed.source().id()===p[i-1]&&ed.target().id()===x)||(ed.source().id()===x&&ed.target().id()===p[i-1])).addClass('path')})}
        else $('#gstat').textContent='No path between those two.';
        gPathMode=false;gPathFrom=null;$('#gPath').setAttribute('aria-pressed','false');$('#gPath').textContent='Path: pick 2'}}});
  $('#gq').oninput=e=>{const q=e.target.value.trim().toLowerCase();
    $('#gres').innerHTML=q.length<2?'':GRAPH.nodes.filter(n=>n.label.toLowerCase().includes(q)||n.id.toLowerCase().includes(q))
      .slice(0,25).map(n=>`<button data-go="${esc(n.id)}"><span class="dot2" style="background:var(${GCOLOR[n.type]})"></span>${esc(n.label.slice(0,50))}
        <span class="gnote">${esc(n.type)}</span></button>`).join('');
    $$('#gres [data-go]').forEach(b=>b.onclick=()=>{const id=b.dataset.go,t=GNODE[id].type;
      if(gHidden.has(t)){gHidden.delete(t);const cb=$(`#main input[data-gt="${t}"]`);if(cb)cb.checked=true}
      gAdd([id]);const el=cy.getElementById(id);cy.$(':selected').unselect();el.select();cy.center(el);gInfo(id)})};
  $$('#main input[data-gt]').forEach(cb=>cb.onchange=()=>{const t=cb.dataset.gt;
    if(cb.checked)gHidden.delete(t);else{gHidden.add(t);cy.nodes(`[type="${t}"]`).remove()}gStat()});
  $$('#main [data-lay]').forEach(b=>b.onclick=()=>cy.layout(b.dataset.lay==='cose'?COSE():{name:b.dataset.lay,animate:false,padding:40,spacingFactor:1.3,nodeDimensionsIncludeLabels:true}).run());
  $('#gExpand').onclick=()=>cy.$('node:selected').forEach(n=>gExpand(n.id()));
  $('#gHide').onclick=()=>{cy.$('node:selected').remove();gStat();gHash()};
  $('#gClear').onclick=()=>{cy.elements().remove();gStat();$('#ginfo').innerHTML='<p class="gnote">Select a node.</p>'};
  $('#gAll').onclick=()=>gAdd(GRAPH.nodes.filter(n=>n.type==='actor').map(n=>n.id));
  $('#gPath').onclick=()=>{gPathMode=!gPathMode;gPathFrom=null;$('#gPath').setAttribute('aria-pressed',String(gPathMode));
    $('#gPath').textContent=gPathMode?'Path: pick 1st':'Path: pick 2'};
  $('#gPng').onclick=()=>{const a=document.createElement('a');a.href=cy.png({full:true,scale:2,bg:cssVar('--panel')});
    a.download=`ai-dfir-graph-${stamp()}.png`;document.body.appendChild(a);a.click();a.remove()};
  $('#gJson').onclick=()=>download(`ai-dfir-graph-${stamp()}.json`,JSON.stringify({source:REPO_URL,
    nodes:cy.nodes().map(n=>GNODE[n.id()]),edges:cy.edges().map(e=>e.data())},null,2),'application/json');
  $('#gCsv').onclick=()=>{const ids=new Set(cy.nodes().map(n=>n.id()));
    const val=id=>{const n=GNODE[id];return n.type==='ioc'?n.label:id};
    const typ=id=>{const n=GNODE[id];return n.type==='ioc'?({domain:'maltego.Domain',ip:'maltego.IPv4Address',url:'maltego.URL',
      email:'maltego.EmailAddress',hash:'maltego.Hash',file:'maltego.File'}[n.ioc_type]||'maltego.Phrase'):
      (n.type==='country'||n.type==='region')?'maltego.Location':'maltego.Phrase'};
    const ent='EntityType,Value,Category,Label\n'+[...ids].map(id=>[typ(id),val(id),GNODE[id].type,GNODE[id].label].map(csvCell).join(',')).join('\n');
    const lnk='SourceType,SourceValue,TargetType,TargetValue,Relationship\n'+cy.edges().map(e=>{const d=e.data();
      return [typ(d.source),val(d.source),typ(d.target),val(d.target),d.rel].map(csvCell).join(',')}).join('\n');
    download(`ai-dfir-graph-entities-${stamp()}.csv`,ent+'\n','text/csv');
    setTimeout(()=>download(`ai-dfir-graph-links-${stamp()}.csv`,lnk+'\n','text/csv'),300)};
  if(graphSeed&&cy.getElementById(graphSeed).nonempty()){cy.getElementById(graphSeed).select();gInfo(graphSeed)}
}

/* ---------- triage script builder ----------
   Turns the collection plan into a script for the host in front of you. The
   templates are fixed and live in scripts/site_scripts.py; this only writes the
   target lines, from specs triage_spec.py computed at build time. */
let triageOS='win', triageFw='native';
const psq=s=>"'"+String(s??'').replace(/'/g,"''")+"'";
const shq=s=>"'"+String(s??'').replace(/'/g,"'\\''")+"'";
function planRowsOrdered(){
  return [...picks].map(a=>ROWMAP[a]).filter(Boolean)
    .sort((a,b)=>(VOL_ORDER[a.vol]??9)-(VOL_ORDER[b.vol]??9)||(RANK[a.forensic_value]??9)-(RANK[b.forensic_value]??9));
}
function triageTargets(os){
  const out={lines:[],n:0,manual:0,skipped:0};
  for(const r of planRowsOrdered()){
    const s=r.spec||{kind:'manual',why:'no collection spec'};
    const base=os==='win'?`a=${psq(r.anchor)};tool=${psq(r.tool)};c=${psq(r.cls)}`:'';
    const push=l=>{out.lines.push(l);out.n++};
    if(s.kind==='path'){
      const ts=s[os]||[];
      if(!ts.length){
        if(s.win.length||s.mac.length||s.linux.length){out.skipped++;continue}
        out.manual++;
      }
      for(const t of ts)push(os==='win'?`  @{${base};k='path';p=${psq(t)};s=$${s.secret?'true':'false'}}`
        :`P ${shq(r.anchor)} ${shq(r.tool)} ${shq(r.cls)} ${s.secret?1:0} ${shq(t)}`);
    }else if(s.kind==='registry'||s.kind==='eventlog'){
      if(os!=='win'){out.skipped++;continue}
      push(s.kind==='registry'?`  @{${base};k='registry';p=${psq(s.win[0])};s=$${s.secret?'true':'false'}}`
        :`  @{${base};k='eventlog';p=${psq(s.channel)}}`);
    }else if(s.kind==='process'){
      push(os==='win'?`  @{${base};k='process';n=@(${s.names.map(n=>psq(n.replace(/\.exe$/i,''))).join(',')})}`
        :`PROC ${shq(r.anchor)} ${shq(r.tool)} ${shq(s.names.map(n=>n.replace(/[^\w.\-]/g,'')).join('|'))}`);
    }else if(s.kind==='network'){
      push(os==='win'?`  @{${base};k='network';ports=@(${(s.ports||[]).join(',')});hosts=@(${(s.hosts||[]).map(psq).join(',')})}`
        :`NET ${shq(r.anchor)} ${shq(r.tool)} ${shq([...(s.ports||[]),...(s.hosts||[])].join(' '))}`);
    }else{
      out.manual++;
      push(os==='win'?`  @{${base};k='manual';why=${psq(r.artifact+' - '+(s.why||''))}}`
        :`MANUAL ${shq(r.anchor)} ${shq(r.tool)} ${shq(r.cls)} ${shq(r.artifact+' - '+(s.why||''))}`);
    }
  }
  return out;
}
function triageScript(os){
  const p=activePlan()||{};
  const t=triageTargets(os);
  const name=(p.name||'ai-triage').replace(/[^\w.-]+/g,'_').slice(0,40)||'ai-triage';
  const meta=`plan: ${(p.name||'untitled').replace(/[\r\n]/g,' ')} | host: ${(p.host||'-').replace(/[\r\n]/g,' ')} | generated ${new Date().toISOString()} | ${t.n} targets | ${REPO_URL}`;
  const tpl=os==='win'?TRIAGE_PS1:TRIAGE_SH;
  // Secret patterns from the whole catalog: tokens become wildcards, a
  // directory becomes "everything under it".
  const sec=[...new Set(ROWS.filter(r=>r.spec&&r.spec.kind==='path'&&r.spec.secret)
    .flatMap(r=>r.spec[os]||[]).map(x=>x.replace(/\{(HOME|REPO)\}/g,'*').replace(/[\\/]$/,m=>m+'*')))].sort();
  const secBlock=os==='win'?sec.map(x=>'  '+psq(x)).join('\n'):sec.map(x=>x.replace(/'/g,'')).join('\n');
  const body=(os==='win'?t.lines.join('\n'):t.lines.join('\n'));
  return {name:name+(os==='win'?'.ps1':'.sh'),t,text:tpl.split('__META__').join(meta).split('__NAME__').join(name)
    .replace('__TARGETS__',()=>body||(os==='win'?'':': # no targets'))
    .replace('__SECRETS__',()=>secBlock)};
}
function triageHTML(){
  if(!picks.size)return '';
  const osL={win:'Windows (PowerShell)',mac:'macOS (bash)',linux:'Linux (bash)'};
  const sc=triageScript(triageOS);
  const tools=[...new Set(planRowsOrdered().map(r=>r.entry_id))].map(id=>TOOLMAP[id]).filter(Boolean);
  const velo=tools.filter(t=>t.velo).map(t=>t.velo), kape=tools.filter(t=>t.kape).map(t=>t.kape);
  return `<div class="tbuild"><h3>Triage script</h3>
    <p class="gnote">Collection without writing one. Pick how you will collect; the native script is the
    default because it needs nothing installed on the host.</p>
    <div class="seg small" role="group" aria-label="Collection method">${[['native','Native script'],['velo','Velociraptor'],
      ['kape','KAPE'],['py','Python collector']].map(([k,l])=>`<button class="segbtn${triageFw===k?' on':''}" data-fw="${k}">${l}</button>`).join('')}</div>
    ${triageFw==='native'?`
      <div class="seg small" role="group" aria-label="Operating system" style="margin-top:8px">${Object.entries(osL).map(([k,l])=>
        `<button class="segbtn${triageOS===k?' on':''}" data-os="${k}">${l}</button>`).join('')}</div>
      <p class="tcount">${sc.t.n} target line${sc.t.n===1?'':'s'} for ${esc(osL[triageOS])}${sc.t.manual?` · ${sc.t.manual} need a person (written to the manifest as manual)`:''}${
        sc.t.skipped?` · ${sc.t.skipped} do not apply to this OS`:''}. Volatile state first; credentials hashed, not copied, unless you pass
        ${triageOS==='win'?'<code>-CollectSecrets</code>':'<code>--collect-secrets</code>'}. Repository-scoped rows need
        ${triageOS==='win'?'<code>-RepoPath</code>':'<code>--repo</code>'}; limit to one user with
        ${triageOS==='win'?'<code>-HomePath</code>':'<code>--home</code>'}.</p>
      <div class="gbtns"><button class="btn primary" id="tDl">Download ${esc(sc.name)}</button>
        <button class="btn" id="tCopy">Copy</button></div>
      <details><summary class="gnote">Preview</summary><pre>${esc(sc.text)}</pre></details>`
    :triageFw==='velo'?`<div class="fw"><div class="fwc"><h4>Velociraptor</h4>
      <p>Best for a fleet, or when you already run it. Import the artifact definitions from the feed, then collect.</p>
      ${velo.length?`<code>velociraptor --definitions artifacts/docs/api/velociraptor/ artifacts collect ${velo.map(esc).join(' ')} --output triage.zip</code>`
        :'<p>No picked tool has a Velociraptor artifact.</p>'}
      <p style="margin-top:6px"><a href="${REPO_URL}/tree/main/artifacts/docs/api/velociraptor" target="_blank" rel="noopener">artifact definitions &#8599;</a>
      · <code style="display:inline">Custom.AIAgents.Triage</code> collects every catalogued tool.</p></div></div>`
    :triageFw==='kape'?`<div class="fw"><div class="fwc"><h4>KAPE (Windows)</h4>
      <p>Best if your Windows triage already runs through KAPE. Copy the .tkape targets into KAPE's Targets folder.</p>
      ${kape.length?`<code>kape.exe --tsource C: --tdest D:\\kape_out --target ${kape.map(esc).join(',')} --vhdx triage</code>`
        :'<p>No picked tool has a KAPE target.</p>'}
      <p style="margin-top:6px"><a href="${REPO_URL}/tree/main/artifacts/docs/api/kape" target="_blank" rel="noopener">targets &#8599;</a>
      · <code style="display:inline">AIAgents_P1</code> is the priority-one compound target.</p></div></div>`
    :`<div class="fw"><div class="fwc"><h4>Python collector</h4>
      <p>The repository's cross-platform collector, driven by collectors/targets.yaml. Needs Python 3 and PyYAML on the host.</p>
      <code>python3 collectors/collect_ai_artifacts.py --case-id IR-001 --operator you --output ./cases --project-dir /path/to/repo</code>
      <p style="margin-top:6px">Add <code style="display:inline">--dry-run</code> to enumerate and hash without copying.</p></div></div>`}
  </div>`;
}
function wireTriage(){
  $$('#main .segbtn[data-fw]').forEach(b=>b.onclick=()=>{triageFw=b.dataset.fw;renderMain()});
  $$('#main .segbtn[data-os]').forEach(b=>b.onclick=()=>{triageOS=b.dataset.os;renderMain()});
  const dl=$('#tDl');if(dl)dl.onclick=()=>{const s=triageScript(triageOS);
    download(s.name,s.text.replace(/\r?\n/g,triageOS==='win'?'\r\n':'\n'),'text/plain');flash(dl,'downloaded')};
  const cp=$('#tCopy');if(cp)cp.onclick=()=>copy(triageScript(triageOS).text,cp);
}
"""
