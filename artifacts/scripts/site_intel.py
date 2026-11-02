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
.skiplist{margin:2px 0 8px;padding-left:18px;font-size:12px}
.skiplist .lnk{background:none;border:0;color:var(--accent);cursor:pointer;padding:0;font-size:12px;text-align:left}
.skiplist .lnk:hover{text-decoration:underline}
.fwskip{margin-top:8px}
.tbuild .tsum{display:flex;flex-wrap:wrap;gap:6px 10px;align-items:center;margin:8px 0 2px}
.tbuild .tsum2{margin:2px 0 6px}
.tchip{font-size:11.5px;border:1px solid var(--line);border-radius:999px;padding:1px 9px;color:var(--muted)}
.tchip b{color:var(--ink)}
.tchip.t-hash,.tchip.t-repo,.tchip.t-manual{border-style:dashed}
.tchip.t-secret{border-color:var(--gap);color:var(--gap)}.tchip.t-secret b{color:var(--gap)}
.tchip.t-skip{opacity:.7}
.tconf{display:inline-flex;height:8px;width:120px;border-radius:3px;overflow:hidden;background:var(--line-soft);margin-left:4px}
.tconf .cs{display:block;height:100%}
.tconf .c-high{background:var(--conf-strong)}.tconf .c-med{background:var(--series-3)}.tconf .c-low{background:var(--gap)}
.brun{margin:6px 0 10px}.brun ol{margin:6px 0 0;padding-left:18px;font-size:12.5px;color:var(--muted)}.brun li{margin:3px 0}
.tform{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px 12px;margin:10px 0 6px}
.tform label{display:flex;flex-direction:column;gap:3px;font-size:11.5px;color:var(--muted)}
.tform input:not([type=checkbox]){border:1px solid var(--field-line,var(--line));border-radius:7px;padding:6px 9px;font-size:13px;background:var(--bg);color:var(--ink)}
.tform label.tog{flex-direction:row;align-items:center;gap:6px;color:var(--ink);font-size:12.5px;grid-column:1/-1}
.tform label.tog input{margin:0}
.cmdwrap{position:relative;margin:4px 0 8px}
.cmdwrap .mini{position:absolute;right:6px;top:6px;font-size:11px;padding:2px 8px}
.tcmd{margin:0;white-space:pre-wrap;word-break:break-all;font-size:12px;background:var(--panel-2);border:1px solid var(--line-soft);border-radius:8px;padding:10px 64px 10px 12px;max-height:none}
.need{font-size:10.5px;border-radius:4px;padding:0 5px;margin-left:6px;white-space:nowrap;color:var(--muted);border:1px dashed var(--line)}
.need.n-secret{color:var(--gap);border-color:var(--gap);border-style:solid}
.need.n-live{border-style:solid}
.need.n-skip{opacity:.75}
.prow.off .path,.prow.off .ptool{opacity:.45}
.planwrap{display:grid;grid-template-columns:minmax(0,1fr);gap:14px;align-items:start}
@media (min-width:1240px){
  .planwrap.has-build{grid-template-columns:minmax(0,1fr) 420px}
  .planwrap.has-build .tbuild{position:sticky;top:64px;max-height:calc(100vh - 80px);overflow:auto;margin:0}
}
/* graph workbench */
.gbar{display:flex;flex-wrap:wrap;gap:5px;align-items:center;margin:0 0 10px;padding:8px 10px;border:1px solid var(--line);
  border-radius:10px;background:var(--panel)}
.gbar .btn{font-size:12px;padding:4px 9px}
.gbar .btn[aria-pressed=true]{background:var(--accent);color:var(--on-accent);border-color:var(--accent)}
.gsel{font-size:12px;color:var(--muted);display:inline-flex;align-items:center;gap:6px}
.gsel select{font-size:12px;padding:3px 6px;border:1px solid var(--line);border-radius:6px;background:var(--panel-2);color:var(--ink);max-width:260px}
.gsep{width:1px;height:20px;background:var(--line);margin:0 4px}
.gwrap{display:grid;grid-template-columns:230px 1fr 300px;gap:10px;min-height:620px}
.gcanvas{position:relative;min-width:0}
.gzoom{position:absolute;right:10px;top:10px;display:flex;flex-direction:column;gap:3px}
.gzoom button{width:28px;height:28px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--ink);font-size:15px;line-height:1;cursor:pointer}
.gzoom button:hover{background:var(--hover)}
.ghint{position:absolute;left:50%;top:45%;transform:translate(-50%,-50%);font-size:13px;color:var(--muted);text-align:center;
  max-width:36ch;pointer-events:none}
#cy.pathmode{cursor:crosshair;outline:2px solid var(--accent);outline-offset:-2px}
#cy:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
.gcnt{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:10px;color:var(--faint)}
.ghelp{margin-top:8px}
.ghelp ul{margin:4px 0 0;padding-left:16px}
.ghelp li{margin:2px 0}
.ghelp kbd,.gtop kbd{font:11px ui-monospace,Menlo,Consolas,monospace;border:1px solid var(--line);border-bottom-width:2px;border-radius:4px;padding:0 4px;background:var(--panel-2)}
.ginfo-h{display:flex;align-items:center;gap:6px}
.ginfo-h h4{margin:6px 0}
.gtitle{font-weight:600;margin:2px 0 4px;line-height:1.3;word-break:break-word}
.relh{display:flex;align-items:baseline;justify-content:space-between;gap:6px;margin-top:8px}
.relh .lnk{background:none;border:0;color:var(--accent);cursor:pointer;font-size:11px;padding:0}
.relh .lnk:hover{text-decoration:underline}
.nbl button.onc{color:var(--muted)}
.nbl button i{font-style:normal;color:var(--covered);font-size:10px}
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
.nbl .rel{font-size:11px;color:var(--faint)}
.gnote{font-size:12px;color:var(--muted)}
/* triage builder */
.tbuild{border:1px solid var(--line);border-radius:10px;background:var(--panel);padding:12px 14px;margin:14px 0}
.tbuild h3{margin:0 0 4px;font-size:15px}
.tbuild .tcount{font-size:12px;color:var(--muted);margin:6px 0}
.tbuild pre{max-height:320px;overflow:auto;background:var(--panel-2);border:1px solid var(--line-soft);
  border-radius:8px;padding:8px;font-size:11px}
.fw{display:grid;grid-template-columns:1fr;gap:10px;margin-top:10px}
.fwc{border:1px solid var(--line-soft);border-radius:8px;padding:9px 11px;background:var(--panel-2)}
.fwc h4{margin:0 0 4px;font-size:13px}
.fwc p{margin:0 0 6px;font-size:12px;color:var(--muted)}
.fwc code{display:block;white-space:pre-wrap;word-break:break-all;font-size:11px;background:var(--panel);
  border:1px solid var(--line-soft);border-radius:6px;padding:6px}
@media (max-width:900px){
  .gwrap{grid-template-columns:1fr}
  .gbar{position:sticky;top:0;z-index:4}
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
   Maltego feeds export. It starts from a small, connected seed and grows by
   expansion, because 500 nodes at once is a hairball, not an investigation.
   New nodes are placed around the node they came from and nothing else moves;
   a global re-layout is something the user asks for, not something that
   happens under the pointer. Cytoscape is inlined as inert text and only
   evaluated the first time this view opens, so the catalog does not pay for it. */
const GNODE=Object.fromEntries(GRAPH.nodes.map(n=>[n.id,n]));
const GADJ=(()=>{const m={};for(const e of GRAPH.edges){
  (m[e.source]=m[e.source]||[]).push({id:e.target,rel:e.rel,dir:'out'});
  (m[e.target]=m[e.target]||[]).push({id:e.source,rel:e.rel,dir:'in'})}return m})();
const GDEG=id=>(GADJ[id]||[]).length;
const GTYPES=['actor','case','tool','artifact','rule','technique','tactic','asi','ioc','malware','sector','country','region','attack-group','attack-campaign'];
const GCOLOR={actor:'--series-6',case:'--series-3',tool:'--series-1',artifact:'--series-8',rule:'--series-2',
  technique:'--series-4',tactic:'--series-4',asi:'--series-5',ioc:'--series-7',malware:'--series-6',
  sector:'--series-5',country:'--series-7',region:'--series-7','attack-group':'--series-6','attack-campaign':'--series-3'};
const GSHAPE={actor:'hexagon',case:'round-rectangle',tool:'ellipse',artifact:'rectangle',rule:'diamond',
  technique:'triangle',tactic:'vee',asi:'star',ioc:'tag',malware:'octagon',sector:'barrel',country:'round-tag',
  region:'round-tag','attack-group':'hexagon','attack-campaign':'round-rectangle'};
// What a relationship reads as from each end, so the neighbour list says
// "detected by 3 rules" rather than "detects (in) · 3".
const GREL={uses:['uses','used by'],'attributed-to':['attributed to','attributed actor'],targets:['targets','targeted by'],
  affects:['affects','affected in'],abuses:['abuses','abused by'],leaves:['leaves on disk','left by'],detects:['detects','detected by'],
  'detected-by':['detected by','detects'],indicator:['has indicator','indicator of'],'in-tactic':['in tactic','techniques'],
  'maps-to':['maps to','mapped from'],'same-as':['same as','same as'],'in-region':['in region','countries']};
const relLabel=(rel,dir)=>(GREL[rel]||[rel,rel+' (in)'])[dir==='out'?0:1];
const GPRESETS={
  story:['Actors, their cases and techniques',()=>{const a=GRAPH.nodes.filter(n=>n.type==='actor').map(n=>n.id);
    return [...a,...a.flatMap(id=>(GADJ[id]||[]).filter(x=>['case','technique'].includes(GNODE[x.id].type)).map(x=>x.id))]}],
  actors:['Actors and what they abuse',()=>{const a=GRAPH.nodes.filter(n=>n.type==='actor').map(n=>n.id);
    return [...a,...a.flatMap(id=>(GADJ[id]||[]).filter(x=>['tool','malware','attack-group'].includes(GNODE[x.id].type)).map(x=>x.id))]}],
  rules:['Rules and the techniques they detect',()=>{const r=GRAPH.nodes.filter(n=>n.type==='rule').map(n=>n.id);
    return [...r,...r.flatMap(id=>(GADJ[id]||[]).filter(x=>GNODE[x.id].type==='technique').map(x=>x.id))]}],
  victims:['Victimology: actors, sectors, countries',()=>{const a=GRAPH.nodes.filter(n=>n.type==='actor').map(n=>n.id);
    return [...a,...a.flatMap(id=>(GADJ[id]||[]).filter(x=>['sector','country'].includes(GNODE[x.id].type)).map(x=>x.id))]}],
  cases:['Cases and the tools they hit',()=>{const c=GRAPH.nodes.filter(n=>n.type==='case').map(n=>n.id);
    return [...c,...c.flatMap(id=>(GADJ[id]||[]).filter(x=>GNODE[x.id].type==='tool').map(x=>x.id))]}],
};
let cy=null, graphSeed=null, gHidden=new Set(['artifact','tactic','region']), gPathMode=false, gPathFrom=null,
    gUndo=[], gRemoved={}, gPreset='story', gLastExpand=null;
const GEXPAND_CAP=40;
// cose's repulsion is in its own units - the default is 2048 per node pair, and
// anything under ~1e5 leaves labelled nodes stacked on each other.
const COSE=()=>({name:'cose',animate:false,fit:true,padding:30,nodeDimensionsIncludeLabels:true,
  nodeRepulsion:()=>220000,nodeOverlap:20,idealEdgeLength:()=>90,edgeElasticity:()=>100,gravity:.7,numIter:1500,
  stop:()=>gAfterLayout()});
// A fit that zooms out past readable is not a fit. Clamp it and let the user pan.
function gAfterLayout(){if(!cy)return;cy.fit(undefined,30);
  if(cy.zoom()<.6){const bb=cy.elements().boundingBox();cy.zoom({level:.6,position:{x:(bb.x1+bb.x2)/2,y:(bb.y1+bb.y2)/2}})}}
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
    <p>Actors, cases, catalogued tools, rules, techniques and indicators as one graph - the same one the
    STIX and Maltego feeds export. Start from a preset or a search, then grow it: <b>double-click</b> a node
    (or press <kbd>E</kbd>) to pull in its neighbours, <b>hover</b> to see what connects to what,
    <b>Path</b> to find how two things are linked. Nothing moves unless you ask it to.</p></div>
    <div class="acts"><button class="btn" id="gBackIntel">&#8592; Threat intel</button></div></div>
  <div class="gbar" role="toolbar" aria-label="Graph tools">
    <label class="gsel">Start from <select id="gPreset" aria-label="Starting view">${Object.entries(GPRESETS).map(([k,[l]])=>
      `<option value="${k}"${k===gPreset?' selected':''}>${esc(l)}</option>`).join('')}</select></label>
    <button class="btn" id="gLoad" title="Replace the canvas with this preset">Load</button>
    <span class="gsep"></span>
    <button class="btn" id="gExpand" title="Pull in the neighbours of the selected nodes (E)">Expand</button>
    <button class="btn" id="gFocus" title="Keep only the selected nodes and their neighbours (K)">Focus</button>
    <button class="btn" id="gHide" title="Remove the selected nodes from the canvas (Delete)">Hide</button>
    <button class="btn" id="gPath" aria-pressed="false" title="Find a route between two nodes, through nodes nobody has expanded yet (P)">Path</button>
    <span class="gsep"></span>
    <button class="btn" id="gUndo" title="Undo the last change to the canvas (Ctrl+Z)" disabled>Undo</button>
    <button class="btn" id="gRelayout" title="Re-run the force layout on everything (L)">Re-layout</button>
    <button class="btn" id="gFit" title="Fit everything in view (F)">Fit</button>
    <button class="btn" id="gClear">Clear</button>
    <span class="gsep"></span>
    <button class="btn" id="gLink" title="Copy a link that reopens this canvas">Copy link</button>
    <button class="btn" id="gPng">PNG</button><button class="btn" id="gJson">JSON</button>
    <button class="btn" id="gCsv">Maltego CSV</button>
  </div>
  <div class="gwrap">
    <div class="gpane">
      <h4>Find</h4>
      <input class="gsearch" id="gq" type="search" placeholder="actor, tool, rule, CVE, domain..." aria-label="Search the graph">
      <div class="gres" id="gres"></div>
      <h4>Types on canvas</h4>
      <div class="tfilter">${GTYPES.map(t=>`<label title="Show or hide every ${esc(t)} node"><input type="checkbox" data-gt="${t}" ${gHidden.has(t)?'':'checked'}
        ><span class="dot2" style="background:var(${GCOLOR[t]})"></span>${esc(t)} <span class="gcnt" data-cnt="${t}"></span></label>`).join('')}</div>
      <h4>Layout</h4>
      <div class="gbtns">${['cose','concentric','breadthfirst','circle'].map(l=>
        `<button class="btn" data-lay="${l}">${l}</button>`).join('')}</div>
      <p class="gnote" id="gstat" aria-live="polite"></p>
      <details class="ghelp"><summary class="gnote">Keys and gestures</summary>
        <ul class="gnote"><li><b>Click</b> selects and shows a node's neighbours on the right</li>
        <li><b>Double-click</b> / <kbd>E</kbd> expands, at most ${GEXPAND_CAP} new nodes at a time</li>
        <li><b>Hover</b> highlights a node's neighbourhood and names the links</li>
        <li><b>Shift-drag</b> box-selects; <kbd>Delete</kbd> hides; <kbd>K</kbd> focuses</li>
        <li><kbd>P</kbd> then two clicks finds a path; <kbd>Esc</kbd> cancels</li>
        <li><kbd>F</kbd> fits, <kbd>L</kbd> re-lays out, <kbd>Ctrl+Z</kbd> undoes, <kbd>/</kbd> searches</li>
        <li>Drag a node to pin it where you put it; layouts leave it there</li></ul></details>
    </div>
    <div class="gcanvas"><div id="cy" tabindex="0" role="application" aria-label="Entity graph. Use the Find box and the neighbour list to navigate by keyboard."></div>
      <div class="gzoom" aria-hidden="true"><button id="gzIn" title="Zoom in">+</button><button id="gzOut" title="Zoom out">&minus;</button><button id="gzFit" title="Fit">&#8982;</button></div>
      <div class="ghint" id="ghint" hidden></div></div>
    <div class="gpane" id="ginfo"><p class="gnote">Select a node to see what it connects to.</p></div>
  </div>`;
}
function gEls(ids){
  const els=[], have=new Set(ids);
  for(const id of ids){const n=GNODE[id];if(!n)continue;
    const d=GDEG(id), size=(n.type==='actor'?26:14)+Math.min(16,2*Math.sqrt(d));
    els.push({group:'nodes',data:{id,label:n.label.length>42?n.label.slice(0,40)+'…':n.label,type:n.type,size}})}
  for(const e of GRAPH.edges)if(have.has(e.source)&&have.has(e.target))
    els.push({group:'edges',data:{id:e.source+'>'+e.rel+'>'+e.target,source:e.source,target:e.target,rel:e.rel}});
  return els;
}
function gSnap(){
  if(!cy)return;
  gUndo.push(cy.nodes().map(n=>({id:n.id(),x:n.position('x'),y:n.position('y'),locked:n.locked()})));
  if(gUndo.length>30)gUndo.shift();
  const b=$('#gUndo');if(b)b.disabled=false;
}
function gUndoDo(){
  const st=gUndo.pop();if(!st)return;
  cy.elements().remove();
  cy.add(gEls(st.map(s=>s.id)));
  st.forEach(s=>{const n=cy.getElementById(s.id);if(n.nonempty()){n.position({x:s.x,y:s.y});if(s.locked)n.lock()}});
  gStat();gHash();
  const b=$('#gUndo');if(b)b.disabled=!gUndo.length;
}
// Place new nodes on a ring around the node they came from, radius growing
// with how many there are, and leave everything already on the canvas alone.
function gPlace(fresh,center){
  const c=center&&cy.getElementById(center).nonempty()?cy.getElementById(center).position():null;
  const ext=cy.extent(), base=c||{x:(ext.x1+ext.x2)/2,y:(ext.y1+ext.y2)/2};
  const n=fresh.length, r=Math.max(90,18*n/Math.PI+40), start=Math.random()*Math.PI*2;
  const taken=new Set(cy.nodes().map(x=>Math.round(x.position('x')/40)+':'+Math.round(x.position('y')/40)));
  return Object.fromEntries(fresh.map((id,i)=>{let a=start+i*2*Math.PI/n, rr=r, p;
    for(let k=0;k<6;k++){p={x:base.x+rr*Math.cos(a),y:base.y+rr*Math.sin(a)};
      const key=Math.round(p.x/40)+':'+Math.round(p.y/40);if(!taken.has(key)){taken.add(key);break}rr+=34}
    return [id,p]}));
}
function gAdd(ids,center,opts={}){
  const seen=new Set(); const fresh=ids.filter(id=>{if(seen.has(id))return false;seen.add(id);
    return GNODE[id]&&!gHidden.has(GNODE[id].type)&&cy.getElementById(id).empty()});
  if(!fresh.length){gStat(opts.quiet?'':'Nothing new to add - every neighbour that is visible is already on the canvas.');return[]}
  gSnap();
  const cur=cy.nodes().map(n=>n.id());
  const pos=gPlace(fresh,center);
  const els=gEls([...cur,...fresh]).filter(e=>cy.getElementById(e.data.id).empty());
  const added=cy.add(els.map(e=>e.group==='nodes'?{...e,position:pos[e.data.id]}:e));
  if(center&&cy.getElementById(center).nonempty()){
    const hood=added.nodes().union(cy.getElementById(center));
    const ext=cy.extent(), bb=hood.boundingBox();
    if(bb.x1<ext.x1||bb.x2>ext.x2||bb.y1<ext.y1||bb.y2>ext.y2)cy.animate({fit:{eles:hood.union(cy.nodes()),padding:40},duration:250});
  }else if(!cur.length)cy.fit(undefined,40);
  gStat();gHash();
  return fresh;
}
function gExpand(id,rel){
  let nb=(GADJ[id]||[]).filter(x=>!rel||x.rel+':'+x.dir===rel).map(x=>x.id);
  const visible=nb.filter(x=>!gHidden.has(GNODE[x].type)&&cy.getElementById(x).empty());
  const hiddenTypes=[...new Set(nb.filter(x=>gHidden.has(GNODE[x].type)).map(x=>GNODE[x].type))];
  let note='';
  if(visible.length>GEXPAND_CAP){
    // Actors first, then by how connected the node is: the well-linked
    // neighbours are the ones that lead somewhere.
    visible.sort((a,b)=>(GNODE[b].type==='actor')-(GNODE[a].type==='actor')||GDEG(b)-GDEG(a));
    note=`Added ${GEXPAND_CAP} of ${visible.length} neighbours - expand again, or add a relationship group from the panel.`;
    nb=visible.slice(0,GEXPAND_CAP);
  }
  const added=gAdd(nb,id,{quiet:true});
  if(hiddenTypes.length)note+=(note?' ':'')+`${hiddenTypes.join(', ')} nodes stay hidden until you tick the type.`;
  if(!added.length&&!note)note='Every visible neighbour is already on the canvas.';
  gStat(note);
  gLastExpand=id;
  return added;
}
function gStat(msg){
  const s=$('#gstat');if(!s||!cy)return;
  const counts={};cy.nodes().forEach(n=>{const t=n.data('type');counts[t]=(counts[t]||0)+1});
  $$('#main .gcnt').forEach(el=>{const c=counts[el.dataset.cnt];el.textContent=c?c:''});
  s.textContent=`${cy.nodes().length} nodes · ${cy.edges().length} edges on canvas${msg?' · '+msg:''}`;
  const h=$('#ghint');if(h){h.hidden=!!cy.nodes().length;h.textContent='Empty canvas. Load a preset, search for something, or open a node from any drawer.'}
}
function gHash(){
  const ids=cy.nodes().map(n=>n.id());
  if(ids.length<=60)history.replaceState(null,'','#graph/'+encodeURIComponent(ids.join('|')));
  else history.replaceState(null,'','#graph');
}
function gFacts(n){
  const id=n.id;
  if(n.type==='actor'){const a=ACTORMAP[n.actor_id];return a?`${KIND_LABEL[a.kind]||a.kind}${a.nexus?' · '+a.nexus:''} · ${a.derived.techniques.length} techniques · ${a.cases.length} case${a.cases.length===1?'':'s'}`:''}
  if(n.type==='case'){const c=CASEMAP[n.case_id];return c?`${c.disclosed||''} · confidence ${c.confidence||'-'} · ${(c.iocs||[]).length} indicators`:''}
  if(n.type==='technique')return `${n.framework||''} ${TNAME(id.split(':')[1])||''}`.trim();
  if(n.type==='rule'){const r=RULEFILE[id.split(':').slice(1).join(':')]||RULEMAP[id.split(':').slice(1).join(':')];return r?`${r.format||''} · ${r.category||''}${r.level?' · '+r.level:''}`:''}
  if(n.type==='tool'){const t=TOOLMAP[n.entry_id];return t?`${t.category||''} · ${t.n_rows||''} artifact rows · risk ${t.risk||'-'}`:''}
  if(n.type==='artifact'){const r=ROWMAP[n.anchor];return r?`${r.cls} · ${r.vol} · value ${r.forensic_value||'-'}`:''}
  if(n.type==='ioc')return n.ioc_type||'';
  return '';
}
function gInfo(id){
  const n=GNODE[id], box=$('#ginfo'); if(!n||!box)return;
  const nb=(GADJ[id]||[]);
  const groups={};
  for(const x of nb){const k=x.rel+':'+x.dir;(groups[k]=groups[k]||{rel:x.rel,dir:x.dir,ids:[]}).ids.push(x.id)}
  const on=x=>cy.getElementById(x).nonempty();
  const open=n.type==='actor'?`<button class="btn" data-open="actor">Open profile</button>`:
    n.type==='rule'?`<button class="btn" data-open="rule">Open rule</button>`:
    n.type==='tool'?`<button class="btn" data-open="tool">Open tool</button>`:
    n.type==='artifact'?`<button class="btn" data-open="artifact">Open artifact</button>`:
    n.type==='case'?`<button class="btn" data-open="case">Open case study</button>`:
    n.type==='technique'&&n.framework==='ATLAS'?`<a class="btn" href="https://atlas.mitre.org/techniques/${esc(id.split(':')[1])}" target="_blank" rel="noopener">ATLAS &#8599;</a>`:
    n.type==='technique'?`<a class="btn" href="https://attack.mitre.org/techniques/${esc(id.split(':')[1].replace('.','/'))}" target="_blank" rel="noopener">ATT&amp;CK &#8599;</a>`:'';
  const facts=gFacts(n);
  const missing=nb.filter(x=>!on(x.id)).length;
  box.innerHTML=`<div class="ginfo-h"><span class="dot2" style="background:var(${GCOLOR[n.type]})"></span><h4>${esc(n.type)}</h4></div>
    <p class="gtitle">${esc(n.label)}</p>
    ${facts?`<p class="gnote">${esc(facts)}</p>`:''}
    <p class="gnote mono">${esc(id)}</p>
    <div class="gbtns">${open}
      <button class="btn" data-exp="1" ${missing?'':'disabled'}>Expand all (${missing})</button>
      <button class="btn" data-focus="1">Focus</button>
      <button class="btn" data-hide="1">Hide</button></div>
    <h4>Connections <span class="gnote">${nb.length}</span></h4>
    <div class="nbl">${Object.entries(groups).sort((a,b)=>b[1].ids.length-a[1].ids.length).map(([k,g])=>{
      const off=g.ids.filter(x=>!on(x)&&!gHidden.has(GNODE[x].type)).length;
      const hid=g.ids.filter(x=>gHidden.has(GNODE[x].type)).length;
      return `<div class="relh"><span class="rel">${esc(relLabel(g.rel,g.dir))} · ${g.ids.length}</span>
        ${off?`<button class="lnk" data-addrel="${esc(k)}">add ${off}</button>`:hid?`<span class="gnote">${hid} hidden by type</span>`:''}</div>
        ${g.ids.slice(0,40).map(x=>`<button data-add="${esc(x)}" class="${on(x)?'onc':''}" title="${on(x)?'On canvas - click to select':'Click to add'}">
          <span class="dot2" style="background:var(${GCOLOR[(GNODE[x]||{}).type]||'--faint'})"></span>${esc(((GNODE[x]||{}).label||x).slice(0,60))}${on(x)?' <i>&#10003;</i>':''}</button>`).join('')}
        ${g.ids.length>40?`<span class="gnote">and ${g.ids.length-40} more - use "add" above</span>`:''}`}).join('')}</div>`;
  box.querySelector('[data-exp]').onclick=()=>gExpand(id);
  box.querySelector('[data-focus]').onclick=()=>gFocus([id]);
  box.querySelector('[data-hide]').onclick=()=>{gSnap();cy.getElementById(id).remove();gStat();gHash();box.innerHTML='<p class="gnote">Hidden. Undo brings it back.</p>'};
  box.querySelectorAll('[data-addrel]').forEach(b=>b.onclick=()=>gExpand(id,b.dataset.addrel));
  box.querySelectorAll('[data-add]').forEach(b=>b.onclick=()=>{const t=GNODE[b.dataset.add];
    if(t&&gHidden.has(t.type)){gHidden.delete(t.type);const cb=$(`#main input[data-gt="${t.type}"]`);if(cb)cb.checked=true}
    gAdd([b.dataset.add],id,{quiet:true});const el=cy.getElementById(b.dataset.add);cy.$(':selected').unselect();el.select();gInfo(b.dataset.add)});
  const o=box.querySelector('[data-open]');
  if(o)o.onclick=()=>{const k=o.dataset.open, v=id.split(':').slice(1).join(':');
    if(k==='actor')openActorDrawer(v,o);else if(k==='rule')openRuleDrawer(v,o);
    else if(k==='tool')openToolDrawer(v,o);else if(k==='artifact')openDrawer(v,o);
    else{pushNav();view='cases';update();const el=document.getElementById('cs-'+v);if(el){el.open=true;el.scrollIntoView()}}};
}
function gFocus(ids){
  if(!ids.length)return;
  gSnap();
  const keep=new Set(ids);ids.forEach(id=>(GADJ[id]||[]).forEach(x=>keep.add(x.id)));
  cy.nodes().filter(n=>!keep.has(n.id())).remove();
  gAdd([...keep],ids[0],{quiet:true});
  cy.animate({fit:{eles:cy.elements(),padding:50},duration:250});
  gStat(`Focused on ${ids.length} node${ids.length===1?'':'s'} and their neighbours.`);
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
function gSetPathMode(on){
  gPathMode=on;gPathFrom=null;
  const b=$('#gPath');if(!b)return;
  b.setAttribute('aria-pressed',String(on));b.textContent=on?'Path: click the 1st node':'Path';
  $('#cy').classList.toggle('pathmode',on);
  if(on)gStat('Path mode: click two nodes. Esc cancels.');
}
function gHighlight(n){
  const hood=n.closedNeighborhood();
  cy.elements().addClass('dim');hood.removeClass('dim');hood.addClass('hl');
}
function gUnhighlight(){cy.elements().removeClass('dim hl');const sel=cy.$('node:selected');if(sel.length===1)gHighlight(sel)}
function gLoadPreset(k){
  const ids=(GPRESETS[k]||GPRESETS.story)[1]();
  const types=new Set(ids.map(id=>GNODE[id].type));
  types.forEach(t=>{if(gHidden.has(t)){gHidden.delete(t);const cb=$(`#main input[data-gt="${t}"]`);if(cb)cb.checked=true}});
  gSnap();cy.elements().remove();
  cy.add(gEls([...new Set(ids)]));
  cy.layout(COSE()).run();
  gStat(`Loaded "${GPRESETS[k][0]}".`);gHash();
  $('#ginfo').innerHTML='<p class="gnote">Select a node to see what it connects to.</p>';
}
function renderGraph(){
  $('#main').innerHTML=graphHTML();
  $('#gBackIntel').onclick=()=>{view='intel';update()};
  if(!loadCyto()){$('#cy').innerHTML='<p class="gnote" style="padding:12px">Graph library unavailable in this build.</p>';return}
  const ink=cssVar('--ink'), line=cssVar('--line'), acc=cssVar('--accent'), gap=cssVar('--gap');
  const style=[
    {selector:'node',style:{'label':'data(label)','font-size':9,'color':ink,'text-valign':'bottom',
      'text-margin-y':3,'width':'data(size)','height':'data(size)','border-width':1,'border-color':line,
      'text-wrap':'ellipsis','text-max-width':96,'text-background-color':cssVar('--panel-2'),
      'text-background-opacity':.75,'text-background-padding':1,'text-background-shape':'roundrectangle',
      'transition-property':'opacity','transition-duration':'120ms'}},
    ...GTYPES.map(t=>({selector:`node[type="${t}"]`,style:{'background-color':cssVar(GCOLOR[t]),'shape':GSHAPE[t]}})),
    {selector:'node[type="actor"]',style:{'font-size':11,'font-weight':'bold'}},
    {selector:'node:selected',style:{'border-width':3,'border-color':acc}},
    {selector:'node:locked',style:{'border-style':'double','border-width':3}},
    {selector:'node.hl',style:{'border-width':2,'border-color':ink}},
    {selector:'node.path',style:{'border-width':4,'border-color':gap}},
    {selector:'edge',style:{'width':1,'line-color':line,'target-arrow-shape':'triangle',
      'target-arrow-color':line,'curve-style':'bezier','arrow-scale':.6,'label':'data(rel)',
      'font-size':7,'color':cssVar('--faint'),'text-rotation':'autorotate','text-opacity':0,
      'text-background-color':cssVar('--panel-2'),'text-background-opacity':.85,'text-background-padding':1}},
    {selector:'edge.zl',style:{'text-opacity':1}},
    {selector:'edge.hl',style:{'width':2,'line-color':ink,'target-arrow-color':ink,'text-opacity':1,'color':ink}},
    {selector:'edge.path',style:{'width':3,'line-color':gap,'target-arrow-color':gap,'text-opacity':1}},
    {selector:'.dim',style:{'opacity':.18}},
  ];
  cy=window.cytoscape({container:$('#cy'),elements:[],style,wheelSensitivity:.25,minZoom:.1,maxZoom:2.2,
    boxSelectionEnabled:true,selectionType:'additive'});
  gUndo=[];gRemoved={};
  const fromHash=decodeURIComponent(location.hash.slice(1));
  let seed=[];
  if(fromHash.startsWith('graph/'))seed=fromHash.slice(6).split('|').filter(x=>GNODE[x]);
  if(!seed.length&&graphSeed&&GNODE[graphSeed])seed=[graphSeed,...(GADJ[graphSeed]||[]).map(x=>x.id).slice(0,GEXPAND_CAP)];
  if(seed.length){
    seed.forEach(id=>{const t=(GNODE[id]||{}).type;if(t&&gHidden.has(t)&&seed.length<40){gHidden.delete(t);const cb=$(`#main input[data-gt="${t}"]`);if(cb)cb.checked=true}});
    cy.add(gEls(seed.filter(id=>!gHidden.has((GNODE[id]||{}).type))));
    cy.layout(COSE()).run();
    gStat();
  }else gLoadPreset(gPreset);
  gUndo=[];const ub=$('#gUndo');if(ub)ub.disabled=true;
  // interactions
  cy.on('dbltap','node',e=>gExpand(e.target.id()));
  cy.on('mouseover','node',e=>{if(!gPathMode)gHighlight(e.target)});
  cy.on('mouseout','node',()=>gUnhighlight());
  cy.on('zoom',()=>cy.edges().toggleClass('zl',cy.zoom()>1.15));
  cy.on('dragfree','node',e=>e.target.lock());
  cy.on('select','node',e=>{if(cy.$('node:selected').length===1)gUnhighlight()});
  cy.on('unselect','node',()=>gUnhighlight());
  cy.on('tap',e=>{if(e.target===cy&&!gPathMode){$('#ginfo').innerHTML='<p class="gnote">Select a node to see what it connects to.</p>'}});
  cy.on('tap','node',e=>{const id=e.target.id();gInfo(id);
    if(gPathMode){if(!gPathFrom){gPathFrom=id;$('#gPath').textContent='Path: click the 2nd node';gStat(`Path from ${GNODE[id].label} - click the destination.`)}
      else{const p=gPath(gPathFrom,id);cy.elements().removeClass('path');
        if(p){gAdd(p,gPathFrom,{quiet:true});p.forEach((x,i)=>{cy.getElementById(x).addClass('path');
          if(i)cy.edges().filter(ed=>(ed.source().id()===p[i-1]&&ed.target().id()===x)||(ed.source().id()===x&&ed.target().id()===p[i-1])).addClass('path')});
          cy.animate({fit:{eles:cy.$('.path'),padding:60},duration:250});
          gSetPathMode(false);
          gStat(`Path: ${p.map(x=>GNODE[x].label).join(' → ')} (${p.length-1} hop${p.length===2?'':'s'}).`)}
        else{gSetPathMode(false);gStat('No path between those two.')}}}});
  // search
  const goTo=id=>{const t=GNODE[id].type;
    if(gHidden.has(t)){gHidden.delete(t);const cb=$(`#main input[data-gt="${t}"]`);if(cb)cb.checked=true}
    gAdd([id],null,{quiet:true});const el=cy.getElementById(id);cy.$(':selected').unselect();el.select();
    cy.animate({center:{eles:el},duration:200});gInfo(id);$('#gres').innerHTML='';$('#gq').value=''};
  $('#gq').oninput=e=>{const q=e.target.value.trim().toLowerCase();
    const hits=q.length<2?[]:GRAPH.nodes.filter(n=>n.label.toLowerCase().includes(q)||n.id.toLowerCase().includes(q))
      .sort((a,b)=>(a.label.toLowerCase().startsWith(q)?0:1)-(b.label.toLowerCase().startsWith(q)?0:1)||GDEG(b.id)-GDEG(a.id)).slice(0,25);
    $('#gres').innerHTML=hits.map(n=>`<button data-go="${esc(n.id)}"><span class="dot2" style="background:var(${GCOLOR[n.type]})"></span>${esc(n.label.slice(0,50))}
        <span class="gnote">${esc(n.type)} · ${GDEG(n.id)}</span></button>`).join('')||(q.length<2?'':'<p class="gnote">No match.</p>');
    $$('#gres [data-go]').forEach(b=>b.onclick=()=>goTo(b.dataset.go))};
  $('#gq').onkeydown=e=>{if(e.key==='Enter'){const f=$('#gres [data-go]');if(f){e.preventDefault();goTo(f.dataset.go)}}
    if(e.key==='Escape'){$('#gq').value='';$('#gres').innerHTML=''}};
  // type filter: unticking removes, re-ticking brings back what it removed
  $$('#main input[data-gt]').forEach(cb=>cb.onchange=()=>{const t=cb.dataset.gt;
    if(cb.checked){gHidden.delete(t);const back=(gRemoved[t]||[]);delete gRemoved[t];
      if(back.length)gAdd(back,null,{quiet:true});gStat()}
    else{gHidden.add(t);gSnap();gRemoved[t]=cy.nodes(`[type="${t}"]`).map(n=>n.id());cy.nodes(`[type="${t}"]`).remove();gStat();gHash()}});
  $$('#main [data-lay]').forEach(b=>b.onclick=()=>{cy.nodes().unlock();cy.layout(b.dataset.lay==='cose'?COSE():{name:b.dataset.lay,animate:false,padding:30,spacingFactor:1.2,nodeDimensionsIncludeLabels:true,stop:()=>gAfterLayout()}).run()});
  const sel=()=>cy.$('node:selected').map(n=>n.id());
  $('#gLoad').onclick=()=>{gPreset=$('#gPreset').value;gLoadPreset(gPreset)};
  $('#gExpand').onclick=()=>{const s=sel();if(!s.length){gStat('Select a node first - click it, or shift-drag a box.');return}s.forEach(id=>gExpand(id))};
  $('#gFocus').onclick=()=>{const s=sel();if(!s.length){gStat('Select a node first.');return}gFocus(s)};
  $('#gHide').onclick=()=>{const s=cy.$('node:selected');if(!s.length){gStat('Select a node first.');return}gSnap();s.remove();gStat();gHash()};
  $('#gClear').onclick=()=>{gSnap();cy.elements().remove();gStat();gHash();$('#ginfo').innerHTML='<p class="gnote">Select a node to see what it connects to.</p>'};
  $('#gPath').onclick=()=>gSetPathMode(!gPathMode);
  $('#gUndo').onclick=gUndoDo;
  $('#gRelayout').onclick=()=>{cy.nodes().unlock();cy.layout(COSE()).run()};
  $('#gFit').onclick=()=>cy.animate({fit:{eles:cy.elements(),padding:40},duration:200});
  $('#gzIn').onclick=()=>cy.animate({zoom:{level:cy.zoom()*1.3,renderedPosition:{x:cy.width()/2,y:cy.height()/2}},duration:150});
  $('#gzOut').onclick=()=>cy.animate({zoom:{level:cy.zoom()/1.3,renderedPosition:{x:cy.width()/2,y:cy.height()/2}},duration:150});
  $('#gzFit').onclick=()=>cy.animate({fit:{eles:cy.elements(),padding:40},duration:200});
  $('#gLink').onclick=e=>{gHash();copy(location.href,e.target)};
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
  // keyboard, scoped to the canvas so the rest of the page keeps its own keys
  $('#cy').onkeydown=e=>{
    if(e.target.tagName==='INPUT')return;
    const k=e.key.toLowerCase();
    if(k==='escape'){if(gPathMode)gSetPathMode(false);else cy.$(':selected').unselect();return}
    if(k==='delete'||k==='backspace'){const s=cy.$('node:selected');if(s.length){gSnap();s.remove();gStat();gHash()}e.preventDefault();return}
    if(k==='e'){sel().forEach(id=>gExpand(id));return}
    if(k==='k'){gFocus(sel());return}
    if(k==='f'){cy.animate({fit:{eles:cy.elements(),padding:40},duration:200});return}
    if(k==='l'){cy.nodes().unlock();cy.layout(COSE()).run();return}
    if(k==='p'){gSetPathMode(!gPathMode);return}
    if(k==='/'){e.preventDefault();$('#gq').focus();return}
    if(k==='z'&&(e.ctrlKey||e.metaKey)){e.preventDefault();gUndoDo()}
  };
  if(graphSeed&&cy.getElementById(graphSeed).nonempty()){cy.getElementById(graphSeed).select();gInfo(graphSeed);graphSeed=null}
}

/* ---------- triage script builder ----------
   Turns the collection plan into a script for the host in front of you. The
   templates are fixed and live in scripts/site_scripts.py; this only writes the
   target lines, from specs triage_spec.py computed at build time. */
let triageOS='win', triageFw='native';
/* Operator inputs live on the plan, so the command you built for a host is
   still there when you come back to it. They never leave the browser. */
const OPT_DEF=()=>({case:'',operator:'',out:'',repos:'',home:'',secrets:false,oneLine:false});
function triageOpts(){const p=activePlan();if(!p)return OPT_DEF();if(!p.opts)p.opts=OPT_DEF();return p.opts}
const repoList=()=>String(triageOpts().repos||'').split(/[\n,;]+/).map(x=>x.trim()).filter(Boolean);
const OSL={win:'Windows',mac:'macOS',linux:'Linux'};
let FWSKIP={};
// What the chosen collector will do with each picked row, so the plan shows the
// consequence of every builder option on the row it affects rather than only
// in a count at the bottom. Mirrors the script's own branches.
function refreshRowStates(){
  FWSKIP={};
  if(triageFw!=='native'&&FW[triageFw]&&picks.size){const x=FW[triageFw].make();FWSKIP=Object.fromEntries(x.skip.map(([r,w])=>[r.anchor,w]))}
}
function rowState(r){
  const s=r.spec||{kind:'manual'}, o=triageOpts();
  if(triageFw!=='native'){
    if(FWSKIP[r.anchor])return {state:'skip',note:FWSKIP[r.anchor]};
    return s.secret?{state:'hash',note:triageFw==='velo'?'metadata unless Upload':triageFw==='py'?(o.secrets?'copied - secret':'hashed only'):'copied - secret'}:{state:'copy',note:''};
  }
  if(s.kind==='manual')return {state:'manual',note:'manual - '+(s.why||'needs a person')};
  if(s.kind==='process'||s.kind==='network')return {state:'live',note:'live state'};
  if(s.kind==='registry'||s.kind==='eventlog')return triageOS==='win'
    ?{state:'copy',note:s.kind==='registry'?(s.secret&&!o.secrets?'key read, values not exported':'registry'):'event log'}
    :{state:'skip',note:'Windows only'};
  const ts=s[triageOS]||[], others=(s.win||[]).length+(s.mac||[]).length+(s.linux||[]).length;
  if(!ts.length)return others?{state:'skip',note:'not on '+OSL[triageOS]}:{state:'manual',note:'manual - no fixed path'};
  if(ts.every(t=>t.startsWith('{REPO}'))&&!repoList().length)return {state:'repo',note:'needs a repo path'};
  if(s.secret)return o.secrets?{state:'secret',note:'copied - secret'}:{state:'hash',note:'hashed only'};
  return {state:'copy',note:''};
}
function rowNeed(r){const st=rowState(r);return st.note?`<span class="need n-${st.state}">${esc(st.note)}</span>`:''}
const STATE_LABEL={copy:'collected',hash:'hashed only',secret:'secrets copied',live:'live state',manual:'manual',repo:'need a repo path',skip:'not in this output'};
function triageSummaryHTML(rows){
  const c={};for(const r of rows){const st=rowState(r).state;c[st]=(c[st]||0)+1}
  const conf={high:0,medium:0,low:0,unv:0};for(const r of rows){conf[r.confidence]=(conf[r.confidence]||0)+1;if(r.unverified)conf.unv++}
  const order=['copy','hash','secret','live','manual','repo','skip'];
  return `<div class="tsum">${order.filter(k=>c[k]).map(k=>`<span class="tchip t-${k}"><b>${c[k]}</b> ${STATE_LABEL[k]}</span>`).join('')}</div>
    <div class="tsum tsum2"><span class="tconf" title="Row confidence: high is host- or vendor-verified, medium is multi-source, low is single-source">
      <i class="cs c-high" style="flex:${conf.high}"></i><i class="cs c-med" style="flex:${conf.medium}"></i><i class="cs c-low" style="flex:${conf.low}"></i></span>
    <span class="gnote">${conf.high} verified · ${conf.medium} multi-source · ${conf.low} single-source${conf.unv?` · <b>${conf.unv} unverified</b>`:''}</span></div>`;
}
function runCmd(){
  const o=triageOpts(), rl=repoList();
  if(triageFw!=='native')return FW[triageFw].make().cmd;
  const name=triageScript(triageOS).name, parts=[];
  if(triageOS==='win'){
    parts.push(`powershell -ExecutionPolicy Bypass -File .\\${name}`);
    if(o.case)parts.push(`-CaseId ${psq(o.case)}`);if(o.operator)parts.push(`-Operator ${psq(o.operator)}`);
    if(o.out)parts.push(`-Out ${psq(o.out)}`);if(rl.length)parts.push(`-RepoPath ${rl.map(psq).join(',')}`);
    if(o.home)parts.push(`-HomePath ${psq(o.home)}`);if(o.secrets)parts.push('-CollectSecrets');
    return parts.join(o.oneLine?' ':' `\n    ');
  }
  parts.push(`sudo bash ${name}`);
  if(o.case)parts.push(`--case ${shq(o.case)}`);if(o.operator)parts.push(`--operator ${shq(o.operator)}`);
  if(o.out)parts.push(`--out ${shq(o.out)}`);rl.forEach(r=>parts.push(`--repo ${shq(r)}`));
  if(o.home)parts.push(`--home ${shq(o.home)}`);if(o.secrets)parts.push('--collect-secrets');
  return parts.join(o.oneLine?' ':' \\\n    ');
}
function tformHTML(){
  const o=triageOpts(), win=triageOS==='win'&&triageFw==='native', native=triageFw==='native';
  const f=(k,label,ph,title)=>`<label title="${esc(title||'')}">${label}<input data-opt="${k}" value="${esc(o[k]||'')}" placeholder="${esc(ph)}" autocomplete="off" spellcheck="false"></label>`;
  return `<div class="tform">
    ${f('case','Case id','IR-2026-001','Names the evidence folder and the manifest')}
    ${f('operator','Operator','your name','Recorded in the chain-of-custody manifest')}
    ${native||triageFw==='py'?f('out','Output directory',win?'D:\\evidence':'/evidence','Where the case folder is created; a removable or network target, not the host disk'):''}
    ${native||triageFw==='py'?f('repos','Repository paths','/src/app, /src/other','Checkouts the <repo> rows resolve against; without one those rows are recorded as needing it'):''}
    ${native?f('home','Home path','one profile; default is every profile','Limit collection to one user\u2019s home on a shared host'):''}
    ${native||triageFw==='py'?`<label class="tog"><input type="checkbox" data-opt="secrets"${o.secrets?' checked':''}> Copy credential files <span class="gnote">(default records hash and metadata only)</span></label>`:''}
    <label class="tog"><input type="checkbox" data-opt="oneLine"${o.oneLine?' checked':''}> One line, for pasting into a ticket</label>
  </div>`;
}
const BEFORE_RUN=[
  'Do not close the agent, the IDE or the terminal it ran in, and do not reboot: every row marked <b>live</b> goes with it, and several agents truncate their session logs on restart.',
  'Credential files are hashed, not copied, by default. Copying them is a decision - make it deliberately and record who made it.',
  'Name the user and the checkouts. <code style="display:inline">&lt;repo&gt;</code> rows resolve only against the paths you pass; a home-wide sweep on a shared host is slow and noisy.',
  'Capture MCP configuration before any remediation. Removing a server destroys the record of what the agent was allowed to run.'];

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
  const o=triageOpts();
  const meta=`plan: ${(p.name||'untitled').replace(/[\r\n]/g,' ')} | host: ${(p.host||'-').replace(/[\r\n]/g,' ')}${o.case?' | case: '+o.case.replace(/[\r\n]/g,' '):''}${o.operator?' | operator: '+o.operator.replace(/[\r\n]/g,' '):''} | generated ${new Date().toISOString()} | ${t.n} targets | ${REPO_URL}`;
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
/* ---------- framework exports from the same plan ----------
   The native script is one rendering of the plan. The collectors people already
   run are the others: KAPE, Velociraptor, ForensicArtifacts (Plaso, GRR,
   Timesketch) and the repository's own Python collector. All four read the same
   per-row spec triage_spec.py computed at build time, so the five outputs cannot
   disagree about what a locator means; this code only formats. Each rendering
   reports what it could not express - a registry key is not a file, a checkout
   path has no fixed location - instead of silently dropping the row. */
const ysq=s=>"'"+String(s??'').replace(/'/g,"''")+"'";
const oneLine=(s,n=180)=>String(s??'').replace(/\s+/g,' ').trim().slice(0,n);
const reEsc=s=>String(s).replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
const planSlug=()=>((activePlan()||{}).name||'AI triage').replace(/[^A-Za-z0-9]+/g,'').slice(0,40)||'AITriage';
const WINEVT='C:\\Windows\\System32\\winevt\\Logs\\';
const evtxFile=ch=>String(ch||'').replace(/\//g,'%4')+'.evtx';
// A GUID derived from the plan id, so downloading the same plan twice yields the
// same KAPE Id and gkape does not see two targets where there is one.
function planGuid(){
  const s=String((activePlan()||{}).id||'plan');
  const words=[0x811c9dc5,0x01000193,0x9e3779b9,0x7f4a7c15].map((seed,i)=>{let x=seed>>>0;
    for(const c of s+'|'+i){x^=c.charCodeAt(0);x=Math.imul(x,16777619)>>>0}return x.toString(16).padStart(8,'0')}).join('');
  return `${words.slice(0,8)}-${words.slice(8,12)}-4${words.slice(13,16)}-${((parseInt(words[16],16)&3)|8).toString(16)}${words.slice(17,20)}-${words.slice(20,32)}`;
}
const skipWhy={repo:'repository-relative - only the native script can take a checkout path',
  nofix:'no fixed path (environment variable, keychain, database or a location the operator supplies)',
  live:'live state, not a file - the native script captures it',
  reg:'registry key - this collector copies files, not keys',
  nowin:'no Windows location', manual:'needs a person'};
function kapePlan(){
  const slug='AIDFIR_'+planSlug(), p=activePlan()||{}, rows=[], skip=[], seen=new Set();
  const add=(path,mask,rec,r)=>{const k=path+'|'+mask;if(seen.has(k))return;seen.add(k);
    rows.push(`    -\n        Name: ${ysq(oneLine(r.artifact,80))}\n        Category: AIAgents\n        Path: ${ysq(path)}\n        FileMask: ${ysq(mask)}\n${rec?'        Recursive: true\n':''}        Comment: ${ysq(r.entry_id+' | '+r.tool+' | '+oneLine(r.description))}`)};
  for(const r of planRowsOrdered()){
    const s=r.spec||{kind:'manual'};
    if(s.kind==='path'){
      const ts=s.win||[];
      if(!ts.length){skip.push([r,(s.mac||[]).length||(s.linux||[]).length?skipWhy.nowin:skipWhy.nofix]);continue}
      let any=false;
      for(const t of ts){
        if(t.startsWith('{REPO}')){skip.push([r,skipWhy.repo]);continue}
        any=true;
        const full=t.replace('{HOME}','C:\\Users\\%user%');
        const segs=full.split('\\'), wild=segs.findIndex((x,i)=>i<segs.length-1&&x.includes('*'));
        if(wild>0){ // a wildcard directory: KAPE's Path takes no wildcards, so stop above it and recurse
          const tail=segs[segs.length-1];
          add(segs.slice(0,wild).join('\\')+'\\',tail&&!tail.includes('\\')?tail||'*':'*',true,r);
        }else if(full.endsWith('\\'))add(full,'*',true,r);
        else{const i=full.lastIndexOf('\\');add(full.slice(0,i+1),full.slice(i+1)||'*',false,r)}
      }
      if(!any&&!skip.some(x=>x[0]===r))skip.push([r,skipWhy.repo]);
    }else if(s.kind==='eventlog')add(WINEVT,evtxFile(s.channel),false,r);
    else if(s.kind==='registry')skip.push([r,skipWhy.reg]);
    else if(s.kind==='process'||s.kind==='network')skip.push([r,skipWhy.live]);
    else skip.push([r,s.why||skipWhy.manual]);
  }
  const text=`Description: ${ysq(oneLine(p.name||'AI triage plan')+' - AI agent artifacts picked in the collection plan')}\nAuthor: AI Agent Artifact Catalog (ai-dfir-toolkit)\nVersion: 1.0\nId: ${planGuid()}\nRecreateDirectories: true\nTargets:\n${rows.join('\n')}\n`;
  return {name:slug+'.tkape',mime:'text/plain',text,n:rows.length,skip,
    how:`Copy the file into KAPE's <code style="display:inline">Targets\\Custom\\</code> folder, then:`,
    cmd:`kape.exe --tsource C: --tdest D:\\kape_out\\${(triageOpts().case||slug).replace(/[^\w.-]+/g,'_')} --target ${slug} --vhdx ${(triageOpts().case||slug).replace(/[^\w.-]+/g,'_')}`};
}
function veloPlan(){
  const slug='Custom.AIAgents.Plan.'+planSlug(), p=activePlan()||{};
  const HOMEV={win:'C:\\Users\\*',mac:'/Users/*',linux:'/home/*'}, OSK={win:'windows',mac:'macos',linux:'linux'};
  const PRE={windows:"SELECT OS FROM info() WHERE OS = 'windows'",macos:"SELECT OS FROM info() WHERE OS = 'darwin'",linux:"SELECT OS FROM info() WHERE OS = 'linux'"};
  const globs={windows:[],macos:[],linux:[]}, reg=[], procs=[], ports=[], hosts=[], skip=[];
  const push=(a,v)=>{if(!a.includes(v))a.push(v)};
  let n=0;
  for(const r of planRowsOrdered()){
    const s=r.spec||{kind:'manual'};
    if(s.kind==='path'){
      let any=false, repo=false;
      for(const os of ['win','mac','linux'])for(const t of (s[os]||[])){
        if(t.startsWith('{REPO}')){repo=true;continue}
        any=true;const sep=os==='win'?'\\':'/';
        let g=t.replace('{HOME}',HOMEV[os]);
        if(/[\\/]$/.test(g))g=g.replace(/[\\/]+$/,'')+sep+'**';
        push(globs[OSK[os]],g);
      }
      if(any)n++;else skip.push([r,repo?skipWhy.repo:skipWhy.nofix]);
    }else if(s.kind==='registry'){n++;
      push(reg,s.win[0].replace(/^HKCU\\/i,'HKEY_USERS\\*\\').replace(/^HKLM\\/i,'HKEY_LOCAL_MACHINE\\')
        .replace(/^HKU\\/i,'HKEY_USERS\\').replace(/^HKCR\\/i,'HKEY_CLASSES_ROOT\\')+'\\*');
    }else if(s.kind==='eventlog'){n++;push(globs.windows,WINEVT+evtxFile(s.channel))}
    else if(s.kind==='process'){n++;s.names.forEach(x=>push(procs,x.replace(/\.exe$/i,'')))}
    else if(s.kind==='network'){n++;(s.ports||[]).forEach(x=>push(ports,x));(s.hosts||[]).forEach(x=>push(hosts,x))}
    else skip.push([r,s.why||skipWhy.manual]);
  }
  let src='';
  for(const os of ['windows','macos','linux'])if(globs[os].length)
    src+=`  - name: ${os[0].toUpperCase()+os.slice(1)}\n    precondition: |\n      ${PRE[os]}\n    query: |\n      LET Globs = [${globs[os].map(ysq).join(', ')}]\n      LET Hits = SELECT OSPath, Size, Mode.String AS Mode, Mtime, Btime, Ctime\n        FROM glob(globs=Globs)\n        WHERE NOT IsDir\n      SELECT *, if(condition=Upload, then=upload(file=OSPath)) AS Upload\n      FROM Hits\n`;
  if(reg.length)src+=`  - name: WindowsRegistry\n    precondition: |\n      ${PRE.windows}\n    query: |\n      SELECT OSPath, Name, Data, Mtime\n      FROM glob(globs=[${reg.map(ysq).join(', ')}], accessor='registry')\n`;
  if(procs.length)src+=`  - name: Processes\n    query: |\n      SELECT Pid, Ppid, Name, Exe, CommandLine, CreateTime, Username\n      FROM pslist()\n      WHERE Name =~ ${ysq('(?i)^('+procs.map(reEsc).join('|')+')(\\.exe)?$')}\n`;
  if(ports.length)src+=`  - name: Network\n    query: |\n      SELECT Pid, FamilyString AS Family, TypeString AS Type, Laddr, Raddr, Status\n      FROM netstat()\n      WHERE ${ports.map(x=>`Laddr.Port = ${x} OR Raddr.Port = ${x}`).join('\n        OR ')}\n`;
  if(!src)src='  []\n';
  const text=`name: ${slug}\ndescription: |\n  ${oneLine(p.name||'AI triage plan')} - artifacts picked in the collection plan${p.host?' for '+oneLine(p.host,60):''}.\n\n  Generated by the ai-dfir-toolkit site from the catalog's collection specs.\n  Metadata only unless Upload is set: credential stores are in here, so pulling\n  them back is a decision, not a default.${hosts.length?`\n  Network rows also name these endpoints, which netstat() cannot match by name:\n  ${hosts.join(', ')}`:''}\nauthor: AI Agent Artifact Catalog (ai-dfir-toolkit)\ntype: CLIENT\nparameters:\n  - name: Upload\n    description: Upload matching files rather than only recording their metadata.\n    type: bool\n    default: "N"\nsources:\n${src}`;
  return {name:slug+'.yaml',mime:'text/yaml',text,n,skip,
    how:'Import the definition (Server Artifacts &#8594; Upload, or <code style="display:inline">--definitions</code>), then collect:',
    cmd:`velociraptor --definitions . artifacts collect ${slug} --output ${(triageOpts().case||planSlug()).replace(/[^\w.-]+/g,'_')}.zip`};
}
function faPlan(){
  const p=activePlan()||{}, skip=[], byTool={};
  const fa=(t,os)=>{let x=t;
    if(os==='win')x=x.replace(/^\{HOME\}\\AppData\\Roaming/i,'%%users.appdata%%').replace(/^\{HOME\}\\AppData\\Local/i,'%%users.localappdata%%').replace(/^\{HOME\}/,'%%users.homedir%%');
    else x=x.replace(/^\{HOME\}/,'%%users.homedir%%');
    return /[\\/]$/.test(x)?x+'**':x};
  const OSN={win:'Windows',mac:'Darwin',linux:'Linux'};
  let n=0;
  for(const r of planRowsOrdered()){
    const s=r.spec||{kind:'manual'};
    const g=byTool[r.entry_id]=byTool[r.entry_id]||{tool:r.tool,files:{win:[],mac:[],linux:[]},keys:[],urls:new Set()};
    if(s.kind==='path'){let any=false,repo=false;
      for(const os of ['win','mac','linux'])for(const t of (s[os]||[])){if(t.startsWith('{REPO}')){repo=true;continue}
        any=true;const v=fa(t,os);if(!g.files[os].includes(v))g.files[os].push(v)}
      if(any)n++;else skip.push([r,repo?skipWhy.repo:skipWhy.nofix]);
    }else if(s.kind==='registry'){n++;
      g.keys.push(s.win[0].replace(/^HKCU\\/i,'HKEY_USERS\\%%users.sid%%\\').replace(/^HKLM\\/i,'HKEY_LOCAL_MACHINE\\').replace(/^HKU\\/i,'HKEY_USERS\\').replace(/^HKCR\\/i,'HKEY_CLASSES_ROOT\\'));
    }else if(s.kind==='eventlog'){n++;const v=WINEVT+evtxFile(s.channel);if(!g.files.win.includes(v))g.files.win.push(v)}
    else if(s.kind==='process'||s.kind==='network')skip.push([r,skipWhy.live]);
    else skip.push([r,s.why||skipWhy.manual]);
  }
  const docs=[];
  for(const [eid,g] of Object.entries(byTool)){
    const srcs=[], oses=new Set();
    for(const os of ['win','mac','linux'])if(g.files[os].length){oses.add(OSN[os]);
      srcs.push(`- type: FILE\n  attributes:\n    paths:\n${g.files[os].map(x=>'    - '+ysq(x)).join('\n')}\n    separator: ${ysq(os==='win'?'\\':'/')}\n  supported_os: [${OSN[os]}]`)}
    if(g.keys.length){oses.add('Windows');srcs.push(`- type: REGISTRY_KEY\n  attributes:\n    keys:\n${g.keys.map(x=>'    - '+ysq(x)).join('\n')}\n  supported_os: [Windows]`)}
    if(!srcs.length)continue;
    const camel=g.tool.replace(/\(.*\)/,'').split(/[^A-Za-z0-9]+/).filter(Boolean).map(w=>w[0].toUpperCase()+w.slice(1)).join('');
    docs.push(`name: ${planSlug()}${camel}\ndoc: ${ysq(`${g.tool} (${eid}) - rows picked in the collection plan ${oneLine(p.name||'',60)}`.trim())}\nsources:\n${srcs.join('\n')}\nsupported_os: [${[...oses].sort().join(', ')}]`);
  }
  const text=`# ForensicArtifacts-format definitions for one collection plan, generated by the\n# ai-dfir-toolkit site. Spec: https://github.com/ForensicArtifacts/artifacts\n# Load into Plaso, GRR or Timesketch alongside their stock definitions.\n---\n${docs.join('\n---\n')}\n`;
  return {name:'aidfir-'+planSlug().toLowerCase()+'.yaml',mime:'text/yaml',text,n,skip,
    how:'Drop the file into your artifact definitions directory and name the definitions when you collect, e.g. with Plaso:',
    cmd:`log2timeline.py --artifact-definitions ./artifacts --artifact-filters ${Object.keys(byTool).length?planSlug()+'*':''} ${planSlug()}.plaso /`};
}
function pyPlan(){
  const p=activePlan()||{}, skip=[], out=[];
  const tok=(t,os)=>{let x=t;
    if(x.startsWith('{REPO}'))return x.replace(/^\{REPO\}[\\/]?/,'').replace(/\\/g,'/');
    if(os==='win')x=x.replace(/^\{HOME\}\\AppData\\Roaming/i,'$APPDATA').replace(/^\{HOME\}\\AppData\\Local/i,'$LOCALAPPDATA').replace(/^\{HOME\}/,'~');
    else x=x.replace(/^\{HOME\}/,'~');
    return x};
  for(const r of planRowsOrdered()){
    const s=r.spec||{kind:'manual'};
    if(s.kind!=='path'){skip.push([r,s.kind==='manual'?(s.why||skipWhy.manual):s.kind==='registry'?skipWhy.reg:skipWhy.live]);continue}
    const all=['win','mac','linux'].flatMap(os=>(s[os]||[]).map(t=>[os,t]));
    if(!all.length){skip.push([r,skipWhy.nofix]);continue}
    const proj=all.every(([,t])=>t.startsWith('{REPO}')), paths=[...new Set(all.filter(([,t])=>t.startsWith('{REPO}')===proj).map(([os,t])=>tok(t,os)))];
    const oses=[...new Set(all.map(([os])=>({win:'windows',mac:'macos',linux:'linux'})[os]))];
    const type=paths.some(x=>/[*?\[]/.test(x))?'glob':paths.every(x=>/[\\/]$/.test(x))?'dir':'file';
    out.push(`  - id: ${r.anchor.replace(/[^A-Za-z0-9_]+/g,'_')}\n    name: ${ysq(oneLine(r.tool+': '+r.artifact,120))}\n    repo_cat: cross\n    cosai: []\n    os: [${oses.join(', ')}]\n    scope: ${proj?'project':'user'}\n    type: ${type}\n    sensitivity: ${s.secret?'secret':'normal'}\n    paths:\n${paths.map(x=>'      - '+ysq(x)).join('\n')}\n    notes: ${ysq(oneLine(r.description,200))}`);
  }
  const text=`# targets.yaml subset for one collection plan - ${oneLine(p.name||'',60)}\n# Generated by the ai-dfir-toolkit site; same schema as collectors/targets.yaml.\n# Project-scoped rows need --project-dir. Secrets are hashed, not copied,\n# unless you pass --collect-secrets.\nversion: 1\n\ntargets:\n${out.join('\n\n')}\n`;
  return {name:'targets-'+planSlug().toLowerCase()+'.yaml',mime:'text/yaml',text,n:out.length,skip,
    how:'Run the repository collector against this file instead of the full registry:',
    cmd:(()=>{const o=triageOpts(),rl=repoList();return `python3 collectors/collect_ai_artifacts.py --targets targets-${planSlug().toLowerCase()}.yaml --case-id ${shq(o.case||'IR-001')} --operator ${shq(o.operator||'you')} --output ${shq(o.out||'./cases')}${rl.length?rl.map(r=>' --project-dir '+shq(r)).join(''):(out.some(x=>/scope: project/.test(x))?' --project-dir /path/to/repo':'')}${o.secrets?' --collect-secrets':''}`})()};
}
const FW={native:{label:'Native script'},velo:{label:'Velociraptor',make:veloPlan,
    feed:'velociraptor',feedLabel:'per-tool artifact definitions',note:'Best for a fleet, or when you already run it. One artifact, one source per OS, metadata-only unless Upload is set.'},
  kape:{label:'KAPE',make:kapePlan,feed:'kape',feedLabel:'per-tool .tkape targets',
    note:'Windows only. One target file holding every picked row KAPE can express; the compound AIAgents_P1 target is the fallback when there is no time to pick.'},
  fa:{label:'ForensicArtifacts',make:faPlan,feed:'',feedLabel:'',
    note:'The format Plaso, GRR and Timesketch read. One definition per picked tool, FILE and REGISTRY_KEY sources with knowledge-base tokens.'},
  py:{label:'Python collector',make:pyPlan,feed:'',feedLabel:'',
    note:'The repository\'s cross-platform collector, scoped to this plan. Needs Python 3 and PyYAML on the host; hashes everything and writes a chain-of-custody manifest.'}};
function fwPanel(fw){
  const d=FW[fw], x=d.make();
  const tools=[...new Set(planRowsOrdered().map(r=>r.entry_id))].map(id=>TOOLMAP[id]).filter(Boolean);
  const pre=fw==='velo'?tools.filter(t=>t.velo).map(t=>t.velo):fw==='kape'?tools.filter(t=>t.kape).map(t=>t.kape):[];
  const bySkip={};for(const [r,why] of x.skip)(bySkip[why]=bySkip[why]||[]).push(r);
  return `<div class="fw"><div class="fwc">
    <p class="gnote">${d.note}</p>
    <p class="tcount">${x.n} of ${planRowsOrdered().length} picked rows rendered${x.skip.length?`, <b>${x.skip.length}</b> not expressible in this format (listed below)`:''}.</p>
    <div class="gbtns"><button class="btn primary" id="fwDl">Download ${esc(x.name)}</button>
      <button class="btn" id="fwCopy">Copy</button></div>
    ${tformHTML()}
    <p class="gnote" style="margin-top:8px">${x.how}</p>
    <div class="cmdwrap"><button class="btn mini" id="tCmdCopy">Copy</button><pre class="tcmd" id="tCmd">${esc(runCmd())}</pre></div>
    ${pre.length?`<p class="gnote" style="margin-top:8px">Or use the repository's ${d.feedLabel} for the picked tools:
      <code style="display:inline">${pre.map(esc).join(' ')}</code> &middot;
      <a href="${REPO_URL}/tree/main/artifacts/docs/api/${d.feed}" target="_blank" rel="noopener">browse &#8599;</a></p>`:''}
    ${x.skip.length?`<details class="fwskip"><summary class="gnote">${x.skip.length} row${x.skip.length===1?'':'s'} this format cannot carry</summary>
      ${Object.entries(bySkip).map(([why,rs])=>`<p class="gnote"><b>${esc(why)}</b></p><ul class="skiplist">${rs.map(r=>
        `<li><button class="lnk" data-row="${esc(r.anchor)}">${esc(r.tool)} &middot; ${esc(r.artifact)}</button></li>`).join('')}</ul>`).join('')}
      <p class="gnote">The native script carries every one of these as a manifest line, so nothing is lost by running both.</p></details>`:''}
    <details><summary class="gnote">Preview</summary><pre>${esc(x.text)}</pre></details>
  </div></div>`;
}
function triageHTML(){
  if(!picks.size)return '';
  const osL={win:'Windows (PowerShell)',mac:'macOS (bash)',linux:'Linux (bash)'};
  const sc=triageScript(triageOS);
  refreshRowStates();
  const prow=planRowsOrdered();
  return `<div class="tbuild"><h3>Collect it</h3>
    <p class="gnote">The plan rendered for whichever collector you will run. All five read the same
    per-row collection spec, so they agree on what each path is; they differ in what they can carry.
    The native script is the default because it needs nothing installed on the host. Nothing typed here leaves your browser.</p>
    ${triageSummaryHTML(prow)}
    <details class="brun"><summary class="gnote">Before you run it</summary><ol>${BEFORE_RUN.map(x=>`<li>${x}</li>`).join('')}</ol></details>
    <div class="seg small" role="group" aria-label="Collection method">${Object.entries(FW).map(([k,d])=>
      `<button class="segbtn${triageFw===k?' on':''}" data-fw="${k}">${d.label}</button>`).join('')}</div>
    ${triageFw==='native'?`
      <div class="seg small" role="group" aria-label="Operating system" style="margin-top:8px">${Object.entries(osL).map(([k,l])=>
        `<button class="segbtn${triageOS===k?' on':''}" data-os="${k}">${l}</button>`).join('')}</div>
      <p class="tcount">${sc.t.n} target line${sc.t.n===1?'':'s'} for ${esc(osL[triageOS])}${sc.t.manual?` · ${sc.t.manual} need a person (written to the manifest as manual)`:''}${
        sc.t.skipped?` · ${sc.t.skipped} do not apply to this OS`:''}. Volatile state first; credentials hashed, not copied, unless you pass
        ${triageOS==='win'?'<code>-CollectSecrets</code>':'<code>--collect-secrets</code>'}. Repository-scoped rows need
        ${triageOS==='win'?'<code>-RepoPath</code>':'<code>--repo</code>'}; limit to one user with
        ${triageOS==='win'?'<code>-HomePath</code>':'<code>--home</code>'}.</p>
      ${tformHTML()}
      <div class="gbtns"><button class="btn primary" id="tDl">Download ${esc(sc.name)}</button>
        <button class="btn" id="tCopy">Copy script</button></div>
      <p class="gnote" style="margin-top:8px">Then, on the host:</p>
      <div class="cmdwrap"><button class="btn mini" id="tCmdCopy">Copy</button><pre class="tcmd" id="tCmd">${esc(runCmd())}</pre></div>
      <details><summary class="gnote">Preview the script</summary><pre>${esc(sc.text)}</pre></details>`
    :fwPanel(triageFw)}
  </div>`;
}
function wireTriage(){
  $$('#main .segbtn[data-fw]').forEach(b=>b.onclick=()=>{triageFw=b.dataset.fw;renderMain()});
  $$('#main .segbtn[data-os]').forEach(b=>b.onclick=()=>{triageOS=b.dataset.os;renderMain()});
  const dl=$('#tDl');if(dl)dl.onclick=()=>{const s=triageScript(triageOS);
    download(s.name,s.text.replace(/\r?\n/g,triageOS==='win'?'\r\n':'\n'),'text/plain');flash(dl,'downloaded')};
  const cp=$('#tCopy');if(cp)cp.onclick=()=>copy(triageScript(triageOS).text,cp);
  const fd=$('#fwDl');if(fd)fd.onclick=()=>{const x=FW[triageFw].make();
    download(x.name,x.text.replace(/\r?\n/g,triageFw==='kape'?'\r\n':'\n'),x.mime);flash(fd,'downloaded')};
  const fc=$('#fwCopy');if(fc)fc.onclick=()=>copy(FW[triageFw].make().text,fc);
  $$('#main .fwskip [data-row]').forEach(b=>b.onclick=()=>openDrawer(b.dataset.row,b));
  const cc=$('#tCmdCopy');if(cc)cc.onclick=()=>copy(runCmd(),cc);
  // Text inputs save on every keystroke and refresh the command in place; the
  // ones that change what a row will do (repo paths, home, secrets) re-render
  // on change so the annotations beside the rows follow.
  $$('#main .tform input[data-opt]').forEach(i=>{const k=i.dataset.opt;
    if(i.type==='checkbox'){i.onchange=()=>{triageOpts()[k]=i.checked;const a=activePlan();if(a){a.updated=nowISO();savePlans()}renderMain()};return}
    i.oninput=()=>{triageOpts()[k]=i.value;const a=activePlan();if(a){a.updated=nowISO();savePlans()}const c=$('#tCmd');if(c)c.textContent=runCmd()};
    if(k==='repos'||k==='home')i.onchange=()=>renderMain();
  });
}
"""
