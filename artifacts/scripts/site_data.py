#!/usr/bin/env python3
"""Build-time loaders for the catalog site's non-catalog data.

build_site.py renders the catalog itself from docs/api/catalog.json. This
module gathers everything else the site shows - detection rules, the ATLAS /
OWASP indexes, case studies, and the investigation guide - so the site stays a
pure function of files already in the repository.

The rule corpus is three formats with three different metadata conventions.
The handoff assumed YAML front matter throughout, which is true only of Sigma:

  Sigma    .yml    YAML document; title/level/logsource/falsepositives/tags
  YARA     .yar    meta: block, `key = "value"` lines; severity/atlas/owasp
  Suricata .rules  alert(...) with msg: and metadata: key value pairs

Each gets its own extractor, and fields a format does not carry are simply
absent rather than faked - the same omit-rather-than-guess rule the catalog
itself follows.
"""
import hashlib
import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent.parent
CATALOG_RULES = REPO / "artifacts" / "detections" / "sigma"
GUIDE = REPO / "docs" / "ai-dfir-investigation-guide.md"
MAPPINGS = REPO / "MAPPINGS.md"

# Discovered, not listed. This was a hardcoded list of six directories, so every
# category added after it was written - 07, 08, 09 - was silently absent from the
# site while README, MAPPINGS and the guide all counted it. The page reported 55
# detections against 68 on disk, and nothing failed, because a shorter list looks
# exactly like a complete one.
CATEGORY_DIRS = sorted(
    d.name for d in REPO.iterdir()
    if d.is_dir() and re.match(r"^\d{2}-", d.name)
)

CATEGORY_LABEL = {
    "01-llm-prompt-injection": "LLM prompt injection",
    "02-mcp-attacks": "MCP attacks",
    "03-model-supply-chain": "Model supply chain",
    "04-ai-infrastructure": "AI infrastructure",
    "05-copilot-assistant-abuse": "Copilot / assistant abuse",
    "06-rag-vector-db": "RAG & vector DB",
    "07-runtime-ai-malware": "Runtime AI-malware",
    "08-agentic-orchestration": "Agentic orchestration & C2",
    "09-agent-memory-forensics": "Agent memory & context",
    "artifacts/detections/sigma": "Agent artifact catalog",
}


def category_label(dirname: str) -> str:
    """Human label for a rule directory, derived when it is not named above.

    A new category must never be invisible just because nobody updated a dict,
    which is the failure this whole block exists to prevent.
    """
    if dirname in CATEGORY_LABEL:
        return CATEGORY_LABEL[dirname]
    stem = re.sub(r"^\d{2}-", "", dirname).replace("-", " ")
    return stem[:1].upper() + stem[1:]


def _norm_atlas(v: str) -> str:
    """T0051.000, AML.T0051, attack.atlas.t0051 -> AML.T0051.000 style."""
    v = v.strip().replace("attack.atlas.", "").upper()
    if not v:
        return ""
    if v.startswith("AML."):
        v = v[4:]
    if not v.startswith("T"):
        return ""
    return "AML." + v


def _norm_owasp(v: str) -> str:
    """owasp.llm01, LLM01:2025 -> LLM01."""
    m = re.search(r"LLM\s*0?(\d+)", v.strip().upper().replace("OWASP.", ""))
    return f"LLM{int(m.group(1)):02d}" if m else ""


def _tags_split(tags):
    """Pull ATLAS / OWASP / ATT&CK out of a Sigma tags list."""
    atlas, owasp, attack = [], [], []
    for t in tags or []:
        t = str(t)
        low = t.lower()
        if "atlas" in low:
            v = _norm_atlas(t)
            if v:
                atlas.append(v)
        elif "owasp" in low:
            v = _norm_owasp(t)
            if v:
                owasp.append(v)
        elif low.startswith("attack."):
            attack.append(t)
    return atlas, owasp, attack


def parse_sigma(path: Path):
    """Sigma: a real YAML document. Multi-document files take the first doc."""
    raw = path.read_text(encoding="utf-8")
    try:
        doc = next(d for d in yaml.safe_load_all(raw) if isinstance(d, dict))
    except (StopIteration, yaml.YAMLError):
        return None
    ls = doc.get("logsource") or {}
    atlas, owasp, attack = _tags_split(doc.get("tags"))
    return {
        "format": "Sigma",
        "title": doc.get("title", path.stem),
        "level": doc.get("level", ""),
        "status": doc.get("status", ""),
        "description": (doc.get("description") or "").strip(),
        "logsource": " / ".join(str(v) for v in (
            ls.get("product"), ls.get("category"), ls.get("service")) if v),
        "falsepositives": [str(f) for f in (doc.get("falsepositives") or [])],
        "references": [str(r) for r in (doc.get("references") or [])],
        "atlas": atlas, "owasp": owasp, "attack": attack,
        "body": raw,
    }


def parse_yara(path: Path):
    """YARA: not YAML. Read the first meta: block as key = "value" lines."""
    raw = path.read_text(encoding="utf-8")
    meta = {}
    block = re.search(r"meta:\s*\n(.*?)(?:\n\s*(?:strings|condition):)", raw, re.S)
    if block:
        for k, v in re.findall(r'(\w+)\s*=\s*"([^"]*)"', block.group(1)):
            meta.setdefault(k.lower(), v)
    names = re.findall(r"^\s*rule\s+(\w+)", raw, re.M)
    header = re.search(r"/\*(.*?)\*/", raw, re.S)
    atlas = [_norm_atlas(x) for x in re.findall(r"AML\.T[\d.]+|T\d{4}(?:\.\d+)?",
             (meta.get("atlas", "") + " " + (header.group(1) if header else "")))]
    owasp = [_norm_owasp(x) for x in re.findall(r"LLM\s*0?\d+",
             (meta.get("owasp", "") + " " + (header.group(1) if header else "")))]
    return {
        "format": "YARA",
        "title": path.stem.replace("_", " "),
        "level": meta.get("severity", ""),
        "status": "",
        "description": meta.get("description", ""),
        "logsource": f"{len(names)} rule{'s' if len(names) != 1 else ''}: " + ", ".join(names[:4])
                     + ("..." if len(names) > 4 else "") if names else "",
        "falsepositives": [],
        "references": re.findall(r"https?://\S+", header.group(1)) if header else [],
        "atlas": sorted({a for a in atlas if a}),
        "owasp": sorted({o for o in owasp if o}),
        "attack": [],
        "body": raw,
    }


def parse_suricata(path: Path):
    """Suricata: alert(...) signatures. msg: is the title, metadata: carries tags."""
    raw = path.read_text(encoding="utf-8")
    joined = raw.replace("\\\n", " ")
    msgs = re.findall(r'msg:\s*"([^"]+)"', joined)
    classtypes = re.findall(r"classtype:\s*([\w-]+)", joined)
    meta_blob = " ".join(re.findall(r"metadata:\s*([^;]+);", joined))
    header = re.search(r"#(.*?)(?:\nalert)", raw, re.S)
    scope = (meta_blob + " " + (header.group(1) if header else ""))
    atlas = [_norm_atlas(x) for x in re.findall(r"AML\.T[\d.]+|T\d{4}(?:\.\d+)?", scope)]
    owasp = [_norm_owasp(x) for x in re.findall(r"LLM\s*0?\d+", scope)]
    return {
        "format": "Suricata",
        "title": (msgs[0] if msgs else path.stem.replace("_", " ")),
        "level": "",
        "status": "",
        "description": "",
        "logsource": f"{len(msgs)} signature{'s' if len(msgs) != 1 else ''}"
                     + (f" · {classtypes[0]}" if classtypes else ""),
        "falsepositives": [],
        "references": re.findall(r"reference:\s*url,([^;]+);", joined),
        "atlas": sorted({a for a in atlas if a}),
        "owasp": sorted({o for o in owasp if o}),
        "attack": [],
        "body": raw,
    }


PARSERS = {".yml": parse_sigma, ".yaml": parse_sigma, ".yar": parse_yara, ".rules": parse_suricata}


def load_rules(mapping_rows):
    """Every rule file in the repo, joined with its MAPPINGS.md row.

    MAPPINGS.md covers the six numbered category directories only, so the
    catalog's own Sigma rules have no row there; for those the ATLAS/OWASP
    values come from the rules' own tags, which is the more reliable source
    either way.
    """
    rules = []
    dirs = [(REPO / d, d) for d in CATEGORY_DIRS]
    dirs.append((CATALOG_RULES, "artifacts/detections/sigma"))
    for d, label in dirs:
        if not d.is_dir():
            continue
        for path in sorted(d.iterdir()):
            parser = PARSERS.get(path.suffix.lower())
            if not parser or not path.is_file():
                continue
            r = parser(path)
            if not r:
                continue
            row = mapping_rows.get(path.name, {})
            # MAPPINGS is the curated source where present; tags fill the gaps.
            atlas = sorted(set(r["atlas"]) | {_norm_atlas(x) for x in row.get("atlas", [])})
            owasp = sorted(set(r["owasp"]) | {_norm_owasp(x) for x in row.get("owasp", [])})
            r.update({
                "file": path.name,
                "path": str(path.relative_to(REPO)),
                "category": category_label(label),
                "atlas": [a for a in atlas if a],
                "owasp": [o for o in owasp if o],
                "reference": row.get("reference", ""),
            })
            rules.append(r)
    return rules


def load_mappings():
    """Parse MAPPINGS.md: per-rule rows plus the ATLAS / OWASP index tables."""
    rows, atlas_index, owasp_index = {}, [], []
    if not MAPPINGS.exists():
        return rows, atlas_index, owasp_index
    section = None
    for line in MAPPINGS.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            head = line[3:].strip().lower()
            section = ("atlas_index" if "atlas technique index" in head
                       else "owasp_index" if "owasp top 10" in head and "index" in head
                       else "rules")
            continue
        if not line.startswith("|") or set(line.strip()) <= set("|-: "):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not cells or cells[0].lower() in ("rule", "atlas id", "owasp"):
            continue
        if section == "rules" and len(cells) >= 5:
            name = cells[0].strip("`")
            rows[name] = {
                "format": cells[1],
                "atlas": [x.strip() for x in cells[2].split(",") if x.strip() and x.strip() != "-"],
                "owasp": [x.strip() for x in cells[3].split(",") if x.strip() and x.strip() != "-"],
                "reference": cells[4],
            }
        elif section == "atlas_index" and len(cells) >= 3:
            atlas_index.append({"id": _norm_atlas(cells[0]), "raw": cells[0],
                                "title": cells[1], "count": int(re.sub(r"\D", "", cells[2]) or 0)})
        elif section == "owasp_index" and len(cells) >= 3:
            owasp_index.append({"id": _norm_owasp(cells[0]), "raw": cells[0],
                                "title": cells[1], "count": int(re.sub(r"\D", "", cells[2]) or 0)})
    return rows, atlas_index, owasp_index


def load_case_studies():
    d = REPO / "artifacts" / "case-studies"
    out = []
    for path in sorted(d.glob("*.yml")) if d.is_dir() else []:
        c = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        iocs = []
        for i in (c.get("iocs") or []):
            if isinstance(i, dict):
                iocs.append({"type": str(i.get("type", "")),
                             "value": str(i.get("value", "")),
                             "description": str(i.get("description", ""))})
            else:
                iocs.append({"type": "", "value": str(i), "description": ""})
        refs = []
        for r in (c.get("references") or []):
            if isinstance(r, dict):
                refs.append({"title": str(r.get("title", "")), "url": str(r.get("url", ""))})
            else:
                refs.append({"title": str(r), "url": str(r)})

        affects = c.get("affects", "")
        affects = affects if isinstance(affects, str) else ", ".join(affects or [])
        out.append({
            "id": c.get("id", path.stem),
            "title": c.get("title", ""),
            "date_range": str(c.get("date_range", "")),
            "disclosed": str(c.get("disclosed", "")),
            "affects": affects,
            # A case can touch several catalogued tools, so the jump targets are a
            # list pulled out of whatever affects says - prose and ids both.
            "affects_ids": re.findall(r"AIRT-\d{4}", affects),
            "summary": c.get("summary", ""),
            # Provenance, on the same scale entries use. A case study asserts things
            # about someone else's incident, so where the claim came from travels
            # with it rather than living in a commit message.
            "confidence": str(c.get("confidence", "")),
            "basis": str(c.get("basis", "")),
            "contested": str(c.get("contested", "")),
            "atlas": [str(a) for a in (c.get("atlas") or [])],
            "iocs": iocs,
            "response_actions": [str(a) for a in (c.get("response_actions") or [])],
            "lesson": c.get("lesson", ""),
            "references": refs,
        })
    return out


def _anchor(text: str) -> str:
    """GitHub's heading anchor slug, so guide links land on the right section."""
    s = re.sub(r"[^\w\s-]", "", text.lower()).strip()
    return re.sub(r"[\s_]+", "-", s)


DIAGRAMS = REPO / "artifacts" / "docs" / "site-assets" / "diagrams"


def _inline_diagrams(html_body: str, raw: str):
    """Swap each rendered mermaid code block for its pre-rendered SVG.

    scripts/render_diagrams.py writes content-addressed SVGs, so a diagram
    edited without re-rendering has no matching file and is reported here
    rather than silently shipping as raw mermaid source.
    """
    sources = re.findall(r"```mermaid\n(.*?)```", raw, re.S)
    missing, it = [], iter(sources)

    def repl(_m):
        try:
            src = next(it)
        except StopIteration:
            return _m.group(0)
        h = hashlib.sha1(src.strip().encode("utf-8")).hexdigest()[:12]
        svg = DIAGRAMS / f"d-{h}-default.svg"
        if not svg.exists():
            missing.append(h)
            return _m.group(0)
        return f'<figure class="mmd">{svg.read_text(encoding="utf-8")}</figure>' 

    out = re.sub(r"<pre><code class=\"language-mermaid\">.*?</code></pre>",
                 repl, html_body, flags=re.S)
    return out, missing


def _demote_headings(html: str) -> str:
    """Shift the guide's heading tree down one level.

    The guide is a document in its own right, so its parts are authored as h1 -
    and it gets injected into a page that already has one, leaving seven h1s
    competing and no usable outline for a screen reader.

    The whole tree moves, not just the top: demoting h1 to h2 alone would put a
    guide Part and a guide Section at the same level, which is worse than the
    problem it fixes. Deepest first, so nothing is shifted twice. Ids are
    untouched, so the table of contents and every #g- anchor still resolve.
    """
    for level in range(5, 0, -1):
        html = re.sub(rf"<(/?)h{level}(\b)", rf"<\g<1>h{level + 1}\g<2>", html)
    return html


def load_guide():
    """Render the investigation guide to HTML at build time.

    Uses the `markdown` package rather than shipping a JS renderer, which keeps
    the page free of any runtime dependency. Returns the HTML plus a chaptered
    table of contents built from the h1/h2 structure.
    """
    if not GUIDE.exists():
        return {"html": "", "toc": [], "source": ""}
    import markdown as md
    raw = GUIDE.read_text(encoding="utf-8")
    html_body = md.markdown(raw, extensions=["fenced_code", "tables", "toc", "sane_lists"])
    html_body = _demote_headings(html_body)
    html_body, missing_diagrams = _inline_diagrams(html_body, raw)
    toc, part, fenced = [], None, False
    for line in raw.splitlines():
        # Shell comments inside fenced blocks look exactly like ATX headings.
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            continue
        m = re.match(r"^(#{1,2})\s+(.*)$", line)
        if not m:
            continue
        level, text = len(m.group(1)), m.group(2).strip()
        if level == 1:
            part = {"title": text, "anchor": _anchor(text), "sections": []}
            toc.append(part)
        elif part is not None:
            part["sections"].append({"title": text, "anchor": _anchor(text)})
    return {"html": html_body, "toc": toc, "missing_diagrams": missing_diagrams,
            "source": "docs/ai-dfir-investigation-guide.md"}
