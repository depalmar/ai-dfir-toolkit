#!/usr/bin/env python3
"""Pre-render the guide's mermaid diagrams to SVG.

    npm install mermaid@11          # once, anywhere
    python scripts/render_diagrams.py --mermaid <path-to>/mermaid.min.js

Mermaid is a 3.5 MB browser library, so inlining it would quadruple the page
and make the diagrams depend on JavaScript at read time. Instead each diagram
is rendered once, here, and the resulting SVG is committed; build_site.py
inlines it into the guide.

Filenames are content-addressed - d-<sha1(source)[:12]>-<theme>.svg - so a
diagram that changes gets a new name and its old SVG simply stops being
referenced. build_site.py fails loudly when a diagram has no matching file,
which makes "guide edited but diagrams not re-rendered" a build error rather
than a silently stale page. Light and dark variants are rendered together
because the site's theme toggle is prominent and a light SVG on the dark
surface looks broken.

This script is not part of the site build; CI never runs it. It is only
needed when the guide's mermaid blocks change.
"""
import argparse
import asyncio
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
GUIDE = ROOT / "docs" / "ai-dfir-investigation-guide.md"
OUT = ROOT / "artifacts" / "docs" / "site-assets" / "diagrams"
# One variant only. The guide's diagrams set their own node colours through
# classDef (GitHub-style light fills with dark text), so a dark render fights
# the source and produces light text on light fills. They are authored for a
# light background; build_site.py puts them on a light card in both themes.
THEME_VARS = {
    "default": {
        "background": "transparent", "primaryColor": "#f2e9e2",
        "primaryTextColor": "#1c1b19", "primaryBorderColor": "#c9a186",
        "secondaryColor": "#f4eec7", "tertiaryColor": "#e4eeda",
        "lineColor": "#8a7d70", "textColor": "#1c1b19",
        "mainBkg": "#f2e9e2", "nodeBorder": "#c9a186",
        "clusterBkg": "#fbfbfa", "clusterBorder": "#e4e1db",
        "edgeLabelBackground": "#ffffff", "fontSize": "15px",
    },
}
THEMES = tuple(THEME_VARS)


def blocks(text):
    """Every ```mermaid fence in the guide, in document order."""
    return re.findall(r"```mermaid\n(.*?)```", text, re.S)


def digest(src: str) -> str:
    return hashlib.sha1(src.strip().encode("utf-8")).hexdigest()[:12]


def svg_name(src: str, theme: str) -> str:
    return f"d-{digest(src)}-{theme}.svg"


async def render(sources, mermaid_js: Path):
    from playwright.async_api import async_playwright
    lib = mermaid_js.read_text(encoding="utf-8")
    OUT.mkdir(parents=True, exist_ok=True)
    written, skipped = 0, 0
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(executable_path="/opt/pw-browsers/chromium")
        page = await browser.new_page()
        await page.set_content("<!doctype html><body><div id=x></div></body>")
        await page.add_script_tag(content=lib)
        for i, src in enumerate(sources, 1):
            for theme in THEMES:
                dest = OUT / svg_name(src, theme)
                if dest.exists():
                    skipped += 1
                    continue
                svg = await page.evaluate(
                    """async ([src, vars, id]) => {
                        mermaid.initialize({startOnLoad:false, theme:'base',
                                            themeVariables:vars, securityLevel:'loose',
                                            flowchart:{htmlLabels:false, useMaxWidth:true}});
                        const {svg} = await mermaid.render('m'+id, src);
                        return svg;
                    }""", [src, THEME_VARS[theme], f"{i}{theme}"])
                # Strip the fixed max-width mermaid injects so the SVG scales
                # with the column instead of pinning to its rendered size.
                svg = re.sub(r'style="[^"]*max-width:[^";]*;?[^"]*"', 'style="max-width:100%"', svg, count=1)
                dest.write_text(svg, encoding="utf-8", newline="\n")
                written += 1
                print(f"  {dest.name}  ({len(svg)//1024} KB)")
        await browser.close()
    return written, skipped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mermaid", required=True, type=Path,
                    help="path to mermaid.min.js (npm install mermaid@11)")
    ap.add_argument("--prune", action="store_true",
                    help="delete SVGs no longer referenced by the guide")
    args = ap.parse_args()
    if not args.mermaid.exists():
        sys.exit(f"mermaid.min.js not found at {args.mermaid}")
    srcs = blocks(GUIDE.read_text(encoding="utf-8"))
    print(f"{len(srcs)} mermaid blocks in {GUIDE.name}")
    written, skipped = asyncio.run(render(srcs, args.mermaid))
    keep = {svg_name(s, t) for s in srcs for t in THEMES}
    stale = sorted(p for p in OUT.glob("d-*.svg") if p.name not in keep)
    for p in stale:
        if args.prune:
            p.unlink(); print(f"  pruned {p.name}")
        else:
            print(f"  stale (use --prune): {p.name}")
    print(f"{written} written, {skipped} already current, {len(stale)} stale")


if __name__ == "__main__":
    main()
