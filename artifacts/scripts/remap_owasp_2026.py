#!/usr/bin/env python3
"""Remap OWASP LLM Top 10 IDs from the 2025 list to the 2026 list.

Eight of the ten IDs changed meaning between the two publications, and the
remapping is a permutation containing chains: 2025 LLM10 becomes LLM06, and 2025
LLM06 becomes LLM03. Applying the pairs one after another would move the same ID
twice - everything that had just become LLM06 would then be turned into LLM03.

So every occurrence is rewritten in ONE pass, by a function that reads the
original matched text. A match is replaced exactly once and never revisited,
which makes cascades impossible rather than merely unlikely.

    python owasp2026.py            # dry run, prints every change
    python owasp2026.py --apply
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import json

REPO = Path(__file__).resolve().parent.parent.parent

# 2025 id -> (2026 id, 2026 title), from the pinned OWASP reference data rather
# than a copy in this script, so the remap table and the MAPPINGS index cannot
# disagree. LLM07 -> LLM08 is renamed and widened, not dropped: the 2026 entry
# covers any non-user-facing content assembled into the context window - tool
# schemas, retrieved policy text, developer instructions - of which the system
# prompt is one case.
_OWASP = json.loads((REPO / "artifacts" / "schema" / "owasp.json").read_text(encoding="utf-8"))
MAP = {old: (new, _OWASP["llm_2026"]["items"][new]["title"])
       for old, new in _OWASP["llm_2025_to_2026"].items()}

# LLM07 -> LLM08 also renames the category, so any prose naming the old title has
# to move with it or the file will describe one thing and tag another.
TITLE_FIX = {
    "System Prompt Leakage": "Hidden Context Exposure",
}

PATTERN = re.compile(r"\bLLM(0[1-9]|10)(:20(?:25|26))?\b")


def rewrite(text: str) -> tuple[str, int]:
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        old = "LLM" + m.group(1)
        new = MAP[old][0]
        year = ":2026" if m.group(2) else ""
        if new + year != m.group(0):
            n += 1
        return new + year

    out = PATTERN.sub(repl, text)
    for a, b in TITLE_FIX.items():
        if a in out:
            n += out.count(a)
            out = out.replace(a, b)
    return out, n


def targets() -> list[Path]:
    out: list[Path] = []
    for d in sorted(REPO.glob("0*-*")):
        if d.is_dir():
            for p in sorted(d.rglob("*")):
                if p.suffix.lower() in (".yml", ".yaml", ".yar", ".rules", ".md"):
                    out.append(p)
    det = REPO / "artifacts" / "detections"
    if det.is_dir():
        for p in sorted(det.rglob("*")):
            if p.suffix.lower() in (".yml", ".yaml", ".yar", ".rules", ".md"):
                out.append(p)
    out.append(REPO / "MAPPINGS.md")
    return [p for p in out if p.is_file()]


def main() -> int:
    apply = "--apply" in sys.argv
    total_files = total_changes = 0
    for p in targets():
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        new, n = rewrite(text)
        if new == text:
            continue
        total_files += 1
        total_changes += n
        rel = p.relative_to(REPO)
        befores = sorted(set(PATTERN.findall(text)))
        afters = sorted(set(PATTERN.findall(new)))
        print(f"{rel}")
        print(f"    {[f'LLM{b[0]}' for b in befores]} -> {[f'LLM{a[0]}' for a in afters]}")
        if apply:
            with p.open("w", encoding="utf-8", newline="\n") as fh:
                fh.write(new)
    print(f"\n{total_files} file(s), {total_changes} id/title change(s)"
          f"{'' if apply else '  [DRY RUN - pass --apply]'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
