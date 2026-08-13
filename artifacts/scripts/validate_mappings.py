#!/usr/bin/env python3
"""Validate MAPPINGS.md against the rules actually on disk.

Two failure modes, both of which reached the published site:

  1. MAPPINGS.md references rule files that no longer exist, so the generated
     site emits dead links.
  2. Rule files exist that MAPPINGS.md never indexes, so the ATLAS and OWASP
     coverage tables undercount real coverage.

Run from the repository root or from artifacts/:

    python artifacts/scripts/validate_mappings.py
    python artifacts/scripts/validate_mappings.py --fix-list   # paths to remove/add
    python artifacts/scripts/validate_mappings.py --json       # machine-readable

Exit code 1 on any drift, so CI can gate on it.

Format note: MAPPINGS.md is parsed defensively. Any token that looks like a rule
filename is treated as a reference, whether it appears in a markdown table cell,
a link target, inline code, or bare text. That tolerates the file being
reformatted without silently missing references.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

RULE_SUFFIXES = (".yml", ".yaml", ".yar", ".yara", ".rules")

# Rule directories are numbered 01-… through 06-… plus the cross-tool sigma set.
RULE_DIR_PATTERN = re.compile(r"^\d{2}-")
EXTRA_RULE_DIRS = ("detections/sigma",)

# Anything that looks like a path ending in a rule suffix.
REFERENCE_PATTERN = re.compile(
    r"(?<![\w./-])((?:[\w.-]+/)*[\w.-]+(?:" + "|".join(re.escape(s) for s in RULE_SUFFIXES) + r"))(?![\w])"
)

# Directories that are never rule content.
IGNORE_DIRS = {".git", "node_modules", "__pycache__", "docs", "schema", "scripts",
               "catalog", "case-studies", ".github"}


def index_drift(mappings: Path, on_disk: set[str]) -> list[str]:
    """Check the ATLAS/OWASP index tables and the Scope line against the rows.

    The index is a hand-readable summary of the per-section tables, so it can
    disagree with them silently - and did, in both directions, before this
    existed. Columns are resolved from each table's own header: the layout
    varies (section 04 has no OWASP column), and the CVE / Reference column
    carries citations like "OWASP LLM10:2025" that are references to a category
    rather than mappings to it. Counting those inflates the index.
    """
    lines = mappings.read_text(encoding="utf-8").splitlines()
    atlas: dict[str, int] = {}
    owasp: dict[str, int] = {}
    columns: list[str] = []
    rows = 0

    for line in lines:
        if line.startswith("|") and "Rule" in line and "Format" in line:
            columns = [c.strip().lower() for c in line.strip().strip("|").split("|")]
            continue
        if not re.match(r"^\| `.*\.(yml|yaml|yar|rules)`", line):
            continue
        rows += 1
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        for i, name in enumerate(columns):
            if i >= len(cells):
                break
            if name == "atlas" and "ATT&CK" not in cells[i]:
                for tag in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", cells[i]):
                    atlas[tag] = atlas.get(tag, 0) + 1
            elif name == "owasp":
                for tag in re.findall(r"\bLLM\d{2}\b", cells[i]):
                    owasp[tag] = owasp.get(tag, 0) + 1

    def published(heading: str) -> dict[str, int]:
        out: dict[str, int] = {}
        try:
            start = next(i for i, l in enumerate(lines) if l.startswith(heading))
        except StopIteration:
            return out
        for line in lines[start + 1:]:
            if line.startswith("##"):
                break
            cells = [c.strip() for c in line.strip("|").split("|")]
            # >= 3, not == 3: the OWASP index gained a "was in 2025" column
            # when the list was remapped, and an exact width made the whole
            # table invisible to this check rather than failing loudly.
            if len(cells) >= 3 and cells[2].isdigit():
                out[cells[0]] = int(cells[2])
        return out

    problems = []
    for label, heading, counted in (
        ("ATLAS", "## ATLAS Technique Index", atlas),
        ("OWASP", "## OWASP Top 10 for LLM Applications 2026 Index", owasp),
    ):
        pub = published(heading)
        for tag in sorted(set(pub) | set(counted)):
            have, want = pub.get(tag), counted.get(tag, 0)
            if have is None:
                problems.append(f"{label} {tag} appears in {want} row(s) but has no index row")
            elif have != want:
                problems.append(f"{label} {tag} index says {have}, tables say {want}")

    # The Scope line is the number most often quoted elsewhere, so gate it too.
    scope = re.search(r"\*\*Scope:\*\* (\d+) rule files", "\n".join(lines))
    if scope and int(scope.group(1)) != len(on_disk):
        problems.append(
            f"Scope line says {scope.group(1)} rule files, {len(on_disk)} are on disk")
    if rows != len(on_disk):
        problems.append(f"{rows} indexed rule row(s) but {len(on_disk)} file(s) on disk")
    return problems


def find_repo_root(start: Path) -> Path:
    """Walk up until MAPPINGS.md or .git is found, so the script runs anywhere."""
    for candidate in [start, *start.parents]:
        if (candidate / "MAPPINGS.md").exists() or (candidate / ".git").exists():
            return candidate
    return start


def discover_rule_files(root: Path) -> set[str]:
    """Every rule file on disk, as a repo-relative POSIX path."""
    found: set[str] = set()

    search_dirs = [
        d for d in root.iterdir()
        if d.is_dir() and d.name not in IGNORE_DIRS and RULE_DIR_PATTERN.match(d.name)
    ]
    for extra in EXTRA_RULE_DIRS:
        for base in (root, root / "artifacts"):
            candidate = base / extra
            if candidate.is_dir():
                search_dirs.append(candidate)

    for directory in search_dirs:
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix.lower() in RULE_SUFFIXES:
                found.add(path.relative_to(root).as_posix())
    return found


def parse_references(mappings: Path) -> dict[str, list[int]]:
    """Referenced filenames mapped to the line numbers they appear on."""
    references: dict[str, list[int]] = {}
    for lineno, line in enumerate(mappings.read_text(encoding="utf-8").splitlines(), 1):
        if line.lstrip().startswith(("<!--", "> _")):
            continue
        for match in REFERENCE_PATTERN.finditer(line):
            references.setdefault(match.group(1), []).append(lineno)
    return references


def resolve(reference: str, on_disk: set[str]) -> str | None:
    """Match a reference to a real file, tolerating partial paths."""
    if reference in on_disk:
        return reference
    # Bare filename, or a path fragment - match on suffix.
    candidates = [p for p in on_disk if p == reference or p.endswith("/" + reference)]
    if len(candidates) == 1:
        return candidates[0]
    basename = reference.rsplit("/", 1)[-1]
    candidates = [p for p in on_disk if p.rsplit("/", 1)[-1] == basename]
    return candidates[0] if len(candidates) == 1 else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fix-list", action="store_true",
                    help="Print just the paths to remove from and add to MAPPINGS.md")
    ap.add_argument("--json", action="store_true", help="Machine-readable output")
    ap.add_argument("--root", type=Path, help="Repository root (auto-detected by default)")
    args = ap.parse_args()

    root = args.root or find_repo_root(Path(__file__).resolve().parent)
    mappings = root / "MAPPINGS.md"

    if not mappings.exists():
        print(f"MAPPINGS.md not found at {mappings}. Pass --root if the layout differs.")
        return 1

    on_disk = discover_rule_files(root)
    references = parse_references(mappings)

    if not on_disk:
        print("No rule files discovered. Check --root, or that rule directories "
              "match the NN-name convention.")
        return 1

    dangling: dict[str, list[int]] = {}
    referenced_real: set[str] = set()
    for reference, lines in references.items():
        resolved = resolve(reference, on_disk)
        if resolved:
            referenced_real.add(resolved)
        else:
            dangling[reference] = lines

    unindexed = sorted(on_disk - referenced_real)
    drift = index_drift(mappings, on_disk)

    if args.json:
        print(json.dumps({
            "index_drift": drift,
            "on_disk": len(on_disk),
            "referenced": len(references),
            "dangling": {k: v for k, v in sorted(dangling.items())},
            "unindexed": unindexed,
        }, indent=2))
        return 1 if dangling or unindexed or drift else 0

    if args.fix_list:
        for reference in sorted(dangling):
            print(f"REMOVE  {reference}")
        for path in unindexed:
            print(f"ADD     {path}")
        for problem in drift:
            print(f"RECOUNT {problem}")
        return 1 if dangling or unindexed or drift else 0

    print(f"Rule files on disk:      {len(on_disk)}")
    print(f"References in MAPPINGS:  {len(references)}")

    if dangling:
        print(f"\n[DANGLING] {len(dangling)} reference(s) point at files that do not exist.")
        print("           These become dead links on the generated site.")
        for reference, lines in sorted(dangling.items()):
            where = ", ".join(f"L{n}" for n in lines[:4])
            print(f"           {reference}  ({where})")

    if unindexed:
        print(f"\n[UNINDEXED] {len(unindexed)} rule file(s) exist but are not in MAPPINGS.md.")
        print("            ATLAS and OWASP coverage tables undercount by this much.")
        for path in unindexed:
            print(f"            {path}")

    if drift:
        print(f"\n[INDEX] {len(drift)} count(s) in the summary tables disagree with the rows.")
        print("        The index is hand-readable but must stay machine-true.")
        for problem in drift:
            print(f"        {problem}")

    total = len(dangling) + len(unindexed) + len(drift)
    if total:
        print(f"\n{total} problem(s). Either restore the missing files or regenerate "
              f"MAPPINGS.md, then re-run.")
        print("Run with --fix-list for a bare remove/add list.")
    else:
        print("\nMAPPINGS.md is in sync with the rules on disk, and its index "
              "counts match the tables.")
    return 1 if total else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # Piping into head/less closes stdout early; that is not an error.
        try:
            sys.stdout.close()
        finally:
            sys.exit(1)
