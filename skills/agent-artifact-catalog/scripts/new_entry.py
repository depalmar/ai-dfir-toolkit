#!/usr/bin/env python3
"""Scaffold a new catalog entry with the next free ID.

    python skills/agent-artifact-catalog/scripts/new_entry.py "Tool Name"
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "artifacts"
CATALOG = ROOT / "catalog"
TEMPLATE = ROOT / "schema" / "entry-template.yml"

def next_id() -> str:
    used = []
    for f in CATALOG.glob("*.yml"):
        m = re.search(r"^id:\s*(AIRT-\d{4})", f.read_text(), re.M)
        if m:
            used.append(int(m.group(1).split("-")[1]))
    return f"AIRT-{max(used) + 1:04d}" if used else "AIRT-0001"

def slug(name: str) -> str:
    s = re.sub(r"\(.*?\)", "", name.lower())
    return re.sub(r"[^a-z0-9]+", "-", s).strip("-")

def main() -> int:
    if len(sys.argv) < 2:
        return print(__doc__) or 1
    name = sys.argv[1]
    dest = CATALOG / f"{slug(name)}.yml"
    if dest.exists():
        print(f"{dest.name} already exists - update it instead of duplicating.")
        return 1
    new_id = next_id()
    body = TEMPLATE.read_text().replace("AIRT-XXXX", new_id).replace("Tool Name", name)
    dest.write_text(body)
    print(f"Created {dest.relative_to(ROOT)} with id {new_id}")
    print("Fill it in, then run: python scripts/validate.py && python scripts/export.py")
    return 0

if __name__ == "__main__":
    sys.exit(main())
