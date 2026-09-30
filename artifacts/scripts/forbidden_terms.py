#!/usr/bin/env python3
"""Fail if any tracked file contains a term the project does not publish.

    FORBIDDEN_TERMS="term one,term two" python scripts/forbidden_terms.py

The terms come from the environment - in CI, a repository secret - and are
never committed, and this script never prints them: a finding reports the file
and line and how many terms matched, nothing more. With the variable unset it
passes and says so, so a fork or a local run without the secret is not blocked.

Why a secret rather than a list in the repo: the point is that certain names do
not appear here, and a committed denylist would be the one file that names them.
Third-party reference data (ATT&CK alias lists, ATLAS case-study credits) is the
usual way such a name arrives, which is why every pin refresh is also checked by
refresh_guard.py against the same secret.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent


def main() -> int:
    terms = [t.strip() for t in os.environ.get("FORBIDDEN_TERMS", "").split(",") if t.strip()]
    if not terms:
        print("FORBIDDEN_TERMS not set - skipped")
        return 0
    pats = [re.compile(r"(?<![A-Za-z0-9])" + re.escape(t) + r"(?![A-Za-z0-9])", re.I) for t in terms]
    files = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True, text=True,
                           check=True).stdout.split("\n")
    hits = 0
    for rel in filter(None, files):
        path = REPO / rel
        if path.suffix.lower() in (".png", ".jpg", ".gif", ".ico", ".pdf", ".zip") or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            k = sum(1 for p in pats if p.search(line))
            if k:
                hits += 1
                print(f"::error file={rel},line={n}::line matches {k} forbidden term(s)")
    print(f"{hits} line(s) match a forbidden term.")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
