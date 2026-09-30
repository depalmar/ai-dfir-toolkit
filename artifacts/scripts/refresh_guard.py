#!/usr/bin/env python3
"""Decide whether a framework refresh is safe to merge without a person.

    python scripts/refresh_guard.py --base origin/main --summary out.md

Run by .github/workflows/framework-refresh.yml after the pins have been
re-fetched and every derived file regenerated. Exit codes:

    0  auto-merge: only pinned reference data and files derived from it changed
    2  needs review: something else changed, or a guard tripped
    1  error

Why this is the whole policy. A refresh that only moves ids and names inside
the pins, and the files generated from them, cannot change a claim this
repository makes - if a pin drops an id something still cites, the offline gates
(validate_techniques.py, cve_status.py) fail on the refreshed tree and the
workflow never gets this far. So the guard only has to prove the diff is
confined to derived data. Anything outside that list is a change a person
should read.

The optional FORBIDDEN_TERMS environment variable (comma-separated, supplied as
a repository secret so the terms themselves are never committed) blocks auto-
merge if any term appears in an added line. Upstream reference data carries
free text written by third parties; this is how the maintainer keeps names out
of the repository that its own content deliberately omits.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT.parent

# Pins, and everything generated from them. Kept deliberately short.
ALLOWED = (
    "artifacts/schema/technique-ids.json",
    "artifacts/schema/cve-status.json",
    "MAPPINGS.md",
    "artifacts/docs/api/",
)
PINS = {"artifacts/schema/technique-ids.json", "artifacts/schema/cve-status.json"}


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO, check=True, capture_output=True,
                          text=True).stdout


def changed(base: str) -> list[str]:
    out = git("diff", "--name-only", base, "--") + git("ls-files", "--others", "--exclude-standard")
    return sorted({l.strip() for l in out.splitlines() if l.strip()})


def old_json(base: str, path: str) -> dict:
    try:
        return json.loads(git("show", f"{base}:{path}"))
    except subprocess.CalledProcessError:
        return {}


def diff_keys(old: dict, new: dict) -> tuple[list, list, list]:
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    renamed = sorted(k for k in set(old) & set(new)
                     if isinstance(old[k], str) and old[k] != new[k])
    return added, removed, renamed


def summary(base: str) -> list[str]:
    lines = []
    old = old_json(base, "artifacts/schema/technique-ids.json")
    new = json.loads((ROOT / "schema" / "technique-ids.json").read_text(encoding="utf-8"))
    oa, na = old.get("atlas", {}), new["atlas"]
    if oa.get("release") != na.get("release"):
        lines.append(f"- ATLAS {oa.get('release', '?')} -> **{na['release']}**")
    for key in ("tactics", "techniques", "mitigations", "case_studies"):
        o = {k: (v if isinstance(v, str) else v.get("name", "")) for k, v in (oa.get(key) or {}).items()}
        n = {k: (v if isinstance(v, str) else v.get("name", "")) for k, v in (na.get(key) or {}).items()}
        add, rem, ren = diff_keys(o, n)
        if add or rem or ren:
            lines.append(f"- ATLAS {key.replace('_', ' ')}: +{len(add)} -{len(rem)} renamed {len(ren)}")
            for k in add[:25]:
                lines.append(f"  - added `{k}` {n[k]}")
            for k in rem[:25]:
                lines.append(f"  - removed `{k}` {o[k]}")
            for k in ren[:25]:
                lines.append(f"  - renamed `{k}`: {o[k]} -> {n[k]}")
    ot, nt = old.get("attack", {}), new["attack"]
    if ot.get("version") != nt.get("version"):
        lines.append(f"- ATT&CK {ot.get('version', '?')} -> **{nt['version']}**")
    for key in ("techniques", "groups", "campaigns"):
        add, rem, _ = diff_keys(ot.get(key) or {}, nt.get(key) or {})
        if add or rem:
            lines.append(f"- ATT&CK {key}: +{len(add)} -{len(rem)}")
    newly_retired = sorted(set(nt.get("retired", [])) - set(ot.get("retired", [])))
    if newly_retired:
        lines.append(f"- ATT&CK newly deprecated or revoked: {', '.join(newly_retired[:30])}")
    oc = old_json(base, "artifacts/schema/cve-status.json").get("cves", {})
    nc = json.loads((ROOT / "schema" / "cve-status.json").read_text(encoding="utf-8"))["cves"]
    flipped = sorted(c for c in nc if c in oc and oc[c].get("cisa_kev") != nc[c].get("cisa_kev"))
    if flipped:
        lines.append("- CISA KEV status changed: " + ", ".join(
            f"{c} -> {'listed' if nc[c]['cisa_kev'] else 'not listed'}" for c in flipped))
    return lines


def forbidden(base: str) -> list[str]:
    terms = [t.strip().lower() for t in os.environ.get("FORBIDDEN_TERMS", "").split(",") if t.strip()]
    if not terms:
        return []
    added = [l[1:].lower() for l in git("diff", "-U0", base, "--").splitlines()
             if l.startswith("+") and not l.startswith("+++")]
    # Report only that a term matched, never which one: the point of keeping the
    # list in a secret is that it does not appear in logs either.
    return [f"{sum(1 for l in added if t in l)} added line(s) match a forbidden term"
            for t in terms if any(t in l for l in added)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--summary", type=Path)
    args = ap.parse_args()
    files = changed(args.base)
    outside = [f for f in files if not f.startswith(ALLOWED)]
    reasons = []
    if not files:
        print("no changes")
        return 0
    if outside:
        reasons.append("changes outside pinned reference data: " + ", ".join(outside[:20]))
    if not (set(files) & PINS):
        reasons.append("no pin changed, so this is not a framework refresh")
    reasons += forbidden(args.base)
    body = ["## Framework refresh", "", *summary(args.base), ""]
    if reasons:
        body += ["**Held for review:**", *[f"- {r}" for r in reasons]]
    else:
        body += ["Only pinned reference data and files derived from it changed, and every "
                 "gate passed on the refreshed tree, so this is set to auto-merge."]
    text = "\n".join(body) + "\n"
    print(text)
    if args.summary:
        args.summary.write_text(text, encoding="utf-8")
    return 2 if reasons else 0


if __name__ == "__main__":
    sys.exit(main())
