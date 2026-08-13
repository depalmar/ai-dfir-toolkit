#!/usr/bin/env python3
"""Check catalogued paths against the machine you are sitting at, and report.

This is the tool for the work that cannot be done from a CI runner: turning
documentation-derived paths into verified ones. It answers three questions per
path - does it exist, what mode is it, and is it a file or a directory - and
nothing else.

It NEVER reads file contents. Several catalogued paths are credential stores
holding live tokens (~/.claude/.credentials.json, ~/.codex/auth.json,
~/.gemini/oauth_creds.json). The forensic question is "does this exist and what
mode is it"; the secret must not end up in a transcript, a commit or a log. This
script cannot leak one because it never opens a file - it stats them.

Usage:
    python scripts/verify_host.py                  # everything for this OS
    python scripts/verify_host.py --entry AIRT-0001
    python scripts/verify_host.py --only-found     # just the hits
    python scripts/verify_host.py --markdown       # paste into a PR or an issue

What to do with the output
--------------------------
A HIT on a path the catalog rates `medium` or `low` is the finding worth having:
it means the path is real and the entry can be raised, with the OS and tool
version recorded in docs/VERIFICATION.md.

A MISS is only interesting if you have the tool installed and used. This script
cannot tell "path is wrong" from "tool not installed", so it never claims a path
is wrong - that judgement is yours, and it needs the tool actually present.
"""
from __future__ import annotations

import argparse
import glob
import os
import platform
import re
import stat
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent

OS_NAME = {"Windows": "windows", "Darwin": "macos", "Linux": "linux"}.get(
    platform.system(), platform.system().lower())


def expand(raw: str) -> list[Path]:
    """Expand one catalog path into concrete candidates on this host.

    Returns [] for anything that cannot be resolved here rather than guessing -
    a repo-relative path has no single location, and a Windows variable has no
    meaning on POSIX.
    """
    p = str(raw or "").strip()
    if not p or p.startswith("<") or "<repo>" in p or "<project>" in p:
        return []
    # Two locations in one field, e.g. "~/.copilot/... | <repo>/.github/..."
    if " | " in p:
        out: list[Path] = []
        for part in p.split(" | "):
            out += expand(part)
        return out
    if "%" in p:
        if OS_NAME != "windows":
            return []
        p = os.path.expandvars(p)
        if "%" in p:                      # an unset variable stayed literal
            return []
    p = os.path.expanduser(p)
    if not os.path.isabs(p) and not p.startswith("/"):
        return []
    # A <version>-style placeholder is a wildcard the catalog wrote in prose.
    if "<" in p:
        p = re.sub(r"<[^>]+>", "*", p)
    if any(ch in p for ch in "*?["):
        return [Path(m) for m in sorted(glob.glob(p))[:20]]
    return [Path(p)]


def mode_of(path: Path) -> str:
    try:
        st = path.lstat()
    except OSError:
        return "?"
    if OS_NAME == "windows":
        return "dir" if stat.S_ISDIR(st.st_mode) else "file"
    return stat.filemode(st.st_mode)


def rows_for(entry: dict):
    """Every locator on an entry that is checkable on this OS."""
    for art in (entry.get("artifacts") or {}).get("disk") or []:
        oses = [o.lower() for o in (art.get("os") or entry.get("supported_os") or [])]
        if oses and OS_NAME not in oses:
            continue
        yield ("disk", art.get("path", ""), art.get("confidence", ""),
               art.get("description", ""))
    for cred in entry.get("credentials") or []:
        oses = [o.lower() for o in (cred.get("os") or entry.get("supported_os") or [])]
        if oses and OS_NAME not in oses:
            continue
        yield ("credential", cred.get("location", ""), cred.get("confidence", ""),
               cred.get("description", ""))
    for mcp in entry.get("mcp") or []:
        yield ("mcp", mcp.get("config_path", ""), "", mcp.get("description", ""))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--entry", help="limit to one AIRT id")
    ap.add_argument("--only-found", action="store_true")
    ap.add_argument("--markdown", action="store_true", help="emit a pasteable table")
    args = ap.parse_args()

    entries = [yaml.safe_load(open(f, encoding="utf-8"))
               for f in sorted(glob.glob(str(ROOT / "catalog" / "*.yml")))]
    if args.entry:
        entries = [e for e in entries if e["id"].lower() == args.entry.lower()]
        if not entries:
            print(f"No entry {args.entry}")
            return 1

    print(f"host: {platform.system()} {platform.release()} · catalog OS: {OS_NAME}")
    print(f"python: {platform.python_version()}\n")
    if args.markdown:
        print("| Entry | Class | Path | Confidence | Result | Mode |")
        print("|---|---|---|---|---|---|")

    found = missing = unresolved = 0
    upgradable = []
    for e in entries:
        lines = []
        for cls, raw, conf, note in rows_for(e):
            cands = expand(raw)
            if not cands:
                unresolved += 1
                continue
            hit = next((c for c in cands if c.exists() or c.is_symlink()), None)
            if hit is None:
                missing += 1
                if args.only_found:
                    continue
                lines.append(("MISS", cls, raw, conf, "-"))
            else:
                found += 1
                lines.append(("HIT ", cls, str(hit), conf, mode_of(hit)))
                if conf in ("medium", "low"):
                    upgradable.append((e["id"], e["name"], str(hit), conf))
        if not lines:
            continue
        if args.markdown:
            for res, cls, path, conf, mode in lines:
                print(f"| {e['id']} | {cls} | `{path}` | {conf or '-'} | "
                      f"{'**HIT**' if res.strip() == 'HIT' else 'miss'} | `{mode}` |")
        else:
            print(f"{e['id']}  {e['name']}")
            for res, cls, path, conf, mode in lines:
                print(f"   {res} {cls:11} {conf or '-':7} {mode:11} {path}")
            print()

    print(f"\nfound {found} · missing {missing} · not resolvable here {unresolved}")
    if upgradable:
        print(f"\n{len(upgradable)} path(s) present on this host that the catalog "
              f"rates medium or low.\nThese are the findings worth recording - note the "
              f"tool version, then raise the\nconfidence and log it in docs/VERIFICATION.md:")
        for eid, name, path, conf in upgradable:
            print(f"   {eid}  {conf:6}  {path}   ({name})")
    print("\nNo file contents were read. Existence, type and mode only.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
