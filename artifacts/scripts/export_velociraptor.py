#!/usr/bin/env python3
"""Export the catalog as Velociraptor artifacts.

Sibling to export_kape.py, and the more useful of the two for this catalog:
KAPE is Windows-only, so it reaches 24 of 45 entries, while Velociraptor runs on
Windows, macOS and Linux - which is where most of these tools actually live.
Every glob emitted is derived from a path already verified in the catalog, so
this adds collection capability without adding fabrication risk.

Emits, into docs/api/velociraptor/:
    Custom.AIAgents.<Tool>.yaml     one per catalogued tool
    Custom.AIAgents.Credentials     every plaintext credential location
    Custom.AIAgents.MCPConfigs      every MCP config location
    Custom.AIAgents.Triage          calls every per-tool artifact

Usage:
    python scripts/export_velociraptor.py            # write files
    python scripts/export_velociraptor.py --check    # validate only, non-zero on problems

Design notes
------------
* One source per OS with its own precondition, so a single artifact is safe to
  push to a mixed fleet and each host only runs the globs that apply to it.
* Directories become recursive globs (`/**`); files stay literal. Velociraptor's
  glob() treats a trailing separator as a directory listing, not a walk.
* Collection is metadata-only by default. `Upload` is a parameter the responder
  opts into, because several of these paths are credential stores and pulling
  them back is a decision, not a default.
"""
from __future__ import annotations

import argparse
import glob as globmod
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "api" / "velociraptor"

# Where a home-relative path lands on each platform. Velociraptor globs use
# forward slashes on POSIX and backslashes on Windows.
HOME = {
    "windows": r"C:\Users\*",
    "macos": "/Users/*",
    "linux": "/home/*",
}
PRECONDITION = {
    "windows": "SELECT OS FROM info() WHERE OS = 'windows'",
    "macos": "SELECT OS FROM info() WHERE OS = 'darwin'",
    "linux": "SELECT OS FROM info() WHERE OS = 'linux'",
}
WIN_ENV = [
    (r"^%APPDATA%[\\/]?", r"C:\Users\*\AppData\Roaming" + "\\"),
    (r"^%LOCALAPPDATA%[\\/]?", r"C:\Users\*\AppData\Local" + "\\"),
    (r"^%USERPROFILE%[\\/]?", r"C:\Users\*" + "\\"),
    (r"^%PROGRAMDATA%[\\/]?", r"C:\ProgramData" + "\\"),
    (r"^%PROGRAMFILES%[\\/]?", r"C:\Program Files" + "\\"),
]

# Prose that describes a location rather than being one. Same guard as the KAPE
# exporter: 'macOS login Keychain (~/Library/...)' must never become a glob.
PROSE = re.compile(r"[A-Za-z]{3,}\s+[A-Za-z]{3,}\s")


def path_like(value: str) -> str:
    v = (value or "").strip()
    if not v or PROSE.search(v) or v.startswith("<"):
        return ""
    return v


def split_paths(value: str) -> list[str]:
    """Some path fields carry two locations separated by ' | '. Emit both."""
    return [p.strip() for p in re.split(r"\s+\|\s+", str(value or "")) if p.strip()]


def to_glob(path: str, os_name: str) -> str:
    """Render one catalog path as a Velociraptor glob for one OS, or ''."""
    p = (path or "").strip()
    if not p:
        return ""
    # A <version> segment is a wildcard the catalog wrote in prose. A <repo>
    # segment is not - it is an arbitrary checkout location, and templating it
    # to * would glob the entire filesystem. Widen the first, refuse the second.
    if re.search(r"<(repo|project|install|home\|gitroot\|cwd)[^>]*>", p, re.I):
        return ""
    p = re.sub(r"<[^>]+>", "*", p)
    if "<" in p or ">" in p:
        return ""
    windows = os_name == "windows"
    recursive = p.endswith(("/", "\\"))

    if p.startswith("~"):
        body = p[1:].lstrip("/\\")
        base = HOME[os_name]
        p = (base + "\\" + body.replace("/", "\\")) if windows else (base + "/" + body)
    elif p.startswith("%"):
        if not windows:
            return ""
        # Sliced, not re.sub: a Windows replacement starts "C:\Users", and re
        # reads "\U" in a replacement template as an escape and raises. Same
        # family of bug as putting a Windows path in a double-quoted YAML scalar.
        for pat, repl in WIN_ENV:
            m = re.match(pat, p, flags=re.I)
            if m:
                p = (repl + p[m.end():]).replace("/", "\\")
                break
        else:
            return ""
    elif re.match(r"^[A-Za-z]:[\\/]", p):
        if not windows:
            return ""
        p = p.replace("/", "\\")
    elif p.startswith("/"):
        if windows:
            return ""
        # A macOS-only path under /Users or /Library is not a Linux path.
        if os_name == "linux" and re.match(r"^/(Users|Library|Applications)/", p):
            return ""
    else:
        return ""           # relative or repo-scoped: cannot be templated

    sep = "\\" if windows else "/"
    return p.rstrip("/\\") + sep + "**" if recursive else p


def artifact_os(art: dict, entry: dict) -> list[str]:
    declared = [o.lower() for o in (art.get("os") or [])]
    if not declared:
        declared = [o.lower() for o in (entry.get("supported_os") or [])]
    return [o for o in declared if o in HOME]


def sq(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def esc(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()[:160]


def artifact_name(entry: dict) -> str:
    slug = re.sub(r"[^A-Za-z0-9]", "", entry["name"].split("(")[0].strip())
    return f"Custom.AIAgents.{slug or entry['id'].replace('-', '')}"


def collect(entry: dict) -> dict[str, list[tuple[str, str]]]:
    """Return {os: [(glob, note)]} for every collectable location on an entry."""
    by_os: dict[str, list[tuple[str, str]]] = {}
    rows = []
    for art in (entry.get("artifacts") or {}).get("disk") or []:
        rows.append((art.get("path", ""), art, art.get("description", "")))
    for cred in entry.get("credentials") or []:
        rows.append((path_like(str(cred.get("location", ""))), cred,
                     cred.get("description", "")))
    for mcp in entry.get("mcp") or []:
        rows.append((path_like(str(mcp.get("config_path", ""))), mcp,
                     mcp.get("description", "")))
    for raw, holder, note in rows:
        for one in split_paths(raw):
            for os_name in artifact_os(holder, entry):
                g = to_glob(one, os_name)
                if g:
                    by_os.setdefault(os_name, []).append((g, esc(note) or esc(one)))
    for os_name in by_os:
        seen, keep = set(), []
        for g, note in by_os[os_name]:
            if g not in seen:
                seen.add(g)
                keep.append((g, note))
        by_os[os_name] = keep
    return by_os


HEAD = """name: {name}
description: |
  {desc}

  Generated from the AI agent artifact catalog ({eid}). Every glob below is
  derived from a location the catalog has already verified.
author: AI Agent Artifact Catalog (ai-dfir-toolkit)
type: CLIENT
parameters:
  - name: Upload
    description: Upload matching files rather than only recording their metadata.
    type: bool
    default: "N"
sources:
"""

SOURCE = """  - name: {label}
    precondition: |
      {pre}
    query: |
      LET Globs = [{globs}]
      LET Hits = SELECT OSPath, Size, Mode.String AS Mode, Mtime, Btime, Ctime
        FROM glob(globs=Globs)
        WHERE NOT IsDir
      SELECT *, if(condition=Upload, then=upload(file=OSPath)) AS Upload
      FROM Hits
"""


def render(entry: dict, by_os: dict) -> str:
    text = HEAD.format(name=artifact_name(entry), eid=entry["id"],
                       desc=esc(entry.get("description")) or entry["name"])
    for os_name in ("windows", "macos", "linux"):
        if os_name not in by_os:
            continue
        globs = ", ".join(sq(g) for g, _ in by_os[os_name])
        text += SOURCE.format(label=os_name.capitalize(),
                              pre=PRECONDITION[os_name], globs=globs)
    return text


def render_themed(name: str, desc: str, rows: dict) -> str:
    text = HEAD.format(name=name, eid="multiple entries", desc=desc)
    for os_name in ("windows", "macos", "linux"):
        if os_name not in rows:
            continue
        globs = ", ".join(sq(g) for g in sorted(set(rows[os_name])))
        text += SOURCE.format(label=os_name.capitalize(),
                              pre=PRECONDITION[os_name], globs=globs)
    return text


def render_triage(names: list[str]) -> str:
    # One source per tool rather than one query chaining them all. VQL has no
    # result-set concatenation operator, and chain() takes named subqueries -
    # but multiple sources are the idiomatic construct here anyway, and they
    # keep each tool's hits labelled with the tool they came from, which is what
    # a responder wants out of a fleet-wide sweep.
    calls = "\n".join(
        f"  - name: {n.rsplit('.', 1)[-1]}\n"
        f"    query: |\n"
        f"      SELECT * FROM Artifact.{n}(Upload=Upload)"
        for n in sorted(names))
    return f"""name: Custom.AIAgents.Triage
description: |
  Collect every catalogued AI agent, LLM runtime and MCP artifact this host has.

  Calls each per-tool artifact in turn. Generated from the AI agent artifact
  catalog; every glob is derived from a verified location.
author: AI Agent Artifact Catalog (ai-dfir-toolkit)
type: CLIENT
parameters:
  - name: Upload
    description: Upload matching files rather than only recording their metadata.
    type: bool
    default: "N"
sources:
{calls}
"""


def audit(files: dict[str, str]) -> list[str]:
    """Parse the rendered YAML back and assert it is loadable Velociraptor.

    Written before the first run rather than after, because the KAPE exporter
    shipped a --check that printed statistics and always exited 0 - a check that
    cannot fail is not a check.
    """
    problems = []
    names = set()
    for fname, text in sorted(files.items()):
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            problems.append(f"[VR] {fname}: does not parse: {exc}")
            continue
        for field in ("name", "description", "author", "type", "sources"):
            if not doc.get(field):
                problems.append(f"[VR] {fname}: missing {field}")
        if doc.get("type") != "CLIENT":
            problems.append(f"[VR] {fname}: type is {doc.get('type')}, expected CLIENT")
        name = doc.get("name", "")
        if not name.startswith("Custom."):
            problems.append(f"[VR] {fname}: name '{name}' is not in the Custom. namespace")
        if name in names:
            problems.append(f"[VR] {fname}: duplicate artifact name {name}")
        names.add(name)
        for src in doc.get("sources") or []:
            q = src.get("query", "")
            if "SELECT" not in q:
                problems.append(f"[VR] {fname}: source {src.get('name', '?')} has no query")
            if "Artifact." in q:
                continue                       # the triage artifact chains others
            if "glob(globs=" not in q:
                problems.append(f"[VR] {fname}: source {src.get('name', '?')} globs nothing")
            for g in re.findall(r"'([^']+)'", q):
                if g.startswith("~") or g.startswith("%") or "<" in g:
                    problems.append(f"[VR] {fname}: unexpanded glob {g}")
    # Every artifact the triage artifact calls must exist.
    triage = files.get("Custom.AIAgents.Triage", "")
    for called in re.findall(r"Artifact\.([\w.]+)\(", triage):
        if called not in files:
            problems.append(f"[VR] Triage calls {called}, which is not emitted")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="validate only, write nothing")
    args = ap.parse_args()

    entries = [yaml.safe_load(open(f, encoding="utf-8"))
               for f in sorted(globmod.glob(str(ROOT / "catalog" / "*.yml")))]

    files: dict[str, str] = {}
    mismatches: list[tuple[str, str, str]] = []
    creds: dict[str, list[str]] = {}
    mcps: dict[str, list[str]] = {}
    per_os_rows = {"windows": 0, "macos": 0, "linux": 0}
    skipped = []

    for e in entries:
        by_os = collect(e)
        if not by_os:
            skipped.append(e["id"])
            declared = ((e.get("collection") or {}).get("velociraptor_artifact") or "").strip()
            if declared:
                mismatches.append((e["id"], declared, "(nothing emitted)"))
            continue
        name = artifact_name(e)
        # The entry declares which artifact collects it, so a reader of the
        # catalog can run the right one without consulting this script.
        declared = ((e.get("collection") or {}).get("velociraptor_artifact") or "").strip()
        if declared != name:
            mismatches.append((e["id"], declared or "(unset)", name))
        files[name] = render(e, by_os)
        for os_name, rows in by_os.items():
            per_os_rows[os_name] += len(rows)

        for cred in e.get("credentials") or []:
            for one in split_paths(path_like(str(cred.get("location", "")))):
                for os_name in artifact_os(cred, e):
                    g = to_glob(one, os_name)
                    if g:
                        creds.setdefault(os_name, []).append(g)
        for mcp in e.get("mcp") or []:
            for one in split_paths(path_like(str(mcp.get("config_path", "")))):
                for os_name in artifact_os(mcp, e):
                    g = to_glob(one, os_name)
                    if g:
                        mcps.setdefault(os_name, []).append(g)

    if creds:
        files["Custom.AIAgents.Credentials"] = render_themed(
            "Custom.AIAgents.Credentials",
            "Plaintext credential stores written by AI agents and LLM runtimes. "
            "Treat the output as credential material.", creds)
    if mcps:
        files["Custom.AIAgents.MCPConfigs"] = render_themed(
            "Custom.AIAgents.MCPConfigs",
            "MCP client and server configs - what the agent was authorised to run. "
            "Collect before remediation; removing a server destroys the record.", mcps)
    per_tool = [n for n in files if n.startswith("Custom.AIAgents.")
                and n not in ("Custom.AIAgents.Credentials", "Custom.AIAgents.MCPConfigs")]
    files["Custom.AIAgents.Triage"] = render_triage(per_tool)

    print(f"entries with collectable paths : {len(entries) - len(skipped)}/{len(entries)}")
    print(f"  windows globs                : {per_os_rows['windows']}")
    print(f"  macos globs                  : {per_os_rows['macos']}")
    print(f"  linux globs                  : {per_os_rows['linux']}")
    print(f"credential globs               : {sum(len(v) for v in creds.values())}")
    print(f"MCP config globs               : {sum(len(v) for v in mcps.values())}")
    print(f"artifacts                      : {len(files)}")
    if skipped:
        print(f"no templatable path (skipped)  : {', '.join(sorted(skipped))}")

    problems = audit(files)
    for eid, declared, emitted in mismatches:
        problems.append(f"[VR] {eid} collection.velociraptor_artifact is {declared}, "
                        f"but the emitted artifact is {emitted}")
    for p in problems:
        print(p)
    print(f"\n{len(problems)} problem(s).")
    if problems:
        return 1
    if args.check:
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (OUT / f"{name}.yaml").write_text(text, encoding="utf-8", newline="\n")
    print(f"written to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
