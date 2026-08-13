#!/usr/bin/env python3
"""Export the catalog as KAPE Targets so responders can collect AI agent artifacts with tooling they run.

KAPE is the de-facto Windows triage collector in IR. The catalog already records verified Windows disk
paths and a triage priority per tool; this turns that into runnable .tkape files. No new artifact
research happens here — every path emitted is one already verified in the catalog, so this adds
collection capability without adding fabrication risk.

Emits, into docs/api/kape/:
    AIAgents.tkape                  compound target pulling in every per-tool target
    AIAgents_P1.tkape               compound target, P1 triage tools only (fast triage)
    AIAgentCredentials.tkape        every plaintext-credential location in the catalog
    AIAgentMCP.tkape                every MCP config location (what the agent was authorised to run)
    <ToolName>.tkape                one per catalogued tool with Windows paths

Usage:
    python scripts/export_kape.py            # write files
    python scripts/export_kape.py --check    # validate only, non-zero exit on problems

Design notes
------------
* KAPE resolves %APPDATA% / %LOCALAPPDATA% / %USERPROFILE% per-user itself when a path is expressed
  relative to C:\\Users\\%user%\\, so those tokens are rewritten rather than passed through literally.
* A path ending in a separator is a directory: it becomes Path + FileMask '*' with Recursive true.
* Catalog entries carry per-artifact `confidence`; anything not `high` is emitted but tagged in the
  Comment so an examiner can see what they are trusting.
"""
from __future__ import annotations

import argparse
import glob
import re
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "api" / "kape"

# KAPE requires Id to be a unique GUID - gKape generates one per target and the
# loader treats it as the identity. Deriving it with uuid5 from a fixed namespace
# keeps it a real GUID while staying deterministic, so regenerating the feed does
# not churn every file's identity on every run.
KAPE_NS = uuid.uuid5(uuid.NAMESPACE_URL,
                     "https://github.com/depalmar/ai-dfir-toolkit/artifacts/kape")


def target_id(name: str) -> str:
    return str(uuid.uuid5(KAPE_NS, name))

# KAPE walks C:\Users\%user%\ itself, so express user-scoped paths relative to that root.
USER_SUBS: list[tuple[str, str]] = [
    (r"^%APPDATA%\\?", r"AppData\\Roaming\\"),
    (r"^%LOCALAPPDATA%\\?", r"AppData\\Local\\"),
    (r"^%USERPROFILE%\\?", ""),
    (r"^~[/\\]", ""),
]
MACHINE_PREFIX = re.compile(r"^(?:%PROGRAMDATA%|%PROGRAMFILES%|C:\\|/)", re.I)

# Markers that make a path definitively NOT Windows. A ~/ prefix alone is ambiguous (many agents use
# ~/.tool.json on every OS), but these are unambiguous and must never be rewritten to C:\Users\.
NON_WINDOWS = re.compile(
    r"(?:/Library/|Application Support|^/etc/|^/usr/|^/opt/|^/var/|^/Applications/|\.app/)", re.I)


PROSE = re.compile(r"[A-Za-z]{3,}\s+[A-Za-z]{3,}\s")  # two+ spaced words = prose, not a path


def path_like(value: str) -> str:
    """Return the value only if it is a bare path. Catalog prose such as
    'macOS login Keychain (~/Library/...)' describes a location rather than being one, and must not
    be emitted as a collection target."""
    v = (value or "").strip()
    if not v or PROSE.search(v) or v.startswith("<"):
        return ""
    return v


def to_windows(path: str) -> str:
    return path.replace("/", "\\")


def classify(path: str) -> tuple[str, str] | None:
    """Return (kape_path, scope) where scope is 'user' or 'machine'. None if not a Windows path."""
    p = path.strip()
    if not p or NON_WINDOWS.search(p):
        return None
    for pat, repl in USER_SUBS:
        if re.match(pat, p, flags=re.I):
            rest = re.sub(pat, repl, p, flags=re.I)
            return to_windows(rest), "user"
    if p.startswith("%PROGRAMDATA%"):
        return to_windows(p.replace("%PROGRAMDATA%", "C:\\ProgramData")), "machine"
    if p.startswith("%PROGRAMFILES%"):
        return to_windows(p.replace("%PROGRAMFILES%", "C:\\Program Files")), "machine"
    if re.match(r"^[A-Za-z]:\\", p):
        return to_windows(p), "machine"
    return None


def split_path(kape_path: str) -> tuple[str, str, bool]:
    """Split a Windows path into (Path, FileMask, recursive).

    NOTE: pathlib must not be used here. On POSIX it does not treat "\\" as a separator, so
    Path("AppData\\Roaming\\x.cmd").parent returns "." and silently corrupts every user-scoped
    target. Split on the literal separator instead so output is identical on any build host.
    """
    if kape_path.endswith("\\"):
        return kape_path, "*", True
    head, sep, tail = kape_path.rpartition("\\")
    if not sep:                      # bare filename: no directory component, caller supplies the base
        return "", kape_path, False
    return head + "\\", tail, False


def esc(text: str) -> str:
    """Single-line comment text, safe inside a YAML single-quoted scalar."""
    return re.sub(r"\s+", " ", str(text or "")).strip()[:180]


def sq(value: str) -> str:
    r"""YAML single-quoted scalar. Backslashes are literal here, unlike double-quoted scalars where
    \U and friends are escape sequences that would corrupt every Windows path."""
    return "'" + str(value).replace("'", "''") + "'"


def target_name(entry: dict) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", entry["name"].split("(")[0].strip()) or entry["id"]


def windows_artifacts(entry: dict) -> list[dict]:
    """Every Windows-applicable disk artifact for an entry."""
    out = []
    for art in (entry.get("artifacts") or {}).get("disk") or []:
        oses = [o.lower() for o in (art.get("os") or [])]
        if oses and "windows" not in oses:
            continue
        c = classify(str(art.get("path", "")))
        if not c:
            continue
        kp, scope = c
        out.append({**art, "_kape_path": kp, "_scope": scope})
    return out


def render_target(entry: dict, arts: list[dict]) -> str:
    desc = esc(entry.get("description"))
    lines = [
        "Description: %s" % sq(esc(entry["name"]) + " - AI agent artifacts"),
        "Author: AI Agent Artifact Catalog (ai-dfir-toolkit)",
        "Version: 1.0",
        "Id: %s" % target_id(entry["id"].lower()),
        "RecreateDirectories: true",
        "Targets:",
    ]
    for a in arts:
        p, mask, rec = split_path(a["_kape_path"])
        base = "C:\\Users\\%user%\\" if a["_scope"] == "user" else ""
        conf = a.get("confidence", "unknown")
        note = esc(a.get("description"))
        if conf != "high":
            note = f"[confidence: {conf}] {note}"
        lines += [
            "    -",
            "        Name: %s" % sq(esc(a.get("description") or a["_kape_path"])[:80]),
            "        Category: AIAgents",
            "        Path: %s" % sq(base + p),
            "        FileMask: %s" % sq(mask),
        ]
        if rec:
            lines.append("        Recursive: true")
        lines.append("        Comment: %s" % sq("%s | %s" % (entry["id"], note)))
    lines.append("")
    return "\n".join(lines)


def render_compound(name: str, description: str, targets: list[str]) -> str:
    lines = [
        "Description: %s" % sq(esc(description)),
        "Author: AI Agent Artifact Catalog (ai-dfir-toolkit)",
        "Version: 1.0",
        "Id: %s" % target_id(name.lower()),
        "RecreateDirectories: true",
        "Targets:",
    ]
    for t in sorted(targets):
        lines += [
            "    -",
            "        Name: %s" % sq(t),
            "        Category: AIAgents",
            "        Path: %s" % sq(t + ".tkape"),
        ]
    lines.append("")
    return "\n".join(lines)


def render_themed(name: str, description: str, rows: list[tuple[str, str, str]]) -> str:
    """rows: (entry_id, kape_path_with_scope_applied, comment)"""
    lines = [
        "Description: %s" % sq(esc(description)),
        "Author: AI Agent Artifact Catalog (ai-dfir-toolkit)",
        "Version: 1.0",
        "Id: %s" % target_id(name.lower()),
        "RecreateDirectories: true",
        "Targets:",
    ]
    for eid, full, comment in rows:
        p, mask, rec = split_path(full)
        lines += [
            "    -",
            "        Name: %s" % sq(esc(comment)[:80]),
            "        Category: AIAgents",
            "        Path: %s" % sq(p),
            "        FileMask: %s" % sq(mask),
        ]
        if rec:
            lines.append("        Recursive: true")
        lines.append("        Comment: %s" % sq("%s | %s" % (eid, esc(comment))))
    lines.append("")
    return "\n".join(lines)


TARGET_BLOCK = re.compile(r"^    -\n((?:^        .*\n)+)", re.M)


def audit(files: dict[str, str]) -> list[str]:
    """Read back what was rendered and assert it is loadable KAPE.

    This exists because --check used to print statistics and exit 0 regardless,
    which is not a check - a run that emitted an empty Path for every row would
    have reported success. Parse the rendered text rather than the data it came
    from, so a bug in the renderer cannot hide behind correct inputs.
    """
    problems = []
    ids = {}
    for name, text in sorted(files.items()):
        head = dict(re.findall(r"^(\w+): (.*)$", text, re.M))
        for field in ("Description", "Author", "Version", "Id", "RecreateDirectories"):
            if not head.get(field):
                problems.append(f"[KAPE] {name}.tkape is missing {field}")
        try:
            uuid.UUID(head.get("Id", ""))
        except ValueError:
            problems.append(f"[KAPE] {name}.tkape Id '{head.get('Id')}' is not a GUID; "
                            f"KAPE requires one")
        ids.setdefault(head.get("Id"), []).append(name)

        blocks = TARGET_BLOCK.findall(text)
        if not blocks:
            problems.append(f"[KAPE] {name}.tkape declares no targets")
        for block in blocks:
            row = dict(re.findall(r"^        (\w+): (.*)$", block, re.M))
            path = (row.get("Path") or "").strip("'")
            mask = (row.get("FileMask") or "").strip("'")
            if not path:
                problems.append(f"[KAPE] {name}.tkape has a row with an empty Path")
                continue
            if path.endswith(".tkape"):     # compound reference, resolved below
                if path[:-6] not in files:
                    problems.append(f"[KAPE] {name}.tkape references {path}, which is not emitted")
                continue
            if not re.match(r"^[A-Za-z]:\\", path):
                problems.append(f"[KAPE] {name}.tkape Path is not absolute: {path}")
            if NON_WINDOWS.search(path):
                problems.append(f"[KAPE] {name}.tkape Path is not a Windows path: {path}")
            if not mask:
                problems.append(f"[KAPE] {name}.tkape row for {path} has an empty FileMask")
    for gid, names in ids.items():
        if len(names) > 1:
            problems.append(f"[KAPE] Id {gid} is shared by {', '.join(names)}")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="validate only, write nothing")
    args = ap.parse_args()

    entries = [yaml.safe_load(open(f, encoding="utf-8"))
               for f in sorted(glob.glob(str(ROOT / "catalog" / "*.yml")))]

    gaps: list[dict] = []
    per_tool: dict[str, str] = {}
    p1: list[str] = []
    mismatches: list[tuple[str, str, str]] = []
    cred_rows: list[tuple[str, str, str]] = []
    mcp_rows: list[tuple[str, str, str]] = []
    stats = {"entries": 0, "targets": 0, "skipped_no_windows": 0, "mcp_repo_relative": 0,
             "windows_declared_no_paths": 0}

    for e in entries:
        arts = windows_artifacts(e)
        if not arts:
            stats["skipped_no_windows"] += 1
            declared = ((e.get("collection") or {}).get("kape_target") or "").strip()
            if declared:
                mismatches.append((e["id"], declared, "(nothing emitted)"))
            if "windows" in [o.lower() for o in (e.get("supported_os") or [])]:
                stats["windows_declared_no_paths"] += 1
                gaps.append(e)
            continue
        name = target_name(e)
        # The entry declares which target collects it, so a reader of the catalog
        # can run the right one without consulting this script. Declared and
        # emitted have to agree, or the entry points at a file that is not there.
        declared = ((e.get("collection") or {}).get("kape_target") or "").strip()
        if declared != name:
            mismatches.append((e["id"], declared or "(unset)", name))
        per_tool[name] = render_target(e, arts)
        stats["entries"] += 1
        stats["targets"] += len(arts)
        if ((e.get("collection") or {}).get("triage_priority") or "").lower() == "p1":
            p1.append(name)

        # themed: credentials (field is `location`, and some values are prose, not paths)
        for c in e.get("credentials") or []:
            oses = [o.lower() for o in (c.get("os") or [])]
            if oses and "windows" not in oses:
                continue
            cp = classify(path_like(str(c.get("location", ""))))
            if cp:
                kp, scope = cp
                full = ("C:\\Users\\%user%\\" if scope == "user" else "") + kp
                cred_rows.append((e["id"], full, f"{e['name']}: {c.get('description', 'credential store')}"))
        # themed: mcp configs (field is `config_path`; repo-relative paths cannot be templated)
        for m in e.get("mcp") or []:
            # config-file rows only - the other four mechanisms have no path to
            # collect. See export_forensicartifacts.py for the full reasoning.
            if m.get("mechanism", "config-file") != "config-file":
                continue
            raw = str(m.get("config_path", ""))
            if raw.startswith("<") or "<repo>" in raw:
                stats["mcp_repo_relative"] += 1
                continue
            mp = classify(path_like(raw))
            if mp:
                kp, scope = mp
                full = ("C:\\Users\\%user%\\" if scope == "user" else "") + kp
                mcp_rows.append((e["id"], full, f"{e['name']}: {m.get('config_key', 'MCP config')}"))

    compounds = {
        "AIAgents": render_compound(
            "AIAgents", "All catalogued AI agent, LLM runtime and MCP artifacts", list(per_tool)),
        "AIAgents_P1": render_compound(
            "AIAgents_P1", "P1 triage priority AI agent artifacts - collect these first", p1),
    }
    themed = {}
    if cred_rows:
        themed["AIAgentCredentials"] = render_themed(
            "AIAgentCredentials",
            "Plaintext credential stores written by AI agents and LLM runtimes", cred_rows)
    if mcp_rows:
        themed["AIAgentMCP"] = render_themed(
            "AIAgentMCP",
            "MCP client/server configs - records what the agent was authorised to run", mcp_rows)

    print(f"catalog entries with Windows paths : {stats['entries']}/{len(entries)}")
    print(f"  (no Windows disk paths, skipped) : {stats['skipped_no_windows']}")
    print(f"target rows emitted                : {stats['targets']}")
    print(f"P1 tools in fast-triage compound   : {len(p1)}")
    print(f"credential rows                    : {len(cred_rows)}")
    print(f"MCP config rows                    : {len(mcp_rows)}")
    print(f"MCP configs repo-relative (skipped): {stats['mcp_repo_relative']}")
    print(f"\nCATALOG GAP - declare Windows support but expose no Windows disk path: "
          f"{stats['windows_declared_no_paths']}")
    for g in gaps:
        print(f"    {g['id']}  {g['name']}")
    files = {**per_tool, **compounds, **themed}
    print(f"files                              : {len(files)}")

    problems = audit(files)
    for eid, declared, emitted in mismatches:
        problems.append(f"[KAPE] {eid} collection.kape_target is {declared}, "
                        f"but the emitted target is {emitted}")
    for p in problems:
        print(p)
    print(f"\n{len(problems)} problem(s).")
    if problems:
        return 1

    if args.check:
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (OUT / f"{name}.tkape").write_text(text, encoding="utf-8", newline="\n")
    print(f"written to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
