#!/usr/bin/env python3
"""What a catalog locator means as a collectable path - one rule, shared by every output.

The catalog's path fields are written for a person: they carry placeholders
(`~/.codeium/<version>/`), two locations in one string (`a  |  b`, `a ; b`), a
key inside a file (`config.json -> mcpServers`), and trailing notes. Every
collection output has to turn that into something a tool can search for, and
each used to do it on its own. They disagreed. The triage scripts widened
`<version>` to `*`; the KAPE feed shipped it as a literal folder name, which
matches nothing, and also emitted `a  |  b` as one Path. Velociraptor globbed
`a ; b` as one string. ForensicArtifacts dropped every `<version>` row outright.

This module makes the decisions that do not depend on the target tool, once:

* which part of a field is the path - split compound locators, drop a
  `-> key` suffix and a trailing parenthetical note
* whether it is a path at all - it must start at a root (`~`, `%VAR%`, `/`, a
  drive letter, or a checkout placeholder). Prose such as "macOS login Keychain
  (~/Library/...)" never does, so no separate prose guard is needed, and a
  rooted path keeps its spaces ("Power Automate Desktop" is a folder)
* which operating system a path can exist on - `%VAR%` and drive letters are
  Windows, an absolute `/` path is not, and `~/Library/` is macOS only
* what a placeholder means - a segment that varies per install or per user
  widens to `*`; a checkout root is templated by a caller that can take one
  (the native triage script, and the Python collector through `--project-dir`)
  and refused by the rest; anything else in angle brackets, an elided `...` or
  an unexpanded `$VAR` is a location only a person knows, so the path is dropped
  rather than guessed
* the one exception to that last rule - a caller that runs on the host can
  expand a `$VAR` itself (collectors/collect_ai_artifacts.py does), so it asks
  for `env=True` and gets the path back with the variable intact. Every export
  is written on one machine and run on another, so none of them does

Rendering for one tool - `%user%` for KAPE, `C:\\Users\\*` for Velociraptor,
`%%users.homedir%%` for ForensicArtifacts, `{HOME}` for the triage scripts -
stays in each exporter.
"""
from __future__ import annotations

import re

# Placeholders the catalog writes for a segment that varies per install, user
# or session. Each widens to a single-segment wildcard, which every target
# format accepts mid-path: Velociraptor and ForensicArtifacts globs do, and KAPE
# documents `*` in a Path directory segment for "folder or file names that are
# unpredictable/unique" (KapeFiles Targets/TargetGuide.guide; Chrome's
# `User Data\*\` target is the canonical example).
WILDCARD_TOKEN = re.compile(
    r"<(version|ver|uuid[^>]*|hash|id|name|user|profile|workspace[^>]*|n)>", re.I)

# A checkout root. Not a wildcard: it names an arbitrary repository location,
# and templating it to `*` would walk the whole disk. Only a collector that is
# handed the checkout path can use it.
REPO_TOKEN = re.compile(r"^<(repo|project|gitroot)>", re.I)

# A locator is a path only if it starts at one of these.
ROOTED = re.compile(r"^(~|%|/|<(repo|project|gitroot)>|[A-Za-z]:[\\/])", re.I)

# An environment variable root ($CLAUDE_CONFIG_DIR/...). A root only for a
# caller that passes env=True, because only that caller can expand it.
ENV_ROOT = re.compile(r"^\$\{?[A-Za-z_]\w*\}?[\\/]")

# Roots that exist only on macOS, so a row that also lists Linux must not
# render them there - '/home/*/Library/Application Support/...' matches nothing.
MAC_ONLY = re.compile(r"^/(Users|Library|Applications|System)/|^~/Library/")
DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


def split_paths(value: str) -> list[str]:
    """Some fields carry two locations: 'a  |  b' or 'a ; b'. Return each."""
    return [p.strip() for p in re.split(r"\s+[|;]\s+", str(value or "")) if p.strip()]


def clean(path: str) -> str:
    """The collectable part of one location."""
    # "path → key" names a key inside the file; the file is what gets collected.
    p = path.split(" → ")[0].split(" -> ")[0].strip()
    # A trailing parenthetical is a note, not part of the path.
    return re.sub(r"\s+\(.*\)$", "", p).strip()


def resolve(path: str, repo: str | None = None, env: bool = False) -> str:
    """Apply the placeholder rule to one cleaned path, or return '' to drop it.

    `repo` is what a leading checkout placeholder becomes. Leave it None in an
    exporter that cannot template a checkout, and those paths are dropped.
    `env` keeps a `$VAR` for a caller that expands it on the host at run time.
    """
    p = path
    m = REPO_TOKEN.match(p)
    if m:
        if repo is None:
            return ""
        p = repo + p[m.end():]
    p = WILDCARD_TOKEN.sub("*", p)
    if re.search(r"[<>]", p) or "..." in p or ("$" in p and not env):
        return ""
    return p


def applies(path: str, os_name: str) -> bool:
    """Whether one resolved path can exist on one OS ('win'/'windows', 'mac'/'macos', 'linux').

    Splitting a compound locator is what makes this necessary: 'a | b' often
    pairs a Windows path with a macOS one under a row that lists both systems,
    and each half has to go only where it can exist.
    """
    os_name = {"win": "windows", "mac": "macos"}.get(os_name, os_name)
    if path.startswith("%") or DRIVE.match(path):
        return os_name == "windows"
    if path.startswith("/"):
        return os_name != "windows" and not (os_name == "linux" and MAC_ONLY.match(path))
    if path.startswith("~"):
        return not (os_name == "linux" and MAC_ONLY.match(path))
    return True          # a checkout path is wherever the operator says it is


def locator_paths(value: str, repo: str | None = None, env: bool = False) -> list[str]:
    """Every collectable path one catalog field names, placeholders resolved."""
    out: list[str] = []
    for one in split_paths(value):
        p = clean(one)
        if not (ROOTED.match(p) or (env and ENV_ROOT.match(p))):
            continue
        p = resolve(p, repo, env)
        if p and p not in out:
            out.append(p)
    return out
