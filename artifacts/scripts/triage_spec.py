#!/usr/bin/env python3
"""How to collect one catalog row, per operating system, for the site's script builder.

The collection plan used to end at a list of paths, and a responder then had to
turn that list into a collection script by hand, under time pressure, on the
platform in front of them. The site now generates that script. The browser only
assembles it; every decision about what a locator means is made here, once, in
Python, next to the exporters that already make the same decisions for KAPE and
Velociraptor - so the three cannot disagree about what a path is.

Each row gets a `spec`:

    {"kind": "path",     "win": [...], "mac": [...], "linux": [...]}
    {"kind": "registry", "win": ["HKCU\\\\Environment"], "values": [...]}
    {"kind": "process",  "names": ["goose", "goosed"]}
    {"kind": "network",  "ports": [8080], "hosts": ["api.anthropic.com"]}
    {"kind": "eventlog", "channel": "...", "event_id": "1"}
    {"kind": "manual",   "why": "..."}

plus "secret": true on credential rows, so the script records metadata and a
hash without copying the value unless the operator opts in - the same default
collectors/collect_ai_artifacts.py uses.

Path templates use two tokens the script expands at run time:
  {HOME}  every user profile on the host (C:\\Users\\*, /Users/*, /home/* and /root)
  {REPO}  every repository path the operator passes in, because a <repo> row
          names an arbitrary checkout and globbing the disk for it would be
          both slow and wrong
A trailing / means "the whole directory".
"""
from __future__ import annotations

import re

from export_velociraptor import PROSE, split_paths

WIN_ENV = [
    (r"^%APPDATA%", r"{HOME}\AppData\Roaming"),
    (r"^%LOCALAPPDATA%", r"{HOME}\AppData\Local"),
    (r"^%USERPROFILE%", r"{HOME}"),
    (r"^%PROGRAMDATA%", r"C:\ProgramData"),
    (r"^%PROGRAMFILES%", r"C:\Program Files"),
    (r"^%TEMP%", r"{HOME}\AppData\Local\Temp"),
]
REPO_TOKEN = re.compile(r"^<(repo|project|gitroot)>", re.I)
MAC_ONLY = re.compile(r"^/(Users|Library|Applications|System)/|^~/Library/")


def _clean(p: str) -> str:
    # "path → key" names a key inside the file; the file is what gets collected.
    p = p.split(" → ")[0].split(" -> ")[0].strip()
    # A trailing parenthetical is a note, not part of the path.
    p = re.sub(r"\s+\(.*\)$", "", p).strip()
    return p


def _one(p: str, os_name: str) -> str:
    """One catalog path to one template for one OS, or '' if it is not a path there."""
    p = _clean(p)
    # The prose guard exists for locators like "macOS login Keychain (~/...)".
    # A locator that already starts at a path root is a path even when a
    # directory name has spaces in it - "Power Automate Desktop" is a folder.
    rooted = re.match(r"^(~|%|/|<(repo|project|gitroot)>|[A-Za-z]:[\\/])", p, re.I)
    if not p or (PROSE.search(p) and not rooted):
        return ""
    if REPO_TOKEN.match(p):
        p = REPO_TOKEN.sub("{REPO}", p)
    # <version>, <uuid>, <name> and similar are wildcards the catalog wrote in
    # prose. Anything else in angle brackets is a location only a person knows.
    p = re.sub(r"<(version|ver|uuid[^>]*|hash|id|name|user|profile|workspace[^>]*|n)>", "*", p, flags=re.I)
    if re.search(r"[<>]", p) or "..." in p or "$" in p:
        return ""
    win = os_name == "win"
    if p.startswith("{REPO}"):
        return p.replace("/", "\\") if win else p.replace("\\", "/")
    if p.startswith("~"):
        body = p[1:].lstrip("/\\")
        if win:
            return "{HOME}\\" + body.replace("/", "\\")
        if os_name == "linux" and MAC_ONLY.match(p):
            return ""
        return "{HOME}/" + body.replace("\\", "/")
    if p.startswith("%"):
        if not win:
            return ""
        for pat, repl in WIN_ENV:
            m = re.match(pat, p, flags=re.I)
            if m:
                return (repl + p[m.end():]).replace("/", "\\")
        return ""
    if re.match(r"^[A-Za-z]:[\\/]", p):
        return p.replace("/", "\\") if win else ""
    if p.startswith("/"):
        if win:
            return ""
        if os_name == "linux" and MAC_ONLY.match(p):
            return ""
        return p
    return ""


def _oses(row: dict) -> dict[str, bool]:
    os_ = {o.lower() for o in row.get("os") or []}
    return {"win": "windows" in os_ or not os_, "mac": "macos" in os_ or not os_,
            "linux": "linux" in os_ or not os_}


def spec(row: dict) -> dict:
    cls, loc = row["cls"], row["artifact"] or ""
    secret = cls == "credential"
    if cls == "registry":
        key = loc.split(" → ")[0].strip()
        if not re.match(r"^HK(CU|LM|U|CR)\\", key, re.I) or "<" in key:
            return {"kind": "manual", "why": "registry location needs a person to resolve"}
        vals = loc.split(" → ", 1)[1] if " → " in loc else ""
        return {"kind": "registry", "win": [key], "values": vals, "secret": "API_KEY" in vals
                or "TOKEN" in vals}
    if cls == "process":
        names = [n.strip() for n in re.split(r"\s*(?:/|,|\|)\s*", re.sub(r"\(.*?\)", "", loc))
                 if re.fullmatch(r"[\w.\-]+", n.strip() or "-")]
        return {"kind": "process", "names": names} if names else {"kind": "manual",
                                                                  "why": "process described, not named"}
    if cls == "network":
        ports = sorted({int(p) for p in re.findall(r":(\d{2,5})(?:-\d+)?/(?:TCP|UDP)", loc)})
        hosts = sorted({h for h in re.findall(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", loc.lower())
                        if "*" not in h})
        return {"kind": "network", "ports": ports, "hosts": hosts}
    if cls == "eventlog":
        m = re.match(r"^(.*?)\s+EID\s+(\S+)$", loc)
        return {"kind": "eventlog", "channel": (m.group(1) if m else loc).strip(),
                "event_id": m.group(2) if m else ""}
    out = {"kind": "path", "win": [], "mac": [], "linux": [], "secret": secret}
    want = _oses(row)
    for one in split_paths(loc.replace(" ; ", " | ").replace("  |  ", " | ")):
        for os_name in ("win", "mac", "linux"):
            if not want[os_name]:
                continue
            t = _one(one, os_name)
            if t and t not in out[os_name]:
                out[os_name].append(t)
    if not (out["win"] or out["mac"] or out["linux"]):
        return {"kind": "manual", "secret": secret,
                "why": "no fixed path - an environment variable, keychain, database or "
                       "a location the operator has to supply"}
    return out
