#!/usr/bin/env python3
"""Generate the catalog-derived section of collectors/targets.yaml.

    python collectors/gen_credential_targets.py            # rewrite the block
    python collectors/gen_credential_targets.py --check    # fail if it is stale

The catalog is the source of truth for where credentials live: it carries the
location, the storage class, the secret type and the confidence, and it is what
gets reviewed when a path changes. Hand-copying those into targets.yaml made a
second list that drifts, and drift here decides whether a responder acquires the
evidence at all.

Two things are generated: every credential location that is a real filesystem
path, and every disk artifact the catalog rates forensic_value: high. Everything
above the marker stays hand-authored, because targets like session transcripts,
model manifests and vector stores are collection concerns the catalog does not
model - it documents what a tool leaves behind, not what an operator should
acquire, and those are different questions that mostly overlap.

Only high-value disk artifacts are emitted. The catalog carries plenty of
low-value presence indicators, and a collector that acquires everything is a
collector nobody runs.

Only locations that a file collector can actually acquire are emitted. The
catalog's `location` field also holds environment variable names, CLI flags and
prose describing an OS keychain; those are real evidence but not files, and
emitting them as paths would produce targets that silently match nothing.

Every generated *credential* target is `sensitivity: secret`, so the collector records
metadata plus a hash and never copies the body unless the operator passes
--collect-secrets. That is deliberate even for files that also hold ordinary
configuration: a file the catalog rates as a credential location should not land
whole in a case directory by default.

Catalog placeholders are resolved here, not in the collector. The collector only
expands `~` and environment variables, so it used to search for a folder
literally named `<repo>` under every --project-dir and match nothing. A leading
placeholder directory (`<repo>`, `<install>`, `<VS Code User dir>`) is now
stripped to a path relative to --project-dir, with the root named in `notes`; a
per-install segment such as `<version>` widens to `*`, by the rule in
artifacts/scripts/locators.py that the KAPE, Velociraptor and ForensicArtifacts
feeds share; and anything else in angle brackets is dropped. The collector
itself stays standalone - it is copied to a suspect host with only PyYAML - so
nothing it needs is imported from the repository.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "artifacts" / "scripts"))
from locators import LEADING_ROOT, WILDCARD_TOKEN, clean  # noqa: E402
CATALOG = ROOT / "artifacts" / "docs" / "api" / "catalog.json"
TARGETS = Path(__file__).resolve().parent / "targets.yaml"

MARKER = "# >>> GENERATED CREDENTIAL TARGETS - do not edit by hand <<<"
FOOTER = "# <<< END GENERATED CREDENTIAL TARGETS >>>"


def is_path(location: str) -> bool:
    """Is this location something a file collector can open?"""
    text = location.strip()
    low = text.lower()
    if "keychain" in low or "keyring" in low or "secretstorage" in low.replace(" ", ""):
        return False
    if "browser local storage" in low or "credential manager" in low:
        return False
    if text.startswith("-"):
        return False
    if re.fullmatch(r"[A-Z][A-Z0-9_]{2,}(\s*[/,]\s*[A-Z][A-Z0-9_]{2,})*", text):
        return False
    return text.startswith(("~", "/", "%", "$", "<", ".")) or "/" in text or "\\" in text


def split_locations(location: str) -> list[str]:
    """Some rows name two files in one string ('a  |  b'). Emit both."""
    parts = [p.strip() for p in re.split(r"\s+\|\s+", location)]
    out = []
    for p in parts:
        # Strip a trailing parenthetical note: "path (mode 0600)" -> "path"
        p = re.sub(r"\s*\([^)]*\)\s*$", "", p).strip()
        if p:
            out.append(p)
    return out


# Rooted on the host as written. `$VAR` and `%VAR%` count: the collector expands
# them at run time on the host, which the KAPE and Velociraptor feeds cannot.
ANCHORED = re.compile(r"^(~|/|%|\$|[A-Za-z]:[\\/])")


def resolve_location(piece: str) -> tuple[str, str, str | None] | None:
    """One catalog location to (collector path, anchor, placeholder root), or None.

    anchor is "user" for a path rooted on the host, "project" for one under a
    placeholder directory or a leading dot, and "relative" for anything else.
    A bare relative piece only means something beside a project-scoped piece
    of the same row; on its own it is usually prose that happens to hold a
    slash ("AWS Builder ID / IAM Identity Center token cache").
    """
    p = clean(piece)
    root = None
    m = LEADING_ROOT.match(p)
    if m:
        root, p = m.group(1), p[m.end():]
    p = WILDCARD_TOKEN.sub("*", p)
    if not p or re.search(r"[<>]", p) or "..." in p:
        return None
    if root:
        return p, "project", root
    if p.startswith("."):
        return p, "project", None
    if ANCHORED.match(p):
        return p, "user", None
    return p, "relative", None


def collector_targets(pieces: list[str]) -> list[dict]:
    """Group one catalog row's pieces into collector targets, one per scope.

    A target carries a single scope, and the collector joins a project-scoped
    path onto --project-dir but resolves a user-scoped one as written - so a
    relative path left in a user-scoped target would be searched for under the
    collector's own working directory. Relative pieces therefore ride only with
    a project-scoped piece of the same row, and a row that names both a home
    path and a checkout path becomes two targets.
    """
    groups: dict[str, dict] = {}
    relative: list[tuple[str, str]] = []
    for raw in pieces:
        r = resolve_location(raw)
        if not r:
            continue
        path, anchor, root = r
        if anchor == "relative":
            relative.append((raw, path))
            continue
        g = groups.setdefault(anchor, {"scope": anchor, "raw": [], "paths": [], "roots": []})
        g["raw"].append(raw)
        if path not in g["paths"]:
            g["paths"].append(path)
        if root and root not in g["roots"]:
            g["roots"].append(root)
    if "project" in groups:
        for raw, path in relative:
            groups["project"]["raw"].append(raw)
            if path not in groups["project"]["paths"]:
                groups["project"]["paths"].append(path)
    return list(groups.values())


def slug(entry_id: str, location: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "_", location.lower()).strip("_")
    base = re.sub(r"_+", "_", base)[:40].strip("_")
    return f"cred_{entry_id.lower().replace('-', '_')}_{base}"


def _norm(p: str) -> str:
    p = p.replace("\\", "/").lower()
    p = re.sub(r"%(\w+)%", r"\1", p)
    p = re.sub(r"\$\{?(\w+)\}?", r"\1", p)
    p = re.sub(r"<[^>]+>/?", "", p)
    return p.replace("~/", "").strip("/")


def collect_disk(catalog, taken: set, cred_paths: set) -> list[dict]:
    """High-forensic-value disk artifacts the catalog documents.

    Only forensic_value: high rows are emitted. The catalog records plenty of
    low-value presence indicators, and a collector that acquires everything is a
    collector nobody runs. Anything already claimed by a credential target is
    skipped so a path is not collected twice under two names.
    """
    out = []
    for entry in catalog:
        for a in (entry.get("artifacts") or {}).get("disk", []):
            path = a.get("path", "")
            if not path or a.get("forensic_value") != "high" or not is_path(path):
                continue
            paths = [p for p in split_locations(path) if is_path(p)]
            # A path whose only distinguishing part is a placeholder root -
            # <install>/.env, <project>/config.json - reduces to a bare filename
            # that matches every same-named file in the catalog. One such target
            # would claim every .env across every entry, including ones the
            # credential half correctly marks secret. Too generic to emit.
            paths = [p for p in paths
                     if re.sub(r"<[^>]+>/?", "", p).strip("/").count("/") >= 1]
            # A directory that contains a catalogued credential file must not be
            # emitted as a normal-sensitivity target: collecting it whole would
            # drag the secret into the case directory unhashed, past the very
            # control the credential target exists to apply. The credential
            # target already covers the file. Generation stays conservative and
            # leaves the directory to a deliberate hand-authored decision.
            paths = [p for p in paths
                     if not any(c.startswith(_norm(p).rstrip("/") + "/")
                                for c in cred_paths if _norm(p))]
            for g in collector_targets(paths):
                key = tuple(sorted(g["raw"]))
                if key in taken:
                    continue
                taken.add(key)
                out.append({
                    "id": slug(entry["id"], g["raw"][0]).replace("cred_", "art_", 1),
                    "name": f"{entry['name']} artifact ({entry['id']})",
                    "os": a.get("os") or entry.get("supported_os") or ["linux"],
                    **g,
                    "artifact_type": a.get("artifact_type", "unknown"),
                    "confidence": a.get("confidence", "unknown"),
                })
    return sorted(out, key=lambda t: t["id"])


def collect(catalog) -> list[dict]:
    seen, targets = set(), []
    for entry in catalog:
        for cred in entry.get("credentials", []):
            location = cred.get("location", "")
            if not location or not is_path(location):
                continue
            paths = [p for p in split_locations(location) if is_path(p)]
            for g in collector_targets(paths):
                key = tuple(sorted(g["raw"]))
                if key in seen:
                    continue
                seen.add(key)
                targets.append({
                    "id": slug(entry["id"], g["raw"][0]),
                    "name": f"{entry['name']} credential store ({entry['id']})",
                    "os": cred.get("os") or entry.get("supported_os") or ["linux"],
                    **g,
                    "secret_type": cred.get("secret_type", "unknown"),
                    "storage": cred.get("storage", "unknown"),
                    "confidence": cred.get("confidence", "unknown"),
                })
    return sorted(targets, key=lambda t: t["id"]), seen


def root_note(t: dict) -> str:
    """Tell the operator which directory a stripped placeholder root stood for."""
    if not t["roots"]:
        return ""
    names = " or ".join(f"<{r}>" for r in t["roots"])
    return f" Paths are relative to {names}: pass that directory as --project-dir."


def render(targets: list[dict], disk: list[dict]) -> str:
    lines = [
        MARKER,
        "# Regenerate with: python collectors/gen_credential_targets.py",
        "# Source: artifacts/docs/api/catalog.json - every credentials[] row with a",
        "# filesystem location, plus every disk artifact rated forensic_value: high.",
        "# Credential targets are sensitivity: secret, so they are recorded as",
        "# metadata and a hash and never copied unless --collect-secrets is passed.",
        "# Catalog placeholder roots (<repo>, <install>) become paths relative to",
        "# --project-dir; per-install segments such as <version> become *.",
    ]
    for t in targets:
        scope = t["scope"]
        os_list = [o for o in t["os"] if o in
                   ("windows", "macos", "linux", "docker", "container")] or ["linux"]
        lines += [
            f"  - id: {t['id']}",
            f"    name: {json.dumps(t['name'])}",
            '    repo_cat: "cred"',
            "    cosai: []",
            f"    os: [{', '.join(os_list)}]",
            f"    scope: {scope}",
            f"    type: {'glob' if any('*' in p for p in t['paths']) else 'file'}",
            "    sensitivity: secret",
            "    paths:",
        ]
        lines += [f"      - {json.dumps(p)}" for p in t["paths"]]
        note = (f"{t['storage']}/{t['secret_type']}, catalog confidence "
                f"{t['confidence']}. Existence and mode are the finding; the body "
                f"is not copied unless --collect-secrets.") + root_note(t)
        lines.append(f"    notes: {json.dumps(note)}")
    for t in disk:
        scope = t["scope"]
        os_list = [o for o in t["os"] if o in
                   ("windows", "macos", "linux", "docker", "container")] or ["linux"]
        lines += [
            f"  - id: {t['id']}",
            f"    name: {json.dumps(t['name'])}",
            '    repo_cat: "art"',
            "    cosai: []",
            f"    os: [{', '.join(os_list)}]",
            f"    scope: {scope}",
            f"    type: {'glob' if any('*' in p for p in t['paths']) else 'file'}",
            "    sensitivity: normal",
            "    paths:",
        ]
        lines += [f"      - {json.dumps(p)}" for p in t["paths"]]
        note = (f"{t['artifact_type']}, forensic_value high, catalog confidence "
                f"{t['confidence']}.") + root_note(t)
        lines.append(f"    notes: {json.dumps(note)}")
    lines.append(FOOTER)
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="Exit non-zero if the generated block is out of date")
    args = ap.parse_args()

    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    creds, taken = collect(catalog)
    # Compared against raw catalog disk paths, so built from the raw locations.
    cred_paths = {_norm(p) for t in creds for p in t["raw"]}
    disk = collect_disk(catalog, taken, cred_paths)

    # The collector searches exactly these strings. A placeholder left in one is
    # a folder name nothing on disk carries, and a relative path in a
    # user-scoped target is resolved against the collector's working directory.
    bad = [f"{t['id']}: {p}" for t in creds + disk for p in t["paths"]
           if re.search(r"[<>]", p) or (t["scope"] == "user" and not ANCHORED.match(p))]
    if bad:
        print("Generated targets the collector cannot resolve:")
        print("\n".join(f"  {b}" for b in bad))
        return 1
    block = render(creds, disk)

    text = TARGETS.read_text(encoding="utf-8")
    if MARKER in text:
        head = text.split(MARKER)[0].rstrip("\n")
        tail = text.split(FOOTER, 1)[1] if FOOTER in text else ""
        new = head + "\n\n" + block + tail
    else:
        new = text.rstrip("\n") + "\n\n" + block + "\n"

    if args.check:
        if new != text:
            print("collectors/targets.yaml credential block is stale.")
            print("Run: python collectors/gen_credential_targets.py")
            return 1
        print("collectors/targets.yaml credential block is current.")
        return 0

    with TARGETS.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(new if new.endswith("\n") else new + "\n")
    n = block.count("  - id: ")
    print(f"targets.yaml: {n} catalog-derived credential target(s) written.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
