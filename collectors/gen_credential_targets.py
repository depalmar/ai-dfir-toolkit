#!/usr/bin/env python3
"""Generate collectors/targets.yaml's credential section from the catalog.

    python collectors/gen_credential_targets.py            # rewrite the block
    python collectors/gen_credential_targets.py --check    # fail if it is stale

The catalog is the source of truth for where credentials live: it carries the
location, the storage class, the secret type and the confidence, and it is what
gets reviewed when a path changes. Hand-copying those into targets.yaml made a
second list that drifts, and drift here decides whether a responder acquires the
evidence at all.

So the credential half of targets.yaml is generated. Everything above the marker
stays hand-authored, because targets like session transcripts and vector stores
are collection concerns the catalog does not model.

Only locations that a file collector can actually acquire are emitted. The
catalog's `location` field also holds environment variable names, CLI flags and
prose describing an OS keychain; those are real evidence but not files, and
emitting them as paths would produce targets that silently match nothing.

Every generated target is `sensitivity: secret`, so the collector records
metadata plus a hash and never copies the body unless the operator passes
--collect-secrets. That is deliberate even for files that also hold ordinary
configuration: a file the catalog rates as a credential location should not land
whole in a case directory by default.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
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


def slug(entry_id: str, location: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "_", location.lower()).strip("_")
    base = re.sub(r"_+", "_", base)[:40].strip("_")
    return f"cred_{entry_id.lower().replace('-', '_')}_{base}"


def collect(catalog) -> list[dict]:
    seen, targets = set(), []
    for entry in catalog:
        for cred in entry.get("credentials", []):
            location = cred.get("location", "")
            if not location or not is_path(location):
                continue
            paths = [p for p in split_locations(location) if is_path(p)]
            if not paths:
                continue
            key = tuple(sorted(paths))
            if key in seen:
                continue
            seen.add(key)
            targets.append({
                "id": slug(entry["id"], paths[0]),
                "name": f"{entry['name']} credential store ({entry['id']})",
                "os": cred.get("os") or entry.get("supported_os") or ["linux"],
                "paths": paths,
                "secret_type": cred.get("secret_type", "unknown"),
                "storage": cred.get("storage", "unknown"),
                "confidence": cred.get("confidence", "unknown"),
            })
    return sorted(targets, key=lambda t: t["id"])


def render(targets: list[dict]) -> str:
    lines = [
        MARKER,
        "# Regenerate with: python collectors/gen_credential_targets.py",
        "# Source: artifacts/docs/api/catalog.json (credentials[] with a filesystem",
        "# location). All are sensitivity: secret - metadata and hash only unless",
        "# --collect-secrets is passed.",
    ]
    for t in targets:
        scope = "project" if t["paths"][0].startswith(("<", ".")) else "user"
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
                f"is not copied unless --collect-secrets.")
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
    block = render(collect(catalog))

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
