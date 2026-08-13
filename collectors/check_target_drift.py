#!/usr/bin/env python3
"""Compare collectors/targets.yaml against the artifact catalog.

    python collectors/check_target_drift.py           # report, exit 1 on a hard finding
    python collectors/check_target_drift.py --json    # machine-readable

targets.yaml is a second list of artifact paths. The catalog is the first, and it
is the one that carries confidence ratings, secret types and forensic value. Two
lists of the same facts drift, and here the drift is not cosmetic: it decides
what a responder does or does not acquire.

Deriving targets.yaml from docs/api/catalog.json is the real fix. Until that
happens this makes the divergence visible on every run, which is the difference
between known debt and a silent gap.

Three findings, only the first of which fails the build:

  MISSED-SECRET  the catalog documents a plaintext credential location that no
                 collector target covers. The collector will not acquire the
                 highest-value evidence class the catalog knows about.
  UNMARKED       a collector target covers a path the catalog rates as a
                 credential location, but the target is not sensitivity: secret,
                 so the file would be copied whole rather than hashed. This is
                 the one that can put a live token in a case directory.
  CATALOG-GAP    the collector knows a path the catalog does not. Usually a real
                 gap in the catalog, sometimes deliberately out of its scope
                 (vector stores, ML platforms), so it is reported, never failed.
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

# Out of the catalog's stated scope (AI coding agents, local runtimes, MCP
# components), so a collector-only target here is correct rather than drift.
OUT_OF_SCOPE = {
    "hf_cache", "hf_token", "mlflow_store", "chroma_store",
    "qdrant_store", "faiss_index", "lancedb",
}


def location_kind(location: str) -> str:
    """Classify what a catalog `location` actually is.

    The field mixes four kinds of thing: filesystem paths, environment variable
    names, CLI flags, and prose describing an OS keychain. Only the first is
    something a file collector can acquire, so only the first can be a real
    coverage gap. Treating them alike would demand the collector "cover" an env
    var, which is meaningless, and would bury the genuine gaps in noise.
    """
    text = location.strip()
    if "keychain" in text.lower() or "keyring" in text.lower() or \
            "secretstorage" in text.lower().replace(" ", ""):
        return "keychain"
    if text.startswith("-"):
        return "flag"
    # ENV_VAR_NAME, or several separated by / or ,
    if re.fullmatch(r"[A-Z][A-Z0-9_]{2,}(\s*[/,]\s*[A-Z][A-Z0-9_]{2,})*", text):
        return "env-var"
    if text.startswith(("~", "/", "%", "$", "<", ".")) or "/" in text or "\\" in text:
        return "path"
    return "other"


def norm(path: str) -> str:
    """Fold the two path dialects far enough to compare them.

    The catalog writes Windows paths as %APPDATA%\\Claude, targets.yaml writes
    $APPDATA/Claude. Comparing them raw reports drift that is only spelling.
    """
    p = path.replace("\\", "/").lower()
    p = re.sub(r"%(\w+)%", r"\1", p)
    p = re.sub(r"\$\{?(\w+)\}?", r"\1", p)
    # The catalog uses <config>, <project>, <install> for roots it will not pin
    # down. Those cannot match a concrete path, so drop the placeholder segment
    # and compare on the part that is actually specified.
    p = re.sub(r"<[^>]+>/?", "", p)
    p = re.sub(r"\*+", "*", p)
    return p.replace("~/", "").strip("/")


def load():
    import yaml
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    targets = yaml.safe_load(TARGETS.read_text(encoding="utf-8"))["targets"]
    return catalog, targets


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="Machine-readable output")
    args = ap.parse_args()

    catalog, targets = load()

    creds = []            # (entry_id, location, storage, secret_type)
    catalog_paths = set()
    for entry in catalog:
        for artifact in (entry.get("artifacts") or {}).get("disk", []):
            if artifact.get("path"):
                catalog_paths.add(norm(artifact["path"]))
        for mcp in entry.get("mcp", []):
            if mcp.get("config_path"):
                catalog_paths.add(norm(mcp["config_path"]))
        for cred in entry.get("credentials", []):
            if cred.get("location"):
                creds.append((entry["id"], cred["location"],
                              cred.get("storage", ""), cred.get("secret_type", "")))
                catalog_paths.add(norm(cred["location"]))

    target_paths = []     # (target_id, normalised path, sensitivity)
    for t in targets:
        for p in t.get("paths", []):
            target_paths.append((t["id"], norm(p), t.get("sensitivity", "normal")))

    def covered_by(n: str):
        return [(tid, sens) for tid, tp, sens in target_paths
                if tp == n or n in tp or tp in n]

    missed, unmarked, uncollectable = [], [], []
    for entry_id, location, storage, secret_type in creds:
        n = norm(location)
        hits = covered_by(n)
        kind = location_kind(location)
        if not hits:
            if storage != "plaintext":
                continue
            if kind == "path":
                missed.append({"entry": entry_id, "location": location,
                               "secret_type": secret_type})
            else:
                # Real evidence, but not a file the collector can copy. Reported
                # so it is not mistaken for coverage, never failed.
                uncollectable.append({"entry": entry_id, "location": location,
                                      "kind": kind, "secret_type": secret_type})
        else:
            for tid, sens in hits:
                if sens != "secret":
                    unmarked.append({"entry": entry_id, "location": location,
                                     "target": tid, "sensitivity": sens,
                                     "storage": storage})

    catalog_gaps = []
    for t in targets:
        if t["id"] in OUT_OF_SCOPE:
            continue
        if not any(norm(p) in catalog_paths or
                   any(norm(p) in c or c in norm(p) for c in catalog_paths)
                   for p in t.get("paths", [])):
            catalog_gaps.append({"target": t["id"], "paths": t.get("paths", [])})

    if args.json:
        print(json.dumps({"missed_secret": missed, "unmarked": unmarked,
                          "uncollectable": uncollectable,
                          "catalog_gap": catalog_gaps}, indent=2))
        return 1 if (missed or unmarked) else 0

    print(f"catalog credential locations : {len(creds)}")
    print(f"collector targets            : {len(targets)} ({len(target_paths)} paths)")

    if unmarked:
        print(f"\n[UNMARKED] {len(unmarked)} collector target(s) cover a catalogued "
              f"credential without sensitivity: secret.")
        print("           These files would be COPIED WHOLE into the case directory.")
        for u in unmarked:
            print(f"           {u['target']:24} {u['location']}  ({u['storage']})")

    if missed:
        print(f"\n[MISSED-SECRET] {len(missed)} plaintext credential location(s) in the "
              f"catalog that no target covers.")
        print("                The collector will not acquire them at all.")
        for m in missed:
            print(f"                {m['entry']}  {m['location']}  ({m['secret_type']})")

    if uncollectable:
        print(f"\n[NOT-A-FILE] {len(uncollectable)} catalogued credential(s) that no file "
              f"collector can acquire (informational).")
        print("             Env vars, CLI flags and OS keychains are real evidence, but")
        print("             they are collected by other means - do not read this as coverage.")
        for u in uncollectable:
            print(f"             {u['entry']}  [{u['kind']}] {u['location'][:62]}")

    if catalog_gaps:
        print(f"\n[CATALOG-GAP] {len(catalog_gaps)} in-scope collector target(s) the "
              f"catalog does not document (informational).")
        for g in catalog_gaps:
            print(f"              {g['target']:24} {', '.join(g['paths'][:2])}")

    hard = len(missed) + len(unmarked)
    if hard:
        print(f"\n{hard} hard finding(s). Cover the location, or mark the target "
              f"sensitivity: secret.")
    else:
        print("\nNo hard drift: every catalogued plaintext credential is either "
              "covered by a target marked secret, or not claimed by one.")
    return 1 if hard else 0


if __name__ == "__main__":
    sys.exit(main())
