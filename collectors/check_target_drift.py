#!/usr/bin/env python3
"""Compare collectors/targets.yaml against the artifact catalog.

    python collectors/check_target_drift.py           # report, exit 1 on a hard finding
    python collectors/check_target_drift.py --json    # machine-readable

targets.yaml is a second list of artifact paths. The catalog is the first, and it
is the one that carries confidence ratings, secret types and forensic value. Two
lists of the same facts drift, and here the drift is not cosmetic: it decides
what a responder does or does not acquire.

The credential half of targets.yaml is now generated from the catalog by
gen_credential_targets.py, so those cannot drift. This check covers what the
generator does not: the hand-authored targets above the marker, and every way the
two lists can still disagree.

Five findings. Only the first two fail the build:

  MISSED-SECRET  the catalog documents a plaintext credential location, as a real
                 filesystem path, that no collector target covers. The collector
                 will not acquire the highest-value evidence class the catalog
                 knows about.
  UNMARKED       a target covers a path the catalog rates as a credential store,
                 without sensitivity: secret, so the body would be copied rather
                 than hashed. This is the one that puts a live token in a case
                 directory.
  MIXED          a target covers a path the catalog documents BOTH as a credential
                 location and as an artifact or MCP config. The config is the
                 evidence, so collecting it whole is correct - but the case
                 directory then holds embedded secrets. Informational.
  NOT-A-FILE     a catalogued credential that is an env var, a CLI flag, an OS
                 keychain, a browser store or a database. Real evidence, acquired
                 by other means; reported so it is not mistaken for coverage.
  CATALOG-GAP    the collector knows a path the catalog does not. Usually a real
                 gap in the catalog, sometimes deliberately out of its scope
                 (vector stores, ML platforms). Informational.
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
    low = text.lower()
    if "keychain" in low or "keyring" in low or "secretstorage" in low.replace(" ", ""):
        return "keychain"
    if "browser local storage" in low or "credential manager" in low:
        return "browser-store"
    if low.startswith(("mysql database", "postgres database", "sqlite database")):
        return "database"
    if text.startswith("-"):
        return "flag"
    # One or more ENV_VAR names, separated by / , or |, with an optional trailing
    # parenthetical such as "(and per-provider equivalents)".
    stripped = re.sub(r"\s*\([^)]*\)\s*$", "", text).strip()
    if re.fullmatch(r"[A-Z][A-Z0-9_]{2,}(\s*[/,|]\s*[A-Z][A-Z0-9_]{2,})*", stripped):
        return "env-var"
    if text.startswith(("~", "/", "%", "$", "<", ".")) or "/" in text or "\\" in text:
        return "path"
    return "other"


def split_locations(location: str) -> list[str]:
    """One catalog location can name several files, or carry a note.

    Rows like "a.json  |  b.json" and "secrets.yaml (mode 0600)" have to be split
    and trimmed the same way the generator does, or the comparison is against a
    string no target will ever equal.
    """
    out = []
    for part in re.split(r"\s+\|\s+", location):
        part = re.sub(r"\s*\([^)]*\)\s*$", "", part).strip()
        if part:
            out.append(part)
    return out or [location.strip()]


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

    non_credential_paths: dict[str, set] = {}
    for entry in catalog:
        s_ = set()
        for a in (entry.get("artifacts") or {}).get("disk", []):
            if a.get("path"):
                s_.add(norm(a["path"]))
        for m in entry.get("mcp", []):
            if m.get("config_path"):
                s_.add(norm(m["config_path"]))
        non_credential_paths[entry["id"]] = s_

    target_paths = []     # (target_id, normalised path, sensitivity)
    for t in targets:
        for p in t.get("paths", []):
            target_paths.append((t["id"], norm(p), t.get("sensitivity", "normal")))

    def same_path(a: str, b: str) -> bool:
        """Equal, or one is a path-suffix of the other on a segment boundary.

        Plain substring matching is wrong here: stripping a <install>/ placeholder
        leaves a bare "config.json", which is a substring of
        "claude_desktop_config.json" and would report GPT Pilot's config as
        covered by the Claude Desktop target.
        """
        if a == b:
            return True
        return a.endswith("/" + b) or b.endswith("/" + a)

    def covered_by(n: str):
        return [(tid, sens) for tid, tp, sens in target_paths if same_path(tp, n)]

    missed, unmarked, uncollectable, mixed_content, unpinnable = [], [], [], [], []
    for entry_id, location, storage, secret_type in creds:
        pieces = [norm(x) for x in split_locations(location)]
        n = pieces[0]
        kind = location_kind(location)
        # After a <project>/ or <install>/ root is stripped, a location like
        # "<project>/config.toml" is just "config.toml" - a name that matches
        # every same-named file in the catalog and pins to nothing on disk.
        # Calling such a row covered, or missed, would both be guesses.
        if kind in ("path", "other") and all("/" not in x for x in pieces):
            unpinnable.append({"entry": entry_id, "location": location,
                               "secret_type": secret_type})
            continue
        hits = [h for piece in pieces for h in covered_by(piece)]
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
            mixed = any(p in non_credential_paths.get(entry_id, set()) for p in pieces)
            for tid, sens in hits:
                if sens == "secret":
                    continue
                record = {"entry": entry_id, "location": location, "target": tid,
                          "sensitivity": sens, "storage": storage}
                # A path the catalog also documents as an artifact or MCP config is
                # a config file that embeds a secret, not a secret store. The
                # config is what a responder came for, so collecting it whole is
                # correct - but the case directory then holds embedded secrets and
                # should be handled accordingly.
                (mixed_content if mixed else unmarked).append(record)

    catalog_gaps = []
    for t in targets:
        if t["id"] in OUT_OF_SCOPE or t["id"].startswith("cred_"):
            continue
        if not any(any(same_path(norm(p), c) for c in catalog_paths)
                   for p in t.get("paths", [])):
            catalog_gaps.append({"target": t["id"], "paths": t.get("paths", [])})

    if args.json:
        print(json.dumps({"missed_secret": missed, "unmarked": unmarked,
                          "uncollectable": uncollectable,
                          "mixed_content": mixed_content,
                          "unpinnable": unpinnable,
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

    if mixed_content:
        print(f"\n[MIXED] {len(mixed_content)} target(s) collect a config file that also "
              f"embeds a credential (informational).")
        print("        The config is the evidence, so it is collected whole - which means")
        print("        the case directory will contain embedded secrets. Handle accordingly.")
        for m in mixed_content:
            print(f"        {m['target']:24} {m['location'][:52]}")

    if unpinnable:
        print(f"\n[UNPINNED] {len(unpinnable)} credential location(s) that resolve to a bare "
              f"filename (informational).")
        print("           A <project>/ or <install>/ root leaves nothing to match on, so")
        print("           coverage cannot be decided either way. Pin the root to gate them.")
        for u in unpinnable:
            print(f"           {u['entry']}  {u['location'][:58]}")

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
