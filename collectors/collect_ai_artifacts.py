#!/usr/bin/env python3
"""
collect_ai_artifacts.py — forensic collector for AI/LLM host artifacts.

Read-only acquisition of the evidence classes named by the CoSAI AI Incident Response Framework
(prompt logs, tool-execution traces, inference activity, RAG/vector state, agent config) from the
paths registered in targets.yaml. Produces a case directory with SHA-256 hashes and a chain-of-custody
manifest, operationalizing the EU AI Act Art. 73 "do not alter the system before investigation" duty.

Design constraints:
  * Never writes to a source path. Sources are opened read-only; copies use shutil.copy2 (mtime preserved).
  * Cross-platform: resolves only targets whose `os` includes the running platform.
  * Secrets (HF token, .env) are recorded as metadata + hash only, unless --collect-secrets.
  * Large blob stores (HF cache, Qdrant, LanceDB) collect manifests/metadata only, unless --collect-blobs.
  * Deterministic, auditable manifest with a self-hash of this collector for tamper-evidence.

Usage:
  python3 collect_ai_artifacts.py --case-id IR-2026-014 --output ./cases \
      --project-dir /path/to/suspect/repo --project-dir /another/project
  python3 collect_ai_artifacts.py --dry-run
  python3 collect_ai_artifacts.py --include-category 02 06 --exclude-id faiss_index

Requires: PyYAML (pip install pyyaml). Standard library otherwise.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import getpass
import glob as _glob
import hashlib
import json
import os
import platform
import shutil
import socket
import sys
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except ImportError:
    sys.stderr.write("ERROR: PyYAML required. Install with: pip install pyyaml\n")
    sys.exit(2)

COLLECTOR_VERSION = "1.0.0"
DEFAULT_MAX_SIZE_MB = 200


# --------------------------------------------------------------------------- helpers
def _utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _platform_key() -> str:
    s = platform.system().lower()
    if s == "darwin":
        return "macos"
    if s == "windows":
        return "windows"
    return "linux"


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:  # read-only
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def self_hash() -> str:
    try:
        return sha256_file(Path(__file__))
    except Exception:
        return "unavailable"


def expand_tokens(raw: str, scope: str, home: Path, project_dir: Path | None) -> str:
    """Expand ~, environment tokens, and choose the base directory for project-scoped globs."""
    p = os.path.expanduser(raw)
    p = os.path.expandvars(p)  # $APPDATA etc. (no-op if unset on this OS)
    if scope == "project" and project_dir is not None and not os.path.isabs(p):
        p = str(project_dir / p)
    return p


def resolve_paths(target: dict[str, Any], home: Path, project_dir: Path | None) -> list[Path]:
    ttype = target.get("type", "file")
    scope = target.get("scope", "user")
    out: list[Path] = []
    for raw in target.get("paths", []):
        expanded = expand_tokens(raw, scope, home, project_dir)
        if "$" in expanded and any(tok in expanded for tok in ("$APPDATA", "$LOCALAPPDATA", "$USERPROFILE", "$XDG")):
            continue  # unexpanded env var on this OS -> path not applicable
        if ttype == "glob" or any(ch in expanded for ch in "*?[]"):
            for hit in _glob.glob(expanded, recursive=True):
                out.append(Path(hit))
        else:
            out.append(Path(expanded))
    # de-dup, keep existing, files only for hashing (dirs expanded via walk below)
    seen: set[str] = set()
    uniq: list[Path] = []
    for p in out:
        rp = str(p)
        if rp not in seen:
            seen.add(rp)
            uniq.append(p)
    return uniq


def iter_files(paths: list[Path], ttype: str) -> list[Path]:
    files: list[Path] = []
    for p in paths:
        if p.is_dir() or ttype == "dir":
            if p.is_dir():
                for root, _dirs, fnames in os.walk(p):
                    for fn in fnames:
                        files.append(Path(root) / fn)
        elif p.is_file():
            files.append(p)
    # de-dup by realpath: recursive globs (**/*) match dirs that then get walked,
    # which would otherwise re-collect the same files multiple times.
    seen: set[str] = set()
    uniq: list[Path] = []
    for f in files:
        rp = os.path.realpath(f)
        if rp not in seen:
            seen.add(rp)
            uniq.append(f)
    return uniq


# --------------------------------------------------------------------------- core
def collect(args: argparse.Namespace) -> int:
    home = Path(os.path.expanduser("~"))
    plat = _platform_key()
    reg = yaml.safe_load(open(args.targets, "r", encoding="utf-8"))
    targets = reg.get("targets", [])

    # Project-scoped targets REQUIRE an explicit --project-dir. Without one, relative globs such as
    # `**/*.faiss` would resolve against the current working directory — walking arbitrary trees and
    # risking collection of files that are not evidence. Skip them and say so.
    project_dirs: list[Path] = [Path(d).resolve() for d in (args.project_dir or [])]
    if not project_dirs:
        sys.stderr.write(
            "[!] No --project-dir supplied: project-scoped targets (repo rules, MLflow, vector stores, "
            ".env) will be SKIPPED. Pass --project-dir to collect them.\n"
        )

    case_id = args.case_id or f"AIDFIR-{_dt.datetime.now().strftime('%Y%m%d-%H%M%S')}"
    case_root = Path(args.output).resolve() / case_id
    manifest: dict[str, Any] = {
        "case_id": case_id,
        "collector": "collect_ai_artifacts.py",
        "collector_version": COLLECTOR_VERSION,
        "collector_sha256": self_hash(),
        "operator": args.operator or getpass.getuser(),
        "hostname": socket.gethostname(),
        "platform": plat,
        "platform_detail": platform.platform(),
        "collection_start_utc": _utcnow(),
        "collection_end_utc": None,
        "options": {
            "dry_run": args.dry_run,
            "collect_secrets": args.collect_secrets,
            "collect_blobs": args.collect_blobs,
            "max_size_mb": args.max_size_mb,
            "project_dirs": [str(d) for d in project_dirs if d],
            "include_category": args.include_category,
            "exclude_id": args.exclude_id,
        },
        "artifacts": [],
        "skipped": [],
    }

    if not args.dry_run:
        case_root.mkdir(parents=True, exist_ok=True)

    max_bytes = args.max_size_mb * 1024 * 1024
    n_collected = n_meta = n_skipped = 0

    for target in targets:
        tid = target["id"]
        if plat not in target.get("os", []):
            continue
        if args.include_category and target.get("repo_cat") not in args.include_category:
            continue
        if args.exclude_id and tid in args.exclude_id:
            continue

        scope = target.get("scope", "user")
        ttype = target.get("type", "file")
        is_secret = target.get("sensitivity") == "secret"
        is_large = bool(target.get("large"))

        if scope == "project" and not project_dirs:
            manifest["skipped"].append({
                "target_id": tid,
                "source_path": None,
                "error": "project-scoped target skipped: no --project-dir supplied",
            })
            n_skipped += 1
            continue

        bases: list[Path | None] = list(project_dirs) if scope == "project" else [None]
        for base in bases:
            paths = resolve_paths(target, home, base)
            files = iter_files(paths, ttype)
            for src in files:
                try:
                    if not src.is_file():
                        continue
                    size = src.stat().st_size
                    mtime = _dt.datetime.fromtimestamp(
                        src.stat().st_mtime, _dt.timezone.utc
                    ).strftime("%Y-%m-%dT%H:%M:%SZ")
                    digest = sha256_file(src)

                    # decide copy vs metadata-only
                    metadata_only = False
                    reason = None
                    if is_secret and not args.collect_secrets:
                        metadata_only, reason = True, "secret (metadata+hash only)"
                    elif is_large and not args.collect_blobs and not _is_small_metadata(src):
                        metadata_only, reason = True, "large blob store (metadata+hash only)"
                    elif size > max_bytes:
                        metadata_only, reason = True, f"exceeds max-size {args.max_size_mb}MB"

                    rec: dict[str, Any] = {
                        "target_id": tid,
                        "repo_cat": target.get("repo_cat"),
                        "cosai": target.get("cosai", []),
                        "scope": scope,
                        "project_base": str(base) if base else None,
                        "source_path": str(src),
                        "size_bytes": size,
                        "sha256": digest,
                        "source_mtime_utc": mtime,
                        "collected_at_utc": _utcnow(),
                        "sensitivity": target.get("sensitivity", "normal"),
                        "metadata_only": metadata_only,
                        "metadata_only_reason": reason,
                    }

                    if args.dry_run:
                        rec["dest_path"] = None
                        manifest["artifacts"].append(rec)
                        if metadata_only:
                            n_meta += 1
                        else:
                            n_collected += 1
                        continue

                    if metadata_only:
                        rec["dest_path"] = None
                        n_meta += 1
                    else:
                        dest = _dest_for(case_root, target.get("repo_cat", "cross"), tid, src, base, home)
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(src, dest)  # read-only source; preserves mtime
                        # integrity: verify copy hash
                        if sha256_file(dest) != digest:
                            rec["copy_verified"] = False
                        else:
                            rec["copy_verified"] = True
                        rec["dest_path"] = str(dest.relative_to(case_root))
                        n_collected += 1

                    manifest["artifacts"].append(rec)

                except (PermissionError, OSError) as e:
                    manifest["skipped"].append({"target_id": tid, "source_path": str(src), "error": str(e)})
                    n_skipped += 1

    manifest["collection_end_utc"] = _utcnow()
    manifest["summary"] = {
        "collected": n_collected,
        "metadata_only": n_meta,
        "skipped": n_skipped,
        "total_records": len(manifest["artifacts"]),
    }

    # write + hash the manifest
    if not args.dry_run:
        mpath = case_root / "collection_manifest.json"
        with open(mpath, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=False)
        manifest_hash = sha256_file(mpath)
        with open(case_root / "collection_manifest.sha256", "w", encoding="utf-8") as fh:
            fh.write(f"{manifest_hash}  collection_manifest.json\n")
        _write_log(case_root, manifest)
        print(f"[+] Case {case_id} written to {case_root}")
        print(f"    collected={n_collected} metadata_only={n_meta} skipped={n_skipped}")
        print(f"    manifest sha256={manifest_hash}")
    else:
        json.dump(manifest, sys.stdout, indent=2)
        sys.stdout.write("\n")
        sys.stderr.write(
            f"[dry-run] would collect={n_collected} metadata_only={n_meta} skipped={n_skipped}\n"
        )
    return 0


def _is_small_metadata(path: Path, limit: int = 256 * 1024) -> bool:
    """Within a 'large' store, still collect small JSON/text metadata (manifests, refs)."""
    try:
        if path.stat().st_size > limit:
            return False
    except OSError:
        return False
    return path.suffix.lower() in {".json", ".txt", ".yaml", ".yml", ".md", ".cfg", ""}


def _dest_for(case_root: Path, cat: str, tid: str, src: Path, base: Path | None, home: Path) -> Path:
    """Preserve a readable, collision-safe path under case_root/artifacts/<cat>/<tid>/."""
    anchor = base if base is not None else home
    try:
        rel = src.relative_to(anchor)
    except ValueError:
        rel = Path(*[p for p in src.parts if p not in ("/", "\\")][-4:]) if len(src.parts) > 1 else Path(src.name)
    return case_root / "artifacts" / str(cat) / tid / rel


def _write_log(case_root: Path, manifest: dict[str, Any]) -> None:
    lines = [
        f"AI-DFIR collection log — case {manifest['case_id']}",
        f"operator={manifest['operator']} host={manifest['hostname']} platform={manifest['platform']}",
        f"start={manifest['collection_start_utc']} end={manifest['collection_end_utc']}",
        f"collector_sha256={manifest['collector_sha256']}",
        "-" * 72,
    ]
    for a in manifest["artifacts"]:
        tag = "META" if a.get("metadata_only") else "COPY"
        lines.append(f"[{tag}] {a['target_id']:24} {a['sha256'][:16]}… {a['source_path']}")
    for s in manifest["skipped"]:
        lines.append(f"[SKIP] {s['target_id']:24} {s['error']}: {s['source_path']}")
    (case_root / "collection.log").write_text("\n".join(lines) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- cli
def build_parser() -> argparse.ArgumentParser:
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description="Forensic collector for AI/LLM host artifacts.")
    ap.add_argument("--case-id", help="Case identifier (default: AIDFIR-<timestamp>).")
    ap.add_argument("--output", default="./cases", help="Output root for case directories.")
    ap.add_argument("--targets", default=str(here / "targets.yaml"), help="Path to targets.yaml.")
    ap.add_argument("--project-dir", action="append", help="Project/repo dir for project-scoped artifacts (repeatable).")
    ap.add_argument("--operator", help="Operator name for chain of custody (default: current user).")
    ap.add_argument("--include-category", nargs="*", help="Only collect these repo categories, e.g. 02 06.")
    ap.add_argument("--exclude-id", nargs="*", help="Skip these target ids.")
    ap.add_argument("--max-size-mb", type=int, default=DEFAULT_MAX_SIZE_MB, help="Per-file copy cap (metadata-only above).")
    ap.add_argument("--collect-secrets", action="store_true", help="Copy secret material (HF token, .env). Default: metadata+hash only.")
    ap.add_argument("--collect-blobs", action="store_true", help="Copy large blob stores (HF cache, Qdrant, LanceDB). Default: metadata only.")
    ap.add_argument("--dry-run", action="store_true", help="Enumerate + hash, print manifest to stdout, copy nothing.")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return collect(args)


if __name__ == "__main__":
    raise SystemExit(main())
