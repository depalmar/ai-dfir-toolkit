# collectors/VALIDATION.md — Forensic-soundness test record

Evidence that `collect_ai_artifacts.py` meets its read-only / chain-of-custody claims. Reproduce with the
harness described at the bottom. Last run: 2026-08-12, Linux, PyYAML present.

## Results

| Check | Result |
|---|---|
| `python3 -m py_compile collect_ai_artifacts.py` | PASS |
| `bash -n cloud/*.sh` (all 3) | PASS |
| `targets.yaml` schema (25 targets, unique ids, valid os/scope/type) | PASS |
| **Non-alteration** — 12 synthetic source files, SHA-256 **and** mtime_ns identical pre/post collection | **PASS (0 changed)** |
| Dry-run writes nothing (no case dir created) | PASS |
| Secrets (`hf_token`, `.env`) captured as **hash + metadata only**, body never copied | PASS |
| All 10 copied artifacts exist under case dir, hash-match source, `copy_verified=true` | PASS |
| `collection_manifest.sha256` matches recomputed manifest hash | PASS |
| Collector self-hash recorded in manifest | PASS |
| Chain-of-custody header complete (operator/host/platform/UTC window/version) | PASS |
| No writes under source trees (only the case dir receives writes) | PASS |

## What "non-alteration" means here (and its limits)

- **Proven:** the collector never opens a source for writing; it hashes (`rb`) and copies with `shutil.copy2`
  (contents + mtime preserved). Source file hashes and mtimes are byte-for-byte identical after collection.
- **Not claimed:** reading a file can still update its **atime** at the OS/filesystem layer (outside the
  tool's control). For strict evidentiary work, acquire from a **read-only mount / forensic image** or set
  `noatime`; the tool's guarantee is that *it* issues no writes to sources and preserves content+mtime.
- Cloud scripts (`cloud/*.{sh,ps1}`) call **read-only** provider APIs (get/lookup/filter/sync/Search) and
  write only to the local case directory; they require **read-only IAM / View-Only Audit Logs** roles.

## Reproduce

```bash
ROOT=/tmp/aidfir_validation; rm -rf "$ROOT"; mkdir -p "$ROOT"
HOME_S="$ROOT/suspect_home"; PROJ="$ROOT/suspect_project"; CASES="$ROOT/cases"
# ... populate $HOME_S and $PROJ with representative artifacts
#     (claude JSONL, .cursorrules, .env, chroma.sqlite3, hf token/cache, faiss, mlruns) ...

# snapshot sources (realpath|sha256|mtime_ns), then:
HOME="$HOME_S" python3 collect_ai_artifacts.py --dry-run --project-dir "$PROJ" --output "$CASES"
HOME="$HOME_S" python3 collect_ai_artifacts.py --case-id IR-VALIDATE-01 --project-dir "$PROJ" \
     --output "$CASES" --operator ray.depalma
# re-snapshot sources and `diff` — must be identical.
```

Metadata-only by default; add `--collect-secrets` and/or `--collect-blobs` only with explicit authorization,
and record that decision in the case notes.
