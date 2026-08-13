# collectors/ — AI Artifact Acquisition Suite

Forensically-sound acquisition for the AI/LLM evidence classes named by the **CoSAI AI Incident Response
Framework v1.0** (prompt logs, tool-execution traces, inference activity, RAG/vector state, agent config).
Turns the toolkit's artifact-path knowledge (documented in `docs/ai-dfir-investigation-guide.md`) into
executable, hash-verified collection.

## Design principles (why this is IR-grade, not a copy script)

1. **Read-only / non-alteration.** Sources are opened read-only and copied with `copy2` (mtime preserved);
   nothing is written back to the target. This operationalizes the **EU AI Act Article 73** duty *not to
   alter the AI system before investigation* (applicable 2 Aug 2026).
2. **Chain of custody.** Every artifact is SHA-256 hashed; the manifest records operator, host, UTC
   collection window, source→dest paths, sizes, source mtime, and a **self-hash of the collector** for
   tamper-evidence. Copies are re-hashed and flagged `copy_verified`. The manifest itself is hashed
   (`collection_manifest.sha256`).
3. **Least-collection for sensitive material.** Secrets (HF token, `.env`) are recorded as **metadata + hash
   only** unless `--collect-secrets`. Large blob stores (HF cache, Qdrant, LanceDB) collect
   manifests/metadata only unless `--collect-blobs` — so you capture provenance without exfiltrating models.
4. **Declarative registry.** `targets.yaml` is the single source of truth for artifact paths, per-OS, with
   CoSAI telemetry-class tags. Extend it without touching code.

## Components

| File | Platform | Purpose |
|---|---|---|
| `collect_ai_artifacts.py` | macOS / Linux / Windows | Cross-platform engine; resolves `targets.yaml`, hashes, copies, writes manifest |
| `targets.yaml` | — | Artifact-path registry (25 targets; user- and project-scoped) |
| `cloud/pull_bedrock_invocation_logs.sh` | AWS | Bedrock logging config + CloudTrail + invocation logs (CW/S3) |
| `cloud/pull_azure_openai_logs.sh` | Azure | Diagnostic settings + AzureDiagnostics/AOAI tables + activity log |
| `cloud/pull_vertex_audit_logs.sh` | GCP | Vertex AI audit + resource activity + request-response logs |
| `cloud/pull_m365_copilot_audit.ps1` | M365 | Purview unified-audit `CopilotInteraction` records (EchoLeak-class) |

## Quick start (endpoint)

```bash
pip install pyyaml

# Collect from the current user's machine + one suspect project/repo:
python3 collect_ai_artifacts.py \
  --case-id IR-2026-014 \
  --operator j.doe \
  --output ./cases \
  --project-dir /path/to/suspect/repo

# Triage first (enumerate + hash, copy nothing):
python3 collect_ai_artifacts.py --dry-run --project-dir /path/to/suspect/repo

# Scope to MCP + RAG evidence only:
python3 collect_ai_artifacts.py --include-category 02 06

# Full capture incl. secrets and model blobs (use deliberately):
python3 collect_ai_artifacts.py --collect-secrets --collect-blobs --case-id IR-2026-014
```

Output layout:

```
cases/IR-2026-014/
├── artifacts/<repo_cat>/<target_id>/<original/relative/path>
├── collection_manifest.json      # full chain-of-custody record
├── collection_manifest.sha256    # hash of the manifest
└── collection.log                # human-readable COPY/META/SKIP log
```

## Cloud logs (require read-only creds)

The cloud helpers acquire the **provider-side** prompt/response and inference telemetry that endpoint
collection cannot see. Each writes into the same `cases/<id>/cloud/...` tree and emits `SHA256SUMS`.

```bash
./cloud/pull_bedrock_invocation_logs.sh -c IR-2026-014 -r us-east-1 -s 2026-08-01T00:00:00Z
./cloud/pull_azure_openai_logs.sh -c IR-2026-014 -w <WORKSPACE_ID> -r <RESOURCE_ID> -d 14
./cloud/pull_vertex_audit_logs.sh -c IR-2026-014 -p <GCP_PROJECT_ID> -d 14
pwsh ./cloud/pull_m365_copilot_audit.ps1 -CaseId IR-2026-014 -Days 14
```

> **Preservation reality check:** provider prompt/response logging (Bedrock model-invocation logging, Azure
> OpenAI request-response, Vertex data-access, Copilot audit) generally must be **enabled before the
> incident**. If it was off, the scripts record that fact — note it in the report; it is itself a finding.

## CoSAI alignment

Every target is tagged with the CoSAI telemetry class it yields (`cosai:` in `targets.yaml`), and the
manifest carries those tags per artifact. See `../COSAI-MAPPINGS.md` for the field→evidence bridge.

## Roadmap hooks

- **Parsers (gap #2):** normalize collected JSONL/logs/vector stores into the CoSAI-aligned event schema for
  timelining. Collector output is the parser's input.
- **Memory/state (gap #10):** add LangGraph checkpoint / agent-memory targets and a poisoning parser.
- **OTel GenAI (framework gap):** add a span collector for `gen_ai.*` traces once conventions stabilize.

## Caveats

- Path coverage reflects mid-2026 app layouts; verify against your estate and extend `targets.yaml`.
- The collector captures artifacts **at rest**; volatile evidence (process memory of a running agent, GPU
  host memory) still requires live-response imaging (LiME/AVML) as the guide notes.
- Cloud scripts are correct CLI wrappers but are only as complete as the logging that was enabled; they do
  not create retroactive telemetry.
