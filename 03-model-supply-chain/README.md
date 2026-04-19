# 03 — Model & ML Supply Chain Attack Detection

Detects malicious model files (pickle exploits, backdoored weights), HuggingFace supply chain attacks, dependency confusion targeting ML libraries, and CI/CD compromise of model registries.

## Threats covered

| Threat | ATLAS | OWASP | Reference |
|--------|-------|-------|-----------|
| Pickle deserialization RCE | T0011, T0018 | LLM03 | Trail of Bits 2024 |
| Malicious HuggingFace model | T0010.003 | LLM03 | JFrog 2024, ReversingLabs 2025 |
| Picklescan bypass | T0010.002 | LLM03 | CVE-2025-1716, -10155, -10156, -10157 |
| Dependency confusion (torchtriton) | T0010.002 | LLM03 | PyTorch 2022 incident |
| MLflow path traversal / RCE | T0011 | — | CVE-2023-6831, CVE-2024-0520 |
| Keras Lambda code execution | T0018 | LLM03 | CVE-2025-1550 |
| HuggingFace token exposure | T0086 | — | Lasso Security 2024 |
| Namespace hijacking | T0010.003 | LLM03 | Published security research |

## Files

- `pickle_malicious_opcodes.yar` — YARA for malicious pickle bytecode
- `huggingface_token_exposure.yml` — Sigma for leaked HF tokens in logs/code
- `mlflow_path_traversal.rules` — Suricata for CVE-2023-6831, CVE-2024-2928
- `mlflow_unauth_api_access.yml` — Sigma for MLflow API abuse
- `pip_install_typosquat.yml` — Sigma for ML package typosquatting (torchtriton-style)
- `keras_lambda_layer_rce.yar` — YARA for malicious Keras Lambda layers
- `huggingface_cache_unexpected_writer.yml` — Sigma for ~/.cache/huggingface tampering
- `model_file_hash_mismatch.yml` — Sigma for model checksum drift detection (SIEM-agnostic)

## Log sources required

- File creation/modification events (Sysmon EID 11, auditd, EDR)
- Process creation events with command line (Sysmon EID 1, auditd execve)
- Network telemetry for MLflow/HuggingFace API monitoring
- Application logs from MLflow tracking server (default port 5000)
- Package manager telemetry (pip, conda, npm install events)
- File contents (for YARA scanning of model files)

## High-value forensic artifacts

| Artifact | Path |
|----------|------|
| HuggingFace cache (Linux/Mac) | `~/.cache/huggingface/hub/` |
| HuggingFace cache (Windows) | `%USERPROFILE%\.cache\huggingface\` |
| HuggingFace token | `~/.cache/huggingface/token` |
| MLflow tracking | `./mlruns/`, `mlflow.db` |
| MLflow artifacts | `./mlartifacts/` or remote object store |
| Weights & Biases | `wandb/`, `~/.netrc` |
| pip cache | `~/.cache/pip/` (Linux/Mac), `%APPDATA%\pip\` (Win) |

## Tuning notes

YARA pickle rules will fire on **legitimate models** that use risky opcodes for valid reasons (e.g., custom layers in PyTorch). Treat hits as **investigation triggers**, not auto-block. Pair with provenance verification (model card check, signed commit, official repo confirmation). The MLflow rules assume MLflow is internal-only — adjust for production exposure if applicable.
