# 04 — AI Infrastructure Compromise Detection

Detects exploitation of AI/ML serving infrastructure: Ray clusters (ShadowRay), Triton/TorchServe inference servers, GPU drivers, NVIDIA Container Toolkit, and Kubernetes-hosted ML workloads.

## Threats covered

| Threat | ATLAS | Reference |
|--------|-------|-----------|
| ShadowRay (CVE-2023-48022) | T0011 | Oligo Security 2024, MITRE C0045 |
| ShadowRay 2.0 self-propagating botnet | T0011, T0019 | Oligo Security 2025 |
| TorchServe ShellTorch (CVE-2023-43654) | T0011 | Oligo Security 2023 |
| Triton Inference Server RCE chain | T0011 | CVE-2025-23319/23320/23334 |
| NVIDIA Container Toolkit escape | T0017 | CVE-2024-0132, CVE-2025-23266, CVE-2025-23359 |
| GPU cryptomining abuse | T0029 | ShadowRay campaign IOCs |
| vLLM unauthenticated exposure | T0011 | AccuKnox 2025 |
| Ollama unauthenticated exposure | T0011 | Multiple vendor reports |

## Files

- `ray_dashboard_exposure.rules` — Suricata for exposed Ray dashboard (port 8265)
- `ray_jobs_api_rce.rules` — Suricata for CVE-2023-48022 exploitation
- `shadowray_process_masquerading.yml` — Sigma for kworker/dns-filter masquerading
- `gpu_unexpected_high_utilization.yml` — Sigma for cryptomining-pattern GPU usage
- `ssh_authorized_keys_injection.yml` — Sigma for SSH key injection (ShadowRay persistence)
- `triton_inference_server_exploit.rules` — Suricata for CVE-2025-23319/23320/23334
- `torchserve_shelltorch.rules` — Suricata for CVE-2023-43654
- `nvidia_container_escape.yml` — Sigma for CVE-2024-0132 / CVE-2025-23266 patterns
- `ollama_vllm_unauth_exposure.rules` — Suricata for unauthenticated AI inference servers

## Log sources required

- Network telemetry (Suricata, Zeek) for inference server attack patterns
- Process creation (Sysmon EID 1, auditd execve)
- File modifications (Sysmon EID 11, auditd)
- GPU telemetry (DCGM, nvidia-smi exporters, Prometheus)
- Container runtime logs (Docker, containerd)
- Ray dashboard / job logs (`/tmp/ray/session_latest/logs/`)

## High-value forensic artifacts

| Component | Artifact path / source |
|-----------|----------------------|
| Ray session logs | `/tmp/ray/session_latest/logs/` |
| Ray dashboard | port 8265 |
| Ray Jobs API | `/api/jobs/` |
| TorchServe logs | `logs/ts_log.log`, `logs/model_log.log`, `logs/access_log.log` |
| Triton shared memory | `/dev/shm/` |
| NVIDIA bug report | `nvidia-bug-report.log.gz` (via `nvidia-bug-report.sh`) |
| Driver logs | `dmesg | grep -i nvidia`, `journalctl -k` |
| GPU process monitoring | `nvidia-smi pmon`, `nvidia-smi dmon` |

## Tuning notes

ShadowRay rules are **highly actionable** — exposed Ray dashboards on the internet are essentially never legitimate in production. The GPU utilization rule needs baselining; legitimate ML training also produces sustained high GPU utilization. Pair with **process name** filtering (legitimate trainers are `python` invoking `pytorch_lightning`, etc., not `kworker/0:0`).
