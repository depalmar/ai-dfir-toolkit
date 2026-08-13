# MAPPINGS — ATLAS, OWASP & CVE Cross-Reference

Per-rule mapping of detection content to MITRE ATLAS techniques, OWASP Top 10 for LLM Applications (2025), and relevant CVEs / public incident references.

All rules are in open formats (Sigma / YARA / Suricata). Convert Sigma to any SIEM query language using [pySigma](https://github.com/SigmaHQ/pySigma) backends.

**Scope:** 55 rule files / 126 individual signatures. Tables below are indexed by **rule file**; the ATLAS / OWASP counts at the bottom reflect per-file coverage (one rule file often tags multiple techniques and OWASP categories).

---

## 01 — LLM Prompt Injection

| Rule | Format | ATLAS | OWASP | CVE / Reference |
|------|--------|-------|-------|-----------------|
| `prompt_injection_keywords.yml` | Sigma | T0051.000 | LLM01 | OWASP genai 2025 |
| `jailbreak_personas.yml` | Sigma | T0054 | LLM01 | jailbreakchat.com |
| `system_prompt_extraction.yml` | Sigma | T0054 | LLM07 | Leaked-system-prompts repo |
| `markdown_image_exfil.yml` | Sigma | T0024 | LLM02 | CVE-2025-32711, CVE-2025-59145 |
| `adversarial_suffix.yar` | YARA | T0051.000, T0029 | LLM01, LLM10 | Zou et al. 2023 (GCG) |
| `bedrock_high_token_usage.yml` | Sigma | T0029, T0051, T0054 | LLM01, LLM10 | OWASP LLM10:2025 |
| `azure_openai_injection.yml` | Sigma | T0051, T0054 | LLM01, LLM07 | OWASP LLM01/LLM07:2025 |
| `llm_response_base64_exfil.yml` | Sigma | T0024 | LLM02 | embracethered.com |

## 02 — MCP Attacks

| Rule | Format | ATLAS | OWASP | CVE / Reference |
|------|--------|-------|-------|-----------------|
| `mcp_tool_poisoning.yar` | YARA | T0110, T0086 | LLM06, LLM02 | Invariant Labs 2025 |
| `mcp_config_tampering.yml` | Sigma | T0010 | LLM03 | CVE-2025-59536 |
| `mcp_credential_access.yml` | Sigma | T0086 | LLM02 | Cyata 2025 |
| `mcp_outbound_unknown_domain.rules` | Suricata | T0011, T0086, T0110 | LLM02, LLM06 | CVE-2025-49596, CVE-2025-6514 |
| `claude_desktop_config_modify.yml` | Sigma | T0010 | — | CVE-2025-53109, CVE-2025-53110 |

## 03 — Model & ML Supply Chain

| Rule | Format | ATLAS | OWASP | CVE / Reference |
|------|--------|-------|-------|-----------------|
| `pickle_malicious_opcodes.yar` | YARA | T0010.002, T0011, T0018, T0086 | LLM03 | CVE-2025-32444, Trail of Bits 2024 |
| `keras_lambda_layer_rce.yar` | YARA | T0018 | LLM03 | CVE-2025-1550 |
| `huggingface_token_exposure.yml` | Sigma | T0086 | — | Lasso Security 2024 |
| `mlflow_path_traversal.rules` | Suricata | T0010, T0011, T0086 | LLM03 | CVE-2023-6831, CVE-2024-0520, CVE-2024-2928, CVE-2023-43472 |
| `mlflow_unauth_api_access.yml` | Sigma | T0011 | LLM03 | CVE-2024-37059 |
| `pip_install_typosquat.yml` | Sigma | T0010.002 | LLM03 | torchtriton 2022, alibaba fakes 2024 |
| `huggingface_cache_unexpected_writer.yml` | Sigma | T0010.003 | LLM03 | HF cache architecture |
| `model_file_hash_mismatch.yml` | Sigma | T0010.003, T0018 | LLM03 | — |

## 04 — AI Infrastructure

| Rule | Format | ATLAS | CVE / Reference |
|------|--------|-------|-----------------|
| `ray_jobs_api_rce.rules` | Suricata | T0011, T0019, T0029 | CVE-2023-48022, MITRE C0045, ShadowRay 2.0 |
| `ray_dashboard_exposure.rules` | Suricata | T0011 | CVE-2023-48022 |
| `shadowray_process_masquerading.yml` | Sigma | T0011, T0029 | Oligo Security 2025 |
| `gpu_unexpected_high_utilization.yml` | Sigma | T0029 | ShadowRay IOCs |
| `ssh_authorized_keys_injection.yml` | Sigma | T0011 | MITRE C0045 |
| `triton_inference_server_exploit.rules` | Suricata | T0011, T0086 | CVE-2025-23319, CVE-2025-23320, CVE-2025-23334 |
| `torchserve_shelltorch.rules` | Suricata | T0010, T0011, T0018 | CVE-2023-43654, CVE-2022-1471 |
| `nvidia_container_escape.yml` | Sigma | T1611 (ATT&CK) | CVE-2024-0132, CVE-2025-23266, CVE-2025-23359 |
| `ollama_vllm_unauth_exposure.rules` | Suricata | T0010, T0011, T0018, T0029 | CVE-2025-32444, AccuKnox 2025 |

## 05 — Copilot & AI Assistant Abuse

| Rule | Format | ATLAS | OWASP | CVE / Reference |
|------|--------|-------|-------|-----------------|
| `m365_copilot_sensitive_label_access.yml` | Sigma | T0086 | LLM02 | CW1226324, CVE-2025-32711 |
| `m365_copilot_anomalous_aggregation.yml` | Sigma | T0024, T0086 | LLM02 | Concentric AI 2024-2025 |
| `github_copilot_yolo_mode_enabled.yml` | Sigma | T0010, T0011 | LLM06 | CVE-2025-53773 |
| `copilot_rules_file_backdoor.yar` | YARA | T0010, T0010.002 | LLM03 | Pillar Security 2025 |
| `cursor_settings_db_modification.yml` | Sigma | T0010 | LLM06 | Check Point MCPoison 2025, CVE-2025-54135 |
| `claude_session_jsonl_unexpected_access.yml` | Sigma | T0086 | — | Claude Code architecture |
| `chatgpt_paste_sensitive_data.yml` | Sigma | T0086 | LLM02 | Samsung 2023 incident |
| `ai_assistant_outbound_to_camo_proxy.rules` | Suricata | T0086 | LLM02 | CVE-2025-59145 (CamoLeak), CVE-2025-32711 (EchoLeak) |

## 06 — RAG & Vector DB

| Rule | Format | ATLAS | OWASP | Reference |
|------|--------|-------|-------|-----------|
| `vector_db_unauth_exposure.rules` | Suricata | T0011, T0024 | LLM02, LLM08 | Shodan 2024 |
| `vector_db_bulk_exfil.yml` | Sigma | T0024 | LLM02, LLM08 | Princeton embedding-inversion |
| `rag_document_hidden_text.yar` | YARA | T0020, T0051.001 | LLM01, LLM08 | Greshake 2023, PoisonedRAG 2025 |
| `chroma_sqlite_unexpected_writer.yml` | Sigma | T0020 | LLM08 | ChromaDB architecture |
| `vector_db_query_anomaly.yml` | Sigma | T0020, T0024 | LLM02, LLM08 | — |

## 07 — Endpoint (cross-tool)

Cross-tool endpoint rules generated alongside the artifact catalog
(`artifacts/detections/sigma/`). Scoped to agent behaviour on a host rather than
to a single attack class, so they apply across every tool in the catalog.

| Rule | Format | ATLAS | OWASP | CVE / Reference |
|------|--------|-------|-------|-----------------|
| `ai_agent_mcp_config_modification.yml` | Sigma | T0081 | LLM06 | — |
| `ai_agent_spawning_shell.yml` | Sigma | T0053 | LLM06 | — |
| `ai_agent_spawning_lolbin.yml` | Sigma | T0053 | LLM06 | LOLBAS via MCP marketplace audit 2025 |
| `local_llm_listener_non_loopback.yml` | Sigma | T0024, T0029 | LLM10 | Pillar Security 2026 (Operation Bizarre Bazaar) |
| `ai_agent_credential_file_access.yml` | Sigma | T0082 | LLM02 | — |
| `ai_inference_endpoint_redirection.yml` | Sigma | T0024 | LLM02 | — |
| `mcp_server_remote_code_fetch.yml` | Sigma | T0110 | LLM03 | postmark-mcp backdoor 2025 |
| `browser_agent_session_state_capture.yml` | Sigma | T0086 | LLM02, LLM06 | — |
| `ai_agent_autostart_persistence.yml` | Sigma | T0081 | LLM06 | — |
| `langflow_rce_exploitation_attempt.yml` | Sigma | T0053 | LLM03 | CVE-2025-3248 (CISA KEV), CVE-2026-5027 |
| `ai_agent_docker_socket_mount.yml` | Sigma | T0053 | LLM06 | OpenHands deployment docs |
| `ai_model_file_written_to_endpoint.yml` | Sigma | T0010.003 | LLM03 | — |

Also in this set: `artifacts/detections/osquery/ai-agent-artifacts.conf` — a
six-query osquery pack for fleet inventory (running agents, listeners, MCP
configs, plaintext credential files, model files, macOS autostart). It answers
*which hosts have this*, which the Sigma rules cannot.


---

## ATLAS Technique Index

| ATLAS ID | Title | Rule count |
|----------|-------|------------|
| T0010    | ML Supply Chain Compromise | 8 |
| T0010.002 | Software Supply Chain | 3 |
| T0010.003 | Model Supply Chain | 3 |
| T0011    | User Execution / Initial Access | 13 |
| T0018    | Poison AI Model | 5 |
| T0019    | Publish Poisoned Datasets | 1 |
| T0020    | Poison Training Data / RAG Corpus | 3 |
| T0024    | Exfiltration via API / Inference | 8 |
| T0029    | Denial of ML Service / Resource Hijacking | 7 |
| T0051    | LLM Prompt Injection | 2 |
| T0051.000 | Direct Prompt Injection | 2 |
| T0051.001 | Indirect Prompt Injection | 1 |
| T0053    | AI Agent Tool Invocation | 4 |
| T0054    | LLM Jailbreak | 4 |
| T0081    | Modify AI Agent Configuration | 2 |
| T0082    | RAG Credential Harvesting | 1 |
| T0086    | Exfiltration via AI Agent Tool Invocation | 13 |
| T0110    | AI Agent Tool Poisoning | 3 |

## OWASP Top 10 for LLM Applications 2025 Index

| OWASP | Title | Rule count |
|-------|-------|------------|
| LLM01    | Prompt Injection | 6 |
| LLM02    | Sensitive Information Disclosure | 15 |
| LLM03    | Supply Chain | 12 |
| LLM06    | Excessive Agency | 10 |
| LLM07    | System Prompt Leakage | 2 |
| LLM08    | Vector and Embedding Weaknesses | 5 |
| LLM10    | Unbounded Consumption | 3 |
