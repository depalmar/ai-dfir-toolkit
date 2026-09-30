# MAPPINGS — ATLAS, OWASP & CVE Cross-Reference

Per-rule mapping of detection content to MITRE ATLAS techniques, OWASP Top 10 for LLM Applications (2026), and relevant CVEs / public incident references.

All rules are in open formats (Sigma / YARA / Suricata). Convert Sigma to any SIEM query language using [pySigma](https://github.com/SigmaHQ/pySigma) backends.

**Scope:** 70 rule files / 161 individual signatures. Tables below are indexed by **rule file**; the ATLAS / OWASP counts at the bottom reflect per-file coverage (one rule file often tags multiple techniques and OWASP categories).

---

## 01 — LLM Prompt Injection

| Rule | Format | ATLAS | OWASP | ASI | CVE / Reference |
|------|--------|-------|-------|-----|-----------------|
| `prompt_injection_keywords.yml` | Sigma | T0051.000 | LLM01 | ASI01 | OWASP genai 2025, mapping updated to the 2026 list |
| `jailbreak_personas.yml` | Sigma | T0054 | LLM01 | ASI01 | jailbreakchat.com |
| `system_prompt_extraction.yml` | Sigma | T0054 | LLM08 | — | Leaked-system-prompts repo |
| `markdown_image_exfil.yml` | Sigma | T0024 | LLM02 | ASI01 | CVE-2025-32711, CVE-2025-59145 |
| `adversarial_suffix.yar` | YARA | T0051.000, T0029 | LLM01, LLM06 | ASI01 | Zou et al. 2023 (GCG) |
| `bedrock_high_token_usage.yml` | Sigma | T0029, T0051, T0054 | LLM01, LLM06 | — | OWASP LLM10:2025, now LLM06:2026 |
| `azure_openai_injection.yml` | Sigma | T0051, T0054 | LLM01, LLM08 | ASI01 | OWASP LLM01/LLM07:2025, now LLM01/LLM08:2026 |
| `llm_response_base64_exfil.yml` | Sigma | T0024 | LLM02 | ASI01 | embracethered.com |

## 02 — MCP Attacks

| Rule | Format | ATLAS | OWASP | ASI | CVE / Reference |
|------|--------|-------|-------|-----|-----------------|
| `mcp_tool_poisoning.yar` | YARA | T0115.002, T0110, T0086 | LLM03, LLM02 | ASI04, ASI02 | Invariant Labs 2025 |
| `mcp_config_tampering.yml` | Sigma | T0010 | LLM04 | ASI04 | CVE-2025-59536 |
| `mcp_credential_access.yml` | Sigma | T0086 | LLM02 | ASI03 | Cyata 2025 |
| `mcp_outbound_unknown_domain.rules` | Suricata | T0011, T0086, T0110 | LLM02, LLM03 | ASI04, ASI05 | CVE-2025-49596, CVE-2025-6514 |
| `claude_desktop_config_modify.yml` | Sigma | T0010 | — | ASI04 | CVE-2025-53109, CVE-2025-53110 |

## 03 — Model & ML Supply Chain

| Rule | Format | ATLAS | OWASP | ASI | CVE / Reference |
|------|--------|-------|-------|-----|-----------------|
| `pickle_malicious_opcodes.yar` | YARA | T0010.002, T0011, T0018, T0086 | LLM04 | ASI04, ASI05 | CVE-2025-32444, Trail of Bits 2024 |
| `keras_lambda_layer_rce.yar` | YARA | T0018 | LLM04 | ASI04, ASI05 | CVE-2025-1550 |
| `huggingface_token_exposure.yml` | Sigma | T0086 | — | ASI03 | Lasso Security 2024 |
| `mlflow_path_traversal.rules` | Suricata | T0010, T0011, T0086 | LLM04 | — | CVE-2023-6831, CVE-2024-0520, CVE-2024-2928, CVE-2023-43472 |
| `mlflow_unauth_api_access.yml` | Sigma | T0011 | LLM04 | — | CVE-2024-37059 |
| `pip_install_typosquat.yml` | Sigma | T0010.002 | LLM04 | ASI04 | torchtriton 2022, alibaba fakes 2024 |
| `huggingface_cache_unexpected_writer.yml` | Sigma | T0010.003 | LLM04 | ASI04 | HF cache architecture |
| `model_file_hash_mismatch.yml` | Sigma | T0010.003, T0018 | LLM04 | ASI04 | — |

## 04 — AI Infrastructure

| Rule | Format | ATLAS | OWASP | ASI | CVE / Reference |
|------|--------|-------|-------|-----|-----------------|
| `ray_jobs_api_rce.rules` | Suricata | T0011, T0049, T0029, T0086 | LLM06 | — | CVE-2023-48022, MITRE C0045, ShadowRay 2.0 |
| `ray_dashboard_exposure.rules` | Suricata | T0011 | — | — | CVE-2023-48022 |
| `shadowray_process_masquerading.yml` | Sigma | T0011, T0029 | LLM06 | — | Oligo Security 2025 |
| `gpu_unexpected_high_utilization.yml` | Sigma | T0029 | LLM06 | — | ShadowRay IOCs |
| `ssh_authorized_keys_injection.yml` | Sigma | T0011 | — | — | MITRE C0045 |
| `triton_inference_server_exploit.rules` | Suricata | T0010, T0011, T0086 | — | — | CVE-2025-23319, CVE-2025-23320, CVE-2025-23334 |
| `torchserve_shelltorch.rules` | Suricata | T0010, T0011, T0018 | — | — | CVE-2023-43654, CVE-2022-1471 |
| `nvidia_container_escape.yml` | Sigma | — | — | — | ATT&CK T1611, CVE-2024-0132, CVE-2025-23266, CVE-2025-23359 |
| `ollama_vllm_unauth_exposure.rules` | Suricata | T0010, T0011, T0018, T0029 | — | — | CVE-2025-32444, AccuKnox 2025 |

## 05 — Copilot & AI Assistant Abuse

| Rule | Format | ATLAS | OWASP | ASI | CVE / Reference |
|------|--------|-------|-------|-----|-----------------|
| `m365_copilot_sensitive_label_access.yml` | Sigma | T0086 | LLM02 | ASI03 | CW1226324, CVE-2025-32711 |
| `m365_copilot_anomalous_aggregation.yml` | Sigma | T0024, T0086 | LLM02 | ASI02 | Concentric AI 2024-2025 |
| `github_copilot_yolo_mode_enabled.yml` | Sigma | T0010, T0011 | LLM03 | ASI05, ASI01 | CVE-2025-53773 |
| `copilot_rules_file_backdoor.yar` | YARA | T0010, T0010.002 | LLM04 | ASI01, ASI04 | Pillar Security 2025 |
| `cursor_settings_db_modification.yml` | Sigma | T0010 | LLM03 | ASI04 | Check Point MCPoison 2025, CVE-2025-54135 |
| `claude_session_jsonl_unexpected_access.yml` | Sigma | T0086 | — | — | Claude Code architecture |
| `chatgpt_paste_sensitive_data.yml` | Sigma | T0086 | LLM02 | — | Samsung 2023 incident |
| `ai_assistant_outbound_to_camo_proxy.rules` | Suricata | T0086 | LLM02 | ASI01 | CVE-2025-59145 (CamoLeak), CVE-2025-32711 (EchoLeak) |

## 06 — RAG & Vector DB

| Rule | Format | ATLAS | OWASP | ASI | Reference |
|------|--------|-------|-------|-----|-----------|
| `vector_db_unauth_exposure.rules` | Suricata | T0011, T0024 | LLM02, LLM09 | — | Shodan 2024 |
| `vector_db_bulk_exfil.yml` | Sigma | T0024 | LLM02, LLM09 | — | Princeton embedding-inversion |
| `rag_document_hidden_text.yar` | YARA | T0020, T0051.001 | LLM01, LLM09 | ASI06, ASI01 | Greshake 2023, PoisonedRAG 2025 |
| `chroma_sqlite_unexpected_writer.yml` | Sigma | T0020 | LLM09 | ASI06 | ChromaDB architecture |
| `vector_db_query_anomaly.yml` | Sigma | T0020, T0024, T0051 | LLM02, LLM09 | ASI06 | — |

## 07 — Runtime AI-Malware

Malware that calls an LLM API *during execution* to generate or mutate its own
code ("just-in-time code creation", GTIG Nov 2025). The payload is not in the
sample, so egress to the model provider and the host artifacts of the rewrite
loop are the durable detection surface.

| Rule | Format | ATLAS | OWASP | ASI | CVE / Reference |
|------|--------|-------|-------|-----|-----------------|
| `script_interpreter_llm_api_dns.yml` | Sigma | T0096, T0086 | LLM03 | — | PROMPTFLUX / PROMPTSTEAL (GTIG Nov 2025) |
| `promptflux_artifacts_fileevent.yml` | Sigma | T0096 | LLM01, LLM03 | — | PROMPTFLUX (GTIG Nov 2025) |
| `powershell_llm_api_command_generation.yml` | Sigma | T0096 | LLM03 | — | FRUITSHELL / PROMPTSTEAL (GTIG Nov 2025) |
| `runtime_ai_malware_correlation.yml` | Sigma | T0096 | LLM01, LLM03 | — | PROMPTFLUX kill-chain |
| `promptflux_thinking_robot.yar` | YARA | T0096 | LLM01, LLM03 | — | PROMPTFLUX |
| `promptsteal_lamehug.yar` | YARA | T0096 | LLM03 | — | PROMPTSTEAL / LAMEHUG (APT28) |
| `llm_api_prompt_in_script_generic.yar` | YARA | T0096 | LLM01, LLM03 | — | Just-in-time code creation (class heuristic) |
| `runtime_llm_api_c2.rules` | Suricata | T0096, T0086 | LLM03 | — | SesameOp-style AI-service C2 (AML.CS0042) |

YARA string sets here are derived from public reporting rather than confirmed
samples — see the category README before deploying them for blocking.

## 08 — Agentic Orchestration Abuse & AI-Service C2

The adversary using an agent as the operator, and AI provider APIs abused as covert
C2. Different in kind from 01-07: every individual tool call here is legitimate, and
what betrays the intrusion is emergent - tempo, phase progression, breadth, and the
ratio of agent actions to human decisions.

| Rule | Format | ATLAS | OWASP | ASI | CVE / Reference |
|------|--------|-------|-------|-----|-----------------|
| `sesameop_assistants_api_c2.yml` | Sigma | T0096 | LLM03 | — | SesameOp, Microsoft DART Nov 2025 (AML.CS0042) |
| `agentic_orchestration_behavior.yml` | Sigma | T0086, T0054, T0053, T0096 | LLM03 | ASI02 | GTG-1002, Anthropic Nov 2025 |
| `ai_service_api_c2.rules` | Suricata | T0096, T0086 | LLM03 | — | SesameOp / agent-as-C2 egress |

GTG-1002 is vendor-disclosed with no public IOCs, so these are behavioural rather
than signature-based. `agentic_orchestration_behavior.yml` is threshold-driven and
must be baselined before alerting - see the category README.

## 09 — Agent Memory Forensics & Context Poisoning

Agent memory as a persistence mechanism. An instruction written into an agent's
long-term memory survives conversation resets, process restarts, and the removal
of whatever injection put it there - so eradication that does not purge memory
leaves the adversary resident.

| Rule | Format | ATLAS | OWASP | ASI | CVE / Reference |
|------|--------|-------|-------|-----|-----------------|
| `memory_poisoning.yml` | Sigma | T0080, T0080.000, T0081, T0086 | LLM01, LLM03 | ASI06 | MITRE/Zenity Labs Oct 2025 |
| `memory_poisoning_indicators.yar` | YARA | T0080.000, T0086 | LLM01, LLM02 | ASI06 | spAIware-class persistent exfiltration |

Also here: `analyze_agent_memory.py`, which parses memory stores and reports
poisoning findings with severity and ATLAS mapping.

## Endpoint (cross-tool)

Cross-tool endpoint rules generated alongside the artifact catalog
(`artifacts/detections/sigma/`). Scoped to agent behaviour on a host rather than
to a single attack class, so they apply across every tool in the catalog.

| Rule | Format | ATLAS | OWASP | ASI | CVE / Reference |
|------|--------|-------|-------|-----|-----------------|
| `ai_agent_mcp_config_modification.yml` | Sigma | T0081 | LLM03 | ASI04 | — |
| `ai_agent_spawning_shell.yml` | Sigma | T0053 | LLM03 | ASI05, ASI02 | — |
| `ai_agent_spawning_lolbin.yml` | Sigma | T0053 | LLM03 | ASI02, ASI05 | LOLBAS via MCP marketplace audit 2025 |
| `local_llm_listener_non_loopback.yml` | Sigma | T0024, T0029 | LLM06 | — | Pillar Security 2026 (Operation Bizarre Bazaar) |
| `ai_agent_credential_file_access.yml` | Sigma | T0083, T0055 | LLM02 | ASI03 | — |
| `ai_inference_endpoint_redirection.yml` | Sigma | T0024 | LLM02 | ASI04 | — |
| `mcp_server_remote_code_fetch.yml` | Sigma | T0110 | LLM04 | ASI04, ASI05 | postmark-mcp backdoor 2025 |
| `browser_agent_session_state_capture.yml` | Sigma | T0086 | LLM02, LLM03 | ASI03 | — |
| `ai_agent_autostart_persistence.yml` | Sigma | T0081 | LLM03 | — | — |
| `langflow_rce_exploitation_attempt.yml` | Sigma | T0053 | LLM04 | ASI05 | CVE-2025-3248 (CISA KEV), CVE-2026-5027 |
| `ai_agent_docker_socket_mount.yml` | Sigma | T0053 | LLM03 | ASI03, ASI05 | OpenHands deployment docs |
| `ai_model_file_written_to_endpoint.yml` | Sigma | T0010.003 | LLM04 | ASI04 | — |
| `ai_cli_permission_bypass_invocation.yml` | Sigma | T0053, T0098 | LLM03 | ASI05, ASI02 | s1ngularity / Nx GHSA-cxm3-wv7p-598c (AIRT-CS-0015) |
| `ai_agent_hook_config_modification.yml` | Sigma | T0081 | LLM03 | ASI04, ASI05 | GTIG Sep 2026, MIDNIGHT NEPTUNE (AIRT-CS-0017) |

Also in this set: `artifacts/detections/osquery/ai-agent-artifacts.conf` — a
six-query osquery pack for fleet inventory (running agents, listeners, MCP
configs, plaintext credential files, model files, macOS autostart). It answers
*which hosts have this*, which the Sigma rules cannot.


---

## ATLAS Technique Index

Titles are ATLAS 2026.09 names, generated from `artifacts/schema/technique-ids.json` by `artifacts/scripts/sync_mappings.py`.

| ATLAS ID | Title | Tactic | Rule count |
|----------|-------|--------|------------|
| T0010    | AI Supply Chain Compromise | Initial Access | 9 |
| T0010.002 | AI Supply Chain Compromise: Data | Initial Access | 3 |
| T0010.003 | AI Supply Chain Compromise: Model | Initial Access | 3 |
| T0011    | User Execution | Execution | 13 |
| T0018    | Manipulate AI Model | AI Attack Adaptation, Persistence | 5 |
| T0020    | Training Data Poisoning | Persistence | 3 |
| T0024    | Exfiltration via AI Inference API | Exfiltration | 8 |
| T0029    | Denial of AI Service | Impact | 7 |
| T0049    | Exploit Public-Facing Application | Initial Access | 1 |
| T0051    | LLM Prompt Injection | Execution | 3 |
| T0051.000 | LLM Prompt Injection: Direct | Execution | 2 |
| T0051.001 | LLM Prompt Injection: Indirect | Execution | 1 |
| T0053    | AI Agent Tool Invocation | Execution, Privilege Escalation, Lateral Movement | 6 |
| T0054    | LLM Jailbreak | Defense Evasion, Privilege Escalation | 5 |
| T0055    | Unsecured Credentials | Credential Access | 1 |
| T0080    | AI Agent Context Poisoning | Persistence | 1 |
| T0080.000 | AI Agent Context Poisoning: Memory | Persistence | 2 |
| T0081    | Modify AI Agent Configuration | Persistence, Defense Evasion | 4 |
| T0083    | Credentials from AI Agent Configuration | Credential Access | 1 |
| T0086    | Exfiltration via AI Agent Tool Invocation | Exfiltration | 20 |
| T0096    | AI Service API | Command and Control | 11 |
| T0098    | AI Agent Tool Credential Harvesting | Credential Access | 1 |
| T0110    | AI Agent Tool Poisoning | Persistence | 3 |
| T0115.002 | Publish Poisoned AI Artifacts: AI Agent Tools | Resource Development | 1 |

## OWASP Top 10 for LLM Applications 2026 Index

Remapped from the 2025 list on 2026-08-13, against the 2026 publication of
2026-08-04. Eight of the ten IDs changed meaning between the two editions, so a
2025 ID read as a 2026 one names the wrong category - `LLM03` was Supply Chain
and is now Excessive Agency. Categories with no rule are listed so the gaps are
visible rather than merely absent.

| OWASP | Title | Rule count | Was in 2025 |
|-------|-------|------------|-------------|
| LLM01    | Prompt Injection | 12 | LLM01 |
| LLM02    | Sensitive Information Disclosure | 16 | LLM02 |
| LLM03    | Excessive Agency | 24 | LLM06 |
| LLM04    | Supply Chain | 12 | LLM03 |
| LLM05    | Data and Model Poisoning | 0 | LLM04 |
| LLM06    | Unbounded Consumption | 6 | LLM10 |
| LLM07    | Misinformation | 0 | LLM09 |
| LLM08    | Hidden Context Exposure | 2 | LLM07, renamed and widened |
| LLM09    | Vector and Embedding Weaknesses | 5 | LLM08 |
| LLM10    | Improper Output Handling | 0 | LLM05 |

## OWASP Top 10 for Agentic Applications 2026 Index

The OWASP Top 10 for Agentic Applications (December 2025) names the risks that
exist because an application acts - holds tools, credentials and memory - rather
than only answers. The per-rule ASI values above are this project's assessment of
which risk a rule gives evidence of, not an OWASP mapping; OWASP publishes none
for detection content. A dash means the rule detects something the agentic list
does not cover, usually an adversary *using* AI rather than an agentic
application being attacked. The related LLM IDs are OWASP's own Appendix A cross-
map, which cites the 2025 list, translated to 2026 IDs through
`artifacts/schema/owasp.json`.

| ASI | Title | Rule count | Related LLM (2026) |
|-----|-------|------------|--------------------|
| ASI01 | Agent Goal Hijack | 10 | LLM01, LLM03 |
| ASI02 | Tool Misuse and Exploitation | 6 | LLM03 |
| ASI03 | Identity and Privilege Abuse | 6 | LLM01, LLM02, LLM03 |
| ASI04 | Agentic Supply Chain Vulnerabilities | 16 | LLM04 |
| ASI05 | Unexpected Code Execution | 11 | LLM01, LLM10 |
| ASI06 | Memory and Context Poisoning | 5 | LLM01, LLM05, LLM09 |
| ASI07 | Insecure Inter-Agent Communication | 0 | LLM02, LLM03 |
| ASI08 | Cascading Failures | 0 | LLM01, LLM03, LLM05 |
| ASI09 | Human-Agent Trust Exploitation | 0 | LLM01, LLM03, LLM07, LLM10 |
| ASI10 | Rogue Agents | 0 | LLM02, LLM07 |
