# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-19

### Added

Initial public release. **43 rule files containing 114 detection signatures** across 6 threat categories (one file often bundles multiple related variants as multi-document Sigma, multiple `rule` blocks in one YARA file, or multiple `alert` lines in one Suricata `.rules` file):

- **01 - LLM Prompt Injection** (8 files / 10 signatures): prompt injection keywords, jailbreak personas, system prompt extraction, markdown image exfil, adversarial suffix YARA, Bedrock token DoS + injection, Azure OpenAI injection (Sigma), base64 response exfil
- **02 - MCP Attacks** (5 files / 14 signatures): tool poisoning YARA, config tampering, credential access, outbound unknown domain Suricata, Claude Desktop config modify
- **03 - Model Supply Chain** (8 files / 23 signatures): pickle malicious opcodes YARA, Keras lambda RCE YARA, HuggingFace token exposure, MLflow path traversal Suricata, MLflow unauth API, pip typosquat, HF cache unexpected writer, model file hash mismatch (Sigma)
- **04 - AI Infrastructure** (9 files / 31 signatures): Ray Jobs API RCE, Ray dashboard exposure, ShadowRay process masquerading, GPU unexpected utilization, SSH key injection, Triton inference server exploit, TorchServe ShellTorch, NVIDIA container escape, Ollama/vLLM unauth exposure
- **05 - Copilot / Assistant Abuse** (8 files / 19 signatures): M365 Copilot sensitivity label access (Sigma), M365 Copilot anomalous aggregation (Sigma), GitHub Copilot YOLO mode, Copilot rules file backdoor YARA, Cursor settings DB modification, Claude session JSONL unexpected access, ChatGPT paste sensitive data, AI assistant outbound to Camo proxy Suricata
- **06 - RAG / Vector DB** (5 files / 17 signatures): vector DB unauth exposure Suricata, vector DB bulk exfil, RAG document hidden text YARA, ChromaDB SQLite unexpected writer, vector DB query anomaly

### Coverage

- MITRE ATLAS v5.4.0 (February 2026): 15 unique techniques covered
- OWASP Top 10 for LLM Applications 2025: 8 of 10 categories covered (LLM01, LLM02, LLM03, LLM06, LLM07, LLM08, LLM10)
- 30+ CVEs referenced, including ShadowRay (CVE-2023-48022), EchoLeak (CVE-2025-32711), CamoLeak (CVE-2025-59145), vLLM Mooncake (CVE-2025-32444), NVIDIA Container Toolkit chain (CVE-2024-0132, CVE-2025-23266, CVE-2025-23359), Triton chain (CVE-2025-23319/23320/23334)

### Test Suite

- 7 smoke tests covering YARA rules (pickle, MCP config, RAG hidden text, Copilot rules file)
- Test artifacts for every rule format
- Sample logs for Sigma rules (Azure OpenAI, Bedrock, M365 Copilot, network captures)
- `tests/validate.sh` for one-command test execution

### Documentation

- `README.md` — project overview, quickstart for each SIEM backend
- `MAPPINGS.md` — per-rule ATLAS + OWASP + CVE cross-reference
- Category-level `README.md` in each numbered directory
- `CONTRIBUTING.md` — rule submission requirements
- `tests/README.md` — test suite documentation
- `docs/ai-dfir-investigation-guide.md` — companion investigation guide with Mermaid attack-chain diagrams (triage flow, MCP trust boundary, ShadowRay kill chain, RAG poisoning lifecycle, IR response lifecycle)
