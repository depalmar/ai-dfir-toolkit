# Verification Log

Every correction applied during the August 2026 verification pass, with the basis for the change.
This file exists so a reader can audit why a field says what it says.

| Scope | Field | Was | Now | Basis |
|---|---|---|---|---|
| `LOLAI-0007` | confidence | Low | **Medium** | CONFIRMED Devin has real endpoint footprint: VS Code extension (CognitionAI/devin-extension) using Remote SSH, a local Devin CLI, and required egress to *.devinapps.com. Architecture/domains HIGH; CLI path-level artifacts remain LOW. |
| `LOLAI-0007` | risk | Low | **Medium** | Local CLI agent + Remote SSH into a Cognition-controlled devbox is a real endpoint and egress surface, not browser-only. |
| `LOLAI-0010` | status | active | **legacy** | CONFIRMED Supermaven acquired by Anysphere (Cursor) 2024-11-12. Plugins stated as maintained but team focus moved to Cursor. Path-level detail stays LOW. |
| `LOLAI-0016` | status | active | **unmaintained** | CONFIRMED repo states 'This repo is not being maintained anymore'; team pivoted to the Pythagora VS Code extension (v1, Oct 2024). |
| `LOLAI-0016` | artifact_path | ~/.gpt-pilot/ | **<repo>/data/database/pythagora.db** | CORRECTED. Current version uses repo-relative data/database/pythagora.db per example-config.json. Treat ~/.gpt-pilot as an older/third-party convention. |
| `LOLAI-0013` | status | active | **dormant** | CONFIRMED development effectively stopped after v1.0.0 (Nov 2023); Reworkd pivoted to web scraping. Repo not archived but unmaintained. |
| `LOLAI-0013` | artifact_path | <install>/.env | **next/.env** | CORRECTED. docker-compose mounts ./next/.env as the canonical env file. Ports 3000 (Next.js) / 8000 (FastAPI); MySQL 8.0 container agentgpt_db. |
| `LOLAI-0017` | attribution | SentinelLABS + Censys | **Pillar Security** | CORRECTED. The 175,000-exposed-host figure is from Pillar Security's Jan 2026 'Operation Bizarre Bazaar' report. Cisco Talos (Sept 2025, Shodan) found only 1,139 — cite the source and note order-of-magnitude methodology variance. |
| `LOLAI-0008` | confidence | High | **Low** | DOWNGRADED. Could not independently confirm the binary name aws-lsp-codewhisperer-token-binary.js or npm package @aws/lsp-codewhisperer. Plausible but unverified — verify against the aws/language-servers repo. |
| `LOLAI-0008` | lifecycle | EOL 2027-04-30 | **EOL 2027-04-30; new signups blocked 2026-05-15** | CONFIRMED and expanded. IDE plugins + paid subs end-of-support 2027-04-30; new signups blocked 2026-05-15; capabilities migrate to Kiro. Console-embedded Q is unaffected. |
| `LOLAI-0031` | env_var | PLAYWRIGHT_MCP_HOST | **PLAYWRIGHT_MCP_HOST (UNVERIFIED)** | The --host flag is CONFIRMED and other options use the PLAYWRIGHT_MCP_* prefix, but PLAYWRIGHT_MCP_HOST was not seen named explicitly. Keep UNVERIFIED. |
| `LOLAI-0031` | profile_path | ms-playwright/ | **ms-playwright/mcp-{channel}-{workspace-hash}** | CORRECTED/REFINED. Persistent profile dirs are mcp-{channel}-{workspace-hash} (older docs show mcp-{channel}-profile). |
| `LOLAI-0011` | guidance | hardcode Claude_pzs8sxrjxfjjc | **derive at runtime** | CONFIRMED path, but recommend deriving the package family name via (Get-AppxPackage -Name *Claude*).PackageFamilyName since the publisher hash can change on republish. |
| `ATLAS` | version | v5.1.0 | **v5.4.0 (Feb 2026)** | CORRECTED. atlas-data release notes: v5.1.0 (Nov 2025) added the 16th tactic Command and Control (AML.TA0015); current release v5.4.0 (Feb 2026). Counts: 16 tactics / 84 techniques / 56 sub-techniques / 32 mitigations / 42 case studies. |
| `AIRT-CS-0001` | affects | LOLAI-0016 | **AIRT-0016** | CORRECTED. The case study still referenced the pre-rename LOLAI scheme retired in the `SCOPE` row below, so it pointed at an entry id that no longer exists and could not be cross-linked to the tool it describes. LOLAI-0016 and AIRT-0016 are both GPT Pilot. |
| `AIRT-0028` | artifact_path | &lt;project&gt;/config/agents.yaml | **&lt;project&gt;/src/&lt;name&gt;/config/agents.yaml** | CORRECTED and raised to high. Verified against the packaged first-party metadata in crewai-1.15.15-py3-none-any.whl, whose scaffold tree is `src/` → `crew.py` and `config/` → `agents.yaml`/`tasks.yaml`, with the prose 'Modify `src/my_project/config/agents.yaml` to define your agents.' The entry already contradicted itself: the crew.py row two entries below correctly used &lt;project&gt;/src/&lt;name&gt;/crew.py. Collecting the documented path would have found nothing. |
| `AML.T0104` / `AML.T0110` | mapping | T0110 for both tool poisoning and rug pull | **T0104 for published-poisoned, T0110 for post-install mutation** | CORRECTED. A third-party pack recommended replacing T0110 with T0104 throughout, on the premise that T0104 supersedes it. It does not: both are current, distinct techniques. `AML.T0104` Publish Poisoned AI Agent Tool sits under Resource Development (adversary publishes the tool); `AML.T0110` AI Agent Tool Poisoning covers modifying tools so future invocations execute attacker behaviour. A blanket replace would have mis-tagged the rug-pull rule. `mcp_tool_poisoning.yar` carries both, because it matches a poisoned description wherever it lands and cannot distinguish the two. Related: `AML.T0011.002` Poisoned AI Agent Tool (User Execution). |
| `AML.T0053` | name | AI Agent Tool Invocation | **AI Agent Tool Invocation** | CONFIRMED. Current official name is 'AI Agent Tool Invocation' (tactics: Execution, Privilege Escalation). Prior label was 'LLM Plugin Compromise'. |
| `LOLAI-0039` | port | 26040 | **26040 (UNVERIFIED)** | Cline standalone/CLI gRPC port 26040 with data in ~/.cline/data/ is single-source. Corroborate before deploying detections. |
| `SCOPE` | name | LOLAI | **the artifact catalog** | CORRECTED. lolai-project.github.io already exists (Jekyll, 11 agents, 3 categories, 19 MITRE techniques). Renamed and re-scoped to avoid collision and to claim the artifact/collection niche rather than the abuse-technique niche. |


## Verification Pass 2 — August 2026

| Scope | Field | Was | Now | Basis |
|---|---|---|---|---|
| `AIRT-0017` | artifact_path | ~/.ollama/models (service acct unconfirmed) | **/usr/share/ollama/.ollama/models** | CONFIRMED from the official Linux install docs: 'useradd -r -s /bin/false -m -d /usr/share/ollama ollama'. The service runs as its own user, so models live under that home - NOT the invoking user's. Collecting only ~/.ollama misses everything on a systemd install. |
| `AIRT-0017` | confidence | medium | **high** | CONFIRMED no built-in authentication ('Since Ollama itself doesn't provide authentication...'), default bind 127.0.0.1, port 11434, systemd unit at /etc/systemd/system/ollama.service. Logs via journalctl -u ollama. |
| `AIRT-0017` | artifact_added | - | **journalctl -u ollama** | CONFIRMED as the log source on systemd installs. Ollama has no separate log file there, so journald is the only timeline source. |
| `AIRT-0025` | confidence | medium | **high** | CONFIRMED port 5678 and Docker volume /home/node/.n8n from n8n's own docs ('-p 5678:5678 -v n8n_data:/home/node/.n8n'). |
| `AIRT-0011` | confidence | high | **high** | RE-CONFIRMED. MSIX package family name Claude_pzs8sxrjxfjjc and the LocalCache\Roaming virtualized path both hold; recommendation to derive at runtime stands. |
| `AIRT-0041` | entry_added | - | **Kiro** | NEW. Authored via the skill workflow. Hooks fire the agent on file events with no user action; MCP + hooks are project-scoped under .kiro/; config hot-reloads via file watcher. |
| `AIRT-0042` | entry_added | - | **Open WebUI** | NEW. First registered account is automatically admin - an instance reachable before its owner registers can be claimed by any visitor. |
| `AIRT-0043` | entry_added | - | **OpenHands** | NEW. Documented deployment mounts /var/run/docker.sock into the container, which is host-root-equivalent. |
| `AIRT-0044` | entry_added | - | **Langflow** | NEW. CVE-2025-3248 is on the CISA KEV catalog with confirmed in-the-wild exploitation delivering the Flodrix botnet - the strongest documented mass-exploitation case in this catalog. |
| `VOCAB` | artifact_type | 52 ad-hoc values | **17 controlled values** | Surfaced by the live authoring test. Near-duplicates (log/logs, agent-def/agent-definition, env-var/env-file/env-override) made the published CSV feed unfilterable. Collapsed and locked as a schema enum; negative-tested. |
| `VOCAB` | secret_type | 17 null values | **backfilled + required** | Every credential entry now carries a typed secret_type from a closed enum, so credential-access hunting can filter by secret class. |
| `SCOPE` | detections | none | **vendor-neutral Sigma + osquery** | Detection content added as Sigma (the vendor-neutral detection standard, convertible to any SIEM via sigma-cli) plus an osquery pack for inventory. No product-specific query language ships in the repo. |
