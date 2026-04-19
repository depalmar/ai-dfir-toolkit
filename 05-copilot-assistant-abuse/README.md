# 05 — Copilot & AI Assistant Abuse Detection

Detects abuse of AI productivity assistants (Microsoft 365 Copilot, GitHub Copilot, Claude Desktop, Cursor IDE) for data exfiltration, oversharing exploitation, and AI-as-proxy attacks.

## Threats covered

| Threat | ATLAS | OWASP | Reference |
|--------|-------|-------|-----------|
| M365 Copilot accessing sensitivity-labeled content | T0086 | LLM02 | CW1226324 |
| M365 Copilot oversharing / aggregation | T0086 | LLM02 | Concentric AI 2024-2025 |
| EchoLeak (zero-click M365 Copilot exfil) | T0086 | LLM02 | CVE-2025-32711 |
| GitHub Copilot Chat exfil (CamoLeak) | T0086 | LLM02 | CVE-2025-59145 |
| GitHub Copilot YOLO mode RCE | T0011 | LLM06 | CVE-2025-53773 |
| Rules File Backdoor (Copilot/Cursor) | T0010 | LLM03 | Pillar Security 2025 |
| Cursor MCPoison persistent backdoor | T0010 | LLM06 | Check Point 2025 |
| Cursor CurXecute RCE | T0011 | LLM01 | CVE-2025-54135 |
| Samsung-style ChatGPT data leak | T0086 | LLM02 | Samsung 2023 incident |

## Files

- `m365_copilot_sensitive_label_access.yml` — Sigma for Purview audit logs (CopilotInteraction)
- `m365_copilot_anomalous_aggregation.yml` — Sigma for cross-source aggregation
- `github_copilot_yolo_mode_enabled.yml` — Sigma for .vscode/settings.json YOLO toggle
- `copilot_rules_file_backdoor.yar` — YARA for hidden Unicode in copilot-instructions
- `cursor_settings_db_modification.yml` — Sigma for state.vscdb tampering
- `chatgpt_paste_sensitive_data.yml` — Sigma for clipboard / browser network detection
- `claude_session_jsonl_unexpected_access.yml` — Sigma for ~/.claude/projects/ access
- `ai_assistant_outbound_to_camo_proxy.rules` — Suricata for CamoLeak-style exfil

## Log sources required

- **Microsoft Purview Audit Logs** (`CopilotInteraction`, `AIAppInteraction` records)
- **GitHub audit log** (Enterprise) — for Copilot org-level events
- VS Code / Cursor extension logs:
  - `%APPDATA%\Code\logs\` (Win), `~/Library/Application Support/Code/logs/` (Mac), `~/.config/Code/logs/` (Linux)
- Endpoint file modification events (Sysmon EID 11, auditd, EDR)
- Network telemetry (Suricata, Zeek) for exfil channels
- Browser proxy logs (where ChatGPT/Claude.ai access is governed)

## High-value forensic artifacts

| Tool | Artifact |
|------|----------|
| M365 Copilot | Purview audit `CopilotInteraction` (metadata only) |
| M365 Copilot full transcripts | eDiscovery → Exchange → "Copilot interactions" type |
| Claude Code | `~/.claude/projects/{slug}/session-*.jsonl` (full transcripts) |
| Claude Desktop config | `claude_desktop_config.json` (per-OS paths in 02-mcp-attacks) |
| Cursor | `state.vscdb` SQLite under globalStorage |
| Cursor project rules | `.cursorrules`, `.cursor/rules/` |
| GitHub Copilot (VS Code) | Output panel → "GitHub Copilot" channel; OTel traces if enabled |

## Tuning notes

M365 Copilot rules will produce volume — start with **scope filters on label sensitivity** (Confidential, Highly Confidential, Internal) before deploying broadly. CamoLeak-style exfil rules require **outbound Camo URL** monitoring; if your perimeter does not see github.com user-content traffic, pivot to GitHub audit log review.
