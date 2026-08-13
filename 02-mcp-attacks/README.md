# 02 — MCP (Model Context Protocol) Attack Detection

Detects compromise of MCP servers and clients including tool poisoning, configuration tampering, rug-pull attacks, and credential exfiltration via MCP tools.

## Threats covered

| Threat | ATLAS | OWASP | Reference |
|--------|-------|-------|-----------|
| MCP tool poisoning (description hijack, published poisoned) | T0104 | LLM03 | Invariant Labs 2025 |
| MCP rug pull (post-install tool mutation) | T0110 | LLM04 | Invariant Labs 2025 |
| Malicious MCP config injection | T0010 | LLM03 | CVE-2025-59536 |
| MCP credential exfiltration | T0086 | LLM02 | Cyata 2025 |
| MCP filesystem escape | T0011 | LLM03 | CVE-2025-53109/53110 |
| MCP Inspector RCE | T0011 | — | CVE-2025-49596 |
| `mcp-remote` OAuth proxy injection | T0011 | — | CVE-2025-6514 |

## Files

- `mcp_tool_poisoning.yar` — YARA for malicious tool descriptions
- `mcp_config_tampering.yml` — Sigma for unauthorized MCP config writes
- `mcp_credential_access.yml` — Sigma for MCP processes touching ~/.ssh, ~/.aws
- `mcp_outbound_unknown_domain.rules` — Suricata for MCP server beaconing
- `claude_desktop_config_modify.yml` — Sigma for claude_desktop_config.json changes

Cursor `.cursor/mcp.json` and VS Code `.vscode/settings.json` changes are covered by `mcp_config_tampering.yml` (multi-client scope). MCP Inspector exposure (CVE-2025-49596) is indirectly caught by `mcp_outbound_unknown_domain.rules` plus the generic unauth-exposure patterns in `04-ai-infrastructure/`.

## Log sources required

- EDR / Sysmon / auditd file modification events
- Process creation events (Sysmon EID 1, auditd execve, EDR equivalents)
- Network telemetry (Zeek, Suricata, EDR network logs)
- File contents (for YARA scanning of MCP config files)

## High-value forensic artifacts

| Platform | Artifact path |
|----------|--------------|
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (Win .exe) | `%APPDATA%\Claude\claude_desktop_config.json` |
| Claude Desktop (Win MSIX) | `%LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json` |
| Claude Code | `~/.claude/settings.json`, `~/.claude/.mcp.json` |
| Cursor IDE | `~/.cursor/mcp.json`, `.cursor/mcp.json` (project) |
| VS Code | `.vscode/settings.json` |
| MCP server logs (Claude) | `~/Library/Logs/Claude/mcp-server-*.log` |

## Tuning notes

MCP rules are lower-FP than prompt injection rules because legitimate users rarely modify MCP configs through unusual processes. The main FP source is **package managers and IDE auto-updates** modifying configs — exclude `npm`, `npx`, `code`, `cursor` parent processes if needed.
