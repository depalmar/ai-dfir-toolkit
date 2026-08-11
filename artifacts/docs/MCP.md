# MCP Security Reference

Model Context Protocol is the highest-value artifact class in this catalog: an MCP
config is a persistence mechanism and an execution primitive in one file, and the
server it launches inherits the agent's credentials and trust.

## Known CVEs

| CVE | Component | CVSS | Class | Summary | Fixed | Researcher | Date |
|---|---|---|---|---|---|---|---|
| CVE-2025-6514 | mcp-remote | 9.6 | OS Command Injection / RCE | Full client-side RCE when connecting to an untrusted MCP server. Affects v0.0.5-0.1.15. 437,000+ downloads impacted. | 0.1.16 | JFrog Security Research (Or Peles) | 2025-07-09 |
| CVE-2025-49596 | MCP Inspector (Anthropic) | 9.4 | Unauthenticated RCE | Browser-based attack against AI developer tooling; among the first critical RCEs in the MCP ecosystem. | 0.14.1 | Oligo Security (Avi Lumelsky) | 2025-06-13 |
| CVE-2025-54136 | Cursor IDE (MCPoison) | n/a | Rug Pull / Persistent Code Execution | Approve a benign mcp.json key once; swap the payload later and it executes silently on project open. | Cursor patch | Check Point | 2025 |
| CVE-2025-54135 | Cursor IDE (CurXecute) | n/a | Indirect Prompt Injection -> RCE | External content injects a prompt that writes mcp.json and executes before the user can reject it. | Cursor patch | Aim Labs | 2025 |
| CVE-2025-52573 | ios-simulator-mcp | n/a | Command Injection via LLM output | Prompt-injected model output reaches an unsanitized shell invocation. | patched | - | 2025 |
| CVE-2025-58357 | 5ire desktop client | n/a | Content Injection / Script Gadget | Script gadgets reachable via a compromised MCP server. | patched | - | 2025 |
| CVE-2025-68143 | Anthropic mcp-server-git | n/a | RCE chain | Part of a three-CVE RCE chain. | patched | - | 2026 |
| CVE-2025-68144 | Anthropic mcp-server-git | n/a | RCE chain | Part of a three-CVE RCE chain. | patched | - | 2026 |
| CVE-2025-68145 | Anthropic mcp-server-git | n/a | RCE chain | Part of a three-CVE RCE chain. | patched | - | 2026 |
| CVE-2026-21852 | Claude Code | n/a | See advisory | Claude Code advisory. | patched | - | 2026 |
| CVE-2025-59536 | Claude Code | n/a | See advisory | Claude Code advisory. | patched | - | 2025 |
| CVE-2026-27825 | mcp-atlassian | n/a | SSRF | Server-side request forgery in the Atlassian MCP server. | patched | - | 2026 |
| CVE-2026-27826 | mcp-atlassian | n/a | Arbitrary File Write | Arbitrary file write in the Atlassian MCP server. | patched | - | 2026 |
| CVE-2026-13341 | Kong Konnect MCP | n/a | Indirect Prompt Injection / Confused Deputy | Confused-deputy at production scale via indirect prompt injection. | patched | - | 2026 |

## Vulnerability Classes

| Class | Description | Origin | ATLAS |
|---|---|---|---|
| Tool Poisoning | Malicious instructions hidden in tool metadata/descriptions the model reads as directives | Invariant Labs (Apr 2025) | AML.T0110 |
| Rug Pull | Server silently redefines a previously approved tool after consent is granted | Invariant Labs | AML.T0081 |
| Tool Shadowing / Ghost Tools | One server's tool definition overrides or impersonates another's | Invariant Labs | AML.T0110 |
| Cross-Server Attack | A malicious server manipulates calls intended for a trusted server | Invariant Labs | AML.T0053 |
| Confused Deputy / OAuth Weakness | MCP server misuses its own privileges on behalf of an untrusted caller; token passthrough anti-pattern | MCP Security Best Practices | AML.T0053 |
| Line Jumping | Injected content jumps the intended tool-call ordering | Community research | AML.T0051 |
| Toxic Agent Flow | Untrusted content -> privileged tool -> exfiltration in one uninterrupted agent turn | Aim Labs | AML.T0086 |
| Lethal Trifecta | Private data access + untrusted content exposure + external communication in one agent | Simon Willison (Apr 2025) | AML.T0086 |

## Config Red Flags

| Red flag | Why it matters | Action |
|---|---|---|
| command uses @latest (npx @scope/server@latest) | Remote code fetched and executed on every single app launch - a supply-chain compromise lands instantly | Require pinned versions; alert on @latest in any MCP config |
| env block contains an API key, PAT, or token | Plaintext secret in a JSON file readable by any process running as the user | DLP + treat as exposed credential; rotate |
| command is docker with -v / --volume host mounts | Container gets read/write access to host filesystem paths | Review mount scope; deny host-root mounts |
| command is an absolute path to a non-standard binary | Arbitrary executable launched at every login with user privileges | Treat as unsigned autostart; hash and analyze the binary |
| Config modified outside a user-driven install window | Possible unauthorized persistence implant | Timeline the file MACB times against user session activity |
| MCP server with filesystem scope set to / or C:\ or user home root | Whole-disk read access exposed to the model context | Scope to specific project directories only |
| Playwright/browser MCP with --caps=storage or --storage-state | Cookie and localStorage read = session-token theft and MFA bypass | Escalate; treat as credential-access capability |
| .mcp.json / .cursor/mcp.json arriving via a cloned repo or PR | An untrusted repo can ship an execution primitive that fires on open | Gate in CI; block MCP config files in PRs from external contributors |
| Config references a base_url or endpoint that is not a sanctioned provider | Silent redirection of all prompts and code to an attacker-controlled proxy | Escalate as potential data exfiltration channel |
