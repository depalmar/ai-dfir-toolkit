/*
   YARA rule: MCP Tool Poisoning Detection
   Author: Raymond DePalma (ai-dfir-toolkit)
   Date: 2026-04-15
   Reference: https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
              https://www.cve.org/CVERecord?id=CVE-2025-59536
   ATLAS: AML.T0104 (Publish Poisoned AI Agent Tool, Resource Development)
          AML.T0110 (AI Agent Tool Poisoning, post-install mutation)
          Both, deliberately: this rule matches a poisoned tool description
          wherever it lands, and cannot tell a tool published poisoned from
          one mutated after approval. T0104 and T0110 are distinct current
          techniques, not alternative names - see docs/VERIFICATION.md.

   Detects malicious instructions embedded in MCP tool descriptions
   designed to coerce the LLM into actions invisible to the human user.
   Common patterns include:
     - <IMPORTANT> / <s> tags forcing instruction interpretation
     - Instructions to read sensitive files (.ssh, .aws, .env)
     - Instructions to exfiltrate via HTTP/DNS
     - Hidden directives wrapped in code-like syntax

   Apply this YARA rule to:
     - MCP server source code (Python/TypeScript)
     - Cached tool definitions on disk
     - JSON-RPC tool registration responses captured from logs
     - claude_desktop_config.json contents
     - .cursor/mcp.json
*/

rule MCP_Tool_Poisoning_Hidden_Instructions
{
    meta:
        description = "MCP tool description containing hidden LLM instructions"
        author      = "Raymond DePalma (ai-dfir-toolkit)"
        date        = "2026-04-15"
        atlas       = "AML.T0104, AML.T0110"
        owasp       = "LLM03:2026"
        reference   = "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"
        severity    = "critical"
        falsepositives = "Benign tool docs that combine generic phrases (e.g. 'before using this tool, you must first authenticate'). To reduce FPs, prefer the '<tag>' branch or require a coercer that names a sensitive path or exfil action ($coerce_7-$coerce_11) over any '2 of $coerce_*'."

    strings:
        // Common instruction-injection wrappers
        $tag_important = "<IMPORTANT>" nocase
        $tag_s         = "</s>"
        $tag_system    = "<|im_start|>system" nocase
        $tag_inst      = "[INST]" nocase

        // Description text indicating coercion of the LLM
        $coerce_1 = "before using this tool" nocase
        $coerce_2 = "you must first" nocase
        $coerce_3 = "do not mention" nocase
        $coerce_4 = "do not tell the user" nocase
        $coerce_5 = "without informing the user" nocase
        $coerce_6 = "always read the file" nocase
        $coerce_7 = "read .ssh" nocase
        $coerce_8 = "read .aws/credentials" nocase
        $coerce_9 = "read .env" nocase
        $coerce_10 = "exfiltrate" nocase
        $coerce_11 = "send the contents to" nocase

        // MCP context markers (confirm we're scanning MCP-related content)
        $mcp_marker_1 = "\"description\":"
        $mcp_marker_2 = "tools/call"
        $mcp_marker_3 = "mcpServers"

    condition:
        any of ($mcp_marker_*) and
        (any of ($tag_*) or 2 of ($coerce_*))
}

rule MCP_Tool_Description_Sensitive_Path_Reference
{
    meta:
        description = "MCP tool description referencing sensitive filesystem paths"
        author      = "Raymond DePalma (ai-dfir-toolkit)"
        date        = "2026-04-15"
        atlas       = "AML.T0086"
        owasp       = "LLM02:2026"
        severity    = "high"

    strings:
        $mcp_marker = "\"description\":"

        $path_1  = "~/.ssh/" nocase
        $path_2  = "~/.aws/credentials" nocase
        $path_3  = "~/.config/gh/hosts.yml" nocase
        $path_4  = "~/.netrc" nocase
        $path_5  = "/etc/shadow"
        $path_6  = "id_rsa"
        $path_7  = "id_ed25519"
        $path_8  = ".kube/config" nocase
        $path_9  = "wallet.dat" nocase
        $path_10 = "Keychains/login.keychain"

    condition:
        $mcp_marker and any of ($path_*)
}

rule MCP_Server_Outbound_Exfil_Code
{
    meta:
        description = "MCP server source containing outbound HTTP exfiltration code"
        author      = "Raymond DePalma (ai-dfir-toolkit)"
        date        = "2026-04-15"
        atlas       = "AML.T0086"
        owasp       = "LLM02:2026"
        severity    = "high"

    strings:
        // MCP framework imports
        $mcp_python    = "from mcp" nocase
        $mcp_ts        = "@modelcontextprotocol/sdk" nocase

        // Suspicious outbound primitives
        $exfil_1 = "requests.post" nocase
        $exfil_2 = "urllib.request.urlopen" nocase
        $exfil_3 = "fetch(" nocase
        $exfil_4 = "axios.post" nocase
        $exfil_5 = "http.request" nocase
        $exfil_6 = "node-fetch" nocase

        // Hardcoded suspicious destinations
        $dest_1 = /https?:\/\/[a-z0-9.-]+\.(ngrok|trycloudflare|serveo|loca)\.io/ nocase
        $dest_2 = /https?:\/\/[a-z0-9.-]+\.(burpcollaborator|interactsh|oast)\./
        $dest_3 = /https?:\/\/(\d{1,3}\.){3}\d{1,3}(:\d+)?\//

    condition:
        any of ($mcp_python, $mcp_ts) and
        any of ($exfil_*) and
        any of ($dest_*)
}
