/*
   YARA rules: Rules File Backdoor — Hidden Instructions in Copilot/Cursor Rules
   Author: Raymond DePalma (ai-dfir-toolkit)
   Date: 2026-04-15
   Reference: https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents
              Pillar Security 2025 — "Rules File Backdoor"
   ATLAS: AML.T0010
   OWASP: LLM04:2026

   Detects hidden Unicode characters and steganographic instructions
   embedded in:
     - .github/copilot-instructions.md
     - .cursorrules
     - .cursor/rules/*.md
     - CLAUDE.md
     - .claude/CLAUDE.md
     - .windsurfrules
   These files are auto-loaded as system instructions by AI coding
   assistants. Attackers commit them to shared repos to coerce the
   assistant into generating backdoored code or exfiltrating data
   while appearing benign during human code review.
*/

rule Copilot_Rules_File_Hidden_Unicode
{
    meta:
        description = "AI assistant rules file containing invisible/hidden Unicode characters"
        author      = "Raymond DePalma (ai-dfir-toolkit)"
        date        = "2026-04-15"
        atlas       = "AML.T0010"
        owasp       = "LLM04:2026"
        reference   = "https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents"
        severity    = "high"

    strings:
        // Bidirectional override characters (Trojan Source style)
        $bidi_lre = { E2 80 AA }   // U+202A LEFT-TO-RIGHT EMBEDDING
        $bidi_rle = { E2 80 AB }   // U+202B RIGHT-TO-LEFT EMBEDDING
        $bidi_pdf = { E2 80 AC }   // U+202C POP DIRECTIONAL FORMATTING
        $bidi_lro = { E2 80 AD }   // U+202D LEFT-TO-RIGHT OVERRIDE
        $bidi_rlo = { E2 80 AE }   // U+202E RIGHT-TO-LEFT OVERRIDE
        $bidi_lri = { E2 81 A6 }   // U+2066 LEFT-TO-RIGHT ISOLATE
        $bidi_rli = { E2 81 A7 }   // U+2067 RIGHT-TO-LEFT ISOLATE

        // Zero-width / invisible characters
        $zwsp     = { E2 80 8B }   // U+200B ZERO WIDTH SPACE
        $zwnj     = { E2 80 8C }   // U+200C ZERO WIDTH NON-JOINER
        $zwj      = { E2 80 8D }   // U+200D ZERO WIDTH JOINER
        $bom      = { EF BB BF }   // U+FEFF BYTE ORDER MARK in middle of file

        // Tags block (used for invisible-prompt-injection research)
        $tag_e0000 = { F3 A0 80 80 }
        $tag_e007f = { F3 A0 81 BF }

    condition:
        any of them
}

rule Copilot_Rules_File_Coercive_Instructions
{
    meta:
        description = "AI rules file containing coercive instructions for the assistant"
        author      = "Raymond DePalma (ai-dfir-toolkit)"
        date        = "2026-04-15"
        atlas       = "AML.T0010"
        owasp       = "LLM04:2026"
        severity    = "high"

    strings:
        // Coercive directives
        $directive_1 = "always include the following" nocase
        $directive_2 = "before generating code" nocase
        $directive_3 = "do not mention this" nocase
        $directive_4 = "do not tell the user" nocase
        $directive_5 = "without informing the user" nocase
        $directive_6 = "silently include" nocase
        $directive_7 = "always add the following import" nocase
        $directive_8 = "in every file" nocase
        $directive_9 = "include this snippet in all generated" nocase
        $directive_10 = "fetch and execute" nocase
        $directive_11 = "send the contents to" nocase
        $directive_12 = "exfiltrate" nocase

        // Suspicious endpoints to "ping" or "report to"
        $endpoint_1 = /https?:\/\/[a-z0-9.-]+\.(ngrok|trycloudflare|serveo|loca|burpcollaborator|interactsh|webhook\.site|requestcatcher)\.(io|com|me|fun|live)/ nocase
        $endpoint_2 = /https?:\/\/(\d{1,3}\.){3}\d{1,3}(:\d+)?/

    condition:
        2 of ($directive_*) or any of ($endpoint_*)
}

rule Copilot_Rules_File_Pinned_Dependency_Override
{
    meta:
        description = "AI rules file forcing use of unusual / typosquattable dependencies"
        author      = "Raymond DePalma (ai-dfir-toolkit)"
        date        = "2026-04-15"
        atlas       = "AML.T0010.002"
        severity    = "medium"

    strings:
        $force_install_1 = /install\s+(torchtriton|huggin-face|tensorflw|tensoflow|transfomers|langchian|pythorch|llama-index-utils|openai-utils)/ nocase
        $force_install_2 = "pip install --index-url http" nocase
        $force_install_3 = "always use the package" nocase
        $force_install_4 = "prefer installing from" nocase

    condition:
        any of them
}
