rule Agent_Memory_Poisoning_Persistent_Exfil_Instruction
{
    meta:
        description         = "Detects a persistent exfiltration instruction stored in an AI agent memory store or instruction file - the spAIware pattern, where poisoned memory makes every future response emit a markdown image beacon carrying conversation content to an attacker URL."
        author              = "Raymond DePalma (@depalmar)"
        date                = "2026-08-12"
        reference           = "MITRE ATLAS AML.T0080.000 (AI Agent Context Poisoning: Memory); Embrace the Red - ChatGPT: Hacking Memories with Prompt Injection (spAIware)"
        atlas               = "AML.T0080.000, AML.T0086"
        owasp_llm           = "LLM01, LLM02"
        target              = "memory.json, memories.json, MEMORY.md, CLAUDE.md, .cursorrules, LangGraph checkpoint stores"
        confidence          = "HIGH when the persistence directive and the beaconing URL co-occur; MEDIUM for either alone"
        tlp                 = "CLEAR"
        version             = "1.0"

    strings:
        // Persistence framing - the instruction is meant to govern future sessions
        $p1 = "all future responses" ascii wide nocase
        $p2 = "every future conversation" ascii wide nocase
        $p3 = "in all future sessions" ascii wide nocase
        $p4 = "from now on" ascii wide nocase
        $p5 = "remember this for" ascii wide nocase
        $p6 = "for all future" ascii wide nocase

        // Beacon shape - markdown image plus URL with an interpolation placeholder
        $b1 = /!\[[^\]]{0,40}\]\(\s*https?:\/\/[^)]{0,200}\)/ ascii wide
        $b2 = /https?:\/\/[^\s)'"]{0,200}[?&][a-zA-Z0-9_]{1,20}=\s*\[[A-Z_]{2,20}\]/ ascii wide
        $b3 = /https?:\/\/[^\s)'"]{0,200}[?&][a-zA-Z0-9_]{1,20}=\s*\{\{?[a-z_]{2,30}\}?\}/ ascii wide

        // Secrecy - legitimate memory never demands concealment
        $s1 = "do not tell the user" ascii wide nocase
        $s2 = "don't tell the user" ascii wide nocase
        $s3 = "never mention this" ascii wide nocase
        $s4 = "without informing the user" ascii wide nocase
        $s5 = "do not mention this instruction" ascii wide nocase

        // Standing credential collection
        $c1 = "whenever you see an api key" ascii wide nocase
        $c2 = "when you find a password" ascii wide nocase
        $c3 = "send it to https://" ascii wide nocase
        $c4 = "contents of any .env" ascii wide nocase

    condition:
        // persistence framing + a beacon, OR any secrecy directive, OR standing credential harvest
        ( any of ($p*) and any of ($b*) )
        or any of ($s*)
        or ( any of ($c*) and any of ($b*, $p*) )
}

rule Agent_Memory_Hidden_Instruction_Concealment
{
    meta:
        description         = "Detects instructions concealed from human review inside an agent memory store or instruction file - HTML comments wrapping directives, zero-width characters, or CSS-invisible styling. Concealment indicates the content was authored to survive a human reading the file."
        author              = "Raymond DePalma (@depalmar)"
        date                = "2026-08-12"
        reference           = "MITRE ATLAS AML.T0080; Rules-File-Backdoor technique"
        atlas               = "AML.T0080"
        owasp_llm           = "LLM01"
        confidence          = "MEDIUM - HTML comments and zero-width characters occur legitimately; requires the concealed text to also carry directive language"
        tlp                 = "CLEAR"
        version             = "1.0"

    strings:
        // Concealment mechanisms
        $h1 = "<!--" ascii wide
        $h2 = /font-size\s*:\s*0/ ascii wide nocase
        $h3 = /color\s*:\s*(#fff{1,6}|white)\s*;/ ascii wide nocase
        $h4 = /display\s*:\s*none/ ascii wide nocase
        $zw1 = { E2 80 8B }          // U+200B zero-width space
        $zw2 = { E2 80 8D }          // U+200D zero-width joiner
        $zw3 = { EF BB BF }          // U+FEFF BOM used mid-content

        // Directive language that should not be hiding
        $d1 = "always use" ascii wide nocase
        $d2 = "from now on" ascii wide nocase
        $d3 = "ignore previous" ascii wide nocase
        $d4 = "do not tell" ascii wide nocase
        $d5 = "send the contents" ascii wide nocase
        $d6 = "POST the contents" ascii wide nocase
        $d7 = "you must" ascii wide nocase

    condition:
        (any of ($h*) or any of ($zw*)) and 2 of ($d*)
}
