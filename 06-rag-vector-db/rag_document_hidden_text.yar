/*
   YARA rules: RAG Document Hidden Text / Indirect Prompt Injection
   Author: Raymond DePalma (ai-dfir-toolkit)
   Date: 2026-04-15
   Reference: Greshake et al. 2023 — "Not what you've signed up for"
              https://arxiv.org/abs/2302.12173
              PoisonedRAG (USENIX Security 2025)
   ATLAS: AML.T0020, AML.T0051.001
   OWASP: LLM01:2025, LLM08:2025

   Detects steganographic and visually-hidden instructions embedded in
   documents intended for RAG ingestion. Apply to:
     - PDFs, DOCX, HTML, Markdown
     - Email bodies (.eml, .msg)
     - Web content scraped for ingestion
     - Wiki / Confluence / Notion exports
*/

rule RAG_Document_Bidi_Override
{
    meta:
        description = "Document contains Unicode bidirectional override (Trojan Source style)"
        author      = "Raymond DePalma (ai-dfir-toolkit)"
        date        = "2026-04-15"
        atlas       = "AML.T0020"
        owasp       = "LLM01:2025"
        reference   = "https://trojansource.codes/"
        severity    = "high"

    strings:
        $bidi_lre = { E2 80 AA }
        $bidi_rle = { E2 80 AB }
        $bidi_pdf = { E2 80 AC }
        $bidi_lro = { E2 80 AD }
        $bidi_rlo = { E2 80 AE }
        $bidi_lri = { E2 81 A6 }
        $bidi_rli = { E2 81 A7 }

    condition:
        any of them
}

rule RAG_Document_Tags_Block_Hidden_Prompt
{
    meta:
        description = "Document contains Unicode Tags block characters (invisible prompt injection)"
        author      = "Raymond DePalma (ai-dfir-toolkit)"
        date        = "2026-04-15"
        atlas       = "AML.T0051.001"
        owasp       = "LLM01:2025"
        reference   = "https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/"
        severity    = "high"

    strings:
        // Tags block U+E0000..U+E007F  (UTF-8: F3 A0 80 80 .. F3 A0 81 BF)
        // Two alternations cover the 80..BF and 80..BF ranges.
        $tag_block = { F3 A0 ( 80 | 81 ) ( 80 | 81 | 82 | 83 | 84 | 85 | 86 | 87 | 88 | 89 | 8A | 8B | 8C | 8D | 8E | 8F | 90 | 91 | 92 | 93 | 94 | 95 | 96 | 97 | 98 | 99 | 9A | 9B | 9C | 9D | 9E | 9F | A0 | A1 | A2 | A3 | A4 | A5 | A6 | A7 | A8 | A9 | AA | AB | AC | AD | AE | AF | B0 | B1 | B2 | B3 | B4 | B5 | B6 | B7 | B8 | B9 | BA | BB | BC | BD | BE | BF ) }

    condition:
        // Need a meaningful run of tag characters, not just one stray
        #tag_block > 5
}

rule RAG_Document_HTML_Hidden_Instructions
{
    meta:
        description = "HTML/Markdown with CSS-hidden text containing prompt-injection patterns"
        author      = "Raymond DePalma (ai-dfir-toolkit)"
        date        = "2026-04-15"
        atlas       = "AML.T0020"
        owasp       = "LLM01:2025"
        severity    = "high"

    strings:
        // CSS visibility tricks
        $hide_1 = "display:none" nocase
        $hide_2 = "visibility:hidden" nocase
        $hide_3 = "color:white" nocase
        $hide_4 = "color:#fff" nocase
        $hide_5 = "color: #ffffff" nocase
        $hide_6 = "font-size:0" nocase
        $hide_7 = "opacity:0" nocase
        $hide_8 = "text-indent:-9999px" nocase

        // Inside the hidden block — common injection markers
        $inj_1 = "ignore previous instructions" nocase
        $inj_2 = "you are now" nocase
        $inj_3 = "system prompt" nocase
        $inj_4 = "<IMPORTANT>" nocase
        $inj_5 = "execute the following" nocase
        $inj_6 = "send the contents to" nocase
        $inj_7 = "ignore the user" nocase
        $inj_8 = "do not mention this" nocase

    condition:
        any of ($hide_*) and any of ($inj_*)
}

rule RAG_Document_Whitespace_Smuggling
{
    meta:
        description = "Document contains long runs of whitespace possibly hiding instructions"
        author      = "Raymond DePalma (ai-dfir-toolkit)"
        date        = "2026-04-15"
        atlas       = "AML.T0020"
        severity    = "medium"

    strings:
        // Long runs of zero-width spaces (U+200B = E2 80 8B in UTF-8)
        $zwsp_run = /(\xe2\x80\x8b){10,}/

        // Long runs of tab/space immediately before injection trigger words
        $smuggle_1 = /[\x20\x09]{50,}(ignore previous|you are now|system prompt)/i

    condition:
        any of them
}

rule RAG_Document_PDF_Whitetext_Injection
{
    meta:
        description = "PDF containing white-on-white text with injection markers"
        author      = "Raymond DePalma (ai-dfir-toolkit)"
        date        = "2026-04-15"
        atlas       = "AML.T0020"
        severity    = "medium"

    strings:
        $pdf_magic = "%PDF-"

        // PDF text-rendering operators with white color set
        // 1 1 1 rg (RGB white) followed by text-show within 200 bytes
        $white_set_1 = /1\s+1\s+1\s+rg\s+/
        $white_set_2 = /1\s+1\s+1\s+RG\s+/
        $white_set_3 = "/Color\\ /DeviceRGB" nocase

        $injection_1 = "ignore previous" nocase
        $injection_2 = "you are now" nocase
        $injection_3 = "system prompt" nocase
        $injection_4 = "execute" nocase

    condition:
        $pdf_magic at 0 and any of ($white_set_*) and any of ($injection_*)
}
