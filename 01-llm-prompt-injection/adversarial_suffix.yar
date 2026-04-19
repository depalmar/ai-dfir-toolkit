/*
   YARA rule: Adversarial Suffix Patterns (GCG-style attacks)
   Author: Raymond DePalma (ai-dfir-detections)
   Date: 2026-04-15
   Reference: Zou et al. 2023 - "Universal and Transferable Adversarial Attacks on Aligned Language Models"
              https://arxiv.org/abs/2307.15043
   ATLAS: AML.T0051.000

   Detects strings exhibiting characteristics of GCG-generated
   (Greedy Coordinate Gradient) adversarial suffixes used to bypass
   LLM safety alignment. These suffixes appear as random-looking
   character sequences appended to malicious prompts.

   Use case: Scan logged LLM input fields, conversation transcripts,
   or RAG-ingested documents for suspected adversarial suffixes.
*/

rule LLM_Adversarial_Suffix_GCG_Style
{
    meta:
        description = "GCG-style adversarial suffix targeting LLM alignment"
        author      = "Raymond DePalma (ai-dfir-detections)"
        date        = "2026-04-15"
        atlas       = "AML.T0051.000"
        owasp       = "LLM01:2025"
        reference   = "https://arxiv.org/abs/2307.15043"
        severity    = "high"

    strings:
        // Known public GCG suffixes from research papers
        $known_1 = "describing.\\ + similarlyNow write oppositeley"
        $known_2 = "== interface Manuel WITH steps instead sentences :)ish?"
        $known_3 = "describing.--;) similarlyNow write opposite contents.](Me giving"
        $known_4 = "!!!!!!!!!!!!!!!!!!!!!!!!!!!"

        // Heuristic: long sequences of mixed punctuation + camelCase typical of GCG
        $heuristic_1 = /[A-Za-z0-9]{3,}[^\s\w]{2,}[A-Za-z0-9]{3,}[^\s\w]{2,}[A-Za-z0-9]{3,}/

        // Heuristic: repeating suffix tokens common in adversarial outputs
        $heuristic_2 = /(\.\\\s+\+\s+){2,}/
        $heuristic_3 = /(\]\(Me|Me giving|Now write opposite)/

    condition:
        any of ($known_*) or
        (2 of ($heuristic_*) and filesize < 10MB)
}

rule LLM_Adversarial_Suffix_Repeated_Tokens
{
    meta:
        description = "Repeated token flooding (often paired with adversarial attacks)"
        author      = "Raymond DePalma (ai-dfir-detections)"
        date        = "2026-04-15"
        atlas       = "AML.T0029"
        owasp       = "LLM10:2025"
        severity    = "medium"

    strings:
        // Excessive repetition of single tokens (Carlini divergence attack)
        $repeat_word    = /(\b\w{1,15}\b\s+){50,}/
        // YARA does not support backreferences. Match concrete long runs of
        // common single characters used in flooding attacks.
        $repeat_char_a  = /a{200,}/
        $repeat_char_x  = /x{200,}/
        $repeat_char_0  = /0{200,}/
        $repeat_char_1  = /1{200,}/
        $repeat_char_sp = / {200,}/
        $repeat_char_nl = /\n{200,}/
        $repeat_char_ex = /!{200,}/
        $repeat_emoji   = /([\xF0-\xF4][\x80-\xBF]{3}){50,}/

    condition:
        any of them and filesize < 5MB
}
