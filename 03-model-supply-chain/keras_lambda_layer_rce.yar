/*
   YARA rule: Malicious Keras Lambda Layer Detection
   Author: Raymond DePalma (ai-dfir-detections)
   Date: 2026-04-15
   Reference: https://www.cve.org/CVERecord?id=CVE-2025-1550
              CVE-2025-1550 — Keras Lambda layers execute code even with safe_mode=True
   ATLAS: AML.T0018
   OWASP: LLM03:2025

   Keras .keras model files are ZIP archives containing config.json
   describing the model. Lambda layers can serialize arbitrary Python
   bytecode that executes on model load. Even safe_mode=True (the
   "secure" loader) was bypassable until recent versions.

   Apply to:
     - .keras files
     - .h5 files (legacy)
     - SavedModel directories
*/

rule Keras_Lambda_Layer_Present
{
    meta:
        description = "Keras model contains Lambda layer (potential code execution)"
        author      = "Raymond DePalma (ai-dfir-detections)"
        date        = "2026-04-15"
        atlas       = "AML.T0018"
        owasp       = "LLM03:2025"
        reference   = "https://www.cve.org/CVERecord?id=CVE-2025-1550"
        severity    = "medium"

    strings:
        $zip_magic   = { 50 4B 03 04 }
        $lambda_class = "\"class_name\": \"Lambda\""
        $lambda_func  = "\"function\": {"
        $lambda_module = "\"module\": \"keras.layers"

    condition:
        $zip_magic at 0 and $lambda_class and ($lambda_func or $lambda_module)
}

rule Keras_Lambda_With_Encoded_Bytecode
{
    meta:
        description = "Keras Lambda layer with marshal-encoded function (CVE-2025-1550 pattern)"
        author      = "Raymond DePalma (ai-dfir-detections)"
        date        = "2026-04-15"
        atlas       = "AML.T0018"
        owasp       = "LLM03:2025"
        reference   = "https://www.cve.org/CVERecord?id=CVE-2025-1550"
        severity    = "high"

    strings:
        $zip_magic = { 50 4B 03 04 }
        $lambda    = "\"class_name\": \"Lambda\""

        // Marshal magic bytes (CPython bytecode header)
        $marshal_py3_11 = { A7 0D 0D 0A }  // 3.11
        $marshal_py3_12 = { CB 0D 0D 0A }  // 3.12
        $marshal_py3_13 = { F3 0D 0D 0A }  // 3.13

        // Long base64 inside config (encoded function)
        $b64_blob = /"function":\s*\{[^}]*"items":\s*\[[^\]]*"[A-Za-z0-9+\/]{100,}={0,2}"/

    condition:
        $zip_magic at 0 and $lambda and (any of ($marshal_*) or $b64_blob)
}

rule Keras_H5_Lambda_Layer_Legacy
{
    meta:
        description = "Legacy H5 Keras model with Lambda layer"
        author      = "Raymond DePalma (ai-dfir-detections)"
        date        = "2026-04-15"
        atlas       = "AML.T0018"
        severity    = "medium"

    strings:
        // HDF5 magic
        $h5_magic = { 89 48 44 46 0D 0A 1A 0A }
        $lambda   = "Lambda" wide ascii
        $func_dump = "function_type" wide ascii

    condition:
        $h5_magic at 0 and $lambda and $func_dump
}
