# 01 — LLM Prompt Injection & Jailbreak Detection

Detects prompt injection attempts (direct and indirect), jailbreak patterns, system prompt extraction attempts, and suspicious LLM input/output behavior.

## Threats covered

| Threat | ATLAS | OWASP | Reference |
|--------|-------|-------|-----------|
| Direct prompt injection | T0051.000 | LLM01 | OWASP LLM01:2025 |
| Indirect prompt injection | T0051.001 | LLM01 | Greshake et al. 2023 |
| Jailbreak (DAN/Developer Mode/etc.) | T0054 | LLM01 | OWASP genai.owasp.org |
| System prompt extraction | T0054 | LLM07 | OWASP LLM07:2025 |
| Output exfiltration via markdown image | T0024 | LLM02 | EchoLeak (CVE-2025-32711) |
| Adversarial suffix attacks | T0051.000 | LLM01 | Zou et al. 2023 (GCG) |
| Token flooding / unbounded consumption | T0029 | LLM10 | OWASP LLM10:2025 |

## Files

- `prompt_injection_keywords.yml` — Sigma rule for known injection trigger phrases
- `jailbreak_personas.yml` — Sigma rule for DAN/Developer Mode/STAN/etc.
- `system_prompt_extraction.yml` — Sigma rule for system prompt leak attempts
- `markdown_image_exfil.yml` — Sigma rule for outputs containing external image refs
- `adversarial_suffix.yar` — YARA rule for GCG-style adversarial suffixes
- `bedrock_high_token_usage.yml` — Sigma rule for AWS Bedrock cost-based DoS
- `azure_openai_injection.yml` — Sigma for Azure OpenAI RequestResponseLog (Log Analytics / SIEM-agnostic)
- `llm_response_base64_exfil.yml` — Sigma rule for Base64 in LLM outputs

## Log sources required

- AWS Bedrock model invocation logs (CloudWatch `/aws/bedrock`)
- Azure OpenAI diagnostic logs (`AzureDiagnostics` Category=`RequestResponseLog`)
- GCP Vertex AI Cloud Audit Logs
- Application-layer LLM proxy logs (LiteLLM, Langfuse, Helicone, etc.)
- Self-hosted Ollama / vLLM logs

## Tuning notes

Prompt injection detection has high false positive potential — security researchers, red teamers, and even legitimate users discussing prompt engineering will trip these rules. Recommended approach:

1. Scope rules to **production** LLM endpoints, not dev/staging
2. Exclude known security/research user accounts
3. Pair these rules with output anomaly detection (response length, refusal rate) for higher confidence
