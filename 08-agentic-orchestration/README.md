# 08 — Agentic Orchestration Abuse & AI-Service C2

Detects the adversary **using an AI agent as the operator** — driving reconnaissance through exfiltration at machine tempo — and **AI provider APIs abused as covert C2 channels**.

This category is different in kind from 01–07. There, the malicious act is visible in a single artifact: a poisoned tool description, a pickle opcode, an injected prompt. Here **every individual tool call is legitimate.** `nmap`, `secretsdump`, `tar`, `aws s3 cp` are all ordinary. What betrays the intrusion is emergent — the tempo, the phase progression, the breadth, and the ratio of agent actions to human decisions. Static signatures cannot express that, which is why the Sigma content here is threshold- and correlation-driven rather than string-matched.

## Threats covered

| Threat | ATLAS | OWASP | Reference |
|--------|-------|-------|-----------|
| Agent tool invocation at machine tempo | T0086 | LLM03 | GTG-1002, Anthropic Nov 2025 |
| Mass collection via agent tool chaining | T0086 | LLM03 | GTG-1002 |
| Agentic killchain progression in one session | T0086, T0054 | LLM03 | GTG-1002 |
| AI service API used as a C2 relay | T0096 | LLM03 | SesameOp, Microsoft DART Nov 2025 |
| Non-inference Assistants/Threads API access | T0096 | LLM03 | SesameOp (AML.CS0042) |

## Cases referenced

**GTG-1002** (Anthropic, 13 Nov 2025) — Claude Code plus MCP servers with sub-agents used as an autonomous attack framework across roughly 30 targets, with the AI performing the large majority of tactical work and humans intervening at only a handful of decision points per campaign. Jailbroken by role-playing an authorised penetration test and decomposing the attack into individually innocuous sub-tasks.

**SesameOp** (Microsoft DART, 3 Nov 2025, discovered Jul 2025) — a backdoor using the OpenAI Assistants API as a C2 relay rather than for inference: it polls the assistants list and reads its command from description and instructions fields, returning output as a message. Delivered by an obfuscated .NET loader and persisted via AppDomainManager injection.

**Vendor-disclosed, no public IOCs.** Neither case shipped hashes or infrastructure indicators, which is precisely why this category is behavioural. Treat the reporting as CLAIMED — corroborated across vendor and press, not independently audited here.

## Files

- `sesameop_assistants_api_c2.yml` — Sigma (proxy + file_event) for non-inference Assistants/Threads API access and the loader's host artifacts
- `agentic_orchestration_behavior.yml` — Sigma, five documents: two base rules, two `event_count` correlations over them, and a temporal killchain correlation
- `ai_service_api_c2.rules` — Suricata for Assistants-API C2 paths, beacon cadence, and large POST volume to provider endpoints

## Baseline before you alert

**These thresholds are starting points, not defaults to deploy.** Two of the rules count events per session:

| Rule | Threshold | Window |
|---|---|---|
| Agent Tool Invocation at Machine Tempo | > 60 invocations | 5 minutes |
| Mass Data Collection via Agent Tool Chaining | > 5 collection calls | 1 hour |

The window matters more than the count. Sixty tool invocations in an hour is an ordinary Claude Code session; sixty in five minutes is twelve per minute, which no human drives. Measure your own agent sessions for a week before turning either into an alert, and raise the tempo threshold rather than widening the window — widening it re-admits exactly the legitimate heavy use the short window excludes.

The killchain correlation is the highest-fidelity rule here because it requires phase progression, not volume.

## Log sources required

- Agent trace telemetry with `session_id` and `event_type` — Claude Code session JSONL normalises to this shape
- Proxy or TLS telemetry with URI paths, for the Assistants-API rules
- File creation events, for the loader artifacts
- Network telemetry with SNI; request bodies only where TLS is intercepted

## Tuning notes

The Suricata rules key on provider hostnames, which are dual-use — a developer estate will generate constant traffic to them. Use the SNI rules for hunting and baselining, and alert on the correlations and the host-artifact rules instead.

`sesameop_assistants_api_c2.yml` distinguishes *non-inference* Assistants/Threads API use from ordinary completions traffic. That distinction is the whole rule: an organisation legitimately using the Assistants API will need this scoped to unexpected client processes rather than deployed as-is.
