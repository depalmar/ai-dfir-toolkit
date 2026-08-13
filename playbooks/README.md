# playbooks/ — Machine-Readable AI-DFIR Response (CACAO v2.0)

Executable response playbooks in **OASIS CACAO Security Playbooks v2.0** format, the machine-readable
playbook standard the **CoSAI AI Incident Response Framework v1.0** references for automated response.
These convert the prose procedures in `docs/ai-dfir-investigation-guide.md` into structured workflows a
SOAR platform can ingest, and they wire directly into this repo's collectors and analytics.

## Playbooks

| File | Type | Covers |
|---|---|---|
| `pb-coding-agent-session-forensics.json` | investigation | Compromised/abused coding agent (Claude Code, Cursor, Copilot, Windsurf): freeze → read-only acquire → score for AI-orchestrated intrusion → escalate or baseline |
| `pb-mcp-compromise-containment.json` | mitigation | Poisoned / rug-pulled / RCE-vulnerable MCP server: preserve → scope blast radius → parallel (remove config, rotate credentials, block egress) → verify |
| `pb-cloud-llm-log-triage.json` | investigation | Managed LLM service (Bedrock / Azure OpenAI / Vertex): acquire logging config + audit trail → branch on whether invocation logging existed → hunt indicators or declare the evidence gap |

## Design choices worth knowing

**Evidence before remediation, always.** Every playbook acquires read-only with chain of custody *before*
any containment action. Containment destroys the record of what the attacker did, and **EU AI Act Article 73**
(applicable 2 Aug 2026) forbids altering the AI system before notifying competent authorities where the
incident is reportable. The MCP containment playbook preserves configs first precisely because a rug-pull
attack means the *current* config is not what executed — only the session traces are authoritative.

**The absent-evidence branch is deliberate.** `pb-cloud-llm-log-triage` branches on whether model-invocation
logging was enabled at all. It is off by default on the major providers and must be enabled *before* an
incident. When it wasn't, the playbook records an explicit **evidence gap** rather than letting "no indicators
found" be misread as "no compromise." That distinction is the difference between an honest report and a wrong one.

**Parallel containment.** MCP containment runs removal, credential rotation, and egress blocking as a CACAO
`parallel` step — a live poisoned server keeps acting while any one of them is pending.

**Variables are `__name__:value`.** CACAO v2.0 changed variable syntax from v1.x `$$var$$` to double
underscores, to work with STIX patterning grammar. Externally-supplied variables are marked `external: true`;
set `__case_id__`, `__suspect_host__`, `__project_dir__`, `__mcp_server_name__`, `__mcp_egress_host__`, and the
time window before execution.

## Validation

`validate_cacao.py` lints against the normative MUST/SHOULD rules of the CACAO v2.0 Committee Specification 01.

```bash
python3 validate_cacao.py .            # validate every playbook here
python3 validate_cacao.py --quiet .    # CI mode: exit 1 on any error
```

It enforces, among others: required playbook properties; `spec_version == cacao-2.0`; identifier format and
workflow-key/step-type agreement; timestamps with **exactly** three decimal places and `modified >= created`;
presence of start/action/end steps; `workflow_start` resolving to a real start step; the `on_completion` vs
`on_success`/`on_failure` exclusivity rule; start/end step branching restrictions; resolution of every step,
agent, target and marking reference; action steps having commands and an agent; `parallel` needing ≥2
`next_steps`; sigma/yara/kestrel/elastic commands requiring `command_b64`; and the activity rules from §3.1.2
(e.g. an `investigation` playbook **MUST** declare `identify-indicators`, a `mitigation` playbook
**MUST** declare `eliminate-risk`, and every declared activity **MUST** appear on some command).

**Current status: 3/3 PASS.** The validator was itself negative-tested against 14 deliberately mutated
playbooks (wrong spec_version, missing `workflow_start`, sub-millisecond timestamps, `modified` before
`created`, dangling step references, end step with `on_completion`, `on_completion` combined with
`on_success`, action without agent, unresolved agent reference, investigation missing
`identify-indicators`, activity absent from all commands, sigma command without `command_b64`, severity out
of range, step key/type mismatch) — **14/14 detected**. A validator that has never rejected anything proves
nothing, so the negative suite is the evidence that these PASS results mean something.

## Limitations

1. **This is a lint, not full JSON-Schema validation.** It covers the statically checkable normative rules,
   not the complete CACAO schema. Run the official OASIS schemas before publishing externally.
2. **Commands are environment-specific.** The `http-api` perimeter-block command and the cloud collector
   invocations are templates — repoint them at your firewall/SWG API and your evidence paths.
3. **Not signed.** CACAO supports JSON-signature (JCS/RFC8785) signing; these playbooks ship unsigned. Sign
   them if you distribute them across a trust boundary.
4. **`identity--9f3d2b17-…` is a placeholder** creator identity. Replace `created_by` with your organization's
   STIX 2.1 Identity object before operational use, and mint a new playbook `id` if you materially modify a
   playbook (per CACAO versioning rules, only the original creator may version an existing `id`).
