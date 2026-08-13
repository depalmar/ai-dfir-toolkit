# AI/ML DFIR Detection Pack

**Open-source detection signatures for AI/ML attacks and breaches.**

A vendor-neutral collection of Sigma, YARA, and Suricata rules for detecting compromise of LLM applications, MCP servers, ML supply chains, AI infrastructure, AI-powered insider threats, and RAG/vector database attacks.

For the companion investigation guide with attack background, forensic artifacts, Mermaid attack-chain diagrams, and hands-on investigation procedures, see [`docs/ai-dfir-investigation-guide.md`](./docs/ai-dfir-investigation-guide.md).

License: Apache 2.0.

---

## Disclaimer

This is an independent personal project. It is not affiliated with, endorsed by, or produced on behalf of any employer. All research is based on public sources — published CVEs, vendor advisories, academic papers, and vendor-neutral security research. Contributions are welcome from the community.

---

## Why this exists

Most existing detection content is either locked behind vendor SIEMs or scattered across blog posts. AI/ML attacks need detection coverage that spans:

- **Endpoint** (Claude Desktop / Cursor / Copilot config tampering)
- **Cloud SaaS logs** (Bedrock, Azure OpenAI, M365 Copilot)
- **Network** (vector DB exfil, model exfil, ShadowRay C2)
- **File artifacts** (poisoned pickle models, malicious MCP configs)

This pack uses **open standards only** so the rules can be deployed in any modern detection stack via open Sigma/YARA/Suricata tooling.

---

## Structure

```
ai-dfir-toolkit/
├── 01-llm-prompt-injection/      # Prompt injection, jailbreaks, indirect injection
├── 02-mcp-attacks/                # MCP tool poisoning, config tampering, rug pulls
├── 03-model-supply-chain/         # Pickle exploits, HuggingFace, dependency confusion
├── 04-ai-infrastructure/          # ShadowRay, Triton, MLflow, GPU abuse
├── 05-copilot-assistant-abuse/    # M365 Copilot, GitHub Copilot, Claude, Cursor
├── 06-rag-vector-db/              # Vector DB exposure, RAG poisoning
├── 07-runtime-ai-malware/         # Malware calling an LLM API at runtime
├── 08-agentic-orchestration/      # Agent-as-operator, AI service API as C2
├── artifacts/                     # Machine-readable AI agent artifact catalog
├── skills/                        # Agent skills for maintaining the catalog
├── tests/                         # Sample events / test files
├── MAPPINGS.md                    # ATLAS + OWASP cross-reference
└── README.md
```

Each category directory contains a `README.md` describing the threats covered and rule files in their native format (`.yml` for Sigma, `.yar` for YARA, `.rules` for Suricata).

---

## Rule formats

| Format | Use Case | Where it Deploys |
|--------|----------|------------------|
| **Sigma** (`.yml`) | Generic log-based detection | Any SIEM via [pySigma](https://github.com/SigmaHQ/pySigma) backends |
| **YARA** (`.yar`) | File / memory artifacts | EDR platforms, malware analysis, file scanning pipelines |
| **Suricata** (`.rules`) | Network traffic | Suricata, Snort (compatible subset), Zeek (via translation) |

**All rules use open formats.** No vendor-specific query languages, no proprietary field schemas. Convert to your platform using pySigma backends.

---

## Quick start

### Elastic / Kibana

```bash
pip install sigma-cli pysigma-backend-elasticsearch
sigma convert -t lucene --without-pipeline ai-dfir-toolkit/**/*.yml > ai-dfir-toolkit.lucene
```

The rules are vendor-neutral Sigma — see the [pySigma backends](https://github.com/SigmaHQ/pySigma) list to convert to any other SIEM query language.

> **Case sensitivity:** the keyword-based rules (prompt injection, jailbreak,
> system-prompt extraction, etc.) follow the Sigma convention that `contains`
> matching is case-insensitive — attacker text varies in case, so the rules are
> written in lowercase and rely on the backend to fold case. On **Elastic**,
> ensure the matched content fields are mapped as analyzed `text` (the default
> for string fields), not `keyword`: a `keyword` mapping matches
> case-sensitively and will miss capitalized input. Do **not** try to force this
> with the `re|i` modifier — Lucene's regex engine does not support the `(?i)`
> flag and the resulting query is invalid.

### YARA scanning

```bash
# Scan a model directory
yara -r ai-dfir-toolkit/03-model-supply-chain/*.yar /path/to/models/

# Scan an MCP config
yara ai-dfir-toolkit/02-mcp-attacks/mcp_tool_poisoning.yar \
  ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

### Suricata

```bash
cp ai-dfir-toolkit/**/*.rules /etc/suricata/rules/
echo 'rule-files: [ai-dfir.rules]' >> /etc/suricata/suricata.yaml
suricata -T -c /etc/suricata/suricata.yaml  # validate
systemctl reload suricata
```

---

## Artifact Catalog

[`artifacts/`](artifacts/) is a machine-readable catalog of the endpoint
artifacts left by AI coding agents, local LLM runtimes, agentic workflow
engines, and Model Context Protocol components — install paths, credential
storage, MCP configs, listening ports, process relationships, and registry keys,
each rated by forensic value and sourcing confidence, with collection priorities
for IR triage.

Ships vendor-neutral Sigma detection rules and an osquery inventory pack, plus
exports in [ForensicArtifacts](https://github.com/ForensicArtifacts/artifacts)
format for Plaso, GRR, and Timesketch.

See [`artifacts/README.md`](artifacts/README.md).

---

## Coverage overview

66 rule files containing 154 individual signatures — eight attack-class categories
plus a cross-tool endpoint set:

| Category | Files | Signatures | ATLAS Techniques | OWASP LLM |
|----------|-------|-----------:|------------------|-----------|
| LLM Prompt Injection | 8 | 10 | T0051, T0054, T0029 | LLM01, LLM07, LLM10 |
| MCP Attacks | 5 | 14 | T0010, T0104, T0110, T0086 | LLM03, LLM06 |
| Model Supply Chain | 8 | 23 | T0010, T0018, T0020 | LLM03, LLM04 |
| AI Infrastructure | 9 | 31 | T0011, T0017, T0019 | LLM10 |
| Copilot/Assistant Abuse | 8 | 19 | T0086, T0024 | LLM02, LLM06 |
| RAG / Vector DB | 5 | 17 | T0020 | LLM08 |
| Runtime AI-Malware | 8 | 16 | T0096, T0086 | LLM01, LLM06 |
| Agentic Orchestration & AI-Service C2 | 3 | 12 | T0096, T0086, T0054 | LLM06 |
| Endpoint (cross-tool) | 12 | 12 | T0053, T0081, T0082 | LLM02, LLM06, LLM03 |
| **Total** | **66** | **154** | | |

The endpoint set lives in [`artifacts/detections/`](artifacts/detections/) and is
scoped to agent behaviour on a host rather than to one attack class, so it applies
across every tool in the artifact catalog. An osquery pack there answers the
inventory question ("which hosts have this") that the Sigma rules cannot.

*Signature count includes multi-document Sigma YAML, multiple `rule` blocks inside a single YARA file, and multiple `alert` lines inside a single Suricata `.rules` file. One file often covers several related variants.*

See [MAPPINGS.md](./MAPPINGS.md) for per-rule mappings.

---

## Tuning notes

These rules are written to err toward signal over noise, but every environment is different. Each rule includes:

- `falsepositives:` section listing known FP scenarios
- `level:` field (`low` / `medium` / `high` / `critical`) — start with `high`+ in production
- Tunable selectors so you can scope to specific orgs/users/namespaces

Recommended rollout:
1. Deploy to a test index/workspace for 7 days
2. Triage hits, tune `selection` and `filter` blocks
3. Promote to production with appropriate severity

---

## Testing

The `tests/` directory contains sample artifacts (malicious and benign) for validating rule correctness. Run:

```bash
cd tests/
./validate.sh
```

Expected result: 7 passes, 0 failures.

---

## Contributing

PRs welcome. Rule submission requirements:

1. Reference an attack technique — ATLAS ID, CVE, or published research
2. Include test data in `tests/` — sample log line, file, or PCAP
3. Document false positives in the rule
4. Use lowercase, snake_case filenames matching the threat
5. Tag with `attack.atlas.txxxx` in Sigma rules

Sigma format: follow the [Sigma specification](https://github.com/SigmaHQ/sigma-specification).

---

## References

- [MITRE ATLAS](https://atlas.mitre.org/)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [Sigma HQ](https://github.com/SigmaHQ/sigma)
- [AI Incident Database](https://incidentdatabase.ai/)

---

## License

Apache License 2.0 — see [LICENSE](./LICENSE).

You are free to use, modify, and redistribute these rules in commercial and non-commercial settings. Attribution appreciated but not required.

Catalog data under `artifacts/catalog/`, `artifacts/case-studies/`, and
`artifacts/docs/api/` is licensed CC BY 4.0; see
[`artifacts/LICENSE-DATA`](./artifacts/LICENSE-DATA). All other content,
including the scripts and schema under `artifacts/`, is under the repository's
Apache-2.0 licence.

---

**Maintainer:** Raymond DePalma — independent security researcher.
This is a personal project and is not affiliated with any employer.
