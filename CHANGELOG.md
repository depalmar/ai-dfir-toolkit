# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Case studies get their own tab, expanded.** They previously rendered as
  three small cards below 45 tool cards at the bottom of the Tools view, where
  nobody would find them. The full view groups indicators by kind — file,
  directory, binary, commit — because a responder hunts one class at a time with
  one tool, and a flat list of mixed strings makes them do the sorting. Response
  actions sit beside the indicators rather than under them, since "what to look
  for" and "what to do" are read separately. Where the catalog knows the affected
  tool, its name is a button through to that tool's rows.

- **CSV and JSON export of the filtered view.** Exports what is on screen —
  filters, search and sort included — because a responder narrowing to one tool
  and OS wants that list, not the whole catalog. Column order matches
  `docs/api/artifacts.csv` so the two read alike, but this is a view export and
  is deliberately not that published feed.

- **`09-agent-memory-forensics/` — 2 rule files / 5 signatures**, plus an
  analytic that parses memory stores and reports poisoning findings. Agent memory
  is a persistence mechanism: an instruction written there survives conversation
  resets, process restarts and the removal of whatever injection put it there, so
  eradication that skips memory leaves the adversary resident. Maps to
  `AML.T0080` AI Agent Context Poisoning and its `.000` Memory sub-technique,
  confirmed against ATLAS (MITRE/Zenity Labs, October 2025).
- **`AIRT-0045` vLLM.** Three vLLM Suricata signatures shipped with no catalog
  entry behind them, so an analyst receiving that alert had no collection block
  and no triage priority. Authored at `high` confidence from the packaged source
  of vllm 0.27.1 — `VLLM_API_KEY` unset by default, `VLLM_CACHE_ROOT`,
  `VLLM_CONFIG_ROOT`, `usage_stats.json`, and the 0.0.0.0 default bind.
- **Fixtures for the three category-07 YARA rules**, with a benign control that
  must stay clean against all of them. They previously shipped compile-verified
  only.
- **`gen_credential_targets.py` now also derives high-forensic-value disk
  artifacts**, not only credential locations, so the hand-authored remainder of
  `targets.yaml` is genuinely collection-specific.

- **127 credential locations across 20 entries** that previously declared
  `plaintext_credentials: true` and listed none. The catalog went from 23
  credential locations to 150. Every row carries a vendor citation and went
  through an adversarial verification pass that dropped 5 and downgraded 14;
  provenance splits 104 `high` / 18 `medium` / 5 `low`, the last marked
  `unverified: true`. The flagship case was `claude-code.yml`: it listed no
  credential location while its own disk row named `.credentials.json`,
  `CLAUDE.md` named that file as holding live tokens, and the repository shipped
  a Sigma rule detecting reads of it. Verification also established that on macOS
  the credential is in the login Keychain rather than that file, so the
  file-access rule cannot fire on a stock macOS host — recorded as an
  `os-keyring` row rather than left implied.
- **`collectors/gen_credential_targets.py`** — the credential half of
  `targets.yaml` is now generated from the catalog rather than hand-copied, with
  a staleness check in CI. Only locations a file collector can actually open are
  emitted; environment variables, CLI flags, keychains, browser stores and
  databases are real evidence acquired by other means and are reported rather
  than faked as paths.

- **`collectors/` — forensically-sound acquisition.** Cross-platform collector
  driven by a declarative `targets.yaml`, plus read-only cloud pulls for Bedrock,
  Azure OpenAI, Vertex and M365 Copilot. Sources are opened read-only and copied
  with mtime preserved; every artifact is SHA-256 hashed into a manifest that
  records operator, host, UTC window, and a self-hash of the collector.
  `VALIDATION.md` records the non-alteration evidence and is explicit that atime
  is outside the tool's control.
- **`collectors/check_target_drift.py`** — `targets.yaml` is a second list of
  artifact paths and the catalog is the first. Until the former is derived from
  the latter, this fails when the catalog documents a plaintext credential that
  no collector target covers, or that a target covers without marking it secret
  (which would copy a live token whole into a case directory). It found 9 real
  gaps on the first run, including `~/.codex/auth.json` and
  `~/.gemini/oauth_creds.json` — both named in this repo's own Sigma and osquery
  content. Credential coverage went from 0 of 23 to complete.
- **`playbooks/` — three CACAO v2.0 response playbooks** (coding-agent session
  forensics, MCP compromise containment, cloud LLM log triage) with a conformance
  validator wired into CI. Each acquires evidence before any containment step.
- **`08-agentic-orchestration/analyze_agent_traces.py`** — behavioural scoring
  over agent traces, the primary detection for a class where every individual
  tool call is legitimate.

- **`08-agentic-orchestration/` — 3 rule files / 12 signatures.** The adversary
  using an agent as the operator (GTG-1002, Anthropic Nov 2025) and AI provider
  APIs abused as covert C2 (SesameOp, Microsoft DART Nov 2025). Different in kind
  from the other categories: every individual tool call is legitimate, and what
  betrays the intrusion is emergent — tempo, phase progression, breadth. Both
  cases are vendor-disclosed with no public IOCs, so the content is behavioural
  and threshold-driven; the README says plainly that the thresholds must be
  baselined before they are alerted on. Maps to `AML.T0096` and `AML.T0086`.

- **`07-runtime-ai-malware/` — 8 rule files / 16 signatures.** Detections for
  malware that calls an LLM API *during execution* to generate or mutate its own
  code ("just-in-time code creation", GTIG November 2025): PROMPTFLUX, PROMPTSTEAL
  / LAMEHUG, FRUITSHELL. The payload is not in the sample, so provider egress and
  the host artifacts of the rewrite loop are the durable detection surface. Maps
  to `AML.T0096` (AI Service API) and `AML.T0086`. YARA string sets are derived
  from public reporting rather than confirmed samples and are labelled MEDIUM —
  validate against real specimens before blocking.
- **First Sigma correlation rule**, and CI support for the class.
  `runtime_ai_malware_correlation.yml` requires LLM egress *and* Startup
  persistence on one host within an hour. Correlation rules reference siblings by
  `name`, so they cannot be converted a file at a time, and the Elastic/lucene
  backend cannot express them at all; `validate.yml` now skips them in the
  per-file pass and validates each containing directory as a collection instead.

- **`MAPPINGS.md` Endpoint (cross-tool) section**: the 12 endpoint Sigma rules
  under `artifacts/detections/sigma/` are now indexed, along with the osquery
  inventory pack. Documented scope moves from 43 rule files / 114
  signatures to **55 rule files / 126 signatures**.
- **`artifacts/scripts/validate_mappings.py`**: fails when `MAPPINGS.md`
  references a rule file that does not exist, or when a rule file on disk is
  never indexed. Wired into CI, so neither kind of drift can recur.
- **`artifacts/scripts/apply_mappings_update.py`**: the idempotent one-shot that
  applied the section-07 insertion and recomputed the index counts.
- **`build_site.py --check`**: validates the site's data contract — anchor
  uniqueness and URL-safety, no empty locators, no orphaned rows, no empty or
  off-enum evidence types — without rendering. Runs on every pull request,
  where previously the site was only built on push to `main`.
- **`artifacts/docs/HANDOFF_REVIEW.md`**: the design-handoff review and its
  resolution, recording which findings were applied, which were declined, and
  why.

### Fixed

- **`AIRT-CS-0001` referenced a dead entry id.** It pointed at `LOLAI-0016`, from
  the naming scheme retired when the catalog was renamed, so the case study could
  not be cross-linked to the tool it describes. Both ids are GPT Pilot; corrected
  to `AIRT-0016` and logged in `VERIFICATION.md`.
- **The site discarded indicator types.** `site_data.py` kept only an indicator's
  value and description and dropped its `type`, so the page could not tell a
  malicious commit hash from a file path from a binary name.

- **The site under-reported detections by 13 and hid three whole categories.**
  `site_data.py` discovered rule directories from a hardcoded list of six, so
  every category added after that list was written — 07 runtime AI-malware, 08
  agentic orchestration, 09 agent memory — was absent from the Detections view
  and from the header stat, which read 55 against 68 on disk. Nothing failed,
  because a shorter list looks exactly like a complete one, and the page was the
  only artifact disagreeing: README, MAPPINGS, CLAUDE.md and the guide all
  counted 68. Directories are now discovered by pattern, labels fall back to a
  derived name so a new category cannot be invisible for want of a dict entry,
  and `build_site.py --check` fails when any rule file on disk was not loaded.

- **The OS facet hid 87 of 425 catalog rows.** The schema declares `os` on disk,
  process and credential rows only, so registry, network and MCP rows carried
  none — and a row with no OS matched no OS filter. Selecting `windows` silently
  dropped every registry key, every listening port and every MCP config. Rows now
  inherit the entry's `supported_os`, which is stricter than making blank rows
  match everything: a cloud-only tool must not appear under `windows`. `windows`
  goes from 163 reachable rows to 339, and `--check` now fails on any row with no
  OS.
- **The CrewAI scaffold path was wrong.** The entry documented
  `<project>/config/agents.yaml`; the packaged first-party metadata puts it at
  `src/<project>/config/`. The entry already contradicted itself twelve lines
  down. Corrected and raised to `high`, with the basis in `VERIFICATION.md`.
- **`tests/validate.sh` scored absent tooling as passes.** `assert_clean` treated
  empty stdout as a pass, so a missing `yara` binary or a rule that failed to
  compile looked identical to a clean scan. It now preflights for the binary and
  exits 2 if it is absent, and checks yara's exit status before its output —
  keeping stderr separate, since non-fatal warnings must not fail a scan that was
  genuinely clean.

- **ATLAS and OWASP index counts in `MAPPINGS.md`.** Hand-maintained counts
  disagreed with the tables they summarise (ATLAS `T0010`, `T0020`, `T0024`;
  OWASP `LLM01`, `LLM03`, `LLM06`, `LLM07`, `LLM10`), and four techniques were
  missing rows entirely (`T0051`, `T0053`, `T0081`, `T0082`). Counting also has
  to resolve columns from each table's own header rather than by position: the
  layout varies (section 04 has no OWASP column) and the CVE / Reference column
  carries citations like `OWASP LLM10:2025` that reference a category rather
  than map to it, which inflated `LLM01`, `LLM07` and `LLM10` by one apiece.
- **`validate_mappings.py` now gates the counts**, not just file existence. It
  recounts both index tables and the Scope line from the rule rows and fails on
  any disagreement, so a hand-edited summary cannot drift from its tables again.
- **Empty "what it proves" on 107 of 298 catalog rows (36%).** The schema
  declares `evidence_type` only on disk artifacts, so every registry, network
  and process row rendered the section blank. These are now derived from
  existing fields, within the schema's `evidence_type` enum.
- **Rule permalinks** use the repo-relative path instead of a bare filename, so
  two directories holding the same filename cannot collide. Previously-shared
  bare-filename links still resolve. `#guide` now deep-links, which it silently
  did not.

### Changed

- **The header stat row is gone.** Everything it carried is still reachable and
  in a better place: tools, catalog rows, detections and mappings are counts on
  the tabs, and the credential / MCP split is a facet count in the rail. The one
  figure with nowhere else to live — `unverified` — moved onto the "Unverified
  only" toggle, which is where a reader looks for it anyway, keeping its warning
  colour. Six numbers became one that is attached to the control it describes.

- **The Artifacts tab is now the Catalog tab.** It holds artifacts, credentials
  and MCP configs, so labelling it "Artifacts" put two different numbers under
  one word: the tab counted 434 rows while the header stat counted 265. Both were
  right and the pair looked broken. Renamed, the header now reads as a
  decomposition of it — 265 artifacts + 152 credentials + 17 MCP configs = 434.
- **The investigation guide is a pill rather than a quiet link.** Next to five
  tabs it read as a sixth tab that happened to be greyer, when it is the only
  long-form document on the site. It stays a real tab, so arrow-key navigation
  and `aria-selected` still work.

- **`AML.T0104` and `AML.T0110` are now distinguished** in the MCP category. A
  third-party pack proposed replacing `T0110` with `T0104` throughout, on the
  premise that `T0104` supersedes it. Verified against ATLAS: both are current
  and distinct — `T0104` Publish Poisoned AI Agent Tool is Resource Development
  (the adversary publishes it), `T0110` AI Agent Tool Poisoning covers modifying
  tools so future invocations execute attacker behaviour. A blanket replace would
  have mis-tagged the rug-pull rule, so the mapping was split by tactic instead.
  `mcp_tool_poisoning.yar` carries both, because it matches a poisoned
  description wherever it lands and cannot tell the two apart. Basis recorded in
  `artifacts/docs/VERIFICATION.md`.
- The cross-tool Endpoint section in `MAPPINGS.md` is no longer numbered. It was
  bumped once per new category (07 → 08) because it competed for numbers with the
  rule directories while not being one; unnumbering it ends that permanently and
  lets numbered sections mirror numbered directories.
- The Investigation guide header entry is a real tab rather than a link inside
  `role="tablist"`, which had broken arrow-key navigation. The tablist now has
  roving tabindex, arrow/Home/End keys, and `aria-controls` onto a
  `role="tabpanel"` container.
- `localStorage` keys renamed from the dropped `aiart-` working name to
  `aidfir-theme` / `aidfir-picks`, each reading the old key once so returning
  visitors keep their theme and saved picks.

## [1.0.0] - 2026-04-19

### Added

Initial public release. **43 rule files containing 114 detection signatures** across 6 threat categories (one file often bundles multiple related variants as multi-document Sigma, multiple `rule` blocks in one YARA file, or multiple `alert` lines in one Suricata `.rules` file):

- **01 - LLM Prompt Injection** (8 files / 10 signatures): prompt injection keywords, jailbreak personas, system prompt extraction, markdown image exfil, adversarial suffix YARA, Bedrock token DoS + injection, Azure OpenAI injection (Sigma), base64 response exfil
- **02 - MCP Attacks** (5 files / 14 signatures): tool poisoning YARA, config tampering, credential access, outbound unknown domain Suricata, Claude Desktop config modify
- **03 - Model Supply Chain** (8 files / 23 signatures): pickle malicious opcodes YARA, Keras lambda RCE YARA, HuggingFace token exposure, MLflow path traversal Suricata, MLflow unauth API, pip typosquat, HF cache unexpected writer, model file hash mismatch (Sigma)
- **04 - AI Infrastructure** (9 files / 31 signatures): Ray Jobs API RCE, Ray dashboard exposure, ShadowRay process masquerading, GPU unexpected utilization, SSH key injection, Triton inference server exploit, TorchServe ShellTorch, NVIDIA container escape, Ollama/vLLM unauth exposure
- **05 - Copilot / Assistant Abuse** (8 files / 19 signatures): M365 Copilot sensitivity label access (Sigma), M365 Copilot anomalous aggregation (Sigma), GitHub Copilot YOLO mode, Copilot rules file backdoor YARA, Cursor settings DB modification, Claude session JSONL unexpected access, ChatGPT paste sensitive data, AI assistant outbound to Camo proxy Suricata
- **06 - RAG / Vector DB** (5 files / 17 signatures): vector DB unauth exposure Suricata, vector DB bulk exfil, RAG document hidden text YARA, ChromaDB SQLite unexpected writer, vector DB query anomaly

### Coverage

- MITRE ATLAS v5.4.0 (February 2026): 15 unique techniques covered
- OWASP Top 10 for LLM Applications 2025: 8 of 10 categories covered (LLM01, LLM02, LLM03, LLM06, LLM07, LLM08, LLM10)
- 30+ CVEs referenced, including ShadowRay (CVE-2023-48022), EchoLeak (CVE-2025-32711), CamoLeak (CVE-2025-59145), vLLM Mooncake (CVE-2025-32444), NVIDIA Container Toolkit chain (CVE-2024-0132, CVE-2025-23266, CVE-2025-23359), Triton chain (CVE-2025-23319/23320/23334)

### Test Suite

- 7 smoke tests covering YARA rules (pickle, MCP config, RAG hidden text, Copilot rules file)
- Test artifacts for every rule format
- Sample logs for Sigma rules (Azure OpenAI, Bedrock, M365 Copilot, network captures)
- `tests/validate.sh` for one-command test execution

### Documentation

- `README.md` — project overview, quickstart for each SIEM backend
- `MAPPINGS.md` — per-rule ATLAS + OWASP + CVE cross-reference
- Category-level `README.md` in each numbered directory
- `CONTRIBUTING.md` — rule submission requirements
- `tests/README.md` — test suite documentation
- `docs/ai-dfir-investigation-guide.md` — companion investigation guide with Mermaid attack-chain diagrams (triage flow, MCP trust boundary, ShadowRay kill chain, RAG poisoning lifecycle, IR response lifecycle)
