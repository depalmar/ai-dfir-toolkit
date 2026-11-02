# Changelog

Format based on Keep a Changelog. Entry IDs are permanent and never renumbered.

## [Unreleased] - 2026-11-02

### Added
- **Collection plan exports.** The plan now renders for the collectors people
  already run, from the same per-row spec the native scripts use: a KAPE
  `.tkape` target, a Velociraptor artifact (file globs per OS, registry,
  process and socket sources), a ForensicArtifacts definition file for Plaso,
  GRR and Timesketch, and a `targets.yaml` subset for the repository's Python
  collector. Each one lists the rows it cannot carry and why, instead of
  dropping them.
- **Collection plan builder.** Case id, operator, output directory,
  repository and home paths and a copy-secrets toggle, saved with the plan,
  feeding the generated script's manifest and a ready-to-paste run command for
  every collector. Each plan row now shows what the chosen collector will do
  with it (hashed only, live state, needs a repo path, not on this OS, manual),
  a summary strip counts those states and the plan's confidence mix, and a
  "Before you run it" checklist sits above the builder, which is sticky beside
  the plan on wide screens. Pattern borrowed from edge-dfir-toolkit's command
  builder, where withheld steps grey out as the operator changes options.
- **Data sources.** Sixteen telemetry sources join the nine Windows-host ones:
  EDR telemetry, macOS Endpoint Security and the unified log, Linux auditd and
  Sysmon for Linux, shell history, Windows execution artifacts (Prefetch,
  Amcache, SRUM), network egress logs, container runtime logs, version control
  history, package manager caches, and the provider-side records - Anthropic
  organization audit logs and Compliance API, OpenAI audit logs, AWS CloudTrail
  and Bedrock invocation logging, Google Cloud audit logs, the GitHub audit
  log's Copilot events, Purview Copilot interactions, and identity provider
  sign-in and consent logs. The coverage model gains `os`, `hosts` and
  `locators` dimensions so every one of them is tied to the corpus by
  derivation, the Windows sources are now scoped to Windows rows, and the audit
  checks class coverage per OS. The enable and retention facts behind the new
  sources were checked against the vendor pages from a network that reaches
  them: the Anthropic audit-log window (180 days, Enterprise only), Bedrock
  invocation logging off by default, CloudTrail's 90-day event history, the
  GitHub audit log's 180 days, Google's 400-day `_Required` and 30-day
  `_Default` buckets, Docker's unbounded json-file default, npm's logs-max,
  auditd's num_logs default of zero, PSReadLine's 4096 entries, git's 90- and
  30-day reflog expiry and Entra's 7- and 30-day tiers all read as the entries
  state them. Google Workspace token-event retention was not found and the
  entry says so.
- **Mappings.** Technique coverage gains an Actors column from the intel layer,
  a `gap` flag (used by an actor or incident, on-host, no rule), per-tactic
  grouping, text and state filters, sortable columns, stat tiles, a CSV
  download, and two more indexes: OWASP Agentic (ASI01-ASI10) and the ATT&CK
  Enterprise techniques the rules tag and the cases cite. The detections view
  gains OWASP Agentic and ATT&CK facets.
- **Graph.** Starting presets, incremental placement (expanding a node no
  longer re-lays out the canvas), hover highlighting with relationship labels,
  relationship-grouped expansion from the side panel with a cap per step, undo,
  focus, zoom controls, keyboard shortcuts, re-tick-to-restore type filters,
  copyable canvas links and degree-scaled nodes.

### Fixed
- The Mappings coverage table showed 0 rules for every ATLAS technique. The
  index parser read the count by column position and the ATLAS index had
  gained a Tactic column; it now reads by header.
- Rule ATT&CK tags are normalised to technique ids; tactic tags such as
  `attack.initial_access` no longer appear as techniques.

## [Unreleased] - 2026-09-30

### Added
- **Threat-intel layer.**
  - 20 actor profiles (`artifacts/intel/actors/`, `AIRT-TA-0001` to `-0020`).
  - Case studies `AIRT-CS-0015` to `-0022`:
    - s1ngularity/Nx using the victim's AI CLIs
    - UNC6780 DUSTMAKER and trojanised MCP servers
    - MIDNIGHT NEPTUNE Claude Code hook poisoning
    - five Anthropic September 2026 clusters, carrying 131 indicators from its
      IOC release
  - Closed schemas for case studies and actors, plus a sector and region
    vocabulary.
  - `scripts/intel_graph.py` derives the entity graph, per-actor
    hunt, detect and collect tables, coverage gaps, and analytics: similarity,
    clusters, co-occurrence and a detection backlog.
- **Feeds:** `docs/api/intel.json`, a STIX 2.1 bundle and Maltego import CSVs.
- **Reference data:**
  - ATLAS 2026.09, pinned with tactics, mitigations and case studies.
  - ATT&CK groups and campaigns.
  - The OWASP LLM 2026 and Agentic 2026 lists (`schema/owasp.json`).
  - CISA KEV status for every cited CVE (`schema/cve-status.json`), gated by
    `cve_status.py`.
  - OWASP Agentic (ASI) values on every rule in MAPPINGS.
- **Detections:** `ai_cli_permission_bypass_invocation.yml` and
  `ai_agent_hook_config_modification.yml`.
- **Site:**
  - a Threat intel view with cross-filtering, pivots, timeline, ATLAS matrix
    and heatmaps
  - a graph workbench (Cytoscape.js, vendored and hash-pinned)
  - a per-OS triage script generator on the collection plan
  - a resizable drawer
- **Automation:** `framework-refresh.yml`, a weekly re-pin that auto-merges when
  guarded, and `intel-watch.yml`, weekly `intel-candidate` issues.

### Fixed
- `AML.T0104` and `AML.T0019` were retired upstream in 2026.07 and have been
  remapped. The id gate now covers every surface, not just the catalog.
- The Ray rule claimed CISA KEV listing, and CVE-2023-48022 is not listed.
- MAPPINGS section 04 was dropped by the site parser.
- `atlas.aml-tNNNN` tags were discarded.
- ATT&CK ids were read as ATLAS ids.
- The credential-access rule was mapped to T0082 instead of T0083.

## [2.0.0] - 2026-08-11

### Added
- Wave 2 tools: OpenHands (`AIRT-0043`), Langflow (`AIRT-0044`).
- Kiro (`AIRT-0041`) and Open WebUI (`AIRT-0042`), authored via the catalog skill.
- 12 vendor-neutral **Sigma** detection rules plus a 6-query **osquery** inventory pack.
- CI verifies every Sigma rule compiles against a real backend, so a rule that
  would not convert cannot merge.
- Case study `AIRT-CS-0003`: Langflow CVE-2025-3248, CISA KEV-listed and
  mass-exploited to deploy the Flodrix botnet.
- ForensicArtifacts-format exporter for Plaso / GRR / Timesketch interop.
- `scripts/rebrand.py`, `scripts/normalize.py`, governance docs, issue templates,
  `CITATION.cff`.

### Changed
- **Controlled vocabularies enforced.** `artifact_type` collapsed from 52 ad-hoc
  values to 17 and locked as a schema enum; `secret_type` backfilled and required.
  Near-duplicates (`log`/`logs`, `agent-def`/`agent-definition`) made the published
  CSV feed unfilterable.
- Ollama: models on systemd installs live at `/usr/share/ollama/.ollama/models`
  under the service account, not the invoking user's home. Collecting only
  `~/.ollama` misses everything on a Linux server.
- Detection queries in proprietary query languages removed in favour of Sigma.

### Fixed
- The bootstrap generator no longer runs destructively against a populated
  catalog; the repository is the source of truth.

## [1.0.0] - 2026-08-11

### Added
- Initial catalog of 40 tools with schema, validator, and export feeds.
- Case studies `AIRT-CS-0001` (GPT Pilot supply-chain worm) and `AIRT-CS-0002`
  (postmark-mcp backdoor).
- Authoring skill for Claude.
