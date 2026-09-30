# Changelog

Format based on Keep a Changelog. Entry IDs are permanent and never renumbered.

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
