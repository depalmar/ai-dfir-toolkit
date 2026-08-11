# Changelog

Format based on Keep a Changelog. Entry IDs are permanent and never renumbered.

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
