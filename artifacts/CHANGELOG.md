# Changelog

Format based on Keep a Changelog. Entry IDs are permanent and never renumbered.

## [Unreleased] - 2026-11-02

### Added
- **Start from the alert.** The landing panel asks which tool the alert
  named, where the AI ran and what role it played, and answers with that
  tool's rows grouped live, rotating and stable, its sourcing mix, unverified
  count and last-verified date, and the same Add volatile, Add all and Show
  all actions as the tool drawer - without leaving the landing view. The
  attacker's-infrastructure branch shows the guide's tempo signs instead of
  rows, the accounts-and-keys branch points to Data sources, and Bystander
  says this is not the guide's case. The tool box follows the ARIA combobox
  pattern, both questions are radio groups, and nothing is saved. On one
  column the result follows the questions directly. From the Claude Design
  assessment (F03).
- **Guide 1.2, from Joshua Wright's "Scoping AI Swarms".** Part I says to act
  without proving AI: rotate exposed credentials, invalidate derived sessions,
  check other uses of the access and look for running execution, whoever the
  operator is. A new subsection groups swarm characteristics into scale and
  tempo, tradecraft and autonomy artifacts, says none of them is an
  attribution test, and gives the four scoping lessons. Section 8 runs the
  lifecycle as a loop rather than a line, after the DAIR model, and further
  reading links the workshop and the book.
- **AI gateway logs data source.** The gateway in front of a model API is
  often the only record of the turn sequence when provider prompt logging is
  off: how clients are pointed at one, what API Management records by
  default and with LLM message logging on, and its retention. Tied to the
  catalog through the Anthropic, OpenAI and Gemini API hosts the network
  rows name.
- **Guide 1.1, from the SANS DFIR Summit 2026 keynote.** "The AI System Was
  the Victim" is folded into the investigation guide and linked under further
  reading. Part II gains the keynote's reconstruction (EchoLeak and MCPoison
  chained at an invented company): four logs, three stages, four owners, with
  the tell of a tool call that has no user turn before it, and a section on
  reading an MCP config as hearsay and the invocation trace as the evidence.
  Part I gains the acquisition order by what you lose first, matching the
  catalog's live, rotating and stable tiers, and what each party can collect
  for attribution. Section 8 gains agent memory as a persistence mechanism
  with its own purge and prove-the-purge steps, and how Article 73 collides
  with containment. A nine-term glossary closes Part V.
- **Investigation guide is the landing page.** The site now opens on the guide,
  with a three-step orientation (decide, locate, collect) that says what the
  site is for before the reader meets a 622-row table. The guide gains a
  characterize-first section: is an AI system present, was it active in the
  incident window, and was it the target, the way in, the attacker's tool or a
  bystander. It states plainly that the guide does not assume every incident
  is AI-driven. A timeline of every documented case study, as a table and a
  cumulative line chart by disclosure quarter, is generated from the case
  studies at build time so it cannot drift from them. Feedback from Joshua
  Wright.
- **Search everything.** Press `/` or Ctrl/Cmd-K, or use the header button,
  to search tools, catalog rows, detections, case studies, actors, data
  sources and guide sections at once. Results are grouped by kind, five per
  group, with keyboard navigation and a jump to the full filtered catalog or
  detection list; the empty state suggests queries. Modelled on
  edge-dfir-toolkit's palette. Artifact matches use the catalog's own fields so
  the two counts agree.
- **Where did the AI run?** A guide section and catalog framing for the case
  the catalog cannot see: an attacker's AI on the attacker's own
  infrastructure. The guide splits incidents by where the AI ran (on your
  hosts, attacker code calling a model API from your hosts, your keys used
  elsewhere, or entirely on the attacker's side) with what each leaves and
  where to look, and lists the tempo and pattern signs that the operator is
  an agent. The catalog opens with a scope note and a three-step how-to-use,
  and every row's drawer says where you would see it, derived from its class:
  a network row is only in your logs when the tool ran on your network.
  Feedback from Joshua Wright.
- **Landing graphic.** Beside the orientation, a chart of where the evidence
  lives: the catalog's locations by type, each bar opening the catalog
  filtered to it, and a sparkline of documented incidents that links to the
  timeline. Both are computed from the data at build time.
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

### Changed
- **Cloud logging defaults in the guide.** The provider table now separates
  what is on by default from where prompt and completion text lives and how
  long it is kept. Azure OpenAI diagnostic logs carry metadata, not the
  text, which needs API Management's LLM message logging or a gateway.
  Vertex AI is listed under its April 2026 name, Gemini Enterprise Agent
  Platform, and Microsoft 365 Copilot is added. Article 73 deadlines now
  include the 10-day window where someone died, and the Digital Omnibus on
  AI (Regulation (EU) 2026/1744) deferral is recorded with its status date.
- Langflow (AIRT-0044) cites the five Langflow flaws CISA added to its Known
  Exploited Vulnerabilities catalog during 2026 - CVE-2026-33017,
  CVE-2025-34291, CVE-2026-55255, CVE-2026-0770 and CVE-2026-9198 - and notes
  that CISA now flags CVE-2025-3248 for known ransomware use. The Langflow case
  study points to them. The KEV pin moves to catalog 2026.11.09, read through
  a lookup of CISA's live feed because the runner cannot fetch it directly.
- Gemini CLI (AIRT-0037) is marked `legacy`: on 18 June 2026 Google stopped
  serving it to free, Pro and Ultra users in favour of Antigravity CLI.
  Enterprise and paid API-key use continue.
- Framework pins moved to ATLAS 2026.10 and ATT&CK 20.0. ATLAS dropped the
  three AML.T0024 subtechniques, AML.T0056 and AML.T0057, none of which the
  repository cited, and renamed AML.T0010 from AI Supply Chain Compromise to
  Supply Chain Compromise. MAPPINGS index titles follow.

### Fixed
- **Site UX batch 5, trust signals, semantics, dark mode and URL state.**
  No text uses the faint grey any more (facet counts 2.67:1 → 5.36:1, drawer
  headings 2.77:1 → 5.55:1), and medium and low sourcing badges use the same
  strong ink as high, told apart by fill and a dashed border. The scale is
  "Sourcing confidence" everywhere, a collapsed case card shows the first
  sentence of its basis, the lesson follows the sourcing, and each case has a
  copy-link button. Technique chips are buttons reading "ID · name" and offer
  "Filter detections" or "Open in Mappings"; rule drawers show OWASP Agentic
  and ATT&CK alongside ATLAS and OWASP LLM. Dark mode follows the system on
  first visit, the armed "Clear all" is legible (2.37:1 → 7.87:1), diagrams
  sit on a dimmed card and the palette scrim is darker. Rule and tool cards are
  articles with a heading button, a one-value facet is hidden, rule status is a
  neutral pill, and the Tools view has a search box. The drawer is modal on
  phones and the palette traps focus. Diagrams enlarge into a viewport-sized
  overlay instead of growing in place. Tab counts name their unit. The view
  and its filters live in the URL (`#catalog?tool=Cursor&os=windows`), a tab
  change is a history entry, and the meta row has "Copy link to this view".
  The site is titled "AI DFIR Toolkit". From the Claude Design assessment;
  `docs/HANDOFF_REVIEW.md` records the outcome and where the assessment was
  wrong.
- **Site UX batch 4, plan export and phone navigation.** The collection
  plan's header carries the export: an "Export for" picker over the five
  collectors and one Download button whose label follows the choice, with
  Copy, the collector's note, the per-tool definitions line and the rows the
  format cannot carry directly under it. "Copy as triage list" and "Copy
  permalinks" are secondary, and the by tool / by volatility switch moves to
  the summary strip. The side panel keeps the options, command and preview,
  and its sticky offset follows the measured header. Every segmented switch
  reports aria-pressed. On phones the header stays sticky, collapsed to the
  title row and the tab strip, the selected tab is scrolled into the strip,
  and edges fade where tabs are cut off. From the Claude Design assessment
  (F10, F11).
- **Site UX batch 2, the catalog working surface.** Rows are grouped by
  volatility - live, rotating, stable - with the column sort applying inside
  each group, because 519 of 622 rows are p1 and the old triage sort could not
  answer "what first". A row whose OS is inherited from its tool says
  "tool:" in the OS column and the drawer, so a Windows filter returning a
  ~/Library path explains itself; the filter itself is unchanged. "Copy path"
  copies the path alone, on hover in the table, on every phone card and as the
  drawer's primary action; the key, value or port sits on its own line with
  its own copy. Filters start with Tool, which has a type-ahead box, class
  options show a plain name beside the token, and zero-match options are
  disabled. The off-host note collapses to one line instead of disappearing.
  The header compacts on scroll and the rail and table size from the measured
  header. The view search and the palette share one matcher (every word, any
  order, hyphen and underscore equal to space), and empty states name what is
  active with separate Clear search and Clear filters. The drawer leads with
  the path and collection order, groups tool material under "Sources for
  <tool>" and a collapsed "About", and keeps "Add to collection plan" pinned
  at the bottom. The table body is one tab stop: arrows move the current row,
  Space ticks, Enter opens, Escape returns to the row. Only the layout in use
  is rendered. The scale is labelled "Sourcing" in the table and filters.
- **Site UX batch 1, from a Claude Design assessment.** The page no longer
  goes blank when the browser blocks site storage: two reads of saved plans
  were outside the guard every other storage call had, and #main now carries
  a loading line until the first render. Ticking a row or opening one keeps
  the table's scroll position and focus instead of rebuilding the view. Plan
  rows with a collector note wrap on phones rather than collapsing the path to
  one character per line. The pick toast is a polite status region with real
  buttons, copy results are announced, and a failed fallback copy says so.
  Controls are at least 24px, and 44px on phones for picks, removes, tabs and
  facets. Pick buttons name their row, chip glyphs are hidden from screen
  readers, the graph zoom buttons are labelled and no longer inside an
  aria-hidden group, and reset is a button. A permalink that no longer
  resolves shows a notice, with a link to the tool's rows when it names a
  known entry. Filtered exports carry the tool or "filtered" in the file name.
- Only rows and headers that do something show the pointer cursor. Every table
  row did, including the guide's tables and the incident timeline, which
  promised a click that went nowhere. The hover highlight stays everywhere.
- Anchor jumps in the guide no longer land under the sticky header. The offset
  is measured from the header rather than hard-coded, because the header wraps
  to a different height per viewport.
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
