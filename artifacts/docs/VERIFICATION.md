# Verification Log

Every correction applied during the August 2026 verification pass, with the basis for the change.
This file exists so a reader can audit why a field says what it says.

| Scope | Field | Was | Now | Basis |
|---|---|---|---|---|
| `LOLAI-0007` | confidence | Low | **Medium** | CONFIRMED Devin has real endpoint footprint: VS Code extension (CognitionAI/devin-extension) using Remote SSH, a local Devin CLI, and required egress to *.devinapps.com. Architecture/domains HIGH; CLI path-level artifacts remain LOW. |
| `LOLAI-0007` | risk | Low | **Medium** | Local CLI agent + Remote SSH into a Cognition-controlled devbox is a real endpoint and egress surface, not browser-only. |
| `LOLAI-0010` | status | active | **legacy** | CONFIRMED Supermaven acquired by Anysphere (Cursor) 2024-11-12. Plugins stated as maintained but team focus moved to Cursor. Path-level detail stays LOW. |
| `LOLAI-0016` | status | active | **unmaintained** | CONFIRMED repo states 'This repo is not being maintained anymore'; team pivoted to the Pythagora VS Code extension (v1, Oct 2024). |
| `LOLAI-0016` | artifact_path | ~/.gpt-pilot/ | **<repo>/data/database/pythagora.db** | CORRECTED. Current version uses repo-relative data/database/pythagora.db per example-config.json. Treat ~/.gpt-pilot as an older/third-party convention. |
| `LOLAI-0013` | status | active | **dormant** | CONFIRMED development effectively stopped after v1.0.0 (Nov 2023); Reworkd pivoted to web scraping. Repo not archived but unmaintained. |
| `LOLAI-0013` | artifact_path | <install>/.env | **next/.env** | CORRECTED. docker-compose mounts ./next/.env as the canonical env file. Ports 3000 (Next.js) / 8000 (FastAPI); MySQL 8.0 container agentgpt_db. |
| `LOLAI-0017` | attribution | SentinelLABS + Censys | **Pillar Security** | CORRECTED. The 175,000-exposed-host figure is from Pillar Security's Jan 2026 'Operation Bizarre Bazaar' report. Cisco Talos (Sept 2025, Shodan) found only 1,139 — cite the source and note order-of-magnitude methodology variance. |
| `LOLAI-0008` | confidence | High | **Low** | DOWNGRADED. Could not independently confirm the binary name aws-lsp-codewhisperer-token-binary.js or npm package @aws/lsp-codewhisperer. Plausible but unverified — verify against the aws/language-servers repo. |
| `LOLAI-0008` | lifecycle | EOL 2027-04-30 | **EOL 2027-04-30; new signups blocked 2026-05-15** | CONFIRMED and expanded. IDE plugins + paid subs end-of-support 2027-04-30; new signups blocked 2026-05-15; capabilities migrate to Kiro. Console-embedded Q is unaffected. |
| `LOLAI-0031` | env_var | PLAYWRIGHT_MCP_HOST | **PLAYWRIGHT_MCP_HOST (UNVERIFIED)** | The --host flag is CONFIRMED and other options use the PLAYWRIGHT_MCP_* prefix, but PLAYWRIGHT_MCP_HOST was not seen named explicitly. Keep UNVERIFIED. |
| `LOLAI-0031` | profile_path | ms-playwright/ | **ms-playwright/mcp-{channel}-{workspace-hash}** | CORRECTED/REFINED. Persistent profile dirs are mcp-{channel}-{workspace-hash} (older docs show mcp-{channel}-profile). |
| `LOLAI-0011` | guidance | hardcode Claude_pzs8sxrjxfjjc | **derive at runtime** | CONFIRMED path, but recommend deriving the package family name via (Get-AppxPackage -Name *Claude*).PackageFamilyName since the publisher hash can change on republish. |
| `ATLAS` | version | v5.1.0 | **v5.4.0 (Feb 2026)** | CORRECTED. atlas-data release notes: v5.1.0 (Nov 2025) added the 16th tactic Command and Control (AML.TA0015); current release v5.4.0 (Feb 2026). Counts: 16 tactics / 84 techniques / 56 sub-techniques / 32 mitigations / 42 case studies. |
| `AIRT-CS-0001` | affects | LOLAI-0016 | **AIRT-0016** | CORRECTED. The case study still referenced the pre-rename LOLAI scheme retired in the `SCOPE` row below, so it pointed at an entry id that no longer exists and could not be cross-linked to the tool it describes. LOLAI-0016 and AIRT-0016 are both GPT Pilot. |
| `AIRT-0028` | artifact_path | &lt;project&gt;/config/agents.yaml | **&lt;project&gt;/src/&lt;name&gt;/config/agents.yaml** | CORRECTED and raised to high. Verified against the packaged first-party metadata in crewai-1.15.15-py3-none-any.whl, whose scaffold tree is `src/` → `crew.py` and `config/` → `agents.yaml`/`tasks.yaml`, with the prose 'Modify `src/my_project/config/agents.yaml` to define your agents.' The entry already contradicted itself: the crew.py row two entries below correctly used &lt;project&gt;/src/&lt;name&gt;/crew.py. Collecting the documented path would have found nothing. |
| `AML.T0104` / `AML.T0110` | mapping | T0110 for both tool poisoning and rug pull | **T0104 for published-poisoned, T0110 for post-install mutation** | CORRECTED. A third-party pack recommended replacing T0110 with T0104 throughout, on the premise that T0104 supersedes it. It does not: both are current, distinct techniques. `AML.T0104` Publish Poisoned AI Agent Tool sits under Resource Development (adversary publishes the tool); `AML.T0110` AI Agent Tool Poisoning covers modifying tools so future invocations execute attacker behaviour. A blanket replace would have mis-tagged the rug-pull rule. `mcp_tool_poisoning.yar` carries both, because it matches a poisoned description wherever it lands and cannot distinguish the two. Related: `AML.T0011.002` Poisoned AI Agent Tool (User Execution). |
| `AML.T0053` | name | AI Agent Tool Invocation | **AI Agent Tool Invocation** | CONFIRMED. Current official name is 'AI Agent Tool Invocation' (tactics: Execution, Privilege Escalation). Prior label was 'LLM Plugin Compromise'. |
| `LOLAI-0039` | port | 26040 | **26040 (UNVERIFIED)** | Cline standalone/CLI gRPC port 26040 with data in ~/.cline/data/ is single-source. Corroborate before deploying detections. |
| `SCOPE` | name | LOLAI | **the artifact catalog** | CORRECTED. lolai-project.github.io already exists (Jekyll, 11 agents, 3 categories, 19 MITRE techniques). Renamed and re-scoped to avoid collision and to claim the artifact/collection niche rather than the abuse-technique niche. |


## Verification Pass 2 — August 2026

| Scope | Field | Was | Now | Basis |
|---|---|---|---|---|
| `AIRT-0017` | artifact_path | ~/.ollama/models (service acct unconfirmed) | **/usr/share/ollama/.ollama/models** | CONFIRMED from the official Linux install docs: 'useradd -r -s /bin/false -m -d /usr/share/ollama ollama'. The service runs as its own user, so models live under that home - NOT the invoking user's. Collecting only ~/.ollama misses everything on a systemd install. |
| `AIRT-0017` | confidence | medium | **high** | CONFIRMED no built-in authentication ('Since Ollama itself doesn't provide authentication...'), default bind 127.0.0.1, port 11434, systemd unit at /etc/systemd/system/ollama.service. Logs via journalctl -u ollama. |
| `AIRT-0017` | artifact_added | - | **journalctl -u ollama** | CONFIRMED as the log source on systemd installs. Ollama has no separate log file there, so journald is the only timeline source. |
| `AIRT-0025` | confidence | medium | **high** | CONFIRMED port 5678 and Docker volume /home/node/.n8n from n8n's own docs ('-p 5678:5678 -v n8n_data:/home/node/.n8n'). |
| `AIRT-0011` | confidence | high | **high** | RE-CONFIRMED. MSIX package family name Claude_pzs8sxrjxfjjc and the LocalCache\Roaming virtualized path both hold; recommendation to derive at runtime stands. |
| `AIRT-0041` | entry_added | - | **Kiro** | NEW. Authored via the skill workflow. Hooks fire the agent on file events with no user action; MCP + hooks are project-scoped under .kiro/; config hot-reloads via file watcher. |
| `AIRT-0042` | entry_added | - | **Open WebUI** | NEW. First registered account is automatically admin - an instance reachable before its owner registers can be claimed by any visitor. |
| `AIRT-0043` | entry_added | - | **OpenHands** | NEW. Documented deployment mounts /var/run/docker.sock into the container, which is host-root-equivalent. |
| `AIRT-0044` | entry_added | - | **Langflow** | NEW. CVE-2025-3248 is on the CISA KEV catalog with confirmed in-the-wild exploitation delivering the Flodrix botnet - the strongest documented mass-exploitation case in this catalog. |
| `VOCAB` | artifact_type | 52 ad-hoc values | **17 controlled values** | Surfaced by the live authoring test. Near-duplicates (log/logs, agent-def/agent-definition, env-var/env-file/env-override) made the published CSV feed unfilterable. Collapsed and locked as a schema enum; negative-tested. |
| `VOCAB` | secret_type | 17 null values | **backfilled + required** | Every credential entry now carries a typed secret_type from a closed enum, so credential-access hunting can filter by secret class. |
| `SCOPE` | detections | none | **vendor-neutral Sigma + osquery** | Detection content added as Sigma (the vendor-neutral detection standard, convertible to any SIEM via sigma-cli) plus an osquery pack for inventory. No product-specific query language ships in the repo. |


## Verification Pass 3 — Case study research, August 2026

Eleven cases were carried over from an external handoff and researched against
primary sources before being authored into `artifacts/case-studies/`. Every case
now records `confidence`, `basis` and `references`, and `build_site.py --check`
fails without them. The corrections below are places where the handoff and the
primary source disagreed.

| Scope | Field | Was | Now | Basis |
|---|---|---|---|---|
| `AIRT-CS-0006` | maturity | presented as an operational metamorphic threat | **assessed by GTIG as in development or testing** | CORRECTED. GTIG states PROMPTFLUX was not capable of compromising a victim environment, and the sample's own `AttemptToUpdateSelf` routine was commented out. The handoff's framing would have had a responder scope for in-the-wild impact that the discloser does not claim. Confidence recorded as medium for the same reason. |
| `AIRT-CS-0009` | attribution | MCPoison credited to 'JFrog · Oligo · others' | **Check Point (CVE-2025-54136, CVSS 7.2, fixed in Cursor 1.3)** | CORRECTED. JFrog disclosed CVE-2025-6514 (mcp-remote) and Oligo CVE-2025-49596 (MCP Inspector); MCPoison is Check Point's and affects Cursor specifically. |
| `AIRT-CS-0009` | scale | '50+ tracked issues, 13 rated critical' | **omitted** | DROPPED. The aggregate comes from the Vulnerable MCP Project, which could not be reached to verify from this environment. The three CVEs are recorded from their own advisories instead. Per 'omit rather than guess', an unverifiable count does not ship. |
| `AIRT-CS-0013` | actor / scope | 'a lone actor', '~10 government bodies' | **a small group per Gambit Security; nine agencies** | CORRECTED. Reporting differs on whether it was one person or a small group, so the disagreement is recorded in `contested` rather than resolved. The second model is identified as GPT-4.1, and Claude is reported to have executed ~75% of remote commands. |
| `AIRT-CS-0005` | indicators | four prose bullets | **11 typed indicators** | EXPANDED from Microsoft's own report: marker file `C:\Windows\Temp\Netapi64.start`, exception log `Netapi64.Exception`, mutexes `Netapi64` and `OpenAI APIS`, and the `TextFile1` resource holding `<key>|<dict>|<proxy>`. None of these were in the handoff. |
| `AIRT-CS-0007` | corroboration | single-source (GTIG, Nov 2025) | **CERT-UA #16039, 17 Jul 2025, plus GTIG** | RAISED to high. CERT-UA published the same malware as LAMEHUG four months earlier, from live phishing against Ukraine's security and defence sector, tracking the actor as UAC-0001. Two independent reporting parties, so behaviour is high confidence; the APT28 attribution stays an assessment (CERT-UA states moderate confidence). |
| `AIRT-CS-0004` | confidence | — | **medium, contested** | The autonomy figure rests on one reporting party and is publicly disputed, and Anthropic's own report notes the model 'frequently overstated findings' and fabricated data. MITRE ATT&CK adopted the campaign as C0062, which corroborates that it happened, not how autonomous it was. |
| `AIRT-CS-0001` | date_range | 2025-08-24 (commit) | **2025-08-24 commit date; force-push reported 2026-06-08** | CORRECTED via `contested`. StepSecurity reports the payload was force-pushed after a co-founder's GitHub account was compromised on 2026-06-08, while the commit carries an August 2025 author date. Commit dates are attacker-controlled; scope from the push and the clone. Payload identified as a Shai-Hulud variant. |

## Verification Pass 4 — KAPE export and site semantics, August 2026

| Scope | Field | Was | Now | Basis |
|---|---|---|---|---|
| `KAPE` | Id | `airt-0001`, `aiagents_p1` | **uuid5 GUID per target** | CORRECTED before shipping. KAPE's own target guide requires `Id` to be a unique GUID, generated in gKape. A slug would have been non-conformant. Derived with uuid5 from a fixed namespace so it is a real GUID and still deterministic - a random one would rewrite every file's identity on each regeneration and make the CI staleness diff useless. |
| `KAPE` | `--check` | printed statistics, always exited 0 | **parses the rendered output, exits non-zero** | CORRECTED. The flag documented itself as "validate only, non-zero exit on problems" but performed no checks, so a run that emitted an empty `Path` on every row would have reported success. It now re-reads what it rendered and fails on a missing header field, non-GUID or duplicate `Id`, empty `Path` or `FileMask`, non-Windows path, target with no rows, or a compound reference to a file that was not emitted. Negative-tested against all nine. |
| `AIRT-0001` | abuse_potential | GTG-2002 | **GTG-2002 (unchanged)** | REVIEWER WRONG, recorded so it is not "fixed" later. A third-party review flagged `GTG-2002` as a typo for `GTG-1002`. Both designations are real and distinct: `GTG-2002` is Anthropic's August 2025 "vibe hacking" data-extortion campaign against 17+ organisations, `GTG-1002` is the November 2025 AI-orchestrated espionage campaign now catalogued as `AIRT-CS-0004`. The entry text describes GTG-2002 accurately. |
| `collection.kape_target` | population | 0/45 | **24/45** | POPULATED from the exporter for every entry that produces a Windows target, and the exporter now fails if a declared target name and the emitted one disagree. The remaining 21 entries emit no Windows target, so leaving the field unset is the honest state rather than a gap. |
| `SITE` | badge colour | one severity ramp for four scales | **severity ramp + a separate strength ramp** | CORRECTED. `confidence`, `forensic_value`, `risk` and `triage_priority` all use the words high/medium/low, and the page rendered all four on the same red-to-green alarm ramp - so a well-sourced artifact and a dangerous tool were the same warning orange, and a bare badge could not say which question it was answering. Severity (risk, triage) keeps the alarm ramp; strength (confidence, forensic value) gets a neutral ramp and carries its label. |

## Verification Pass 5 — Wave 3 entries and provenance, August 2026

| Scope | Field | Was | Now | Basis |
|---|---|---|---|---|
| `AIRT-0046` | entry_added | — | **Warp** | NEW. `BACKLOG.md` gave the starting point as `~/.warp/`, which is wrong on every platform. The command database is `warp.sqlite`, under a macOS group container (`~/Library/Group Containers/2BBY89MBSN.dev.warp/...`), `%LOCALAPPDATA%\warp\Warp\data\` on Windows and `~/.local/state/warp-terminal/` on Linux. Recorded at `medium` - vendor-documented, not observed on a host. Its `-wal` sibling matters: commands run in Warp never reach shell history, so an uncheckpointed WAL is lost execution evidence. |
| `AIRT-0047` | entry_added | — | **Letta** | NEW. `~/.letta/` confirmed; the documented Docker deployment stores agent state in `~/.letta/.persist/pgdata`, and the pip install defaults to SQLite. Server on 8283 with no authentication. `LETTA_PG_URI` carries a PostgreSQL password in the environment. Memory here is a persistence mechanism, so the entry maps to `AML.T0080.000` and the guidance puts memory collection before any teardown. |
| `AIRT-0048` | entry_added | — | **Docker Model Runner** | NEW, and deliberately with **no disk artifacts**. Models live in a dedicated named Docker volume rather than on the host filesystem, so a filesystem sweep finds nothing and enumeration has to go through the Docker API. Default access is the Docker socket; host TCP on 12434 is opt-in via `docker desktop enable model-runner --tcp 12434`. On Docker Desktop the process is inside the VM, so host process collection misses it - recorded as `low`/`unverified`. |
| `AIRT-0049` | entry_added | — | **Agent framework libraries** | NEW. One entry for Semantic Kernel, PydanticAI, Smolagents, the OpenAI Agents SDK and Strands, per the open question in issue #13. The schema accommodated it without change: `install-dir` and `project-artifact` cover site-packages and dependency manifests, and the provider API key is the shared credential. States explicitly that library presence is availability, not use. |
| `KAPE` / `Velociraptor` | consistency check | one direction only | **both directions** | CORRECTED. The declared-vs-emitted check only ran for entries that produced output, so `AIRT-0047` could declare `kape_target: Letta` while producing no target at all - a catalog entry pointing a responder at a file that does not exist. Found by listing the emitted files rather than by trusting the clean run. Both exporters now also fail on a declaration with nothing behind it; negative-tested. |
| `NOTES` | acronym list | derived from the corpus | **plus MITRE, ATLAS, CVE, KEV, SIEM, EDR, DFIR** | CORRECTED. The allowlist was derived by enumerating every uppercase token then in the corpus, which is why it was right about CWD and PKCE and wrong about MITRE - no note used it until `AIRT-0047` did. A derived allowlist is only complete for the corpus it was derived from. |
| `REFS` | coverage | 3/45 | **48/49** | Every entry except `AIRT-0034` OpenAI Operator now cites a primary source. The holdout is left empty rather than padded, and `validate.py` names it on every run. |

## Verification Pass 6 — first lifecycle sweep, August 2026

The first run of `docs/REVERIFICATION.md` step 2, against all 49 entries. 34 cite
a GitHub repository and were checked through the API for `archived` and
`updated_at`; the other 15 are vendor-hosted and were checked against reporting.

### Corrections

| Scope | Field | Was | Now | Basis |
|---|---|---|---|---|
| `AIRT-0022` | repo / description | `oobabooga/text-generation-webui`, "Gradio web UI" | **`oobabooga/textgen`, and a native desktop app** | CORRECTED. Renamed to TextGen in 2026; the repository is the same object (created 2022-12-21, 47.5k stars) under a new name, and the old URL redirects. It now ships a native Electron desktop app alongside the browser UI, released in v4.7.3 on 2026-05-03. The catalogued paths were recorded against the web UI, and the entry now says so - a desktop build may add Electron app-data locations that nobody here has verified. |
| `AIRT-0015` | successor | not recorded | **Rust rewrite at `openinterpreter/openinterpreter`** | CORRECTED. The project has a Rust successor, built on Codex, carrying the same name. The catalogued paths are the classic Python build (`pip install open-interpreter`), which is still on PyPI. A host running the Rust build will not match them. Its locations are unverified and deliberately not recorded. |
| `AIRT-0027` | status detail | "maintenance mode as of 2026" | **maintenance mode since October 2025; AG2 controls the original PyPI packages** | EXPANDED. Last feature release September 2025, bug and security fixes only, community managed. Microsoft Agent Framework is the successor (1.0 GA April 2026). The forensically useful part is the fork: the original authors' AG2 controls the original PyPI package names, so `pip install` may not put Microsoft's AutoGen on disk. Check the installed distribution, not the import name. |

### Re-confirmed, no change

Not archived and updated within the day of the sweep: `AIRT-0001` Claude Code,
`AIRT-0004` Aider, `AIRT-0005` Continue.dev, `AIRT-0012` AutoGPT, `AIRT-0016`
GPT Pilot, `AIRT-0017` Ollama, `AIRT-0019` Jan, `AIRT-0020` GPT4All, `AIRT-0021`
llama.cpp, `AIRT-0024` LocalAI, `AIRT-0025` n8n, `AIRT-0026` LangChain/LangGraph,
`AIRT-0028` CrewAI, `AIRT-0029` Dify, `AIRT-0030` Flowise, `AIRT-0031` Playwright
MCP, `AIRT-0032` Browser-Use, `AIRT-0035` Skyvern, `AIRT-0036` Codex CLI,
`AIRT-0037` Gemini CLI, `AIRT-0038` Goose, `AIRT-0039` Cline, `AIRT-0043`
OpenHands, `AIRT-0044` Langflow, `AIRT-0048` Docker Model Runner, `AIRT-0049`
framework libraries (all three cited repos).

Archived, and already marked as such: `AIRT-0013` AgentGPT and `AIRT-0040` Roo
Code both return `archived: true` from the API, which confirms the status set in
the previous pass from reporting alone.

### Methodology note — an absent search result is not evidence of absence

`LostRuins/koboldcpp` returned nothing from GitHub's repository search, including
under a `user:LostRuins` query, while its forks and satellites indexed normally.
That looks exactly like a deleted or transferred repository. It is not: the
repository is live and actively maintained, with v1.117.1 released 2026-07-10.
The search index simply does not return it.

`AIRT-0023` is therefore **unchanged**, and the next person running this sweep
should confirm a disappearance against a second source before recording it. The
same caution applied to `AIRT-0022` produced the opposite result - there the
absence was real, and the repository had been renamed.

### Live-host check, same day

`scripts/verify_host.py` was run on the Linux container this pass was done from,
which has Claude Code installed. Two `AIRT-0001` paths confirmed present with
their modes:

| Scope | Field | Was | Now | Basis |
|---|---|---|---|---|
| `AIRT-0001` | `~/.claude/` | documented | **confirmed present, `drwxr-xr-x`** | Verified on Linux 6.18.5, 2026-08-13, via `scripts/verify_host.py`. Existence and mode only; no contents read. |
| `AIRT-0001` | `~/.claude.json` | documented | **confirmed present, `-rw-------`** | Same run. Mode 0600 as a credential-bearing file should be, which is worth knowing: a wider mode on this file is itself a finding. |

Everything else missed on this host, which means only that the tools are not
installed here - `verify_host.py` cannot distinguish a wrong path from an absent
tool and does not try. That distinction needs the tool installed and run at least
once, because several of these paths are created lazily on first use.
