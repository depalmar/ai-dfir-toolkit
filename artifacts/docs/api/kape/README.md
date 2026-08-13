# KAPE Targets — AI Agent Artifact Catalog

Generated from the catalog by `scripts/export_kape.py`. Every path here is one already verified in a
catalog entry — the exporter adds **collection capability, not new artifact research**, so it carries no
fabrication risk beyond what the catalog itself already carries.

Rationale is the same one behind the ForensicArtifacts export: emit the formats responders already run
rather than asking them to adopt a new one. ForensicArtifacts covers Plaso, GRR and Timesketch. KAPE is
the tool most Windows IR teams reach for first at triage, and it was not covered.

## Usage

```
kape.exe --tsource C: --tdest E:\triage --target AIAgents_P1   # fast triage, P1 tools only
kape.exe --tsource C: --tdest E:\triage --target AIAgents      # everything catalogued
kape.exe --tsource C: --tdest E:\triage --target AIAgentCredentials
kape.exe --tsource C: --tdest E:\triage --target AIAgentMCP
```

Copy the `.tkape` files into your KAPE `Targets\AIAgents\` directory (or anywhere under `Targets\`).

**Handle the output as evidence containing live secrets.** `AIAgentCredentials` collects files that
hold usable API keys and OAuth tokens - that is the point of collecting them, but it means the
destination directory is credential material from the moment the collection finishes. Treat it the way
you would a registry hive containing cached credentials: restricted storage, no ticket attachments, and
rotate what you find rather than reading it into a report.

## What's here

| Target | Rows | Collects |
|---|---|---|
| `AIAgents.tkape` | 24 tools | Compound — pulls in every per-tool target |
| `AIAgents_P1.tkape` | 20 tools | Compound — P1 triage priority only |
| `AIAgentCredentials.tkape` | 30 | Every plaintext credential location in the catalog |
| `AIAgentMCP.tkape` | 7 | MCP configs — what the agent was authorised to run |
| `<Tool>.tkape` | 24 files | One per catalogued tool with Windows paths |

**Collect `AIAgentMCP` before remediation.** The MCP config records what the agent was permitted to
execute; removing a malicious server destroys that record, and in a rug-pull the on-disk config is not
what actually ran.

## Coverage and its limits

- **24 of 45** catalog entries produce Windows targets. The rest are macOS/Linux-only, or declare
  Windows support without a verified Windows disk path (see the gap list below).
- **5 MCP configs are repo-relative** (`<repo>/.mcp.json`) and are deliberately skipped — KAPE cannot
  template an arbitrary repository location. Collect those with the repo, and note that a project-scoped
  MCP config travels with the clone.
- **macOS/Linux-only paths are excluded**, not rewritten. An earlier build of this exporter turned
  `~/Library/Application Support/Claude/` into `C:\Users\%user%\Library\Application Support\Claude\`,
  which is a path that does not exist; the exporter now refuses any path carrying a non-Windows marker.
- Per-artifact `confidence` below `high` is preserved in the target `Comment` so an examiner can see
  what they are trusting.

## Catalog gap surfaced while building this

13 entries declare `windows` in `supported_os` but expose no Windows disk artifact path, so they produce
no target:

`AIRT-0012` AutoGPT · `AIRT-0013` AgentGPT · `AIRT-0016` GPT Pilot · `AIRT-0021` llama.cpp ·
`AIRT-0022` text-generation-webui · `AIRT-0023` KoboldCpp · `AIRT-0026` LangChain/LangGraph ·
`AIRT-0027` AutoGen · `AIRT-0028` CrewAI · `AIRT-0030` Flowise · `AIRT-0032` Browser-Use ·
`AIRT-0042` Open WebUI · `AIRT-0043` OpenHands

Most are pip-installed Python frameworks whose footprint is `site-packages` plus a working directory, so
this may be accurate rather than missing — but it is worth an explicit decision per entry, because a
responder reading `supported_os: [windows]` reasonably expects a Windows path to exist.

## Regenerating

```
python scripts/export_kape.py           # write
python scripts/export_kape.py --check   # validate only, writes nothing
```

Output is deterministic and LF-terminated, so it diffs cleanly in CI. `Id` is a uuid5 derived from a
fixed namespace rather than a random GUID, for the same reason - KAPE requires a GUID, and a random one
would rewrite every file's identity on every regeneration.

`--check` parses the rendered output back and fails on a missing header field, a non-GUID `Id`, a
duplicate `Id`, an empty `Path` or `FileMask`, a non-Windows path, a target with no rows, or a compound
target referencing a file that was not emitted. CI runs the writing form and then fails on any diff
under `docs/api`, so a catalog change that is not re-exported does not merge.
