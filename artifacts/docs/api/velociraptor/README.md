# Velociraptor artifacts — AI Agent Artifact Catalog

Generated from the catalog by `scripts/export_velociraptor.py`. Every glob here derives from a location
already verified in a catalog entry — the exporter adds **collection capability, not new artifact
research**, so it carries no fabrication risk beyond what the catalog itself already carries.

This is the sibling of the KAPE export, and the broader of the two. KAPE is Windows-only and reaches
**24 of 45** entries; Velociraptor runs on Windows, macOS and Linux and reaches **32 of 45**, which
matters because most of these tools are developer tooling that lives on macOS and Linux.

## Usage

Import the YAML files under **View Artifacts → Add an Artifact**, or drop them into your server's
custom artifact directory.

| Artifact | Collects |
|---|---|
| `Custom.AIAgents.Triage` | Every per-tool artifact, one source per tool |
| `Custom.AIAgents.Credentials` | Every plaintext credential location in the catalog |
| `Custom.AIAgents.MCPConfigs` | MCP configs — what the agent was authorised to run |
| `Custom.AIAgents.<Tool>` | One per catalogued tool with templatable paths |

Every artifact takes an `Upload` parameter, default **N**. Metadata only by default — path, size, mode
and the three timestamps. Turning `Upload` on pulls the files back, which is a decision rather than a
default because several of these paths are credential stores.

**Collect `Custom.AIAgents.MCPConfigs` before remediation.** The MCP config records what the agent was
permitted to execute; removing a malicious server destroys that record, and in a rug-pull the on-disk
config is not what actually ran.

**Handle `Custom.AIAgents.Credentials` output as evidence containing live secrets.** With `Upload` on it
returns files holding usable API keys and OAuth tokens. Restricted storage, no ticket attachments, and
rotate what you find rather than reading it into a report.

## How paths are templated

- One **source per OS**, each with its own precondition, so a single artifact is safe to push to a mixed
  fleet and each host runs only the globs that apply to it.
- `~/x` becomes `C:\Users\*\x`, `/Users/*/x` and `/home/*/x` respectively.
- `%APPDATA%`, `%LOCALAPPDATA%`, `%USERPROFILE%`, `%PROGRAMDATA%` and `%PROGRAMFILES%` expand on Windows
  only.
- A path ending in a separator is a directory and becomes a recursive `**` glob.
- A `<version>`-style placeholder becomes `*`. A `<repo>`-style placeholder does **not** — that is an
  arbitrary checkout location, and templating it to `*` would glob the entire filesystem. Those paths are
  skipped; collect them with the repository.
- macOS-only roots (`/Users`, `/Library`, `/Applications`) are never emitted as Linux globs.

## Coverage and its limits

**32 of 45** entries produce artifacts. The 13 that do not are entries whose footprint is a Python
`site-packages` install plus a working directory, with no fixed path to template:

`AIRT-0007` Devin · `AIRT-0012` AutoGPT · `AIRT-0013` AgentGPT · `AIRT-0014` Copilot Studio ·
`AIRT-0016` GPT Pilot · `AIRT-0021` llama.cpp · `AIRT-0022` text-generation-webui · `AIRT-0023` KoboldCpp ·
`AIRT-0024` LocalAI · `AIRT-0026` LangChain/LangGraph · `AIRT-0028` CrewAI · `AIRT-0029` Dify ·
`AIRT-0034` OpenAI Operator

This overlaps the KAPE gap list and has the same root cause. It is worth an explicit per-entry decision,
even if that decision is a note saying "no fixed install path; collect the venv and CWD".

## Regenerating

```
python scripts/export_velociraptor.py           # write
python scripts/export_velociraptor.py --check   # validate only, writes nothing
```

`--check` parses the rendered YAML back and fails on a missing field, a non-`CLIENT` type, a name outside
the `Custom.` namespace, a duplicate name, a source with no query, a source that globs nothing, an
unexpanded `~`/`%`/`<>` glob, a `Triage` source calling an artifact that was not emitted, or an entry
whose `collection.velociraptor_artifact` disagrees with what was emitted.

CI runs the writing form and then fails on any diff under `docs/api`, so a catalog change that is not
re-exported does not merge.
