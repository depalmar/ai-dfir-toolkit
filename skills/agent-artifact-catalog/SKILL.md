---
name: agent-artifact-catalog
description: >-
  Research, author, and validate AI agent artifact catalog entries documenting the
  forensic artifacts AI agents leave on endpoints - install paths, config and
  credential files, MCP server configs, listening ports, process trees,
  registry keys, and the Windows event log records that prove a tool ran. Use this skill whenever the user mentions AI agent forensics,
  AI agent artifacts, MCP server artifacts, shadow AI discovery, local LLM
  runtime detection, adding or updating a tool in the AI agent artifact catalog, or
  asks what an AI coding agent or LLM runtime leaves behind on a host. Also use
  it when the user names a specific agent tool (Claude Code, Cursor, Cline, Roo
  Code, Codex CLI, Gemini CLI, Goose, Ollama, LM Studio, n8n, Playwright MCP)
  and wants its endpoint footprint documented, or asks to build an IR triage
  collection list for AI agent tooling - even if they do not use those exact words.
---

# AI Agent Artifact Catalog Authoring

This catalog documents what AI agents **leave behind on an endpoint** so responders
can find, collect, and interpret it. That framing matters: it is a *collection and
analysis* reference, not an abuse-technique reference. LOL-family projects answer
"what can this be misused to do." This one answers "what is on the disk, what does
it prove, and in what order do I collect it."

Keep that distinction in view while authoring. If a proposed field describes an
attack technique rather than an observable artifact, it belongs in the
`abuse_potential` prose field or in the ATLAS mapping, not as a new artifact type.

## Layout

The catalog lives at `artifacts/` inside the toolkit. Run every command from
that directory.

```
artifacts/
catalog/          one YAML file per tool, slug-named
case-studies/     documented real-world incidents with IOC blocks
schema/           artifact.schema.json + entry-template.yml
scripts/          validate.py, export.py
docs/api/         generated JSON/CSV feeds - never hand-edit
docs/             VERIFICATION.md, MCP.md
```

## Authoring workflow

Work in this order. Each step feeds the next, and skipping research produces
entries that look authoritative but are guesses.

### 1. Check for an existing entry

```bash
grep -ril "<tool name>" catalog/
```

Update in place rather than adding a duplicate. IDs are permanent once merged -
never renumber an existing entry, because downstream detections reference them.

### 2. Research the artifacts

Prefer sources in this order, because confidence ratings depend on provenance:

1. **A real installation you can inspect.** Install in a VM, run it, then diff the
   filesystem and enumerate listeners. This is the only path to `confidence: high`
   on a path you have not seen documented.
2. **Vendor documentation** - official docs, the source repo, release notes.
3. **Source-code reading** - config loaders and path constants in the repo.
4. **Third-party analysis** - sandbox reports, security research.

Anything resting only on tier 4 is `confidence: low` and needs `unverified: true`.

Gather, per platform: install paths and binary names, config file locations,
credential storage (and *how* it is stored - plaintext, keyring, SQLite),
MCP config paths, default listener ports and bind addresses, process names with
typical parents and children, registry keys, event log channels and IDs, and
persistence mechanisms.

### 3. Write the entry

Copy `schema/entry-template.yml` to `catalog/<slug>.yml`. Assign the next free ID:

```bash
ls catalog/ | wc -l   # then confirm against existing ids
grep -h '^id:' catalog/*.yml | sort | tail -3
```

Fill every field you can source and omit the rest. An omitted field is honest;
a guessed field is a liability, because someone will build a detection on it.

### 4. Use the controlled vocabularies

`artifact_type`, `evidence_type`, `secret_type`, and `storage` are closed enums,
enforced by the schema. This matters more than it looks: the published CSV feed
is meant to be filtered, and a field where `log` and `logs` and `logfile` all
appear cannot be filtered. Pick the closest existing value rather than coining
a new one.

**artifact_type:** `binary` · `install-dir` · `config-file` · `config-dir` ·
`mcp-config` · `rules-file` · `agent-definition` · `credential-file` ·
`session-artifact` · `log` · `database` · `data-dir` · `env-var` ·
`service-config` · `extension-bundle` · `container` · `project-artifact`

**evidence_type:** `execution` · `persistence` · `configuration` ·
`credential-access` · `user-activity` · `data-access` · `timeline` ·
`program-presence` · `prompt-injection-surface`

**secret_type:** `api-key` · `oauth-token` · `jwt-signing-key` ·
`session-state` · `aws-sso-token` · `admin-credential` ·
`embedded-credentials` · `encryption-key` · `unknown`

**storage:** `plaintext` · `os-keyring` · `encrypted` · `sqlite` · `unknown`

If something genuinely does not fit, extend the enum in the schema, the
template, and this skill in the same change - never just in one.

### 5. Rate forensic value deliberately

`forensic_value` is not "how interesting is this" - it is **what investigative
question does this artifact answer**:

- **high** - proves execution, attributes activity to a user, establishes a
  timeline, exposes credentials, or records what the agent was authorised to do.
  Session transcripts, MCP configs, credential files, prompt history.
- **medium** - establishes that the tool is present and how it was configured.
  Binaries, install directories, model directories.
- **low** - supporting context only.

### 6. Rate confidence honestly

This is the field that makes the catalog trustworthy, so treat it as the one you
are least willing to inflate. `high` means you verified it on a real host or in
vendor documentation. `medium` means multiple independent third-party sources
agree. `low` means single-source or inferred - and must carry `unverified: true`.

The validator enforces this: a `confidence: high` entry cannot contain an
unmarked low-confidence row — in **any** class. Disk, registry, network, process,
eventlog and credential rows all accept `unverified: true` and are all checked. (The gate
covered only disk artifacts until August 2026, and three of those classes could
not even carry the flag, so the rule was unenforceable rather than merely
unenforced.)

It also rejects `capabilities.plaintext_credentials: true` alongside an empty
`credentials:` block. Announcing that a tool stores plaintext secrets and then
listing nowhere to look is worse than silence — it is the exact question the
catalog exists to answer, left blank. If you genuinely cannot source a location,
drop the capability claim rather than leaving the block empty; and remember that
`storage: os-keyring` is a real answer, because "not on disk, look in the
keychain" is what a responder needs to hear.

### 7. Validate before every commit

```bash
python scripts/validate.py     # schema + duplicate IDs + confidence gate
python scripts/export.py       # regenerate docs/api feeds
```

CI runs both and fails the build if `docs/api` is stale, so regenerate the feeds
in the same commit as the entry.


### `eventlog` rows: the class that proves execution

Disk presence proves a tool is **installed**. Only an event log record proves it
**ran**, and that distinction is the one most investigations actually turn on.

Two rules when writing one:

- **Give it a `selector`.** Without the field and value that narrow the channel
  to this tool, the row names a log rather than an artifact. For anything hosted
  by a shared interpreter — half this catalog runs under `node` or `python` — the
  image name is not a discriminator and the selector has to key on the command
  line.
- **Fill in `requires`.** None of these events exist by default. Sysmon has to be
  deployed, and Security 4688 carries a command line only when command line
  auditing is enabled. A row that omits this reads as though the evidence is
  always waiting to be collected, and on most hosts it is not there at all.

### `retention`: only when the tool documents it

A disk row's default lifetime is "until somebody uninstalls the tool", and that
is what an omitted `retention` means. Fill it in only where the vendor documents
a purge or rotation window - one row in the whole catalog does, and a guessed
second one would tell a responder they have longer than they do. Where it is
present the site promotes the row to `rotating` volatility and sorts it up the
collection plan, so the field changes behaviour rather than just reading well.

Volatility itself is never authored. It is derived from the row class and the
artifact type by `scripts/data_sources.py`, for the same reason `evidence_type`
is derived for the classes that do not declare it: one function cannot drift,
507 hand-set copies of one rule will.

## Data sources

`docs/data-sources.yml` records what somebody had to switch on **before** the
incident for an artifact class or a Sigma rule to have produced anything. Add a
source there when you add a rule in a logsource category no existing source
covers - `validate.py` fails until one does, and it fails the other way too if a
source claims coverage nothing in the corpus supplies.

Write only the prose a machine cannot derive: how to enable it, what retention
it needs, and the investigative question that goes unanswerable without it. Every
count is computed. `enable`, `retention`, `default_state`, `without_it` and at
least one reference are all required, on the same reasoning as a catalog entry -
an unsourced claim about somebody's estate is a guess.

## MCP entries need extra care

**Pick the mechanism before you look for a path.** `config-file` is only one of
five, and reaching for it by default is what produced 25 entries claiming MCP
capability with nowhere to look:

- `config-file` - a file listing servers. Give `config_path`.
- `database` - registered through the tool's own UI or API and persisted to its
  database. Nearly every self-hosted workflow engine works this way. Give an
  `indicator` naming the table or the node type to search for; the collection
  step is a query against a container volume, not a file copy.
- `in-code` - a literal in a script. Give the import or client class. There is no
  artifact to collect, and saying so is the answer - the source file and its
  history are the record of what the agent could reach.
- `server` - the tool *is* an MCP server and has no config of its own. The
  finding is whichever client config names it, so point the reader there.
- `cloud` - configured tenant-side. Recording this stops somebody searching a
  disk that was never going to hold it.

Before filling any of them in, check the claim itself. Ollama and Aider both
declared `mcp_capable: true` and neither is an MCP client; a request open on the
vendor's own tracker asking for MCP support is stronger evidence of absence than
a third-party blog claiming presence.


An MCP config is simultaneously a persistence mechanism and an execution
primitive - it launches a child process with inherited environment on every app
start. When documenting one, always capture:

- Every config path **including virtualized ones**. Windows MSIX/Store installs
  redirect `%APPDATA%` into `%LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalCache\Roaming\`.
  Derive the family name at runtime rather than hardcoding a publisher hash:
  `(Get-AppxPackage -Name *Claude*).PackageFamilyName`
- Whether config is **project-scoped** - a `.mcp.json` or `.cursor/mcp.json` in a
  repo travels with a clone and fires on open, which makes it a supply-chain path.
- Where secrets live. `env` blocks inside MCP configs are the single most common
  place plaintext API keys end up across the whole AI toolchain.
- Whether the config syncs. VS Code Settings Sync can carry `mcpServers` env
  blocks off the endpoint entirely.

See `docs/MCP.md` for the CVE set and vulnerability classes.

## Writing detections

Detection content lives in `detections/` and is **vendor-neutral**: Sigma for
event rules, osquery for inventory. Never add a rule written in a proprietary
query language - one Sigma rule converts to every SIEM via `sigma-cli`, and
shipping SPL or KQL forces a platform choice on everyone downstream.

When adding a rule:

- Pick the honest `level`. On a developer estate an agent spawning a shell *is*
  the product working correctly. Shipping that as `high` trains people to ignore
  the feed, so it belongs at `low` as a baseline signal. Reserve `high` for
  behaviour that is hard to explain as normal use - a plaintext token read by a
  non-owning process, an inference endpoint quietly redirected, an unauthenticated
  inference API bound to a routable address.
- Write `falsepositives` truthfully. If a rule will be noisy in the environment
  it is aimed at, say so in the rule rather than letting the analyst discover it.
- Use generic field names (`Image`, `ParentImage`, `TargetFilename`,
  `CommandLine`) and let the converter map them.
- Verify it converts before committing:

```bash
sigma convert -t splunk detections/sigma/your_rule.yml
```

CI runs both the structural check and a real backend conversion, so a rule that
does not compile cannot merge.

## Case studies

Add one only for a **documented, dated, publicly reported** incident. Use
`case-studies/airt-cs-XXXX.yml` and include concrete IOCs an analyst can hunt on
- file paths, package names and versions, commit hashes, network destinations -
plus response actions and the transferable lesson. A case study without IOCs is
a news summary, and does not belong here.

## Boundaries

This catalog is defensive. Document where artifacts live and what they prove.
Do not add exploit code, working attack tooling, or step-by-step abuse
instructions. Documenting that a config file can launch a child process is
defensive; supplying a malicious config is not.

Most catalogued tools are legitimate, widely used software. Entries should read
as neutral artifact documentation, and the `risk` field describes *exposure if
misused or misconfigured*, not a claim that the tool is malicious.
