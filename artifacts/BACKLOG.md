# Backlog

Tools identified as in scope but **not yet catalogued**, because their artifact
locations have not been verified. They are listed here rather than added with
guessed paths — a missing entry is honest, a fabricated one becomes somebody's
broken detection.

Use `skills/agent-artifact-catalog/references/research-checklist.md` when picking
one up.

## Wave 3 — coding agents and IDEs

| Tool | Vendor | Why it matters | Known starting point |
|---|---|---|---|
| Sourcegraph Cody | Sourcegraph | Broad enterprise deployment; indexes whole codebases | VS Code / JetBrains extension |
| Amp | Sourcegraph | Agentic sibling of Cody | CLI + extension |
| Zed AI | Zed Industries | Editor with native agent + MCP support | `~/.config/zed/settings.json` |
| JetBrains AI Assistant / Junie | JetBrains | Large IDE install base | JetBrains config dirs |
| Kilo Code | Kilo | Cline/Roo lineage — likely same globalStorage pattern | VS Code globalStorage |
| Qodo (Codium) | Qodo | Test-generation agent | IDE extension |
| Replit Agent | Replit | Mostly cloud; confirm any local footprint | browser / CLI |
| Antigravity | Google | New agentic IDE | unknown |

## Wave 3 — terminals and runtimes

| Tool | Vendor | Why it matters | Known starting point |
|---|---|---|---|
| ~~Warp~~ | Warp | **Done — `AIRT-0046`.** `~/.warp/` was wrong: the database is `warp.sqlite` under a macOS group container, `%LOCALAPPDATA%\warp\Warp\data\` on Windows, and `~/.local/state/warp-terminal/` on Linux | — |
| ~~vLLM~~ | vLLM project | **Done — `AIRT-0045`.** | — |
| SGLang | SGLang | Inference server | container |
| ~~Docker Model Runner~~ | Docker | **Done — `AIRT-0048`.** Models live in a named Docker volume, not on the host filesystem, so it has no disk artifacts to collect | — |
| Foundry Local | Microsoft | Local inference on Windows | unknown |
| llamafile | Mozilla | Single-file executable model — no install trace | single binary |
| Msty / AnythingLLM | various | Desktop LLM clients with RAG | app data dirs |

## Wave 3 — agent frameworks and platforms

| Tool | Vendor | Why it matters | Known starting point |
|---|---|---|---|
| ~~Letta (MemGPT)~~ | Letta | **Done — `AIRT-0047`.** `~/.letta/` confirmed; `~/.letta/.persist/pgdata` is the store in the documented Docker deployment | — |
| ~~Semantic Kernel~~ | | **Done — covered by `AIRT-0049` Agent framework libraries.** | — |
| ~~PydanticAI / Smolagents~~ | | **Done — covered by `AIRT-0049` Agent framework libraries.** | — |
| ~~OpenAI Agents SDK~~ | | **Done — covered by `AIRT-0049` Agent framework libraries.** | — |
| ~~Strands~~ | | **Done — covered by `AIRT-0049` Agent framework libraries.** | — |
| Mastra | Mastra | Targeted by DPRK npm supply-chain attack | npm package |
| Stagehand | Browserbase | Browser agent | Playwright-based |
| Nanobrowser / Bytebot | various | Browser and desktop agents | extension / container |

## Notes on priority

The highest-value additions are tools that **open a network listener** or
**store plaintext credentials**, because those produce findings rather than
inventory. On that basis vLLM, Warp, Letta and Docker Model Runner were the ones
worth doing first, and all four are now catalogued (`AIRT-0045` to `AIRT-0048`).

Next on the same criterion: **SGLang** and **Foundry Local** (listeners),
**Msty / AnythingLLM** (desktop clients with app data dirs and likely credential
stores), and **Mastra**, which was targeted by a DPRK npm supply-chain attack and
so has a documented incident behind it.

Library-only frameworks (Semantic Kernel, PydanticAI, Agents SDK, Strands) have
no fixed install path and are documented as a single entry, `AIRT-0049`, which
inventories them by dependency manifest, site-packages presence, process lineage
and provider egress rather than by path. It says plainly that library presence is
availability, not use - the evidence an agent actually ran is the egress and the
child processes, not the import.
