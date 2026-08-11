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
| Warp | Warp | AI terminal — command history is a rich artifact | `~/.warp/` |
| vLLM | vLLM project | Common inference server; port 8000 | container/systemd |
| SGLang | SGLang | Inference server | container |
| Docker Model Runner | Docker | Ships with Docker Desktop — wide install base | Docker Desktop |
| Foundry Local | Microsoft | Local inference on Windows | unknown |
| llamafile | Mozilla | Single-file executable model — no install trace | single binary |
| Msty / AnythingLLM | various | Desktop LLM clients with RAG | app data dirs |

## Wave 3 — agent frameworks and platforms

| Tool | Vendor | Why it matters | Known starting point |
|---|---|---|---|
| Letta (MemGPT) | Letta | Persistent agent memory is a novel artifact class | `~/.letta/` |
| Semantic Kernel | Microsoft | Enterprise agent framework | library, no fixed path |
| PydanticAI / Smolagents | various | Growing framework use | library |
| OpenAI Agents SDK | OpenAI | Library | library |
| Strands | AWS | Library | library |
| Mastra | Mastra | Targeted by DPRK npm supply-chain attack | npm package |
| Stagehand | Browserbase | Browser agent | Playwright-based |
| Nanobrowser / Bytebot | various | Browser and desktop agents | extension / container |

## Notes on priority

The highest-value additions are tools that **open a network listener** or
**store plaintext credentials**, because those produce findings rather than
inventory. On that basis vLLM, Warp, Letta, and Docker Model Runner are the ones
worth doing first.

Library-only frameworks (Semantic Kernel, PydanticAI, Agents SDK, Strands) have
no fixed install path and are best documented as a single "agent framework
libraries" entry describing how to inventory them by process command line and
imported module, rather than as separate entries with invented paths.
