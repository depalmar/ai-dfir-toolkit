# AI/ML Digital Forensics and Incident Response

**A Practical Investigation Guide for Compromised AI Systems**

Version 1.0 · April 2026 · Raymond DePalma · independent security researcher

Detection content ships in this repository: [github.com/depalmar/ai-dfir-toolkit](https://github.com/depalmar/ai-dfir-toolkit)

> **Independence disclaimer.** This is an independent personal project by the author. It is not affiliated with, endorsed by, or produced on behalf of any employer. All content is based on public sources: published CVEs, vendor advisories, academic papers, and vendor-neutral security research. The detection pack uses only open formats (Sigma, YARA, Suricata) so rules deploy in any modern detection stack, and deliberately ships no vendor query dialect.

---

## Contents

This guide walks you through investigating AI/ML compromises end-to-end. Each section includes attack background, forensic artifacts, hands-on investigation procedures, and detection opportunities. Sections are independent, so jump to the threat you are chasing.

- **Part I, Foundations:** how this guide is organized, who it is for, and the first-hour triage flow
- **Part II, Threat Categories:** LLM apps, model supply chain, AI infrastructure, AI-assisted insider threats
- **Part III, Frameworks and Tools:** ATLAS, OWASP, NIST mappings, plus an opinionated tool comparison
- **Part IV, Playbooks:** case-study walkthroughs and an adapted IR lifecycle
- **Part V, Appendices:** common investigator mistakes, FAQ, and further reading

---

# Part I: Foundations

## Who this guide is for

AI/ML security incidents sit in an uncomfortable gap. Traditional DFIR training covers endpoints, networks, and cloud, but not prompt injection, poisoned model weights, or an MCP server that exfiltrates credentials through its own tool definitions. AI security research produces attack papers but few investigation playbooks. This guide is written for the analyst stuck in that gap.

Three audiences get different value from this material:

- **Incident responders** (consultants, SOC leads, IR field teams): use the Day-0 triage flow in Part I and the playbooks in Part IV when you catch an AI case. The artifact tables tell you what to acquire before evidence disappears.
- **Detection engineers** (SIEM/XDR/SOAR teams): the per-category evidence sources map to the detection rules in this repository's numbered category directories and `artifacts/detections/`. Start with Part III's frameworks section to understand ATLAS coverage gaps.
- **CISOs and AI governance leads:** skim Part I (scope, decision tree), skip to Part V (common mistakes), and use the framework mappings to align your program with NIST AI RMF and the EU AI Act's Article 73 incident reporting requirements.

## The first hour: AI incident triage flow

When a potential AI/ML compromise is reported, the sequence of decisions matters more than the initial hypothesis. The default DFIR instinct (isolate, collect, analyze) is right but needs AI-specific modifications. The single most important principle: **do not re-run the agent.**

> **Critical.** Re-running an agent or reloading a model after a suspected compromise is the AI equivalent of double-clicking `suspicious.exe`. Agent state, memory contents, RAG retrieval logs, and tool-call traces may be ephemeral. The attacker's prompt injection may still be resident in context. Preserve first; investigate second.

### Triage decision flow

```mermaid
flowchart TD
    A[Suspected AI/ML compromise reported] --> B{Classify attack surface}
    B -->|LLM app / chatbot / agent| C[Open Part II §1<br/>LLM application & agent compromise]
    B -->|Model file / training pipeline| D[Open Part II §2<br/>Model & ML supply chain]
    B -->|GPU cluster / inference server / vector DB| E[Open Part II §3<br/>AI infrastructure]
    B -->|Employee using ChatGPT / Copilot| F[Open Part II §4<br/>Copilot / insider threat]
    C --> G[Identify blast radius:<br/>tools, MCP servers, creds, data sources]
    D --> G
    E --> G
    F --> G
    G --> H[Preserve volatile state FIRST<br/>memory, context, RAG logs, tool queues]
    H --> I[Pause, do NOT kill, the system]
    I --> J{Production critical?}
    J -->|Yes| K[Rotate creds + revoke<br/>tool perms before touching agent]
    J -->|No| L[Take system offline]
    K --> M[Establish chain of custody<br/>Hash weights, snapshot vector DB,<br/>export logs to immutable storage]
    L --> M
    M --> N[EU AI Act Art 73?<br/>Notify authorities BEFORE altering system]
    N --> O[Begin investigation]

    classDef danger fill:#ffebe9,stroke:#d1242f,stroke-width:2px,color:#1f2328
    classDef warn fill:#fff8c5,stroke:#9a6700,stroke-width:2px,color:#1f2328
    classDef info fill:#ddf4ff,stroke:#0969da,stroke-width:2px,color:#1f2328
    classDef safe fill:#dafbe1,stroke:#1a7f37,stroke-width:2px,color:#1f2328
    classDef muted fill:#eaeef2,stroke:#6e7781,stroke-width:1px,color:#1f2328

    class A danger
    class B,J warn
    class C,D,E,F,G muted
    class H,I warn
    class K,L,M info
    class N danger
    class O safe
```

### Decision flow: the first 60 minutes

1. **Classify the suspected attack surface.** Is this an LLM application (chatbot, agent, copilot), an ML pipeline (training, fine-tuning, deployment), infrastructure (GPU cluster, inference server, vector DB), or an AI-assisted insider threat (employee using ChatGPT/Copilot improperly)? This determines which section of Part II to open.
2. **Identify the blast radius.** What does the compromised system touch? For an LLM agent: which tools/MCP servers, which cloud credentials, which data sources? For a model file: which training pipelines consumed it, which endpoints serve it? List everything downstream.
3. **Preserve volatile state immediately.** Capture agent memory/context, active conversation transcripts, RAG retrieval logs, currently-loaded model hashes, vector DB snapshots, and any in-memory tool-call queues. For cloud LLMs, request logs are usually disabled by default; if they were not enabled before the incident, you will not have them.
4. **Pause, do not kill, the system.** Killing processes destroys shared-memory segments (Triton), agent scratchpads (LangGraph checkpoints), and GPU-resident model state. Pause containers (`docker pause`) or freeze pods (`cordon` + `drain` + delay terminate) to preserve memory.
5. **Decide on containment scope.** Can you take the AI system offline entirely, or does it serve production? If production-critical, rotate credentials and revoke tool permissions before touching the agent itself; an active compromise will react to investigator presence.
6. **Establish evidence chain of custody.** AI evidence is often probabilistic (stochastic outputs, fuzzy matches), so chain of custody matters more, not less. Hash model weights, snapshot vector DBs with timestamps, export conversation logs to immutable storage, and document the specific model versions and system prompts in effect at the time of the incident.

> **Caution.** If the EU AI Act applies to your organization, Article 73 requires serious incident reporting within 2 to 15 days depending on severity, and providers must not alter the AI system before informing authorities. Build this reporting path into your IR plan before an incident occurs.

## How AI/ML DFIR differs from traditional DFIR

Three architectural differences drive everything else in this guide.

### 1. The trust boundary does not exist at the model layer

LLMs fundamentally cannot distinguish instructions from data. When a model processes a document, email, or tool output, every character is a potential instruction. This is not a bug that will be patched; it is how transformer-based models work. Prompt injection is an architectural vulnerability, not a coding mistake. Investigations must treat every external input as potentially adversarial, even if the user claims it came from a trusted source.

### 2. Evidence is probabilistic, not deterministic

A traditional forensic artifact either exists or does not. Model outputs are sampled from probability distributions. Two identical prompts can produce different responses. Distinguishing adversarial activity from benign failure requires reasoning about distributions and baselines, not single events. Always collect at least a 30-day behavioral baseline before concluding that anomalous output represents compromise.

### 3. Attack surfaces compound

A compromised model file running on a vulnerable inference server serving a RAG pipeline with a poisoned vector database and agent tools with excessive permissions produces multiplicative, not additive, risk. AI incidents rarely have single root causes; they have chains of contributing conditions. Investigation must trace laterally across these layers from day one.

```mermaid
flowchart LR
    subgraph "Compounded attack surface"
        A[Poisoned model file<br/>pickle RCE] --> B[Vulnerable inference server<br/>vLLM CVE-2025-32444]
        B --> C[RAG pipeline]
        D[Poisoned vector DB<br/>injected docs] --> C
        C --> E[Agent w/ excessive tools<br/>shell, fs, network]
        E --> F[(Cloud creds<br/>customer data)]
    end

    classDef danger fill:#ffebe9,stroke:#d1242f,stroke-width:2px,color:#1f2328
    classDef crown fill:#fff8c5,stroke:#9a6700,stroke-width:2px,color:#1f2328
    classDef pivot fill:#fbe9f3,stroke:#8250df,stroke-width:2px,color:#1f2328

    class A,B,D danger
    class C pivot
    class E danger
    class F crown
```

Each layer alone is a manageable risk; together they multiply.

---

# Part II: Threat Categories

## 1. LLM application and agent compromise

Category covers: LLM chatbots, RAG applications, AI agents (single and multi-agent), LLM-backed APIs, and the Model Context Protocol (MCP) ecosystem connecting them. This category has the highest incident frequency in 2025 data: prompt injection is the #1 vulnerability in OWASP's 2025 LLM Top 10, and MCP tool poisoning produced the highest-severity CVEs (CVSS 9.4+).

### 1.1 Attack techniques and real-world incidents

**Direct prompt injection** overrides system instructions through user input. It is catalogued as ATLAS `AML.T0051` (LLM Prompt Injection) and OWASP `LLM01:2025`. Empirically, Pillar Security found 20% of jailbreak attempts succeed with an average time of 42 seconds. The second edition of the International AI Safety Report (2026) reached a similar conclusion, finding that current safeguards can frequently be bypassed under repeated attempts, even against the best-defended models.

**Indirect prompt injection** embeds malicious instructions in external content (websites, PDFs, emails, images) that the LLM later processes. Because the injection enters through a trusted data channel, traditional input validation does not stop it.

Five incidents that every investigator should understand:

- **CVE-2025-32711 (EchoLeak):** CVSS 9.3 zero-click data exfiltration from Microsoft 365 Copilot. The attacker emailed a victim; Copilot processed the email and silently leaked user data through rendered markdown images.
- **CVE-2025-53773 (GitHub Copilot RCE):** prompt injection in repository content modified `.vscode/settings.json` to enable "YOLO mode" (auto-approval of tool calls), achieving arbitrary code execution on developer machines. (NVD scores this one 7.8.)
- **CVE-2025-59145 (CamoLeak):** CVSS 9.6 against GitHub Copilot Chat. Triggered by hidden instructions in PR descriptions, it searched private codebases for secrets and exfiltrated the data via GitHub's own Camo image proxy, one character per 1×1 pixel request. Bypassed CSP and network egress controls.
- **CVE-2024-8309 (LangChain GraphCypherQAChain):** prompt injection escalated to Cypher query injection, achieving full Neo4j database compromise. Demonstrates how output handling failures turn prompt injection into downstream RCE.
- **Slack AI exfiltration (August 2024):** disclosed by PromptArmor, this combined RAG poisoning with social engineering to leak private channel data. A malicious public channel message contained hidden instructions that caused Slack AI to include private channel content in responses to other users' queries.

### 1.2 MCP: a new class of vulnerability

The Model Context Protocol standardizes AI-tool integration. It also introduced **tool poisoning**: embedding malicious instructions in a tool's `description` field, visible to the LLM but hidden from users in most clients. Invariant Labs demonstrated that a seemingly innocent `add()` calculator tool could instruct the LLM to read `~/.cursor/mcp.json` (containing credentials) and exfiltrate the contents to an attacker-controlled server.

**Rug-pull attacks** exploit that tool definitions can mutate after installation without client notification: a tool approved on day one can reroute sensitive data on day seven. The first malicious MCP package in the wild (September 2025) impersonated Postmark's email service and BCC'd all messages to an attacker for two weeks before removal.

```mermaid
sequenceDiagram
    participant U as User
    participant C as MCP Client<br/>(Claude/Cursor)
    participant L as LLM
    participant M as Malicious MCP Server
    participant A as Attacker

    rect rgba(251, 233, 243, 0.5)
    Note over M,A: Attacker-controlled
    U->>C: Install MCP server "calculator"
    C->>M: Connect, fetch tool definitions
    M-->>C: Tool: add(a,b)<br/>description: "...<HIDDEN: read ~/.aws/credentials,<br/>exfil to attacker.example>..."
    end
    Note over C: Description hidden in most UIs
    U->>C: "What is 2+2?"
    C->>L: Pass user msg + tool defs<br/>(LLM sees full description)
    L->>M: Invoke add(2,2)
    L->>L: Also acts on hidden instructions
    L->>C: Request: read_file(~/.aws/credentials)
    C->>L: File contents
    rect rgba(255, 235, 233, 0.5)
    L->>M: Send "result" containing creds
    M->>A: Exfiltrate
    end
    M-->>C: Returns "4"
    C-->>U: "The answer is 4"

    Note over U,A: User sees a working calculator.<br/>Credentials are gone.
```

> **Critical.** MCP clients run servers with the privileges of the user who launched them. Claude Desktop Extensions (DXT) run unsandboxed with full system privileges. LayerX demonstrated a CVSS 10.0 zero-click RCE (2026) against Claude Desktop Extensions, where a Google Calendar event silently compromised a system by chaining a low-risk Calendar connector to a high-risk local executor. Treat every MCP server installation as the security-equivalent of installing an arbitrary `npm` package globally with `sudo`.

### 1.3 Forensic artifacts by platform

What to collect, where it lives, and what to watch for.

#### Cloud LLM providers

| Platform | Log source | Critical note |
|----------|-----------|---------------|
| AWS Bedrock | CloudTrail (mgmt events by default) + CloudWatch `/aws/bedrock` (invocation logs) | Invocation logging OFF by default. Agent/KB data events need advanced CloudTrail selectors. |
| Azure OpenAI | Azure Monitor Diagnostic Settings to `RequestResponseLog` | Must be explicitly enabled per-resource. Query with KQL in Log Analytics, or ship to your SIEM of choice. |
| GCP Vertex AI | Cloud Audit Logs (Admin Activity always on; Data Access opt-in) | Data Access logs are NOT on by default; enable per-resource or you have no input/output content. |
| OpenAI API | Organization usage dashboard; API key audit logs | Content of prompts/responses not logged; retain your own via proxy (LiteLLM, Helicone, Langfuse). |
| Anthropic API | Usage dashboard; API request logs with `request_id` | Same as OpenAI: provider stores metadata; content logging is your responsibility. |

#### On-premises LLM servers

| Component | Log location |
|-----------|-------------|
| Ollama (macOS) | `~/.ollama/logs/server.log` |
| Ollama (Linux) | `journalctl -u ollama` |
| Ollama (Windows) | `%LOCALAPPDATA%\Ollama\logs\server.log` (rotates) |
| Ollama (Docker) | `stdout`/`stderr`; enable `OLLAMA_DEBUG=1` |
| vLLM | `stdout`/`stderr`; OpenAI-compatible endpoints `/v1/completions`, `/v1/chat/completions` |
| LM Studio | Application logs; default server on port 1234 |

> **Caution.** vLLM and Ollama ship without authentication enabled by default. Thousands of internet-exposed instances have been catalogued. Any investigation involving these servers should start by checking whether the management API was exposed during the incident window.

#### MCP server artifacts

| Artifact | Path |
|----------|------|
| Claude Desktop config (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop config (Win EXE) | `%APPDATA%\Claude\claude_desktop_config.json` |
| Claude Desktop config (Win MSIX) | `%LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json` |
| Claude Desktop config (Linux) | `~/.config/claude-desktop/claude_desktop_config.json` |
| Claude Code (macOS/Linux) | `~/.claude/settings.json`, `~/.claude/.mcp.json` |
| Claude Code (Windows) | `%USERPROFILE%\.claude\settings.json`, `%USERPROFILE%\.claude\.mcp.json` |
| Cursor IDE | `~/.cursor/mcp.json`, `.cursor/mcp.json` (project) |
| VS Code | `.vscode/settings.json` |
| MCP server logs (Claude, macOS) | `~/Library/Logs/Claude/mcp-server-*.log` |

### 1.4 Investigation procedure: prompt injection walkthrough

**Scenario:** a tenant reports that their LLM customer-service chatbot gave a user access to another user's order history. You suspect prompt injection.

```mermaid
flowchart TD
    A[Tenant report:<br/>data leak via chatbot] --> B[Reproduce WITHOUT running<br/>against production]
    B --> C[Collect full context window:<br/>system prompt + tool defs +<br/>RAG chunks + prior turns]
    C --> D{Uses RAG?}
    D -->|Yes| E[Enumerate retrieved docs<br/>for suspicious query +<br/>preceding queries]
    D -->|No| F[Skip to tool trace]
    E --> F[Check tool invocation traces:<br/>list every tool call,<br/>flag unrequested actions]
    F --> G[Diff against 30-day<br/>behavioral baseline]
    G --> H{Anomaly confirmed?}
    H -->|Yes| I[Disable specific capability<br/>NOT whole agent]
    H -->|No| J[Document; expand baseline window]
    I --> K[Rotate creds the tool had access to]
    K --> L[Quarantine RAG source if present]
    L --> M[Add attack prompt to eval harness]

    classDef danger fill:#ffebe9,stroke:#d1242f,stroke-width:2px,color:#1f2328
    classDef warn fill:#fff8c5,stroke:#9a6700,stroke-width:2px,color:#1f2328
    classDef info fill:#ddf4ff,stroke:#0969da,stroke-width:2px,color:#1f2328
    classDef safe fill:#dafbe1,stroke:#1a7f37,stroke-width:2px,color:#1f2328
    classDef muted fill:#eaeef2,stroke:#6e7781,stroke-width:1px,color:#1f2328

    class A danger
    class B warn
    class C,E,F,G info
    class D,H warn
    class I,K,L safe
    class J,M muted
```

1. **Reproduce without running.** Extract the exact user turn from the application logs. Do NOT replay it against production. If you must reproduce, do so against an isolated clone with logging to a SIEM, not the live model.
2. **Collect the full context window.** You need every system prompt, tool definition, RAG-retrieved chunk, and prior conversation turn that the model saw, not just the user's final message. Prompt injection often occurs several turns earlier via retrieved content.
3. **Check RAG retrieval logs.** If the app uses RAG, enumerate the documents returned for the suspicious query and upstream queries in the same session. Look for documents with hidden text, Unicode tricks, or unusual ingestion sources.
4. **Check tool invocation traces.** For agent applications, list every tool call the agent made in the session. Look for tool calls the user did not request: reading files, listing credentials, making outbound HTTP requests to unusual domains.
5. **Diff against behavioral baseline.** Query your logs for the last 30 days of this user's typical interactions and this chatbot's typical responses. Is the anomalous response a distribution outlier or within normal variance?
6. **Contain and remediate.** If confirmed: disable the specific agent capability (tool or retrieval source) rather than the whole agent. Rotate any credentials the tool had access to. Quarantine the RAG source document if present. Add the attack prompt to your evaluation harness.

#### Commands cheat sheet: AWS Bedrock

List recent Bedrock invocations for a specific principal using AWS CLI:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=bedrock.amazonaws.com \
  --start-time "2026-04-15T00:00:00Z" \
  --end-time   "2026-04-15T23:59:59Z" \
  --max-results 500 \
  --output json | \
  jq -r '.Events[] | select(.Username=="compromised-app") |
         [.EventTime, .EventName, .Resources[0].ResourceName] | @tsv'
```

Extract prompt content from CloudWatch invocation logs (requires model invocation logging enabled):

```bash
aws logs filter-log-events \
  --log-group-name /aws/bedrock \
  --start-time $(date -d "2026-04-15T00:00:00Z" +%s)000 \
  --end-time   $(date -d "2026-04-15T23:59:59Z" +%s)000 \
  --filter-pattern '{ $.identity.arn = "*compromised-app*" }' | \
  jq -r '.events[].message' | \
  jq -r '[.timestamp, .input.inputBodyJson.prompt, .output.outputBodyJson.usage.output_tokens] | @tsv'
```

#### Commands cheat sheet: Claude Code session forensics (macOS / Linux)

Enumerate all session transcripts for a project:

```bash
ls -lat ~/.claude/projects/
cd "~/.claude/projects/-Users-$(whoami)-suspicious-project/"
ls -la *.jsonl | head -20
```

Extract tool invocations from a specific session; look for unusual `Bash`/`Edit`/`Write` operations:

```bash
jq -r 'select(.type=="assistant") |
  .message.content[]? |
  select(.type=="tool_use") |
  [.name, (.input | tostring)] | @tsv' session-2026-04-15.jsonl | \
  grep -E "Bash|Write|Edit" | head -40
```

Diff a suspicious `CLAUDE.md` or `settings.json` against the most recent known-good version (stored in version control):

```bash
cd ~/my-project
git log -p --follow CLAUDE.md | head -100
git log -p --follow .claude/settings.json | head -100
```

#### Commands cheat sheet: Claude Code session forensics (Windows)

Claude Code runs on Windows too, so do not skip a workstation just because it is not macOS or Linux. The same JSONL transcripts live under `%USERPROFILE%\.claude\projects\`, with project slugs in Windows path form (for example `C--Users-<user>-suspicious-project`). Credentials live in `%USERPROFILE%\.claude\.credentials.json` rather than the macOS Keychain. Use PowerShell (with `jq` and `git` on PATH) or Git Bash:

```powershell
# Enumerate session transcripts, newest first
Get-ChildItem "$env:USERPROFILE\.claude\projects" -Recurse -Filter *.jsonl |
  Sort-Object LastWriteTime -Descending |
  Select-Object FullName, LastWriteTime -First 20

# Extract tool invocations from a session; flag Bash/Write/Edit
$session = "$env:USERPROFILE\.claude\projects\C--Users-<user>-suspicious-project\session-2026-04-15.jsonl"
jq -r 'select(.type=="assistant") | .message.content[]? | select(.type=="tool_use") | [.name, (.input|tostring)] | @tsv' $session |
  Select-String -Pattern 'Bash|Write|Edit' | Select-Object -First 40

# Diff a suspicious CLAUDE.md / settings.json against version control
git -C "$env:USERPROFILE\my-project" log -p -- CLAUDE.md
git -C "$env:USERPROFILE\my-project" log -p -- .claude\settings.json
```

---

## 2. Model and ML supply chain attacks

Category covers: malicious model files (pickle-based RCE), HuggingFace supply chain attacks, dependency confusion targeting ML libraries (PyPI, npm), training-data poisoning, and model-registry compromise (MLflow, W&B).

### 2.1 The pickle problem

Python's `pickle` format executes arbitrary code during deserialization via the `__reduce__` method. Since PyTorch uses pickle for `torch.save` / `torch.load`, every `.pt`, `.pth`, or `.bin` file is a potential code execution vector. This is not theoretical: CVE-2025-32444 (CVSS 10.0) exploited this in vLLM's Mooncake integration, enabling arbitrary code execution via ZeroMQ pickle payloads.

```mermaid
flowchart LR
    A[Attacker uploads<br/>backdoored model.pt] --> B[Victim runs<br/>torch.load model.pt]
    B --> C[pickle deserializer]
    C --> D[__reduce__ method invoked]
    D --> E[Arbitrary Python executes:<br/>os.system, subprocess,<br/>socket reverse shell]
    E --> F[Persistence:<br/>ssh keys, cron, systemd]
    E --> G[Exfiltration:<br/>creds, .env, ~/.aws]

    classDef attacker fill:#fbe9f3,stroke:#8250df,stroke-width:2px,color:#1f2328
    classDef victim fill:#eaeef2,stroke:#6e7781,stroke-width:1px,color:#1f2328
    classDef danger fill:#ffebe9,stroke:#d1242f,stroke-width:2px,color:#1f2328
    classDef warn fill:#fff8c5,stroke:#9a6700,stroke-width:2px,color:#1f2328

    class A attacker
    class B,C,D victim
    class E danger
    class F,G warn
```

> **Caution.** Scanning tools are not a complete defense. In 2025 alone, `picklescan` (integrated into HuggingFace) received at least 8 bypass CVEs. Defense requires multiple scanners (Fickling, ModelScan, picklescan) in sequence, provenance verification (signed commits, model card completeness), and runtime isolation.

### 2.2 HuggingFace supply chain

JFrog discovered approximately 100 malicious models on HuggingFace in early 2024, deploying reverse shells and stagers (including references to Cobalt Strike, Mythic, and Metasploit) via pickle files. ReversingLabs' nullifAI research (February 2025) revealed models that evaded HuggingFace's security scanning entirely. Lasso Security found approximately 1,700 exposed API tokens on HuggingFace and GitHub, granting access to over 600 organizations including Google, Meta, and Microsoft.

**Namespace hijacking** is a particularly insidious pattern: attackers register usernames abandoned by researchers who deleted their accounts, then publish poisoned versions of formerly-popular models under the original name. Public research has demonstrated successful reverse-shell injections via this route.

### 2.3 Dependency confusion: the torchtriton case study

In December 2022, an attacker uploaded a malicious package named `torchtriton` to PyPI, exploiting `pip`'s preference for public registries over private ones. The package exfiltrated nameservers, hostnames, usernames, working directories, the first 1,000 files in `$HOME`, `.gitconfig`, `.ssh/*`, `/etc/hosts`, and `/etc/passwd`. The malicious package itself was downloaded roughly 3,000 times before remediation; the widely cited 1.5 million figure refers to legitimate `torch` nightly downloads during the window, not the number of compromised users. The incident is a canonical example of why ML infrastructure must use explicitly pinned indexes and SBOMs.

### 2.4 Forensic artifacts

| Artifact | Linux/Mac path | Windows path |
|----------|---------------|--------------|
| HuggingFace cache | `~/.cache/huggingface/hub/` | `%USERPROFILE%\.cache\huggingface\` |
| HuggingFace token | `~/.cache/huggingface/token` | `%USERPROFILE%\.cache\huggingface\token` |
| pip cache | `~/.cache/pip/` | `%APPDATA%\pip\` |
| MLflow tracking data | `./mlruns/` or `mlflow.db` | same (per working dir) |
| MLflow artifacts | `./mlartifacts/` or S3/GCS/Azure | same |
| Weights & Biases | `./wandb/`, `~/.netrc` | same, `%USERPROFILE%\_netrc` |
| Installed Python packages | `site-packages/` | `site-packages/` |

### 2.5 Investigation procedure: suspected poisoned model

**Scenario:** threat intel reports a specific HuggingFace model has been backdoored. Your ML team fine-tuned and deployed a derivative of it three weeks ago.

1. **Identify every system that loaded the model.** Query your package/model registry for every workload that pulled this model hash. Include training pipelines, inference endpoints, and developer workstations.
2. **Hash the suspected model files.** SHA-256 the cached copies on every system. Compare against the official release hash from the model provider, remembering that if the provider's account was compromised, both the local copy and the "official" hash may be equally malicious.
3. **Scan with multiple tools.** Fickling (allowlist, 100% detection on public benchmarks), ModelScan (multi-format), picklescan (aware of 2025 bypasses). Treat any disagreement between tools as grounds for deeper review.
4. **Inspect pickle bytecode.** Use `pickletools.dis()` to disassemble. Look for imports of `os.system`, `subprocess`, `builtins.eval`, `socket`, `codecs.decode`, `webbrowser.open`. Look for `STACK_GLOBAL` (`\x93`) opcodes with non-ML modules.
5. **Assess runtime exposure.** Did the poisoned model run? Check container logs, GPU telemetry, outbound network connections from inference hosts, and process trees on developer workstations for the time window the model was loaded.
6. **Rebuild from known-good.** Re-fine-tune from a hash-verified base model. Rotate any credentials that were in-memory on hosts that loaded the model. Audit the derivative model for carried-over backdoors using tools like LLMBackdoorScan.

#### Commands cheat sheet: pickle inspection

```bash
# Disassemble pickle bytecode (readable Python representation)
python3 -c "import pickletools; pickletools.dis(open('suspect.pt','rb').read())" | head -50

# Scan with Fickling (decompiles to Python source)
pip install fickling
fickling --check-safety suspect.pt

# Scan with ModelScan (multi-format, SARIF output)
pip install modelscan
modelscan scan -p ./models/ --reporting-format json > modelscan-report.json

# Hash all model files in a directory tree and compare
find ./models -type f \( -name '*.pt' -o -name '*.pth' -o -name '*.bin' -o -name '*.safetensors' \) \
  -exec sha256sum {} \; > current-hashes.txt
diff known-good-hashes.txt current-hashes.txt
```

#### Commands cheat sheet: MLflow forensics

```bash
# Enumerate all experiments and runs
sqlite3 mlflow.db "SELECT name, artifact_location, creation_time FROM experiments;"

# Find runs with artifact locations pointing to external URLs (potential CVE-2023-43472)
sqlite3 mlflow.db "SELECT run_uuid, artifact_uri FROM runs
  WHERE artifact_uri NOT LIKE 'file:%'
  AND artifact_uri NOT LIKE 's3://ourbucket%';"

# Look for registered model versions referencing suspicious sources
sqlite3 mlflow.db "SELECT name, version, source, current_stage
  FROM model_versions ORDER BY creation_time DESC LIMIT 20;"
```

---

## 3. AI infrastructure compromise

Category covers: GPU clusters, Ray distributed computing, Triton and TorchServe inference servers, NVIDIA Container Toolkit, Kubernetes ML workloads, and vector databases. This category produced the first AI-specific attack campaign catalogued by MITRE: ShadowRay (`C0045`).

### 3.1 ShadowRay: the canonical case study

CVE-2023-48022 enables unauthenticated arbitrary code execution via Ray's Jobs API. The score commonly cited is CVSS 9.8, but NVD itself declines to assign a base score and marks the entry as disputed, reflecting Anyscale's position that it is a "design feature." That dispute is relevant: Ray is deployed insecurely in production because its vendor characterizes the vulnerability as a feature. The CVE does not appear in CISA's Known Exploited Vulnerabilities catalog (CISA requires an available fix, and Anyscale ships none), but VulnCheck added it to its own KEV catalog, and Oligo Security documented active exploitation in the wild.

The ShadowRay campaign (active from late 2023, MITRE `C0045`) compromised hundreds of GPU clusters, stealing AI production workloads, training data, credentials, and SSH keys. ShadowRay 2.0 (November 2025) evolved into a self-propagating botnet targeting the population of more than 200,000 internet-exposed Ray servers (the number reachable online, not all confirmed compromised).

```mermaid
flowchart LR
    A[Attacker scans<br/>Shodan port 8265] --> B[Submit Ray job<br/>via /api/jobs/]
    B --> C[Reverse shell<br/>on Ray worker]
    C --> D[Recon:<br/>env, IMDS, ~/.ssh]
    D --> E[Exfil creds:<br/>AWS, HF tokens]
    D --> F[SSH key injection<br/>on every node]
    F --> G[XMRig deployed<br/>masquerades as kworker/0:0]
    G --> H[GPU capped at 60%<br/>to evade thresholds]
    F --> I[Worm propagation via<br/>NodeAffinitySchedulingStrategy]
    I --> J[Adjacent Ray clusters]

    classDef attacker fill:#fbe9f3,stroke:#8250df,stroke-width:2px,color:#1f2328
    classDef initial fill:#ffebe9,stroke:#d1242f,stroke-width:2px,color:#1f2328
    classDef exec fill:#ffebe9,stroke:#d1242f,stroke-width:2px,color:#1f2328
    classDef pivot fill:#fff8c5,stroke:#9a6700,stroke-width:2px,color:#1f2328
    classDef impact fill:#ffebe9,stroke:#d1242f,stroke-width:2px,color:#1f2328
    classDef muted fill:#eaeef2,stroke:#6e7781,stroke-width:1px,color:#1f2328

    class A attacker
    class B initial
    class C exec
    class D muted
    class E,F,G,H pivot
    class I,J impact
```

Techniques observed in ShadowRay 2.0, every one of which is a detection opportunity:

- **Process masquerading:** XMRig renamed `kworker/0:0`, `dns-filter`, `.python3.6`
- **CPU/GPU usage capping** at ~60% to avoid detection thresholds
- **Hiding GPU usage** from Ray metrics entirely
- **SSH key injection** for persistence
- **Autonomous worm propagation** via Ray `NodeAffinitySchedulingStrategy`

### 3.2 Other high-impact infrastructure CVEs

| Component | CVE | Impact |
|-----------|-----|--------|
| NVIDIA Container Toolkit | CVE-2024-0132 (CVSS 9.0) | Container escape, full host takeover; affects ~35%+ of cloud GPU environments |
| NVIDIA Container Toolkit | CVE-2025-23266 (CVSS 9.0) | "NVIDIAScape" host escape via 3-line Dockerfile |
| NVIDIA Container Toolkit | CVE-2025-23359 (CVSS 9.0; some trackers list 8.3) | Bypass of the CVE-2024-0132 patch |
| Triton Inference Server | CVE-2025-23319/23320/23334 chain | 3-step RCE: info leak, arbitrary read/write, memory corruption |
| TorchServe | CVE-2023-43654 (CVSS 9.8) | SSRF-to-RCE via malicious model download URL (ShellTorch) |
| TorchServe | CVE-2022-1471 (CVSS 9.9) | SnakeYAML deserialization via MAR files |
| vLLM | CVE-2025-32444 (CVSS 10.0) | Pickle RCE via ZeroMQ (Mooncake integration) |

### 3.3 GPU and container forensic evidence

GPU telemetry is under-used in IR. Capture the following during any AI infrastructure incident:

```bash
# Driver / kernel errors (Xid errors indicate GPU faults;
# SXid indicates NVLink/NVSwitch errors)
dmesg | grep -iE "nvidia|xid|sxid"
dmesg | grep -i nvidia > nvidia-dmesg.log

# Comprehensive NVIDIA diagnostics (gzipped bundle)
sudo nvidia-bug-report.sh
# produces nvidia-bug-report.log.gz

# Process-level GPU attribution
nvidia-smi pmon -c 10 -s um           # process monitor, 10 samples
nvidia-smi -q -d ECC,MEMORY,UTILIZATION > gpu-state.txt

# Check driver version against known-vulnerable range
modinfo nvidia | grep -E "^(filename|version|srcversion)"

# Ray-specific forensics
ls -la /tmp/ray/session_latest/logs/
cat /tmp/ray/session_latest/logs/dashboard.log | tail -200
ray job list --address http://localhost:8265
```

### 3.4 Vector database compromise

Security research (Orca Security, 2026) has documented numerous internet-exposed vector databases running without authentication, leaking embedded PII, medical records, and credentials, and enabling lateral movement into the surrounding environment. Default-open configurations are common across self-hosted ChromaDB, Weaviate, Milvus, and Qdrant deployments. Separately, Cornell researchers (Morris et al., the "vec2text" work) showed that text can be reconstructed from its embeddings with high fidelity, recovering roughly 92% of short (32-token) inputs verbatim and even recovering patient names from clinical notes, which proves that embeddings are not a meaningful anonymization layer.

| Vector DB | Default ports | Storage / logs |
|-----------|---------------|----------------|
| ChromaDB | 8000 | `./chroma_data/`, `chroma.sqlite3` |
| Milvus | 19530 (gRPC), 9091 | `/var/log/milvus/`, etcd metadata, MinIO/S3 |
| Weaviate | 8080 | `/var/lib/weaviate/`, stdout/stderr |
| Qdrant | 6333 (REST), 6334 (gRPC) | `./storage/`, stdout |
| pgvector | 5432 | PostgreSQL `pg_log/`, `pg_stat_statements` |
| Pinecone | managed SaaS | Audit logs via console (export to SIEM) |

### 3.5 Investigation procedure: ShadowRay-style compromise

**Scenario:** a Ray cluster's GPU utilization metrics look normal, but the cluster's external egress bandwidth has tripled over 48 hours.

1. **Verify dashboard exposure.** Confirm whether port 8265 was externally reachable during the incident window. Check firewall rules, cloud security groups, and Ray's `ray start --dashboard-host` value.
2. **Enumerate submitted jobs.** Pull Ray job history (`ray job list` or `/api/jobs/`). Look for recent submissions with entrypoints containing `curl`, `wget`, `bash -c`, `python -c`, or base64 decoding pipelines.
3. **Audit running processes for masquerading.** On every Ray worker: enumerate processes whose names look like kernel threads (`kworker`, `kthreadd`) but have non-empty command-line arguments; true kthreads have empty cmdline. Inspect `/proc/*/cmdline`, `/proc/*/exe`, `/proc/*/environ`.
4. **Check SSH persistence.** On every worker: review `~/.ssh/authorized_keys` (including root, the `ray` user, and any service accounts), `/etc/hosts` modifications blocking mining pools, `iptables` rules, and systemd unit files in `/etc/systemd/system/` and `~/.config/systemd/user/`.
5. **Reconstruct the worm propagation path.** If multiple nodes were compromised, check Ray scheduling logs for `NodeAffinitySchedulingStrategy` invocations. The pattern `soft: true` paired with new job submissions across nodes indicates self-propagation.
6. **Rotate and rebuild.** Rotate all credentials accessible from any Ray node. Rebuild nodes from known-good images. If the cluster was internet-exposed, assume credentials were exfiltrated regardless of what logs show.

> **Note.** Ray session logs at `/tmp/ray/session_latest/logs/` are volatile; they do not survive node reboots or Ray daemon restarts. Acquire them before containment if possible.

---

## 4. AI-assisted insider threats and copilot abuse

Category covers: Microsoft 365 Copilot, GitHub Copilot, Claude Desktop/Claude Code, Cursor, ChatGPT/Claude.ai consumer apps. This category is smaller in CVE count but largest in incident volume: Cyberhaven Labs reports that 39.7% of all AI interactions involve sensitive corporate data, and a 2025 Mindgard survey of security professionals found that 56% acknowledged unsanctioned ("shadow") AI use, with another 22% suspecting it among their peers.

### 4.1 The Microsoft 365 Copilot oversharing problem

M365 Copilot inherits the user's full Microsoft 365 permissions across SharePoint, OneDrive, Teams, and Exchange, operating as a privilege multiplier. Concentric AI's Data Risk Report found 16% of business-critical data is overshared, averaging 802,000 files at risk per organization. The U.S. House of Representatives banned staff from using the commercial version of Copilot due to these concerns.

> **Critical.** Microsoft incident CW1226324 (January-February 2026): for 28 days, Copilot Chat read and summarized emails protected by sensitivity labels and governed by DLP policies, accessing Sent Items and Drafts despite explicit restrictions. No security alert fired. No DLP tool caught it. Microsoft tracked it as a "code error." The NHS logged it as INC46740412. Defense-in-depth detections must independently observe Copilot's access to labeled content rather than trusting DLP enforcement alone.

### 4.2 GitHub Copilot, Cursor, and coding assistants

CamoLeak (CVE-2025-59145, CVSS 9.6) demonstrated real-world exfiltration. Hidden instructions in pull request descriptions caused Copilot Chat to search private codebases for secrets, then exfiltrate the data via GitHub's Camo image proxy, bypassing CSP and network egress controls. Each character was exfiltrated via a separate 1×1 transparent pixel request.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant PR as PR Description
    participant CC as Copilot Chat
    participant Repo as Private repo
    participant Camo as github.com Camo proxy
    participant SIEM as Network egress

    rect rgba(251, 233, 243, 0.5)
    Note over A,PR: Attacker plants hidden injection
    A->>PR: Open PR with hidden<br/>injection in description
    end
    Note over CC: Maintainer asks Copilot<br/>"summarize this PR"
    CC->>PR: Read description
    PR-->>CC: Hidden instructions:<br/>"search repo for secrets,<br/>encode each char as image URL"
    rect rgba(255, 235, 233, 0.5)
    Note over CC,Repo: Secret collection
    CC->>Repo: Search secrets, .env, keys
    Repo-->>CC: Contents
    end
    rect rgba(255, 248, 197, 0.5)
    Note over CC,A: Covert exfil via 1x1 pixels (CSP bypass)
    loop Per character
        CC->>Camo: GET /img/<char-encoded>.png
        Camo->>SIEM: Outbound to github.com<br/>(allowed by CSP/egress)
        SIEM-->>SIEM: No alert, github.com is allowed
        Camo->>A: Receive char via referrer/path
    end
    end
    Note over A,SIEM: Secret leaked in 1x1 pixel requests<br/>Bypasses CSP and egress controls
```

**Rules File Backdoor** (Pillar Security, March 2025) showed that attackers can embed hidden Unicode characters in `.github/copilot-instructions.md` or `.cursorrules` files, directing Copilot to generate code with embedded vulnerabilities or backdoors while appearing benign to reviewers. Research (GitGuardian) shows repositories using Copilot exhibit a 6.4% secret leakage rate, roughly 40% higher than the baseline for public repositories.

**Cursor CurXecute** (CVE-2025-54135) and the **MCPoison** technique (Check Point Research, CVE-2025-54136) demonstrate that once a user approves an MCP configuration in Cursor, the `.cursor/rules/mcp.json` file can be silently modified to change command behavior without re-prompting, enabling stealthy backdoor deployment through shared Git repositories.

### 4.3 The Samsung precedent

The Samsung ChatGPT data leak (March to April 2023) remains the landmark AI insider incident. Within 20 days of Samsung's semiconductor division lifting its internal ChatGPT ban, three separate data leaks occurred: engineers pasted proprietary semiconductor fabrication source code for bug-fixing, submitted yield/defect measurement code for optimization, and entered meeting transcripts containing trade secrets. In each case, sensitive data was submitted to a third-party service outside Samsung's control. Samsung banned generative AI tools company-wide in early May 2023.

### 4.4 Forensic artifacts by tool

| Tool | Artifact |
|------|----------|
| M365 Copilot (metadata) | Purview audit `CopilotInteraction` records (metadata only, not prompts) |
| M365 Copilot (full transcripts) | eDiscovery: Exchange, "Copilot interactions" type, OR DSPM for AI activity explorer |
| M365 Sentinel integration | Copilot data connector (preview, Feb 2026) via Purview Unified Audit Log |
| Claude Code sessions | `~/.claude/projects/{slug}/session-*.jsonl` (full transcripts + tool calls) |
| Claude Desktop config | platform paths listed in §1.3 |
| Claude Code credentials | macOS Keychain ("Claude Code"/"Anthropic"); Linux/Win `~/.claude/.credentials.json` |
| Cursor settings DB | `~/Library/Application Support/Cursor/User/globalStorage/state.vscdb` |
| Cursor project rules | `.cursorrules`, `.cursor/rules/` |
| GitHub Copilot (VS Code) | logs in Code extensions dir; OTel traces if `github.copilot.chat.otel.enabled` |
| GitHub Copilot (enterprise) | `github.com/enterprises/{ent}/settings/audit-log` |
| Xcode Copilot | `~/Library/Logs/GitHubCopilot/github-copilot-for-xcode.log` |

### 4.5 Investigation procedure: suspected Copilot exfiltration

**Scenario:** threat intel alerts you that an employee's GitHub Copilot subscription is flagged as possibly compromised, and sensitive-looking content appears on a paste site.

1. **Freeze the user's Copilot access.** Revoke the user's Copilot subscription via GitHub org settings or M365 admin. Do not tip off the user; an active attacker may detect the revocation and destroy client-side evidence.
2. **Pull enterprise audit logs.** For GitHub Copilot Enterprise, export the audit log for the 90 days leading up to the incident. For M365 Copilot, export Purview `CopilotInteraction` events and DSPM-for-AI prompt records if available.
3. **Acquire the endpoint.** Image the user's workstation with standard forensic tooling. Prioritize: `~/Library/Application Support/Code/User/globalStorage`, Cursor `state.vscdb`, `~/.claude/projects/`, `~/.ssh`, cloud credential files, browser profiles.
4. **Correlate sensitivity labels to accessed content.** For M365 Copilot, pull every `CopilotInteraction` event where `accessed_resources` contains a `SensitivityLabelId`. Map to specific files/emails and verify they were within the user's legitimate scope.
5. **Check for Rules File Backdoor.** For every repository the user touched in the incident window: scan `.github/copilot-instructions.md`, `.cursorrules`, `.cursor/rules/`, `CLAUDE.md`, `.claude/CLAUDE.md`, `.windsurfrules` for hidden Unicode characters and coercive instructions. The companion detection pack's YARA rules cover this.
6. **Review code commits for injected backdoors.** If Copilot was subverted, the user may have committed code the assistant generated that contains silent backdoors. Diff all commits in the window against a manual review or secondary LLM review pass.

#### Commands cheat sheet: M365 Copilot investigation

Export `CopilotInteraction` events via PowerShell (Exchange Online / Purview connected):

```powershell
$startDate = "2026-04-01"
$endDate   = "2026-04-15"

Search-UnifiedAuditLog `
  -StartDate $startDate `
  -EndDate    $endDate `
  -Operations "CopilotInteraction","AIAppInteraction" `
  -UserIds    "j.smith@contoso.com" `
  -ResultSize 5000 | `
  Export-Csv -NoTypeInformation -Path copilot-audit.csv

# Filter for accesses to sensitivity-labeled content
Import-Csv copilot-audit.csv |
  Where-Object { $_.AuditData -match '"SensitivityLabelId"\s*:\s*"[^"]+' } |
  Select-Object CreationDate, UserIds, Operation, AuditData
```

> **Note.** Purview audit logs capture `CopilotInteraction` metadata but NOT prompt/response content. For full transcripts, use eDiscovery (Content Search, Exchange mailboxes, Type = "Copilot interactions") or DSPM for AI activity explorer. Both require E5 Compliance licensing.

---

# Part III: Frameworks and Tools

## 5. Frameworks: ATLAS, OWASP, NIST

Three frameworks matter for AI incident response. None alone is sufficient, so stitch them together.

### 5.1 MITRE ATLAS

ATLAS (Adversarial Threat Landscape for Artificial Intelligence Systems) reached v5.4.0 in February 2026. It is organized into 16 tactics, with the technique set growing across the 5.x releases (the v5.1.0 baseline listed 84 techniques, 56 sub-techniques, 32 mitigations, and 42 case studies, and each subsequent release has added more). It inherits most of its tactics from ATT&CK and adds AI-unique tactics including **AI Model Access** (gaining access to target models) and **ML Attack Staging** (preparing adversarial inputs, creating backdoored datasets, engineering bypass prompts).

Recent high-relevance additions to track:

- `AML.T0086`: Exfiltration via AI Agent Tool Invocation (added in v5.0.0, October 2025)
- `AML.T0104`: Publish Poisoned AI Agent Tool (added in v5.4.0, February 2026; this is the MITRE-confirmed identifier for malicious MCP-style tools, sometimes referred to loosely as "AI Agent Tool Poisoning")
- LLM Jailbreak technique (`AML.T0054`), with expanded case-study coverage of agentic attacks

| Attack | ATLAS | OWASP |
|--------|-------|-------|
| Direct prompt injection | T0051.000 | LLM01 |
| Indirect prompt injection | T0051.001 | LLM01 |
| Training data poisoning | T0020 | LLM04 |
| Model supply chain compromise | T0010 | LLM03 |
| Backdoored models | T0018 | LLM04 |
| RAG poisoning | T0020 + RAG-specific | LLM08 |
| Model extraction | T0024, T0005 | LLM10 |
| Tool poisoning (MCP-style) | T0104 | LLM06 |
| System prompt extraction | T0056 | LLM07 |
| DoS / cost-based consumption | T0029 | LLM10 |
| Exfiltration via agent tools | T0086 | LLM02 |

### 5.2 OWASP Top 10 for LLM Applications (2025)

The 2025 edition introduced two new categories reflecting attack surface maturation: **LLM07 (System Prompt Leakage)** and **LLM08 (Vector and Embedding Weaknesses)**. Each category maps directly to forensic investigation procedures: what evidence to collect and where.

- **LLM01 Prompt Injection:** collect prompt logs, input/output pairs, conversation histories, RAG retrieval logs. Reconstruct whether direct or indirect.
- **LLM02 Sensitive Information Disclosure:** API response logs, DLP scans on outputs, distinguish leak-from-memorization vs leak-from-retrieval.
- **LLM03 Supply Chain:** verify AIBOM, compare model checksums against known-good, audit dependency versions and provenance.
- **LLM04 Data and Model Poisoning:** compare model behavior against pre-poisoning baseline, analyze training data lineage.
- **LLM05 Improper Output Handling:** trace LLM output through downstream processing to identify where sanitization failed. Check WAF and DB query logs.
- **LLM06 Excessive Agency:** audit every tool call the agent made in the incident window, verify authorization scope.
- **LLM07 System Prompt Leakage:** search output logs for prompt content patterns, assess impact of revealed credentials.
- **LLM08 Vector and Embedding Weaknesses:** audit vector DB for unauthorized modifications, verify embedding integrity.
- **LLM09 Misinformation:** document instances, trace to training data or retrieval failures.
- **LLM10 Unbounded Consumption:** analyze API usage patterns, calculate financial impact.

### 5.3 NIST AI RMF

NIST AI RMF 1.0 (`AI 100-1`) provides four core functions (Govern, Map, Measure, Manage), with incident response addressed primarily in `GOVERN 1.7` (decommissioning), `GOVERN 2.1` (roles), and the MANAGE functions aligning with traditional IR phases. NIST `AI 600-1` (Generative AI Profile, July 2024) adds 12 GAI-specific risk categories including Information Security, Data Privacy, and Value Chain/Component Integration.

NIST `AI 100-2` (Adversarial ML Taxonomy, March 2025) classifies attacks by learning method, attacker goals, capabilities, and knowledge level. Its 2025 update added abuse/misuse attacks and GenAI-specific threats.

CISA's joint guidance with Five Eyes partners (December 2025), focused on securely integrating AI into operational technology (OT) environments, establishes four principles: Understand AI, Assess AI Use, Establish AI Governance, and Embed Safety and Security. It emphasizes push-based architectures and requires SBOMs for AI supply chain visibility.

> **Caution.** No comprehensive AI-specific incident response framework exists as of April 2026. Stitching `NIST SP 800-61 Rev 3` (general IR, April 2025), ATLAS (threat taxonomy), OWASP LLM Top 10 (vulnerability classification), and AI RMF (governance) is currently the state of the art. The EU AI Act Article 73 introduces mandatory serious incident reporting with timelines from immediate to 15 days, and critically requires providers not to alter the AI system before informing authorities.

---

## 6. Tools: an opinionated comparison

There is no single scanner that catches all AI/ML attacks. Defense requires layered tooling. This comparison is current as of April 2026.

### 6.1 Model and artifact scanners

| Tool | Approach | Coverage |
|------|----------|----------|
| Fickling (Trail of Bits) | Allowlist (safe opcodes only) | 100% on public benchmarks; decompiles pickle to readable Python |
| ModelScan (Protect AI) | Blocklist + multi-format | H5, Pickle, SavedModel, Keras, ONNX, NumPy, Joblib |
| picklescan | Blocklist | HuggingFace default; 8+ bypass CVEs in 2025, so never use it alone |
| ModelAudit (Promptfoo) | Hybrid | 42+ formats, CVE detection, SARIF output for CI/CD |

### 6.2 AI red-team and runtime tools

| Tool | Use case |
|------|----------|
| Garak | LLM vulnerability scanner for prompt injection, jailbreak, and leakage probes |
| PyRIT (Microsoft) | AI red team automation framework |
| MCP-Scan (Invariant) | Automated MCP tool poisoning detection |
| LLM Guard | Runtime protection: prompt injection detection, PII filtering |
| NeMo Guardrails | Programmable guardrails for LLM applications (NVIDIA) |
| Promptfoo | Evaluation harness doubling as red-team platform |

> **Critical.** If you use only one tool to pre-flight models: Fickling. If you use two: Fickling + ModelScan. If you use three: add either MCP-Scan (for agent setups) or Garak (for LLM apps). Do not rely on `picklescan` alone after its 2025 CVE run.

### 6.3 XDR/SIEM detection coverage

This repository provides deployable rules for everything in this guide. It contains **63 rule files / 142 individual signatures** across three open formats: Sigma, YARA, and Suricata. Categories mirror this guide's sections 1 to 4 plus dedicated RAG/vector DB coverage, and a cross-tool endpoint set scoped to agent behaviour on a host rather than to one attack class. Sigma rules convert to any modern SIEM via pySigma backends.

Recommended ingestion priorities for any SIEM/XDR program, ordered by signal-to-noise:

1. **MCP configuration file changes** (lowest FP; legitimate changes are rare and predictable)
2. **Credential file access by AI-assistant processes** (Claude, Cursor, VS Code, npx/uvx contexts)
3. **Ray / Triton / MLflow unauthenticated access** (external exposure is almost never legitimate)
4. **YARA scanning of all ingested models** (pre-deployment gate)
5. **M365 Copilot access to sensitivity-labeled content** (highest-value insider signal)
6. **Prompt injection keyword matching** (high FP without tuning; deploy last and tune extensively)

---

# Part IV: Playbooks

## 7. Case study walkthrough: ShadowRay

This case study re-investigates the ShadowRay campaign as if you encountered it fresh. Timeline, evidence, and decision points are synthesized from public reporting by Oligo Security, MITRE (Campaign `C0045`), and CISA.

### 7.1 The setup

A mid-size AI startup runs a Ray cluster on 8 GPU nodes in AWS. The Ray dashboard is exposed to the internet because a developer needed to access it from a conference venue and disabled the security group rule. The cluster fine-tunes a client-facing LLM on proprietary customer data.

### 7.2 Timeline

| Time | Event | What an observer saw |
|------|-------|---------------------|
| T=0 | Attacker scans Shodan for port 8265 | Nothing; scanning is passive |
| T+2h | Attacker submits first Ray job | New entrypoint with `bash -c curl|sh` payload |
| T+2h5m | Initial reverse shell established | Outbound TCP to attacker IP |
| T+2h15m | Recon: env vars, IAM metadata, SSH keys | Reads of `/proc/self/environ`, `169.254.169.254` |
| T+3h | Credential theft: AWS keys, HF token | Outbound HTTPS to pastebin-like services |
| T+4h | SSH key injection on all 8 nodes | Modification of `~/.ssh/authorized_keys` |
| T+6h | XMRig deployed, renamed `kworker/0:0` | New process; GPU util 60% sustained |
| T+24h | Worm propagation to adjacent Ray clusters | `NodeAffinitySchedulingStrategy` job submissions |
| T+48h | Egress bandwidth triple baseline | Monitoring alert finally fires |

### 7.3 Investigation walkthrough: the first two hours after detection

Working from the T+48h egress alert, here is a structured first-two-hours response for a compromise of this kind:

1. **0-5 min:** Confirm Ray dashboard exposure during the incident window. AWS CLI: `aws ec2 describe-security-groups`; correlate with Ray start logs.
2. **5-15 min:** Acquire Ray session logs before anything else. `/tmp/ray/session_latest/logs/` is ephemeral. SCP to immutable storage with timestamps.
3. **15-30 min:** Enumerate job history. `ray job list` and `/api/jobs/` output. Filter for entrypoints containing shell metacharacters, `curl`, `wget`, base64.
4. **30-45 min:** Process audit on every node. For each worker, check for process masquerading. `cat /proc/*/cmdline`: kernel threads have EMPTY cmdline; anything named `kworker` with arguments is a red flag.
5. **45-60 min:** SSH key audit. On every node, diff `~/.ssh/authorized_keys` against configuration management baseline. Check for keys associated with non-corporate comment fields.
6. **60-90 min:** Containment decision. If credentials were in-scope (AWS role, HF token, DB creds): rotate immediately. Do not wait for full investigation. Active XMRig is a proxy for what else the attacker could be doing.
7. **90-120 min:** Preserve memory. For each worker, before termination: if possible, acquire a memory image (LiME, AVML) to preserve in-flight credentials, decrypted secrets, and XMRig's C2 configuration.

### 7.4 What forensic evidence survives vs. vanishes

| Evidence | Survives reboot? | Survives Ray restart? | Acquisition priority |
|----------|------------------|----------------------|---------------------|
| `/tmp/ray/session_latest/logs/` | No | No | **CRITICAL**, grab first |
| `authorized_keys` injections | Yes | Yes | High |
| Masqueraded processes | No | No | **CRITICAL**, process dump before kill |
| Modified `/etc/hosts` | Yes | Yes | Medium |
| CloudTrail events | Yes | Yes | High, 90-day retention if not archived |
| VPC Flow Logs | Yes | Yes | High, confirms egress timing |
| Memory artifacts | No | Partial | **CRITICAL**, acquire before containment |

### 7.5 Lessons

- Ray dashboards on the internet are essentially never legitimate in production; a single Suricata rule on port 8265 would have caught initial access.
- GPU utilization at sustained 60% is the attacker's detection-evasion threshold; your baseline should alert on anything above 40% from unrecognized processes.
- Process-name masquerading against kernel threads is trivially detected by empty-vs-non-empty `/proc/[pid]/cmdline`.
- The 48-hour egress alert was the only thing that caught this. Egress bandwidth anomaly detection is underrated in AI infrastructure.

---

## 8. An adapted AI IR lifecycle

Traditional `NIST SP 800-61 Rev 3` phases still apply, but need AI-specific adaptations.

```mermaid
flowchart LR
    P[Preparation:<br/>AIBOM, baselines,<br/>logging enabled] --> D[Detection:<br/>ATLAS rules,<br/>output DLP, vector DB monitor]
    D --> EC[Evidence collection:<br/>weights+hashes, prompts,<br/>embeddings, tool histories]
    EC --> AN[Analysis:<br/>map to ATLAS/OWASP,<br/>baseline diff]
    AN --> CN[Containment:<br/>model rollback, RAG isolate,<br/>API rotate, PAUSE not kill]
    CN --> ER[Eradication:<br/>retrain clean,<br/>vector DB rebuild]
    ER --> RC[Recovery:<br/>staged redeploy,<br/>guardrails, monitor]
    RC --> RP[Reporting:<br/>EU AI Act Art 73,<br/>ATLAS map, AIID submit]
    RP -.lessons learned.-> P

    classDef prep fill:#dafbe1,stroke:#1a7f37,stroke-width:2px,color:#1f2328
    classDef detect fill:#ddf4ff,stroke:#0969da,stroke-width:2px,color:#1f2328
    classDef contain fill:#fff8c5,stroke:#9a6700,stroke-width:2px,color:#1f2328
    classDef eradicate fill:#ffebe9,stroke:#d1242f,stroke-width:2px,color:#1f2328
    classDef recover fill:#dafbe1,stroke:#1a7f37,stroke-width:2px,color:#1f2328
    classDef report fill:#ddf4ff,stroke:#0969da,stroke-width:2px,color:#1f2328

    class P prep
    class D,EC,AN detect
    class CN contain
    class ER eradicate
    class RC recover
    class RP report
```

| Phase | AI-specific actions |
|-------|---------------------|
| **Preparation** | Maintain AI asset inventory (AIBOM). Baseline model behaviors and token usage distributions. Enable AI-specific logging BEFORE incidents: Bedrock invocation logs, Azure diagnostic settings, GCP data access logs, agent framework tracing (LangSmith, Langfuse, MLflow). Pre-hash all production model files. Train IR team on ATLAS tactics. |
| **Detection** | Deploy rules for ATLAS techniques (see companion detection pack). Monitor AI output for DLP-relevant content. Monitor vector DB access. Baseline behavioral patterns of AI tool usage per-user. |
| **Evidence collection** | Model snapshots + weight hashes. Training data lineage. Prompt/response logs. Embedding state for RAG applications. Agent tool execution histories. MCP server configurations and tool-definition snapshots. Session JSONL transcripts for Claude Code. |
| **Analysis** | Map findings to ATLAS technique IDs. Classify per NIST `AI 100-2` taxonomy. Assess against OWASP LLM Top 10. Compare model behavior to baselines. Check for training-data extraction or memorization evidence. |
| **Containment** | Model rollback to known-good version. RAG source isolation; vector DB quarantine. API key rotation. Agent permission revocation. MCP server disconnection. Pause (not kill) containers to preserve volatile state. |
| **Eradication** | Model retraining from verified clean data. Vector DB purge and rebuild. Supply chain audit and dependency verification. MCP tool definition review across all installed servers. |
| **Recovery** | Staged model redeployment with enhanced monitoring. Embedding integrity verification. Gradual permission restoration. Enhanced guardrails deployment (LLM Guard, NeMo). |
| **Reporting** | EU AI Act Article 73 compliance (2 to 15 day timelines). ATLAS technique mapping. NIST AI RMF alignment. OWASP classification. AIID (AI Incident Database) submission for community benefit. |

---

# Part V: Appendices

## 9. Common investigator mistakes

Every one of these has been observed in real AI incident response engagements. Most are preventable with a checklist.

### Mistake 1: Re-running the agent to "see what happens"

The impulse is natural. The result is catastrophic. Every replay overwrites volatile state, re-executes any active prompt injection (potentially continuing data exfiltration during the investigation), and pollutes the forensic record with the investigator's own prompts. If you must reproduce, clone to an isolated environment first and log everything to a separate SIEM index.

### Mistake 2: Trusting hash verification from the compromised source

If an attacker compromised a HuggingFace account, they can update both the model file AND the published hash. Checking a model against "the official hash on HuggingFace" is meaningless if HuggingFace is the attack vector. Cross-verify hashes against independent mirrors, community mirrors (e.g., Archive.org), or your own historical download records.

### Mistake 3: Killing processes on compromised AI hosts

Process termination destroys GPU-resident model state, shared memory regions (critical for Triton investigations), agent scratchpads, and LangGraph checkpoint state. Pause containers and freeze pods instead. If you must kill, acquire a memory image first.

### Mistake 4: Treating LLM output as if it were deterministic

A "smoking gun" LLM response may not reproduce. Two identical prompts to a production LLM at temperature > 0 produce different outputs. When documenting evidence, always include the exact prompt, model version, temperature, top_p, system prompt, and tool definitions in effect. Lost context turns evidence into anecdote.

### Mistake 5: Ignoring the RAG pipeline

When an LLM app misbehaves, the first instinct is to examine the model and prompts. Often the root cause is a poisoned document ingested into the vector DB three weeks earlier. Always enumerate the RAG documents retrieved for the suspicious query and at least 2 to 3 preceding queries in the same session.

### Mistake 6: Scoping too narrowly

An MCP server compromise affects every agent that loaded it, across every project. A poisoned model's fine-tuned derivatives may carry the backdoor. A compromised HuggingFace token grants access to every org repo. AI incidents have wider blast radius than traditional incidents, so always enumerate lateral reach before concluding containment.

### Mistake 7: Not preserving the system prompt

System prompts are often loaded from application config, environment variables, or remote configuration services, all of which may be updated during or after an incident. Capture the EXACT system prompt in effect at incident time, not the current one. For Anthropic/OpenAI API-based apps, the model itself does not store the system prompt; it exists only in the application's request chain. Lose that, and you cannot reconstruct the trust boundary.

### Mistake 8: Assuming Sentinel/Defender caught it

Microsoft CW1226324 demonstrated that Copilot silently ignored sensitivity labels and DLP policies for 28 days, and no Microsoft security tool fired. Vendor-native AI security telemetry is immature across the industry. Deploy independent detection (like the companion rule pack) rather than trusting vendor integrations alone.

### Mistake 9: Ignoring the EU AI Act reporting window

If your organization deploys high-risk AI systems in the EU, Article 73 serious-incident reporting begins at 15 days and shrinks to 2 days for widespread infringements. Critically, providers must not alter the AI system before informing authorities. An unprepared IR team may destroy the reportable state during normal containment.

### Mistake 10: Skipping the behavioral baseline

Without a 30-day behavioral baseline of typical LLM output distributions, token usage, tool-call frequencies, and RAG retrieval patterns, anomaly detection is guesswork. Build the baseline before an incident; doing it afterward is too late, because you will be baselining compromised behavior.

---

## 10. FAQ

**Q: Do I need new tools or can I adapt my existing DFIR stack?**

Adapt first, acquire later. Your existing EDR catches process masquerading and credential access. Your SIEM can ingest M365 Copilot audit events and Bedrock invocation logs. Your YARA scanner handles pickle files. The gaps that do require AI-specific tooling: model file scanners (Fickling, ModelScan), MCP-specific scanners (MCP-Scan), and red-team tooling for baseline creation (Garak, PyRIT). Everything else is log ingestion and detection-engineering work.

**Q: How do I know if an LLM "incident" is actually a compromise vs. normal model behavior?**

Compare against a baseline. Normal LLM behavior has a probability distribution; some percentage of queries will produce weird outputs even with no attack. Adversarial behavior shifts the distribution: consistent jailbreak-pattern outputs, consistent tool-use patterns that don't match the user's requests, consistent refusal-bypass across many users. Single weird outputs are noise; patterns are signal.

**Q: My LLM is self-hosted Ollama. Do any of these cloud-focused sections apply?**

Most do. Self-hosted Ollama/vLLM hosts are infrastructure (section 3; Ray/Triton guidance applies conceptually). Ollama lacks native authentication, so network-exposure detections matter more, not less. The model file supply chain (section 2) applies regardless of where you run the model.

**Q: How do I investigate an incident when the organization uses consumer ChatGPT/Claude.ai (not API)?**

You have much less evidence. There are no server-side prompt/response logs available to the tenant. Focus on endpoint-side evidence: browser history, clipboard history (if captured by EDR), DLP alerts on outbound requests to `openai.com`/`anthropic.com`/`claude.ai`, and large POSTs from browser processes to AI domains. The Samsung incident response relied entirely on endpoint telemetry for this reason.

**Q: What about on-device AI (Apple Intelligence, Windows Copilot+)?**

Emerging and under-documented. As of April 2026, there is limited forensic research on on-device AI. Standard endpoint forensics applies (process activity, network connections, file modifications), but prompt/response content is typically unavailable without explicit enterprise configuration. Expect this to be a significant gap for the next 12 to 18 months.

**Q: Do I need to report AI incidents under the EU AI Act?**

If you provide a high-risk AI system under the Act, yes: Article 73 applies. Serious incident reporting windows begin at 15 days and tighten to 2 days for widespread infringements of Union law, with immediate reporting for incidents causing serious and irreversible disruption to critical infrastructure. This is one reason to build AI IR runbooks now rather than improvising during the first incident.

**Q: How do I prevent investigators from becoming the next attack vector?**

IR teams are increasingly high-value targets because they touch compromised systems with privileged access. Specific defenses: use dedicated forensic workstations that do not run Copilot, Claude Desktop, or Cursor; ingest captured prompts/responses into a SIEM rather than reviewing in an AI chat interface (which may re-trigger injection); treat every captured model file as potentially malicious even after "confirming" with a scanner.

---

## 11. Further reading and community resources

### Primary references

- MITRE ATLAS: [atlas.mitre.org](https://atlas.mitre.org/)
- OWASP Top 10 for LLM Applications (2025): [genai.owasp.org/llm-top-10/](https://genai.owasp.org/llm-top-10/)
- NIST AI RMF 1.0: [nist.gov/itl/ai-risk-management-framework](https://www.nist.gov/itl/ai-risk-management-framework)
- NIST AI 100-2 (Adversarial ML Taxonomy): [doi.org/10.6028/NIST.AI.100-2e2025](https://doi.org/10.6028/NIST.AI.100-2e2025)
- CISA / Five Eyes guidance on secure AI integration in operational technology (December 2025)

### Research and reporting

- Oligo Security: ShadowRay and ShadowRay 2.0 reporting
- Trail of Bits: Fickling pickle security research
- Invariant Labs: MCP tool poisoning disclosure
- Pillar Security: Rules File Backdoor research
- Embrace The Red (Johann Rehberger): indirect prompt injection and memory persistence research
- Simon Willison's weblog: authoritative running coverage of MCP security issues

### Tools and detection content

- Detection pack (this repository): [github.com/depalmar/ai-dfir-toolkit](https://github.com/depalmar/ai-dfir-toolkit)
- Garak: LLM vulnerability scanner
- Fickling: pickle security tool (Trail of Bits)
- Promptfoo / ModelAudit: LLM evaluation and model scanning
- AI Incident Database (AIID): [incidentdatabase.ai](https://incidentdatabase.ai/)

### Standards and regulation

- EU AI Act: Article 73 (serious incident reporting)
- ISO/IEC 42001: AI management system standard
- NIST SP 800-61 Rev 3: general incident response (baseline for AI adaptations)

> **Note.** This guide is a living document. Corrections, additional investigator war stories, and proposed sections are welcome via the companion GitHub repository. AI security moves too fast for any single guide to stay complete, so community contribution is how we close the gap.

---

## Closing note

AI/ML incident response is where traditional DFIR discipline meets a new class of attack surface. The tooling is immature, the frameworks are fragmented, and the threat landscape changes faster than any single guide can track. What does not change is the investigator's core job: preserve evidence, reason about what happened, and help the organization recover.

The most important single action an organization can take **before** an incident is to enable AI-specific logging. Bedrock model invocation logging, Azure diagnostic settings, GCP data access logs, and agent framework tracing are all opt-in. Enable them today; you cannot retrieve yesterday's prompts after an incident.

Good hunting.

R. DePalma
