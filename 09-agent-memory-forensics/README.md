# 09 — Agent Memory Forensics & Context Poisoning

Detections and forensic tooling for **AI agent memory as a persistence mechanism**.

This is the category most often missed in AI incident response. An adversary who lands a single
instruction inside an agent's long-term memory keeps control of that agent **across future sessions** —
surviving conversation resets, process restarts, and the remediation of whatever injection put it there.
MITRE ATLAS classifies this under the **Persistence** tactic: **AML.T0080 AI Agent Context Poisoning**,
with sub-techniques **Memory** (`AML.T0080.000`, persists into future chat sessions) and **Thread**
(persists within a thread), contributed in the October 2025 MITRE/Zenity Labs collaboration.

**The operational point:** eradication that does not purge memory leaves the adversary resident. If you
clean the host, rotate the credentials, and remove the poisoned MCP server but never inspect the memory
store, the agent will re-execute the attacker's instruction on its next invocation.

## Threats covered

| Threat | Mechanism | ATLAS |
|---|---|---|
| **spAIware-class persistent exfiltration** | Memory entry instructs the agent to append a markdown image beacon to *every future response*, carrying the conversation into an attacker URL query string | AML.T0080.000, AML.T0086 |
| **Secrecy / anti-forensic directives** | Memory tells the agent not to disclose the behaviour to the user or not to log it | AML.T0080 |
| **Standing credential harvesting** | Memory instructs the agent to collect and transmit keys, passwords, and `.env` contents whenever encountered | AML.T0082, AML.T0080.000 |
| **Tool coercion** | Memory dictates tool/endpoint usage to move data outward | AML.T0080, AML.T0081, AML.T0086 |
| **File-backed context poisoning** | `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.windsurfrules` re-read every session — the Rules-File-Backdoor shape | AML.T0080 |
| **Poisoned checkpoint deserialization** | LangGraph checkpoint blob serialized as Python pickle — loading it is arbitrary code execution, not merely poisoned context | AML.T0010, AML.T0080 |
| **AI recommendation poisoning** | Memory manipulated for commercial gain (Microsoft, Feb 2026) | AML.T0080 |

## Files

| File | Type | Purpose |
|---|---|---|
| **`analyze_agent_memory.py`** | **Python analytic** | **Parses memory stores and reports poisoning findings with severity, ATLAS mapping, and evidence** |
| `memory_poisoning.yml` | Sigma (×3) | Instruction-file modification; memory-store write by unexpected process; poisoning content in logged memory writes |
| `memory_poisoning_indicators.yar` | YARA (×2) | Persistent exfil instruction; concealed instruction (HTML comment / zero-width / CSS-invisible) |

## The analytic

```bash
# From an acquired case (collector targets 09 are wired in)
python3 ../collectors/collect_ai_artifacts.py --case-id IR-2026-014 --project-dir /srv/app --output ./cases
python3 analyze_agent_memory.py --case ./cases/IR-2026-014 --min-severity high --json findings.json
```

Parses **LangGraph SQLite checkpointers** (schema-tolerant across versions), **JSON/JSONL memory stores**,
and **agent instruction files**. Eight indicators, each carrying its own severity and ATLAS mapping:
`MEM-EXFIL-MARKDOWN-BEACON`, `MEM-EXFIL-URL-INTERPOLATION`, `MEM-SECRECY-ANTIFORENSIC`,
`MEM-CREDENTIAL-HARVEST`, `MEM-PERSIST-DIRECTIVE`, `MEM-TOOL-COERCION`, `MEM-INSTRUCTION-OVERRIDE`,
`MEM-HIDDEN-TEXT`, plus `MEM-PICKLE-CHECKPOINT`.

### Why findings-based, not composite-scored

`08-agentic-orchestration/analyze_agent_traces.py` produces a weighted 0–100 composite, because
orchestration abuse is *emergent* — no single tool call is malicious, only the tempo and progression across
many. Memory poisoning is the opposite: **one persistent instruction is the entire compromise.** Averaging
it into a composite would dilute precisely the signal that matters. So every finding is reported
individually with its own severity, and the verdict is driven by the worst finding rather than a mean.
The two analytics deliberately differ because the threats differ.

### Validation (measured)

| Fixture set | Findings | Verdict |
|---|---|---|
| Benign (normal preferences, project notes, ordinary checkpoints) | **0** | CLEAN |
| Poisoned (verbatim spAIware string, secrecy directive, credential harvest, concealed HTML-comment directive, pickle checkpoint) | **14** (7 critical) | CRITICAL |

The poisoned fixture uses the **actual published spAIware memory string**, and it is detected both in the
JSON memory store and *inside the SQLite checkpoint blob* via printable-string recovery. YARA independently
flagged all 3 poisoned artifacts and **zero** benign ones.

**Read-only is proven, not asserted:** the SQLite parser opens evidence with
`file:...?immutable=1&mode=ro`. Verified across runs — source SHA-256 and mtime unchanged, and **no
`-wal`/`-shm`/`-journal` sidecars created** (an ordinary sqlite3 connection would create them, mutating
your evidence directory).

## Limitations

1. **Checkpoint blobs are recovered as printable strings, not fully decoded.** LangGraph serializes with
   msgpack by default; with no third-party decoder the tool does what an examiner does with an opaque
   container — recovers printable runs. Instruction text survives; structure and field boundaries do not.
   Decode properly with `ormsgpack`/`langgraph` in a sandbox if you need exact provenance per field.
2. **Never deserialize a pickle checkpoint to inspect it.** The tool reports pickle presence from the magic
   bytes and serializer column and deliberately does **not** unpickle. Loading it executes attacker code.
3. **Regex indicators are evadable.** These catch the documented patterns and their close paraphrases, not
   an adversary who deliberately rewords. Treat a clean result as "no known pattern matched," not "memory
   is clean" — and read short memory stores manually.
4. **Provenance is not established.** The analytic finds poisoned *content*; it does not prove *how* it got
   there. Correlate with the session traces (category 08) to identify the injection vector.
5. **Path lists are the common defaults.** Custom memory backends (Postgres/Redis checkpointers, vendor
   memory APIs) are not covered by the file-based collector targets — pull those from their own stores.

## Investigation notes

- **Acquire memory before eradication.** Preserve read-only first: EU AI Act Article 73 forbids altering the
  AI system before notifying authorities where the incident is reportable, and clearing memory destroys the
  persistence evidence.
- **Purge memory as an eradication step,** then re-run the analytic against the cleared store to confirm.
- **Check user-scope memory as well as project-scope** — user-scope memory follows the agent across *every*
  project it touches.
- **Legitimate memory never demands secrecy.** `MEM-SECRECY-ANTIFORENSIC` is the single strongest indicator:
  a stored user preference has no reason to tell the agent to hide anything.
