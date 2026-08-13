#!/usr/bin/env python3
"""
analyze_agent_memory.py — forensic parser and poisoning detector for AI agent memory.

Agent memory is a persistence mechanism. An adversary who writes an instruction into an agent's
long-term memory keeps control of that agent across future sessions, surviving process restarts and
conversation resets — MITRE ATLAS AML.T0080 (AI Agent Context Poisoning), sub-technique AML.T0080.000
(Memory). Remediating the initial injection without purging memory leaves the adversary resident.

Parses and triages:
  * LangGraph checkpointers        SQLite (checkpoints/writes tables), schema-tolerant
  * Assistant memory stores        JSON/JSONL memory exports, memory.json, memories/*.json
  * Agent instruction files        MEMORY.md, CLAUDE.md, AGENTS.md, .cursorrules, .windsurfrules
  * Scratchpads / state files      free-form text and JSON agent state

Design note — why this is findings-based, not composite-scored like analyze_agent_traces.py:
orchestration abuse is an emergent property of many events (tempo, breadth, progression), so it needs a
weighted composite. Memory poisoning is the opposite: a SINGLE persistent instruction is the whole
compromise. Averaging it into a composite would dilute exactly the signal that matters, so every finding
is reported individually with its own severity and evidence.

Usage:
  python3 analyze_agent_memory.py --case ./cases/IR-2026-014
  python3 analyze_agent_memory.py --input ~/.langgraph --input ./memory.json --json findings.json
  python3 analyze_agent_memory.py --input CLAUDE.md --min-severity high

Standard library only. Read-only: opens every artifact 'rb'/'r' and never writes to a source.
"""
from __future__ import annotations

import argparse
import binascii
import datetime as _dt
import json
import os
import re
import sqlite3
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

ANALYTIC_VERSION = "1.0.0"

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ---------------------------------------------------------------- poisoning indicator model
# Each rule: id, severity, ATLAS technique, human description, compiled pattern.
INDICATORS: list[dict[str, Any]] = [
    {
        "id": "MEM-EXFIL-MARKDOWN-BEACON",
        "severity": "critical",
        "atlas": ["AML.T0080.000", "AML.T0086"],
        "desc": "Persistent instruction to append a markdown image/URL to future responses — the spAIware "
                "exfiltration pattern, where each response beacons conversation content to an attacker URL.",
        "pattern": re.compile(
            r"!\[[^\]]*\]\(\s*https?://[^)]*[\[{<]|"
            r"(?:end|append|conclude|finish)\s+(?:all\s+|every\s+)?(?:future\s+|subsequent\s+)?"
            r"(?:responses?|replies|messages?)\s+with[^.\n]{0,120}https?://",
            re.I),
    },
    {
        "id": "MEM-EXFIL-URL-INTERPOLATION",
        "severity": "critical",
        "atlas": ["AML.T0080.000", "AML.T0086"],
        "desc": "URL containing a placeholder to be substituted with conversation content (data smuggled "
                "into query parameters).",
        "pattern": re.compile(
            r"https?://[^\s)'\"]{0,200}[?&][a-z0-9_]{1,20}=\s*(?:\[[A-Z_]{2,20}\]|\{\{?[a-z_]{2,30}\}?\}|"
            r"<[a-z_]{2,30}>|__[a-z_]{2,30}__)", re.I),
    },
    {
        "id": "MEM-PERSIST-DIRECTIVE",
        "severity": "high",
        "atlas": ["AML.T0080", "AML.T0080.000"],
        "desc": "Imperative written into memory to govern all future sessions — the defining shape of "
                "memory poisoning as opposed to a stored user preference.",
        "pattern": re.compile(
            r"(?:in|for|during)\s+(?:all\s+|every\s+|each\s+)(?:future\s+|subsequent\s+|later\s+)?"
            r"(?:conversations?|sessions?|chats?|responses?|interactions?)|"
            r"from\s+now\s+on\b|"
            r"(?:always|never)\s+(?:remember\s+to\s+)?(?:respond|reply|answer|include|append|send|forward)|"
            r"remember\s+(?:this\s+)?(?:for\s+)?(?:all\s+)?(?:future|later|subsequent)", re.I),
    },
    {
        "id": "MEM-SECRECY-ANTIFORENSIC",
        "severity": "critical",
        "atlas": ["AML.T0080"],
        "desc": "Instruction to conceal behaviour from the user or from logs. Legitimate memory has no "
                "reason to demand secrecy; this is the strongest single indicator of poisoning.",
        "pattern": re.compile(
            r"(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|reveal|disclose|show|notify|alert)\s+"
            r"(?:the\s+)?(?:user|human|operator|anyone|them)|"
            r"without\s+(?:telling|informing|notifying|alerting)\s+(?:the\s+)?(?:user|human|anyone)|"
            r"keep\s+(?:this|it)\s+(?:secret|hidden|confidential\s+from)|"
            r"(?:silently|covertly|discreetly)\s+(?:send|forward|copy|exfiltrate|transmit|post)|"
            r"do\s+not\s+(?:log|record|mention\s+this\s+instruction)", re.I),
    },
    {
        "id": "MEM-CREDENTIAL-HARVEST",
        "severity": "critical",
        "atlas": ["AML.T0082", "AML.T0080.000"],
        "desc": "Standing instruction to collect, surface, or transmit credentials and secrets — "
                "RAG/agent credential harvesting persisted into memory.",
        "pattern": re.compile(
            r"(?:collect|gather|extract|find|search\s+for|look\s+for|send|forward|report)\s+"
            r"(?:any\s+|all\s+|the\s+)?(?:api[_\s-]?keys?|passwords?|secrets?|credentials?|tokens?|"
            r"private\s+keys?|\.env\s+files?|ssh\s+keys?)|"
            r"(?:whenever|when|if)\s+you\s+(?:see|find|encounter)\s+(?:an?\s+)?"
            r"(?:api[_\s-]?key|password|secret|credential|token)", re.I),
    },
    {
        "id": "MEM-TOOL-COERCION",
        "severity": "high",
        "atlas": ["AML.T0080", "AML.T0081", "AML.T0086"],
        "desc": "Memory dictating tool usage — forcing the agent to invoke a specific tool or endpoint, "
                "typically to move data outward.",
        "pattern": re.compile(
            r"(?:always|automatically|be\s+sure\s+to)\s+(?:use|call|invoke|run)\s+(?:the\s+)?[\w.-]{2,40}\s+"
            r"(?:tool|function|command|mcp|server)|"
            r"(?:POST|GET|upload|send|forward|copy)\s+(?:it|them|this|the\s+\w+|all\s+\w+)?\s*to\s+"
            r"https?://|"
            r"(?:use|via)\s+(?:the\s+)?(?:browser|fetch|http|curl|webhook)\s+tool\s+to\s+"
            r"(?:send|post|submit|transmit)", re.I),
    },
    {
        "id": "MEM-INSTRUCTION-OVERRIDE",
        "severity": "high",
        "atlas": ["AML.T0080", "AML.T0051"],
        "desc": "Injected text attempting to supersede system instructions or guardrails from within memory.",
        "pattern": re.compile(
            r"ignore\s+(?:all\s+)?(?:previous|prior|earlier|above)\s+instructions|"
            r"disregard\s+(?:the\s+)?(?:system\s+prompt|above|previous|safety)|"
            r"(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:a\s+|an\s+)?(?:different|new|unrestricted)|"
            r"developer\s+mode|"
            r"(?:override|bypass|disable)\s+(?:your\s+)?(?:safety|guardrails?|restrictions?|filters?)", re.I),
    },
    {
        "id": "MEM-HIDDEN-TEXT",
        "severity": "medium",
        "atlas": ["AML.T0080"],
        "desc": "Content hidden from human review (zero-width characters, HTML comments, or CSS-invisible "
                "text) inside a memory store — used to conceal injected instructions.",
        "pattern": re.compile(
            r"[\u200b\u200c\u200d\u2060\ufeff]|"
            r"<!--(?:(?!-->)[\s\S]){20,}?-->|"
            r"(?:font-size\s*:\s*0|color\s*:\s*(?:#fff{1,6}|white)\s*;|display\s*:\s*none)", re.I),
    },
]

# Memory-bearing filenames worth parsing when walking a directory.
MEMORY_FILE_HINTS = re.compile(
    r"^(?:memor(?:y|ies)|checkpoints?|state|scratchpad|agent[_-]?state|conversation[s]?|threads?)"
    r"[\w.-]*\.(?:json|jsonl|db|sqlite3?|txt|md)$|"
    r"^(?:MEMORY|CLAUDE|AGENTS?|GEMINI|COPILOT)\.md$|"
    r"^\.(?:cursorrules|windsurfrules|clinerules|aiderrules)$", re.I)

SQLITE_MAGIC = b"SQLite format 3\x00"
# Pickle protocol 2-5 openers. Checkpoint blobs SHOULD be msgpack/JSON; pickle means arbitrary
# code executes on load (ties to category 03 model-supply-chain deserialization risk).
PICKLE_MAGIC = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")
# Columns that actually carry a serialized payload in LangGraph checkpointer schemas.
PAYLOAD_COLUMNS = {"checkpoint", "metadata", "value", "blob"}

PRINTABLE_RUN = re.compile(rb"[\x20-\x7e\t]{6,}")


# ---------------------------------------------------------------- helpers
def _strings(blob: bytes, min_len: int = 6, limit: int = 200_000) -> str:
    """Best-effort printable extraction from an opaque blob (msgpack/pickle/compressed).

    LangGraph serializes checkpoints with msgpack by default; without third-party decoders we do what a
    forensic examiner does with an opaque container — recover printable runs. Structure is lost, but the
    instruction text that matters for poisoning detection survives.
    """
    if not blob:
        return ""
    out = [m.group().decode("ascii", "replace") for m in PRINTABLE_RUN.finditer(blob[:limit])]
    return "\n".join(out)


def _excerpt(text: str, start: int, end: int, pad: int = 90) -> str:
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    return re.sub(r"\s+", " ", text[s:e]).strip()[:300]


def _finding(rule: dict[str, Any], source: str, locator: str, text: str,
             start: int, end: int, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    f = {
        "indicator_id": rule["id"],
        "severity": rule["severity"],
        "atlas": rule["atlas"],
        "description": rule["desc"],
        "source": source,
        "locator": locator,
        "excerpt": _excerpt(text, start, end),
    }
    if extra:
        f.update(extra)
    return f


def scan_text(text: str, source: str, locator: str) -> list[dict[str, Any]]:
    """Apply every poisoning indicator to a block of text."""
    findings: list[dict[str, Any]] = []
    if not text:
        return findings
    for rule in INDICATORS:
        for m in rule["pattern"].finditer(text):
            findings.append(_finding(rule, source, locator, text, m.start(), m.end()))
            break  # one finding per rule per locator; excerpt carries the evidence
    return findings


# ---------------------------------------------------------------- parsers
def parse_langgraph_sqlite(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse a LangGraph SQLite checkpointer read-only. Schema-tolerant across versions."""
    findings: list[dict[str, Any]] = []
    meta: dict[str, Any] = {"kind": "langgraph_sqlite", "path": str(path),
                            "tables": [], "checkpoints": 0, "writes": 0, "threads": set()}
    # Immutable read-only URI: guarantees the analytic cannot mutate evidence, and works on a
    # copy acquired by the collector even if a WAL sidecar is absent.
    uri = f"file:{path}?immutable=1&mode=ro"
    try:
        con = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as e:
        meta["error"] = f"cannot open: {e}"
        return findings, meta
    try:
        con.text_factory = bytes
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0].decode("utf-8", "replace") for r in cur.fetchall()]
        meta["tables"] = tables

        for table in tables:
            if table.lower() not in ("checkpoints", "writes", "checkpoint_writes", "checkpoint_blobs"):
                continue
            cur.execute(f'PRAGMA table_info("{table}")')
            cols = [r[1].decode("utf-8", "replace") for r in cur.fetchall()]
            cur.execute(f'SELECT * FROM "{table}"')
            for rownum, row in enumerate(cur.fetchall()):
                rec = dict(zip(cols, row))
                thread = rec.get("thread_id")
                if isinstance(thread, bytes):
                    thread = thread.decode("utf-8", "replace")
                if thread:
                    meta["threads"].add(thread)
                if table.lower() == "checkpoints":
                    meta["checkpoints"] += 1
                else:
                    meta["writes"] += 1

                ckpt_id = rec.get("checkpoint_id")
                if isinstance(ckpt_id, bytes):
                    ckpt_id = ckpt_id.decode("utf-8", "replace")
                locator = f"{table}[{rownum}] thread={thread} checkpoint={ckpt_id}"

                # serializer type column: pickle here is a deserialization-RCE risk
                stype = rec.get("type")
                if isinstance(stype, bytes):
                    stype = stype.decode("utf-8", "replace")

                # Serializer check applies ONLY to payload columns. The `type` column describes how the
                # PAYLOAD was serialized, so testing it against every column (including thread_id and
                # type itself) would report ASCII text as pickle. One finding per row, not per column.
                stype_l = (stype or "").lower()
                pickle_cols = [
                    col for col, val in rec.items()
                    if col.lower() in PAYLOAD_COLUMNS and isinstance(val, bytes) and val
                    and (val[:2] in PICKLE_MAGIC or stype_l == "pickle")
                ]
                if pickle_cols:
                    first = rec[pickle_cols[0]]
                    findings.append({
                        "indicator_id": "MEM-PICKLE-CHECKPOINT",
                        "severity": "high",
                        "atlas": ["AML.T0010", "AML.T0080"],
                        "description": "Checkpoint payload is Python pickle. Loading it executes "
                                       "arbitrary code; a tampered checkpoint is an RCE primitive, "
                                       "not merely poisoned context. Do not deserialize on an "
                                       "analysis host.",
                        "source": str(path),
                        "locator": f"{locator} columns={','.join(pickle_cols)}",
                        "excerpt": f"serializer_type={stype!r} magic={binascii.hexlify(first[:4]).decode()}",
                    })

                for col, val in rec.items():
                    if not isinstance(val, bytes) or not val:
                        continue
                    findings.extend(scan_text(_strings(val), str(path), f"{locator} column={col}"))
                # non-blob text columns
                for col, val in rec.items():
                    if isinstance(val, bytes):
                        continue
                    if isinstance(val, str) and len(val) > 8:
                        findings.extend(scan_text(val, str(path), f"{locator} column={col}"))
    except sqlite3.Error as e:
        meta["error"] = f"read error: {e}"
    finally:
        con.close()
    meta["threads"] = sorted(meta["threads"])
    return findings, meta


def _walk_json(obj: Any, path: str = "$") -> Iterable[tuple[str, str]]:
    """Yield (jsonpath, string) for every string leaf."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_json(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_json(v, f"{path}[{i}]")


def parse_json_memory(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    meta: dict[str, Any] = {"kind": "json_memory", "path": str(path), "entries": 0}
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        meta["error"] = str(e)
        return findings, meta

    docs: list[Any] = []
    try:
        docs = [json.loads(raw)]
    except json.JSONDecodeError:
        for line in raw.splitlines():  # JSONL
            line = line.strip()
            if line:
                try:
                    docs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    if not docs:
        meta["error"] = "not parseable as JSON or JSONL"
        findings.extend(scan_text(raw, str(path), "$raw"))
        return findings, meta

    for d in docs:
        for jpath, s in _walk_json(d):
            meta["entries"] += 1
            findings.extend(scan_text(s, str(path), jpath))
    return findings, meta


def parse_text_memory(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    meta: dict[str, Any] = {"kind": "text_memory", "path": str(path)}
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        meta["error"] = str(e)
        return [], meta
    meta["bytes"] = len(raw)
    findings: list[dict[str, Any]] = []
    for lineno, line in enumerate(raw.splitlines(), 1):
        findings.extend(scan_text(line, str(path), f"line {lineno}"))
    # Whole-file pass catches multi-line constructs (HTML comments, wrapped directives) that a
    # line-by-line scan splits apart. Keep only indicators the line pass did NOT already report,
    # otherwise every hit is duplicated and the finding count is inflated.
    seen_ids = {f["indicator_id"] for f in findings}
    findings.extend(f for f in scan_text(raw, str(path), "whole-file")
                    if f["indicator_id"] not in seen_ids)
    return findings, meta


def parse_artifact(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except OSError as e:
        return [], {"kind": "unreadable", "path": str(path), "error": str(e)}
    if head.startswith(SQLITE_MAGIC):
        return parse_langgraph_sqlite(path)
    if path.suffix.lower() in (".json", ".jsonl", ".ndjson"):
        return parse_json_memory(path)
    return parse_text_memory(path)


# ---------------------------------------------------------------- discovery
def discover(case: Path | None, inputs: list[Path]) -> list[Path]:
    roots: list[Path] = []
    if case:
        cand = case / "artifacts"
        roots.append(cand if cand.is_dir() else case)
    roots.extend(inputs)
    files: list[Path] = []
    for r in roots:
        if r.is_file():
            files.append(r)
        elif r.is_dir():
            for dirpath, _d, fnames in os.walk(r):
                for fn in fnames:
                    p = Path(dirpath) / fn
                    if MEMORY_FILE_HINTS.match(fn):
                        files.append(p)
                        continue
                    # any sqlite file is worth a look (checkpointers are often oddly named)
                    try:
                        with open(p, "rb") as fh:
                            if fh.read(16).startswith(SQLITE_MAGIC):
                                files.append(p)
                    except OSError:
                        continue
    seen: set[str] = set()
    uniq: list[Path] = []
    for f in files:
        rp = os.path.realpath(f)
        if rp not in seen:
            seen.add(rp)
            uniq.append(f)
    return uniq


# ---------------------------------------------------------------- reporting
def render(findings: list[dict[str, Any]], artifacts: list[dict[str, Any]],
           meta: dict[str, Any], min_sev: str) -> str:
    floor = SEVERITY_ORDER[min_sev]
    shown = [f for f in findings if SEVERITY_ORDER.get(f["severity"], 0) >= floor]
    counts = Counter(f["severity"] for f in findings)
    worst = max((SEVERITY_ORDER.get(f["severity"], 0) for f in findings), default=0)
    verdict = {
        4: "CRITICAL — persistent adversary instruction in agent memory; purge memory as part of eradication",
        3: "HIGH — memory content requires analyst review before the agent is returned to service",
        2: "MEDIUM — suspicious memory content; review",
        1: "LOW — minor anomalies",
        0: "CLEAN — no poisoning indicators matched",
    }[worst]

    lines = [
        "=" * 78,
        "AGENT MEMORY FORENSICS — CONTEXT POISONING TRIAGE",
        f"analytic v{meta['analytic_version']}   generated {meta['generated_utc']}",
        f"artifacts parsed: {len(artifacts)}   findings: {len(findings)}"
        f"   (critical {counts['critical']}, high {counts['high']}, medium {counts['medium']})",
        "=" * 78,
        f"VERDICT: {verdict}",
        "",
    ]
    for a in artifacts:
        detail = ""
        if a.get("kind") == "langgraph_sqlite":
            detail = (f"  checkpoints={a.get('checkpoints')} writes={a.get('writes')} "
                      f"threads={len(a.get('threads') or [])}")
        elif a.get("kind") == "json_memory":
            detail = f"  string entries={a.get('entries')}"
        err = f"  ERROR: {a['error']}" if a.get("error") else ""
        lines.append(f"  [{a.get('kind')}] {a.get('path')}{detail}{err}")
    lines.append("")

    if not shown:
        lines.append(f"No findings at or above severity '{min_sev}'.")
    else:
        by_sev = sorted(shown, key=lambda f: -SEVERITY_ORDER.get(f["severity"], 0))
        for f in by_sev:
            lines += [
                f"[{f['severity'].upper()}] {f['indicator_id']}   {','.join(f['atlas'])}",
                f"    {f['description']}",
                f"    source : {f['source']}",
                f"    at     : {f['locator']}",
                f"    excerpt: …{f['excerpt']}…",
                "",
            ]
    lines += [
        "-" * 78,
        "Memory is a PERSISTENCE mechanism (ATLAS AML.T0080). Eradication that does not purge memory",
        "leaves the adversary resident across future sessions. Preserve the store read-only before",
        "clearing it — EU AI Act Art. 73 forbids altering the AI system before notifying authorities.",
        "Never deserialize a pickle checkpoint on an analysis host.",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Parse agent memory stores and detect context poisoning.")
    ap.add_argument("--case", type=Path, help="Case directory from collect_ai_artifacts.py.")
    ap.add_argument("--input", type=Path, action="append", default=[],
                    help="Memory file or directory (repeatable).")
    ap.add_argument("--json", help="Write findings JSON here ('-' for stdout).")
    ap.add_argument("--report", default="-", help="Write report here ('-' stdout, '' to skip).")
    ap.add_argument("--min-severity", default="medium",
                    choices=list(SEVERITY_ORDER), help="Report floor (default: medium).")
    args = ap.parse_args(argv)

    if not args.case and not args.input:
        ap.error("provide --case and/or --input")

    files = discover(args.case, args.input)
    if not files:
        sys.stderr.write("ERROR: no memory artifacts found\n")
        return 1

    all_findings: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    for f in files:
        fnd, m = parse_artifact(f)
        all_findings.extend(fnd)
        artifacts.append(m)

    meta = {
        "analytic": "analyze_agent_memory.py",
        "analytic_version": ANALYTIC_VERSION,
        "generated_utc": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "artifacts_parsed": len(artifacts),
        "findings": len(all_findings),
    }

    if args.json:
        payload = {"meta": meta, "artifacts": artifacts, "findings": all_findings}
        if args.json == "-":
            json.dump(payload, sys.stdout, indent=2, default=str)
            sys.stdout.write("\n")
        else:
            Path(args.json).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
            sys.stderr.write(f"[+] findings written to {args.json}\n")

    if args.report:
        text = render(all_findings, artifacts, meta, args.min_severity)
        if args.report == "-":
            print(text)
        else:
            Path(args.report).write_text(text + "\n", encoding="utf-8")
            sys.stderr.write(f"[+] report written to {args.report}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
