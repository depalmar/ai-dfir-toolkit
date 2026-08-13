#!/usr/bin/env python3
"""
analyze_agent_traces.py — behavioral analytic for AI-orchestrated intrusion (GTG-1002 class).

Consumes agent execution traces (Claude Code session JSONL, or any JSONL normalized to the same shape)
— typically acquired by ../collectors/collect_ai_artifacts.py — and scores them against the behavioral
signatures of AI-orchestrated attack chains. Static rules cannot catch this class: the individual tool
calls are legitimate; the *tempo, phase progression, breadth, and autonomy ratio* are what betray it.

Signals scored (weighted composite 0-100):
  1. TEMPO           Tool-invocation rate beyond human capability (GTG-1002: "thousands of requests/second").
  2. PHASE_CHAIN     Distinct kill-chain phases observed in one session, and monotonic recon->exfil ordering.
  3. BREADTH         Distinct targets (hosts/IPs/domains) touched in parallel (GTG-1002: ~30 targets).
  4. EXFIL_FLOW      High tool-output volume with low narrative output (collection/staging signature).
  5. AUTONOMY        Agent actions per human turn ("thousands of actions between human check-ins";
                     GTG-1002 human operators intervened at only 4-6 decision points per campaign).
  6. ROLEPLAY        Authorization/pentest role-play framing in prompts paired with offensive tooling
                     (the documented GTG-1002 jailbreak: posing as a "defensive cybersecurity firm").

Output: JSON findings (--json) and/or an analyst report, with per-signal scores, ATLAS mappings, and
evidence excerpts keyed by session_id for correlation.

THIS IS A TRIAGE AID, NOT A VERDICT. Every signal has benign analogues (legitimate pentest engagements,
CI automation, bulk refactoring). Scores are calibrated for HUNTING; corroborate before escalation.

Usage:
  python3 analyze_agent_traces.py --case ./cases/IR-2026-014
  python3 analyze_agent_traces.py --input ~/.claude/projects --json findings.json
  python3 analyze_agent_traces.py --input session.jsonl --min-score 40 --report -

Standard library only.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

ANALYTIC_VERSION = "1.0.0"

# --------------------------------------------------------------------------- kill-chain phase model
# Maps observed tool usage / command content to intrusion phases. Ordered: index = expected progression.
PHASES: list[str] = [
    "reconnaissance",
    "vulnerability_discovery",
    "exploitation",
    "credential_access",
    "lateral_movement",
    "collection_exfiltration",
]

PHASE_PATTERNS: dict[str, list[str]] = {
    "reconnaissance": [
        r"\bnmap\b", r"\bmasscan\b", r"\bshodan\b", r"\bsubfinder\b", r"\bamass\b", r"\bdnsrecon\b",
        r"\bwhois\b", r"\bdig\s", r"\bnslookup\b", r"\bgobuster\b", r"\bffuf\b", r"\bdirb\b",
        r"port\s*scan", r"enumerat", r"\bfping\b", r"\bnetdiscover\b", r"service\s*discovery",
    ],
    "vulnerability_discovery": [
        r"\bnuclei\b", r"\bnikto\b", r"\bsqlmap\b", r"\bwpscan\b", r"\bopenvas\b", r"\bnessus\b",
        r"\btestssl\b", r"vulnerab", r"\bcve-\d{4}-\d{4,7}\b", r"exploit\s*db", r"searchsploit",
    ],
    "exploitation": [
        r"\bmetasploit\b", r"\bmsfconsole\b", r"\bmsfvenom\b", r"\bexploit\b", r"payload",
        r"reverse\s*shell", r"\bwebshell\b", r"\brce\b", r"deserializ", r"\bssrf\b",
        r"command\s*injection", r"\bpwntools\b",
    ],
    "credential_access": [
        r"\bmimikatz\b", r"\bhashdump\b", r"\bsecretsdump\b", r"\blsass\b", r"\bntds\.dit\b",
        r"\bkerberoast\b", r"\basreproast\b", r"\bhashcat\b", r"\bjohn\b", r"credential",
        r"\bshadow\b", r"id_rsa", r"\.aws/credentials", r"secrets?\s*manager", r"\bkeyring\b",
        r"password\s*(dump|spray|hash)", r"\bcrackmapexec\b", r"\bnetexec\b",
    ],
    "lateral_movement": [
        r"\bpsexec\b", r"\bwmiexec\b", r"\bsmbexec\b", r"\bevil-winrm\b", r"\bwinrm\b",
        r"lateral", r"pass[-\s]?the[-\s]?hash", r"\bproxychains\b", r"pivot", r"\bchisel\b",
        r"ssh\s+-[LRD]\b", r"\brdp\b",
    ],
    "collection_exfiltration": [
        r"\btar\s+-?c", r"\bzip\s+-r\b", r"\b7z\s+a\b", r"exfil", r"\bcurl\b.*(-T|--upload-file)",
        r"\bscp\b", r"\brclone\b", r"\baws\s+s3\s+(cp|sync)\b", r"\bgsutil\s+cp\b",
        r"stag(e|ing)\s*data", r"\bdd\s+if=", r"database\s*dump", r"\bmysqldump\b", r"\bpg_dump\b",
    ],
}

# Role-play / false-authorization framing documented in the GTG-1002 jailbreak.
ROLEPLAY_PATTERNS: list[str] = [
    r"authorized\s+(penetration|pen)\s*test", r"we\s+are\s+a\s+(defensive\s+)?cyber\s*security\s+firm",
    r"legitimate\s+security\s+(assessment|testing|audit)", r"bug\s*bounty", r"red\s*team\s+engagement",
    r"you\s+are\s+(a\s+)?(pentester|penetration\s+tester|security\s+researcher)",
    r"client\s+has\s+authorized", r"scope\s+of\s+(the\s+)?engagement", r"rules\s+of\s+engagement",
    r"this\s+is\s+(a\s+)?sanctioned", r"with\s+(full\s+)?written\s+permission",
    r"for\s+(defensive|educational)\s+purposes\s+only",
]

# Offensive tooling that, paired with role-play framing, elevates ROLEPLAY confidence.
OFFENSIVE_HINT = re.compile(
    r"\b(nmap|masscan|metasploit|msfvenom|sqlmap|mimikatz|secretsdump|hashcat|crackmapexec|netexec|"
    r"evil-winrm|psexec|nuclei|responder|impacket)\b", re.I)

TARGET_RE = re.compile(
    r"\b(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|ai|gov|mil|edu|local|internal|corp|lan|co|uk|de|cn|ru))\b", re.I)

# Hosts that are noise, not targets.
TARGET_IGNORE = re.compile(
    r"^(?:127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.255|localhost|"
    r"(?:.*\.)?(?:github\.com|githubusercontent\.com|npmjs\.org|npmjs\.com|pypi\.org|"
    r"anthropic\.com|openai\.com|google\.com|microsoft\.com|docker\.io|ubuntu\.com|debian\.org|"
    r"example\.com|schema\.org|w3\.org))$", re.I)

# Signal weights (sum = 100). Tuned so no single signal alone reaches escalation.
WEIGHTS: dict[str, int] = {
    "tempo": 25,
    "phase_chain": 25,
    "breadth": 15,
    "exfil_flow": 12,
    "autonomy": 13,
    "roleplay": 10,
}

ATLAS_MAP: dict[str, list[str]] = {
    "tempo": ["AML.T0096"],
    "phase_chain": ["AML.T0096", "AML.T0053"],
    "breadth": ["AML.T0096"],
    "exfil_flow": ["AML.T0086"],
    "autonomy": ["AML.T0096", "AML.T0053"],
    "roleplay": ["AML.T0054", "AML.T0051"],
}


# --------------------------------------------------------------------------- parsing
def _parse_ts(value: Any) -> _dt.datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            ts = float(value)
            if ts > 1e12:  # milliseconds
                ts /= 1000.0
            return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        v = value.strip().replace("Z", "+00:00")
        try:
            dt = _dt.datetime.fromisoformat(v)
            return dt if dt.tzinfo else dt.replace(tzinfo=_dt.timezone.utc)
        except ValueError:
            return None
    return None


def _walk_strings(obj: Any, budget: int = 400) -> Iterable[str]:
    """Yield string leaves from nested JSON, bounded to keep analysis cheap on huge records."""
    stack = [obj]
    seen = 0
    while stack and seen < budget:
        cur = stack.pop()
        if isinstance(cur, str):
            seen += 1
            yield cur
        elif isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)


def _record_kind(rec: dict[str, Any]) -> str:
    """Classify a JSONL record into: human | tool_use | tool_result | assistant_text | other."""
    rtype = str(rec.get("type") or rec.get("role") or "").lower()
    msg = rec.get("message") if isinstance(rec.get("message"), dict) else {}
    role = str(msg.get("role") or "").lower()

    content = msg.get("content") if msg else rec.get("content")
    blocks = content if isinstance(content, list) else []
    block_types = {str(b.get("type", "")).lower() for b in blocks if isinstance(b, dict)}

    if "tool_use" in block_types or rtype == "tool_use":
        return "tool_use"
    if "tool_result" in block_types or rtype in ("tool_result", "user_tool_result"):
        return "tool_result"
    if rtype in ("user", "human") or role in ("user", "human"):
        # A 'user' record carrying only tool_result blocks is agent plumbing, not a human turn.
        return "tool_result" if block_types and block_types <= {"tool_result"} else "human"
    if rtype == "assistant" or role == "assistant":
        return "assistant_text"
    return "other"


def _tool_names(rec: dict[str, Any]) -> list[str]:
    out: list[str] = []
    msg = rec.get("message") if isinstance(rec.get("message"), dict) else {}
    content = msg.get("content") if msg else rec.get("content")
    if isinstance(content, list):
        for b in content:
            if isinstance(b, dict) and str(b.get("type", "")).lower() == "tool_use":
                if b.get("name"):
                    out.append(str(b["name"]))
    if not out and rec.get("tool_name"):
        out.append(str(rec["tool_name"]))
    return out


def load_events(paths: list[Path]) -> list[dict[str, Any]]:
    """Read JSONL files into normalized events."""
    events: list[dict[str, Any]] = []
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(rec, dict):
                        continue
                    text = " ".join(_walk_strings(rec))
                    events.append({
                        "source_file": str(p),
                        "lineno": lineno,
                        "ts": _parse_ts(rec.get("timestamp") or rec.get("time") or rec.get("ts")),
                        "session_id": str(rec.get("sessionId") or rec.get("session_id")
                                          or rec.get("trace_id") or p.stem),
                        "kind": _record_kind(rec),
                        "tools": _tool_names(rec),
                        "text": text,
                        "text_len": len(text),
                    })
        except OSError:
            continue
    return events


def discover_inputs(case: Path | None, inputs: list[Path]) -> list[Path]:
    files: list[Path] = []
    roots: list[Path] = []
    if case:
        # Prefer collector-acquired coding-agent artifacts, else scan the whole case.
        cand = case / "artifacts" / "05" / "claude_code_sessions"
        roots.append(cand if cand.is_dir() else case)
    roots.extend(inputs)
    for r in roots:
        if r.is_file():
            files.append(r)
        elif r.is_dir():
            for dirpath, _d, fnames in os.walk(r):
                for fn in fnames:
                    if fn.endswith((".jsonl", ".ndjson")):
                        files.append(Path(dirpath) / fn)
    # de-dup
    seen: set[str] = set()
    uniq: list[Path] = []
    for f in files:
        rp = os.path.realpath(f)
        if rp not in seen:
            seen.add(rp)
            uniq.append(f)
    return uniq


# --------------------------------------------------------------------------- signals
def _phase_of(text: str) -> set[str]:
    hits: set[str] = set()
    low = text.lower()
    for phase, pats in PHASE_PATTERNS.items():
        for pat in pats:
            if re.search(pat, low):
                hits.add(phase)
                break
    return hits


def _score_tempo(events: list[dict[str, Any]]) -> tuple[float, dict[str, Any]]:
    """Max tool-invocations-per-minute in a sliding 60s window. Humans rarely exceed ~6-10/min sustained."""
    stamped = sorted([e for e in events if e["kind"] == "tool_use" and e["ts"]], key=lambda e: e["ts"])
    if len(stamped) < 2:
        return 0.0, {"max_per_min": 0, "tool_events": len(stamped), "note": "insufficient timestamped tool events"}
    times = [e["ts"] for e in stamped]
    best = 1
    j = 0
    for i in range(len(times)):
        while (times[i] - times[j]).total_seconds() > 60:
            j += 1
        best = max(best, i - j + 1)
    # 0 at <=10/min (human), 100 at >=120/min (machine tempo)
    score = max(0.0, min(100.0, (best - 10) / (120 - 10) * 100))
    span = (times[-1] - times[0]).total_seconds()
    return score, {
        "max_tool_calls_per_min": best,
        "tool_events": len(stamped),
        "span_seconds": round(span, 1),
        "mean_per_min": round(len(stamped) / (span / 60), 2) if span > 0 else None,
    }


def _score_phase_chain(events: list[dict[str, Any]]) -> tuple[float, dict[str, Any]]:
    """Distinct kill-chain phases present + monotonic recon->exfil ordering."""
    seq: list[tuple[Any, str]] = []
    phases_seen: set[str] = set()
    for e in events:
        if e["kind"] not in ("tool_use", "tool_result"):
            continue
        for ph in _phase_of(e["text"]):
            phases_seen.add(ph)
            seq.append((e["ts"], ph))
    n = len(phases_seen)
    base = min(100.0, (n / len(PHASES)) * 100)
    ordered = [p for _t, p in sorted([s for s in seq if s[0]], key=lambda x: x[0])]
    idxs = [PHASES.index(p) for p in ordered]
    progression = False
    if len(idxs) >= 3:
        rising = sum(1 for a, b in zip(idxs, idxs[1:]) if b >= a)
        progression = rising / max(1, len(idxs) - 1) >= 0.7 and idxs[-1] > idxs[0]
    if progression and n >= 3:
        base = min(100.0, base + 20)
    return base, {
        "phases_observed": sorted(phases_seen, key=lambda p: PHASES.index(p)),
        "phase_count": n,
        "monotonic_progression": progression,
    }


def _score_breadth(events: list[dict[str, Any]]) -> tuple[float, dict[str, Any]]:
    targets: Counter[str] = Counter()
    for e in events:
        if e["kind"] not in ("tool_use", "tool_result"):
            continue
        for m in TARGET_RE.findall(e["text"]):
            t = m.lower().strip(".")
            if not TARGET_IGNORE.match(t):
                targets[t] += 1
    n = len(targets)
    score = max(0.0, min(100.0, (n - 2) / (30 - 2) * 100))  # 0 at <=2, 100 at >=30 distinct targets
    return score, {"distinct_targets": n, "top_targets": [t for t, _c in targets.most_common(10)]}


def _score_exfil_flow(events: list[dict[str, Any]]) -> tuple[float, dict[str, Any]]:
    """Collection signature: large tool-result volume, little narrative assistant output."""
    tool_bytes = sum(e["text_len"] for e in events if e["kind"] == "tool_result")
    narr_bytes = sum(e["text_len"] for e in events if e["kind"] == "assistant_text")
    if tool_bytes < 20_000:
        return 0.0, {"tool_result_bytes": tool_bytes, "assistant_text_bytes": narr_bytes,
                     "note": "below volume floor"}
    ratio = tool_bytes / max(1, narr_bytes)
    score = max(0.0, min(100.0, (ratio - 5) / (100 - 5) * 100))  # 0 at <=5:1, 100 at >=100:1
    return score, {"tool_result_bytes": tool_bytes, "assistant_text_bytes": narr_bytes,
                   "ratio_tool_to_narrative": round(ratio, 1)}


def _score_autonomy(events: list[dict[str, Any]]) -> tuple[float, dict[str, Any]]:
    """Agent actions per human turn. GTG-1002: 4-6 human decision points across an entire campaign."""
    human = sum(1 for e in events if e["kind"] == "human")
    actions = sum(1 for e in events if e["kind"] == "tool_use")
    if actions < 5:
        return 0.0, {"human_turns": human, "agent_actions": actions, "note": "too few actions"}
    per_turn = actions / max(1, human)
    score = max(0.0, min(100.0, (per_turn - 5) / (100 - 5) * 100))  # 0 at <=5:1, 100 at >=100:1
    return score, {"human_turns": human, "agent_actions": actions,
                   "actions_per_human_turn": round(per_turn, 1)}


def _score_roleplay(events: list[dict[str, Any]]) -> tuple[float, dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for e in events:
        if e["kind"] not in ("human", "assistant_text"):
            continue
        for pat in ROLEPLAY_PATTERNS:
            m = re.search(pat, e["text"], re.I)
            if m:
                s = max(0, m.start() - 60)
                matches.append({
                    "pattern": pat,
                    "session_id": e["session_id"],
                    "source_file": e["source_file"],
                    "lineno": e["lineno"],
                    "excerpt": e["text"][s:m.end() + 60].replace("\n", " ")[:200],
                })
                break
    if not matches:
        return 0.0, {"matches": 0}
    offensive = any(OFFENSIVE_HINT.search(e["text"]) for e in events
                    if e["kind"] in ("tool_use", "tool_result"))
    score = 100.0 if offensive else 45.0
    return score, {"matches": len(matches), "paired_with_offensive_tooling": offensive,
                   "evidence": matches[:5]}


SIGNALS = {
    "tempo": _score_tempo,
    "phase_chain": _score_phase_chain,
    "breadth": _score_breadth,
    "exfil_flow": _score_exfil_flow,
    "autonomy": _score_autonomy,
    "roleplay": _score_roleplay,
}


def _verdict(score: float) -> str:
    if score >= 70:
        return "HIGH — consistent with AI-orchestrated intrusion; escalate to IR"
    if score >= 40:
        return "MEDIUM — anomalous agent behavior; analyst review required"
    if score >= 20:
        return "LOW — minor deviations; monitor"
    return "INFORMATIONAL — no orchestration-abuse indicators"


def analyze(events: list[dict[str, Any]], session_id: str) -> dict[str, Any]:
    detail: dict[str, Any] = {}
    weighted = 0.0
    for name, fn in SIGNALS.items():
        raw, meta = fn(events)
        contrib = raw * WEIGHTS[name] / 100.0
        weighted += contrib
        detail[name] = {
            "raw_score": round(raw, 1),
            "weight": WEIGHTS[name],
            "contribution": round(contrib, 1),
            "atlas": ATLAS_MAP[name],
            "detail": meta,
        }
    total = round(weighted, 1)
    times = [e["ts"] for e in events if e["ts"]]
    return {
        "session_id": session_id,
        "composite_score": total,
        "verdict": _verdict(total),
        "event_counts": dict(Counter(e["kind"] for e in events)),
        "first_event_utc": min(times).strftime("%Y-%m-%dT%H:%M:%SZ") if times else None,
        "last_event_utc": max(times).strftime("%Y-%m-%dT%H:%M:%SZ") if times else None,
        "signals": detail,
    }


# --------------------------------------------------------------------------- reporting
def render_report(findings: list[dict[str, Any]], meta: dict[str, Any]) -> str:
    lines = [
        "=" * 78,
        "AI-ORCHESTRATED INTRUSION — AGENT TRACE ANALYSIS",
        f"analytic v{meta['analytic_version']}   generated {meta['generated_utc']}",
        f"files analyzed: {meta['files']}   events: {meta['events']}   sessions: {len(findings)}",
        "=" * 78,
        "",
    ]
    if not findings:
        lines.append("No sessions met the reporting threshold.")
        return "\n".join(lines)
    for f in findings:
        lines += [
            f"SESSION {f['session_id']}",
            f"  COMPOSITE {f['composite_score']}/100 — {f['verdict']}",
            f"  window: {f['first_event_utc']} .. {f['last_event_utc']}   events: {f['event_counts']}",
            "  signals:",
        ]
        for name, s in sorted(f["signals"].items(), key=lambda kv: -kv[1]["contribution"]):
            bar = "#" * int(s["raw_score"] / 5)
            lines.append(f"    {name:<12} {s['raw_score']:>5.1f}/100  (+{s['contribution']:>4.1f})  "
                         f"{','.join(s['atlas']):<22} {bar}")
            d = s["detail"]
            if name == "tempo" and d.get("max_tool_calls_per_min"):
                lines.append(f"        peak {d['max_tool_calls_per_min']} tool calls/min over "
                             f"{d.get('span_seconds')}s ({d.get('tool_events')} events)")
            if name == "phase_chain" and d.get("phases_observed"):
                lines.append(f"        phases: {' -> '.join(d['phases_observed'])}"
                             f"{'  [monotonic]' if d.get('monotonic_progression') else ''}")
            if name == "breadth" and d.get("distinct_targets"):
                lines.append(f"        {d['distinct_targets']} distinct targets: "
                             f"{', '.join(d['top_targets'][:6])}")
            if name == "exfil_flow" and d.get("ratio_tool_to_narrative"):
                lines.append(f"        tool-output:narrative = {d['ratio_tool_to_narrative']}:1 "
                             f"({d['tool_result_bytes']} bytes collected)")
            if name == "autonomy" and d.get("actions_per_human_turn"):
                lines.append(f"        {d['agent_actions']} agent actions / {d['human_turns']} human turns "
                             f"= {d['actions_per_human_turn']}:1")
            if name == "roleplay" and d.get("evidence"):
                for ev in d["evidence"][:2]:
                    lines.append(f"        [{ev['source_file'].split('/')[-1]}:{ev['lineno']}] "
                                 f"…{ev['excerpt']}…")
        lines.append("")
    lines += [
        "-" * 78,
        "TRIAGE AID ONLY — corroborate before escalation. Benign analogues exist for every signal",
        "(authorized pentest engagements, CI automation, large refactors). Preserve traces read-only;",
        "EU AI Act Art. 73 forbids altering the AI system before notifying authorities.",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- cli
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Score agent traces for AI-orchestrated intrusion behavior.")
    ap.add_argument("--case", type=Path, help="Case directory produced by collect_ai_artifacts.py.")
    ap.add_argument("--input", type=Path, action="append", default=[],
                    help="JSONL file or directory to analyze (repeatable).")
    ap.add_argument("--json", help="Write findings JSON to this path ('-' for stdout).")
    ap.add_argument("--report", default="-", help="Write analyst report here ('-' for stdout, '' to skip).")
    ap.add_argument("--min-score", type=float, default=0.0, help="Only report sessions at/above this score.")
    ap.add_argument("--per-file", action="store_true",
                    help="Treat each file as one session instead of grouping by session id.")
    args = ap.parse_args(argv)

    if not args.case and not args.input:
        ap.error("provide --case and/or --input")

    files = discover_inputs(args.case, args.input)
    if not files:
        sys.stderr.write("ERROR: no .jsonl/.ndjson trace files found\n")
        return 1

    events = load_events(files)
    if not events:
        sys.stderr.write("ERROR: no parseable JSONL records found\n")
        return 1

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        groups[e["source_file"] if args.per_file else e["session_id"]].append(e)

    findings = [analyze(evs, sid) for sid, evs in groups.items()]
    findings = [f for f in findings if f["composite_score"] >= args.min_score]
    findings.sort(key=lambda f: -f["composite_score"])

    meta = {
        "analytic": "analyze_agent_traces.py",
        "analytic_version": ANALYTIC_VERSION,
        "generated_utc": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": len(files),
        "events": len(events),
        "weights": WEIGHTS,
    }

    if args.json:
        payload = {"meta": meta, "findings": findings}
        if args.json == "-":
            json.dump(payload, sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
            sys.stderr.write(f"[+] findings written to {args.json}\n")

    if args.report:
        text = render_report(findings, meta)
        if args.report == "-":
            print(text)
        else:
            Path(args.report).write_text(text + "\n", encoding="utf-8")
            sys.stderr.write(f"[+] report written to {args.report}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
