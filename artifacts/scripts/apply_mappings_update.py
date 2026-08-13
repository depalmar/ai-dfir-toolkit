#!/usr/bin/env python3
"""Add the endpoint Sigma rules to MAPPINGS.md and refresh the index counts.

Operates on the real file in place rather than replacing it, so nothing already
there is at risk. Idempotent: running it twice is a no-op.

    python artifacts/scripts/apply_mappings_update.py --dry-run
    python artifacts/scripts/apply_mappings_update.py

What it does:
  1. Inserts a "## 07 - Endpoint (cross-tool)" section before the index tables.
  2. Updates the Scope line's rule-file count.
  3. Recomputes the ATLAS and OWASP index counts to include the new rules.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
MAPPINGS = ROOT / "MAPPINGS.md"
SIGMA_DIR = ROOT / "artifacts" / "detections" / "sigma"

SECTION_HEADING = "## Endpoint (cross-tool)"

# Mapped from each rule's own scope. ATLAS ids use the short form already used
# throughout this file (T0053 rather than AML.T0053).
RULES = [
    ("ai_agent_mcp_config_modification.yml", "T0081", "LLM06", "—"),
    ("ai_agent_spawning_shell.yml", "T0053", "LLM06", "—"),
    ("ai_agent_spawning_lolbin.yml", "T0053", "LLM06", "LOLBAS via MCP marketplace audit 2025"),
    ("local_llm_listener_non_loopback.yml", "T0024, T0029", "LLM10", "Pillar Security 2026 (Operation Bizarre Bazaar)"),
    ("ai_agent_credential_file_access.yml", "T0082", "LLM02", "—"),
    ("ai_inference_endpoint_redirection.yml", "T0024", "LLM02", "—"),
    ("mcp_server_remote_code_fetch.yml", "T0110", "LLM03", "postmark-mcp backdoor 2025"),
    ("browser_agent_session_state_capture.yml", "T0086", "LLM02, LLM06", "—"),
    ("ai_agent_autostart_persistence.yml", "T0081", "LLM06", "—"),
    ("langflow_rce_exploitation_attempt.yml", "T0053", "LLM03", "CVE-2025-3248 (CISA KEV), CVE-2026-5027"),
    ("ai_agent_docker_socket_mount.yml", "T0053", "LLM06", "OpenHands deployment docs"),
    ("ai_model_file_written_to_endpoint.yml", "T0010.003", "LLM03", "—"),
]

ATLAS_TITLES = {
    "T0053": "AI Agent Tool Invocation",
    "T0081": "Modify AI Agent Configuration",
    "T0082": "RAG Credential Harvesting",
}


def build_section() -> str:
    lines = [
        SECTION_HEADING,
        "",
        "Cross-tool endpoint rules generated alongside the artifact catalog",
        "(`artifacts/detections/sigma/`). Scoped to agent behaviour on a host rather than",
        "to a single attack class, so they apply across every tool in the catalog.",
        "",
        "| Rule | Format | ATLAS | OWASP | CVE / Reference |",
        "|------|--------|-------|-------|-----------------|",
    ]
    for name, atlas, owasp, ref in RULES:
        lines.append(f"| `{name}` | Sigma | {atlas} | {owasp} | {ref} |")
    lines += [
        "",
        "Also in this set: `artifacts/detections/osquery/ai-agent-artifacts.conf` — a",
        "six-query osquery pack for fleet inventory (running agents, listeners, MCP",
        "configs, plaintext credential files, model files, macOS autostart). It answers",
        "*which hosts have this*, which the Sigma rules cannot.",
        "",
    ]
    return "\n".join(lines)


def parse_index_counts(text: str) -> tuple[Counter, Counter]:
    """Count ATLAS and OWASP tags across every rule row in the per-section tables.

    Column layout differs between sections - 04 omits OWASP - so the columns are
    resolved from each table's own header rather than by position.

    Scanning every column from the third onward looks equivalent and is not: the
    CVE / Reference column carries citations like "OWASP LLM10:2025" and
    "OWASP LLM01/LLM07:2025", which are references to a category, not mappings
    to it. Counting those inflates LLM01, LLM07 and LLM10 by one apiece.
    """
    atlas, owasp = Counter(), Counter()
    columns: list[str] = []
    for line in text.splitlines():
        if line.startswith("|") and "Rule" in line and "Format" in line:
            columns = [c.strip().lower() for c in line.strip().strip("|").split("|")]
            continue
        if not re.match(r"^\| `.*\.(yml|yaml|yar|rules)`", line):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        for i, name in enumerate(columns):
            if i >= len(cells):
                break
            cell = cells[i]
            if name == "atlas":
                if "ATT&CK" in cell:
                    # e.g. "T1611 (ATT&CK)" - an ATT&CK id, not an ATLAS technique.
                    continue
                for tag in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", cell):
                    atlas[tag] += 1
            elif name == "owasp":
                for tag in re.findall(r"\bLLM\d{2}\b", cell):
                    owasp[tag] += 1
    return atlas, owasp


def current_index(text: str, heading: str) -> dict[str, int]:
    """The counts as they stand, so a rewrite can be reviewed rather than trusted."""
    existing: dict[str, int] = {}
    lines = text.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.startswith(heading))
    except StopIteration:
        return existing
    for i in range(start, len(lines)):
        line = lines[i]
        if line.startswith("##") and i != start:
            break
        if not line.startswith("|") or line.startswith("|---") or "Rule count" in line:
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) == 3 and cells[2].isdigit():
            existing[cells[0]] = int(cells[2])
    return existing


def rewrite_index(text: str, heading: str, counts: Counter) -> str:
    """Replace the Rule count column in an index table, leaving titles intact."""
    lines = text.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.startswith(heading))
    except StopIteration:
        return text

    for i in range(start, len(lines)):
        line = lines[i]
        if line.startswith("##") and i != start:
            break
        if not line.startswith("|") or line.startswith("|---") or "Rule count" in line:
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) != 3:
            continue
        tag = cells[0]
        if tag in counts:
            lines[i] = f"| {tag}{' ' * max(0, 8 - len(tag))} | {cells[1]} | {counts[tag]} |"
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="Report changes, write nothing")
    args = ap.parse_args()

    if not MAPPINGS.exists():
        print(f"MAPPINGS.md not found at {MAPPINGS}")
        return 1

    text = MAPPINGS.read_text(encoding="utf-8")

    if SECTION_HEADING in text:
        print("Section 07 already present - nothing to do.")
        return 0

    anchor = "## ATLAS Technique Index"
    if anchor not in text:
        print(f"Could not find '{anchor}'. Insert the section manually.")
        return 1

    # Insert before the horizontal rule that precedes the index tables.
    head, tail = text.split(anchor, 1)
    head = head.rstrip()
    if head.endswith("---"):
        head = head[: -len("---")].rstrip()
        separator = "\n\n---\n\n"
    else:
        separator = "\n\n"

    updated = head + "\n\n" + build_section() + separator + anchor + tail

    # Refresh the scope line.
    on_disk = len(list(SIGMA_DIR.glob("*.yml"))) if SIGMA_DIR.is_dir() else len(RULES)
    updated = re.sub(
        r"(\*\*Scope:\*\* )\d+( rule files)",
        lambda m: f"{m.group(1)}{43 + on_disk}{m.group(2)}",
        updated,
        count=1,
    )

    atlas, owasp = parse_index_counts(updated)
    updated = rewrite_index(updated, "## ATLAS Technique Index", atlas)
    updated = rewrite_index(updated, "## OWASP Top 10 for LLM Applications 2025 Index", owasp)

    if args.dry_run:
        print(f"Would add {len(RULES)} rules under '{SECTION_HEADING}'.")
        print(f"Would set scope to {43 + on_disk} rule files.")
        for label, heading, counts in (
            ("ATLAS", "## ATLAS Technique Index", atlas),
            ("OWASP", "## OWASP Top 10 for LLM Applications 2025 Index", owasp),
        ):
            before = current_index(text, heading)
            print(f"\n{label} index (before -> after):")
            for tag in sorted(set(before) | set(counts)):
                was, now = before.get(tag), counts.get(tag, 0)
                if tag not in before:
                    print(f"  {tag:12} (not indexed) -> {now}   NEW - add a row for this")
                elif was != now:
                    print(f"  {tag:12} {was} -> {now}")
            unchanged = sum(1 for t in before if before[t] == counts.get(t, 0))
            print(f"  ({unchanged} unchanged)")
        print("\nReview the deltas above. Existing counts were hand-maintained, so a")
        print("difference may be a pre-existing miscount rather than an effect of this")
        print("change. Rows the index lacks entirely must be added by hand.")
        return 0

    with MAPPINGS.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(updated)
    print(f"MAPPINGS.md updated: +{len(RULES)} rules, indexes recomputed.")
    print("Now run:  python artifacts/scripts/validate_mappings.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
