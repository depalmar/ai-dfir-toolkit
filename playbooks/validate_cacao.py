#!/usr/bin/env python3
"""
validate_cacao.py — conformance checker for CACAO Security Playbooks v2.0.

Checks the normative MUST/SHOULD rules from the OASIS CACAO Security Playbooks Version 2.0
Committee Specification 01 (27 November 2023) that are cheap to verify statically. This is a
lint, not a full JSON-Schema validation — it exists so playbooks in this repo cannot drift into
plausible-looking-but-invalid JSON.

Rules enforced (spec section in brackets):
  * type == "playbook", spec_version == "cacao-2.0"                              [3.1]
  * required properties present: type, spec_version, id, name, created_by,
    created, modified, workflow_start, workflow                                  [3.1]
  * identifiers are "<type>--<uuid>"; workflow keys match their step type        [10.10]
  * created/modified are RFC3339 with EXACTLY three decimal places               [3.1]
  * modified >= created                                                          [2.3.1]
  * workflow contains at least a start, an action/playbook-action, and an end    [3.1]
  * workflow_start references an existing start step                             [3.1]
  * start step has no on_success/on_failure                                      [4.3]
  * end step has no on_completion/on_success/on_failure                          [4.4]
  * on_completion is mutually exclusive with on_success/on_failure               [4.1]
  * every step reference (on_*, next_steps, on_true/on_false, cases) resolves    [4.x]
  * action steps have commands (non-empty) and an agent                          [4.5]
  * parallel steps have >= 2 next_steps                                          [4.7]
  * if-condition has condition + on_true; while-condition has condition+on_true  [4.8/4.9]
  * switch-condition has switch + cases                                          [4.10]
  * agent/target references resolve to agent_definitions/target_definitions      [4.5]
  * commands carry a `command` or `command_b64`                                  [5.1]
  * sigma/yara/kestrel/elastic commands MUST use command_b64                     [5.2]
  * if playbook_types is populated, playbook_activities MUST be non-empty        [3.1]
  * every declared playbook_activity appears on some command in the workflow     [3.1]
  * required activity per playbook type is present (e.g. investigation ->
    identify-indicators, mitigation -> eliminate-risk)                           [3.1.2]
  * every step is reachable from workflow_start                                  [advisory]
  * markings resolve to data_marking_definitions                                 [3.1]

Usage:
  python3 validate_cacao.py playbooks/*.json
  python3 validate_cacao.py --quiet playbooks/          # exit 1 on any ERROR
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SPEC_VERSION = "cacao-2.0"

REQUIRED_PLAYBOOK_PROPS = [
    "type", "spec_version", "id", "name", "created_by", "created", "modified",
    "workflow_start", "workflow",
]

STEP_TYPES = {
    "start", "end", "action", "playbook-action", "parallel",
    "if-condition", "while-condition", "switch-condition",
}

PLAYBOOK_TYPE_OV = {
    "attack", "detection", "engagement", "investigation",
    "mitigation", "notification", "prevention", "remediation",
}

# Activities marked MUST for each playbook type in spec section 3.1.2.
REQUIRED_ACTIVITY = {
    "notification": "compose-content",
    "detection": "match-indicator",
    "investigation": "identify-indicators",
    "prevention": "configure-systems",
    "mitigation": "eliminate-risk",
    "remediation": "restore-capabilities",
    "attack": "step-sequence",
}
# engagement requires three activities
ENGAGEMENT_REQUIRED = {"prepare-engagement", "execute-operation", "analyze-engagement-results"}

COMMAND_TYPES_REQUIRING_B64 = {"sigma", "yara", "kestrel", "elastic"}

ID_RE = re.compile(r"^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


class Report:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def err(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    @property
    def ok(self) -> bool:
        return not self.errors


def _step_prefix(step_id: str) -> str:
    return step_id.split("--", 1)[0] if "--" in step_id else ""


def validate(pb: dict[str, Any], rep: Report) -> None:
    # --- playbook-level required properties -------------------------------------------------
    for prop in REQUIRED_PLAYBOOK_PROPS:
        if prop not in pb:
            rep.err(f"missing required playbook property: {prop}")
    if pb.get("type") != "playbook":
        rep.err(f'type MUST be "playbook" (got {pb.get("type")!r})')
    if pb.get("spec_version") != SPEC_VERSION:
        rep.err(f'spec_version MUST be "{SPEC_VERSION}" (got {pb.get("spec_version")!r})')

    pid = str(pb.get("id", ""))
    if not ID_RE.match(pid):
        rep.err(f"id is not a valid CACAO identifier: {pid!r}")
    elif not pid.startswith("playbook--"):
        rep.err(f'playbook id MUST start with "playbook--": {pid!r}')

    for prop in ("created", "modified"):
        val = pb.get(prop)
        if val is not None and not TS_RE.match(str(val)):
            rep.err(f"{prop} MUST be RFC3339 with exactly three decimal places: {val!r}")
    if TS_RE.match(str(pb.get("created", ""))) and TS_RE.match(str(pb.get("modified", ""))):
        if str(pb["modified"]) < str(pb["created"]):
            rep.err("modified MUST NOT be earlier than created")

    cb = str(pb.get("created_by", ""))
    if cb and not cb.startswith("identity--"):
        rep.err(f"created_by MUST reference a STIX identity object: {cb!r}")

    for num_prop in ("priority", "severity", "impact"):
        if num_prop in pb and not (0 <= int(pb[num_prop]) <= 100):
            rep.err(f"{num_prop} MUST be between 0 and 100 (got {pb[num_prop]})")

    workflow = pb.get("workflow")
    if not isinstance(workflow, dict) or not workflow:
        rep.err("workflow MUST be a non-empty dictionary")
        return

    # --- workflow step structure -------------------------------------------------------------
    types_present: set[str] = set()
    for sid, step in workflow.items():
        if not isinstance(step, dict):
            rep.err(f"workflow[{sid}] is not an object")
            continue
        stype = step.get("type")
        types_present.add(str(stype))
        if stype not in STEP_TYPES:
            rep.err(f"{sid}: invalid step type {stype!r}")
        if not ID_RE.match(sid):
            rep.err(f"workflow key is not a valid identifier: {sid!r}")
        elif _step_prefix(sid) != stype:
            rep.err(f"{sid}: key prefix does not match step type {stype!r}")

        # branching-property exclusivity
        if "on_completion" in step and ("on_success" in step or "on_failure" in step):
            rep.err(f"{sid}: on_completion MUST NOT be combined with on_success/on_failure")
        if stype == "start" and ("on_success" in step or "on_failure" in step):
            rep.err(f"{sid}: start step MUST NOT use on_success/on_failure")
        if stype == "end":
            for banned in ("on_completion", "on_success", "on_failure"):
                if banned in step:
                    rep.err(f"{sid}: end step MUST NOT use {banned}")

        # type-specific required properties
        if stype == "action":
            cmds = step.get("commands")
            if not isinstance(cmds, list) or not cmds:
                rep.err(f"{sid}: action step MUST have a non-empty commands list")
            if "agent" not in step:
                rep.err(f"{sid}: action step MUST have an agent")
            for i, c in enumerate(cmds or []):
                if not isinstance(c, dict):
                    rep.err(f"{sid}: command[{i}] is not an object")
                    continue
                if "command" not in c and "command_b64" not in c:
                    rep.err(f"{sid}: command[{i}] MUST have command or command_b64")
                ctype = c.get("type")
                if ctype in COMMAND_TYPES_REQUIRING_B64 and "command_b64" not in c:
                    rep.err(f"{sid}: command[{i}] of type {ctype!r} MUST use command_b64")
        if stype == "playbook-action" and "playbook_id" not in step:
            rep.err(f"{sid}: playbook-action MUST have playbook_id")
        if stype == "parallel":
            ns = step.get("next_steps")
            if not isinstance(ns, list) or len(ns) < 2:
                rep.err(f"{sid}: parallel step MUST have at least two next_steps")
        if stype in ("if-condition", "while-condition"):
            if "condition" not in step:
                rep.err(f"{sid}: {stype} MUST have a condition")
            if "on_true" not in step:
                rep.err(f"{sid}: {stype} MUST have on_true")
        if stype == "switch-condition":
            if "switch" not in step:
                rep.err(f"{sid}: switch-condition MUST have switch")
            if not isinstance(step.get("cases"), dict) or not step.get("cases"):
                rep.err(f"{sid}: switch-condition MUST have a non-empty cases dictionary")

    # required step kinds present
    if "start" not in types_present:
        rep.err("workflow MUST contain a start step")
    if "end" not in types_present:
        rep.err("workflow MUST contain an end step")
    if not ({"action", "playbook-action"} & types_present):
        rep.err("workflow MUST contain an action or playbook-action step")

    # workflow_start resolves to a start step
    ws = pb.get("workflow_start")
    if ws not in workflow:
        rep.err(f"workflow_start {ws!r} not present in workflow")
    elif workflow[ws].get("type") != "start":
        rep.err(f"workflow_start {ws!r} MUST reference a start step")

    # --- reference resolution ----------------------------------------------------------------
    def refs_of(step: dict[str, Any]) -> list[str]:
        out: list[str] = []
        for k in ("on_completion", "on_success", "on_failure", "on_true", "on_false"):
            if isinstance(step.get(k), str):
                out.append(step[k])
        if isinstance(step.get("next_steps"), list):
            out.extend([s for s in step["next_steps"] if isinstance(s, str)])
        if isinstance(step.get("cases"), dict):
            out.extend([v for v in step["cases"].values() if isinstance(v, str)])
        return out

    agents = pb.get("agent_definitions", {}) or {}
    targets = pb.get("target_definitions", {}) or {}
    for sid, step in workflow.items():
        if not isinstance(step, dict):
            continue
        for ref in refs_of(step):
            if ref not in workflow:
                rep.err(f"{sid}: dangling step reference {ref!r}")
        ag = step.get("agent")
        if ag and ag not in agents:
            rep.err(f"{sid}: agent {ag!r} not in agent_definitions")
        for t in step.get("targets", []) or []:
            if t not in targets:
                rep.err(f"{sid}: target {t!r} not in target_definitions")

    for m in pb.get("markings", []) or []:
        if m not in (pb.get("data_marking_definitions", {}) or {}):
            rep.err(f"marking {m!r} not in data_marking_definitions")

    # --- reachability (advisory) --------------------------------------------------------------
    if ws in workflow:
        seen: set[str] = set()
        stack = [ws]
        while stack:
            cur = stack.pop()
            if cur in seen or cur not in workflow:
                continue
            seen.add(cur)
            stack.extend(refs_of(workflow[cur]))
        for sid in workflow:
            if sid not in seen:
                rep.warn(f"{sid}: step is unreachable from workflow_start")

    # --- activity metadata --------------------------------------------------------------------
    ptypes = pb.get("playbook_types") or []
    pacts = pb.get("playbook_activities") or []
    if ptypes and not pacts:
        rep.err("playbook_activities MUST be populated when playbook_types is populated")
    for pt in ptypes:
        if pt not in PLAYBOOK_TYPE_OV:
            rep.warn(f"playbook_type {pt!r} is not in playbook-type-ov")
        req = REQUIRED_ACTIVITY.get(pt)
        if req and req not in pacts:
            rep.err(f'playbook_type "{pt}" requires activity "{req}" in playbook_activities')
        if pt == "engagement" and not ENGAGEMENT_REQUIRED <= set(pacts):
            rep.err(f"engagement playbooks require activities {sorted(ENGAGEMENT_REQUIRED)}")

    # every declared activity must be reflected in a workflow step's commands
    used: set[str] = set()
    for step in workflow.values():
        if not isinstance(step, dict):
            continue
        for c in step.get("commands", []) or []:
            if isinstance(c, dict) and c.get("playbook_activity"):
                used.add(c["playbook_activity"])
    for a in pacts:
        if a not in used:
            rep.err(f'declared playbook_activity "{a}" is not reflected in any workflow command')


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Validate CACAO v2.0 playbooks.")
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("--quiet", action="store_true", help="only print failures")
    args = ap.parse_args(argv)

    files: list[Path] = []
    for p in args.paths:
        if p.is_dir():
            files.extend(sorted(p.glob("*.json")))
        elif p.suffix == ".json":
            files.append(p)
    if not files:
        sys.stderr.write("no .json playbooks found\n")
        return 1

    failed = 0
    for f in files:
        rep = Report(f)
        try:
            pb = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            rep.err(f"invalid JSON: {e}")
            pb = None
        if isinstance(pb, dict):
            validate(pb, rep)
        if rep.ok:
            if not args.quiet:
                w = f" ({len(rep.warnings)} warning(s))" if rep.warnings else ""
                print(f"PASS  {f.name}{w}")
                for msg in rep.warnings:
                    print(f"        WARN  {msg}")
        else:
            failed += 1
            print(f"FAIL  {f.name}")
            for msg in rep.errors:
                print(f"        ERROR {msg}")
            for msg in rep.warnings:
                print(f"        WARN  {msg}")
    print(f"\n{len(files) - failed}/{len(files)} playbooks conform to CACAO {SPEC_VERSION}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
