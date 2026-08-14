#!/usr/bin/env python3
"""Validate every AI agent artifact catalog entry against the JSON Schema.

Runs in CI and locally:  python scripts/validate.py
Exit code 1 on any failure, so it gates merges.
"""
import glob
import json
import re
import sys
from datetime import date
from pathlib import Path

try:
    import yaml
    from jsonschema import Draft202012Validator
except ImportError:
    sys.exit("Install deps first:  pip install pyyaml jsonschema")

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "schema" / "artifact.schema.json").read_text(encoding="utf-8"))
validator = Draft202012Validator(SCHEMA)

def main() -> int:
    files = sorted(glob.glob(str(ROOT / "catalog" / "*.yml")))
    if not files:
        print("No catalog entries found.")
        return 1

    failures = 0
    seen_ids: dict[str, str] = {}

    for path in files:
        name = Path(path).name
        try:
            doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            print(f"[YAML]   {name}: {exc}")
            failures += 1
            continue

        errors = sorted(validator.iter_errors(doc), key=lambda e: e.path)
        for err in errors:
            loc = ".".join(str(p) for p in err.absolute_path) or "(root)"
            print(f"[SCHEMA] {name}: {loc}: {err.message}")
        failures += len(errors)

        # Reject unfilled template scaffolds - these validate structurally but
        # carry no information, and a placeholder merged by accident is worse
        # than a missing entry.
        PLACEHOLDERS = ("Vendor or Project", "https://example.com",
                        "~/.example/config.json", "example.exe",
                        "What the tool is and what it does on an endpoint")
        blob = json.dumps(doc)
        hits = [p for p in PLACEHOLDERS if p in blob]
        if hits:
            print(f"[STUB]   {name}: unfilled template placeholder(s): "
                  f"{', '.join(hits[:3])}")
            failures += 1

        entry_id = doc.get("id")
        if entry_id in seen_ids:
            print(f"[DUPE]   {name}: id {entry_id} already used by {seen_ids[entry_id]}")
            failures += 1
        elif entry_id:
            seen_ids[entry_id] = name

        # Honesty gate: a low-confidence field must not sit inside a
        # high-confidence entry without being marked, because a catalog that
        # overstates certainty is worse than one with gaps.
        #
        # This used to check artifacts.disk only, which left registry, network,
        # process and credential rows able to hide an unmarked low-confidence
        # claim inside a high-confidence entry. Three of those classes could not
        # even carry the flag until the schema declared it.
        if doc.get("confidence") == "high":
            rows = [(a.get("path"), a) for a in doc.get("artifacts", {}).get("disk", [])]
            rows += [(a.get("key"), a) for a in doc.get("artifacts", {}).get("registry", [])]
            rows += [(a.get("indicator"), a) for a in doc.get("artifacts", {}).get("network", [])]
            rows += [(a.get("name"), a) for a in doc.get("artifacts", {}).get("process", [])]
            rows += [(c.get("location"), c) for c in doc.get("credentials", []) or []]
            for locator, row in rows:
                if row.get("confidence") == "low" and not row.get("unverified"):
                    print(f"[TRUST]  {name}: entry confidence=high but {locator!r} "
                          f"is low and unmarked. Either verify it, set "
                          f"unverified: true, or downgrade the entry.")
                    failures += 1

        # A tool documented as storing plaintext credentials, with no credential
        # locations listed, tells a responder the secret exists and gives them
        # nowhere to look. That is worse than saying nothing: it is the exact
        # question the catalog exists to answer, left blank.
        if (doc.get("capabilities") or {}).get("plaintext_credentials") is True \
                and not (doc.get("credentials") or []):
            print(f"[CREDS]  {name}: capabilities.plaintext_credentials is true but "
                  f"credentials is empty. List where the secret lives, or drop the "
                  f"capability claim.")
            failures += 1

    # Sigma rules ship as detection content, so they get checked too - a rule
    # that does not parse is worse than no rule, because nobody notices.
    sigma_files = sorted(glob.glob(str(ROOT / "detections" / "sigma" / "*.yml")))
    seen_rule_ids = {}
    for path in sigma_files:
        name = Path(path).name
        try:
            rule = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            print(f"[SIGMA]  {name}: {exc}")
            failures += 1
            continue
        for field in ("title", "id", "description", "logsource", "detection", "level"):
            if not rule.get(field):
                print(f"[SIGMA]  {name}: missing required field {field!r}")
                failures += 1
        if isinstance(rule.get("detection"), dict) and "condition" not in rule["detection"]:
            print(f"[SIGMA]  {name}: detection block has no condition")
            failures += 1
        rule_id = rule.get("id")
        if rule_id in seen_rule_ids:
            print(f"[SIGMA]  {name}: duplicate rule id, also in {seen_rule_ids[rule_id]}")
            failures += 1
        elif rule_id:
            seen_rule_ids[rule_id] = name

    # Locators are machine-read. `path`, `location` and `config_path` are emitted
    # verbatim into the KAPE, Velociraptor and forensicartifacts feeds, so a
    # parenthetical or an arrow inside one does not degrade gracefully - it ships
    # as a glob that matches nothing. AIRT-0011 was publishing
    # "~/Library/Application Support/Claude/ (Windows: %APPDATA%\Claude\, ...)"
    # as a literal Velociraptor glob, and six more entries were doing the same
    # across 21 rows, all silently collecting zero. Two locations in one field is
    # a legitimate case and already has a spelling: " | ", which expand() splits
    # and the exporters understand. Anything else belongs in `description`.
    prose_in_locator = re.compile(r"\([A-Za-z]|  ->  ")
    for path in files:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        rows = [("disk", a.get("path"))
                for a in (doc.get("artifacts") or {}).get("disk") or []]
        rows += [("credential", c.get("location")) for c in doc.get("credentials") or []]
        rows += [("mcp", m.get("config_path")) for m in doc.get("mcp") or []]
        for kind, raw in rows:
            loc = str(raw or "").strip()
            if not loc or loc.startswith("<"):
                continue
            # Only judge fields that actually claim to be a filesystem path. A
            # keyring or a registry-style locator legitimately reads as prose and
            # the exporters already skip it.
            looks_like_path = loc.startswith(("~", "/", "%")) or re.match(r"^[A-Za-z]:", loc)
            if looks_like_path and prose_in_locator.search(loc):
                print(f"[LOCATOR] {Path(path).name}: {kind} locator carries prose. "
                      f"Move it to description, or use ' | ' for a second "
                      f"location: {loc[:64]}")
                failures += 1

    # Note style. Four styles had accumulated across 363 captions - sentence
    # case, ALL-CAPS, a shouted leading token, bare lowercase - with a terminal
    # period on about half. They render in one table column and one CSV field,
    # so the drift is visible to every reader. Gate it here rather than trusting
    # the next author to match a convention nobody wrote down.
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from normalize_notes import clean, clean_prose, each_note
    except ImportError:
        clean = None
    if clean:
        drift = 0
        for path in files:
            doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
            for holder, key in each_note(doc):
                before = holder.get(key) or ""
                if clean(before) != before:
                    if drift < 5:
                        print(f"[NOTE]   {Path(path).name}: {before[:70]}")
                    drift += 1
            prose = doc.get("abuse_potential") or ""
            if clean_prose(prose) != prose:
                print(f"[NOTE]   {Path(path).name}: abuse_potential is off style")
                drift += 1
        if drift:
            print(f"[NOTE]   {drift} note(s) are off style - run "
                  f"scripts/normalize_notes.py")
            failures += drift

    # Provenance coverage. The catalog states that confidence reflects where a
    # fact came from, so an entry with no reference asserts a provenance the
    # reader cannot check. Reported rather than failed, because the gap is real
    # and closing it needs research, not a commit - but reported on every run so
    # it stays visible and shrinks instead of being forgotten.
    # A tool documented as MCP-capable with no MCP location is the same defect as
    # plaintext_credentials with no credentials: it tells a responder the config
    # exists and gives them nowhere to look. The MCP config records what the agent
    # was authorised to execute, and under a rug-pull it is the only authoritative
    # record - so this is the exact question the catalog exists to answer, left
    # blank. This was a report while the backlog of 25 was worked down. The count
    # reached zero on 2026-08-13, so it is a hard gate now, on the same footing as
    # the credential check - a report nobody has to act on drifts straight back up.
    #
    # Closing it is not always a matter of finding the path. Three of the 25 were
    # claiming a capability the tool does not have: Ollama is an inference server
    # that needs a bridge, Aider has open requests asking for MCP support, and the
    # computer-use demo is a plain agent loop. Ask whether the tool hosts MCP at
    # all before going looking for its config.
    no_mcp = []
    for path in files:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        if (doc.get("capabilities") or {}).get("mcp_capable") is True \
                and not (doc.get("mcp") or []):
            no_mcp.append(f"{doc.get('id')} {doc.get('name')}")
    if no_mcp:
        print(f"[MCP]    {len(no_mcp)} entr(ies) declare mcp_capable with no MCP "
              f"location. Either record where the config lives, or drop the claim. "
              f"mechanism has five values - a tool with no config file is "
              f"in-code, server, database or cloud, not an empty block:")
        for m in no_mcp:
            print(f"[MCP]      {m}")
        failures += len(no_mcp)

    # Data source coverage. Every row class, every Sigma logsource category and
    # every event log channel in the corpus has to map to a defined telemetry
    # source, and no source may claim coverage the corpus does not supply. This
    # is a hard gate rather than a report, because it fails the moment somebody
    # adds a rule in a new logsource category - which is exactly when the
    # "what do I need to be logging" answer would otherwise go quietly stale.
    try:
        from data_sources import audit, coverage, load_sources
    except ImportError:
        audit = None
    if audit:
        entries = [yaml.safe_load(Path(p).read_text(encoding="utf-8")) for p in files]
        for problem in audit(coverage(load_sources(), entries)):
            print(f"[SOURCE] {problem}")
            failures += 1

    unsourced = []
    # Verification age, on the quarterly cadence docs/REVERIFICATION.md sets.
    # last_modified tracks edits and answers the wrong question - a typo fix moves
    # it and verifies nothing - so staleness is measured from last_verified, and
    # an entry that has never been checked says so rather than looking fresh.
    stale, never = [], []
    today = date.today()
    for path in files:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        label = f"{doc.get('id')} {doc.get('name')}"
        if not (doc.get("references") or []):
            unsourced.append(label)
        seen = doc.get("last_verified")
        if not seen:
            never.append(label)
            continue
        try:
            age = (today - date.fromisoformat(str(seen))).days
        except ValueError:
            print(f"[STALE]  {Path(path).name}: last_verified {seen!r} is not a date")
            failures += 1
            continue
        if age > 90:
            stale.append((age, label))

    if unsourced:
        print(f"[REFS]   {len(files) - len(unsourced)}/{len(files)} entries carry a "
              f"reference. Still unsourced:")
        for u in unsourced:
            print(f"[REFS]     {u}")
    if never or stale:
        checked = len(files) - len(never)
        print(f"[STALE]  {checked}/{len(files)} entries have been verified; "
              f"{len(stale)} are past the 90-day cadence.")
        for age, label in sorted(stale, reverse=True):
            print(f"[STALE]    {age:4}d  {label}")
        for label in never:
            print(f"[STALE]    never  {label}")

    print(f"\n{len(files)} entries + {len(sigma_files)} sigma rules checked, "
          f"{failures} problem(s).")
    return 1 if failures else 0

if __name__ == "__main__":
    sys.exit(main())
