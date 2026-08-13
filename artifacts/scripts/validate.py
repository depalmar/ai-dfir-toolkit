#!/usr/bin/env python3
"""Validate every AI agent artifact catalog entry against the JSON Schema.

Runs in CI and locally:  python scripts/validate.py
Exit code 1 on any failure, so it gates merges.
"""
import glob
import json
import sys
from pathlib import Path

try:
    import yaml
    from jsonschema import Draft202012Validator
except ImportError:
    sys.exit("Install deps first:  pip install pyyaml jsonschema")

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "schema" / "artifact.schema.json").read_text())
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
            doc = yaml.safe_load(Path(path).read_text())
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
            rule = yaml.safe_load(Path(path).read_text())
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
            doc = yaml.safe_load(Path(path).read_text())
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

    print(f"\n{len(files)} entries + {len(sigma_files)} sigma rules checked, "
          f"{failures} problem(s).")
    return 1 if failures else 0

if __name__ == "__main__":
    sys.exit(main())
