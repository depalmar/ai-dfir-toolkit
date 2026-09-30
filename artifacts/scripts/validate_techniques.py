#!/usr/bin/env python3
"""Resolve every ATLAS and ATT&CK id in the catalog against real framework data.

The schema validates these ids by shape only - `^AML\\.T[0-9]{4}(\\.[0-9]{3})?$`
and `^T[0-9]{4}(\\.[0-9]{3})?$` - so `AML.T9999` passes CI today, and so does a
technique MITRE deprecated three releases ago. Shape is not existence.

    python scripts/validate_techniques.py           # gate, writes nothing
    python scripts/validate_techniques.py --check   # same, explicit
    python scripts/validate_techniques.py --refresh # re-pin from upstream

Validation runs offline against `schema/technique-ids.json`, which is vendored
and pinned. It is deliberately not fetched at gate time: a gate that silently
follows upstream lets a MITRE rename break the build with no diff to explain it,
and CI that needs the network fails for reasons that have nothing to do with the
change under test. `--refresh` is the only thing that touches the network, and it
rewrites the pin so the bump shows up in review as a diff someone signs off on.

Two upstream traps, both of which produce a plausible wrong answer rather than an
error, and both of which this script exists to avoid repeating:

  ATLAS ships a `dist/ATLAS.yaml` that opens by declaring itself deprecated. It
  carries fewer techniques than the current release. Validating against it
  reports success while checking stale data, so `--refresh` reads
  `dist/manifest.yaml` and takes the newest release path instead.

  The ATLAS YAML uses anchors, so techniques exist that never appear as literal
  text in the file. Grepping it undercounts by roughly sixteen and would reject
  valid ids as unknown. Parse it, never grep it.
"""
from __future__ import annotations

import argparse
import glob
import json
import re
import sys
import urllib.request
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PINNED = ROOT / "schema" / "technique-ids.json"

ATLAS_MANIFEST = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/manifest.yaml"
ATLAS_BASE = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/"
ATTACK_INDEX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=180) as r:
        return r.read()


def version_key(s: str) -> tuple:
    """Numeric version sort, component-wise.

    Two ways to get this wrong, both of which pick a real-looking older release
    rather than raising: sorting as strings puts ATT&CK 9.0 above 17.0, and
    stripping the separator first turns ATLAS 2025.11.2 into 2025112, which
    beats 2026.07 at 202607. Compare tuples of ints, per component.
    """
    try:
        return tuple(int(x) for x in str(s).split("."))
    except ValueError:
        return (0,)


def _load_yaml(url: str, local: Path | None, rel: str):
    """Read one upstream YAML file, from a local mirror when one is given.

    The mirror path exists because some runners reach GitHub's git transport but
    not raw.githubusercontent.com. A shallow clone of the upstream repository is
    byte-identical to what the URL serves, so the pin records the canonical URL
    either way - where the bytes came from is transport, not provenance.
    """
    if local:
        return yaml.safe_load((local / rel).read_text(encoding="utf-8"))
    return yaml.safe_load(fetch(url + rel).decode("utf-8"))


def _load_json(url: str, local: Path | None, rel: str):
    if local:
        return json.loads((local / rel).read_text(encoding="utf-8"))
    return json.loads(fetch(url))


def _values(node):
    """ATLAS v6 keys objects by id; earlier formats used lists. Accept both."""
    return list(node.values()) if isinstance(node, dict) else list(node or [])


def refresh_atlas(local: Path | None = None) -> dict:
    manifest = _load_yaml(ATLAS_BASE, local, "manifest.yaml")
    newest = max(manifest, key=lambda r: version_key(str(r["release"])))
    path = newest["versions"][0]["path"]
    doc = _load_yaml(ATLAS_BASE, local, path)

    # Bucket by object type, not by id prefix. The first version of this walked
    # every dict and kept any id starting "AML.T" - which is also the prefix of
    # every tactic, so sixteen tactics were pinned as techniques and the count
    # read 194 where upstream said 178.
    tactics = {t["id"]: t.get("name", "") for t in _values(doc.get("tactics"))}
    techniques = {t["id"]: t.get("name", "") for t in _values(doc.get("techniques"))}
    mitigations = {m["id"]: m.get("name", "") for m in _values(doc.get("mitigations"))}

    technique_tactics: dict[str, list[str]] = {}
    mitigates: dict[str, list[str]] = {}
    employs: dict[str, list[str]] = {}
    order: list[tuple[int, str]] = []
    for src, rels in (doc.get("relationships") or {}).items():
        for rtype, items in (rels or {}).items():
            for r in items or []:
                tgt = r.get("target")
                if rtype == "achieves":
                    technique_tactics.setdefault(src, []).append(tgt)
                elif rtype == "mitigates":
                    mitigates.setdefault(tgt, []).append(src)
                elif rtype == "employs":
                    employs.setdefault(src, []).append(tgt)
                elif rtype == "sequences":
                    order.append((int(r.get("position", 0)), tgt))

    case_studies = {}
    for cs in _values(doc.get("case-studies")):
        row = {"name": cs.get("name", "")}
        # Type and date only. Upstream also ships free-text actor, target and
        # reporter fields, which name the organisations that wrote or were the
        # subject of each study. This repository's data stays organisation-
        # neutral beyond what a catalog entry itself cites, so those fields are
        # left upstream - the id links to them.
        for key in ("type", "date"):
            if cs.get(key):
                row[key] = str(cs[key])
        row["techniques"] = sorted(set(employs.get(cs["id"], [])))
        case_studies[cs["id"]] = row

    return {
        "release": str(newest["release"]),
        "release_date": str(newest.get("release-date", "")),
        "source": ATLAS_BASE + path,
        "tactic_order": [t for _, t in sorted(order)] or sorted(tactics),
        "tactics": dict(sorted(tactics.items())),
        "techniques": dict(sorted(techniques.items())),
        "technique_tactics": {k: sorted(set(v)) for k, v in sorted(technique_tactics.items())},
        "mitigations": dict(sorted(mitigations.items())),
        "technique_mitigations": {k: sorted(set(v)) for k, v in sorted(mitigates.items())},
        "case_studies": dict(sorted(case_studies.items())),
    }


def refresh_attack(local: Path | None = None) -> dict:
    index = _load_json(ATTACK_INDEX, local, "index.json")
    enterprise = next(c for c in index["collections"] if c["name"] == "Enterprise ATT&CK")
    latest = max(enterprise["versions"], key=lambda v: version_key(v["version"]))
    rel = latest["url"].split("/attack-stix-data/master/", 1)[-1]
    bundle = _load_json(latest["url"], local, rel)

    def ext_id(obj):
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                return ref["external_id"]
        return None

    attack: dict[str, str] = {}
    retired: list[str] = []
    tactic_by_short: dict[str, str] = {}
    tactics: dict[str, str] = {}
    technique_tactics: dict[str, list[str]] = {}
    groups, campaigns, software = {}, {}, {}
    for obj in bundle.get("objects", []):
        ident = ext_id(obj)
        if not ident:
            continue
        gone = bool(obj.get("x_mitre_deprecated") or obj.get("revoked"))
        kind = obj.get("type")
        if kind == "x-mitre-tactic":
            tactics[ident] = obj.get("name", "")
            tactic_by_short[obj.get("x_mitre_shortname", "")] = ident
        elif kind == "attack-pattern":
            attack[ident] = obj.get("name", "")
            if gone:
                retired.append(ident)
            technique_tactics[ident] = [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                                        if p.get("kill_chain_name") == "mitre-attack"]
        elif gone:
            continue
        elif kind == "intrusion-set":
            # Name only. ATT&CK's alias lists carry every vendor's naming scheme
            # for the group, and this repository does not republish vendor
            # attributions beyond what an actor profile itself cites. Nothing
            # here uses the aliases; an actor profile records the ones its
            # sources use, with the source named.
            groups[ident] = {"name": obj.get("name", "")}
        elif kind == "campaign":
            campaigns[ident] = {"name": obj.get("name", ""),
                                "first_seen": str(obj.get("first_seen", ""))[:10],
                                "last_seen": str(obj.get("last_seen", ""))[:10]}
        elif kind in ("malware", "tool"):
            software[ident] = {"name": obj.get("name", ""), "type": kind}

    return {
        "version": latest["version"],
        "source": latest["url"],
        "techniques": dict(sorted(attack.items())),
        "retired": sorted(set(retired)),
        "tactics": dict(sorted(tactics.items())),
        "technique_tactics": {k: sorted(tactic_by_short.get(s, s) for s in v)
                              for k, v in sorted(technique_tactics.items()) if v},
        "groups": dict(sorted(groups.items())),
        "campaigns": dict(sorted(campaigns.items())),
        "software": dict(sorted(software.items())),
    }


def refresh(atlas_dir: Path | None = None, attack_dir: Path | None = None) -> dict:
    return {
        "_comment": "Generated by scripts/validate_techniques.py --refresh. Do not hand-edit.",
        "retrieved": date.today().isoformat(),
        "atlas": refresh_atlas(atlas_dir),
        "attack": refresh_attack(attack_dir),
    }


# Every surface that carries a framework id. The gate used to read catalog/*.yml
# alone, so AML.T0104 and AML.T0019 - both folded into AML.T0115 in ATLAS
# 2026.07 - sat in a case study, MAPPINGS, two rules and a playbook for a month
# while CI stayed green. An id is an id wherever it is written.
TEXT_SURFACES = [
    "MAPPINGS.md",
    "playbooks/*.json",
    "0[0-9]-*/*",
    "artifacts/detections/**/*",
    "artifacts/case-studies/*.yml",
    "artifacts/intel/**/*.yml",
    "docs/ai-dfir-investigation-guide.md",
    "README.md",
]
ATLAS_ID = re.compile(r"\bAML\.(?:TA|T|M|CS)\d{4}(?:\.\d{3})?\b")


def surface_ids(repo: Path):
    """(file, id) for every ATLAS id written anywhere on a text surface."""
    seen = set()
    for pattern in TEXT_SURFACES:
        for f in sorted(repo.glob(pattern)):
            if not f.is_file() or f in seen or f.suffix.lower() in (".png", ".jpg", ".svg", ".pdf"):
                continue
            seen.add(f)
            try:
                text = f.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for m in ATLAS_ID.finditer(text):
                yield f.relative_to(repo), m.group(0)


def _as_list(v):
    if not v:
        return []
    return v if isinstance(v, list) else [v]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="validate only - the default, accepted for symmetry with the other gates")
    ap.add_argument("--refresh", action="store_true",
                    help="re-pin schema/technique-ids.json from upstream (network)")
    ap.add_argument("--atlas-dir", type=Path,
                    help="read ATLAS from a local atlas-data/dist mirror instead of the network")
    ap.add_argument("--attack-dir", type=Path,
                    help="read ATT&CK from a local attack-stix-data mirror instead of the network")
    ap.add_argument("--advise", action="store_true",
                    help="also list parents whose subtechniques might be a more precise mapping")
    args = ap.parse_args()

    if args.refresh:
        data = refresh(args.atlas_dir, args.attack_dir)
        # newline="\n" explicitly: this file is generated on whatever platform
        # the refresher happens to run on, and the repo keeps generated output
        # byte-identical across platforms.
        with open(PINNED, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        a = data["atlas"]
        print(f"ATLAS   {a['release']:>8}  {len(a['tactics'])} tactics, "
              f"{len(a['techniques'])} techniques, {len(a['mitigations'])} mitigations, "
              f"{len(a['case_studies'])} case studies")
        print(f"ATT&CK  {data['attack']['version']:>8}  "
              f"{len(data['attack']['techniques'])} techniques "
              f"({len(data['attack']['retired'])} deprecated or revoked), "
              f"{len(data['attack']['groups'])} groups, "
              f"{len(data['attack']['campaigns'])} campaigns")
        print(f"pinned to {PINNED.relative_to(ROOT)}")
        return 0

    if not PINNED.exists():
        print(f"{PINNED.relative_to(ROOT)} is missing - run --refresh", file=sys.stderr)
        return 1

    pin = json.loads(PINNED.read_text(encoding="utf-8"))
    atlas = pin["atlas"]["techniques"]
    attack = pin["attack"]["techniques"]
    retired = set(pin["attack"]["retired"])

    # Parent -> subtechniques, built once. Scanning every id per technique per
    # entry re-walks the whole framework a few hundred times for one lookup.
    children: dict[str, list[str]] = {}
    if args.advise:
        for ident in atlas:
            # rpartition, not partition: AML.T0051.000 splits on the LAST dot.
            # Splitting on the first one makes every parent "AML" and silently
            # produces zero advisories rather than an error.
            parent, _, sub = ident.rpartition(".")
            if sub and len(sub) == 3 and sub.isdigit():
                children.setdefault(parent, []).append(ident)
        for subs in children.values():
            subs.sort()

    problems: list[str] = []
    advisories: list[str] = []

    for path in sorted(glob.glob(str(ROOT / "catalog" / "*.yml"))):
        entry = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        eid = entry.get("id", Path(path).name)

        for ident in entry.get("atlas_techniques") or []:
            if ident not in atlas:
                problems.append(f"{eid}: atlas_techniques {ident} is not in ATLAS "
                                f"{pin['atlas']['release']}")
            elif args.advise:
                subs = children.get(ident, [])
                if subs:
                    advisories.append(
                        f"{eid}: {ident} ({atlas[ident]}) has {len(subs)} subtechnique(s) - "
                        f"a more precise mapping may exist: {', '.join(subs)}")

        for ident in entry.get("attack_techniques") or []:
            if ident not in attack:
                problems.append(f"{eid}: attack_techniques {ident} is not in Enterprise "
                                f"ATT&CK {pin['attack']['version']}")
            elif ident in retired:
                problems.append(f"{eid}: attack_techniques {ident} ({attack[ident]}) is "
                                f"deprecated or revoked in {pin['attack']['version']}")

    # Everything else that carries an id. Catalog entries are checked above
    # with their field names; these are checked by value, wherever written.
    known_atlas = (set(atlas) | set(pin["atlas"].get("tactics", {}))
                   | set(pin["atlas"].get("mitigations", {}))
                   | set(pin["atlas"].get("case_studies", {})))
    repo = ROOT.parent
    for rel, ident in sorted(set(surface_ids(repo))):
        if ident not in known_atlas:
            problems.append(f"{rel}: {ident} is not in ATLAS {pin['atlas']['release']}")

    # MAPPINGS writes ATLAS ids without the AML. prefix, and Sigma tags write
    # them as attack.atlas.tNNNN or atlas.aml-tNNNN - neither form is caught by
    # the text scan, so both go through the site loader's normaliser.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import site_data
    rows, _, _ = site_data.load_mappings()
    for name, row in rows.items():
        for raw in row.get("atlas", []):
            ident = site_data._norm_atlas(raw)
            if ident and ident not in atlas:
                problems.append(f"MAPPINGS.md {name}: {raw} is not in ATLAS "
                                f"{pin['atlas']['release']}")
    for rule in site_data.load_rules({}):
        for ident in rule.get("atlas", []):
            if ident not in atlas:
                problems.append(f"{rule['path']}: {ident} is not in ATLAS "
                                f"{pin['atlas']['release']}")
        for tag in rule.get("attack", []):
            m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", tag.lower())
            if m:
                ident = m.group(1).upper()
                if ident not in attack:
                    problems.append(f"{rule['path']}: {tag} is not in Enterprise ATT&CK "
                                    f"{pin['attack']['version']}")
                elif ident in retired:
                    problems.append(f"{rule['path']}: {tag} is deprecated or revoked")

    # Structured ATT&CK references on case studies and actor profiles.
    groups = pin["attack"].get("groups", {})
    campaigns = pin["attack"].get("campaigns", {})
    for f in sorted(glob.glob(str(ROOT / "case-studies" / "*.yml"))) + \
            sorted(glob.glob(str(ROOT / "intel" / "actors" / "*.yml"))):
        doc = yaml.safe_load(Path(f).read_text(encoding="utf-8")) or {}
        did = doc.get("id", Path(f).name)
        for ident in doc.get("attack") or []:
            if ident not in attack:
                problems.append(f"{did}: attack {ident} is not in Enterprise ATT&CK")
            elif ident in retired:
                problems.append(f"{did}: attack {ident} is deprecated or revoked")
        ext = doc.get("external_ids") or {}
        for ident in _as_list(ext.get("attack_campaign")):
            if ident not in campaigns:
                problems.append(f"{did}: ATT&CK campaign {ident} is not in "
                                f"{pin['attack']['version']}")
        for ident in _as_list(ext.get("attack_group")):
            if ident not in groups:
                problems.append(f"{did}: ATT&CK group {ident} is not in "
                                f"{pin['attack']['version']}")
        for ident in _as_list(ext.get("atlas_case_study")):
            if ident not in pin["atlas"].get("case_studies", {}):
                problems.append(f"{did}: ATLAS case study {ident} is not in "
                                f"{pin['atlas']['release']}")

    print(f"pinned: ATLAS {pin['atlas']['release']} ({len(atlas)} techniques, "
          f"{len(pin['atlas'].get('tactics', {}))} tactics), "
          f"ATT&CK {pin['attack']['version']} ({len(attack)} techniques), "
          f"retrieved {pin['retrieved']}")

    if advisories:
        print(f"\n{len(advisories)} advisory - not failures, --advise only:")
        for line in advisories:
            print(f"  [SUB]  {line}")

    if problems:
        print()
        for line in problems:
            print(f"  [BAD]  {line}", file=sys.stderr)

    print(f"\n{len(problems)} problem(s).")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
