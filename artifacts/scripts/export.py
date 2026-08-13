#!/usr/bin/env python3
"""Export the catalog to JSON and CSV feeds for downstream consumers.

ai-dfir-toolkit and any detection pipeline should consume these feeds rather
than parsing the YAML directly, so the on-disk format can change without
breaking consumers.

    python scripts/export.py            # writes docs/api/
"""
import csv
import glob
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "api"
OUT.mkdir(parents=True, exist_ok=True)


def write_lf(path: Path, text: str) -> None:
    """Write with LF endings on every platform.

    Python writes CRLF on Windows by default. That would make the generated
    feeds differ by platform and break the CI staleness check on a diff that is
    pure line-ending noise.
    """
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from data_sources import volatility_of  # noqa: E402  (same-directory helper)

entries = [yaml.safe_load(Path(p).read_text())
           for p in sorted(glob.glob(str(ROOT / "catalog" / "*.yml")))]


def locator(kind, a):
    """The identifier a responder types into a query bar, per artifact class.

    Every class has its own key, and the fallback chain here missed eventlog
    when that class was added - which shipped 30 rows to the published CSV with
    an empty artifact column. Match on the class instead of guessing from the
    keys present, so a seventh class fails loudly rather than silently.
    """
    if kind == "eventlog":
        return f"{a.get('channel', '')} EID {a.get('event_id', '')}".strip()
    return a.get("path") or a.get("key") or a.get("indicator") or a.get("name") or ""

write_lf(OUT / "catalog.json", json.dumps(entries, indent=2))

# Flat artifact feed - one row per artifact, the shape most tools want.
rows = []
for e in entries:
    for kind, items in e.get("artifacts", {}).items():
        for a in items:
            rows.append({
                "entry_id": e["id"],
                "tool": e["name"],
                "category": e["category"],
                "entry_risk": e["risk"],
                "artifact_class": kind,
                "artifact": locator(kind, a),
                "os": "|".join(a.get("os", [])) if isinstance(a.get("os"), list) else "",
                "forensic_value": a.get("forensic_value", ""),
                "evidence_type": "|".join(a.get("evidence_type", [])),
                "description": a.get("description", ""),
                "confidence": a.get("confidence", ""),
                # Appended, never inserted: docs/api/artifacts.csv is a
                # published feed and a column that moves breaks every consumer
                # that reads by position.
                "volatility": volatility_of(kind, a),
                "retention": a.get("retention", ""),
            })
    for c in e.get("credentials", []):
        rows.append({
            "entry_id": e["id"], "tool": e["name"], "category": e["category"],
            "entry_risk": e["risk"], "artifact_class": "credential",
            "artifact": c["location"],
            "os": "|".join(c.get("os", [])),
            "forensic_value": "high",
            "evidence_type": "credential-access",
            "description": f"{c.get('storage', '')}: {c.get('description', '')}",
            "confidence": c.get("confidence", ""),
            "volatility": volatility_of("credential", c),
            "retention": "",
        })
    for m in e.get("mcp", []):
        rows.append({
            "entry_id": e["id"], "tool": e["name"], "category": e["category"],
            "entry_risk": e["risk"], "artifact_class": "mcp-config",
            "artifact": m.get("config_path") or m.get("indicator", ""), "os": "",
            "forensic_value": "high",
            "evidence_type": "execution|persistence",
            "description": m.get("notes", ""),
            "confidence": m.get("confidence", "high"),
            "volatility": volatility_of("mcp-config", m),
            "retention": "",
        })

with (OUT / "artifacts.csv").open("w", newline="", encoding="utf-8") as fh:
    writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)

# Collection manifest - the triage sweep list, path-only.
manifest = sorted({
    r["artifact"] for r in rows
    if r["forensic_value"] == "high" and r["artifact_class"] in ("disk", "credential", "mcp-config")
})
write_lf(OUT / "collection-targets.txt", "\n".join(manifest) + "\n")

# Detection index so consumers can pull rules without walking the tree.
detections = []
for path in sorted(glob.glob(str(ROOT / "detections" / "sigma" / "*.yml"))):
    rule = yaml.safe_load(Path(path).read_text())
    detections.append({
        "file": f"detections/sigma/{Path(path).name}",
        "id": rule.get("id"),
        "title": rule.get("title"),
        "level": rule.get("level"),
        "tags": rule.get("tags", []),
        "logsource": rule.get("logsource", {}),
    })
write_lf(OUT / "detections.json", json.dumps(detections, indent=2))

print(f"{len(entries)} entries -> {len(rows)} artifact rows")
print(f"{len(detections)} sigma rules indexed")
print(f"{len(manifest)} high-value collection targets")
