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
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "api"
OUT.mkdir(parents=True, exist_ok=True)

entries = [yaml.safe_load(Path(p).read_text())
           for p in sorted(glob.glob(str(ROOT / "catalog" / "*.yml")))]

(OUT / "catalog.json").write_text(json.dumps(entries, indent=2))

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
                "artifact": a.get("path") or a.get("key") or a.get("indicator") or a.get("name"),
                "os": "|".join(a.get("os", [])) if isinstance(a.get("os"), list) else "",
                "forensic_value": a.get("forensic_value", ""),
                "evidence_type": "|".join(a.get("evidence_type", [])),
                "description": a.get("description", ""),
                "confidence": a.get("confidence", ""),
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
        })
    for m in e.get("mcp", []):
        rows.append({
            "entry_id": e["id"], "tool": e["name"], "category": e["category"],
            "entry_risk": e["risk"], "artifact_class": "mcp-config",
            "artifact": m["config_path"], "os": "",
            "forensic_value": "high",
            "evidence_type": "execution|persistence",
            "description": m.get("notes", ""),
            "confidence": "high",
        })

with (OUT / "artifacts.csv").open("w", newline="") as fh:
    writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)

# Collection manifest - the triage sweep list, path-only.
manifest = sorted({
    r["artifact"] for r in rows
    if r["forensic_value"] == "high" and r["artifact_class"] in ("disk", "credential", "mcp-config")
})
(OUT / "collection-targets.txt").write_text("\n".join(manifest) + "\n")

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
(OUT / "detections.json").write_text(json.dumps(detections, indent=2))

print(f"{len(entries)} entries -> {len(rows)} artifact rows")
print(f"{len(detections)} sigma rules indexed")
print(f"{len(manifest)} high-value collection targets")
