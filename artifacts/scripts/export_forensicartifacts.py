#!/usr/bin/env python3
"""Export the catalog in ForensicArtifacts format for existing DFIR tooling.

The ForensicArtifacts specification (github.com/ForensicArtifacts/artifacts) is
the established machine-readable artifact knowledge base, consumed by Plaso,
GRR, and Timesketch. Emitting that format means this catalog plugs into
collection tooling people already run, instead of asking them to adopt a new one.

    python scripts/export_forensicartifacts.py   # writes docs/api/forensicartifacts.yaml
"""
import glob
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "api" / "forensicartifacts.yaml"

# ForensicArtifacts uses %%users.homedir%% style knowledge-base interpolation.
SUBS = [
    (r"^~/", "%%users.homedir%%/"),
    (r"%APPDATA%", "%%users.appdata%%"),
    (r"%LOCALAPPDATA%", "%%users.localappdata%%"),
    (r"%USERPROFILE%", "%%users.homedir%%"),
]

SUPPORTED_OS = {"windows": "Windows", "macos": "Darwin", "linux": "Linux"}


def normalise(path: str) -> str:
    for pattern, repl in SUBS:
        path = re.sub(pattern, repl, path)
    return path


def camel(name: str) -> str:
    return "".join(w.capitalize() for w in re.split(r"[^A-Za-z0-9]+", name) if w)


def main() -> int:
    definitions = []
    for f in sorted(glob.glob(str(ROOT / "catalog" / "*.yml"))):
        entry = yaml.safe_load(Path(f).read_text(encoding="utf-8"))

        # Only file-backed artifacts map cleanly onto the FILE source type.
        paths_by_os: dict[str, list[str]] = {}
        for artifact in entry.get("artifacts", {}).get("disk", []):
            if artifact.get("forensic_value") != "high":
                continue
            for os_name in artifact.get("os", []):
                if os_name in SUPPORTED_OS:
                    paths_by_os.setdefault(os_name, []).append(normalise(artifact["path"]))
        for cred in entry.get("credentials", []):
            for os_name in cred.get("os", []):
                if os_name in SUPPORTED_OS:
                    paths_by_os.setdefault(os_name, []).append(normalise(cred["location"]))
        for mcp in entry.get("mcp", []):
            # config-file rows only. This format collects paths, and the other
            # four mechanisms have none to give - a database row wants a query,
            # an in-code row wants a source grep, a server row points at some
            # other tool's config, and a cloud row is not on the host at all.
            # Substituting the indicator would emit an import name as a file
            # path and quietly poison the feed.
            if mcp.get("mechanism", "config-file") != "config-file":
                continue
            for os_name in ("windows", "macos", "linux"):
                paths_by_os.setdefault(os_name, []).append(normalise(mcp["config_path"]))

        if not paths_by_os:
            continue

        sources = []
        for os_name, paths in sorted(paths_by_os.items()):
            unique = sorted(set(p for p in paths if "<" not in p and "(" not in p))
            if not unique:
                continue
            sources.append({
                "type": "FILE",
                "attributes": {"paths": unique,
                               "separator": "\\" if os_name == "windows" else "/"},
                "supported_os": [SUPPORTED_OS[os_name]],
            })
        if not sources:
            continue

        definitions.append({
            "name": f"{camel(entry['name'])}Artifacts",
            "doc": f"{entry['name']} ({entry['id']}) - {entry['description'].strip()}",
            "sources": sources,
            "supported_os": sorted({o for s in sources for o in s["supported_os"]}),
            "urls": [r["url"] for r in entry.get("references", [])][:3],
        })

    header = (
        "# ForensicArtifacts-format export, generated from the catalog.\n"
        "# Spec: https://github.com/ForensicArtifacts/artifacts\n"
        "# Consumable by Plaso, GRR, and Timesketch. Do not hand-edit - regenerate with\n"
        "# scripts/export_forensicartifacts.py after changing catalog/*.yml.\n"
        "# Only high-forensic-value file artifacts are exported; registry, network, and\n"
        "# process artifacts have no clean equivalent in the FILE source type.\n---\n"
    )
    body = yaml.safe_dump_all(definitions, sort_keys=False, default_flow_style=False)
    with OUT.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(header + body)
    print(f"{len(definitions)} artifact definitions -> {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
