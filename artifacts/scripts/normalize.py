# -*- coding: utf-8 -*-
"""Collapse the ad-hoc artifact_type / secret_type values into controlled
vocabularies, and tighten the schema so they cannot fragment again.

Surfaced by the live authoring test: 52 distinct artifact_type values had
accumulated, including near-duplicate pairs (log/logs, agent-def/
agent-definition, env-var/env-file/env-override). An unconstrained enum makes
the CSV feed unfilterable, which defeats the point of publishing it.
"""
import glob, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

ARTIFACT_TYPES = [
    "binary", "install-dir", "config-file", "config-dir", "mcp-config",
    "rules-file", "agent-definition", "credential-file", "session-artifact",
    "log", "database", "data-dir", "env-var", "service-config",
    "extension-bundle", "container", "project-artifact",
]

MAP = {
    "logs": "log",
    "agent-def": "agent-definition",
    "agent-hook": "agent-definition",
    "agent-settings": "agent-definition",
    "project-mcp-config": "mcp-config",
    "project-config": "config-file",
    "zed-config": "config-file",
    "daemon-env": "config-file",
    "system-config": "config-file",
    "permissions": "config-file",
    "env-override": "env-var",
    "env-file": "credential-file",
    "instruction-file": "rules-file",
    "models-dir": "data-dir",
    "model-file": "data-dir",
    "model-def": "config-file",
    "local-model": "data-dir",
    "browser-cache": "data-dir",
    "cache-dir": "data-dir",
    "work-dir": "data-dir",
    "workspace": "data-dir",
    "output-dir": "data-dir",
    "standalone-data": "data-dir",
    "skills-dir": "agent-definition",
    "extension-dir": "install-dir",
    "extensions": "install-dir",
    "updater": "install-dir",
    "downloaded-binary": "binary",
    "cli": "binary",
    "daemon": "binary",
    "invocation": "binary",
    "entrypoint": "binary",
    "history": "session-artifact",
    "repo-artifact": "session-artifact",
    "browser-artifact": "session-artifact",
    "token-cache": "credential-file",
    "credential-store": "credential-file",
    "key-material": "credential-file",
    "session-state": "credential-file",
    "session-file": "credential-file",
}

SECRET_TYPES = ["api-key", "oauth-token", "jwt-signing-key", "session-state",
                "aws-sso-token", "admin-credential", "embedded-credentials",
                "encryption-key", "unknown"]

# Infer secret_type from the location string when the generator left it null.
def infer_secret(loc, desc):
    blob = f"{loc} {desc}".lower()
    if "jwt" in blob or "signing" in blob: return "jwt-signing-key"
    if "sso" in blob or "aws" in blob: return "aws-sso-token"
    if "oauth" in blob or "auth.json" in blob or "oauth_creds" in blob: return "oauth-token"
    if "storage-state" in blob or "cookie" in blob or "session" in blob: return "session-state"
    if "encryption_key" in blob or "encryption key" in blob: return "encryption-key"
    if "admin" in blob: return "admin-credential"
    if "keyring" in blob or "keychain" in blob or "secretstorage" in blob: return "api-key"
    return "api-key"

changed = 0
unmapped = set()
for path in sorted(glob.glob(str(ROOT / "catalog" / "*.yml"))):
    text = Path(path).read_text()
    orig = text

    for m in set(re.findall(r"artifact_type: ([\w-]+)", text)):
        if m in MAP:
            text = re.sub(rf"artifact_type: {re.escape(m)}\b",
                          f"artifact_type: {MAP[m]}", text)
        elif m not in ARTIFACT_TYPES:
            unmapped.add(m)

    if text != orig:
        Path(path).write_text(text)
        changed += 1

if unmapped:
    print("UNMAPPED artifact_type values:", sorted(unmapped))
    sys.exit(1)

print(f"normalized artifact_type in {changed} files")

# secret_type backfill via yaml round-trip only where missing
import yaml
filled = 0
for path in sorted(glob.glob(str(ROOT / "catalog" / "*.yml"))):
    text = Path(path).read_text()
    doc = yaml.safe_load(text)
    creds = doc.get("credentials") or []
    if not creds:
        continue
    out = text
    for c in creds:
        if c.get("secret_type"):
            continue
        st = infer_secret(c.get("location", ""), c.get("description", ""))
        loc = c["location"]
        # insert secret_type immediately after the matching location line
        pat = re.compile(rf"(  - location: {re.escape(loc)}\n(?:    \w+:.*\n)*?)(    storage: )")
        new, n = pat.subn(rf"\1    secret_type: {st}\n\2", out, count=1)
        if n:
            out = new
            filled += 1
    if out != text:
        Path(path).write_text(out)

print(f"backfilled secret_type on {filled} credential entries")
