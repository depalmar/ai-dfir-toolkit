#!/usr/bin/env bash
# One-shot check that the artifact catalog landed intact and is ready to commit.
# Safe to re-run. Changes nothing except regenerating the export feeds.
set -euo pipefail

cd "$(dirname "$0")"

echo "==> Checking layout"
for d in artifacts/catalog artifacts/scripts artifacts/schema skills/agent-artifact-catalog; do
  [ -d "$d" ] || { echo "MISSING: $d"; exit 1; }
done
echo "    ok"

echo "==> Python dependencies"
python3 -m pip install -q -r artifacts/requirements.txt 2>/dev/null \
  || python3 -m pip install -q --break-system-packages -r artifacts/requirements.txt
echo "    ok"

cd artifacts

echo "==> Validating catalog and detections"
python3 scripts/validate.py

echo "==> Checking for vocabulary drift"
python3 scripts/normalize.py

echo "==> Regenerating export feeds"
python3 scripts/export.py
python3 scripts/export_forensicartifacts.py

cd ..

echo
echo "==> Ready."
echo "    Entries:  $(ls artifacts/catalog/*.yml | wc -l | tr -d ' ')"
echo "    Sigma:    $(ls artifacts/detections/sigma/*.yml | wc -l | tr -d ' ')"
echo
echo "    Next:  see CONTRIBUTING.md to add an entry, or"
echo "           artifacts/BACKLOG.md for open work"
