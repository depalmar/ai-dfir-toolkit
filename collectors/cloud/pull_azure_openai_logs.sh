#!/usr/bin/env bash
# pull_azure_openai_logs.sh — acquire Azure OpenAI evidence (CoSAI: prompt_logs, model_output,
# inference_activity). Read-only. Requires Azure CLI (az) logged in, the Log Analytics query extension,
# and Reader + Log Analytics Reader on the resource/workspace.
#
# Usage:
#   ./pull_azure_openai_logs.sh -c IR-2026-014 -w LOG_ANALYTICS_WORKSPACE_ID \
#       -r "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.CognitiveServices/accounts/<name>" \
#       [-d DAYS] [-o ./cases]
#
# Azure OpenAI request/response content logging is delivered to a Log Analytics workspace via a diagnostic
# setting that must be enabled BEFORE the incident (RequestResponse / Audit / Trace categories). This script
# records the diagnostic-setting config, then pulls the relevant tables and the subscription activity log.
set -euo pipefail

CASE=""; WS=""; RESID=""; DAYS=7; OUT="./cases"
while getopts "c:w:r:d:o:h" opt; do case "$opt" in
  c) CASE="$OPTARG";; w) WS="$OPTARG";; r) RESID="$OPTARG";; d) DAYS="$OPTARG";; o) OUT="$OPTARG";;
  h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;; esac; done
[ -z "$CASE" ] && { echo "ERROR: -c CASE_ID required"; exit 1; }
[ -z "$WS" ] && { echo "ERROR: -w LOG_ANALYTICS_WORKSPACE_ID required"; exit 1; }

DEST="$OUT/$CASE/cloud/azure-openai"; mkdir -p "$DEST"
echo "[*] Azure OpenAI acquisition -> $DEST (last ${DAYS}d)"

if [ -n "$RESID" ]; then
  echo "[*] diagnostic-settings for resource"
  az monitor diagnostic-settings list --resource "$RESID" \
    > "$DEST/diagnostic-settings.json" 2>"$DEST/diagnostic-settings.err" || true
fi

echo "[*] AzureDiagnostics (Cognitive Services) — requests/responses/audit"
az monitor log-analytics query -w "$WS" --analytics-query \
  "AzureDiagnostics | where ResourceProvider == 'MICROSOFT.COGNITIVESERVICES' | where TimeGenerated > ago(${DAYS}d) | order by TimeGenerated asc" \
  -o json > "$DEST/azurediagnostics-cognitiveservices.json" 2>"$DEST/azurediagnostics.err" || true

# Some tenants land content in a dedicated table; try it non-fatally.
az monitor log-analytics query -w "$WS" --analytics-query \
  "AOAIRequestResponse | where TimeGenerated > ago(${DAYS}d) | order by TimeGenerated asc" \
  -o json > "$DEST/aoai-requestresponse.json" 2>/dev/null || true

echo "[*] subscription activity log (control plane)"
az monitor activity-log list --offset "${DAYS}d" \
  > "$DEST/activity-log.json" 2>"$DEST/activity-log.err" || true

echo "[*] hashing outputs"
( cd "$DEST" && find . -type f ! -name 'SHA256SUMS' -print0 | xargs -0 sha256sum > SHA256SUMS 2>/dev/null || true )
echo "[+] Done. Manifest: $DEST/SHA256SUMS"
