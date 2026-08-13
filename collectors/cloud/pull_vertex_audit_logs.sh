#!/usr/bin/env bash
# pull_vertex_audit_logs.sh — acquire Google Vertex AI evidence (CoSAI: inference_activity, tool_calls,
# trace_id). Read-only. Requires gcloud logged in and roles/logging.viewer (+ roles/logging.privateLogViewer
# for Data Access logs).
#
# Usage:
#   ./pull_vertex_audit_logs.sh -c IR-2026-014 -p GCP_PROJECT_ID [-d DAYS] [-o ./cases]
#
# Vertex AI Data Access audit logs (predict/generateContent calls) must be explicitly ENABLED for
# aiplatform.googleapis.com before the incident. Admin Activity logs are on by default. This script pulls
# both, plus any request-response logging the project routed to Cloud Logging.
set -euo pipefail

CASE=""; PROJECT=""; DAYS=7; OUT="./cases"
while getopts "c:p:d:o:h" opt; do case "$opt" in
  c) CASE="$OPTARG";; p) PROJECT="$OPTARG";; d) DAYS="$OPTARG";; o) OUT="$OPTARG";;
  h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;; esac; done
[ -z "$CASE" ] && { echo "ERROR: -c CASE_ID required"; exit 1; }
[ -z "$PROJECT" ] && { echo "ERROR: -p GCP_PROJECT_ID required"; exit 1; }

DEST="$OUT/$CASE/cloud/gcp-vertex"; mkdir -p "$DEST"
FRESH="$(date -u -d "${DAYS} days ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-${DAYS}d +%Y-%m-%dT%H:%M:%SZ)"
echo "[*] Vertex AI acquisition -> $DEST (since $FRESH)"

echo "[*] audit logs for aiplatform.googleapis.com (admin activity + data access)"
gcloud logging read \
  "protoPayload.serviceName=\"aiplatform.googleapis.com\" AND timestamp>=\"$FRESH\"" \
  --project="$PROJECT" --format=json --order=asc \
  > "$DEST/aiplatform-auditlogs.json" 2>"$DEST/aiplatform-auditlogs.err" || true

echo "[*] endpoint/model resource activity"
gcloud logging read \
  "resource.type=(\"aiplatform.googleapis.com/Endpoint\" OR \"aiplatform.googleapis.com/PublisherModel\") AND timestamp>=\"$FRESH\"" \
  --project="$PROJECT" --format=json --order=asc \
  > "$DEST/aiplatform-resource-activity.json" 2>/dev/null || true

echo "[*] request-response logging (if routed to Cloud Logging)"
gcloud logging read \
  "logName:\"aiplatform.googleapis.com%2Frequest_response\" AND timestamp>=\"$FRESH\"" \
  --project="$PROJECT" --format=json --order=asc \
  > "$DEST/aiplatform-request-response.json" 2>/dev/null || true

echo "[*] hashing outputs"
( cd "$DEST" && find . -type f ! -name 'SHA256SUMS' -print0 | xargs -0 sha256sum > SHA256SUMS 2>/dev/null || true )
echo "[+] Done. Manifest: $DEST/SHA256SUMS"
