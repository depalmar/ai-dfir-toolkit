#!/usr/bin/env bash
# pull_bedrock_invocation_logs.sh — acquire Amazon Bedrock evidence (CoSAI: prompt_logs, model_output,
# inference_activity). Read-only. Requires AWS CLI v2 and read-only IAM (bedrock:Get*, cloudtrail:LookupEvents,
# logs:FilterLogEvents, s3:GetObject/ListBucket on the invocation-log destination).
#
# Usage:
#   ./pull_bedrock_invocation_logs.sh -c IR-2026-014 -r us-east-1 [-s START_ISO] [-e END_ISO] [-o ./cases]
#
# Bedrock model-invocation logging (prompts + completions) is delivered to CloudWatch Logs and/or S3 and
# must have been enabled BEFORE the incident. This script (1) records the current logging config, (2) pulls
# control-plane activity from CloudTrail, and (3) pulls invocation logs from whichever destination is set.
set -euo pipefail

CASE=""; REGION="${AWS_REGION:-us-east-1}"; START=""; END=""; OUT="./cases"
while getopts "c:r:s:e:o:h" opt; do case "$opt" in
  c) CASE="$OPTARG";; r) REGION="$OPTARG";; s) START="$OPTARG";; e) END="$OPTARG";; o) OUT="$OPTARG";;
  h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;; esac; done
[ -z "$CASE" ] && { echo "ERROR: -c CASE_ID required"; exit 1; }
: "${START:=$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-7d +%Y-%m-%dT%H:%M:%SZ)}"
: "${END:=$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

DEST="$OUT/$CASE/cloud/aws-bedrock-$REGION"; mkdir -p "$DEST"
echo "[*] Bedrock acquisition -> $DEST (region=$REGION window=$START..$END)"

echo "[*] 1/4 logging configuration"
aws bedrock get-model-invocation-logging-configuration --region "$REGION" \
  > "$DEST/logging-configuration.json" 2>"$DEST/logging-configuration.err" || true

echo "[*] 2/4 CloudTrail control-plane events (bedrock.amazonaws.com)"
aws cloudtrail lookup-events --region "$REGION" \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=bedrock.amazonaws.com \
  --start-time "$START" --end-time "$END" --max-results 5000 \
  > "$DEST/cloudtrail-bedrock.json" 2>"$DEST/cloudtrail-bedrock.err" || true

# 3/4 invocation logs from configured destination(s)
CW_GROUP=$(python3 -c "import json,sys;d=json.load(open('$DEST/logging-configuration.json'));print(d.get('loggingConfig',{}).get('cloudWatchConfig',{}).get('logGroupName',''))" 2>/dev/null || echo "")
S3_BUCKET=$(python3 -c "import json;d=json.load(open('$DEST/logging-configuration.json'));print(d.get('loggingConfig',{}).get('s3Config',{}).get('bucketName',''))" 2>/dev/null || echo "")
S3_PREFIX=$(python3 -c "import json;d=json.load(open('$DEST/logging-configuration.json'));print(d.get('loggingConfig',{}).get('s3Config',{}).get('keyPrefix',''))" 2>/dev/null || echo "")

if [ -n "$CW_GROUP" ]; then
  echo "[*] 3/4 CloudWatch invocation logs from $CW_GROUP"
  SMS=$(date -u -d "$START" +%s000 2>/dev/null || date -u -jf %Y-%m-%dT%H:%M:%SZ "$START" +%s000)
  EMS=$(date -u -d "$END" +%s000 2>/dev/null || date -u -jf %Y-%m-%dT%H:%M:%SZ "$END" +%s000)
  aws logs filter-log-events --region "$REGION" --log-group-name "$CW_GROUP" \
    --start-time "$SMS" --end-time "$EMS" \
    > "$DEST/invocation-logs-cloudwatch.json" 2>"$DEST/invocation-logs-cloudwatch.err" || true
elif [ -n "$S3_BUCKET" ]; then
  echo "[*] 3/4 S3 invocation logs from s3://$S3_BUCKET/$S3_PREFIX"
  aws s3 sync "s3://$S3_BUCKET/$S3_PREFIX" "$DEST/invocation-logs-s3/" --region "$REGION" \
    > "$DEST/s3-sync.log" 2>"$DEST/s3-sync.err" || true
else
  echo "[!] 3/4 No invocation-logging destination configured — prompts/completions were NOT logged. Note in report."
fi

echo "[*] 4/4 hashing outputs"
( cd "$DEST" && find . -type f ! -name 'SHA256SUMS' -print0 | xargs -0 sha256sum > SHA256SUMS 2>/dev/null || true )
echo "[+] Done. Manifest: $DEST/SHA256SUMS"
