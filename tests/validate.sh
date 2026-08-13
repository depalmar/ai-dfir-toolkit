#!/usr/bin/env bash
#
# validate.sh — smoke-test the YARA rules in the detection pack
# against the test artifacts. Verifies that:
#   - "malicious" test artifacts fire the expected YARA rules
#   - "benign" test artifacts produce zero matches
#
# Requires:  yara (v4.x), python3
# Run from the tests/ directory.

set -u
PASS=0
FAIL=0
RULES_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$(dirname "$0")"

echo "=== ai-dfir-toolkit smoke test ==="
echo "Rules root: $RULES_ROOT"

# Without this, a missing yara binary is indistinguishable from a clean scan:
# every assert_clean would report PASS and the suite would look healthy while
# testing nothing at all.
if ! command -v yara >/dev/null 2>&1; then
  echo "ERROR: yara is not installed. Install YARA 4.x and re-run."
  echo "       Refusing to continue - absent tooling would score as passes."
  exit 2
fi
echo

# ---------- Helper: assert the YARA scan produces matches ----------
assert_match() {
  local label="$1"
  local rule_file="$2"
  local target="$3"
  local out rc errf
  errf=$(mktemp)
  out=$(yara "$RULES_ROOT/$rule_file" "$target" 2>"$errf"); rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "  FAIL  $label  (yara exited $rc: $(head -1 "$errf"))"
    FAIL=$((FAIL + 1)); rm -f "$errf"; return
  fi
  rm -f "$errf"
  if [ -n "$out" ]; then
    echo "  PASS  $label"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $label  (expected matches, got none)"
    FAIL=$((FAIL + 1))
  fi
}

# ---------- Helper: assert the YARA scan produces NO matches ----------
assert_clean() {
  local label="$1"
  local rule_file="$2"
  local target="$3"
  local out rc errf
  # Exit status decides whether the scan ran; stdout decides whether it matched.
  # Both are needed and they must stay separate. Empty stdout means "no matches"
  # only when yara actually ran, so a rule that fails to compile must not score
  # as clean - but yara also writes non-fatal warnings to stderr, and folding
  # those into the match check would fail a scan that was genuinely clean.
  errf=$(mktemp)
  out=$(yara "$RULES_ROOT/$rule_file" "$target" 2>"$errf"); rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "  FAIL  $label  (yara exited $rc: $(head -1 "$errf"))"
    FAIL=$((FAIL + 1)); rm -f "$errf"; return
  fi
  rm -f "$errf"
  if [ -z "$out" ]; then
    echo "  PASS  $label"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $label  (expected clean, got: $out)"
    FAIL=$((FAIL + 1))
  fi
}

# Generate pickle test files if missing
if [ ! -f pickle_test_malicious.pkl ]; then
  echo "Generating pickle test fixtures..."
  python3 generate_test_pickles.py
  echo
fi

echo "[ Pickle YARA tests ]"
assert_match "malicious pickle triggers Pickle_Dangerous_Imports" \
  "03-model-supply-chain/pickle_malicious_opcodes.yar" \
  "pickle_test_malicious.pkl"
assert_clean "benign pickle produces no matches" \
  "03-model-supply-chain/pickle_malicious_opcodes.yar" \
  "pickle_test_benign.pkl"

echo
echo "[ MCP tool poisoning YARA tests ]"
assert_match "poisoned MCP config triggers MCP rules" \
  "02-mcp-attacks/mcp_tool_poisoning.yar" \
  "mcp_config_poisoned.json"
assert_clean "benign MCP config produces no matches" \
  "02-mcp-attacks/mcp_tool_poisoning.yar" \
  "mcp_config_benign.json"

echo
echo "[ RAG hidden-text YARA tests ]"
assert_match "RAG document with hidden text triggers RAG rules" \
  "06-rag-vector-db/rag_document_hidden_text.yar" \
  "rag_document_hidden_text.html"
assert_clean "benign RAG document produces no matches" \
  "06-rag-vector-db/rag_document_hidden_text.yar" \
  "rag_document_benign.html"

echo
echo "[ Copilot Rules File Backdoor YARA tests ]"
assert_match "backdoored copilot-instructions triggers Rules File Backdoor rules" \
  "05-copilot-assistant-abuse/copilot_rules_file_backdoor.yar" \
  "copilot_rules_backdoored.md"

echo
echo "[ Runtime AI-malware YARA tests ]"
assert_match "PROMPTFLUX indicators trigger promptflux_thinking_robot" \
  "07-runtime-ai-malware/promptflux_thinking_robot.yar" \
  "runtime_ai_malware_promptflux.txt"
assert_match "PROMPTSTEAL indicators trigger promptsteal_lamehug" \
  "07-runtime-ai-malware/promptsteal_lamehug.yar" \
  "runtime_ai_malware_promptsteal.txt"
assert_match "endpoint + prompt intent + exec triggers the class heuristic" \
  "07-runtime-ai-malware/llm_api_prompt_in_script_generic.yar" \
  "runtime_ai_malware_generic.txt"
assert_clean "benign LLM client produces no PROMPTFLUX matches" \
  "07-runtime-ai-malware/promptflux_thinking_robot.yar" \
  "runtime_ai_benign_llm_client.txt"
assert_clean "benign LLM client produces no PROMPTSTEAL matches" \
  "07-runtime-ai-malware/promptsteal_lamehug.yar" \
  "runtime_ai_benign_llm_client.txt"
assert_clean "benign LLM client does not trip the class heuristic" \
  "07-runtime-ai-malware/llm_api_prompt_in_script_generic.yar" \
  "runtime_ai_benign_llm_client.txt"

echo
echo "=== Summary ==="
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
