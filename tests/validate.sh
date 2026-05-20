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
echo

# ---------- Helper: assert the YARA scan produces matches ----------
assert_match() {
  local label="$1"
  local rule_file="$2"
  local target="$3"
  local out
  out=$(yara "$RULES_ROOT/$rule_file" "$target" 2>/dev/null)
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
  local out
  out=$(yara "$RULES_ROOT/$rule_file" "$target" 2>/dev/null)
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
echo "=== Summary ==="
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
