#!/usr/bin/env bash
# Automated Test Script for OPA Authorization Policies
# Post-Quantum Zero-Trust Microsegmentation Mesh (pqc-zero-trust-mesh)
# Day 2 Verification Suite

set -euo pipefail

echo "=========================================================="
echo "   PQC Zero-Trust Mesh - Automated OPA Test Suite         "
echo "=========================================================="

if ! command -v opa &> /dev/null; then
    echo "[-] Error: 'opa' command not found in PATH." >&2
    exit 1
fi

echo "[+] OPA binary found: $(opa version | head -n 1)"

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

run_opa_eval_test() {
    local test_name="$1"
    local policy_path="$2"
    local input_path="$3"
    local query="$4"
    local expected="$5"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo ""
    echo "[TEST ${TOTAL_TESTS}] ${test_name}"
    echo "  Policy: ${policy_path}"
    echo "  Input:  ${input_path}"
    echo "  Query:  ${query} (Expected: ${expected})"

    local actual
    actual=$(opa eval --data "${policy_path}" --input "${input_path}" "${query}" | grep -o '"value": *[a-z]*' | head -n 1 | awk '{print $2}')

    if [ "${actual}" = "${expected}" ]; then
        echo "  RESULT: PASS (Output: ${actual})"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "  RESULT: FAIL (Expected: ${expected}, got: ${actual})"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

echo ""
echo "--- Part 1: Policy Unit Tests (opa test) ---"
opa test opa/policies/ -v
echo "[+] All policy unit tests passed successfully."

echo ""
echo "--- Part 2: Integration Contract Tests (tests/opa/*.json) ---"
run_opa_eval_test "Contract Test 1: Frontend -> Backend [ALLOW]" "opa/policies/authorization.rego" "tests/opa/allow-frontend-backend.json" "data.mesh.authz.allow" "true"
run_opa_eval_test "Contract Test 2: Backend -> Database [ALLOW]" "opa/policies/authorization.rego" "tests/opa/allow-backend-database.json" "data.mesh.authz.allow" "true"
run_opa_eval_test "Contract Test 3: Frontend -> Database [DENY]" "opa/policies/authorization.rego" "tests/opa/deny-frontend-database.json" "data.mesh.authz.allow" "false"
run_opa_eval_test "Contract Test 4: Unknown -> Backend [DENY]" "opa/policies/authorization.rego" "tests/opa/deny-unknown-backend.json" "data.mesh.authz.allow" "false"

echo ""
echo "--- Part 3: Identity Tests (opa/inputs/*.json) ---"
run_opa_eval_test "Identity Test 1: Simple Verified Identity [ALLOW]" "opa/policies/authz.rego" "opa/inputs/allowed.json" "data.authz.allow" "true"
run_opa_eval_test "Identity Test 2: Simple Unapproved Identity [DENY]" "opa/policies/authz.rego" "opa/inputs/denied.json" "data.authz.allow" "false"

echo ""
echo "--- Part 4: SPIFFE SVID Request Envelope Tests (opa/tests/*.json) ---"
run_opa_eval_test "SPIFFE SVID Test 1: Full SVID URI Allowed [ALLOW]" "opa/policies/authz.rego" "opa/tests/input_allowed.json" "data.authz.allow" "true"
run_opa_eval_test "SPIFFE SVID Test 2: Rogue SVID URI Denied [DENY]" "opa/policies/authz.rego" "opa/tests/input_denied.json" "data.authz.allow" "false"

echo ""
echo "--- Part 5: Mesh Integration Identity Tests (opa/inputs/demo_*.json) ---"
run_opa_eval_test "Mesh Identity Test 1: Demo Frontend SPIFFE URI Allowed [ALLOW]" "opa/policies/authz.rego" "opa/inputs/demo_frontend_allowed.json" "data.authz.allow" "true"
run_opa_eval_test "Mesh Identity Test 2: Demo Unapproved SPIFFE URI Denied [DENY]" "opa/policies/authz.rego" "opa/inputs/demo_unapproved_denied.json" "data.authz.allow" "false"

echo ""
echo "=========================================================="

echo "                   SUMMARY OF RESULTS                     "
echo "=========================================================="
echo "Total Evaluation Tests: ${TOTAL_TESTS}"
echo "Passed:                 ${PASSED_TESTS}"
echo "Failed:                 ${FAILED_TESTS}"

if [ "${FAILED_TESTS}" -gt 0 ]; then
    echo "[-] Test suite FAILED with ${FAILED_TESTS} failures."
    exit 1
else
    echo "[+] All tests PASSED successfully!"
    exit 0
fi
