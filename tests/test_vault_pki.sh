#!/usr/bin/env bash
# Bash Wrapper for Vault PKI Setup and Rotation Test Suite
# Post-Quantum Zero-Trust Microsegmentation Mesh (pqc-zero-trust-mesh)
# Member 5: Manideep (OPA, Vault & Dashboard)

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P)"
ROOT="$(cd -- "$SCRIPT_DIR/.." 2>/dev/null && pwd -P)"

echo "=========================================================="
echo "   PQC Zero-Trust Mesh - Vault PKI & Rotation Suite       "
echo "=========================================================="

if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
    echo "[-] Python is not installed or accessible in PATH." >&2
    exit 1
fi

PYTHON_CMD="python3"
if ! command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python"
fi

$PYTHON_CMD "$ROOT/tests/test_vault_pki.py"
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "[+] Vault PKI test suite PASSED (100%)."
    exit 0
else
    echo ""
    echo "[-] Vault PKI test suite FAILED with exit code $EXIT_CODE."
    exit $EXIT_CODE
fi
