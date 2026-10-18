#!/usr/bin/env bash
# Bash Runner for Service Request Path Authorization & Secret Management Test Suite
# Post-Quantum Zero-Trust Microsegmentation Mesh (pqc-zero-trust-mesh)
# Member 5: Manideep

set -euo pipefail

echo "=========================================================="
echo "  PQC Zero-Trust Mesh - Service Request Path & Vault Suite "
echo "=========================================================="

if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
    echo "[-] Python 3 not found in PATH."
    exit 1
fi

PY_BIN="python3"
if ! command -v python3 >/dev/null 2>&1; then
    PY_BIN="python"
fi

echo "[+] Python binary: $($PY_BIN --version)"

if ! command -v opa >/dev/null 2>&1; then
    echo "[-] OPA not found in PATH."
    exit 1
fi

echo "[+] OPA binary: $(opa version | head -n 1)"

echo ""
echo "[+] Executing Python End-to-End Service Path & Vault Test Suite..."
$PY_BIN tests/test_service_path.py
