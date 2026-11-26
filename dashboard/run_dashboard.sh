#!/usr/bin/env bash
# Launch PQC Zero-Trust Mesh Observability Dashboard
# Member 5: Manideep (OPA, Vault & Dashboard)

set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
echo "=========================================================="
echo "   PQC Zero-Trust Mesh - Launching Dashboard Server       "
echo "=========================================================="
echo "[+] Starting Dashboard Server at http://127.0.0.1:8050"
python3 "$SCRIPT_DIR/server.py" 8050
