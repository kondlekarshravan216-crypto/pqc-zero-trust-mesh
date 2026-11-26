#!/usr/bin/env bash
# Prepare Docker Compose's flat certificate layout from the hardened local PKI output.
# Never generates, overwrites or deletes CA material; only copies already-issued files.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
PKI_OUT="${PKI_OUT:-$ROOT/pki/out}"
CERT_DIR="${CERT_DIR:-$PKI_OUT/compose-certs}"

required=(
  "$PKI_OUT/ca/ca.crt"
  "$PKI_OUT/frontend/frontend.crt"
  "$PKI_OUT/frontend/frontend.key"
  "$PKI_OUT/backend/backend.crt"
  "$PKI_OUT/backend/backend.key"
)

for file in "${required[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "ERROR: required file not found: $file" >&2
    echo "Generate the test CA and frontend/backend certificates first." >&2
    exit 1
  fi
done

if ! openssl verify -CAfile "$PKI_OUT/ca/ca.crt" "$PKI_OUT/frontend/frontend.crt" "$PKI_OUT/backend/backend.crt"; then
  echo "ERROR: one or more leaf certificates do not verify against the CA." >&2
  exit 1
fi

mkdir -p "$CERT_DIR"
chmod 700 "$CERT_DIR"

install -m 644 "$PKI_OUT/ca/ca.crt" "$CERT_DIR/ca.crt"
install -m 644 "$PKI_OUT/frontend/frontend.crt" "$CERT_DIR/frontend.crt"
install -m 600 "$PKI_OUT/frontend/frontend.key" "$CERT_DIR/frontend-envoy.key"
install -m 644 "$PKI_OUT/backend/backend.crt" "$CERT_DIR/backend.crt"
install -m 600 "$PKI_OUT/backend/backend.key" "$CERT_DIR/backend-envoy.key"

echo
echo "Compose certificate bundle prepared at: $CERT_DIR"
echo "Private keys were copied with mode 600. The directory is inside pki/out and should remain untracked."
echo
echo "Create or update your local .env (do not overwrite an existing file blindly) with:"
printf 'CERT_DIR=%q\nLOCAL_UID=%s\nLOCAL_GID=%s\n' "$CERT_DIR" "$(id -u)" "$(id -g)"
