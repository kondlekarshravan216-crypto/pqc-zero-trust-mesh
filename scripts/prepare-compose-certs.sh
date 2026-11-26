#!/usr/bin/env bash
# Prepare Docker Compose's flat certificate layout from the hardened local PKI output.
# Never generates, overwrites or deletes CA material; only copies already-issued files.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
PKI_OUT="${PKI_OUT:-$ROOT/pki/out}"
CERT_DIR="${CERT_DIR:-$PKI_OUT/compose-certs}"

[[ "$CERT_DIR" == /* ]] || {
  echo "ERROR: CERT_DIR must be an absolute path (got: $CERT_DIR)" >&2
  exit 1
}

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

copy_once() {
  local source="$1" destination="$2" mode="$3"
  if [[ -e "$destination" || -L "$destination" ]]; then
    if [[ -f "$destination" && ! -L "$destination" ]] && cmp -s "$source" "$destination"; then
      chmod "$mode" "$destination"
      return 0
    fi
    echo "ERROR: refusing to replace existing file: $destination" >&2
    echo "Choose a new CERT_DIR or inspect/remove the old export after backing it up." >&2
    exit 1
  fi
  install -m "$mode" "$source" "$destination"
}

copy_once "$PKI_OUT/ca/ca.crt" "$CERT_DIR/ca.crt" 644
copy_once "$PKI_OUT/frontend/frontend.crt" "$CERT_DIR/frontend.crt" 644
copy_once "$PKI_OUT/frontend/frontend.key" "$CERT_DIR/frontend-envoy.key" 600
copy_once "$PKI_OUT/backend/backend.crt" "$CERT_DIR/backend.crt" 644
copy_once "$PKI_OUT/backend/backend.key" "$CERT_DIR/backend-envoy.key" 600

echo
echo "Compose certificate bundle prepared at: $CERT_DIR"
echo "Private keys were copied with mode 600. The directory is inside pki/out and should remain untracked."
echo
echo "Create or update your local .env (do not overwrite an existing file blindly) with:"
printf 'CERT_DIR=%q\nLOCAL_UID=%s\nLOCAL_GID=%s\n' "$CERT_DIR" "$(id -u)" "$(id -g)"
