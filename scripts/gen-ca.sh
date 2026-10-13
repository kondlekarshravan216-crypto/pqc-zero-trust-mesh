#!/usr/bin/env bash
# Create the local TEST root CA in $PKI_OUT/ca. Never overwrites. Fails loudly on partial/inconsistent state.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
case "$(ca_state)" in
  complete) echo "CA already present and consistent in $PKI_OUT/ca - left unchanged."; exit 0;;
  inconsistent) die "Partial or inconsistent CA material in $PKI_OUT/ca (missing, mismatched, unreadable, expired or not self-consistent). Nothing was changed. Inspect it manually; to build a separate CA, set PKI_OUT to a new directory.";;
esac
[[ -d "$PKI_OUT" ]] || mkdir -p -m 700 "$PKI_OUT"
d="$PKI_OUT/ca"; [[ -d "$d" ]] || mkdir -m 700 "$d"
umask 077
tmp="$(mk_tmp "$d" gen)"; trap 'rm_own_tmp "${tmp:-}" "$d" gen' EXIT
quiet openssl ecparam -name "$CURVE" -genkey -noout -out "$tmp/ca.key"
quiet openssl req -new -key "$tmp/ca.key" -subj "/O=PQZT Demo/CN=PQZT Local Test Root CA" -out "$tmp/ca.csr"
quiet openssl x509 -req -in "$tmp/ca.csr" -signkey "$tmp/ca.key" -sha256 -days "$CA_DAYS" -extfile "$EXT_DIR/ca.ext" -out "$tmp/ca.crt"
keymatch "$tmp/ca.key" "$tmp/ca.crt" || die "generated CA key/cert mismatch (aborting before install)"
exists "$d/ca.key" || exists "$d/ca.crt" && die "CA files appeared during generation; refusing to overwrite"
mv -n "$tmp/ca.key" "$d/ca.key"; mv -n "$tmp/ca.crt" "$d/ca.crt"
chmod 600 "$d/ca.key"; chmod 644 "$d/ca.crt"
[[ "$(ca_state)" == complete ]] || die "CA installed but failed consistency check"
echo "Created CA: $d/ca.crt (key: $d/ca.key, mode 600)"
