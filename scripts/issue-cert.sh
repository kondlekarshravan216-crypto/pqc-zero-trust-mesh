#!/usr/bin/env bash
# Usage: issue-cert.sh <service>   (definition read from pki/ext/<service>.ext)
# Never overwrites. Fails loudly on partial/inconsistent state. Verifies the result.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
name="${1:-}"
[[ "$name" =~ ^[a-z][a-z0-9-]{0,31}$ && "$name" != ca ]] || die "usage: issue-cert.sh <service>  (lowercase letters/digits/hyphen; 'ca' is reserved)"
ext="$EXT_DIR/$name.ext"
[[ -f "$ext" ]] || die "no identity definition $ext"
grep -q '^subjectAltName' "$ext" && grep -q '^extendedKeyUsage' "$ext" || die "$ext must define subjectAltName and extendedKeyUsage"
[[ "$(ca_state)" == complete ]] || die "CA missing or inconsistent in $PKI_OUT/ca. Run gen-ca.sh first (it never touches inconsistent material)."
openssl x509 -in "$PKI_OUT/ca/ca.crt" -noout -checkend $((LEAF_DAYS*86400)) >/dev/null || die "CA expires before the requested ${LEAF_DAYS}-day leaf lifetime"
case "$(svc_state "$name")" in
  complete) echo "$name credentials already present and consistent - left unchanged."; exit 0;;
  inconsistent) die "Partial or inconsistent material for '$name' in $PKI_OUT/$name (missing file, key/cert mismatch, CA-copy mismatch or bad chain). Nothing was changed. Inspect manually or use a different PKI_OUT.";;
esac
d="$PKI_OUT/$name"; [[ -d "$d" ]] || mkdir -m 700 "$d"
umask 077
tmp="$(mk_tmp "$d" issue)"; trap 'rm_own_tmp "${tmp:-}" "$d" issue' EXIT
quiet openssl ecparam -name "$CURVE" -genkey -noout -out "$tmp/$name.key"
quiet openssl req -new -key "$tmp/$name.key" -subj "/O=PQZT Demo/CN=$name" -out "$tmp/$name.csr"
serial="0x$(openssl rand -hex 16 | sed 's/^./0/')"      # random 128-bit positive serial; no serial file state
quiet openssl x509 -req -in "$tmp/$name.csr" -CA "$PKI_OUT/ca/ca.crt" -CAkey "$PKI_OUT/ca/ca.key" -set_serial "$serial" \
      -sha256 -days "$LEAF_DAYS" -extfile "$ext" -out "$tmp/$name.crt"
keymatch "$tmp/$name.key" "$tmp/$name.crt" || die "generated key/cert mismatch (aborting before install)"
exists "$d/$name.key" || exists "$d/$name.crt" || exists "$d/ca.crt" && die "files appeared during issuance; refusing to overwrite"
mv -n "$tmp/$name.key" "$d/$name.key"; mv -n "$tmp/$name.crt" "$d/$name.crt"; [[ -e "$d/ca.crt" ]] && die "ca.crt appeared during issuance; refusing to overwrite"; cp "$PKI_OUT/ca/ca.crt" "$d/ca.crt"
chmod 600 "$d/$name.key"; chmod 644 "$d/$name.crt" "$d/ca.crt"
echo "Issued $name certificate: $d/$name.crt"
PKI_OUT="$PKI_OUT" EXT_DIR="$EXT_DIR" bash "$(dirname "${BASH_SOURCE[0]}")/verify-pki.sh" "$name" >/dev/null \
  || die "issued, but verify-pki.sh reports problems - run it for details"
