#!/usr/bin/env bash
# Usage: verify-pki.sh [service ...]   (default: frontend backend). READ-ONLY. Never prints key material.
# Exit status = number of FAILed checks.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
fail=0; ok(){ echo "PASS  $*"; }; bad(){ echo "FAIL  $*"; fail=$((fail+1)); }; warn(){ echo "WARN  $*"; }
norm(){ tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed '/^$/d' | sort; }
CA="$PKI_OUT/ca/ca.crt"; CAK="$PKI_OUT/ca/ca.key"
[[ -f "$CA" && -f "$CAK" ]] || { bad "CA material missing in $PKI_OUT/ca"; exit $fail; }
ci(){ openssl x509 -in "$CA" -noout "$@" 2>/dev/null; }
ci -ext basicConstraints | grep -q 'CA:TRUE' && ci -ext basicConstraints | grep -q 'pathlen:0' && ok "CA basicConstraints CA:TRUE, pathlen:0" || bad "CA basicConstraints"
ci -ext keyUsage | grep -q 'Certificate Sign' && ok "CA keyUsage keyCertSign" || bad "CA keyUsage"
openssl verify -CAfile "$CA" "$CA" >/dev/null 2>&1 && ok "CA self-consistent and currently valid" || bad "CA invalid/expired"
keymatch "$CAK" "$CA" && ok "CA certificate matches CA key" || bad "CA cert/key mismatch"
[[ "$(stat -c %a "$CAK")" =~ ^[0-7]00$ ]] && ok "CA key is owner-only ($(stat -c %a "$CAK"))" || bad "CA key permissions too open ($(stat -c %a "$CAK"))"
ci -checkend 2592000 >/dev/null && : || warn "CA expires within 30 days"
for n in "${@:-frontend backend}"; do for s in $n; do
  d="$PKI_OUT/$s"; c="$d/$s.crt"; k="$d/$s.key"; ext="$EXT_DIR/$s.ext"
  [[ -f "$c" && -f "$k" && -f "$ext" ]] || { bad "$s: missing $c, $k or $ext"; continue; }
  x(){ openssl x509 -in "$c" -noout "$@" 2>/dev/null; }
  openssl verify -CAfile "$CA" "$c" >/dev/null 2>&1 && ok "$s: chain verifies to CA" || bad "$s: chain"
  x -checkend 0 >/dev/null && ok "$s: not expired" || bad "$s: expired"
  [[ "$(date -d "$(x -startdate | cut -d= -f2)" +%s)" -le "$(date +%s)" ]] && ok "$s: notBefore reached" || bad "$s: not yet valid"
  x -checkend 604800 >/dev/null || warn "$s: expires within 7 days"
  keymatch "$k" "$c" && ok "$s: certificate matches private key" || bad "$s: cert/key mismatch"
  [[ "$(stat -c %a "$k")" =~ ^[0-7]00$ ]] && ok "$s: key owner-only ($(stat -c %a "$k"))" || bad "$s: key permissions too open ($(stat -c %a "$k"))"
  cmp -s "$d/ca.crt" "$CA" && ok "$s: ca.crt copy equals CA" || bad "$s: ca.crt copy differs/missing"
  x -ext basicConstraints | grep -q 'CA:FALSE' && ok "$s: CA:FALSE" || bad "$s: CA flag"
  [[ "$(x -issuer)" == "issuer=$(ci -subject | sed 's/^subject=//')" ]] && ok "$s: issuer is the mesh CA" || bad "$s: issuer mismatch"
  x -text | grep -q 'ASN1 OID: prime256v1' && x -text | grep -q 'Signature Algorithm: ecdsa-with-SHA256' && ok "$s: ECDSA P-256 / ecdsa-with-SHA256" || bad "$s: unexpected key/sig algorithm"
  [[ "$(x -ext keyUsage | sed 1d | norm)" == "Digital Signature" ]] && ok "$s: keyUsage = digitalSignature only" || bad "$s: keyUsage"
  want_eku="$(grep '^extendedKeyUsage' "$ext" | sed 's/^[^=]*=//' | tr -d ' ' | sed 's/clientAuth/TLS Web Client Authentication/;s/serverAuth/TLS Web Server Authentication/')"
  [[ "$(x -ext extendedKeyUsage | sed 1d | norm)" == "$want_eku" ]] && ok "$s: EKU = $want_eku only" || bad "$s: EKU differs from $ext"
  want_san="$(grep '^subjectAltName' "$ext" | sed 's/^[^=]*=//' | norm)"
  [[ "$(x -ext subjectAltName | sed 1d | norm)" == "$want_san" ]] && ok "$s: SAN set equals definition in $(basename "$ext")" || bad "$s: SAN differs from $ext"
  purpose=sslserver; [[ "$want_eku" == *Client* ]] && purpose=sslclient
  openssl verify -CAfile "$CA" -purpose "$purpose" "$c" >/dev/null 2>&1 && ok "$s: valid for purpose $purpose" || bad "$s: not valid for $purpose"
done; done
exit $fail
