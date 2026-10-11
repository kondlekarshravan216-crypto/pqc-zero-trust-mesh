#!/usr/bin/env bash
# Repeatable verification + negative tests. Uses `openssl s_server` as a STAND-IN for the backend
# Envoy mTLS listener (Envoy is not required). Writes tests/results.md. Exit non-zero if any test FAILS.
set -uo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P)" || { echo "ERROR: cannot resolve tests directory" >&2; exit 70; }
ROOT="$(cd -- "$SCRIPT_DIR/.." 2>/dev/null && pwd -P)" || { echo "ERROR: cannot resolve module root" >&2; exit 70; }
[[ -f "$ROOT/scripts/lib.sh" && -d "$ROOT/pki/ext" && -d "$ROOT/tests" ]] || { echo "ERROR: unexpected module root: $ROOT" >&2; exit 70; }
source "$ROOT/scripts/lib.sh"
# Unique test-owned workspace; never remove a pre-existing tests/work directory.
W="$(mktemp -d "$ROOT/tests/.work-run.XXXXXX")" || { echo "ERROR: cannot create isolated test workspace" >&2; exit 70; }
[[ -n "$W" && "$W" == "$ROOT/tests/.work-run."* && -d "$W" && ! -L "$W" ]] || { echo "ERROR: unsafe workspace path" >&2; exit 70; }
chmod 700 "$W"; umask 077
# All generated test PKI and adversarial fixtures live in this invocation's sandbox,
# never in the module's normal pki/out directory or any shared CA directory.
export PKI_OUT="$W/pki"
if ! bash "$ROOT/scripts/gen-ca.sh" || ! bash "$ROOT/scripts/issue-cert.sh" frontend || ! bash "$ROOT/scripts/issue-cert.sh" backend; then
  echo "ERROR: unable to create isolated test-only PKI; no existing PKI was touched" >&2
  exit 1
fi
OUT="$ROOT/tests/results-$(date -u +%Y%m%dT%H%M%SZ)-$$.md"; FAILS=0; N=0; PIDS=()
CA="$PKI_OUT/ca/ca.crt"; FC="$PKI_OUT/frontend/frontend.crt"; FK="$PKI_OUT/frontend/frontend.key"
BC="$PKI_OUT/backend/backend.crt"; BK="$PKI_OUT/backend/backend.key"
cleanup(){
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  for p in "${PIDS[@]:-}"; do wait "$p" 2>/dev/null || true; done
  # Remove only the unique workspace created by this invocation.
  if [[ -n "${W:-}" && "$W" == "$ROOT/tests/.work-run."* && -d "$W" && ! -L "$W" ]]; then rm -rf -- "$W"; fi
}; trap cleanup EXIT
{ echo "# Test results"; echo; echo "Generated: $(date -u +%FT%TZ) | $(openssl version)"; echo
  echo "| # | Test | Command | Expected | Actual | Status |"; echo "|---|------|---------|----------|--------|--------|"; } > "$OUT"
rec(){ # name cmd expected actual status
  N=$((N+1)); [[ "$5" == FAIL ]] && FAILS=$((FAILS+1))
  printf '| %s | %s | `%s` | %s | %s | **%s** |\n' "$N" "$1" "${2//|/\\|}" "$3" "${4//|/\\|}" "$5" >> "$OUT"
  printf '%-9s %s\n' "[$5]" "$1"; }
# expect_ok / expect_fail: run command, capture rc + output, decide status
expect_ok(){ local n="$1" c="$2" e="$3"; local o; o=$(eval "$c" 2>&1); local rc=$?
  [[ $rc -eq 0 ]] && rec "$n" "$c" "$e" "rc=0 ${o:0:90}" PASS || rec "$n" "$c" "$e" "rc=$rc ${o:0:90}" FAIL; }
expect_fail(){ local n="$1" c="$2" e="$3"; local o; o=$(eval "$c" 2>&1); local rc=$?
  [[ $rc -ne 0 ]] && rec "$n" "$c" "$e" "rc=$rc (rejected) ${o:0:90}" PASS || rec "$n" "$c" "$e" "rc=0 (WRONGLY ACCEPTED)" FAIL; }

# ---- Part A: static PKI checks ----
expect_ok "Chain: frontend -> CA" "openssl verify -CAfile $CA $FC" "OK"
expect_ok "Chain: backend -> CA"  "openssl verify -CAfile $CA $BC" "OK"
for n in frontend backend; do
 expect_ok "Key matches cert ($n)" "[ \"\$(openssl x509 -in $PKI_OUT/$n/$n.crt -noout -pubkey|openssl sha256)\" = \"\$(openssl pkey -in $PKI_OUT/$n/$n.key -pubout|openssl sha256)\" ]" "public keys identical"
 expect_ok "Not expired ($n)" "openssl x509 -in $PKI_OUT/$n/$n.crt -noout -checkend 0" "valid now"
done
expect_ok "Full PKI verification script" "bash $ROOT/scripts/verify-pki.sh" "all PASS (EKU, SAN, CA flags)"
expect_fail "Cert/key mismatch detected (frontend cert vs backend key)" "[ \"\$(openssl x509 -in $FC -noout -pubkey|openssl sha256)\" = \"\$(openssl pkey -in $BK -pubout|openssl sha256)\" ]" "mismatch detected"
expect_fail "Frontend cert does NOT carry backend identity" "openssl x509 -in $FC -noout -ext subjectAltName | grep -q 'sa/backend'" "no backend SAN in frontend cert"
expect_fail "Backend cert not valid for clientAuth purpose" "openssl verify -CAfile $CA -purpose sslclient $BC" "rejected (EKU serverAuth only)"
expect_ok   "Frontend cert valid for clientAuth purpose" "openssl verify -CAfile $CA -purpose sslclient $FC" "OK"
expect_fail "Frontend cert not valid for serverAuth purpose" "openssl verify -CAfile $CA -purpose sslserver $FC" "rejected (EKU clientAuth only)"

# ---- Test-only adversarial material (never touches real PKI) ----
openssl ecparam -name prime256v1 -genkey -noout -out $W/rogue-ca.key
openssl req -x509 -new -key $W/rogue-ca.key -sha256 -days 30 -subj "/CN=Rogue CA" -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -out $W/rogue-ca.crt 2>/dev/null
mk_rogue(){ # name ext-file -> signed by rogue CA, same SAN as the real service
  openssl ecparam -name prime256v1 -genkey -noout -out $W/$1.key
  openssl req -new -key $W/$1.key -subj "/CN=$1" -out $W/$1.csr
  openssl x509 -req -in $W/$1.csr -CA $W/rogue-ca.crt -CAkey $W/rogue-ca.key -CAcreateserial -days 30 -extfile $2 -out $W/$1.crt 2>/dev/null; }
mk_rogue rogue-frontend "$EXT_DIR/frontend.ext"; mk_rogue rogue-backend "$EXT_DIR/backend.ext"
# Expired certs signed by the REAL CA (python cryptography; openssl 3.0 x509 cannot backdate)
python3 - "$PKI_OUT" "$W" <<'PY'
import sys,datetime as dt
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
out,w=sys.argv[1:3]
ca=x509.load_pem_x509_certificate(open(f"{out}/ca/ca.crt","rb").read())
cak=serialization.load_pem_private_key(open(f"{out}/ca/ca.key","rb").read(),None)
def mk(name,eku,san):
    k=ec.generate_private_key(ec.SECP256R1()); now=dt.datetime.now(dt.timezone.utc)
    c=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)]))
      .issuer_name(ca.subject).public_key(k.public_key()).serial_number(x509.random_serial_number())
      .not_valid_before(now-dt.timedelta(days=60)).not_valid_after(now-dt.timedelta(days=30))
      .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
      .add_extension(x509.ExtendedKeyUsage([eku]),False)
      .add_extension(x509.SubjectAlternativeName(san),False).sign(cak,hashes.SHA256()))
    open(f"{w}/{name}.crt","wb").write(c.public_bytes(serialization.Encoding.PEM))
    open(f"{w}/{name}.key","wb").write(k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
mk("expired-frontend",ExtendedKeyUsageOID.CLIENT_AUTH,[x509.UniformResourceIdentifier("spiffe://pqzt.local/ns/demo/sa/frontend"),x509.DNSName("frontend")])
mk("expired-backend",ExtendedKeyUsageOID.SERVER_AUTH,[x509.UniformResourceIdentifier("spiffe://pqzt.local/ns/demo/sa/backend"),x509.DNSName("backend")])
PY

# ---- Part B: live mTLS handshakes against a stand-in backend listener ----
srv(){ # port cert key ca  (TLS1.3 only, client cert REQUIRED, errors fatal) - mirrors backend-envoy.yaml
  openssl s_server -accept "127.0.0.1:$1" -cert "$2" -key "$3" -CAfile "$4" -Verify 1 -verify_return_error -tls1_3 -www >"$W/srv-$1.log" 2>&1 &
  local pid=$!; PIDS+=("$pid"); sleep 0.6
  if ! kill -0 "$pid" 2>/dev/null; then echo "ERROR: test server failed to start on 127.0.0.1:$1; see $W/srv-$1.log" >&2; return 1; fi
  if ! (echo >/dev/tcp/127.0.0.1/"$1") >/dev/null 2>&1; then echo "ERROR: test server did not listen on 127.0.0.1:$1" >&2; return 1; fi
}
srv 18443 "$BC" "$BK" "$CA" || exit 1
cu(){ curl -sS -m 5 -o /dev/null -w '%{http_code}' --resolve backend:18443:127.0.0.1 "$@" https://backend:18443/; }
expect_ok   "mTLS success: trusted frontend cert -> backend (HTTP 200)" "[ \"\$(cu --cacert $CA --cert $FC --key $FK)\" = 200 ]" "HTTP 200"
expect_fail "No client certificate" "[ \"\$(cu --cacert $CA)\" = 200 ]" "handshake/request rejected, no 200"
expect_fail "Client cert from untrusted (rogue) CA, correct SAN" "[ \"\$(cu --cacert $CA --cert $W/rogue-frontend.crt --key $W/rogue-frontend.key)\" = 200 ]" "rejected, no 200"
expect_fail "Expired client cert (real CA)" "[ \"\$(cu --cacert $CA --cert $W/expired-frontend.crt --key $W/expired-frontend.key)\" = 200 ]" "rejected, no 200"
expect_fail "Wrong-purpose client cert (backend serverAuth cert as client)" "[ \"\$(cu --cacert $CA --cert $BC --key $BK)\" = 200 ]" "rejected (EKU), no 200"
expect_fail "Client does not trust server (empty trust: rogue CA only)" "[ \"\$(cu --cacert $W/rogue-ca.crt --cert $FC --key $FK)\" = 200 ]" "client aborts: unknown issuer"
expect_fail "Server hostname/SAN mismatch (connect as 'evil')" "curl -sS -m 5 -o /dev/null --resolve evil:18443:127.0.0.1 --cacert $CA --cert $FC --key $FK https://evil:18443/" "client aborts: name mismatch"
expect_ok   "Legacy TLS 1.2 client refused (server TLS1.3-only): protocol_version alert" "{ echo | openssl s_client -connect 127.0.0.1:18443 -tls1_2 -CAfile $CA -cert $FC -key $FK 2>&1 || true; } | grep -q 'alert protocol version'" "server sends protocol_version alert"
# Server-side rogue / expired server certificates
srv 18444 "$W/rogue-backend.crt" "$W/rogue-backend.key" "$W/rogue-ca.crt" || exit 1
expect_fail "Server presents cert from untrusted CA" "curl -sS -m 5 -o /dev/null --resolve backend:18444:127.0.0.1 --cacert $CA --cert $FC --key $FK https://backend:18444/" "client rejects server"
srv 18445 "$W/expired-backend.crt" "$W/expired-backend.key" "$CA" || exit 1
expect_fail "Server presents expired cert" "curl -sS -m 5 -o /dev/null --resolve backend:18445:127.0.0.1 --cacert $CA --cert $FC --key $FK https://backend:18445/" "client rejects expired server"
# Capture negotiated parameters of the good session (what we actually verified)
echo | openssl s_client -connect 127.0.0.1:18443 -servername backend -verify_hostname backend -verify_return_error -CAfile $CA -cert $FC -key $FK -tls1_3 >"$W/good.txt" 2>&1
PROTO=$(grep -m1 '^New, ' "$W/good.txt"); GROUP=$(grep -m1 'Server Temp Key' "$W/good.txt"); SIG=$(grep -m1 'Peer signature type' "$W/good.txt"); VER=$(grep -m1 'Verification' "$W/good.txt")
[[ "$VER" == *OK* && "$PROTO" == *TLSv1.3* ]] && rec "Negotiated parameters (hostname verified)" "openssl s_client ... -verify_hostname backend -tls1_3" "TLS1.3, verify OK" "$PROTO; $GROUP; $SIG; $VER" PASS || rec "Negotiated parameters" "openssl s_client" "TLS1.3" "$PROTO $VER" FAIL
echo "$PROTO | $GROUP | $SIG | $VER" > "$W/negotiated.txt"

# ---- Part C: config validation ----
expect_ok "Envoy/Compose YAML syntax + mTLS flag present" "python3 -c \"import yaml;[yaml.safe_load(open('$ROOT/'+f)) for f in ['envoy/backend-envoy.yaml','envoy/frontend-envoy.yaml','docker-compose.yml']];c=yaml.safe_load(open('$ROOT/envoy/backend-envoy.yaml'))['static_resources']['listeners'][0]['filter_chains'][0]['transport_socket']['typed_config'];assert c['require_client_certificate'] is True\"" "parses; require_client_certificate: true"
if command -v envoy >/dev/null; then
  for f in backend frontend; do expect_ok "envoy --mode validate ($f)" "envoy --mode validate -c $ROOT/envoy/$f-envoy.yaml" "configuration OK"; done
else rec "Envoy config validation (envoy --mode validate)" "envoy --mode validate -c envoy/*.yaml" "configuration OK" "envoy binary not installed in this environment" "NOT RUN"; fi
if command -v docker >/dev/null; then expect_ok "docker compose config" "docker compose -f $ROOT/docker-compose.yml config -q" "valid"
else rec "Docker Compose config / live Envoy mTLS" "docker compose up; curl localhost:8080" "200 via Envoy; unauth rejected" "docker not installed in this environment" "NOT RUN"; fi
# ---- Part D: PQC capability probe (informational; records facts, never claims PQC) ----
if openssl list -kem-algorithms 2>/dev/null | grep -Eqi 'mlkem|kyber'; then PQ="ML-KEM/Kyber KEM present"; else PQ="no ML-KEM/Kyber KEM in OpenSSL providers"; fi
if echo | openssl s_client -connect 127.0.0.1:18443 -groups X25519MLKEM768 -CAfile $CA -cert $FC -key $FK 2>&1 | grep -qi 'MLKEM768'; then PQ2="hybrid group accepted"; else PQ2="X25519MLKEM768 not usable"; fi
rec "PQC capability probe (informational)" "openssl list -kem-algorithms; s_client -groups X25519MLKEM768" "report support truthfully" "$PQ; $PQ2" "INFO"
echo; echo "Negotiated: $(cat $W/negotiated.txt)"; echo "Tests: $N, failures: $FAILS (see $OUT)"
exit $FAILS
