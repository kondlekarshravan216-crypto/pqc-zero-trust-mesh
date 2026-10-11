# Source after scripts/lib.sh. Builds INTENTIONALLY INVALID credentials for negative tests.
# Safety: refuses to run unless both the test PKI and the output dir are inside $PQZT_TEST_SANDBOX,
# so a real/shared CA key can never be used to sign test fixtures.
make_fixtures(){ # $1 = test PKI dir (isolated test CA)   $2 = fixture output dir
  local pki="$1" f="$2" sb="${PQZT_TEST_SANDBOX:-}"
  [[ -n "$sb" && "$pki" == "$sb"/* && "$f" == "$sb"/* ]] || { echo "refusing: fixtures only inside the test sandbox" >&2; return 1; }
  mkdir -p "$f"
  local tca="$pki/ca/ca.crt" tcak="$pki/ca/ca.key"
  # --- rogue CA (untrusted) and certs signed by it carrying the REAL service identities ---
  openssl ecparam -name prime256v1 -genkey -noout -out "$f/rogue-ca.key"
  quiet openssl req -x509 -new -key "$f/rogue-ca.key" -sha256 -days 30 -subj "/CN=Rogue CA" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -out "$f/rogue-ca.crt"
  _leaf rogue-frontend "$f/rogue-ca.crt" "$f/rogue-ca.key" "$EXT_DIR/frontend.ext" "$f"
  _leaf rogue-backend  "$f/rogue-ca.crt" "$f/rogue-ca.key" "$EXT_DIR/backend.ext"  "$f"
  # --- signed by the TRUSTED test CA, but different identity (must fail the allow-list) ---
  cat > "$f/attacker.ext" <<'X'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = URI:spiffe://pqzt.local/ns/demo/sa/attacker, DNS:attacker
X
  _leaf wrongid-client "$tca" "$tcak" "$f/attacker.ext" "$f"
  # --- trusted CA + correct identity but keyUsage lacks digitalSignature ---
  cat > "$f/badku.ext" <<'X'
basicConstraints = critical, CA:FALSE
keyUsage = critical, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = URI:spiffe://pqzt.local/ns/demo/sa/frontend, DNS:frontend
X
  _leaf badku-client "$tca" "$tcak" "$f/badku.ext" "$f"
  # --- trusted CA + correct identity but EKU = serverAuth only ---
  cat > "$f/badeku.ext" <<'X'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = URI:spiffe://pqzt.local/ns/demo/sa/frontend, DNS:frontend
X
  _leaf badeku-client "$tca" "$tcak" "$f/badeku.ext" "$f"
  # --- expired (python: openssl 3.0 cannot backdate) ---
  python3 - "$tca" "$tcak" "$f" <<'PY'
import sys,datetime as dt
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
ca_crt,ca_key,out=sys.argv[1:4]
ca=x509.load_pem_x509_certificate(open(ca_crt,"rb").read()); cak=serialization.load_pem_private_key(open(ca_key,"rb").read(),None)
def mk(name,eku,san):
    k=ec.generate_private_key(ec.SECP256R1()); now=dt.datetime.now(dt.timezone.utc)
    c=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)]))
      .issuer_name(ca.subject).public_key(k.public_key()).serial_number(x509.random_serial_number())
      .not_valid_before(now-dt.timedelta(days=60)).not_valid_after(now-dt.timedelta(days=30))
      .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
      .add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),True)
      .add_extension(x509.ExtendedKeyUsage([eku]),False)
      .add_extension(x509.SubjectAlternativeName(san),False).sign(cak,hashes.SHA256()))
    open(f"{out}/{name}.crt","wb").write(c.public_bytes(serialization.Encoding.PEM))
    open(f"{out}/{name}.key","wb").write(k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
mk("expired-frontend",ExtendedKeyUsageOID.CLIENT_AUTH,[x509.UniformResourceIdentifier("spiffe://pqzt.local/ns/demo/sa/frontend"),x509.DNSName("frontend")])
mk("expired-backend",ExtendedKeyUsageOID.SERVER_AUTH,[x509.UniformResourceIdentifier("spiffe://pqzt.local/ns/demo/sa/backend"),x509.DNSName("backend")])
PY
  chmod 600 "$f"/*.key
}
_leaf(){ # name ca.crt ca.key extfile outdir
  openssl ecparam -name prime256v1 -genkey -noout -out "$5/$1.key"
  quiet openssl req -new -key "$5/$1.key" -subj "/CN=$1" -out "$5/$1.csr"
  quiet openssl x509 -req -in "$5/$1.csr" -CA "$2" -CAkey "$3" -set_serial "0x$(openssl rand -hex 8 | sed 's/^./0/')" -days 30 -sha256 -extfile "$4" -out "$5/$1.crt"
}
