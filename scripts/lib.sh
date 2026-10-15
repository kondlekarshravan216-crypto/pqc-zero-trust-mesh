# Shared helpers. SOURCE ONLY. Never deletes anything except temp dirs it created itself (see rm_own_tmp).
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then echo "lib.sh must be sourced, not executed" >&2; exit 64; fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd -P)" || { echo "FATAL: cannot resolve module root" >&2; exit 70; }
if [[ -z "$ROOT" || ! -f "$ROOT/scripts/lib.sh" || ! -d "$ROOT/pki/ext" ]]; then echo "FATAL: unexpected module root '$ROOT'" >&2; exit 70; fi
PKI_OUT="${PKI_OUT:-$ROOT/pki/out}"
EXT_DIR="${EXT_DIR:-$ROOT/pki/ext}"
[[ "$PKI_OUT" == /?* ]] || { echo "FATAL: PKI_OUT must be an absolute path (got '$PKI_OUT')" >&2; exit 70; }
PKI_OUT="${PKI_OUT%/}"
CA_DAYS="${CA_DAYS:-3650}"; LEAF_DAYS="${LEAF_DAYS:-90}"
[[ "$CA_DAYS" =~ ^[0-9]+$ && "$LEAF_DAYS" =~ ^[0-9]+$ ]] || { echo "FATAL: CA_DAYS/LEAF_DAYS must be integers" >&2; exit 70; }
CURVE="prime256v1"   # ECDSA P-256 keys, SHA-256 signatures

die(){ echo "ERROR: $*" >&2; exit 1; }
exists(){ [[ -e "$1" || -L "$1" ]]; }
# run a command, show its output only if it fails (keeps routine openssl chatter out of logs; never prints key files)
quiet(){ local o; o="$("$@" 2>&1)" || { echo "$o" >&2; return 1; }; }
# key matches cert? Fails (not "equal") if either side cannot be read.
keymatch(){ local k c; k="$(openssl pkey -in "$1" -pubout 2>/dev/null)" || return 1; c="$(openssl x509 -in "$2" -noout -pubkey 2>/dev/null)" || return 1; [[ -n "$k" && "$k" == "$c" ]]; }
mk_tmp(){ mktemp -d "$1/.$2.XXXXXX"; }
# remove ONLY a temp dir that this process created: must live directly under $2 and be named .<prefix>.*
rm_own_tmp(){ local t="${1:-}" parent="$2" prefix="$3"; [[ -n "$t" && "$t" == "$parent"/."$prefix".* && -d "$t" && ! -L "$t" ]] && rm -rf -- "$t"; return 0; }

# none | complete | inconsistent
ca_state(){ local k="$PKI_OUT/ca/ca.key" c="$PKI_OUT/ca/ca.crt"
  if ! exists "$k" && ! exists "$c"; then echo none; return; fi
  if [[ -f "$k" && -f "$c" ]] && keymatch "$k" "$c" && openssl verify -CAfile "$c" "$c" >/dev/null 2>&1; then echo complete; else echo inconsistent; fi; }
# none | complete | inconsistent   ($1 = service name)
svc_state(){ local d="$PKI_OUT/$1" k c a; k="$d/$1.key"; c="$d/$1.crt"; a="$d/ca.crt"
  if ! exists "$k" && ! exists "$c"; then echo none; return; fi
  if [[ -f "$k" && -f "$c" && -f "$a" ]] && keymatch "$k" "$c" && cmp -s "$a" "$PKI_OUT/ca/ca.crt" \
     && openssl verify -CAfile "$PKI_OUT/ca/ca.crt" "$c" >/dev/null 2>&1; then echo complete; else echo inconsistent; fi; }
