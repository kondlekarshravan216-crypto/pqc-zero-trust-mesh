#!/usr/bin/env python3
"""STAND-IN for the backend Envoy listener (NOT Envoy).
TLS1.3-only, client cert REQUIRED and chain-verified against --ca, then the peer's URI SANs are checked against the allow-list
read from the *actual* envoy/backend-envoy.yaml (validation_context.match_typed_subject_alt_names). It models the policy
written in that file; it does not prove Envoy enforces it. Only 'exact' URI matchers are modelled; anything else aborts
so the model cannot silently diverge from the config."""
import argparse, socket, ssl, sys, yaml

ap = argparse.ArgumentParser()
ap.add_argument("--cert"); ap.add_argument("--key"); ap.add_argument("--ca")
ap.add_argument("--envoy-config"); ap.add_argument("--port-file"); ap.add_argument("--log")
a = ap.parse_args()

cfg = yaml.safe_load(open(a.envoy_config))
tc = cfg["static_resources"]["listeners"][0]["filter_chains"][0]["transport_socket"]["typed_config"]
assert tc["require_client_certificate"] is True, "config does not require client certs"
vc = tc["common_tls_context"]["validation_context"]
allow = []
for m in vc.get("match_typed_subject_alt_names", []):
    if m.get("san_type") != "URI" or set(m["matcher"]) != {"exact"}:
        sys.exit("unsupported matcher in config for this stand-in: %r" % (m,))
    allow.append(m["matcher"]["exact"])
if not allow:
    sys.exit("empty allow-list: refusing to start (Envoy would accept any trusted cert)")

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(a.cert, a.key)
ctx.load_verify_locations(a.ca)
ctx.verify_mode = ssl.CERT_REQUIRED
ctx.verify_flags |= ssl.VERIFY_X509_STRICT if hasattr(ssl, "VERIFY_X509_STRICT") else 0

log = open(a.log, "a", buffering=1)
def L(msg): log.write(msg + "\n")

srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0)); srv.listen(8)
open(a.port_file, "w").write(str(srv.getsockname()[1]))
L("READY allow=%s" % allow)
BODY = b'{"service":"backend","status":"ok"}\n'
while True:
    raw, _ = srv.accept(); raw.settimeout(3)
    try:
        c = ctx.wrap_socket(raw, server_side=True)
    except (ssl.SSLError, OSError) as e:
        L("REJECT handshake: %s" % (getattr(e, "reason", None) or type(e).__name__)); raw.close(); continue
    try:
        uris = [v for k, v in c.getpeercert().get("subjectAltName", ()) if k == "URI"]
        if not any(u in allow for u in uris):
            L("REJECT identity: presented=%s" % uris); c.close(); continue
        c.recv(4096)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(BODY) + BODY)
        L("ACCEPT identity: %s" % uris)
    except (ssl.SSLError, OSError) as e:
        L("ERROR after handshake: %s" % type(e).__name__)
    finally:
        try: c.close()
        except OSError: pass
