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
ap.add_argument("--opa-url", default=None, help="OPA HTTP endpoint for ext_authz policy check")
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

def check_opa(identity, destination="backend", action="GET"):
    if not a.opa_url:
        return True, "OPA check skipped (no opa-url)"
    import json, urllib.request
    try:
        payload = json.dumps({"input": {"identity": identity, "destination": destination, "action": action}}).encode("utf-8")
        req = urllib.request.Request(f"{a.opa_url}/v1/data/authz/allow", data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=2) as r:
            res = json.loads(r.read().decode("utf-8")).get("result", False)
            return res, "OPA evaluated allow" if res else "OPA evaluated deny"
    except Exception as e:
        return False, f"OPA error: {e}"

srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0)); srv.listen(8)
open(a.port_file, "w").write(str(srv.getsockname()[1]))
L("READY allow=%s opa_url=%s" % (allow, a.opa_url))
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
        
        req = c.recv(4096).decode("utf-8", errors="replace")
        parts = req.split(" ")
        method = parts[0] if len(parts) > 0 and parts[0] else "GET"
        path = parts[1] if len(parts) > 1 else "/"
        
        # Determine destination service from request path
        destination = "database" if "/database" in path else "backend"
        
        # OPA ext_authz check on service request path
        client_id = uris[0] if uris else ""
        opa_allowed, opa_reason = check_opa(client_id, destination=destination, action=method)
        if not opa_allowed:
            err_body = (
                f'{{"error":"forbidden","reason":"Access denied by OPA ext_authz: {opa_reason}",'
                f'"opa_decision":"deny","destination":"{destination}","identity":"{client_id}"}}\n'
            ).encode("utf-8")
            c.sendall(
                b"HTTP/1.1 403 Forbidden\r\n"
                b"Content-Type: application/json\r\n"
                b"X-Ext-Authz-Decision: deny\r\n"
                b"Connection: close\r\n"
                + f"Content-Length: {len(err_body)}\r\n\r\n".encode("utf-8")
                + err_body
            )
            L("REJECT opa_ext_authz: %s -> %s [%s] (%s)" % (client_id, destination, method, opa_reason))
            c.close()
            continue

        success_body = (
            f'{{"service":"backend","status":"ok","opa_decision":"allow",'
            f'"identity":"{client_id}","destination":"{destination}"}}\n'
        ).encode("utf-8")
        c.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"X-Ext-Authz-Decision: allow\r\n"
            b"Connection: close\r\n"
            + f"Content-Length: {len(success_body)}\r\n\r\n".encode("utf-8")
            + success_body
        )
        L("ACCEPT identity: %s -> %s [%s] (OPA ext_authz: %s)" % (client_id, destination, method, opa_reason))
    except (ssl.SSLError, OSError) as e:
        L("ERROR after handshake: %s" % type(e).__name__)
    finally:
        try: c.close()
        except OSError: pass

