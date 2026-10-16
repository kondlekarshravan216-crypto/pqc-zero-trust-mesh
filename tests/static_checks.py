#!/usr/bin/env python3
"""STATIC consistency checks across envoy/*.yaml, docker-compose.yml, pki/ext/*.ext and backend/app.py.
Prints TSV lines: STATUS<TAB>name<TAB>detail. These are configuration checks, NOT live Envoy/Docker tests."""
import re, sys, yaml, pathlib
root = pathlib.Path(sys.argv[1]); out = []
def r(ok, name, detail=""): out.append(("PASS" if ok else "FAIL", name, detail))
def load(p): return yaml.safe_load((root / p).read_text())
bk, fr, dc = load("envoy/backend-envoy.yaml"), load("envoy/frontend-envoy.yaml"), load("docker-compose.yml")
def ext(n):
    d = {}
    for line in (root / f"pki/ext/{n}.ext").read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1); d[k.strip()] = v.strip()
    return d
fe, be = ext("frontend"), ext("backend")
uri = lambda e: [x.strip()[4:] for x in e["subjectAltName"].split(",") if x.strip().startswith("URI:")]

lis = bk["static_resources"]["listeners"][0]; ts = lis["filter_chains"][0]["transport_socket"]["typed_config"]
ctx = ts["common_tls_context"]; vc = ctx["validation_context"]
r(ts["require_client_certificate"] is True, "backend Envoy requires client certificate")
allow = [m["matcher"].get("exact") for m in vc.get("match_typed_subject_alt_names", [])]
r(allow == uri(fe), "backend allow-list == exactly the frontend URI SAN in frontend.ext", f"{allow}")
r(vc["trusted_ca"]["filename"] == "/etc/pqzt/certs/ca.crt", "backend trusts CA file /etc/pqzt/certs/ca.crt")
fts = fr["static_resources"]["clusters"][0]["transport_socket"]["typed_config"]; fvc = fts["common_tls_context"]["validation_context"]
fallow = [m["matcher"].get("exact") for m in fvc.get("match_typed_subject_alt_names", [])]
r(fallow == uri(be), "frontend expects exactly the backend URI SAN in backend.ext", f"{fallow}")
r(fts.get("sni") in be["subjectAltName"], "frontend SNI is covered by a backend SAN", str(fts.get("sni")))
for who, c in (("backend", ctx), ("frontend", fts["common_tls_context"])):
    p = c["tls_params"]
    r(p["tls_minimum_protocol_version"] == "TLSv1_3" and p["tls_maximum_protocol_version"] == "TLSv1_3", f"{who} Envoy pinned to TLS 1.3 (provisional policy)")
    r(not any("MLKEM" in x.upper() or "KYBER" in x.upper() for x in p.get("ecdh_curves", [])), f"{who} ecdh_curves classical only (no PQC group configured)", str(p.get("ecdh_curves")))
r("clientAuth" in fe["extendedKeyUsage"] and "serverAuth" not in fe["extendedKeyUsage"], "frontend.ext EKU is clientAuth only")
r("serverAuth" in be["extendedKeyUsage"] and "clientAuth" not in be["extendedKeyUsage"], "backend.ext EKU is serverAuth only")

svc = dc["services"]
def mounts(s):
    m = {}
    for v in svc[s].get("volumes", []):
        src, dst, mode = v.rsplit(":", 2); m[dst] = (src, mode)
    return m
bm, fm = mounts("backend-envoy"), mounts("frontend-envoy")
used_b = {ctx["tls_certificates"][0]["certificate_chain"]["filename"], ctx["tls_certificates"][0]["private_key"]["filename"], vc["trusted_ca"]["filename"]}
used_f = {fts["common_tls_context"]["tls_certificates"][0]["certificate_chain"]["filename"], fts["common_tls_context"]["tls_certificates"][0]["private_key"]["filename"], fvc["trusted_ca"]["filename"]}
r(used_b <= set(bm), "every cert/key path in backend-envoy.yaml is mounted by compose", str(sorted(used_b - set(bm))))
r(used_f <= set(fm), "every cert/key path in frontend-envoy.yaml is mounted by compose", str(sorted(used_f - set(fm))))
r(all(bm[p][1] == "ro" for p in used_b if p in bm) and all(fm[p][1] == "ro" for p in used_f if p in fm), "all certificate/key mounts are read-only")
r(any("backend.key" in bm[p][0] for p in bm) and not any("frontend." in bm[p][0] for p in bm), "backend container mounts only backend credentials")
r(any("frontend.key" in fm[p][0] for p in fm) and not any("backend." in fm[p][0] for p in fm), "frontend container mounts only frontend credentials")
allsrc = " ".join(v.rsplit(":", 2)[0] for s in svc.values() for v in s.get("volumes", []))
r("ca.key" not in allsrc and "/ca/" not in allsrc, "CA private key is not mounted into any container")
for s in ("backend-envoy", "frontend-envoy"):
    u = svc[s].get("user", "")
    r("LOCAL_UID:?" in u and "LOCAL_GID:?" in u, f"{s} runs as host UID/GID that must be set explicitly (no silent default)", u)
r(lis["address"]["socket_address"]["port_value"] == 8443, "backend listener port 8443")
fl = fr["static_resources"]["listeners"][0]["address"]["socket_address"]["port_value"]
r(fl == 8080, "frontend listener port 8080")
def pubs(s): return [p.split(":") for p in svc[s].get("ports", [])]
r(all(p[0] == "127.0.0.1" and p[-1] == "8443" for p in pubs("backend-envoy")) and pubs("backend-envoy"), "backend published port targets 8443, host-loopback only")
r(all(p[0] == "127.0.0.1" and p[-1] == "8080" for p in pubs("frontend-envoy")) and pubs("frontend-envoy"), "frontend published port targets 8080, host-loopback only")
r(not svc["backend-app"].get("ports"), "backend app is not published to the host")
fe_ep = fr["static_resources"]["clusters"][0]["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]["socket_address"]
r(fe_ep["address"] in svc and fe_ep["port_value"] == 8443, "frontend upstream = compose service 'backend-envoy':8443", str(fe_ep))
be_ep = bk["static_resources"]["clusters"][0]["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]["socket_address"]
app_port = re.search(r'\("0\.0\.0\.0",\s*(\d+)\)', (root / "backend/app.py").read_text())
r(be_ep["address"] in svc and app_port and int(app_port.group(1)) == be_ep["port_value"], "backend upstream = compose service 'backend-app' on the port app.py listens on", str(be_ep))
for n, c in (("backend", bk), ("frontend", fr)):
    a = c["admin"]["address"]["socket_address"]["address"]
    r(a == "127.0.0.1", f"{n} Envoy admin bound to loopback", a)
for l in out: print("\t".join(l))
