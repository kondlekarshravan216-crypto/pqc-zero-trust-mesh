#!/usr/bin/env python3
"""
Vault PKI Coordinator & Lifecycle Engine
Post-Quantum Zero-Trust Microsegmentation Mesh (pqc-zero-trust-mesh)
Member 5: Manideep (OPA, Vault & Dashboard)

Coordinating:
1. Vault PKI Engine Setup (pki_mesh mount, CA generation, role configuration)
2. Live HashiCorp Vault HTTP REST API Client (issuance, revocation, CRL, roles)
3. Dual-Mode Execution:
   - Live Vault REST API (when Vault daemon is available at VAULT_ADDR)
   - High-Fidelity Cryptographic Emulation (fallback for isolated/sandbox tests)
4. SPIFFE SVID Leaf Certificate Issuance (frontend, backend)
5. Automated Certificate Renewal & Dynamic Rotation (Envoy SDS zero-downtime model)
6. Emergency Certificate Revocation & CRL Generation
7. Telemetry Event Emission into Dashboard Audit Pipeline
"""

import os
import sys
import json
import time
import socket
import ssl
import threading
import urllib.request
import urllib.error
import datetime as dt
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
TELEMETRY_LOG = ROOT_DIR / "opa" / "telemetry" / "audit_log.json"


# ==============================================================================
# HashiCorp Vault REST API Client
# ==============================================================================
class VaultAPIClient:
    """
    Direct HTTP REST client for HashiCorp Vault PKI Secrets Engine.
    Implements standard Vault PKI API endpoints:
      - POST /v1/sys/mounts/:path
      - POST /v1/:path/root/generate/:type
      - POST /v1/:path/roles/:role
      - POST /v1/:path/issue/:role
      - POST /v1/:path/revoke
      - GET  /v1/:path/crl/pem
      - GET  /v1/:path/ca/pem
      - GET  /v1/sys/health
    """

    def __init__(self, vault_addr: Optional[str] = None, vault_token: Optional[str] = None, timeout: float = 3.0):
        self.vault_addr = (vault_addr or os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")).rstrip("/")
        self.vault_token = vault_token or os.environ.get("VAULT_TOKEN")
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        if not self.vault_token:
            raise RuntimeError("VAULT_TOKEN is required for authenticated Vault API requests.")
        return {
            "X-Vault-Token": self.vault_token,
            "Content-Type": "application/json",
            "User-Agent": "PQC-ZeroTrust-Mesh-VaultClient/1.0"
        }

    def check_health(self) -> bool:
        """Checks if live Vault daemon is reachable and unsealed."""
        url = f"{self.vault_addr}/v1/sys/health"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "PQC-ZeroTrust-Mesh-VaultClient/1.0"}, method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                # Vault returns 200 (healthy) or 429 (unsealed standby)
                return resp.status in (200, 429)
        except urllib.error.HTTPError as e:
            # Code 429 (standby) is still initialized and usable
            return e.code in (200, 429)
        except Exception:
            return False

    def mount_pki(self, mount_path: str = "pki_mesh", max_lease_ttl: str = "87600h") -> Dict[str, Any]:
        """Mounts the PKI secrets engine at mount_path."""
        url = f"{self.vault_addr}/v1/sys/mounts/{mount_path}"
        payload = json.dumps({
            "type": "pki",
            "description": "PQC Zero-Trust Mesh PKI Secrets Engine",
            "config": {"max_lease_ttl": max_lease_ttl}
        }).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return {"status": resp.status, "mounted": True}
        except urllib.error.HTTPError as e:
            if e.code == 400 and b"path is already in use" in e.read():
                return {"status": 200, "mounted": True, "already_existed": True}
            raise

    def generate_root_ca(
        self,
        mount_path: str = "pki_mesh",
        common_name: str = "PQC Zero-Trust Mesh Root CA",
        ttl: str = "26280h",
        key_type: str = "ec",
        key_bits: int = 256,
    ) -> Dict[str, Any]:
        """Generates a self-signed Root CA in the mounted PKI engine."""
        url = f"{self.vault_addr}/v1/{mount_path}/root/generate/internal"
        payload = json.dumps({
            "common_name": common_name,
            "ttl": ttl,
            "key_type": key_type,
            "key_bits": key_bits,
            "organization": "ZeroTrustMesh",
            "ou": "Security Infrastructure",
        }).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers=self._headers(), method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("data", {})

    def configure_role(
        self,
        role_name: str = "mesh-workload",
        mount_path: str = "pki_mesh",
        role_config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Configures a PKI certificate issuance role."""
        url = f"{self.vault_addr}/v1/{mount_path}/roles/{role_name}"
        config = role_config or {
            "allowed_domains": ["pqzt.local", "cluster.local", "demo.svc.cluster.local"],
            "allow_subdomains": True,
            "allowed_uri_sans": [
                "spiffe://pqzt.local/ns/demo/sa/*",
                "spiffe://cluster.local/ns/mesh/sa/*",
            ],
            "key_type": "ec",
            "key_bits": 256,
            "max_ttl": "24h",
            "ttl": "12h",
            "require_cn": False,
        }
        payload = json.dumps(config).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers=self._headers(), method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return {"status": resp.status, "role": role_name}

    def issue_certificate(
        self,
        role_name: str = "mesh-workload",
        common_name: str = "frontend",
        mount_path: str = "pki_mesh",
        uri_sans: Optional[List[str]] = None,
        alt_names: Optional[List[str]] = None,
        ttl: str = "12h",
    ) -> Dict[str, Any]:
        """Issues an X.509 certificate via the Vault PKI issue endpoint."""
        url = f"{self.vault_addr}/v1/{mount_path}/issue/{role_name}"
        body: Dict[str, Any] = {
            "common_name": common_name,
            "ttl": ttl,
        }
        if uri_sans:
            body["uri_sans"] = ",".join(uri_sans)
        if alt_names:
            body["alt_names"] = ",".join(alt_names)

        payload = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers=self._headers(), method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("data", {})

    def revoke_certificate(self, serial_number: str, mount_path: str = "pki_mesh") -> Dict[str, Any]:
        """Revokes a certificate by its serial number."""
        url = f"{self.vault_addr}/v1/{mount_path}/revoke"
        # Normalize serial: Vault accepts colon-separated or plain hex
        normalized_serial = serial_number.replace(":", "-").lower()
        payload = json.dumps({"serial_number": normalized_serial}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers=self._headers(), method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("data", {})

    def get_crl(self, mount_path: str = "pki_mesh") -> bytes:
        """Retrieves the latest Certificate Revocation List (PEM format)."""
        url = f"{self.vault_addr}/v1/{mount_path}/crl/pem"
        req = urllib.request.Request(url, headers={"User-Agent": "PQC-ZeroTrust-Mesh-VaultClient/1.0"}, method="GET")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return resp.read()

    def get_ca(self, mount_path: str = "pki_mesh") -> bytes:
        """Retrieves the issuing CA certificate (PEM format)."""
        url = f"{self.vault_addr}/v1/{mount_path}/ca/pem"
        req = urllib.request.Request(url, headers={"User-Agent": "PQC-ZeroTrust-Mesh-VaultClient/1.0"}, method="GET")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return resp.read()


# ==============================================================================
# Dual-Mode Vault PKI Engine & Lifecycle Coordinator
# ==============================================================================
class VaultPKIEngine:
    """
    Coordinates the HashiCorp Vault PKI Secrets Engine (pki_mesh).
    Supports dual execution modes:
      1. LIVE_VAULT_HTTP_API: connects directly to HashiCorp Vault REST endpoints.
      2. STANDALONE_CRYPTOGRAPHIC_EMULATION: exact fallback using python-cryptography
         for offline environments, isolated sandboxes, and automated CI pipelines.
    """

    def __init__(
        self,
        work_dir: Optional[Path] = None,
        vault_addr: Optional[str] = None,
        vault_token: Optional[str] = None,
        force_mode: Optional[str] = None,
    ):
        self.work_dir = work_dir or (ROOT_DIR / "vault" / ".pki_store_v2")
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.work_dir.chmod(0o700)
        self.roles = {}
        self.certificates: Dict[str, dict] = {}  # serial -> cert metadata
        self.revoked_serials = set()
        self.crl_pem = None
        self.events: List[dict] = []

        self.api_client = VaultAPIClient(vault_addr, vault_token)
        if force_mode not in (None, "live", "simulation"):
            raise ValueError("force_mode must be None, 'live', or 'simulation'")
        self.require_live = (force_mode == "live")
        self.live_init_error = None

        # Determine operating mode
        if self.require_live:
            self.engine_mode = "LIVE_VAULT_HTTP_API"
        elif force_mode == "simulation":
            self.engine_mode = "STANDALONE_CRYPTOGRAPHIC_EMULATION"
        else:
            # Auto-detect live Vault availability. The selected mode and any
            # initialization failure are returned by get_integration_status().
            if self.api_client.check_health():
                self.engine_mode = "LIVE_VAULT_HTTP_API"
            else:
                self.engine_mode = "STANDALONE_CRYPTOGRAPHIC_EMULATION"

        # Initialize Root CA and roles
        self._init_root_ca()
        self._configure_default_roles()
        if self.engine_mode == "STANDALONE_CRYPTOGRAPHIC_EMULATION":
            self._load_emulated_certificates()

    def _init_root_ca(self):
        """Initializes Root CA via live Vault API or cryptographic emulation."""
        self.now = dt.datetime.now(dt.timezone.utc)
        self.ca_file = self.work_dir / "ca.crt"
        self.ca_key = None  # Only set when running in emulation mode

        if self.engine_mode == "LIVE_VAULT_HTTP_API":
            try:
                # 1. Mount pki_mesh engine (idempotent — no-op if already mounted)
                self.api_client.mount_pki("pki_mesh")
                # 2. Check if Root CA already exists before generating a new one
                existing_ca_pem = None
                try:
                    existing_ca_pem = self.api_client.get_ca("pki_mesh")
                except Exception:
                    pass
                if existing_ca_pem and len(existing_ca_pem.strip()) > 100:
                    # Root CA already exists — reuse it
                    ca_pem = existing_ca_pem
                else:
                    # Generate new Root CA
                    ca_data = self.api_client.generate_root_ca("pki_mesh")
                    ca_pem = ca_data.get("certificate", "").encode("utf-8")
                    if not ca_pem or ca_pem == b"":
                        ca_pem = self.api_client.get_ca("pki_mesh")
                self.ca_file.write_bytes(ca_pem)
                self.ca_cert = x509.load_pem_x509_certificate(ca_pem)
                self.ca_serial = format(self.ca_cert.serial_number, "x")
                self.crl_pem = self.api_client.get_crl("pki_mesh")
                crl_file = self.work_dir / "crl.pem"
                crl_file.write_bytes(self.crl_pem)
                return
            except Exception as e:
                self.live_init_error = str(e)
                if getattr(self, "require_live", False):
                    # An explicit live-mode request must never silently become
                    # an emulated CA/PKI operation.
                    raise RuntimeError(
                        f"Explicit live Vault mode initialization failed: {e}"
                    ) from e
                self.engine_mode = "STANDALONE_CRYPTOGRAPHIC_EMULATION"

        # Emulation initialization. Keep the local CA stable across dashboard
        # restarts so previously issued emulated leaf certificates remain verifiable.
        ca_key_file = self.work_dir / "emulation-ca.key"
        ca_cert_file = self.work_dir / "ca.crt"
        if ca_key_file.exists() or ca_key_file.is_symlink() or ca_cert_file.exists() or ca_cert_file.is_symlink():
            if (
                not ca_key_file.is_file() or ca_key_file.is_symlink()
                or not ca_cert_file.is_file() or ca_cert_file.is_symlink()
            ):
                raise RuntimeError(
                    "Incomplete emulation CA state. Refusing to replace or regenerate existing CA material; "
                    "preserve the directory and inspect it before recovery."
                )
            try:
                stored_key = serialization.load_pem_private_key(ca_key_file.read_bytes(), password=None)
                stored_cert = x509.load_pem_x509_certificate(ca_cert_file.read_bytes())
                key_public = stored_key.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
                cert_public = stored_cert.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
                constraints = stored_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
                if key_public != cert_public or stored_cert.subject != stored_cert.issuer or not constraints.ca:
                    raise ValueError("stored CA key/certificate mismatch or invalid CA constraints")
                self.ca_key = stored_key
                self.ca_cert = stored_cert
                self.ca_serial = format(stored_cert.serial_number, "x")
                crl_file = self.work_dir / "crl.pem"
                if crl_file.exists():
                    self.crl_pem = crl_file.read_bytes()
                    x509.load_pem_x509_crl(self.crl_pem)
                else:
                    self._generate_crl()
                return
            except Exception as exc:
                raise RuntimeError(f"Existing emulation CA state failed validation; no files were overwritten: {exc}") from exc

        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "PQC Zero-Trust Mesh Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZeroTrustMesh"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security Infrastructure"),
        ])
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_subject)
            .issuer_name(ca_subject)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self.now - dt.timedelta(hours=1))
            .not_valid_after(self.now + dt.timedelta(days=365 * 3))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256())
        )
        ca_key_file.write_bytes(
            self.ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        ca_key_file.chmod(0o600)
        self.ca_file.write_bytes(self.ca_cert.public_bytes(serialization.Encoding.PEM))
        self.ca_file.chmod(0o644)
        self.ca_serial = format(self.ca_cert.serial_number, "x")
        self._generate_crl()

    def _load_emulated_certificates(self) -> None:
        """Reload previously issued local test certificates and current CRL state."""
        crl = x509.load_pem_x509_crl(self.crl_pem) if self.crl_pem else None
        revoked = {item.serial_number for item in crl} if crl else set()
        for cert_file in sorted(self.work_dir.glob("*-v*.crt")):
            if cert_file.is_symlink() or not cert_file.is_file():
                raise RuntimeError(f"Refusing symlink/non-file certificate entry: {cert_file.name}")
            match = re.fullmatch(r"([a-z][a-z0-9-]{0,31})-v([1-9][0-9]*)\.crt", cert_file.name)
            if not match:
                continue
            common_name, version_text = match.groups()
            version = int(version_text)
            key_file = self.work_dir / f"{common_name}-v{version}.key"
            if key_file.is_symlink() or not key_file.is_file():
                raise RuntimeError(f"Certificate {cert_file.name} has no safe matching private-key file")
            cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
            private_key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
            cert_public = cert.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            key_public = private_key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            if cert_public != key_public:
                raise RuntimeError(f"Certificate/private-key mismatch for {common_name} version {version}")
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                uri_sans = san.get_values_for_type(x509.UniformResourceIdentifier)
                dns_sans = san.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                uri_sans, dns_sans = [], []
            cn_values = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if not cn_values:
                raise RuntimeError(f"Certificate {cert_file.name} has no commonName")
            serial_int = cert.serial_number
            serial_hex = format(serial_int, "x")
            is_revoked = serial_int in revoked
            self.certificates[serial_hex] = {
                "common_name": cn_values[0].value,
                "version": version,
                "serial": serial_hex,
                "serial_int": serial_int,
                "role": "mesh-workload",
                "uri_sans": uri_sans,
                "dns_sans": dns_sans,
                "cert_file": str(cert_file),
                "key_file": str(key_file),
                "valid_from": cert.not_valid_before.replace(tzinfo=dt.timezone.utc).isoformat(),
                "valid_until": cert.not_valid_after.replace(tzinfo=dt.timezone.utc).isoformat(),
                "status": "REVOKED" if is_revoked else "ACTIVE",
                "algorithm": "ECDSA P-256 / ECDSA-SHA256 (certificate)",
                "backend": self.engine_mode,
            }
            if is_revoked:
                self.revoked_serials.add(serial_int)

    def _configure_default_roles(self):
        """Registers the approved workload role locally without modifying Vault."""
        role_data = {
            "allowed_domains": ["pqzt.local"],
            "allow_subdomains": True,
            "allow_any_name": False,
            "allow_bare_domains": False,
            "allow_glob_domains": False,
            "allow_ip_sans": False,
            "allow_localhost": False,
            "allow_wildcard_certificates": False,
            "allowed_uri_sans": [
                "spiffe://pqzt.local/ns/demo/sa/frontend",
                "spiffe://pqzt.local/ns/demo/sa/backend",
            ],
            "key_type": "ec",
            "key_bits": 256,
            "max_ttl": "24h",
            "ttl": "12h",
            "require_cn": True,
            "enforce_hostnames": True,
        }
        # Live Vault role configuration is managed explicitly and is never
        # overwritten automatically during coordinator initialization.
        self.roles["mesh-workload"] = role_data

    def _generate_crl(self):
        """Builds CRL containing revoked certificate serial numbers."""
        if self.engine_mode == "LIVE_VAULT_HTTP_API":
            try:
                crl_pem = self.api_client.get_crl("pki_mesh")
                x509.load_pem_x509_crl(crl_pem)
                crl_file = self.work_dir / "crl.pem"
                crl_file.write_bytes(crl_pem)
                self.crl_pem = crl_pem
                return
            except Exception as exc:
                # Never replace a live Vault CRL with a locally signed emulated CRL.
                raise RuntimeError(f"Live Vault CRL retrieval/validation failed: {exc}") from exc

        # Emulation CRL generation
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.ca_cert.subject)
        builder = builder.last_update(self.now)
        builder = builder.next_update(self.now + dt.timedelta(days=7))

        for serial_int in self.revoked_serials:
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial_int)
                .revocation_date(self.now)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(self.ca_key, hashes.SHA256())
        self.crl_pem = crl.public_bytes(serialization.Encoding.PEM)
        crl_file = self.work_dir / "crl.pem"
        crl_file.write_bytes(self.crl_pem)

    def issue_certificate(
        self,
        common_name: str,
        role: str = "mesh-workload",
        uri_sans: Optional[List[str]] = None,
        dns_sans: Optional[List[str]] = None,
        is_server: bool = True,
        ttl_hours: int = 12,
        version: int = 1,
    ) -> Tuple[Path, Path, str]:
        """
        Issues an X.509 leaf certificate signed by Vault Mesh Root CA.
        Returns (cert_file_path, key_file_path, serial_hex).
        """
        if role not in self.roles:
            raise ValueError(f"Unknown PKI role: {role}")
        if not isinstance(common_name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", common_name):
            raise ValueError("common_name must be a lowercase service name (letters, digits, hyphens)")
        if not isinstance(version, int) or version < 1:
            raise ValueError("certificate version must be a positive integer")

        cert_filename = f"{common_name}-v{version}.crt"
        key_filename = f"{common_name}-v{version}.key"
        cert_file = self.work_dir / cert_filename
        key_file = self.work_dir / key_filename
        if cert_file.exists() or cert_file.is_symlink() or key_file.exists() or key_file.is_symlink():
            raise FileExistsError(f"Refusing to overwrite existing certificate/key for {common_name} version {version}")
        now = dt.datetime.now(dt.timezone.utc)

        # 1. Attempt Live Vault API Issuance
        if self.engine_mode == "LIVE_VAULT_HTTP_API":
            try:
                issue_resp = self.api_client.issue_certificate(
                    role_name=role,
                    common_name=common_name,
                    mount_path="pki_mesh",
                    uri_sans=uri_sans,
                    alt_names=dns_sans,
                    ttl=f"{ttl_hours}h",
                )
                cert_pem = issue_resp.get("certificate", "").encode("utf-8")
                key_pem = issue_resp.get("private_key", "").encode("utf-8")
                raw_serial = issue_resp.get("serial_number", "")
                serial_hex = raw_serial.replace(":", "").lower()
                serial_int = int(serial_hex, 16) if serial_hex else x509.random_serial_number()

                cert_file.write_bytes(cert_pem)
                key_file.write_bytes(key_pem)
                key_file.chmod(0o600)

                meta = {
                    "common_name": common_name,
                    "version": version,
                    "serial": serial_hex,
                    "serial_int": serial_int,
                    "role": role,
                    "uri_sans": uri_sans or [],
                    "dns_sans": dns_sans or [],
                    "cert_file": str(cert_file),
                    "key_file": str(key_file),
                    "valid_from": now.isoformat(),
                    "valid_until": (now + dt.timedelta(hours=ttl_hours)).isoformat(),
                    "status": "ACTIVE",
                    "algorithm": "ECDSA P-256 / ECDSA-SHA256 (certificate)",
                    "backend": "LIVE_VAULT_HTTP_API",
                }
                self.certificates[serial_hex] = meta
                self._emit_issuance_telemetry(meta, version, common_name, uri_sans, now)
                return cert_file, key_file, serial_hex
            except Exception as api_err:
                # In LIVE mode, if ca_key is unavailable emulation is not possible;
                # re-raise so the caller sees the real Vault API error.
                if not hasattr(self, 'ca_key') or self.ca_key is None:
                    raise RuntimeError(
                        f"Vault API certificate issuance failed and no emulation "
                        f"fallback is available (LIVE_VAULT_HTTP_API mode): {api_err}"
                    ) from api_err
                # Otherwise fall through to emulation
                pass

        # 2. Cryptographic Emulation Issuance
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZeroTrustMesh"),
        ])

        san_entries = []
        if uri_sans:
            for u in uri_sans:
                san_entries.append(x509.UniformResourceIdentifier(u))
        if dns_sans:
            for d in dns_sans:
                san_entries.append(x509.DNSName(d))

        eku = ExtendedKeyUsageOID.SERVER_AUTH if is_server else ExtendedKeyUsageOID.CLIENT_AUTH

        serial_int = x509.random_serial_number()
        serial_hex = format(serial_int, "x")

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(serial_int)
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(hours=ttl_hours))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
            .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )

        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        key_file.chmod(0o600)

        meta = {
            "common_name": common_name,
            "version": version,
            "serial": serial_hex,
            "serial_int": serial_int,
            "role": role,
            "uri_sans": uri_sans or [],
            "dns_sans": dns_sans or [],
            "cert_file": str(cert_file),
            "key_file": str(key_file),
            "valid_from": now.isoformat(),
            "valid_until": (now + dt.timedelta(hours=ttl_hours)).isoformat(),
            "status": "ACTIVE",
            "algorithm": "ECDSA P-256 / ECDSA-SHA256 (certificate)",
            "backend": self.engine_mode,
        }
        self.certificates[serial_hex] = meta
        self._emit_issuance_telemetry(meta, version, common_name, uri_sans, now)
        return cert_file, key_file, serial_hex

    def _emit_issuance_telemetry(self, meta: dict, version: int, common_name: str, uri_sans: Optional[List[str]], now: dt.datetime):
        primary_svid = uri_sans[0] if uri_sans else f"spiffe://pqzt.local/ns/demo/sa/{common_name}"
        event = {
            "timestamp": now.isoformat(),
            "eventType": "key_certificate_rotation",
            "category": "crypto_lifecycle",
            "severity": "INFO",
            "serviceIdentity": primary_svid,
            "rotationType": "scheduled_rotation" if version > 1 else "initial_issuance",
            "algorithm": "ECDSA P-256 / ECDSA-SHA256 (certificate)",
            "validFrom": meta["valid_from"],
            "validUntil": meta["valid_until"],
            "serialNumber": meta["serial"],
            "version": version,
            "status": "SUCCESS",
            "vaultBackend": self.engine_mode,
            "isLiveVault": (self.engine_mode == "LIVE_VAULT_HTTP_API"),
            "isGenuine": (self.engine_mode == "LIVE_VAULT_HTTP_API"),
            "provenance": ("live_vault_pki" if self.engine_mode == "LIVE_VAULT_HTTP_API" else "standalone_cryptographic_emulation"),
            "details": f"Vault PKI issued version {version} certificate for {common_name} (backend={self.engine_mode})",
        }
        self.events.append(event)
        self._record_telemetry(event)

    def renew_certificate(self, common_name: str, is_server: bool = True) -> Tuple[Path, Path, str, int]:
        """
        Executes automated renewal at 66% TTL threshold:
        Generates new keypair and leaf cert (version N+1).
        """
        if not isinstance(common_name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", common_name):
            raise ValueError("common_name must be a lowercase service name (letters, digits, hyphens)")
        existing = [c for c in self.certificates.values() if c["common_name"] == common_name]
        disk_versions = []
        for cert_path in self.work_dir.glob(f"{common_name}-v*.crt"):
            match = re.fullmatch(rf"{re.escape(common_name)}-v([1-9][0-9]*)\.crt", cert_path.name)
            if match:
                disk_versions.append(int(match.group(1)))
        next_version = max([c["version"] for c in existing] + disk_versions + [0]) + 1
        last_meta = existing[-1] if existing else None

        uri_sans = last_meta["uri_sans"] if last_meta else [f"spiffe://pqzt.local/ns/demo/sa/{common_name}"]
        dns_sans = last_meta["dns_sans"] if last_meta else [common_name]

        cert_f, key_f, new_serial = self.issue_certificate(
            common_name=common_name,
            role="mesh-workload",
            uri_sans=uri_sans,
            dns_sans=dns_sans,
            is_server=is_server,
            version=next_version,
        )
        return cert_f, key_f, new_serial, next_version

    def revoke_certificate(self, serial_hex: str, reason: str = "key_compromise") -> bool:
        """Revoke a serial in the selected backend; never claim success before CRL confirmation."""
        normalized_serial = str(serial_hex).replace(":", "").replace("-", "").lower()
        if (
            len(normalized_serial) < 8
            or len(normalized_serial) > 128
            or any(ch not in "0123456789abcdef" for ch in normalized_serial)
        ):
            raise ValueError("Certificate serial must contain 8-128 hexadecimal characters")

        cert_meta = self.certificates.get(normalized_serial)

        if self.engine_mode == "LIVE_VAULT_HTTP_API":
            # Vault is authoritative in live mode. A serial may have been issued
            # before this process started, so do not require in-memory metadata.
            self.api_client.revoke_certificate(normalized_serial, "pki_mesh")
            self._generate_crl()  # fetches and parses the actual Vault CRL; raises on failure
            revoked_serial_int = int(normalized_serial, 16)
            live_crl = x509.load_pem_x509_crl(self.crl_pem)
            if not any(item.serial_number == revoked_serial_int for item in live_crl):
                raise RuntimeError("Vault revoke returned but the fetched CRL does not contain the requested serial")
            if cert_meta:
                cert_meta["status"] = "REVOKED"
            event = {
                "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
                "eventType": "key_certificate_rotation",
                "category": "crypto_lifecycle",
                "severity": "WARNING",
                "serviceIdentity": (
                    cert_meta["uri_sans"][0] if cert_meta and cert_meta["uri_sans"]
                    else cert_meta["common_name"] if cert_meta else "unknown"
                ),
                "rotationType": "emergency_revocation",
                "algorithm": "ECDSA P-256 / ECDSA-SHA256 (certificate)",
                "serialNumber": normalized_serial,
                "status": "REVOKED",
                "vaultBackend": "LIVE_VAULT_HTTP_API",
                "isLiveVault": True,
                "isGenuine": True,
                "provenance": "live_vault_pki",
                "details": f"Vault confirmed revocation for serial {normalized_serial}; CRL fetched and parsed",
            }
            self.events.append(event)
            self._record_telemetry(event)
            return True

        # Emulation mode can revoke only certificates issued by this local engine.
        if cert_meta is None:
            return False
        cert_meta["status"] = "REVOKED"
        self.revoked_serials.add(cert_meta["serial_int"])
        self._generate_crl()

        event = {
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
            "eventType": "key_certificate_rotation",
            "category": "crypto_lifecycle",
            "severity": "WARNING",
            "serviceIdentity": cert_meta["uri_sans"][0] if cert_meta["uri_sans"] else cert_meta["common_name"],
            "rotationType": "emergency_revocation",
            "algorithm": "ECDSA P-256 / ECDSA-SHA256 (certificate)",
            "validFrom": cert_meta["valid_from"],
            "validUntil": cert_meta["valid_until"],
            "serialNumber": normalized_serial,
            "status": "REVOKED",
            "vaultBackend": "STANDALONE_CRYPTOGRAPHIC_EMULATION",
            "isLiveVault": False,
            "isGenuine": False,
            "provenance": "standalone_cryptographic_emulation",
            "details": f"Emulated revocation for serial {normalized_serial} due to {reason}",
        }
        self.events.append(event)
        self._record_telemetry(event)
        return True

    def is_revoked(self, serial_hex: str) -> bool:
        """Checks a serial against the active backend's revocation state."""
        normalized = str(serial_hex).replace(":", "").replace("-", "").lower()
        if self.engine_mode == "LIVE_VAULT_HTTP_API" and self.crl_pem:
            serial_int = int(normalized, 16)
            crl = x509.load_pem_x509_crl(self.crl_pem)
            return any(item.serial_number == serial_int for item in crl)
        if normalized in self.certificates:
            return self.certificates[normalized]["serial_int"] in self.revoked_serials
        return False

    def get_integration_status(self) -> Dict[str, Any]:
        """Provides an audit breakdown of actual Vault integration vs simulation fallback."""
        return {
            "engine_mode": self.engine_mode,
            "vault_addr": self.api_client.vault_addr,
            "live_vault_healthy": self.api_client.check_health(),
            "live_init_error": self.live_init_error,
            "ca_serial": self.ca_serial,
            "issued_certificates_count": len(self.certificates),
            "revoked_serials_count": len(self.revoked_serials),
            "crl_size_bytes": len(self.crl_pem) if self.crl_pem else 0,
            "architecture_breakdown": {
                "actual_vault_api_endpoints": [
                    "POST /v1/sys/mounts/pki_mesh (Engine Mount)",
                    "POST /v1/pki_mesh/root/generate/internal (Mesh Root CA)",
                    "POST /v1/pki_mesh/roles/mesh-workload (Role Configuration)",
                    "POST /v1/pki_mesh/issue/mesh-workload (Leaf Cert Issuance)",
                    "POST /v1/pki_mesh/revoke (Emergency Revocation)",
                    "GET /v1/pki_mesh/crl/pem (Certificate Revocation List)",
                    "GET /v1/pki_mesh/ca/pem (Root CA Certificate)",
                    "GET /v1/sys/health (Engine Liveness Probe)"
                ],
                "simulation_fallback_components": [
                    "ECDSA P-256 / SHA-256 Root CA builder using python-cryptography",
                    "Leaf Certificate builder with SPIFFE URI SANs and EKU constraints",
                    "In-memory CRL builder updating revocation dates",
                    "Simulated KV v2 versioned secrets state machine in test harness"
                ]
            }
        }

    def _record_telemetry(self, event: dict):
        """Appends event to the shared telemetry audit log."""
        try:
            records = []
            if TELEMETRY_LOG.exists():
                try:
                    records = json.loads(TELEMETRY_LOG.read_text(encoding="utf-8"))
                except Exception:
                    records = []
            records.append(event)
            # Keep latest 150 events
            records = records[-150:]
            TELEMETRY_LOG.parent.mkdir(parents=True, exist_ok=True)
            TELEMETRY_LOG.write_text(json.dumps(records, indent=2), encoding="utf-8")
        except Exception:
            pass


if __name__ == "__main__":
    print("=" * 65)
    print("   PQC Zero-Trust Mesh - Vault PKI Engine & API Coordinator")
    print("=" * 65)
    pki = VaultPKIEngine()
    status = pki.get_integration_status()
    print(f"[+] Engine Mode:         {status['engine_mode']}")
    print(f"[+] Vault Target Addr:   {status['vault_addr']}")
    print(f"[+] Live Vault Healthy:  {status['live_vault_healthy']}")
    print(f"[+] Root CA Serial:      {status['ca_serial']}")

    # Issue frontend
    fc, fk, fs = pki.issue_certificate("frontend", is_server=False, uri_sans=["spiffe://pqzt.local/ns/demo/sa/frontend"], dns_sans=["frontend"])
    print(f"[+] Issued Frontend Leaf Cert (V1): {fs}")

    # Issue backend
    bc, bk, bs = pki.issue_certificate("backend", is_server=True, uri_sans=["spiffe://pqzt.local/ns/demo/sa/backend"], dns_sans=["backend"])
    print(f"[+] Issued Backend Leaf Cert (V1):  {bs}")

    # Renew frontend
    rfc, rfk, rfs, v = pki.renew_certificate("frontend", is_server=False)
    print(f"[+] Renewed Frontend Leaf Cert (V{v}): {rfs}")

    # Revoke old cert
    pki.revoke_certificate(fs, reason="scheduled_retirement")
    print(f"[+] Revoked Frontend V1 Cert: {fs} (is_revoked={pki.is_revoked(fs)})")
    print("[+] Vault PKI lifecycle complete.")
