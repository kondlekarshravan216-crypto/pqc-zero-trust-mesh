# Vault PKI Least-Privilege Policy for PQC Zero-Trust Mesh
# Allows workload agents to request and renew certificates from the mesh PKI role,
# while restricting administrative CA destruction.

# Read and list issued certificates and CRL
path "pki_mesh/cert/*" {
  capabilities = ["read"]
}

path "pki_mesh/certs" {
  capabilities = ["list"]
}

path "pki_mesh/crl" {
  capabilities = ["read"]
}

# Workload certificate issuance and renewal via role
path "pki_mesh/issue/mesh-workload" {
  capabilities = ["create", "update"]
}

path "pki_mesh/roles/mesh-workload" {
  capabilities = ["read", "list"]
}

# Emergency revocation capability
path "pki_mesh/revoke" {
  capabilities = ["create", "update"]
}
