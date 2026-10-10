path "secret/data/mesh/*" {
  capabilities = ["create", "read", "update"]
}

path "secret/metadata/mesh/*" {
  capabilities = ["read", "list"]
}