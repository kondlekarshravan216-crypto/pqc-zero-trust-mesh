package authz

# Default to denying all requests (Zero-Trust Principle: deny-by-default)
default allow = false

# Approved frontend service identities permitted to access backend services
approved_frontend_identities = {
    "frontend-service",
    "spiffe://cluster.local/ns/mesh/sa/frontend-service"
}

# Allow rule: verified frontend identity accessing backend service
allow {
    approved_frontend_identities[input.identity]
    input.destination == "backend"
}

# Decision reason metadata for audit logging and dashboard telemetry
reason = "Access granted: approved frontend identity" {
    allow
}

reason = "Access denied: unapproved identity or unauthorized destination" {
    not allow
}
