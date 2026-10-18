package authz

import rego.v1

# Default to denying all requests (Zero-Trust Principle: deny-by-default)
default allow := false

# Approved frontend service identities permitted to access backend services
approved_frontend_identities := {
    "frontend",
    "frontend-service",
    "spiffe://cluster.local/ns/mesh/sa/frontend-service",
    "spiffe://pqzt.local/ns/demo/sa/frontend",
}

# Permitted actions for frontend -> backend communication
read_actions := {"GET", "get", "read", "HEAD", "head"}

# Allow rule: verified frontend identity accessing backend service
allow if {
    approved_frontend_identities[input.identity]
    input.destination == "backend"
    not input.action
}

allow if {
    approved_frontend_identities[input.identity]
    input.destination == "backend"
    read_actions[input.action]
}

# Decision reason metadata for audit logging and dashboard telemetry
reason := "Access granted: approved frontend identity" if {
    allow
}

reason := "Access denied: unapproved identity or unauthorized destination" if {
    not allow
}

