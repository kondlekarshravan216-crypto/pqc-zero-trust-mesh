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

# Extracted Caller Identity (supports direct input.identity, input.source, or Envoy attributes)
caller_identity := input.identity if {
    input.identity
} else := input.source if {
    input.source
} else := input.attributes.source.principal if {
    input.attributes.source.principal
} else := ""

# Extracted Destination (supports direct destination or derives from Envoy request path)
target_destination := input.destination if {
    input.destination
} else := "database" if {
    startswith(input.attributes.request.http.path, "/database")
} else := "backend" if {
    input.attributes.request.http.path
} else := ""

# Extracted Action (supports direct action or Envoy HTTP method, defaults to GET if omitted)
request_action := input.action if {
    input.action
} else := input.attributes.request.http.method if {
    input.attributes.request.http.method
} else := "GET" if {
    # If action is omitted but identity and destination are provided
    caller_identity != ""
    target_destination != ""
    not input.action
} else := ""

# Allow rule: verified frontend identity accessing backend service with read action
allow if {
    approved_frontend_identities[caller_identity]
    target_destination == "backend"
    read_actions[request_action]
}

# Decision reason metadata for audit logging and dashboard telemetry
reason := "Access granted: approved frontend identity" if {
    allow
}

reason := "Access denied: unapproved identity or unauthorized destination" if {
    not allow
}


