package authz

# Test case 1: Approved frontend identity allowed to access backend
test_allow_approved_identity {
    allow with input as {
        "identity": "spiffe://cluster.local/ns/mesh/sa/frontend-service",
        "destination": "backend",
        "action": "GET"
    }
}

# Test case 2: Unapproved identity denied access to backend
test_deny_unapproved_identity {
    not allow with input as {
        "identity": "spiffe://cluster.local/ns/mesh/sa/unapproved-service",
        "destination": "backend",
        "action": "POST"
    }
}

# Test case 3: Approved frontend identity denied access to unauthorized destination
test_deny_unauthorized_destination {
    not allow with input as {
        "identity": "spiffe://cluster.local/ns/mesh/sa/frontend-service",
        "destination": "database",
        "action": "GET"
    }
}

# Test case 4: Empty input denied
test_deny_empty_input {
    not allow with input as {}
}
