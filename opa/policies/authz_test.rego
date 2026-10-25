package authz

import rego.v1

# Test case 1: Approved frontend identity allowed to access backend
test_allow_approved_identity if {
    allow with input as {
        "identity": "spiffe://cluster.local/ns/mesh/sa/frontend-service",
        "destination": "backend",
        "action": "GET",
    }
}

# Test case 2: Unapproved identity denied access to backend
test_deny_unapproved_identity if {
    not allow with input as {
        "identity": "spiffe://cluster.local/ns/mesh/sa/unapproved-service",
        "destination": "backend",
        "action": "POST",
    }
}

# Test case 3: Approved frontend identity denied access to unauthorized destination
test_deny_unauthorized_destination if {
    not allow with input as {
        "identity": "spiffe://cluster.local/ns/mesh/sa/frontend-service",
        "destination": "database",
        "action": "GET",
    }
}

# Test case 4: Empty input denied
test_deny_empty_input if {
    not allow with input as {}
}

# Test case 5: Demo mesh SPIFFE identity allowed to access backend
test_allow_demo_frontend_identity if {
    allow with input as {
        "identity": "spiffe://pqzt.local/ns/demo/sa/frontend",
        "destination": "backend",
        "action": "GET",
    }
}

# Test case 6: Unauthorized action denied (e.g. DELETE method)
test_deny_unauthorized_action if {
    not allow with input as {
        "identity": "spiffe://pqzt.local/ns/demo/sa/frontend",
        "destination": "backend",
        "action": "DELETE",
    }
}

# Test case 7: Envoy ext_authz CheckRequest envelope allowed
test_allow_envoy_check_request if {
    allow with input as {
        "attributes": {
            "source": {
                "principal": "spiffe://pqzt.local/ns/demo/sa/frontend",
            },
            "request": {
                "http": {
                    "method": "GET",
                    "path": "/api/v1/resource",
                },
            },
        },
    }
}

# Test case 8: Envoy ext_authz lateral movement to /database denied
test_deny_envoy_lateral_database if {
    not allow with input as {
        "attributes": {
            "source": {
                "principal": "spiffe://pqzt.local/ns/demo/sa/frontend",
            },
            "request": {
                "http": {
                    "method": "GET",
                    "path": "/database/credentials",
                },
            },
        },
    }
}

# Test case 9: Mesh source-based input allowed
test_allow_mesh_source_input if {
    allow with input as {
        "source": "frontend",
        "destination": "backend",
        "action": "GET",
    }
}

# Test case 10: Envoy ext_authz mutating action denied
test_deny_envoy_mutating_action if {
    not allow with input as {
        "attributes": {
            "source": {
                "principal": "spiffe://pqzt.local/ns/demo/sa/frontend",
            },
            "request": {
                "http": {
                    "method": "POST",
                    "path": "/api/v1/admin",
                },
            },
        },
    }
}


