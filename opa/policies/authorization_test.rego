package mesh.authz

import rego.v1

# Test 1: Frontend allowed to read backend
test_allow_frontend_backend if {
    allow with input as {
        "source": "frontend",
        "destination": "backend",
        "action": "read",
    }
}

# Test 2: Backend allowed to read database
test_allow_backend_database if {
    allow with input as {
        "source": "backend",
        "destination": "database",
        "action": "read",
    }
}

# Test 3: Frontend denied direct access to database (lateral movement restriction)
test_deny_frontend_database if {
    not allow with input as {
        "source": "frontend",
        "destination": "database",
        "action": "read",
    }
}

# Test 4: Unknown service denied access to backend
test_deny_unknown_backend if {
    not allow with input as {
        "source": "unknown",
        "destination": "backend",
        "action": "read",
    }
}
