
package mesh.authz

import rego.v1

default allow := false

allow if {
    input.source == "frontend"
    input.destination == "backend"
    input.action == "read"
}

allow if {
    input.source == "backend"
    input.destination == "database"
    input.action == "read"
}
