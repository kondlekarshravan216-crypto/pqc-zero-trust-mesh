
package mesh.authz

import rego.v1

default allow := false

read_actions := {"read", "GET", "get", "HEAD", "head"}

allow if {
    input.source == "frontend"
    input.destination == "backend"
    read_actions[input.action]
}

allow if {
    input.source == "backend"
    input.destination == "database"
    read_actions[input.action]
}

