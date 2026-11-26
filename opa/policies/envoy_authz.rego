package envoy.authz

import rego.v1

# Reuse the existing authorization policy for Envoy ext_authz.
allow := data.authz.allow
