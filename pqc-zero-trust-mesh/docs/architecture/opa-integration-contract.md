# OPA Authorization Integration Contract — v1

## 1. Purpose
Define the initial request format and authorization behavior for
the Post-Quantum Zero-Trust Microsegmentation Mesh prototype.

This document describes the contract. It does not claim that OPA,
Envoy, Kubernetes, or the application are fully integrated.

## 2. Policy Location
- Policy file: opa/policies/authorization.rego
- Package: mesh.authz
- Decision: data.mesh.authz.allow
- Decision type: Boolean
- Default decision: DENY

## 3. Request Input Format
The initial policy expects a JSON object with three string fields:

{
  "source": "frontend",
  "destination": "backend",
  "action": "read"
}

Fields:
- source: name of the requesting service
- destination: name of the target service
- action: requested operation

The initial policy evaluates these input fields. Trusted identity
verification and input validation are not yet implemented here.

## 4. Initial Authorization Rules

| Source | Destination | Action | Expected decision |
|---|---|---|---|
| frontend | backend | read | ALLOW |
| backend | database | read | ALLOW |
| frontend | database | read | DENY |
| unknown | backend | read | DENY |

Any request that does not match an allow rule should be denied.

## 5. Integration Responsibilities
- Kubernetes: restrict network reachability using NetworkPolicies.
- Envoy: enforce the configured service-connection security and,
  when integrated, obtain authorization decisions from OPA.
- OPA: evaluate authorization input and return ALLOW or DENY.
- Application: reject unauthorized requests.
- Dashboard: display authorization events after event collection
  is implemented.

These are intended responsibilities; integration must be tested.

## 6. Security Requirements
- Do not trust a caller-provided source field as proof of identity.
- Bind authorization inputs to authenticated service identity.
- Default to DENY when authorization cannot be established.
- Do not commit private keys, passwords, tokens, or real secrets.
- Do not treat a successful standalone OPA test as proof of
  Envoy, Kubernetes, or end-to-end integration.

## 7. Verification Status
- Initial policy reviewed from the feature/opa-vault branch.
- Four standalone OPA test cases passed using OPA 1.21.1 in Docker.
- Envoy integration: not yet verified.
- Kubernetes enforcement: not yet verified.
- Vault operation and key rotation: not yet verified.
- End-to-end authorization: not yet verified.

## 8. Next Steps
1. Review the contract with the team.
2. Confirm the authorization input schema.
3. Integrate OPA with the chosen enforcement point.
4. Test allowed and denied requests end to end.
5. Record reproducible commands and actual results.
