Kubernetes Zero-Trust Microsegmentation

1. Objective

Implement Kubernetes network segmentation to restrict communication between frontend and backend workloads. Allow explicitly authorized traffic and deny unauthorized connections using Kubernetes NetworkPolicies.

2. Namespace

Namespace: "zero-trust-demo"

The namespace isolates the demonstration workloads from other application namespaces.

3. Kubernetes Resources

- "namespace.yaml" — creates the demonstration namespace.
- "frontend.yaml" — defines the frontend deployment.
- "backend.yaml" — defines the backend deployment.
- "frontend-service.yaml" — exposes the frontend internally.
- "backend-service.yaml" — exposes the backend internally.
- "network-policy.yaml" — permits frontend-to-backend ingress on TCP port 8080.
- "default-deny.yaml" — denies ingress to pods by default.

4. Network Segmentation Design

- Frontend pods → backend pods on TCP port 8080: Allowed
- Unauthorized pods → backend pods on TCP port 8080: Denied
- Other incoming connections: Denied unless another applicable policy allows them

Kubernetes NetworkPolicies are additive. The default-deny policy and explicit allow policy work together.

5. CNI Requirements

NetworkPolicy enforcement depends on the cluster's Container Network Interface (CNI). The presence of a NetworkPolicy does not prove that traffic is being filtered.

6. Validation Status

- Manifest creation: Completed
- YAML syntax validation: Pending
- Kubernetes API validation: Pending
- Cluster availability verification: Pending
- CNI enforcement verification: Pending
- Frontend-to-backend connectivity test: Pending
- Unauthorized traffic-denial test: Pending

Runtime tests must be performed before marking them successful.

7. Runtime Testing Plan

1. Apply the namespace and workload manifests.
2. Confirm that frontend and backend pods are ready.
3. Verify that the backend Service targets the correct pods.
4. Test frontend-to-backend connectivity on TCP port 8080.
5. Create a temporary unauthorized test pod.
6. Verify that the unauthorized pod cannot connect to the backend.
7. Record test outputs and any failures.
8. Confirm that the cluster's CNI enforces NetworkPolicies.

8. Current Limitations

Runtime testing has not yet been confirmed. A working Kubernetes cluster and compatible CNI are required to demonstrate actual network isolation.

The frontend workload must also be configured to generate HTTP requests before end-to-end application connectivity can be tested.

9. Integration Considerations

Coordinate with the Envoy and OPA team members to identify required service ports, authenticated service identities, and additional traffic requirements.

Kubernetes NetworkPolicies provide network-level controls; they do not independently implement mTLS, post-quantum cryptography, or application authorization.

10. Conclusion

This module establishes the configuration foundation for Kubernetes microsegmentation. Final completion requires manifest validation, runtime traffic testing, and documented evidence.
