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

## 6. Validation Status

The Kubernetes manifests were deployed and tested in a Killercoda Kubernetes environment.

- Namespace creation: Completed
- Frontend and backend deployments: Completed
- Service creation and endpoint checks: Completed
- Default-deny ingress policy: Applied
- Frontend-to-backend NetworkPolicy: Applied
- Cilium status check: Reported OK
- Authorized traffic test: Passed
- Unauthorized traffic test: Timed out; further verification required
- Frontend pod restart test: Completed
- Authorized communication after restart: Passed

## 7. Environment and Deployment Evidence

**Environment**
- Kubernetes cluster: Killercoda
- Nodes: controlplane and node01
- CNI: Cilium
- Namespace: `zero-trust-demo`

**Commands executed**
```bash
kubectl get nodes
kubectl get pods -A
kubectl get namespaces
cilium status

kubectl apply -f kubernetes/namespace.yaml
kubectl apply -f kubernetes/kubernetes/backend.yaml
kubectl apply -f kubernetes/kubernetes/frontend.yaml
kubectl apply -f kubernetes/kubernetes/default-deny.yaml
kubectl apply -f kubernetes/kubernetes/kubernetes/network-policy.yaml

kubectl get pods -n zero-trust-demo
kubectl get svc -n zero-trust-demo
kubectl get networkpolicy -n zero-trust-demo
kubectl get endpoints -n zero-trust-demo
```

The namespace, deployments, services, and NetworkPolicies were created successfully. Both application pods reached `1/1 Running`.

## 8. Traffic Testing Results

### Authorized traffic

The frontend pod successfully accessed the backend service on TCP port 8080.

Observed response:

```text
zero-trust-backend-ok
```

**Result:** Passed.

### Unauthorized traffic

A temporary pod labelled `app=unauthorized` was created and tested against the backend.

Observed result:

```text
wget: download timed out
command terminated with exit code 1
```

**Result:** Connection timed out, consistent with the intended deny policy. A repeat test with additional connectivity checks is still required to conclusively establish NetworkPolicy enforcement.

### Pod restart behavior

The frontend pod was deleted and its Deployment recreated it.

Observed result:
- Frontend Deployment rollout completed successfully.
- Authorized frontend-to-backend communication worked after the restart.

**Result:** Passed.

## 9. Current Limitations and Next Steps

- Repeat the unauthorized traffic test and confirm that the timeout is caused by NetworkPolicy enforcement.
- Capture complete terminal output for both allowed and denied traffic tests.
- Confirm the final manifest paths and remove unnecessary nested directories if required.
- Coordinate with the Envoy and OPA teams for integration testing.
- End-to-end integration with PQC, Envoy mTLS, OPA, and Vault remains outside the scope of the tests demonstrated here.

## 10. Conclusion

The Kubernetes microsegmentation module has a working deployment foundation. Namespace creation, workload deployment, service discovery, NetworkPolicy creation, authorized backend access, and frontend recovery after restart were demonstrated in Killercoda.

Unauthorized traffic produced a timeout, but additional verification is required before declaring the deny policy fully validated.

Runtime results are limited to the demonstrated Kubernetes environment and should not be interpreted as proof of complete end-to-end zero-trust integration.
