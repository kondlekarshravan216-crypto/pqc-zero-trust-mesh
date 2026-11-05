# Kubernetes NetworkPolicy and Microsegmentation Validation Report

## 1. Objective

Validate Kubernetes NetworkPolicy enforcement by allowing authorized frontend-to-backend communication and blocking unauthorized pod access.

## 2. Environment

- Kubernetes cluster: KillerCoda Kubernetes Playground
- Kubernetes version: v1.37.1
- CNI: Cilium
- Namespace: `zero-trust-demo`
- Frontend workload: `frontend`
- Backend workload: `backend`
- Backend TCP port: `8080`

## 3. Resources Deployed

The following resources were successfully created:

- Namespace: `zero-trust-demo`
- Frontend Deployment and Service
- Backend Deployment and Service
- NetworkPolicy: `backend-restrict-ingress`
- NetworkPolicy: `default-deny-ingress`

## 4. Cluster and Workload Validation

**Cluster nodes:** Both control-plane and worker nodes reported Ready.

**Cilium status:**
- Cilium: OK
- Operator: OK
- Envoy DaemonSet: OK

**Pod status:**
- Frontend: Running (1/1)
- Backend: Running (1/1)
- Unauthorized test pod: Running (1/1)

**Service endpoints:**
- Backend service: port 8080
- Frontend service: port 80

## 5. NetworkPolicy Configuration

The backend ingress policy allows TCP port 8080 only from pods carrying the label:

`app: frontend`

The default-deny ingress policy selects all pods in the demonstration namespace and denies incoming traffic unless another applicable NetworkPolicy allows it.

## 6. Test Results

### Test 1: Authorized Frontend-to-Backend Communication

Command:

`kubectl exec -n zero-trust-demo deploy/frontend -- wget -T 5 -qO- http://backend:8080`

Observed output:

`zero-trust-backend-ok`

**Result: PASS**

The frontend successfully accessed the backend.

### Test 2: Unauthorized Pod-to-Backend Communication

A temporary pod named `unauthorized-client` was created with the label:

`app: unauthorized`

Command:

`kubectl exec -n zero-trust-demo unauthorized-client -- wget -T 5 -qO- http://backend:8080`

Observed output:

`wget: download timed out`

Command exited with code 1.

**Result: PASS — connection was blocked in this test.**

## 7. Validation Summary

| Validation | Result |
|---|---|
| Namespace creation | PASS |
| Deployments created | PASS |
| Pods running | PASS |
| Services and endpoints | PASS |
| Cilium status | PASS |
| Authorized communication | PASS |
| Unauthorized communication | PASS |
| NetworkPolicy resources | PASS |

## 8. Evidence and Limitations

Terminal screenshots show the cluster status, deployed workloads, service endpoints, NetworkPolicy resources, and authorized/unauthorized test outputs.

The unauthorized timeout is consistent with the intended NetworkPolicy denial. For stronger evidence, repeat the test and confirm the result using CNI-specific flow monitoring or packet-level diagnostics.

## 9. Conclusion

The Kubernetes microsegmentation demonstration was deployed successfully. The authorized frontend-to-backend request returned the expected response, while the unauthorized client request timed out.

The observed results support the intended ingress isolation behavior in the test environment.
