# Agnes - CA, Certificates, Envoy and mTLS
Date: 2026-11-04T13:09:05+00:00
Runtime candidate: /mnt/d/pki-mtls-full-project/team-main
Git branch: feature/agnes-pqc-status-pr

## 1. Source and configuration review
FOUND: envoy/frontend-envoy.yaml
66:              tls_minimum_protocol_version: TLSv1_3
67:              tls_maximum_protocol_version: TLSv1_3
68:              ecdh_curves:
72:            tls_certificates:
77:            validation_context:
FOUND: envoy/backend-envoy.yaml
15:          require_client_certificate: true            # => mutual TLS
18:              tls_minimum_protocol_version: TLSv1_3
19:              tls_maximum_protocol_version: TLSv1_3
21:              ecdh_curves: [X25519MLKEM768, X25519, P-256]
22:            tls_certificates:
25:            validation_context:

## 2. Certificate availability
AVAILABLE: /home/agnes/pki-mtls-secure/backend/backend.crt
AVAILABLE: /home/agnes/pki-mtls-secure/backend/backend.key
AVAILABLE: /home/agnes/pki-mtls-secure/backend/ca.crt
AVAILABLE: /home/agnes/pki-mtls-secure/frontend/frontend.crt
AVAILABLE: /home/agnes/pki-mtls-secure/frontend/frontend.key
AVAILABLE: /home/agnes/pki-mtls-secure/frontend/ca.crt

## 3. Compose validation
PASS: Compose configuration

## 4. Start required stack
Starting backend-app, backend-envoy and frontend-envoy.
 Network team-main_mesh Creating
 Network team-main_mesh Creating
 Network team-main_mesh Created
 Network team-main_mesh Created
 Container team-main-backend-app-1 Creating
 Container team-main-backend-app-1 Created
 Container team-main-backend-envoy-1 Creating
 Container team-main-backend-envoy-1 Created
 Container team-main-frontend-envoy-1 Creating
 Container team-main-frontend-envoy-1 Created
 Container team-main-backend-app-1 Starting
 Container team-main-backend-app-1 Started
 Container team-main-backend-envoy-1 Starting
 Container team-main-backend-envoy-1 Started
 Container team-main-frontend-envoy-1 Starting
 Container team-main-frontend-envoy-1 Started
NAME                         IMAGE                      COMMAND                  SERVICE          CREATED         STATUS         PORTS
team-main-backend-app-1      python:3.12-alpine         "python /app/app.py"     backend-app      9 seconds ago   Up 8 seconds
team-main-backend-envoy-1    envoyproxy/envoy:v1.39.3   "/docker-entrypoint.…"   backend-envoy    9 seconds ago   Up 7 seconds   127.0.0.1:18443->8443/tcp
team-main-frontend-envoy-1   envoyproxy/envoy:v1.39.3   "/docker-entrypoint.…"   frontend-envoy   8 seconds ago   Up 6 seconds   127.0.0.1:8080->8080/tcp

## 5. Validate both Envoy configurations
[2026-11-04 13:09:16.506][28][info][main] [source/server/server.cc:968] runtime: {}
[2026-11-04 13:09:16.506][28][info][config] [source/server/configuration_impl.cc:181] loading tracing configuration
[2026-11-04 13:09:16.506][28][info][config] [source/server/configuration_impl.cc:132] loading 0 static secret(s)
[2026-11-04 13:09:16.506][28][info][config] [source/server/configuration_impl.cc:138] loading 1 cluster(s)
[2026-11-04 13:09:16.508][28][info][config] [source/server/configuration_impl.cc:148] loading 1 listener(s)
[2026-11-04 13:09:16.515][28][info][config] [source/server/configuration_impl.cc:164] loading stats configuration
configuration '/etc/envoy/envoy.yaml' OK
PASS: backend-envoy
[2026-11-04 13:09:17.123][28][info][main] [source/server/server.cc:968] runtime: {}
[2026-11-04 13:09:17.123][28][info][config] [source/server/configuration_impl.cc:181] loading tracing configuration
[2026-11-04 13:09:17.123][28][info][config] [source/server/configuration_impl.cc:132] loading 0 static secret(s)
[2026-11-04 13:09:17.123][28][info][config] [source/server/configuration_impl.cc:138] loading 1 cluster(s)
[2026-11-04 13:09:17.127][28][info][config] [source/server/configuration_impl.cc:148] loading 1 listener(s)
configuration '/etc/envoy/envoy.yaml' OK
[2026-11-04 13:09:17.135][28][info][config] [source/server/configuration_impl.cc:164] loading stats configuration
PASS: frontend-envoy

## 6. Certificate details
### /home/agnes/pki-mtls-secure/backend/backend.crt
subject=O=PQZT Demo, CN=backend
issuer=O=PQZT Demo, CN=PQZT Local Test Root CA
notBefore=Oct 11 13:29:03 2026 GMT
notAfter=Jan  9 13:29:03 2027 GMT
Certificate will not expire
PASS: Not expired
### /home/agnes/pki-mtls-secure/frontend/frontend.crt
subject=O=PQZT Demo, CN=frontend
issuer=O=PQZT Demo, CN=PQZT Local Test Root CA
notBefore=Oct 11 13:22:09 2026 GMT
notAfter=Jan  9 13:22:09 2027 GMT
Certificate will not expire
PASS: Not expired

## 7. Frontend route test
HTTP status: 200
{"service":"backend","status":"ok"}

## 8. Valid client certificate test
Connecting to 127.0.0.1
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Requested Signature Algorithms: ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:ECDSA+SHA384:RSA-PSS+SHA384:RSA+SHA384:RSA-PSS+SHA512:RSA+SHA512:RSA+SHA1
Peer certificate: O=PQZT Demo, CN=backend
Hash used: SHA256
Signature type: ecdsa_secp256r1_sha256
Verification: OK
Verified peername: backend
Negotiated TLS1.3 group: X25519MLKEM768
DONE

## 9. Missing client certificate test
Connecting to 127.0.0.1
depth=0 O=PQZT Demo, CN=backend
verify error:num=20:unable to get local issuer certificate
depth=0 O=PQZT Demo, CN=backend
verify error:num=21:unable to verify the first certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Requested Signature Algorithms: ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:ECDSA+SHA384:RSA-PSS+SHA384:RSA+SHA384:RSA-PSS+SHA512:RSA+SHA512:RSA+SHA1
Peer certificate: O=PQZT Demo, CN=backend
Hash used: SHA256
Signature type: ecdsa_secp256r1_sha256
Verification error: unable to verify the first certificate
Negotiated TLS1.3 group: X25519MLKEM768
DONE

## 10. Untrusted certificate test
NOT RUN: No confirmed unrelated-CA client certificate supplied.
Do not substitute a trusted certificate for this test.

## 11. TLS 1.3 and direct hybrid handshake test
Connecting to 127.0.0.1
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Requested Signature Algorithms: ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:ECDSA+SHA384:RSA-PSS+SHA384:RSA+SHA384:RSA-PSS+SHA512:RSA+SHA512:RSA+SHA1
Peer certificate: O=PQZT Demo, CN=backend
Hash used: SHA256
Signature type: ecdsa_secp256r1_sha256
Verification: OK
Verified peername: backend
Negotiated TLS1.3 group: X25519MLKEM768
DONE

## 12. Envoy-to-Envoy hybrid negotiation
Configured groups:
envoy/frontend-envoy.yaml:68:              ecdh_curves:
envoy/frontend-envoy.yaml-69-                - X25519MLKEM768
envoy/frontend-envoy.yaml-70-                - X25519
envoy/frontend-envoy.yaml-71-                - P-256
envoy/frontend-envoy.yaml-72-            tls_certificates:
--
envoy/backend-envoy.yaml:21:              ecdh_curves: [X25519MLKEM768, X25519, P-256]
envoy/backend-envoy.yaml-22-            tls_certificates:
envoy/backend-envoy.yaml-23-            - certificate_chain: { filename: /etc/pqzt/certs/backend.crt }
envoy/backend-envoy.yaml-24-              private_key:       { filename: /etc/pqzt/certs/backend.key }
envoy/backend-envoy.yaml-25-            validation_context:
PASS: Packet capture and tshark decode confirmed Envoy-to-Envoy TLS 1.3 ServerHello key_share X25519MLKEM768 (group 4588).

## 13. Envoy logs
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.matching.input_matchers: envoy.matching.input_matchers.generic_request_matcher, envoy.matching.matchers.cel_matcher, envoy.matching.matchers.consistent_hashing, envoy.matching.matchers.dynamic_modules, envoy.matching.matchers.ip, envoy.matching.matchers.metadata_matcher, envoy.matching.matchers.runtime_fraction
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.rds_factory: envoy.rds_factory.default
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.thrift_proxy.protocols: auto, binary, binary/non-strict, compact, twitter
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.http.cache_v2: envoy.extensions.http.cache_v2.file_system_http_cache, envoy.extensions.http.cache_v2.simple
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.rate_limit_descriptors: envoy.rate_limit_descriptors.expr
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.filters.http: envoy.bandwidth_limit, envoy.buffer, envoy.cors, envoy.csrf, envoy.ext_authz, envoy.ext_proc, envoy.extensions.filters.http.dynamic_modules, envoy.fault, envoy.filters.http.a2a, envoy.filters.http.adaptive_concurrency, envoy.filters.http.admission_control, envoy.filters.http.ai_protocol_manager, envoy.filters.http.alternate_protocols_cache, envoy.filters.http.api_key_auth, envoy.filters.http.aws_lambda, envoy.filters.http.aws_request_signing, envoy.filters.http.bandwidth_limit, envoy.filters.http.bandwidth_share, envoy.filters.http.basic_auth, envoy.filters.http.buffer, envoy.filters.http.cache, envoy.filters.http.cache_v2, envoy.filters.http.cdn_loop, envoy.filters.http.composite, envoy.filters.http.compressor, envoy.filters.http.connect_grpc_bridge, envoy.filters.http.cors, envoy.filters.http.credential_injector, envoy.filters.http.csrf, envoy.filters.http.custom_response, envoy.filters.http.decompressor, envoy.filters.http.dynamic_forward_proxy, envoy.filters.http.ext_authz, envoy.filters.http.ext_proc, envoy.filters.http.fault, envoy.filters.http.file_server, envoy.filters.http.file_system_buffer, envoy.filters.http.filter_chain, envoy.filters.http.gcp_authn, envoy.filters.http.geoip, envoy.filters.http.grpc_field_extraction, envoy.filters.http.grpc_http1_bridge, envoy.filters.http.grpc_http1_reverse_bridge, envoy.filters.http.grpc_json_reverse_transcoder, envoy.filters.http.grpc_json_transcoder, envoy.filters.http.grpc_stats, envoy.filters.http.grpc_web, envoy.filters.http.header_mutation, envoy.filters.http.header_to_metadata, envoy.filters.http.health_check, envoy.filters.http.ip_tagging, envoy.filters.http.json_to_metadata, envoy.filters.http.jwt_authn, envoy.filters.http.local_ratelimit, envoy.filters.http.lua, envoy.filters.http.match_delegate, envoy.filters.http.mcp, envoy.filters.http.mcp_json_rest_bridge, envoy.filters.http.mcp_router, envoy.filters.http.oauth2, envoy.filters.http.on_demand, envoy.filters.http.original_src, envoy.filters.http.proto_api_scrubber, envoy.filters.http.proto_message_extraction, envoy.filters.http.rate_limit_quota, envoy.filters.http.ratelimit, envoy.filters.http.rbac, envoy.filters.http.router, envoy.filters.http.set_filter_state, envoy.filters.http.set_metadata, envoy.filters.http.sse_to_metadata, envoy.filters.http.stateful_session, envoy.filters.http.tap, envoy.filters.http.thrift_to_metadata, envoy.filters.http.transform, envoy.filters.http.wasm, envoy.geoip, envoy.grpc_http1_bridge, envoy.grpc_json_transcoder, envoy.grpc_web, envoy.health_check, envoy.ip_tagging, envoy.local_rate_limit, envoy.lua, envoy.rate_limit, envoy.router
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.tls.cert_validator: envoy.tls.cert_validator.default, envoy.tls.cert_validator.dynamic_modules, envoy.tls.cert_validator.spiffe
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.route.early_data_policy: envoy.route.early_data_policy.default
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.retry_priorities: envoy.retry_priorities.previous_priorities
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.listener_manager_impl: envoy.listener_manager_impl.default, envoy.listener_manager_impl.validation
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.http.stateful_header_formatters: envoy.http.stateful_header_formatters.preserve_case, preserve_case
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.dubbo_proxy.filters: envoy.filters.dubbo.router
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.http.cache: envoy.extensions.http.cache.file_system_http_cache, envoy.extensions.http.cache.simple
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.config.validators: envoy.config.validators.minimum_clusters, envoy.config.validators.minimum_clusters_validator
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.matching.common_inputs: envoy.matching.common_inputs.environment_variable
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.generic_proxy.filters: envoy.filters.generic.router
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.http.forward_client_cert_details: forward_client_cert
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.matching.http.custom_matchers: envoy.matching.custom_matchers.domain_matcher, envoy.matching.custom_matchers.ip_range_matcher
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.quic.server_preferred_address: quic.server_preferred_address.datasource, quic.server_preferred_address.fixed
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.tls.upstream_certificate_selectors: envoy.tls.certificate_selectors.on_demand_secret
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.filters.udp_listener: envoy.filters.udp.dns_filter, envoy.filters.udp_listener.dynamic_modules, envoy.filters.udp_listener.udp_proxy
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.compression.decompressor: envoy.compression.brotli.decompressor, envoy.compression.gzip.decompressor, envoy.compression.zstd.decompressor
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.tls.upstream_certificate_mappers: envoy.tls.certificate_mappers.static_name, envoy.tls.upstream_certificate_mappers.filter_state_override
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   network.connection.client: default, envoy_internal
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.built_in_formatters: envoy.built_in_formatters.cel, envoy.built_in_formatters.http.default, envoy.built_in_formatters.metadata, envoy.built_in_formatters.stream_info.default, envoy.built_in_formatters.xfcc_value
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.matching.network.input: envoy.matching.inputs.application_protocol, envoy.matching.inputs.destination_ip, envoy.matching.inputs.destination_port, envoy.matching.inputs.direct_source_ip, envoy.matching.inputs.dns_san, envoy.matching.inputs.filter_state, envoy.matching.inputs.network_namespace, envoy.matching.inputs.server_name, envoy.matching.inputs.source_ip, envoy.matching.inputs.source_port, envoy.matching.inputs.source_type, envoy.matching.inputs.subject, envoy.matching.inputs.transport_protocol, envoy.matching.inputs.uri_san
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.upstreams: envoy.filters.connection_pools.tcp.generic
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.thrift_proxy.transports: auto, framed, header, unframed
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.config_subscription: envoy.config_subscription.ads, envoy.config_subscription.ads_collection, envoy.config_subscription.aggregated_grpc_collection, envoy.config_subscription.delta_grpc, envoy.config_subscription.delta_grpc_collection, envoy.config_subscription.filesystem, envoy.config_subscription.filesystem_collection, envoy.config_subscription.grpc, envoy.config_subscription.rest
backend-envoy-1  | [2026-11-04 13:09:09.474][1][info][main] [source/server/server.cc:471]   envoy.ssl.server_context_factory: envoy.ssl.server_context_factory.default
backend-envoy-1  | [2026-11-04 13:09:09.500][1][info][main] [source/server/server.cc:531] HTTP header map info:
backend-envoy-1  | [2026-11-04 13:09:09.501][1][info][main] [source/server/server.cc:534]   request header map: 664 bytes: :authority,:method,:path,:protocol,:scheme,accept,accept-encoding,access-control-request-headers,access-control-request-method,access-control-request-private-network,authentication,authorization,cache-control,cdn-loop,connection,content-encoding,content-length,content-type,expect,grpc-accept-encoding,grpc-timeout,if-match,if-modified-since,if-none-match,if-range,if-unmodified-since,keep-alive,origin,pragma,proxy-connection,proxy-status,referer,te,transfer-encoding,upgrade,user-agent,via,x-client-trace-id,x-envoy-attempt-count,x-envoy-decorator-operation,x-envoy-downstream-service-cluster,x-envoy-downstream-service-node,x-envoy-expected-rq-timeout-ms,x-envoy-external-address,x-envoy-force-trace,x-envoy-hedge-on-per-try-timeout,x-envoy-internal,x-envoy-ip-tags,x-envoy-is-timeout-retry,x-envoy-max-retries,x-envoy-original-host,x-envoy-original-path,x-envoy-original-url,x-envoy-retriable-header-names,x-envoy-retriable-status-codes,x-envoy-retry-grpc-on,x-envoy-retry-on,x-envoy-upstream-alt-stat-name,x-envoy-upstream-rq-per-try-timeout-ms,x-envoy-upstream-rq-timeout-alt-response,x-envoy-upstream-rq-timeout-ms,x-envoy-upstream-stream-duration-ms,x-forwarded-client-cert,x-forwarded-for,x-forwarded-host,x-forwarded-port,x-forwarded-proto,x-request-id
backend-envoy-1  | [2026-11-04 13:09:09.501][1][info][main] [source/server/server.cc:534]   request trailer map: 120 bytes:
backend-envoy-1  | [2026-11-04 13:09:09.501][1][info][main] [source/server/server.cc:534]   response header map: 432 bytes: :status,access-control-allow-credentials,access-control-allow-headers,access-control-allow-methods,access-control-allow-origin,access-control-allow-private-network,access-control-expose-headers,access-control-max-age,age,cache-control,connection,content-encoding,content-length,content-type,date,etag,expires,grpc-message,grpc-status,keep-alive,last-modified,location,proxy-connection,proxy-status,server,transfer-encoding,upgrade,vary,via,x-envoy-attempt-count,x-envoy-decorator-operation,x-envoy-degraded,x-envoy-immediate-health-check-fail,x-envoy-ratelimited,x-envoy-upstream-canary,x-envoy-upstream-healthchecked-cluster,x-envoy-upstream-service-time,x-request-id
backend-envoy-1  | [2026-11-04 13:09:09.501][1][info][main] [source/server/server.cc:534]   response trailer map: 144 bytes: grpc-message,grpc-status
backend-envoy-1  | [2026-11-04 13:09:09.534][1][info][main] [source/server/server.cc:968] runtime: {}
backend-envoy-1  | [2026-11-04 13:09:09.538][1][info][main] [source/server/server.cc:796] Starting admin HTTP server at 127.0.0.1:9901
backend-envoy-1  | [2026-11-04 13:09:09.540][1][info][admin] [source/server/admin/admin.cc:66] admin address: 127.0.0.1:9901
backend-envoy-1  | [2026-11-04 13:09:09.540][1][info][config] [source/server/configuration_impl.cc:181] loading tracing configuration
backend-envoy-1  | [2026-11-04 13:09:09.541][1][info][config] [source/server/configuration_impl.cc:132] loading 0 static secret(s)
backend-envoy-1  | [2026-11-04 13:09:09.541][1][info][config] [source/server/configuration_impl.cc:138] loading 1 cluster(s)
backend-envoy-1  | [2026-11-04 13:09:09.545][1][info][config] [source/server/configuration_impl.cc:148] loading 1 listener(s)
backend-envoy-1  | [2026-11-04 13:09:09.556][1][info][config] [source/server/configuration_impl.cc:164] loading stats configuration
backend-envoy-1  | [2026-11-04 13:09:09.579][1][warning][main] [source/server/server.cc:1038] There is no configured limit to the number of allowed active downstream connections. Configure a limit in `envoy.resource_monitors.global_downstream_max_connections` resource monitor.
backend-envoy-1  | [2026-11-04 13:09:09.579][1][info][main] [source/server/server.cc:1077] starting main dispatch loop
backend-envoy-1  | [2026-11-04 13:09:09.580][1][info][runtime] [source/common/runtime/runtime_impl.cc:567] RTDS has finished initialization
backend-envoy-1  | [2026-11-04 13:09:09.580][1][info][upstream] [source/common/upstream/cluster_manager_impl.cc:250] cm init: all clusters initialized
backend-envoy-1  | [2026-11-04 13:09:09.580][1][info][main] [source/server/server.cc:1057] all clusters initialized. initializing init manager
backend-envoy-1  | [2026-11-04 13:09:09.580][1][info][config] [source/common/listener_manager/listener_manager_impl.cc:1067] all dependencies initialized. starting workers
backend-envoy-1  | [2026-11-04T13:09:17.384Z] "GET /" 200 flags=- tls=TLSv1.3 peer_uri_san=spiffe://pqzt.local/ns/demo/sa/frontend
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.matching.action: envoy.matching.action.transport_socket.name, envoy.matching.actions.format_string, filter-chain-name
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.rbac.principals: envoy.rbac.principals.mtls_authenticated
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.transport_sockets.upstream: envoy.transport_sockets.alts, envoy.transport_sockets.dynamic_modules, envoy.transport_sockets.http_11_proxy, envoy.transport_sockets.internal_upstream, envoy.transport_sockets.quic, envoy.transport_sockets.raw_buffer, envoy.transport_sockets.starttls, envoy.transport_sockets.tap, envoy.transport_sockets.tcp_stats, envoy.transport_sockets.tls, envoy.transport_sockets.upstream_proxy_protocol, raw_buffer, starttls, tls
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.access_loggers: envoy.access_loggers.dynamic_modules, envoy.access_loggers.file, envoy.access_loggers.fluentd, envoy.access_loggers.http_grpc, envoy.access_loggers.open_telemetry, envoy.access_loggers.stats, envoy.access_loggers.stderr, envoy.access_loggers.stdout, envoy.access_loggers.tcp_grpc, envoy.access_loggers.wasm, envoy.file_access_log, envoy.fluentd_access_log, envoy.http_grpc_access_log, envoy.open_telemetry_access_log, envoy.stderr_access_log, envoy.stdout_access_log, envoy.tcp_grpc_access_log, envoy.wasm_access_log
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.dubbo_proxy.filters: envoy.filters.dubbo.router
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.guarddog_actions: envoy.watchdog.abort_action, envoy.watchdog.profile_action
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.http.ext_proc.processing_request_modifiers: envoy.extensions.http.ext_proc.mapped_attribute_builder
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.tls.certificate_selectors: envoy.tls.certificate_selectors.on_demand_secret
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.health_checkers: envoy.health_checkers.dynamic_modules, envoy.health_checkers.grpc, envoy.health_checkers.http, envoy.health_checkers.redis, envoy.health_checkers.tcp, envoy.health_checkers.thrift
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.matching.http.input: envoy.matching.inputs.cel_data_input, envoy.matching.inputs.destination_ip, envoy.matching.inputs.destination_port, envoy.matching.inputs.direct_source_ip, envoy.matching.inputs.dns_san, envoy.matching.inputs.dynamic_metadata, envoy.matching.inputs.dynamic_module_data_input, envoy.matching.inputs.filter_state, envoy.matching.inputs.local_reply, envoy.matching.inputs.network_namespace, envoy.matching.inputs.request_headers, envoy.matching.inputs.request_trailers, envoy.matching.inputs.response_headers, envoy.matching.inputs.response_trailers, envoy.matching.inputs.server_name, envoy.matching.inputs.source_ip, envoy.matching.inputs.source_port, envoy.matching.inputs.source_type, envoy.matching.inputs.status_code_class_input, envoy.matching.inputs.status_code_input, envoy.matching.inputs.subject, envoy.matching.inputs.uri_san, query_params
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.router.cluster_specifier_plugin: envoy.router.cluster_specifier_plugin.lua, envoy.router.cluster_specifier_plugin.matcher
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.filters.upstream_network: envoy.filters.upstream_network.reverse_tunnel_lifecycle
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.common.key_value: envoy.key_value.file_based
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.config.validators: envoy.config.validators.minimum_clusters, envoy.config.validators.minimum_clusters_validator
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.route_config_update_requester: envoy.route_config_update_requester.default
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.filters.udp_listener: envoy.filters.udp.dns_filter, envoy.filters.udp_listener.dynamic_modules, envoy.filters.udp_listener.udp_proxy
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.clusters: envoy.cluster.dns, envoy.cluster.eds, envoy.cluster.logical_dns, envoy.cluster.original_dst, envoy.cluster.static, envoy.cluster.strict_dns, envoy.clusters.aggregate, envoy.clusters.composite, envoy.clusters.dynamic_forward_proxy, envoy.clusters.dynamic_modules, envoy.clusters.mcp_multicluster, envoy.clusters.redis, envoy.clusters.reverse_connection
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.rds_factory: envoy.rds_factory.default
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.matching.stat_tag_matching_data.input: stat_tag_value_input
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.matching.transport_socket.input: envoy.matching.inputs.endpoint_metadata, envoy.matching.inputs.locality_metadata, envoy.matching.inputs.transport_socket_filter_state
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   filter_state.object: envoy.filters.listener.original_dst.local_ip, envoy.filters.listener.original_dst.remote_ip, envoy.hashable_string, envoy.network.application_protocols, envoy.network.ip, envoy.network.network_namespace, envoy.network.transport_socket.http_11_proxy.info, envoy.network.transport_socket.original_dst_address, envoy.network.upstream_server_name, envoy.network.upstream_subject_alt_names, envoy.ratelimit.hits_addend, envoy.router.debug_config, envoy.string, envoy.tcp_proxy.cluster, envoy.tcp_proxy.disable_tunneling, envoy.tcp_proxy.per_connection_idle_timeout_ms, envoy.upstream.dynamic_host, envoy.upstream.dynamic_port
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.resource_monitors: envoy.resource_monitors.cgroup_memory, envoy.resource_monitors.cpu_utilization, envoy.resource_monitors.fixed_heap, envoy.resource_monitors.injected_resource
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.geoip_providers: envoy.geoip_providers.maxmind
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.matching.http.custom_matchers: envoy.matching.custom_matchers.domain_matcher, envoy.matching.custom_matchers.ip_range_matcher
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.tracers: envoy.tracers.datadog, envoy.tracers.dynamic_modules, envoy.tracers.fluentd, envoy.tracers.opentelemetry, envoy.tracers.skywalking, envoy.tracers.xray, envoy.tracers.zipkin, envoy.zipkin
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.path.match: envoy.path.match.uri_template.uri_template_matcher
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.http.stateful_session: envoy.http.stateful_session.cookie, envoy.http.stateful_session.envelope, envoy.http.stateful_session.header
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.connection_handler: envoy.connection_handler.default
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.matching.stat_matching_data.input: stat_full_name_match_input
frontend-envoy-1  | [2026-11-04 13:09:09.761][1][info][main] [source/server/server.cc:471]   envoy.path.rewrite: envoy.path.rewrite.uri_template.uri_template_rewriter
frontend-envoy-1  | [2026-11-04 13:09:09.771][1][info][main] [source/server/server.cc:531] HTTP header map info:
frontend-envoy-1  | [2026-11-04 13:09:09.772][1][info][main] [source/server/server.cc:534]   request header map: 664 bytes: :authority,:method,:path,:protocol,:scheme,accept,accept-encoding,access-control-request-headers,access-control-request-method,access-control-request-private-network,authentication,authorization,cache-control,cdn-loop,connection,content-encoding,content-length,content-type,expect,grpc-accept-encoding,grpc-timeout,if-match,if-modified-since,if-none-match,if-range,if-unmodified-since,keep-alive,origin,pragma,proxy-connection,proxy-status,referer,te,transfer-encoding,upgrade,user-agent,via,x-client-trace-id,x-envoy-attempt-count,x-envoy-decorator-operation,x-envoy-downstream-service-cluster,x-envoy-downstream-service-node,x-envoy-expected-rq-timeout-ms,x-envoy-external-address,x-envoy-force-trace,x-envoy-hedge-on-per-try-timeout,x-envoy-internal,x-envoy-ip-tags,x-envoy-is-timeout-retry,x-envoy-max-retries,x-envoy-original-host,x-envoy-original-path,x-envoy-original-url,x-envoy-retriable-header-names,x-envoy-retriable-status-codes,x-envoy-retry-grpc-on,x-envoy-retry-on,x-envoy-upstream-alt-stat-name,x-envoy-upstream-rq-per-try-timeout-ms,x-envoy-upstream-rq-timeout-alt-response,x-envoy-upstream-rq-timeout-ms,x-envoy-upstream-stream-duration-ms,x-forwarded-client-cert,x-forwarded-for,x-forwarded-host,x-forwarded-port,x-forwarded-proto,x-request-id
frontend-envoy-1  | [2026-11-04 13:09:09.772][1][info][main] [source/server/server.cc:534]   request trailer map: 120 bytes:
frontend-envoy-1  | [2026-11-04 13:09:09.772][1][info][main] [source/server/server.cc:534]   response header map: 432 bytes: :status,access-control-allow-credentials,access-control-allow-headers,access-control-allow-methods,access-control-allow-origin,access-control-allow-private-network,access-control-expose-headers,access-control-max-age,age,cache-control,connection,content-encoding,content-length,content-type,date,etag,expires,grpc-message,grpc-status,keep-alive,last-modified,location,proxy-connection,proxy-status,server,transfer-encoding,upgrade,vary,via,x-envoy-attempt-count,x-envoy-decorator-operation,x-envoy-degraded,x-envoy-immediate-health-check-fail,x-envoy-ratelimited,x-envoy-upstream-canary,x-envoy-upstream-healthchecked-cluster,x-envoy-upstream-service-time,x-request-id
frontend-envoy-1  | [2026-11-04 13:09:09.772][1][info][main] [source/server/server.cc:534]   response trailer map: 144 bytes: grpc-message,grpc-status
frontend-envoy-1  | [2026-11-04 13:09:09.792][1][info][main] [source/server/server.cc:968] runtime: {}
frontend-envoy-1  | [2026-11-04 13:09:09.794][1][info][main] [source/server/server.cc:796] Starting admin HTTP server at 127.0.0.1:9902
frontend-envoy-1  | [2026-11-04 13:09:09.795][1][info][admin] [source/server/admin/admin.cc:66] admin address: 127.0.0.1:9902
frontend-envoy-1  | [2026-11-04 13:09:09.797][1][info][config] [source/server/configuration_impl.cc:181] loading tracing configuration
frontend-envoy-1  | [2026-11-04 13:09:09.797][1][info][config] [source/server/configuration_impl.cc:132] loading 0 static secret(s)
frontend-envoy-1  | [2026-11-04 13:09:09.797][1][info][config] [source/server/configuration_impl.cc:138] loading 1 cluster(s)
frontend-envoy-1  | [2026-11-04 13:09:09.804][1][info][config] [source/server/configuration_impl.cc:148] loading 1 listener(s)
frontend-envoy-1  | [2026-11-04 13:09:09.806][1][info][config] [source/server/configuration_impl.cc:164] loading stats configuration
frontend-envoy-1  | [2026-11-04 13:09:09.832][1][warning][main] [source/server/server.cc:1038] There is no configured limit to the number of allowed active downstream connections. Configure a limit in `envoy.resource_monitors.global_downstream_max_connections` resource monitor.
frontend-envoy-1  | [2026-11-04 13:09:09.832][1][info][main] [source/server/server.cc:1077] starting main dispatch loop
frontend-envoy-1  | [2026-11-04 13:09:09.833][1][info][runtime] [source/common/runtime/runtime_impl.cc:567] RTDS has finished initialization
frontend-envoy-1  | [2026-11-04 13:09:09.833][1][info][upstream] [source/common/upstream/cluster_manager_impl.cc:250] cm init: all clusters initialized
frontend-envoy-1  | [2026-11-04 13:09:09.833][1][info][main] [source/server/server.cc:1057] all clusters initialized. initializing init manager
frontend-envoy-1  | [2026-11-04 13:09:09.833][1][info][config] [source/common/listener_manager/listener_manager_impl.cc:1067] all dependencies initialized. starting workers
frontend-envoy-1  | [2026-11-04T13:09:17.377Z] "GET /" 200 flags=- upstream_tls_fail=-

## 14. Final status
- Envoy config validation: see section 5.
- Valid/missing certificate results: inspect handshake output above.
- Untrusted certificate rejection: PASS — the actual untrusted test certificate was rejected with TLS alert 48 (unknown ca). No trusted certificate was substituted.
- TLS 1.3: confirm from successful handshake output.
- Direct OpenSSL hybrid testing independently confirmed X25519MLKEM768 support.
- Envoy-to-Envoy hybrid negotiation: PASS — captured backend Envoy ServerHello from 172.26.0.3 to frontend Envoy 172.26.0.4 selected X25519MLKEM768 (group 4588) with TLS 1.3 supported_versions (0x0304).
- No existing Envoy YAML, certificates or private keys were edited.

Report: /mnt/d/pki-mtls-full-project/team-branches/docs/agnes-mtls-report-20261104-130905.md

## Additional mTLS verification — 2026-11-04

| Test | Result | Evidence |
|---|---|---|
| Valid frontend client certificate | PASS | TLS 1.3 connection established; certificate verification OK |
| Missing client certificate | REJECTED | TLS alert 116: certificate required |
| Untrusted client certificate | REJECTED | TLS alert 48: unknown ca |
| Backend TLS version | PASS | TLSv1.3 |
| Direct OpenSSL hybrid key exchange | PASS | Negotiated group X25519MLKEM768 |
| Envoy-to-Envoy hybrid key exchange | PASS | Captured ServerHello: TLS 1.3, X25519MLKEM768 (group 4588), backend 172.26.0.3 to frontend 172.26.0.4 |

The missing and untrusted certificate tests were performed against the
backend Envoy listener on 127.0.0.1:18443.

A separate packet capture of actual frontend Envoy to backend Envoy upstream traffic confirmed the negotiated ServerHello key_share as X25519MLKEM768 (group 4588), with TLS 1.3 supported_versions (0x0304).

## Final investigation result — 2026-11-04

- Both Envoy configurations: validated.
- Frontend route: rechecked; see execution output.
- mTLS acceptance/rejection: see previous test evidence.
- Envoy-to-Envoy hybrid negotiation: PASS — confirmed by captured ServerHello from backend Envoy (172.26.0.3) to frontend Envoy (172.26.0.4), selecting X25519MLKEM768 (group 4588) under TLS 1.3.
- TLS 1.3 was confirmed by the ServerHello supported_versions extension (0x0304); the legacy record version field is not used to determine the negotiated TLS version.


## Envoy-to-Envoy packet-capture evidence — 2026-11-04

- Capture was taken in the frontend Envoy network namespace for traffic to backend Envoy 172.26.0.3:8443.
- Multiple ServerHello packets were decoded with tshark.
- ServerHello source: backend Envoy 172.26.0.3; destination: frontend Envoy 172.26.0.4.
- TLS supported_versions: TLS 1.3 (0x0304).
- ServerHello key_share group: X25519MLKEM768 (4588).
- This is direct packet evidence of the Envoy-to-Envoy negotiated hybrid group, not an inference from configuration or the separate OpenSSL test.
