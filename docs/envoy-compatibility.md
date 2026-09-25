# Envoy compatibility matrix

This matrix records behavior claims for the Envoy bootstrap converter
(docs/envoy-converter.md), not syntax coverage. `SUPPORTED` requires
behavioral-equivalence evidence against the pinned Envoy image. Golden output
alone is `PARTIAL` at most.

Allowed states are `SUPPORTED`, `PARTIAL`, `BLOCKED_BY_RUT`,
`NOT_IMPLEMENTED`, and `NOT_PLANNED`.

Column meanings: `parser` is semantic-model admission with source spans and
fail-closed diagnostics (`tests/test_envoy_parser.cc`); `converter` is
deterministic RUT emission; `RUT capability` is whether the runtime can carry
the behavior; `behavior test` is the differential evidence. The pinned Envoy
image does not exist yet; no row can be promoted past `PARTIAL` until
`tests/pinned-envoy-image.txt` and the differential target land.

## Milestone: one listener, wildcard virtual host, catch-all route, one STATIC endpoint

| Envoy feature | parser | converter | RUT capability | behavior test | status |
| --- | --- | --- | --- | --- | --- |
| Bootstrap envelope: `static_resources` with exactly one listener and one cluster; proto3 JSON encoding; snake_case and lowerCamelCase field spellings; both spellings of one field rejected as a duplicate | yes: increment 1 model (`include/rut/envoy/parser.h`), every other top-level field (`admin`, `node`, `dynamic_resources`, ...) and every `static_resources.secrets` entry rejected at the key | no | n/a | none | NOT_IMPLEMENTED |
| Listener: optional `name`, one IPv4 `socket_address` with `port_value` 1..65535, one filter chain with no match and no transport socket | yes: IPv6, hostnames, `pipe`, `protocol`, `additional_addresses`, `listener_filters`, `filter_chain_match`, `transport_socket`, multiple listeners/chains rejected | no | `listen a.b.c.d:port` exists for one IPv4 listener | none | NOT_IMPLEMENTED |
| HTTP connection manager: v3 `@type`, non-empty `stat_prefix`, `codec_type: "HTTP1"` required, `generate_request_id: false` required, inline `route_config`, `http_filters` = exactly the router | yes: other network filters, other `@type`, `codec_type` omitted/`AUTO`/`HTTP2`/`HTTP3` (AUTO permits downstream h2c, out of scope), `generate_request_id` omitted or `true`, `rds`, `access_log`, `tracing`, `use_remote_address`, `server_name`, non-router HTTP filters rejected | no | see BLOCKED rows below | none | NOT_IMPLEMENTED |
| Route table: one virtual host with `domains: ["*"]`, one route `match.prefix: "/"` with `route.cluster` naming the declared cluster | yes: host lists, multiple virtual hosts/routes, `path`/`safe_regex`/headers matchers, non-`/` prefixes, `redirect`, `direct_response`, `weighted_clusters`, route `timeout`/`retry_policy`/rewrites, undeclared cluster references rejected | no | segment-aware `route "/"` catch-all exists; `unmatched` policies exist for the 404 shape | none | NOT_IMPLEMENTED |
| Cluster: `type` omitted or `STATIC`, positive `connect_timeout` with millisecond precision, `load_assignment` with required `cluster_name` matching the cluster and one locality with one IPv4 `lb_endpoints` entry | yes: `STRICT_DNS`/`LOGICAL_DNS`/`EDS`/`ORIGINAL_DST`, `lb_policy`, `health_checks`, `circuit_breakers`, `outlier_detection`, `transport_socket`, weights, `locality`, multiple localities/endpoints, sub-millisecond or zero durations, omitted or mismatched `load_assignment.cluster_name` rejected | no | `upstream x at "ip:port"` exists; `connect_timeout` has no RUT surface (fixed loop constant) | none | NOT_IMPLEMENTED |

## Blocked by Rut before the milestone can reach SUPPORTED

Each row needs a runtime/language issue before the converter may emit it. The
converter fails closed on the whole configuration until then.

| Envoy behavior | RUT gap | status |
| --- | --- | --- |
| `Host` preserved unchanged on the upstream request | `request_policy.host` offers only `"upstream"` (rewrite to the upstream address) | BLOCKED_BY_RUT |
| HTTP/1.1 header names emitted in lowercase on both upstream request and downstream response | no header-name casing selector in request/response policies | BLOCKED_BY_RUT |
| `date` added to the response only when the upstream omits it | `response_policy.date: "current"` always overwrites | BLOCKED_BY_RUT |
| `server: envoy` overwrites the upstream `server` header | `response_policy.server` is a literal; overwrite semantics need confirmation against the existing policy | PARTIAL |
| `x-envoy-upstream-service-time` response header | no policy exposes a measured value; only the `suppress_envoy_headers: true` shape can avoid it | BLOCKED_BY_RUT |
| `x-forwarded-proto: http` and `x-envoy-expected-rq-timeout-ms: 15000` on the upstream request | `set_header` with literal values exists | PARTIAL |
| Route timeout 15s over the whole response, cluster `connect_timeout` | only whole-second `response_read_timeout`; no connect timeout surface | BLOCKED_BY_RUT |
| Unmatched route → 404 with empty body | `unmatched` policies with `local_response` exist; exact Envoy bytes to be pinned | PARTIAL |
| Connect failure → 503 `upstream connect error ...`, timeout → 504 `upstream request timeout` | `failure_policy` / `timeout_failure_policy` exist; exact bytes to be pinned | PARTIAL |

## Not planned in the converter

| Envoy feature | reason |
| --- | --- |
| xDS (`dynamic_resources`, ADS, REST) | control-plane transport belongs to `rut-master` and the Istio helper, not to the converter |
| Envoy admin interface, stats names, access-log format strings | out of scope per docs/envoy-converter.md |
| Non-router HTTP filters (`lua`, `wasm`, `ext_authz`, `ratelimit`, `fault`, ...) | each is a separate capability decision; none is planned for the static converter |

## Internal evidence notes

- Increment 1 (this matrix's first revision): `rut_envoy` library with the
  bounded JSON document parser (`include/rut/envoy/json.h`, 4096 nodes, depth
  32, no comments/trailing commas/duplicate keys, escapes validated but never
  decoded, raw string bytes validated as well-formed UTF-8 per RFC 3629
  including lone-surrogate `\uXXXX` escapes) and the milestone semantic
  model. `test_envoy_parser` covers the accepted document, camelCase
  aliasing, optional fields, and 100+ rejection vectors with key-anchored
  spans. No RUT is emitted.
