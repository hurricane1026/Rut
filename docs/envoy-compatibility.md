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
| Bootstrap envelope: `static_resources` with exactly one listener and one cluster; proto3 JSON encoding; snake_case and lowerCamelCase field spellings; both spellings of one field rejected as a duplicate | yes: increment 1 model (`include/rut/envoy/parser.h`), every other top-level field (`admin`, `node`, `dynamic_resources`, ...) and every `static_resources.secrets` entry rejected at the key | yes, capability-gated (fails closed until the BLOCKED rows land) | n/a | none | NOT_IMPLEMENTED |
| Listener: optional `name`, one IPv4 `socket_address` with `port_value` 1..65535, one filter chain with no match and no transport socket | yes: IPv6, hostnames, `pipe`, `protocol`, `additional_addresses`, `listener_filters`, `filter_chain_match`, `transport_socket`, multiple listeners/chains rejected | yes, capability-gated (fails closed until the BLOCKED rows land) | `listen a.b.c.d:port` exists for one IPv4 listener; `listen :port` for the wildcard (`listen 0.0.0.0:port` does not parse) | none | NOT_IMPLEMENTED |
| HTTP connection manager: v3 `@type`, non-empty `stat_prefix`, `codec_type: "HTTP1"` required, `generate_request_id: false` required, inline `route_config`, `http_filters` = exactly the router | yes: other network filters, other `@type`, `codec_type` omitted/`AUTO`/`HTTP2`/`HTTP3` (AUTO permits downstream h2c, out of scope), `generate_request_id` omitted or `true`, `rds`, `access_log`, `tracing`, `use_remote_address`, `server_name`, non-router HTTP filters rejected | yes, capability-gated (fails closed until the BLOCKED rows land) | see BLOCKED rows below | none | NOT_IMPLEMENTED |
| Route table: one virtual host with `domains: ["*"]`, one route `match.prefix: "/"` with `route.cluster` naming the declared cluster | yes: host lists, multiple virtual hosts/routes, `path`/`safe_regex`/headers matchers, non-`/` prefixes, `redirect`, `direct_response`, `weighted_clusters`, route `retry_policy`/rewrites, undeclared cluster references rejected | yes, capability-gated (fails closed until the BLOCKED rows land) | segment-aware `route "/"` catch-all exists; `unmatched` policies exist for the 404 shape | none | NOT_IMPLEMENTED |
| Cluster: `type` omitted or `STATIC`, positive `connect_timeout` with millisecond precision, `load_assignment` with required `cluster_name` matching the cluster and one locality with one IPv4 `lb_endpoints` entry | yes: `STRICT_DNS`/`LOGICAL_DNS`/`EDS`/`ORIGINAL_DST`, `lb_policy`, `health_checks`, `circuit_breakers`, `outlier_detection`, `transport_socket`, weights, `locality`, multiple localities/endpoints, sub-millisecond or zero durations, omitted or mismatched `load_assignment.cluster_name` rejected | yes, capability-gated (fails closed until the BLOCKED rows land) | `upstream envoy_cluster_0 at "ip:port"` exists; `connect_timeout` has no RUT surface (fixed loop constant) | none | NOT_IMPLEMENTED |
| Router filter `suppress_envoy_headers: true` (v3 `Router` typed_config; also accepts `suppressEnvoyHeaders`) | yes: boolean-only, duplicate-spelling rejection, only valid inside the router's typed_config | required (milestone-S; see docs/envoy-converter.md) | removes `x-envoy-upstream-service-time` / `x-envoy-expected-rq-timeout-ms`; no separate RUT surface needed once emitted | none | NOT_IMPLEMENTED |
| Route action `timeout: "0s"` (proto3 JSON `Duration`, zero permitted) | yes: `"0s"` through `"4294967s"`, sub-millisecond and non-numeric forms rejected | required (milestone-S; a present, non-zero `timeout` is also rejected until a RUT route-timeout surface exists) | none needed for `"0s"` (removes the implicit 15s default); non-zero values are BLOCKED_BY_RUT | none | NOT_IMPLEMENTED |

## Blocked by Rut before the milestone can reach SUPPORTED

Each row needs a runtime/language issue before the converter may emit it. The
converter fails closed on the whole configuration until then.

| Envoy behavior | RUT gap | status |
| --- | --- | --- |
| `Host` preserved unchanged on the upstream request | `request_policy.host` offers only `"upstream"` (rewrite to the upstream address); `host: "preserve"` is the `request_envoy_h1` capability | BLOCKED_BY_RUT |
| HTTP/1.1 header names emitted in lowercase on both upstream request and downstream response | no header-name casing selector in request/response policies; part of `request_envoy_h1` / `response_envoy_h1` | BLOCKED_BY_RUT |
| `date` added to the response only when the upstream omits it | `response_policy.date: "current"` always overwrites; `"preserve_or_current"` is part of `response_envoy_h1` | BLOCKED_BY_RUT |
| `server: envoy` overwrites the upstream `server` header | `response_policy.server` is a literal; overwrite-in-place semantics are part of `response_envoy_h1` | PARTIAL |
| `x-envoy-upstream-service-time` response header | no policy exposes a measured value; the `suppress_envoy_headers: true` shape avoids it instead (milestone-S) | BLOCKED_BY_RUT |
| `x-forwarded-proto: http` on the upstream request | `request_policy` and `set_header` cannot be used together; `forwarded_proto: "http"` is part of `request_envoy_h1` | BLOCKED_BY_RUT |
| `x-envoy-expected-rq-timeout-ms` on the upstream request | no RUT equivalent; removed by `suppress_envoy_headers: true` (milestone-S) instead of emitted | BLOCKED_BY_RUT |
| Route timeout 15s default over the whole response | `timeout: "0s"` (milestone-S) removes the default; a present non-zero `timeout` has no RUT surface | BLOCKED_BY_RUT |
| Cluster `connect_timeout` (positive, millisecond precision) | parsed and validated, but not enforced: Rut uses a fixed 30s `kDefaultUpstreamTimeout` per event loop with no per-upstream connect-timeout surface (D2) | PARTIAL |
| Unmatched route → 404 with empty body, lowercase headers | `local_response` lowercase/date-server-length layout is part of `local_reply_envoy_h1` | BLOCKED_BY_RUT |
| Connect failure → 503 `upstream connect error ...` (Envoy's exact text), timeout → 504 `upstream request timeout` | `failure_policy` status is 502-only until `local_reply_envoy_h1`; the milestone's 503 body is provisional pending the pinned Envoy oracle (PR2) | BLOCKED_BY_RUT |

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
- Increment 2: `rut::envoy::lower_to_rut` and the `rut-envoy-convert` CLI.
  Capability validation (`rut::envoy::RutCapabilities`) gates six
  `BLOCKED_BY_RUT` checks in a fixed order; the shipped table is all-`false`,
  so the CLI fails closed on every input, including milestone-S, until PR3-PR5
  land the request/response/local-reply capabilities. A test-only overload
  with all capabilities `true` pins the target RUT text byte for byte
  (`tests/fixtures/envoy_milestone_s.inc`, checked by
  `tests/test_envoy_convert.cc`) so the golden shape does not drift ahead of
  those PRs. No RUT is emitted by the shipped binary; no differential
  evidence exists yet.
