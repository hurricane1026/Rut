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

The design contract's fail-closed rule is about configuration semantics: a
bootstrap that needs a RUT surface the shipped binary does not have must be
rejected at conversion time, in full, rather than partially lowered. It is not
about individual requests or responses that a correctly-converted route later
sees. When Rut's runtime safely refuses a specific request or response shape
(a fixed status, no upstream mis-forward) that Envoy would have carried, that
is a per-request divergence, not a configuration-admission gap: it is recorded
below as `PARTIAL` or `NOT_IMPLEMENTED` with the observed bytes, the same way
the nginx compatibility matrix records nginx-vs-Rut per-request differences,
and it is not gated behind a `RutCapabilities` flag that would otherwise block
every bootstrap indefinitely.

## Milestone: one listener, wildcard virtual host, catch-all route, one STATIC endpoint

| Envoy feature | parser | converter | RUT capability | behavior test | status |
| --- | --- | --- | --- | --- | --- |
| Bootstrap envelope: `static_resources` with exactly one listener and one cluster; proto3 JSON encoding; snake_case and lowerCamelCase field spellings; both spellings of one field rejected as a duplicate | yes: increment 1 model (`include/rut/envoy/parser.h`), every other top-level field (`admin`, `node`, `dynamic_resources`, ...) and every `static_resources.secrets` entry rejected at the key | yes, capability-gated (fails closed until the BLOCKED rows land) | n/a | none | NOT_IMPLEMENTED |
| Listener: optional `name`, one IPv4 `socket_address` with `port_value` 1..65535, one filter chain with no match and no transport socket | yes: IPv6, hostnames, `pipe`, `protocol`, `additional_addresses`, `listener_filters`, `filter_chain_match`, `transport_socket`, multiple listeners/chains rejected | yes, capability-gated (fails closed until the BLOCKED rows land) | `listen a.b.c.d:port` exists for one IPv4 listener; `listen :port` for the wildcard (`listen 0.0.0.0:port` does not parse) | none | NOT_IMPLEMENTED |
| HTTP connection manager: v3 `@type`, non-empty `stat_prefix`, `codec_type: "HTTP1"` required, `generate_request_id: false` required, inline `route_config`, `http_filters` = exactly the router | yes: other network filters, other `@type`, `codec_type` omitted/`AUTO`/`HTTP2`/`HTTP3` (AUTO permits downstream h2c, out of scope), `generate_request_id` omitted or `true`, `rds`, `access_log`, `tracing`, `use_remote_address`, `server_name`, non-router HTTP filters rejected | yes, capability-gated (fails closed until the BLOCKED rows land) | see BLOCKED rows below | none | NOT_IMPLEMENTED |
| Route table: one virtual host with `domains: ["*"]`, one route `match.prefix: "/"` with `route.cluster` naming the declared cluster | yes: host lists, multiple virtual hosts/routes, `path`/`safe_regex`/headers matchers, non-`/` prefixes, `redirect`, `direct_response`, `weighted_clusters`, route `retry_policy`/rewrites, undeclared cluster references rejected | yes, capability-gated (fails closed until the BLOCKED rows land) | segment-aware `route "/"` catch-all exists; `unmatched` policies exist for the 404 shape | none | NOT_IMPLEMENTED |
| Cluster: `type` omitted or `STATIC`, positive `connect_timeout` with millisecond precision, `load_assignment` with required `cluster_name` matching the cluster and one locality with one IPv4 `lb_endpoints` entry | yes: `STRICT_DNS`/`LOGICAL_DNS`/`EDS`/`ORIGINAL_DST`, `lb_policy`, `health_checks`, `circuit_breakers`, `outlier_detection`, `transport_socket`, weights, `locality`, multiple localities/endpoints, sub-millisecond or zero durations, omitted or mismatched `load_assignment.cluster_name` rejected | yes, capability-gated (fails closed until the BLOCKED rows land) | `upstream envoy_cluster_0 at "ip:port"` exists; `connect_timeout` has no connect-establishment RUT surface (accepted with a stderr warning, see "Blocked by Rut") | none | NOT_IMPLEMENTED |
| Router filter `suppress_envoy_headers: true` (v3 `Router` typed_config; also accepts `suppressEnvoyHeaders`) | yes: boolean-only, duplicate-spelling rejection, only valid inside the router's typed_config | required (milestone-S; see docs/envoy-converter.md) | removes `x-envoy-upstream-service-time` / `x-envoy-expected-rq-timeout-ms`; no separate RUT surface needed once emitted | none | NOT_IMPLEMENTED |
| Route action `timeout: "0s"` (proto3 JSON `Duration`, zero permitted) | yes: `"0s"` through `"4294967s"`, sub-millisecond and non-numeric forms rejected | required (milestone-S; a present, non-zero `timeout` is also rejected until a RUT route-timeout surface exists) | none needed for `"0s"` (removes the implicit 15s default); non-zero values are BLOCKED_BY_RUT | none | NOT_IMPLEMENTED |

Per-request divergences on the milestone's own `forward(...)` route (PR #692
round-2 review; not configuration-admission gaps, see the note above): the
converter emits these rows' route unconditionally once PR3-PR5 land, and Rut's
runtime, when it later sees the specific request or response shape below,
safely refuses it with a fixed status rather than mis-forwarding.

| Envoy feature | parser | converter | RUT capability | behavior test | status |
| --- | --- | --- | --- | --- | --- |
| Fixed-length request body larger than the 16 KiB request slice, forwarded by Envoy (no body-size cap tied to a single buffer; `Cluster.per_connection_buffer_limit_bytes` defaults to a 1 MiB soft watermark, `api/envoy/config/cluster/v3/cluster.proto`) | yes: milestone bootstrap admission does not depend on any per-request body size | yes: the emitted route forwards fixed-length bodies unconditionally, no capability gate | no: Rut fails closed with `400 Bad Request` before upstream contact (`inspect_request_policy_body` requires `content_length <= recv_buf.capacity() - header_end`, `include/rut/runtime/callbacks_impl.h:5461-5463`; `recv_buf` is one `SlicePool::kSliceSize`, 16384 bytes, `include/rut/runtime/io_backend.h:50`) | live observation on envoy/lower-increment-2 with the nginx-era policy shape: `POST /` with a 20000-byte fixed-length body (20051 bytes total) got `HTTP/1.1 400 Bad Request`, no upstream connection attempted | NOT_IMPLEMENTED |
| `Expect: 100-continue` with a body, forwarded by Envoy after it sends the interim `100 Continue` itself (`ConnectionManagerImpl::ActiveStream::decodeHeaders`, `source/common/http/conn_manager_impl.cc`) and strips `Expect` before forwarding | yes: milestone bootstrap admission does not depend on per-request `Expect` | yes: the emitted route has no interim-response surface to gate on | no: Rut fails closed with `400 Bad Request` before upstream contact (`inspect_request_policy_body` treats `Expect` on a content-length request as invalid, `include/rut/runtime/callbacks_impl.h:5451,5460`); no interim 100 response exists | live observation on envoy/lower-increment-2 with the nginx-era policy shape: `POST /` with `Content-Length: 2` and `Expect: 100-continue` got `HTTP/1.1 400 Bad Request`, no upstream connection attempted | NOT_IMPLEMENTED |
| `TE: trailers` preserved by Envoy while every other `TE` value and hop-by-hop header is stripped (`ConnectionManagerUtility::sanitizeTEHeader`, `source/common/http/conn_manager_utility.cc`) | yes: milestone bootstrap admission does not depend on per-request `TE` | yes: the emitted route strips `TE` via the fixed `strip_headers` list, no capability gate | no, but improving: for a request with a `Content-Length` body, Rut fails closed with `400 Bad Request` before upstream contact (`inspect_request_policy_body` treats `TE` on a content-length request as invalid, `include/rut/runtime/callbacks_impl.h:5450,5460`). For a bodyless request, today's fixed `strip_headers` list instead silently drops `TE` entirely rather than preserving `trailers` — a mis-forward, not a fail-closed refusal. PR #696 (`envoy/rut-request-envoy-h1`, commit `366ad196`, ID4 `Http11PreserveHostLowercase`) adds exact-value `TE: trailers` preservation for the bodyless case once `request_envoy_h1` lands, but its `apply_preserve_host_lowercase_request_policy` still calls the same `inspect_request_policy_body` gate first, so a request with a body still fails closed 400 even after #696 | live observation on envoy/lower-increment-2 with the nginx-era policy shape: `POST /` with `Content-Length: 2` and `TE: trailers` got `HTTP/1.1 400 Bad Request`, no upstream connection attempted; a bodyless `GET /` with `TE: trailers` was forwarded to the origin with the `TE` header silently removed (`GET / HTTP/1.1\r\nHost: 127.0.0.1:9100\r\n\r\n`, no `TE` field) | PARTIAL |
| Extension/unrecognized HTTP methods (e.g. `PROPFIND`) forwarded by Envoy's default hard-coded 34-method list, which includes WebDAV methods (`kValidMethods`, `source/common/http/http1/balsa_parser.cc`) | yes: milestone bootstrap admission does not depend on per-request methods | yes: the emitted route is any-method, no capability gate | no: Rut fails closed with `400 Bad Request` before any route lookup (`HttpMethod` recognizes 9 methods; an unrecognized method resolves to `ParseStatus::Error` once the request head is complete, `src/runtime/http_parser.cc:101-159,360,493-501`) | live observation on envoy/lower-increment-2 with the nginx-era policy shape: `PROPFIND / HTTP/1.1` got `HTTP/1.1 400 Bad Request` | NOT_IMPLEMENTED |
| Upstream response with 65-100 headers, forwarded by Envoy (default `HttpProtocolOptions.max_headers_count` is 100, `api/envoy/config/core/v3/protocol.proto`) | yes: milestone bootstrap admission does not depend on per-response header counts | yes: the emitted route's response_policy has no header-count knob, no capability gate | no: Rut fails closed with `502 Bad Gateway` before downstream commit (`kMaxHeaders` is a fixed 64, `include/rut/runtime/http_parser.h:46`; `build_strict_response_headers` rejects any response with `headers_truncated`, `include/rut/runtime/callbacks_impl.h:10169`, tripping the route's configured failure response) | live observation on envoy/lower-increment-2 with the nginx-era policy shape: an origin returning 90 headers plus `Content-Length: 5` got the client `HTTP/1.1 502 Bad Gateway` | NOT_IMPLEMENTED |
| Valid HTTP/1.0 upstream response with `Content-Length`, forwarded by Envoy (`accept_http_10` gates only the downstream-facing server codec, `source/common/http/http1/codec_impl.h`; the client codec's version check accepts any `HTTP/<digit>.<digit>` line) | yes: milestone bootstrap admission does not depend on the upstream's response version | yes: the emitted route's response_policy has no upstream-version knob, no capability gate | no: Rut fails closed with `502 Bad Gateway` before downstream commit (`build_strict_response_headers` requires `resp.version == HttpVersion::Http11`, `include/rut/runtime/callbacks_impl.h:10164`) | live observation on envoy/lower-increment-2 with the nginx-era policy shape: an origin answering `HTTP/1.0 200 OK` with `Content-Length: 5` got the client `HTTP/1.1 502 Bad Gateway` | NOT_IMPLEMENTED |
| Upstream response with an empty reason phrase, forwarded by Envoy (RFC 7230 §3.1.2 allows a zero-length `reason-phrase`; `BalsaParser::OnResponseFirstLineInput` does not reject it, `source/common/http/http1/balsa_parser.cc`) | yes: milestone bootstrap admission does not depend on the upstream's reason phrase | yes: the emitted route's response_policy has no reason-phrase knob, no capability gate | no: Rut fails closed with `502 Bad Gateway` before downstream commit (`build_strict_response_headers` rejects `resp.reason.len == 0`, `include/rut/runtime/callbacks_impl.h:10170`) | live observation on envoy/lower-increment-2 with the nginx-era policy shape: an origin answering `HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n` got the client `HTTP/1.1 502 Bad Gateway` | NOT_IMPLEMENTED |

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
| Route timeout 15s default over the whole response, disabled entirely by `timeout: "0s"` | `timeout: "0s"` (milestone-S) removes the *default*, but Rut still enforces its own fixed 30s `kDefaultUpstreamTimeout` from upstream-connect-completion to the first response byte regardless of the route's `timeout`; a present non-zero `timeout` has no RUT surface at all. An upstream slower than 30s to produce headers gets a Rut 504 where Envoy (`timeout: "0s"`) would wait indefinitely — accepting `"0s"` is not behavioral equivalence, only a documented, bounded PARTIAL | PARTIAL |
| Cluster `connect_timeout` (positive, millisecond precision); Envoy's field is optional (proto default 5s, `(validate.rules).duration = {gt {}}`, not `required: true`) but this frontend's own parser requires it present | parsed and validated, but not enforced: Rut has no connect-establishment timeout surface at all — the fixed 30s `kDefaultUpstreamTimeout` bounds connect-completion-to-first-byte, not TCP connect (`include/rut/runtime/event_loop.h`). Since the parser already requires the field, rejecting it would make the milestone unreachable for no gain; `rut-envoy-convert` instead accepts and prints a stderr warning naming the ignored value (D2) | PARTIAL |
| Unmatched route → 404 with empty body, lowercase headers | `local_response` lowercase/date-server-length layout is part of `local_reply_envoy_h1` | BLOCKED_BY_RUT |
| Connect failure → 503 `upstream connect error ...` (Envoy's exact text), timeout → 504 `upstream request timeout` | `failure_policy` status is 502-only until `local_reply_envoy_h1`; the milestone's 503 body is provisional pending the pinned Envoy oracle (PR2) | BLOCKED_BY_RUT |
| HTTP1-only HCM rejects a client that opens with the h2c connection preface | Rut's cleartext `listen` always recognizes the preface and upgrades (`include/rut/runtime/callbacks_impl.h`, `on_header_received`); `AstListenDecl` has no protocol field to disable it. Verified live: a raw preface + `SETTINGS` frame against a plain `listen` gets an HTTP/2 `SETTINGS` reply | BLOCKED_BY_RUT |
| `Connection`-nominated headers on the upstream request are removed dynamically (e.g. `Connection: X-Secret` also removes `X-Secret`) | `request_policy.strip_headers` is a fixed closed literal list, not dynamic parsing of the client's `Connection` value; distinct from Host preservation/casing (`request_envoy_h1`, PR3/#696) — the response direction already has the equivalent (`upstream_connection_nominates`), only the request direction is missing it | BLOCKED_BY_RUT |
| Chunked request bodies (`Transfer-Encoding: chunked`) forwarded by Envoy | Rut's `Http11FixedStrip` request-policy admission rejects any request carrying `Transfer-Encoding` with `400` before the upstream ever sees the connection (verified live); fail-closed, not mis-forwarded | BLOCKED_BY_RUT |
| Chunked or close-delimited upstream responses forwarded by Envoy | `response_policy.framing` has exactly one legal value, `content_length` (`ResponsePolicyFraming`); a non-content-length upstream response is rejected `502` before any byte reaches the client (verified live); fail-closed, not mis-forwarded | BLOCKED_BY_RUT |

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
- Increment 2 review fixes: the input buffer moved from `malloc` to a static
  1 MiB+1 buffer (AGENTS.md's no-`new`/no-`malloc` rule). The four rows added
  above (h2c preface, `Connection`-nomination, chunked request, non-CL
  response) plus the refined `connect_timeout` / route-timeout rows were each
  verified against a live `rut` process built from this tree (a minimal `.rut`
  program using the same `request_policy`/`response_policy` shapes the
  converter emits, driven with raw sockets and `curl --noproxy '*'`), not
  inferred from reading the runtime alone.
- PR #692 round-2 review (`envoy/lower-increment-2`, base
  `envoy/parser-increment-1`): the seven per-request rows added above (request
  body larger than the request slice, `Expect: 100-continue`, `TE: trailers`,
  extension methods, response header ceiling, HTTP/1.0 upstream response,
  empty reason phrase) were each verified against Envoy v1.39.1 source
  (`conn_manager_impl.cc`, `conn_manager_utility.cc`, `balsa_parser.cc`,
  `codec_impl.h`, `protocol.proto`, `cluster.proto`) and against a live `rut`
  process built from `envoy/lower-increment-2` (head `738d5e75`), driven with
  a scripted Python socket-level origin and raw sockets. That branch predates
  the request/response/local-reply serializers (#696/#698/#699), so the
  milestone's own emitted policy vocabulary does not compile there yet; the
  live checks used the nearest existing nginx-era policy shape
  (`tests/fixtures/nginx373_hide.inc`) instead of the milestone's exact text —
  see docs/envoy-converter.md, "Round-2 review edge cases (PR #692)" for the
  full citations and the stated scope of that substitution. Each is a
  per-request behavior of an already-admitted, already-converted route, not a
  configuration-admission gap, so none is gated behind a `RutCapabilities`
  flag: gating them would make the converter reject every bootstrap
  indefinitely (the flags could only flip once the runtime gained streaming
  bodies, 100-continue, a raised header ceiling, HTTP/1.0 upstream support,
  etc.), which would defeat the milestone #699/#700 verify against real
  Envoy. They are recorded as `PARTIAL`/`NOT_IMPLEMENTED` matrix rows instead,
  the same way the nginx matrix records nginx-vs-Rut per-request differences.
  `TE: trailers` is `PARTIAL` rather than `NOT_IMPLEMENTED`: PR #696
  (`envoy/rut-request-envoy-h1`, commit `366ad196`) already preserves an
  exact `TE: trailers` value for a bodyless request once `request_envoy_h1`
  lands, though a request with a `Content-Length` body still fails closed
  through the same `inspect_request_policy_body` gate even after #696 (code
  review of `366ad196` on that branch, not runnable from this branch).
