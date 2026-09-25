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
| Route table: one virtual host with `domains: ["*"]`, a bounded ordered route list (`kMaxEnvoyRoutes` = 8) with `route.cluster` naming a declared cluster | yes: host lists, `safe_regex`/headers matchers, route `retry_policy`/rewrites, `weighted_clusters`, undeclared cluster references, a 9th route rejected; `path`, prefix ending in `/`, `direct_response` and `redirect` are now modeled (see the increment-4 rows below), not rejected as unknown fields | yes, capability-gated (fails closed until the BLOCKED rows land); an ordered route list of any size up to `kMaxEnvoyRoutes` is lowered by construction (PR 8, see the increment-4 rows below), but every `route.cluster` action still needs the six rows below | segment-aware `route "/"` catch-all exists; `unmatched` policies exist for the 404 shape | none | NOT_IMPLEMENTED |
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

Per-request divergences found in the PR #692 round-3 review (same non-gating
rule as round-2 above). Live checks used the same nginx-era policy fixture
(`tests/fixtures/nginx373_hide.inc`) against a `rut` process built from
`envoy/lower-increment-2` (head `ec0f9df4`), `--shards 1 --no-pin`, driven
with raw sockets and a scripted Python origin.

| Envoy feature | parser | converter | RUT capability | behavior test | status |
| --- | --- | --- | --- | --- | --- |
| Request with 65-100 headers, accepted by Envoy (default `HttpProtocolOptions.max_headers_count` is 100, applied per direction, `api/envoy/config/core/v3/protocol.proto`) | yes: milestone bootstrap admission does not depend on per-request header counts | yes: the emitted route has no request-header-count knob, no capability gate | no: Rut fails closed before any route lookup (`kMaxHeaders` is a fixed 64, `include/rut/runtime/http_parser.h:46`; `HttpParser::parse` resolves to `ParseStatus::Error` once the count is exceeded) | live observation: a `GET /` with 73 header fields got the connection closed with no response bytes at all (not the `400 Bad Request` the parser header comment documents for `ParseStatus::Error` generally — confirmed the harness itself works by reproducing the documented `400 Bad Request` for round-2's `PROPFIND` case on the same fixture) | NOT_IMPLEMENTED |
| Request or response header block between 16 KiB and Envoy's default 60 KiB limit (`max_request_headers_kb` / `max_response_headers_kb`, default 60, `api/envoy/config/core/v3/protocol.proto`), accepted and forwarded by Envoy | yes: milestone bootstrap admission does not depend on per-request/response header byte size | yes: neither policy has a header-byte-size knob, no capability gate | no: Rut fails closed on both directions before the 16 KiB `SlicePool::kSliceSize` buffer (`include/rut/runtime/io_backend.h:50`) is exceeded — `on_header_received` for the request side, `on_upstream_response`'s `-ENOBUFS` path for the response side | live observation: a `GET /` with one 20000-byte request header got the connection closed with no response bytes, no upstream connection attempted; an upstream response with one 20000-byte header (request otherwise ordinary) got the upstream contacted but the client connection closed with no response bytes | NOT_IMPLEMENTED |
| Status-defined no-body responses (`204 No Content`, `304 Not Modified` with a legal `Content-Length`), forwarded by Envoy without a body (`StreamEncoderImpl::encodeHeadersBase`, `source/common/http/http1/codec_impl.cc`, suppresses the body for 204/1xx and disables chunking for 304) | yes: milestone bootstrap admission does not depend on per-response status | yes: the emitted route's response_policy has no no-body-status knob, no capability gate | no: `build_strict_response_headers` unconditionally rejects `status_code == 204 \|\| status_code == 205`, and rejects `304` unless a `StrictNoBodyMetadataSuccess` purpose is selected (`include/rut/runtime/callbacks_impl.h:10165-10168`), which this route does not request | live observation: an upstream `204 No Content` and a `304 Not Modified` (with `Content-Length: 0`) each got the upstream contacted but the client connection closed with no response bytes | NOT_IMPLEMENTED |
| Interim (1xx) responses (e.g. `103 Early Hints`) forwarded unconditionally ahead of the final response (`ConnectionManagerImpl::ActiveStream::encode1xxHeaders`, `source/common/http/conn_manager_impl.cc`, no route/filter gating) | yes: milestone bootstrap admission does not depend on per-response informational status | yes: the emitted route's response_policy has no interim-response knob, no capability gate | no: a strict `response_policy` rejects every 1xx immediately (`include/rut/runtime/callbacks_impl.h:11215-11218`, "a strict policy has no interim-response ... domain") before the final response is ever read | live observation: an upstream sending `100 Continue` followed immediately by `200 OK` got the upstream contacted but the client connection closed with no response bytes — neither the interim nor the final response reached the client | NOT_IMPLEMENTED |
| Ordinary upstream response headers Envoy has no special handling for beyond hop-by-hop stripping — e.g. `Location` on a `302 Found`, `Refresh`, `Last-Modified` — forwarded unchanged (`ConnectionManagerUtility`, `source/common/http/conn_manager_utility.cc`, only strips `connection`/`keep-alive`/`proxy-connection`/`te`(non-trailers)/`upgrade`/`transfer-encoding`-on-reframe) | yes: milestone bootstrap admission does not depend on per-response header names | yes: the emitted route explicitly requests `hide_headers: []` (hide nothing) | no: `strict_response_forbidden` unconditionally rejects `location`, `refresh`, and `last-modified` regardless of the route's `hide_headers` list (`include/rut/runtime/callbacks_impl.h:9856-9868`) — there is no policy value that admits them, so the converter cannot express this even once `response_envoy_h1` lands | live observation: an upstream `302 Found` with `Location: /login` got the upstream contacted but the client connection closed with no response bytes | NOT_IMPLEMENTED |
| Upstream failure replies differentiated by cause: Envoy maps `LocalConnectionFailure`/`RemoteConnectionFailure`/`ConnectionTimeout` to one local-reply text and `ConnectionTermination` (reset after the stream was established) to another, and protocol errors to `502` versus other resets to `503` (`source/common/router/router.cc`, `StreamResetReason` → `CoreResponseFlag` mapping) | n/a (per-request runtime behavior, not a parser concern) | yes: the emitted route has exactly one `failure_policy` for every non-timeout upstream failure, no capability gate | no, and worse than "one generic text for every cause": a genuine connect refusal fires the route's configured `failure_policy` (the exact body/status the bootstrap's failure policy specifies), but an upstream that accepts the connection, receives the request, and then resets before sending any response byte gets no local-reply text at all — see behavior test | live observation on the same nginx-era `failure_policy` (502 "Bad Gateway" HTML body): stopping the origin entirely (connect refused) got the client the exact configured `HTTP/1.1 502 Bad Gateway` body; an origin that accepted the connection, read the request, and closed without writing any bytes got the client connection closed with no response bytes at all | NOT_IMPLEMENTED |

The any-method `route "/"` also matches `CONNECT` (`route_table.h`: "method 0
in a route entry matches any request method"), which is a bug, not a
fail-closed divergence — recorded separately below rather than in the table
above because Rut does not merely refuse the request, it forwards it.

**Bug (mis-forward, not fail-closed):** `CONNECT / HTTP/1.1` against the
milestone's any-method route opens the upstream connection and relays the
origin's response back to the client. Envoy rejects this request locally
(a non-empty `:path` on a `CONNECT` request fails
`ConnectionManagerImpl::ActiveStream::decodeHeaders`'s validation,
`source/common/http/conn_manager_impl.cc`) without ever contacting an
upstream. Live observation on `envoy/lower-increment-2` (head `ec0f9df4`)
with the nginx-era policy fixture: `CONNECT / HTTP/1.1` reached the origin
(`ORIGIN RECEIVED: b'CONNECT / HTTP/1.1\r\nHost: 127.0.0.1:29000\r\n\r\n'`)
and the origin's `200 OK` body was relayed back to the client unchanged. Two
converter-level fixes were investigated and both are infeasible today: (1)
splitting the any-method route into one explicit `route <METHOD> "/"` per
forwarded method overflows the lexer's fixed `kMaxTokens = 932`
(`include/rut/compiler/lexer.h:135`) once duplicated across all 7 non-HEAD
forwarded methods (confirmed by compiling that shape with `rut`); (2) a
`guard req.method == GET \|\| … else { return 400 }` inside the existing
any-method route stays within the token budget, but `CONNECT` and `TRACE`
are both plain identifiers with no `req.method == <KW>` expression form and
no `route <METHOD> "/"` declaration spelling of their own (confirmed live:
`route TRACE "/"` and `pre_route TRACE { return forward(...) }` are both
parse errors — `pre_route`/`unmatched` bodies are fixed-shape local-response
policies only), so a guard that excludes `CONNECT` is indistinguishable from
one that also excludes `TRACE`, and Envoy forwards `TRACE` like any other
method. This needs either a runtime capability (an expression-level `CONNECT`
literal, a per-route method exclusion list, or a higher token budget) before
the converter can prevent it without trading the `CONNECT` mis-forward for a
new `TRACE` divergence.

Found in the PR #692 round-4 review, same class of bug as the `CONNECT` one
above (Rut forwards where Envoy fails closed, recorded separately from the
per-request divergence tables because Rut does not merely refuse the
request): a request target containing a `#` fragment.

**Bug (mis-forward, not fail-closed):** for an origin-form target such as
`GET /admin#frag HTTP/1.1`, Envoy rejects the request. The accepted HCM shape
here cannot set `strip_fragment_from_path` (the milestone parser does not
expose that field at all) and its default is `false`
(`envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager.strip_fragment_from_path`);
with fragment stripping off, Envoy's universal header validator rejects the
`#` in the `:path` pseudo-header (`kPathHeaderCharTableWithAdditionalCharacters`
explicitly excludes `?`/`#`,
`source/extensions/http/header_validators/envoy_default/http1_header_validator.cc`),
so the request never reaches an upstream. Rut instead records the fragment
(`HttpParser::parse` sets `target_has_fragment`, `src/runtime/http_parser.cc`)
and canonicalizes the *routing* path at the `#` (`finalize_path_canonical`),
but `apply_request_policy` — the function that builds the forwarded request
line for `forward(..., request_policy: {...})`
(`include/rut/runtime/callbacks_impl.h`) — copies the parser's raw
`req.path` (which still includes everything after the `#`) verbatim and
never consults `target_has_fragment`, so the request is forwarded to the
upstream with the fragment intact. Live observation on
`envoy/lower-increment-2` (head `ca7f0dce`) with a `route "/" { return
forward(backend, request_policy: { host: "upstream", ... }) }` route (the
currently-shipped `host: "upstream"` request policy exercises the same
`apply_request_policy` path the milestone's future `host: "preserve"` will
use once `request_envoy_h1` lands — the fragment handling is identical
either way): `GET /admin#frag HTTP/1.1` got a real `200 OK` from the origin,
and the origin received `GET /admin#frag HTTP/1.1\r\nHost:
127.0.0.1:29011\r\n\r\n` — the fragment reached the upstream unchanged. This
is a runtime bug in `apply_request_policy`, not something the converter can
gate around (the milestone route is any-method/any-path by construction, and
the runtime forwards the fragment regardless of which capabilities the
converter has enabled), so it needs a fix in
`include/rut/runtime/callbacks_impl.h` — reject a fragment-bearing target in
`apply_request_policy` the way `inspect_request_policy_body` already rejects
other malformed shapes — before this milestone's `request_envoy_h1` capability
can claim behavioral equivalence for this request shape.

Per-request divergences found in the PR #692 round-6 review (same
non-gating rule as round-2/round-3 above; verified by reading Envoy v1.39.1
source — no live Envoy/Rut differential run in this round).

| Envoy feature | parser | converter | RUT capability | behavior test | status |
| --- | --- | --- | --- | --- | --- |
| Downstream HTTP/1.0 (or HTTP/0.9) request rejected before any route/filter logic runs: `ServerConnectionImpl::checkProtocolVersion` (`source/common/http/http1/codec_impl.cc:1176-1189`) checks `codec_settings_.accept_http_10_` (`Http1Settings::accept_http_10`, `api/envoy/config/core/v3/protocol.proto:457`, proto3 `bool` — defaults `false`, and the milestone HCM's fixed 6-field allow-list has no `http_protocol_options` at all, so every model this converter can admit leaves it at that default); when false, Envoy sets `error_code_ = Http::Code::UpgradeRequired` and calls `sendProtocolError` (`codec_impl.cc:1387-1406`), which sends the client a real `426 Upgrade Required` local reply (detail `low_version`) without ever reaching `decodeHeaders`/route selection | yes: milestone bootstrap admission does not depend on per-request HTTP version | yes: the emitted route's `request_policy` already pins `version: "HTTP/1.1"` (`src/envoy/converter.cc:165`), no capability gate | no: an HTTP/1.0 request still reaches this route (Rut's listener accepts any version at the connection level) and only then does `inspect_request_policy_body` (`include/rut/runtime/callbacks_impl.h:5406-5412`) reject it — `conn.req_http_version != HttpVersion::Http11` makes it return `Invalid`, `apply_request_policy` (`callbacks_impl.h:5479-5481`) then returns `false`, and `reject_request_policy` (`callbacks_impl.h:5767-5777`) sends a generic `400 Bad Request` and closes, with no upstream contact | code reading only (`src/runtime/http_parser.cc`, `include/rut/runtime/callbacks_impl.h`); a live check against this branch would need the milestone's own emitted route text, which requires #696/#698/#699 first | PARTIAL |

**SECURITY (P1) — client-forged `x-envoy-*` internal headers are forwarded verbatim.** Found in the PR #692 round-6 review; routed to the runtime team, see docs/envoy-converter.md, "Round-6 review edge cases (PR #692)" for the fix location.

| Envoy feature | parser | converter | RUT capability | behavior test | status |
| --- | --- | --- | --- | --- | --- |
| `ConnectionManagerUtility::mutateRequestHeaders` (`source/common/http/conn_manager_utility.cc:121-327`) unconditionally removes a client-supplied `x-envoy-internal` header (`request_headers.removeEnvoyInternalRequest()`, line 142) before route selection, and re-adds it only if Envoy's own address-based `internal_request` check (lines 263-265, `config.internalAddressConfig().isInternalAddress(*final_remote_address)`, gated by `allow_trusted_address_checks`, itself only ever set `true` inside `if (config.useRemoteAddress())`) says so; separately, whenever `internal_request` is false, `cleanInternalHeaders(request_headers, edge_request, ...)` (called at line 282; function body at lines 351-388) unconditionally strips `x-envoy-retriable-status-codes`, `x-envoy-retriable-header-names`, `x-envoy-retry-on`, `x-envoy-retry-grpc-on`, `x-envoy-max-retries`, `x-envoy-upstream-alt-stat-name`, `x-envoy-upstream-rq-timeout-ms`, `x-envoy-upstream-rq-per-try-timeout-ms`, `x-envoy-upstream-rq-timeout-alt-response`, `x-envoy-expected-rq-timeout-ms`, `x-envoy-force-trace`, `x-envoy-ip-tags`, `x-envoy-original-url`, `x-envoy-hedge-on-per-try-timeout` (literal names from `source/common/http/headers.h:153-208`, default `x-envoy` prefix), regardless of `edge_request`. The milestone HCM never sets (and its 6-field allow-list cannot express) `use_remote_address`, so `config.useRemoteAddress()` is always `false` for every model this converter admits, which makes `allow_trusted_address_checks` and therefore `internal_request` always `false` too — i.e. for this exact milestone config, all 15 headers above (`x-envoy-internal` plus the 14-header `cleanInternalHeaders` list) are stripped from *every* request, unconditionally, before Envoy ever forwards it upstream. (The additional `edge_request`-only strip list — `x-envoy-decorator-operation`, `x-envoy-downstream-service-cluster`, `x-envoy-downstream-service-node`, `x-envoy-original-path`, `x-envoy-original-host` — never triggers for this milestone config since `edge_request` requires `useRemoteAddress() == true`, which the parser rejects.) | yes: milestone bootstrap admission does not depend on per-request header names, and the parser's fixed HCM allow-list makes `use_remote_address` unreachable, which is exactly why the `internal_request`/`edge_request` computation above collapses to "always false" for every admitted model | yes: the emitted route's `request_policy.strip_headers` (`src/envoy/converter.cc:171`) is the fixed closed list `["Connection", "Keep-Alive", "TE", "Expect", "Upgrade", "Proxy-Connection"]` — none of the 15 `x-envoy-*` names above are in it, and no other stripping mechanism exists in the grammar or in #696's `apply_preserve_host_lowercase_request_policy` (Host preservation + header-name lowercasing + the same fixed hop-by-hop list only) | no: `strip_headers` is a closed literal list the converter writes once at lowering time, so it cannot express Envoy's dynamic, address-derived `internal_request`/`edge_request` split even in principle — every one of the 15 headers, including a client-forged `x-envoy-internal: true`, reaches the upstream cluster unchanged when a client sends it, which Envoy would never do for this exact milestone config | code reading only (`source/common/http/conn_manager_utility.cc`, `source/common/http/headers.h`); no live differential exists yet (needs #696-#699) | BLOCKED_BY_RUT |

The converter cannot fix this by adding literal names to `strip_headers`: the
list is a fixed compile-time array with no dynamic-set semantics, so it can
only ever approximate Envoy's address-derived internal/edge split, never
reproduce it. A correct fix belongs in the runtime's request-policy
application, not the converter — see docs/envoy-converter.md, "Round-6
review edge cases (PR #692)" for the design note routed to #696.

Per-request divergence found in the PR #692 round-8 review (same non-gating
rule as round-2/round-3/round-6 above): a request-target shape the milestone
route's parser accepts but Envoy's HTTP/1 codec never lets reach routing.

| Envoy feature | parser | converter | RUT capability | behavior test | status |
| --- | --- | --- | --- | --- | --- |
| Absolute-form request target (e.g. `GET http://example.com/ HTTP/1.1`); a plain cleartext HCM listener (no explicit proxy-protocol/CONNECT configuration, which this milestone's fixed 6-field HCM allow-list cannot express in the first place) never accepts absolute-form, so Envoy's HTTP/1 codec rejects the request with `400` before route selection ever runs (docs/envoy-converter.md, "Routing": "Envoy's HTTP/1 codec rejects `CONNECT` and absolute-form targets in specific ways") | yes: milestone bootstrap admission does not depend on per-request target form | yes: the emitted route/`unmatched` policy has no request-target-form knob, no capability gate | no: Rut's parser accepts the request line but leaves the canonical routing path null for an absolute-form target, so the generated `route "/"` catch-all misses and the `unmatched` policy (`put_unmatched`, `src/envoy/converter.cc:118`) answers with the fixed no-route `404`, not Envoy's pre-routing `400` | code reading only (`src/envoy/converter.cc`, `include/rut/runtime/http_parser.h`); no live differential exists yet — filed as a runtime issue to add pre-route absolute-form rejection | PARTIAL |

## Operational note: `--metrics` shadows a converted `/metrics` route

Found in the PR #692 round-4 review. This is a CLI-launch-mode interaction,
not a per-request divergence or a converter gap, so it is recorded here as a
matrix row rather than blocking conversion.

`rut`'s `--metrics` flag (`src/main.cc`) is opt-in and documented at the CLI
level already: "this RESERVES the /metrics path — GET /metrics (and
/metrics/, /metrics?…) is served by the built-in endpoint ahead of route
matching, shadowing any user route on that path" (`src/main.cc`, the
`--metrics` usage comment; enforced in
`include/rut/runtime/callbacks_impl.h`, the `RESERVED PATH` block that
intercepts `GET /metrics` "ahead of route matching, works even with no
RouteConfig"). The milestone's converted program is an any-method,
any-path catch-all (`route "/" { return forward(...) }`), so a client
`GET /metrics` against a `rut` process launched with `--metrics` gets the
built-in Prometheus exposition instead of being forwarded to the Envoy
bootstrap's declared cluster, which is what the source Envoy configuration
would have done (Envoy has no such reserved path).

| Envoy behavior | RUT gap | status |
| --- | --- | --- |
| `GET /metrics` forwarded to the declared cluster like any other path (Envoy reserves no `/metrics` path of its own) | `rut --metrics` intercepts `GET /metrics` (and `/metrics/`, `/metrics?…`) ahead of route matching for every loaded program, converted or hand-written; this is an operator launch-mode choice, not something the generated RUT source controls or the converter can gate — only present when the operator opts into `--metrics` on this specific data listener | PARTIAL (opt-in CLI flag only; the converted program itself is unaffected without `--metrics`) |

## Increment 4: route matching, multiple routes and clusters, `direct_response`, `redirect`

These rows widen the parser's semantic model (`include/rut/envoy/parser.h`,
`RouteMatchKind`, `RouteActionKind`) beyond the single-route, single-cluster
milestone above. PR 8 lowers the ordered-route-list shapes (`path`, prefix
ending in `/`, multiple routes, multiple clusters) by construction (owner
decision D3): `rut::envoy::lower_to_rut` builds, for each declared node, a
nested `if`/`else` chain reproducing Envoy's first-match order restricted to
that node (see the algorithm doc comment in `src/envoy/converter.cc` and
docs/envoy-converter.md's "Routing" section) instead of rejecting the shape.
`direct_response` and `redirect` are still rejected with their own
`UnsupportedSyntax` diagnostic (`"direct_response is not lowered yet"`,
`"redirect is not lowered yet"`), checked before the six capability rows
above, same as before.

| Envoy feature | parser | converter | RUT capability | behavior test | status |
| --- | --- | --- | --- | --- | --- |
| `match.path` exact match (bytes 0x21-0x7e excluding `?`/`#`/`%`, max 64 bytes) | yes: modeled as `RouteMatchKind::Path`; both `prefix` and `path` on one match, a `path` not starting with `/`, and reserved/oversized bytes rejected | yes: an exact `path` becomes a conditional `req.pathOnly == "..."` arm in its owning node's chain; when its literal text equals a node's own text and no other Envoy route ever resolves the node's literal, lowering fails closed instead of emitting a `route exact "N"` fallback (see the row below) | Rut's `req.pathOnly` comparisons cover the conditional-arm case once the six capability rows above are met; golden (c)/(f) and the brute-force equivalence tests cover it | none | PARTIAL (golden + equivalence test; pair evidence pending) |
| `match.prefix` ending in `/` (e.g. `"/api/"`), in addition to the catch-all `"/"` | yes: modeled as `RouteMatchKind::Prefix`; validated as `"/"` or starting and ending with `/` | yes: each distinct prefix becomes its own RUT node (`route "N"` / `route HEAD "N"`); golden (a)/(b)/(f) cover declaration-order variants | same as `match.path` above | none | PARTIAL (golden + equivalence test; pair evidence pending) |
| A node's own literal path with no earlier exact `path` route resolving it (e.g. `prefix: "/api/"` alone, or preceded only by an exact route under a *different* literal): Envoy's no-route 404 for that one literal path | yes: same modeling as the two rows above | no: `route exact "N"`'s strict local-response admission serves only GET/HEAD/POST/OPTIONS/PUT/DELETE/PATCH (`callbacks_impl.h`), so an ANY-method `route exact "N"` 404 would close the connection instead of answering TRACE/CONNECT the way Envoy's real 404 does; lowering fails closed with `"BLOCKED_BY_RUT: a no-route 404 for this node's own literal path has no RUT form that serves every method Envoy would 404"` (Codex P1 on PR #695) | none until an all-method `local_response` surface exists | none | BLOCKED_BY_RUT |
| A `prefix` segment beginning with `:` (e.g. `"/:tenant/"`) | yes: `:` is not a reserved byte, so the parser admits it like any other printable-ASCII byte | rejects: a `prefix` match's text becomes a generated RUT route declaration, and a segment starting with `:` there is a route parameter (`include/rut/runtime/route_trie.h`), so `route "/:tenant"` would capture and forward `/anything/x`, which Envoy's literal byte match never does; rejected with `"route match segments beginning with \":\" would become a RUT route parameter, not a literal match; not lowered"`. An exact `path` match (e.g. `"/:tenant"`) is never emitted as a route declaration — only ever compared as the string literal `req.pathOnly == "/:tenant"` — so it carries no such risk and is not rejected for containing `:` (Codex P1 on PR #695, then narrowed to `prefix`-only on round 3) | n/a | none | BLOCKED_BY_RUT (`prefix` only) |
| Raw (non-segment) `prefix` not ending in `/` (e.g. `"/api"`) | no: rejected at the field with `"only \"/\" or prefixes ending in \"/\" are supported"` | n/a (never reaches the converter) | Rut's route trie is segment-aware; a plain string prefix like Envoy's has no equivalent match today | none | BLOCKED_BY_RUT |
| Multiple routes per virtual host, in list order (`kMaxEnvoyRoutes` = 8, a 9th rejected at its span) | yes: `VirtualHost::routes` is a bounded `FixedVec`, order preserved from the source array; no shadowing check here (owner decision D3, PR 8 lowers an ordered list correctly by construction) | yes: lowered by construction (see "Routing" above); a two-route bootstrap still fails closed on the same capability rows the single-route milestone hits until PR3-PR5 land | first-match semantics reproduced per node; goldens (a)/(b)/(c)/(f) and the brute-force equivalence tests (~40 + 10 probe paths) cover shadowing, ancestor resolution and dead-arm pruning | none | PARTIAL (golden + equivalence test; pair evidence pending) |
| Multiple STATIC clusters (`kMaxEnvoyClusters` = 8, a 9th rejected at its span; duplicate names rejected) | yes: `Bootstrap::clusters` is a bounded `FixedVec`; every Forward route's `cluster` must name a declared entry; a duplicate name is rejected at the second declaration's span | yes: every cluster is emitted as `upstream envoy_cluster_<i> at "..."` in declaration order, independent of which routes reference it; a hand-built `Bootstrap` with a duplicate cluster name (bypassing the parser) is rejected defensively too, since `cluster_index_of` would otherwise silently resolve every same-named reference to the first match (Codex P2 on PR #695) | n/a | none | PARTIAL (golden + equivalence test; pair evidence pending) |
| `direct_response.status` + optional `body.inline_string` (≤ 4096 bytes) | yes: modeled as `RouteActionKind::DirectResponse`; other `DataSource` variants (`inline_bytes`, `filename`, ...) rejected as unsupported fields | rejects with `"direct_response is not lowered yet"` at the action's span | Envoy-layout `local_response` for an arbitrary status/body has no RUT emission yet (see PR 9) | none | NOT_IMPLEMENTED |
| `redirect.path_redirect` / `host_redirect` / `response_code` (closed to `MOVED_PERMANENTLY`/`FOUND`/`SEE_OTHER`/`TEMPORARY_REDIRECT`/`PERMANENT_REDIRECT`) | yes: modeled as `RouteActionKind::Redirect`; every other `RedirectAction` field (`https_redirect`, `scheme_redirect`, `port_redirect`, `prefix_rewrite`, `strip_query`, ...) rejected as unsupported | rejects with `"redirect is not lowered yet"` at the action's span | no `redirect(...)` RUT construct exists yet (see PR 10) | none | NOT_IMPLEMENTED |
| Path normalization: `merge_slashes`, percent-decoding, and Rut route-trie segment normalization (`"/api/"` / `"/api//v1"` collapse the same as `"/api"` / `"/api/v1"`) vs. Envoy's literal (unnormalized) string-prefix matching | not modeled: `merge_slashes` is not a recognized field; a configured `prefix` containing an internal `"//"` (the directly-detectable case: two declared prefixes that would collapse to the same node text, e.g. `"/api//v1/"` and `"/api/v1/"`) is rejected at `validate()` with `"route match prefix contains \"//\", which Rut's route trie collapses; not lowered"` (Codex P1 on PR #695 round 3) | n/a | Rut's trie normalizes empty path segments when selecting a node; PR 8's `req.pathOnly` arm comparisons do not; neither matches Envoy's default (no normalization) exactly. This remains a real divergence even with no `"//"` in any declared text: a request whose raw path contains an injected empty segment (e.g. `/api//v1/x`) can reach a declared node (e.g. `"/api/v1"`) and forward through its terminal prefix arm even though Envoy's literal prefix comparison would 404 it — confirmed NOT_IMPLEMENTED, not fixed by the `validate()` check above (which only catches the configured text itself, not every request that could alias into a node through collapsing) | none | NOT_IMPLEMENTED |

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
| HTTP1-only HCM rejects a client that opens with the h2c connection preface | Rut's cleartext `listen` always recognizes the preface and upgrades (`include/rut/runtime/callbacks_impl.h`, `on_header_received`); `AstListenDecl` has no protocol field to disable it. Verified live: a raw preface + `SETTINGS` frame against a plain `listen` gets an HTTP/2 `SETTINGS` reply. This is permissive, not fail-closed (PR #692 round-7 review): every milestone HCM requires `codec_type: "HTTP1"`, so gating this behind a `RutCapabilities` flag would block every conversion over a per-connection client shape, not a configuration Rut cannot express; `rut-envoy-convert` instead proceeds and prints a stderr warning after a successful conversion (`src/envoy/main.cc`, same style as the `connect_timeout` warning, D2 above). Closing the gap for real needs a listener protocol option in Rut | BLOCKED_BY_RUT |
| `Connection`-nominated headers on the upstream request are removed dynamically (e.g. `Connection: X-Secret` also removes `X-Secret`) | `request_policy.strip_headers` (`src/envoy/converter.cc:171`) is only the *fixed* part of the request-side H1 profile — the literal hop-by-hop list. Dynamic per-request `Connection`-nomination removal is implemented as part of the same `request_envoy_h1` capability's runtime behavior, not a separate feature: PR #696's ID4 `Http11PreserveHostLowercase` (`apply_preserve_host_lowercase_request_policy`, `include/rut/runtime/callbacks_impl.h` on `origin/envoy/rut-request-envoy-h1`) parses the client's `Connection` value and drops every field it nominates (`name_nominated`/`drop_nominated`), matching the response direction's existing `upstream_connection_nominates`. So this row resolves alongside Host preservation/casing once #696 lands under the converter's existing `request_envoy_h1` gate; it is not a distinct gap needing its own `RutCapabilities` flag | BLOCKED_BY_RUT |
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
- PR #692 round-3 review (`envoy/lower-increment-2`, base
  `envoy/parser-increment-1`): the six per-request rows added above (request
  header ceiling, request/response header byte size, status-defined no-body
  responses, interim 1xx responses, ordinary-but-forbidden response headers,
  and undifferentiated failure replies) were each verified against Envoy
  v1.39.1 source (`http1/codec_impl.cc`, `conn_manager_impl.cc`,
  `conn_manager_utility.cc`, `router/router.cc`, `protocol.proto`) and against
  a live `rut` process built from `envoy/lower-increment-2` (head `ec0f9df4`),
  `--shards 1 --no-pin`, driven with raw sockets and a scripted Python
  socket-level origin. Same substitution as round-2: this branch predates
  the request/response/local-reply serializers, so the live checks used the
  nginx-era policy fixture (`tests/fixtures/nginx373_hide.inc`) instead of
  the milestone's exact emitted text — see docs/envoy-converter.md, "Round-3
  review edge cases (PR #692)". None of the six is gated behind a
  `RutCapabilities` flag, for the same reason as round-2. A seventh finding —
  `CONNECT` matching the any-method route — is a mis-forward, not a
  fail-closed refusal, and is recorded separately above (not as a numbered
  table row) with the two converter-level fixes that were tried and found
  infeasible within the lexer's token budget and the language's expression
  grammar.
- Increment 4 lowering (PR 8): `rut::envoy::lower_to_rut` now accepts an
  ordered route list of any size up to `kMaxEnvoyRoutes` and multiple
  clusters, lowering them by construction (owner decision D3) instead of
  rejecting the shape; `direct_response` and `redirect` are still rejected.
  Five goldens (`tests/fixtures/envoy_routes_<letter>.inc`, all capabilities
  `true`) pin declaration-order variants byte for byte, and a brute-force
  test compares Envoy's real first-match semantics against an independent
  reimplementation of the "longest node, then arm chain" structure over ~40
  probe paths. The lex/parse/analyze/MIR/RIR round-trip these goldens will
  eventually need is deferred to PR3-PR5 (see the TODO in
  `tests/test_envoy_convert.cc`): today's parser does not yet accept the
  `local_response` fields the goldens use, and the single-route milestone-S
  golden already fails the same way, so this is not a PR8 regression. No
  differential evidence exists yet.
- PR 8 review fixes (Codex on PR #695): (1) a node's own literal path with no
  earlier exact arm covering it now fails closed instead of emitting a
  `route exact "N"` 404 whose strict local-response admission cannot serve
  every method Envoy's real 404 would (TRACE/CONNECT closed the connection);
  goldens (d) and (e) were exactly this shape and are now
  `blocked_on_node_own_literal_needs_all_method_fallback` /
  `blocked_on_shadowed_exact_needs_all_method_fallback`, and a new golden (f)
  covers the case that IS still lowered (an earlier exact arm for the same
  literal). (2) a `prefix` / `path` segment beginning with `:` is rejected
  rather than silently becoming a RUT route parameter. (3) the defensive
  `validate()` path for a hand-built `Bootstrap` now revalidates every route
  match's prefix/path shape (catching an integer underflow in
  `strip_trailing_slash` on an empty prefix) and rejects a duplicate cluster
  name the same way the JSON parser does. Verified against Envoy v1.39.1's
  `source/common/router/config_impl.cc` route-matching semantics and this
  tree's `route_trie.h` / `callbacks_impl.h`, not inferred from the PR
  description alone.
