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
the behavior; `behavior test` is the differential evidence. The pinned image
is `envoyproxy/envoy@sha256:57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4`
(tag `v1.39.1`, `tests/pinned-envoy-image.txt`); no row may be promoted past
`PARTIAL` until the differential evidence for that exact row lands.

Evidence note: `tests/test_envoy_differential.cc` (envoy-pr-plan.md PR 2) runs
the milestone-S bootstrap through the pinned image against a recording
upstream over loopback and writes the observed bytes as a transcript header.
It exercises no RUT or converter code path and asserts only two invariants
(`get_smoke` downstream/upstream shape, `connect_failure` downstream status);
everything else is recorded evidence for PRs 3-6, not a behavioral claim. The
transcript is produced by CI (`envoy-required` job, label `envoy;docker`,
`RESOURCE_LOCK envoy-differential`) as the `envoy-oracle-transcript` artifact;
it is committed as `tests/fixtures/envoy_oracle_milestone_s.inc` by the lead
after a CI run. The committed transcript comes from CI run `36040192963`
(`envoy-required` job, v1.39.1, recorded 2026-09-24T18:18:42Z). It is
Envoy-only evidence: no row below changes status in this PR.

Facts the transcript establishes for PRs 3-5 (each is a byte in the fixture,
not an assumption): the upstream request keeps the client's `Host` value as
the first header, lowercases every header name, removes `Connection`,
`Keep-Alive`, `Proxy-Connection` and the Connection-nominated header, keeps
`te: trailers`, keeps a client-supplied `x-forwarded-proto` value unchanged,
and appends `x-forwarded-proto: http` as the last header when absent. The
downstream response keeps the upstream header order with lowercase names,
replaces `server` in place, keeps an upstream `date` in place, appends
`date` then `server: envoy` when the upstream omitted them, uses the
canonical reason phrase (`200 Fine` becomes `200 OK`), and appends
`connection: close` last only when closing. Local replies (404 for
`OPTIONS *` and authority-form CONNECT) are `date, server, [connection:
close,] content-length: 0`; the connect failure is a 503 with
`content-length: 98, content-type: text/plain, date, server` and the body
`upstream connect error or disconnect/reset before headers. reset reason:
remote connection failure`.

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
| `TE: trailers` preserved by Envoy while every other `TE` value and hop-by-hop header is stripped (`ConnectionManagerUtility::sanitizeTEHeader`, `source/common/http/conn_manager_utility.cc`) | yes: milestone bootstrap admission does not depend on per-request `TE` | Historical (nginx-era converter, pre-`request_envoy_h1`): the emitted route stripped `TE` via the fixed `strip_headers` list (ID1), no capability gate. Current (this branch, `envoy/rut-request-envoy-h1`): `put_forward_route` (`src/envoy/converter.cc`) unconditionally emits `host: "preserve"`/`header_names: "lowercase"`/`forwarded_proto: "http"` -- i.e. ID4 `Http11PreserveHostLowercase` -- once `validate()` clears every capability gate; with all capabilities enabled (`all_capabilities_true()`, test-only) the generated route is therefore ID4, not ID1. The *shipped* CLI (`kShippedRutCapabilities`, `include/rut/envoy/converter.h`) still has `response_envoy_h1`/`local_reply_envoy_h1` false, so `validate()` fails closed with `BLOCKED_BY_RUT` at the `response_envoy_h1` check (`src/envoy/converter.cc`) before `put_forward_route` ever runs -- the real binary emits no route at all today, ID1 or ID4 | Historical (nginx-era ID1 route): for a request with a `Content-Length` body, Rut failed closed with `400 Bad Request` before upstream contact -- but not specifically for "a `TE` value with no `trailers` token" as an earlier revision of this row said; `inspect_request_policy_body`'s `has_te` computation is token-blind (`has_te |= request_policy_name_eq(hs, name_len, "te", 2)`, matching purely on the field *name*), so it rejects **every** body-carrying `TE` field for a policy that does not preserve Host, including one that already carries `trailers`. For a bodyless ID1 request, the fixed `strip_headers` list instead silently dropped `TE` entirely rather than preserving `trailers` — a mis-forward, not a fail-closed refusal. Current (ID4, this branch): `inspect_request_policy_body` admits a body-carrying `TE` field regardless of its value once the policy preserves Host (token content decides its fate later, not admission), and `apply_preserve_host_lowercase_request_policy` rewrites a field carrying a `trailers` token to the canonical lowercase `te: trailers` -- for both the bodyless-GET and fixed-Content-Length cases -- matching Envoy's `sanitizeTEHeader`/`sanitizeConnectionHeader` byte for byte. This ID4 behavior is unit/wire-tested (`tests/test_network.cc`, `request_policy` suite) but not yet exercised by the shipped CLI (see the capability-gate column) | Historical live observation on envoy/lower-increment-2 with the nginx-era ID1 policy shape: `POST /` with `Content-Length: 2` and `TE: trailers` got `HTTP/1.1 400 Bad Request`, no upstream connection attempted; a bodyless `GET /` with `TE: trailers` was forwarded to the origin with the `TE` header silently removed (`GET / HTTP/1.1\r\nHost: 127.0.0.1:9100\r\n\r\n`, no `TE` field). No live differential run yet for the current ID4 route (blocked on the shipped CLI's own gates, above) | PARTIAL |
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

**Bug (mis-forward, not fail-closed), `host: "upstream"` (ID1/ID2/ID3)
only — historical, still current for these policies:** for an origin-form
target such as `GET /admin#frag HTTP/1.1`, Envoy rejects the request. The
accepted HCM shape here cannot set `strip_fragment_from_path` (the milestone
parser does not expose that field at all) and its default is `false`
(`envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager.strip_fragment_from_path`);
with fragment stripping off, Envoy's universal header validator rejects the
`#` in the `:path` pseudo-header (`kPathHeaderCharTableWithAdditionalCharacters`
explicitly excludes `?`/`#`,
`source/extensions/http/header_validators/envoy_default/http1_header_validator.cc`),
so the request never reaches an upstream. Rut instead records the fragment
(`HttpParser::parse` sets `target_has_fragment`, `src/runtime/http_parser.cc`)
and canonicalizes the *routing* path at the `#` (`finalize_path_canonical`),
but `apply_request_policy` — the function that builds the forwarded request
line for `forward(..., request_policy: {...})` with `host: "upstream"`
(`include/rut/runtime/callbacks_impl.h`) — copies the parser's raw
`req.path` (which still includes everything after the `#`) verbatim and
never consults `target_has_fragment`, so the request is forwarded to the
upstream with the fragment intact. Live observation on
`envoy/lower-increment-2` (head `ca7f0dce`) with a `route "/" { return
forward(backend, request_policy: { host: "upstream", ... }) }` route:
`GET /admin#frag HTTP/1.1` got a real `200 OK` from the origin, and the
origin received `GET /admin#frag HTTP/1.1\r\nHost:
127.0.0.1:29011\r\n\r\n` — the fragment reached the upstream unchanged. This
remains a runtime bug in `apply_request_policy` for every `host: "upstream"`
policy (ID1/ID2/ID3) today, not something the converter can gate around
(a route emitting one of these policies is any-method/any-path by
construction, and the runtime forwards the fragment regardless of which
capabilities the converter has enabled).

**Fixed for `host: "preserve"` (ID4 `Http11PreserveHostLowercase`) on this
branch (`envoy/rut-request-envoy-h1`):** `apply_preserve_host_lowercase_
request_policy` (`include/rut/runtime/callbacks_impl.h:5934`) checks
`req.target_has_fragment` immediately after parsing and fails the whole
request closed (`400 Bad Request`, no upstream contact) rather than copying
the raw fragment-bearing path through -- the same defect described above,
fixed for exactly the policy this milestone's converter now emits
(`put_forward_route`, `src/envoy/converter.cc`, unconditionally selects ID4
once `validate()` clears every capability gate; see the `TE: trailers` row
above for why the *shipped* CLI does not reach that code path yet). This is
not byte-identical to Envoy's own rejection (Envoy's header validator
rejects the request differently, and Rut's is a generic `400`), but it is a
fail-closed refusal instead of a mis-forward, matching the behavioral class
Envoy exhibits for this shape. Unit-tested directly (`request_policy.
preserve_host_lowercase_wire_and_fail_closed_host`, `tests/test_network.cc`:
`GET /smoke#admin HTTP/1.1` via `apply_request_policy(conn, endpoint,
kPreserveHost)` returns `false` with no bytes written); no live Envoy/Rut
differential run yet for this exact ID4 shape.

Per-request divergences found in the PR #692 round-6 review (same
non-gating rule as round-2/round-3 above; verified by reading Envoy v1.39.1
source — no live Envoy/Rut differential run in this round).

| Envoy feature | parser | converter | RUT capability | behavior test | status |
| --- | --- | --- | --- | --- | --- |
| Downstream HTTP/1.0 (or HTTP/0.9) request rejected before any route/filter logic runs: `ServerConnectionImpl::checkProtocolVersion` (`source/common/http/http1/codec_impl.cc:1176-1189`) checks `codec_settings_.accept_http_10_` (`Http1Settings::accept_http_10`, `api/envoy/config/core/v3/protocol.proto:457`, proto3 `bool` — defaults `false`, and the milestone HCM's fixed 6-field allow-list has no `http_protocol_options` at all, so every model this converter can admit leaves it at that default); when false, Envoy sets `error_code_ = Http::Code::UpgradeRequired` and calls `sendProtocolError` (`codec_impl.cc:1387-1406`), which sends the client a real `426 Upgrade Required` local reply (detail `low_version`) without ever reaching `decodeHeaders`/route selection | yes: milestone bootstrap admission does not depend on per-request HTTP version | yes: the emitted route's `request_policy` already pins `version: "HTTP/1.1"` (`src/envoy/converter.cc:165`), no capability gate | no: an HTTP/1.0 request still reaches this route (Rut's listener accepts any version at the connection level) and only then does `inspect_request_policy_body` (`include/rut/runtime/callbacks_impl.h:5406-5412`) reject it — `conn.req_http_version != HttpVersion::Http11` makes it return `Invalid`, `apply_request_policy` (`callbacks_impl.h:5479-5481`) then returns `false`, and `reject_request_policy` (`callbacks_impl.h:5767-5777`) sends a generic `400 Bad Request` and closes, with no upstream contact | code reading only (`src/runtime/http_parser.cc`, `include/rut/runtime/callbacks_impl.h`); a live check against this branch would need the milestone's own emitted route text, which requires #696/#698/#699 first | PARTIAL |

**SECURITY (P1) — client-forged `x-envoy-*` internal headers are forwarded verbatim.** Found in the PR #692 round-6 review; routed to the runtime team, see docs/envoy-converter.md, "Round-6 review edge cases (PR #692)" for the fix location. **Fixed in PR #696** (ID4 `request_policy_is_stripped_client_envoy_header`, `include/rut/runtime/callbacks_impl.h`): all 15 names below plus `x-forwarded-client-cert` (round-7 review of #696) are stripped unconditionally; the row is kept for the Envoy-side evidence and now reads `PARTIAL` (see the ID4 rows further down).

| Envoy feature | parser | converter | RUT capability | behavior test | status |
| --- | --- | --- | --- | --- | --- |
| `ConnectionManagerUtility::mutateRequestHeaders` (`source/common/http/conn_manager_utility.cc:121-327`) unconditionally removes a client-supplied `x-envoy-internal` header (`request_headers.removeEnvoyInternalRequest()`, line 142) before route selection, and re-adds it only if Envoy's own address-based `internal_request` check (lines 263-265, `config.internalAddressConfig().isInternalAddress(*final_remote_address)`, gated by `allow_trusted_address_checks`, itself only ever set `true` inside `if (config.useRemoteAddress())`) says so; separately, whenever `internal_request` is false, `cleanInternalHeaders(request_headers, edge_request, ...)` (called at line 282; function body at lines 351-388) unconditionally strips `x-envoy-retriable-status-codes`, `x-envoy-retriable-header-names`, `x-envoy-retry-on`, `x-envoy-retry-grpc-on`, `x-envoy-max-retries`, `x-envoy-upstream-alt-stat-name`, `x-envoy-upstream-rq-timeout-ms`, `x-envoy-upstream-rq-per-try-timeout-ms`, `x-envoy-upstream-rq-timeout-alt-response`, `x-envoy-expected-rq-timeout-ms`, `x-envoy-force-trace`, `x-envoy-ip-tags`, `x-envoy-original-url`, `x-envoy-hedge-on-per-try-timeout` (literal names from `source/common/http/headers.h:153-208`, default `x-envoy` prefix), regardless of `edge_request`. The milestone HCM never sets (and its 6-field allow-list cannot express) `use_remote_address`, so `config.useRemoteAddress()` is always `false` for every model this converter admits, which makes `allow_trusted_address_checks` and therefore `internal_request` always `false` too — i.e. for this exact milestone config, all 15 headers above (`x-envoy-internal` plus the 14-header `cleanInternalHeaders` list) are stripped from *every* request, unconditionally, before Envoy ever forwards it upstream. (The additional `edge_request`-only strip list — `x-envoy-decorator-operation`, `x-envoy-downstream-service-cluster`, `x-envoy-downstream-service-node`, `x-envoy-original-path`, `x-envoy-original-host` — never triggers for this milestone config since `edge_request` requires `useRemoteAddress() == true`, which the parser rejects.) | yes: milestone bootstrap admission does not depend on per-request header names, and the parser's fixed HCM allow-list makes `use_remote_address` unreachable, which is exactly why the `internal_request`/`edge_request` computation above collapses to "always false" for every admitted model | yes: the emitted route's `request_policy.strip_headers` (`src/envoy/converter.cc:171`) is the fixed closed list `["Connection", "Keep-Alive", "TE", "Expect", "Upgrade", "Proxy-Connection"]` — none of the 15 `x-envoy-*` names above are in it; that closed list is only the static, request-independent part of Rut's mitigation for this row, not the whole mechanism -- the actual per-request stripping for these names is the runtime ID4 mechanism described in the next column (`request_policy_is_stripped_client_envoy_header`, #696's `apply_preserve_host_lowercase_request_policy`), not a grammar feature or a `strip_headers` entry | yes, in the runtime rather than in `strip_headers` (which is a closed literal list the converter writes once at lowering time and cannot express Envoy's address-derived `internal_request`/`edge_request` split): #696's ID4 `request_policy_is_stripped_client_envoy_header` drops every one of the 15 headers, including a client-forged `x-envoy-internal: true`, unconditionally — the "always external" collapse is exactly Envoy's own net behavior for this milestone config — and (round-7) `x-forwarded-client-cert` as well, plus (round-8) a client-supplied `x-envoy-external-address`, which a real Envoy configured this exact way would *not* strip on its own (`mutateRequestHeaders` only ever writes it, gated by `edge_request`, unreachable here) but which Rut drops anyway so a client can never forge the address a trusted hop is meant to assert, seventeen names in total | unit (`tests/test_network.cc`, `request_policy` suite: `/envoy-internal-headers*`, `/envoy-internal-only`, `/xfcc-*`) and integration (`tests/test_integration.cc`, `forward_request_policy_preserve_host_lowercase_strips_client_envoy_internal_headers`) against a `RecordingUpstream`; no pinned-Envoy differential run yet | PARTIAL |

The converter cannot fix this by adding literal names to `strip_headers`: the
list is a fixed compile-time array with no dynamic-set semantics, so it can
only ever approximate Envoy's address-derived internal/edge split, never
reproduce it. The fix therefore lives in the runtime's request-policy
application, not the converter — see docs/envoy-converter.md, "Round-6
review edge cases (PR #692)" for the design note routed to #696, where it
landed.

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

## Blocked by Rut before the milestone can reach SUPPORTED

Each row needs a runtime/language issue before the converter may emit it. The
converter fails closed on the whole configuration until then.

| Envoy behavior | RUT gap | status |
| --- | --- | --- |
| `Host` preserved unchanged on the upstream request | `request_policy.host: "preserve"` (`request_envoy_h1`, PR3) is implemented and unit/wire-tested byte for byte against the recorded Envoy oracle (`tests/fixtures/envoy_oracle_milestone_s.inc`); no pinned-Envoy differential-pair run yet (PR6), so this stays below `SUPPORTED` | PARTIAL |
| Client-supplied `x-envoy-*` internal-only request headers stripped for external requests: `ConnectionManagerUtility::mutateRequestHeaders` (`source/common/http/conn_manager_utility.cc`, v1.39.1) removes `x-envoy-internal` unconditionally (`removeEnvoyInternalRequest()`, line 142) and writes it back (lines 278-280) only when `internal_request` is `true`, which needs `allow_trusted_address_checks` — set only inside `if (config.useRemoteAddress())` (lines 163-164) — so it is always `false` under this milestone's fixed HCM shape (no `use_remote_address: true`); every request then reaches `cleanInternalHeaders` (line 282), whose unconditional block strips fourteen more `x-envoy-*` names regardless of `edge_request` (`= !internal_request && config.useRemoteAddress()`, line 275, also always `false`) | Implemented in `apply_preserve_host_lowercase_request_policy` (`request_policy_is_stripped_client_envoy_header`, `include/rut/runtime/callbacks_impl.h`): drops `x-envoy-internal` plus the fourteen headers `cleanInternalHeaders` removes unconditionally for a non-edge external request, regardless of client input — `x-envoy-retriable-status-codes`, `-retriable-header-names`, `-retry-on`, `-retry-grpc-on`, `-max-retries`, `-upstream-alt-stat-name`, `-upstream-rq-timeout-ms`, `-upstream-rq-per-try-timeout-ms`, `-upstream-rq-timeout-alt-response`, `-expected-rq-timeout-ms`, `-force-trace`, `-ip-tags`, `-original-url`, `-hedge-on-per-try-timeout` (fifteen `x-envoy-*` names; seventeen stripped names in total with `x-forwarded-client-cert` and `x-envoy-external-address`, next two rows). `cleanInternalHeaders`'s five `edge_request`-gated removals (`-decorator-operation`, `-downstream-service-cluster`, `-downstream-service-node`, `-original-path`, `-original-host`) are unreachable under this fixed `edge_request == false` shape and are left unstripped, matching Envoy's own net behavior here. Unit-tested (`tests/test_network.cc`, `request_policy` suite) and integration-tested against a `RecordingUpstream` (`tests/test_integration.cc`); no pinned-Envoy differential-pair run yet (PR6), so this stays below `SUPPORTED` | PARTIAL |
| Client-supplied `x-forwarded-client-cert` removed on the upstream request: `ConnectionManagerUtility::mutateXfccRequestHeader` (`source/common/http/conn_manager_utility.cc:324`, body at 662-686) applies the HCM's static `forward_client_cert_details`, whose proto default is `SANITIZE` ("Do not send the XFCC header to the next hop. This is the default value.", `api/envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto`; the milestone HCM allow-list cannot set the field), and `applyForwardClientCertConfig` (lines 541-545) then calls `removeForwardedClientCert()` — for `Sanitize` outright, and independently for any connection that is not mutual TLS, so it fires on this cleartext listener either way | Implemented in the same ID4 stripped set (`request_policy_is_stripped_client_envoy_header`): `x-forwarded-client-cert` is dropped unconditionally, in any casing, on every physical field, so a client-asserted certificate identity can never reach an XFCC-trusting upstream through Rut (Codex round-7 review of #696). Unit-tested (`tests/test_network.cc`, `request_policy` suite, `/xfcc-only`, `/xfcc-mixed`) and integration-tested (`tests/test_integration.cc`); no pinned-Envoy differential-pair run yet (PR6) | PARTIAL |
| Client-supplied `x-envoy-external-address` on the upstream request: this is a per-request divergence, not an Envoy-parity claim. `ConnectionManagerUtility::mutateRequestHeaders` (`source/common/http/conn_manager_utility.cc`, v1.39.1) never removes a client-supplied value for this header — `request_headers.setEnvoyExternalAddress(...)` (line 308) only ever *writes* it, gated by `edge_request` (`= !internal_request && config.useRemoteAddress()`, line 275), which needs `use_remote_address: true` and is therefore always `false` under this milestone's fixed HCM shape; `cleanInternalHeaders`'s fourteen unconditional removals (lines 368-381) do not name it, and the `internal_only_headers` route list it also consults (line 282) is empty by default and unset by this converter. A real Envoy configured exactly this way would forward a client-supplied `x-envoy-external-address` unchanged | Implemented in the same ID4 stripped set (`request_policy_is_stripped_client_envoy_header`): `x-envoy-external-address` is dropped unconditionally, in any casing, regardless of what Envoy itself would do with this exact shape — this header exists so a trusted hop can assert the client address it accepted a connection from, and letting a client forge that assertion for itself defeats its purpose independent of byte-for-byte Envoy parity (Codex round-8 review of #696). Unit-tested (`tests/test_network.cc`, `request_policy` suite, `/envoy-external-address-only`, `/envoy-external-address-mixed`); no pinned-Envoy differential-pair run yet (PR6) | PARTIAL |
| Hop-by-hop headers removed on the upstream request: `connection`, `keep-alive`, `proxy-connection`, `expect`, `upgrade`, and every header the client's `Connection` value nominates; `te` is kept only when one of its comma-separated tokens is `trailers` (stripped otherwise, rewritten to the canonical lowercase token when kept) | `request_policy.strip_headers` six-name list with `host: "preserve"` (`request_envoy_h1`, PR3); TE-trailers-token and Connection-token nomination are oracle-driven runtime behavior, not a literal strip-list entry. A `Connection` token nominating `content-length` fails the whole request closed rather than matching Envoy byte-for-byte (Envoy removes the header and forwards; Rut would desync a persistent upstream's framing if it did the same), as does a body-carrying request with `Expect` (no `100 Continue` interim-response support exists). Nominating `host`, `x-forwarded-for`, `x-forwarded-host`, `x-forwarded-proto`, or a pseudo-header-shaped token (one starting with `:`, e.g. the aliased `:authority`) also fails closed, which does match Envoy's own net behavior for these tokens (`sanitizeConnectionHeader`, `source/common/http/utility.cc`: an explicit reject naming exactly `ForwardedFor`/`ForwardedHost`/`ForwardedProto` or any token whose first byte is `:`; for `host` the header is removed and the resulting Host-less request is then rejected 400 by `ConnectionManagerImpl`'s own Host-presence check) | PARTIAL |
| A second physical occurrence of an Envoy inline (O(1)-slot) request header coalesces into the same wire value instead of forwarding two lines: `HeaderMapImpl::insertByKey`/`appendCopy` (`source/common/http/header_map_impl.cc`) place every name in `INLINE_REQ_HEADERS`/`INLINE_REQ_RESP_HEADERS` (`envoy/http/header_map.h`) and every request-side `Http::RegisterCustomInlineHeader<CustomInlineHeaderRegistry::Type::RequestHeaders>` registration (`gh search code "RegisterCustomInlineHeader" --repo envoyproxy/envoy`, e.g. `cors_filter.cc`, `cache_custom_headers.cc`, `compressor_filter.cc`) into one inline slot, comma-joining a duplicate rather than keeping a second line — for example a second `Content-Type` field | ID4 (`Http11PreserveHostLowercase`) does not replicate this coalescing (Rut has no per-request comma-join transform), so `apply_preserve_host_lowercase_request_policy` (`include/rut/runtime/callbacks_impl.h`, `request_policy_inline_request_header_index`) instead fails the whole request closed (`400`) on a second physical occurrence of any of these names, except the seven already covered by their own dedicated handling above/below (`host`, `content-length`, `te`, `connection`, `expect`, `upgrade`, `x-forwarded-proto`) and the three (`keep-alive`, `proxy-connection`, `transfer-encoding`) `drop_fixed` already strips unconditionally regardless of duplication. A non-inline header name (e.g. `x-custom`) is unaffected and still forwarded once per physical field, matching this profile's existing behavior for arbitrary headers. Unit-tested (`tests/test_network.cc`, `request_policy` suite) | PARTIAL |
| HTTP/1.1 header names emitted in lowercase on both upstream request and downstream response | request side landed with `request_envoy_h1` (PR3, `request_policy.header_names: "lowercase"`); response side is still `response_envoy_h1` | BLOCKED_BY_RUT |
| `date` added to the response only when the upstream omits it | `response_policy.date: "current"` always overwrites; `"preserve_or_current"` is part of `response_envoy_h1` | BLOCKED_BY_RUT |
| `server: envoy` overwrites the upstream `server` header | `response_policy.server` is a literal; overwrite-in-place semantics are part of `response_envoy_h1` | PARTIAL |
| `x-envoy-upstream-service-time` response header | no policy exposes a measured value; the `suppress_envoy_headers: true` shape avoids it instead (milestone-S) | BLOCKED_BY_RUT |
| `x-forwarded-proto: http` on the upstream request | `request_policy.forwarded_proto: "http"` (`request_envoy_h1`, PR3) is implemented; per the Envoy oracle (`Utility::schemeIsValid`) it keeps a client-supplied `x-forwarded-proto` unchanged in place when its trimmed value is case-insensitively exactly `http`/`https`. An empty, OWS-only, or otherwise invalid value (e.g. `http,https`, `ftp`) is overwritten in place, at that field's original physical position, with `x-forwarded-proto: http` -- matching Envoy's own inline (O(1) slot) storage for this header, which is overwritten rather than cleared and re-appended -- and `x-forwarded-proto: http` is appended as the last header only when the client sent no `x-forwarded-proto` field at all | PARTIAL |
| `x-envoy-expected-rq-timeout-ms` on the upstream request | no RUT equivalent; removed by `suppress_envoy_headers: true` (milestone-S) instead of emitted | BLOCKED_BY_RUT |
| Route timeout 15s default over the whole response, disabled entirely by `timeout: "0s"` | `timeout: "0s"` (milestone-S) removes the *default*, but Rut still enforces its own fixed 30s `kDefaultUpstreamTimeout` from upstream-connect-completion to the first response byte regardless of the route's `timeout`; a present non-zero `timeout` has no RUT surface at all. An upstream slower than 30s to produce headers gets a Rut 504 where Envoy (`timeout: "0s"`) would wait indefinitely — accepting `"0s"` is not behavioral equivalence, only a documented, bounded PARTIAL | PARTIAL |
| Cluster `connect_timeout` (positive, millisecond precision); Envoy's field is optional (proto default 5s, `(validate.rules).duration = {gt {}}`, not `required: true`) but this frontend's own parser requires it present | parsed and validated, but not enforced: Rut has no connect-establishment timeout surface at all — the fixed 30s `kDefaultUpstreamTimeout` bounds connect-completion-to-first-byte, not TCP connect (`include/rut/runtime/event_loop.h`). Since the parser already requires the field, rejecting it would make the milestone unreachable for no gain; `rut-envoy-convert` instead accepts and prints a stderr warning naming the ignored value (D2) | PARTIAL |
| Unmatched route → 404 with empty body, lowercase headers | `local_response` lowercase/date-server-length layout is part of `local_reply_envoy_h1` | BLOCKED_BY_RUT |
| Connect failure → 503 `upstream connect error ...` (Envoy's exact text), timeout → 504 `upstream request timeout` | `failure_policy` status is 502-only until `local_reply_envoy_h1`; the milestone's 503 body is provisional pending the pinned Envoy oracle (PR2) | BLOCKED_BY_RUT |
| HTTP1-only HCM rejects a client that opens with the h2c connection preface | Rut's cleartext `listen` always recognizes the preface and upgrades (`include/rut/runtime/callbacks_impl.h`, `on_header_received`); `AstListenDecl` has no protocol field to disable it. Verified live: a raw preface + `SETTINGS` frame against a plain `listen` gets an HTTP/2 `SETTINGS` reply. This is permissive, not fail-closed (PR #692 round-7 review): every milestone HCM requires `codec_type: "HTTP1"`, so gating this behind a `RutCapabilities` flag would block every conversion over a per-connection client shape, not a configuration Rut cannot express; `rut-envoy-convert` instead proceeds and prints a stderr warning after a successful conversion (`src/envoy/main.cc`, same style as the `connect_timeout` warning, D2 above). Closing the gap for real needs a listener protocol option in Rut | BLOCKED_BY_RUT |
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
  **Correction (PR #696 round-4 review):** the body-carrying gap described in
  the previous sentence was closed by that branch's own round-3 revision
  (commit `8200f648`, landed before this note was corrected) —
  `inspect_request_policy_body` and `apply_preserve_host_lowercase_request_policy`
  both now admit and canonicalize a `TE` value carrying a `trailers` token
  (comma-tokenized, not compared whole) on a fixed-Content-Length request,
  not only an exact-match bodyless one; see the matrix row above and
  `tests/test_network.cc`'s `preserve_host_lowercase_wire_and_fail_closed_host`
  for the byte-exact wire assertions.
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
- PR 2 (envoy-pr-plan.md): pinned
  `envoyproxy/envoy@sha256:57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4`
  (`v1.39.1`, `tests/pinned-envoy-image.txt`) and added the docker-gated
  oracle-recording scaffold `tests/test_envoy_differential.cc`. It runs the milestone-S
  bootstrap through the pinned image against a recording upstream and writes
  the wire bytes as `tests/fixtures/envoy_oracle_milestone_s.inc`; it does not
  exercise RUT or the converter and asserts only two invariants (see the
  evidence note above). CI runs it as the `envoy-required` job and uploads the
  transcript as an artifact; the artifact from run `36040192963` is committed
  verbatim as the fixture. No status changes in this PR.
