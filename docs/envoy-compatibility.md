# Envoy compatibility matrix

The configuration helper is independently buildable in `helpers/envoy/`.
Rut accepts `.rut` programs only; all wire behavior is implemented by typed
language policies and runtime code, never by the helper. The request, response,
and local-reply surfaces and pair harness are now integrated with ordered
routes and enum syntax. Historical pair evidence below remains scoped to its
recorded cases; integration does not imply full Envoy compatibility.

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
| Bootstrap envelope: `static_resources` with exactly one listener and a bounded list of `STATIC` clusters (`kMaxEnvoyClusters` = 8; increment 4 / PR 8 widens this from the increment-1 single-cluster baseline, see the Cluster row below); proto3 JSON encoding; snake_case and lowerCamelCase field spellings; both spellings of one field rejected as a duplicate | yes: increment 1 model (`helpers/envoy/include/rut/envoy/parser.h`), every other top-level field (`admin`, `node`, `dynamic_resources`, ...) and every `static_resources.secrets` entry rejected at the key | yes: emitted by the standalone helper using implemented Rut policy syntax | n/a | milestone pair evidence only; broader configurations remain unverified | PARTIAL |
| Listener: optional `name`, one IPv4 `socket_address` with `port_value` 1..65535, one filter chain with no match and no transport socket | yes: IPv6, hostnames, `pipe`, `protocol`, `additional_addresses`, `listener_filters`, `filter_chain_match`, `transport_socket`, multiple listeners/chains rejected | yes: emitted by the standalone helper using implemented Rut policy syntax | `listen a.b.c.d:port` exists for one IPv4 listener; `listen :port` for the wildcard (`listen 0.0.0.0:port` does not parse) | milestone pair evidence only; broader configurations remain unverified | PARTIAL |
| HTTP connection manager: v3 `@type`, non-empty `stat_prefix`, `codec_type: "HTTP1"` required, `generate_request_id: false` required, inline `route_config`, `http_filters` = exactly the router | yes: other network filters, other `@type`, `codec_type` omitted/`AUTO`/`HTTP2`/`HTTP3` (AUTO permits downstream h2c, out of scope), `generate_request_id` omitted or `true`, `rds`, `access_log`, `tracing`, `use_remote_address`, `server_name`, non-router HTTP filters rejected | yes: emitted by the standalone helper using implemented Rut policy syntax | typed request/response/local-reply policies are implemented; remaining gaps below | milestone pair evidence only; broader configurations remain unverified | PARTIAL |
| Route table: one virtual host with `domains: ["*"]`, a bounded ordered route list (`kMaxEnvoyRoutes` = 8) with `route.cluster` naming a declared cluster | yes: host lists, `safe_regex`/headers matchers, route `retry_policy`/rewrites, `weighted_clusters`, undeclared cluster references, a 9th route rejected; `path`, prefix ending in `/`, `direct_response` and `redirect` are now modeled (see the increment-4 rows below), not rejected as unknown fields | yes: emitted by the standalone helper using implemented Rut policy syntax; an ordered route list up to `kMaxEnvoyRoutes` is lowered by construction (PR 8, see the increment-4 rows below), but every `route.cluster` action uses the implemented request/response/failure policy fields. "Any size up to `kMaxEnvoyRoutes`" is the admission rule, not a usable capacity claim: the emitted program is also bounded by the RUT compiler frontend's lexer token budget (`LexedTokens::kMaxTokens`, `include/rut/compiler/lexer.h` -- 4096 today, raised from 932 by #697), which a route list well inside `kMaxEnvoyRoutes` can still exceed at `kMaxEnvoyRoutes` scale (confirmed: `kMaxEnvoyRoutes` nested prefix routes, narrowest declared first -- so none shadows another and all register as nodes, each non-root node contributing its own conditional prefix arm plus one unconditional nearest-ancestor terminal arm -- lexes to well over 4096 tokens; `capacity_covers_worst_case_node_arm_duplication`, `tests/test_envoy_convert.cc`; a 2-route, 2-node bootstrap needing an if/else arm on one node -- `tests/fixtures/envoy_routes_a.inc`'s scenario -- needed over the old 932-token budget but comfortably fits the current 4096-token one at 1126 tokens). The token budget is not the only shape-dependent admission limit: a lone `prefix` route with no catch-all (e.g. `prefix: "/api/"` alone, well under both `kMaxEnvoyRoutes` and the token budget) and a root containing only exact `path` routes with no catch-all `"/"` are both rejected as `BLOCKED_BY_RUT`, because their no-route 404 has no RUT form that serves every method Envoy's real 404 would (see the increment-4 rows below and the "Internal evidence notes" section's `blocked_on_node_own_literal_needs_all_method_fallback` / `blocked_root_exact_arms_without_catch_all` tests). `lower_to_rut` now measures the emitted program against that budget and fails closed with `TooManyTokens` instead of returning a program `rut` cannot load | segment-aware `route "/"` catch-all exists; `unmatched` policies exist for the 404 shape | milestone pair evidence only; broader configurations remain unverified | PARTIAL |
| Cluster: `type` omitted or `STATIC`, positive `connect_timeout` with millisecond precision, `load_assignment` with required `cluster_name` matching the cluster and one locality with one IPv4 `lb_endpoints` entry; increment 4 / PR 8 widens `static_resources.clusters` from the increment-1 single-cluster baseline to a bounded list (`kMaxEnvoyClusters` = 8, a 9th rejected at its span, duplicate names rejected), and permits omitting the field or declaring an empty array when every route is `direct_response`/`redirect` and none needs a declared cluster (`parse_clusters`, `helpers/envoy/parser.cc`) | yes: `STRICT_DNS`/`LOGICAL_DNS`/`EDS`/`ORIGINAL_DST`, `lb_policy`, `health_checks`, `circuit_breakers`, `outlier_detection`, `transport_socket`, weights, `locality`, multiple localities/endpoints, sub-millisecond or zero durations, omitted or mismatched `load_assignment.cluster_name` rejected | yes: emitted by the standalone helper using implemented Rut policy syntax | one `upstream envoy_cluster_<i> at "ip:port"` per declared cluster, in declaration order (`helpers/envoy/converter.cc`), independent of which routes reference it, for a bootstrap that actually lowers; the only admitted clusterless shape today is every route being `direct_response`/`redirect`, and `validate()` (`helpers/envoy/converter.cc:1152`) rejects both of those with `UnsupportedSyntax` ("direct_response is not lowered yet" / "redirect is not lowered yet") before `emit_rut_source()` ever writes a byte — so a clusterless bootstrap is parsed and admitted at the model level but never actually produces a program yet; `local_only_route_table_omits_clusters` (`tests/test_envoy_convert.cc`) asserts exactly that failure, not a zero-`upstream`-line success; `connect_timeout` has no connect-establishment RUT surface (accepted with a stderr warning, see "Blocked by Rut") | milestone pair evidence only; broader configurations remain unverified | PARTIAL |
| Router filter `suppress_envoy_headers: true` (v3 `Router` typed_config; also accepts `suppressEnvoyHeaders`) | yes: boolean-only, duplicate-spelling rejection, only valid inside the router's typed_config | required (milestone-S; see docs/envoy-converter.md) | removes `x-envoy-upstream-service-time` / `x-envoy-expected-rq-timeout-ms`; no separate RUT surface needed once emitted | milestone pair evidence only; broader configurations remain unverified | PARTIAL |
| Route action `timeout: "0s"` (proto3 JSON `Duration`, zero permitted) | yes: `"0s"` through `"4294967s"`, sub-millisecond and non-numeric forms rejected | required (milestone-S; a present, non-zero `timeout` is also rejected until a RUT route-timeout surface exists) | none needed for `"0s"` (removes the implicit 15s default); non-zero values are BLOCKED_BY_RUT | milestone pair evidence only; broader configurations remain unverified | PARTIAL |

Per-request divergences on the milestone's own `forward(...)` route (PR #692
round-2 review; not configuration-admission gaps, see the note above): the
helper emits these routes using the implemented PR3-PR5 policy fields, and Rut's
runtime, when it later sees the specific request or response shape below,
safely refuses it with a fixed status rather than mis-forwarding.

| Envoy feature | parser | converter | RUT capability | behavior test | status |
| --- | --- | --- | --- | --- | --- |
| Fixed-length request body larger than the 16 KiB request slice, forwarded by Envoy (no body-size cap tied to a single buffer; `Cluster.per_connection_buffer_limit_bytes` defaults to a 1 MiB soft watermark, `api/envoy/config/cluster/v3/cluster.proto`) | yes: milestone bootstrap admission does not depend on any per-request body size | yes: the emitted route forwards fixed-length bodies unconditionally, no capability gate | no: Rut fails closed with `400 Bad Request` before upstream contact (`inspect_request_policy_body` requires `content_length <= recv_buf.capacity() - header_end`, `include/rut/runtime/callbacks_impl.h:5461-5463`; `recv_buf` is one `SlicePool::kSliceSize`, 16384 bytes, `include/rut/runtime/io_backend.h:50`) | live observation on envoy/lower-increment-2 with the nginx-era policy shape: `POST /` with a 20000-byte fixed-length body (20051 bytes total) got `HTTP/1.1 400 Bad Request`, no upstream connection attempted | NOT_IMPLEMENTED |
| `Expect: 100-continue` with a body, forwarded by Envoy after it sends the interim `100 Continue` itself (`ConnectionManagerImpl::ActiveStream::decodeHeaders`, `source/common/http/conn_manager_impl.cc`) and strips `Expect` before forwarding | yes: milestone bootstrap admission does not depend on per-request `Expect` | yes: the emitted route has no interim-response surface to gate on | no: Rut fails closed with `400 Bad Request` before upstream contact (`inspect_request_policy_body` treats `Expect` on a content-length request as invalid, `include/rut/runtime/callbacks_impl.h:5451,5460`); no interim 100 response exists | live observation on envoy/lower-increment-2 with the nginx-era policy shape: `POST /` with `Content-Length: 2` and `Expect: 100-continue` got `HTTP/1.1 400 Bad Request`, no upstream connection attempted | NOT_IMPLEMENTED |
| `TE: trailers` preserved by Envoy while every other `TE` value and hop-by-hop header is stripped (`ConnectionManagerUtility::sanitizeTEHeader`, `source/common/http/conn_manager_utility.cc`) | yes: milestone bootstrap admission does not depend on per-request `TE` | Historical (nginx-era converter, pre-`request_envoy_h1`): the emitted route stripped `TE` via the fixed `strip_headers` list (ID1), no capability gate. Current (this branch): `put_forward_route` (`helpers/envoy/converter.cc`) unconditionally emits `host: .preserve`/`header_names: .lowercase`/`forwarded_proto: .http` -- i.e. ID4 `Http11PreserveHostLowercase` -- once `validate()` clears every capability gate. `kShippedRutCapabilities` (`helpers/envoy/include/rut/envoy/converter.h`) is now all true (PR3/PR4/PR5 have landed), so `validate()` clears every gate for the milestone-S bootstrap and the shipped binary emits the ID4 route unconditionally, not ID1; `cli_milestone_s_converts` (`tests/test_envoy_convert.cc`) runs the real CLI end to end and checks its stdout against the golden RUT source, which carries `host: .preserve`, `header_names: .lowercase`, `forwarded_proto: .http` (`tests/fixtures/envoy_milestone_s.inc`) | Historical (nginx-era ID1 route): for a request with a `Content-Length` body, Rut failed closed with `400 Bad Request` before upstream contact -- but not specifically for "a `TE` value with no `trailers` token" as an earlier revision of this row said; `inspect_request_policy_body`'s `has_te` computation is token-blind (`has_te |= request_policy_name_eq(hs, name_len, "te", 2)`, matching purely on the field *name*), so it rejects **every** body-carrying `TE` field for a policy that does not preserve Host, including one that already carries `trailers`. For a bodyless ID1 request, the fixed `strip_headers` list instead silently dropped `TE` entirely rather than preserving `trailers` — a mis-forward, not a fail-closed refusal. Current (ID4, this branch): `inspect_request_policy_body` admits a body-carrying `TE` field regardless of its value once the policy preserves Host (token content decides its fate later, not admission), and `apply_preserve_host_lowercase_request_policy` rewrites a field carrying a `trailers` token to the canonical lowercase `te: trailers` -- for both the bodyless-GET and fixed-Content-Length cases -- matching Envoy's `sanitizeTEHeader`/`sanitizeConnectionHeader` byte for byte. This ID4 behavior is unit/wire-tested (`tests/test_network.cc`, `request_policy` suite), and the shipped CLI now emits this exact route for the milestone-S bootstrap (`cli_milestone_s_converts`, `tests/test_envoy_convert.cc`); no live pair run against the real binary has exercised the `TE` handling itself yet | Historical live observation on envoy/lower-increment-2 with the nginx-era ID1 policy shape: `POST /` with `Content-Length: 2` and `TE: trailers` got `HTTP/1.1 400 Bad Request`, no upstream connection attempted; a bodyless `GET /` with `TE: trailers` was forwarded to the origin with the `TE` header silently removed (`GET / HTTP/1.1\r\nHost: 127.0.0.1:9100\r\n\r\n`, no `TE` field). No pinned-Envoy differential-pair run yet for the current ID4 route (PR6) | PARTIAL |
| Extension/unrecognized HTTP methods (e.g. `PROPFIND`) forwarded by Envoy's default hard-coded 34-method list, which includes WebDAV methods (`kValidMethods`, `source/common/http/http1/balsa_parser.cc`) | yes: milestone bootstrap admission does not depend on per-request methods | yes: the emitted route is any-method, no capability gate | no: Rut fails closed with `400 Bad Request` before any route lookup (`HttpMethod` recognizes 9 methods; an unrecognized method resolves to `ParseStatus::Error` once the request head is complete, `src/runtime/http_parser.cc:101-159,360,493-501`) | live observation on envoy/lower-increment-2 with the nginx-era policy shape: `PROPFIND / HTTP/1.1` got `HTTP/1.1 400 Bad Request` | NOT_IMPLEMENTED |
| Upstream response with 65-100 headers, forwarded by Envoy (default `HttpProtocolOptions.max_headers_count` is 100, `api/envoy/config/core/v3/protocol.proto`) | yes: milestone bootstrap admission does not depend on per-response header counts | yes: the emitted route's response_policy has no header-count knob, no capability gate | no: Rut fails closed with `502 Bad Gateway` before downstream commit (`kMaxHeaders` is a fixed 64, `include/rut/runtime/http_parser.h:46`; `build_strict_response_headers` rejects any response with `headers_truncated`, `include/rut/runtime/callbacks_impl.h:10169`, tripping the route's configured failure response) | live observation on envoy/lower-increment-2 with the nginx-era policy shape: an origin returning 90 headers plus `Content-Length: 5` got the client `HTTP/1.1 502 Bad Gateway` | NOT_IMPLEMENTED |
| Valid HTTP/1.0 upstream response with `Content-Length`, forwarded by Envoy (`accept_http_10` gates only the downstream-facing server codec, `source/common/http/http1/codec_impl.h`; the client codec's version check accepts any `HTTP/<digit>.<digit>` line) | yes: milestone bootstrap admission does not depend on the upstream's response version | yes: the emitted route's response_policy has no upstream-version knob, no capability gate | no: Rut fails closed with `502 Bad Gateway` before downstream commit (`build_strict_response_headers` requires `resp.version == HttpVersion::Http11`, `include/rut/runtime/callbacks_impl.h:10164`) | live observation on envoy/lower-increment-2 with the nginx-era policy shape: an origin answering `HTTP/1.0 200 OK` with `Content-Length: 5` got the client `HTTP/1.1 502 Bad Gateway` | NOT_IMPLEMENTED |
| Upstream response with an empty reason phrase, forwarded by Envoy (RFC 7230 §3.1.2 allows a zero-length `reason-phrase`; `BalsaParser::OnResponseFirstLineInput` does not reject it, `source/common/http/http1/balsa_parser.cc`) | yes: milestone bootstrap admission does not depend on the upstream's reason phrase | yes: the emitted route's response_policy has no reason-phrase knob, no capability gate | partial, profile-dependent: the legacy fixed-order (`Synthesized`) profile still fails closed with `502 Bad Gateway` before downstream commit (`build_strict_response_headers` rejects `resp.reason.len == 0`, `include/rut/runtime/callbacks_impl.h:10170`); the newer `header_order: .upstream` (Envoy H1) profile added on `envoy/rut-response-envoy-h1` admits it instead, since it never forwards `resp.reason` in the first place and always substitutes the canonical reason for the status code (`build_upstream_order_response_headers`, `include/rut/runtime/callbacks_impl.h:10625-10627`; `test_network.cc: response_policy.upstream_header_order_accepts_empty_upstream_reason`) | live observation on envoy/lower-increment-2 with the nginx-era policy shape (legacy `Synthesized` profile): an origin answering `HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n` got the client `HTTP/1.1 502 Bad Gateway`; the `header_order: .upstream` profile instead accepts the same upstream shape and forwards the canonical `200 OK` reason downstream (unit-tested, not yet a live pair observation) | PARTIAL |

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
| Ordinary upstream response headers Envoy has no special handling for beyond hop-by-hop stripping — e.g. `Location` on a `302 Found`, `Refresh`, `Last-Modified` — forwarded unchanged (`ConnectionManagerUtility`, `source/common/http/conn_manager_utility.cc`, only strips `connection`/`keep-alive`/`proxy-connection`/`upgrade`/`transfer-encoding`-on-reframe (Codex sweep-1 review of #698: `te` removed from this list -- `removeTE()` is request-only, response `TE` is forwarded unchanged; see the hop-by-hop row below)) | yes: milestone bootstrap admission does not depend on per-response header names | yes: the emitted route explicitly requests `hide_headers: []` (hide nothing) | partial, profile-dependent: the legacy fixed-order (`Synthesized`) profile's `strict_response_forbidden` still unconditionally rejects `location`, `refresh`, and `last-modified` regardless of `hide_headers` (`include/rut/runtime/callbacks_impl.h:9856-9868`); the `header_order: .upstream` (Envoy H1) profile added on `envoy/rut-response-envoy-h1` never routes headers through `strict_response_forbidden` at all — it only removes the fixed hop-by-hop set and policy-`hide_headers` names, so ordinary headers such as `Last-Modified` pass through unchanged (`build_upstream_order_response_headers`, `include/rut/runtime/callbacks_impl.h:10666-10685`; `tests/test_integration.cc: route.forward_response_policy_upstream_order_wire`, the Last-Modified pass-through case) — this closes the capability gap once the converter emits the `response_envoy_h1` profile | live observation on the legacy `Synthesized` profile: an upstream `302 Found` with `Location: /login` got the upstream contacted but the client connection closed with no response bytes; the `header_order: .upstream` profile instead forwards a `Last-Modified` upstream header downstream unchanged, lowercased (integration-tested) | PARTIAL |
| Upstream response with a duplicate Envoy-inline single-value header -- every Envoy inline response header, pinned v1.39.1, from both (1) the unconditional macro-defined set (`envoy/http/header_map.h` `INLINE_RESP_HEADERS` + `INLINE_REQ_RESP_HEADERS` + `INLINE_RESP_HEADERS_TRAILERS` -- the last inherited via `ResponseHeaderOrTrailerMap`, which both `ResponseHeaderMap` and `ResponseTrailerMap` mix in, so despite the "_TRAILERS" macro name `grpc-status`/`grpc-message` are inline on an ordinary response header map too (Codex round-17 review of #698, correcting a round-9-era gap in this inventory), response-relevant subset): `content-type`, `date`, `keep-alive`, `location`, `proxy-connection`, `proxy-status`, `upgrade`, `via`, `x-envoy-attempt-count`, `x-envoy-decorator-operation`, `x-envoy-degraded`, `x-envoy-immediate-health-check-fail`, `x-envoy-ratelimited`, `x-envoy-upstream-canary`, `x-envoy-upstream-healthchecked-cluster`, `x-envoy-upstream-service-time`, `x-request-id`, `grpc-status`, `grpc-message`; and (2) every header a stock (all-extensions-linked) Envoy binary registers as a custom inline slot at static init via a file-scope `Http::RegisterCustomInlineHeader<Type::ResponseHeaders>`, enumerated with `gh api search/code -f q='repo:envoyproxy/envoy RegisterCustomInlineHeader'` and confirmed present at the v1.39.1 tag (`source/extensions/filters/http/{cache,cache_v2}/cache_custom_headers.cc`, `compressor/compressor_filter.cc`, `decompressor/decompressor_filter.cc`, `cors/cors_filter.cc`, `stat_sinks/hystrix/hystrix.cc`): `cache-control`, `content-encoding`, `last-modified`, `etag`, `age`, `expires`, `vary`, `access-control-allow-origin`, `access-control-allow-credentials`, `access-control-allow-methods`, `access-control-allow-headers`, `access-control-max-age`, `access-control-expose-headers`, `access-control-allow-private-network` -- coalesced by Envoy's `HeaderMapImpl` into one entry (comma-joined) rather than forwarded as two physical lines (custom-inlined single-value headers, `source/common/http/header_map_impl.h`) | yes: milestone bootstrap admission does not depend on per-response header duplication | yes: the emitted route's response_policy has no duplicate-header knob, no capability gate | no, fails closed rather than reproducing the join, but only for a name this policy actually forwards: the `header_order: .upstream` (Envoy H1) profile forwards headers verbatim in upstream order instead of rebuilding a HeaderMap, so it cannot comma-join a duplicate; a second occurrence of a name in the `kEnvoyInlineResponseHeaders` table makes `build_upstream_order_response_headers` return false, tripping `reject_strict_response` for a `502 Bad Gateway` before any byte reaches the client, *except* for a name that will never reach the wire either way: `keep-alive`, `upgrade`, and `proxy-connection` are unconditionally dropped by the same fixed hop-by-hop set the serializer always strips (`hide_headers` or not), and any table entry the policy's own `hide_headers` names is dropped the same way -- a duplicate of either can never produce two physical lines, so it is accepted rather than rejected (Codex round-15 review of #698, correcting a round-10-era over-reject; `include/rut/runtime/callbacks_impl.h`). `Content-Length` duplicates were already rejected by the existing `content_length_count != 1` precondition and a duplicate `Server` is deliberately deduplicated first-wins rather than rejected, per the row above; `Transfer-Encoding` keeps its own pre-existing check (any occurrence at all, not just a duplicate, is rejected as a protocol error) -- none of those three is in the generic table. `Connection` is not in the table either, and is no longer counted at all (Codex round-16 review of #698, correcting a round-15-era gap): it is one more name the fixed hop-by-hop set always drops regardless of `hide_headers`, so a duplicate can never reach the wire and is accepted like the three always-dropped table exemptions -- a dedicated `connection_count` check that used to reject it on duplicate served no purpose and was removed. The response's own persistence decision does not depend on this check: `resp.keep_alive`/`resp.connection_close` are computed once by the parser across every physical `Connection` field with `close` sticky, so a mixed duplicate (`keep-alive` plus `close`) still vetoes upstream pooling exactly as a single `close` field would. This is a code-search-based inventory: it would miss a custom registration in a file deleted from Envoy's default branch since v1.39.1 was cut, though every hit the search did find was individually confirmed present at the pinned tag | unit-tested (`tests/test_network.cc: response_policy.upstream_header_order_rejects_duplicate_of_every_inline_header`, iterating the whole table -- now split between the still-fail-closed entries and the three always-dropped exemptions -- plus a non-inline `x-custom` header proving ordinary headers may still repeat; `response_policy.upstream_header_order_accepts_duplicate_of_hidden_inline_header`, proving a `hide_headers`-named duplicate is also accepted while the same duplicate with no hide entry still fails closed; `response_policy.upstream_header_order_accepts_duplicate_connection_header`, proving two `Connection` fields are accepted and never forwarded; `upstream_reuse.upstream_order_profile_accepts_duplicate_connection_and_honors_close`, proving a `keep-alive`+`close` duplicate is accepted and still vetoes upstream pooling; `response_policy.kEnvoyInlineResponseHeaders_matches_full_envoy_inline_inventory`, independently transcribing the complete macro-defined and custom-registered inline sets and asserting the runtime table is exactly their union -- catching the `grpc-status`/`grpc-message` gap and guarding against a similar future one); no live pinned-Envoy differential-pair observation of the joined value yet | PARTIAL |
| Upstream failure replies differentiated by cause: Envoy maps `LocalConnectionFailure`/`RemoteConnectionFailure`/`ConnectionTimeout` to one local-reply text and `ConnectionTermination` (reset after the stream was established) to another, and protocol errors to `502` versus other resets to `503` (`source/common/router/router.cc`, `StreamResetReason` → `CoreResponseFlag` mapping) | n/a (per-request runtime behavior, not a parser concern) | yes: the emitted route has exactly one `failure_policy` for every non-timeout upstream failure, no capability gate | no, and worse than "one generic text for every cause": a genuine connect refusal fires the route's configured `failure_policy` (the exact body/status the bootstrap's failure policy specifies), but an upstream that accepts the connection, receives the request, and then resets before sending any response byte gets no local-reply text at all — see behavior test | live observation on the same nginx-era `failure_policy` (502 "Bad Gateway" HTML body): stopping the origin entirely (connect refused) got the client the exact configured `HTTP/1.1 502 Bad Gateway` body; an origin that accepted the connection, read the request, and closed without writing any bytes got the client connection closed with no response bytes at all | NOT_IMPLEMENTED |

The any-method `route "/"` historically matched origin-form `CONNECT`
(`route_table.h`: "method 0 in a route entry matches any request method").
The mis-forward and its runtime admission fix are recorded below.

**Fixed (#708):** shared runtime admission now rejects origin-form `CONNECT`
with a local 400 before static routes, handlers, or upstream effects. HTTP/1
closes after the response; HTTP/2 emits a status-only 400, including while a
prepared Forward owns another stream. Existing strict-policy zero-byte fences
retain precedence. Authority-form CONNECT retains its existing unmatched
behavior, and TRACE remains eligible for method-any routing. No CONNECT/TRACE
language spelling or tunnel capability is added.

**Historical bug evidence:** `CONNECT / HTTP/1.1` against the
milestone's any-method route opens the upstream connection and relays the
origin's response back to the client. Envoy rejects this request locally
(a non-empty `:path` on a `CONNECT` request fails
`ConnectionManagerImpl::ActiveStream::decodeHeaders`'s validation,
`source/common/http/conn_manager_impl.cc`) without ever contacting an
upstream. Live observation on `envoy/lower-increment-2` (head `ec0f9df4`)
with the nginx-era policy fixture: `CONNECT / HTTP/1.1` reached the origin
(`ORIGIN RECEIVED: b'CONNECT / HTTP/1.1\r\nHost: 127.0.0.1:29000\r\n\r\n'`)
and the origin's `200 OK` body was relayed back to the client unchanged. Two
converter-level fixes were investigated and both were infeasible at the
time: (1) splitting the any-method route into one explicit `route <METHOD>
"/"` per forwarded method overflowed the lexer's fixed `kMaxTokens`, then
932 (`include/rut/compiler/lexer.h:135`), once duplicated across all 7
non-HEAD forwarded methods (confirmed by compiling that shape with `rut`);
#697 has since raised `kMaxTokens` to 4096, and whether that specific shape
now fits has not been re-measured; the runtime fix no longer depends on
that expansion; (2) a
`guard req.method == GET \|\| … else { return 400 }` inside the existing
any-method route stays within the token budget, but `CONNECT` and `TRACE`
are both plain identifiers with no `req.method == <KW>` expression form and
no `route <METHOD> "/"` declaration spelling of their own (confirmed live:
`route TRACE "/"` and `pre_route TRACE { return forward(...) }` are both
parse errors — `pre_route`/`unmatched` bodies are fixed-shape local-response
policies only), so a guard that excludes `CONNECT` is indistinguishable from
one that also excludes `TRACE`, and Envoy forwards `TRACE` like any other
method. At the time this needed a runtime capability (an expression-level `CONNECT`
literal, a per-route method exclusion list, or a higher token budget) before
the converter can prevent it without trading the `CONNECT` mis-forward for a
new `TRACE` divergence.

Found in the PR #692 round-4 review, same class of bug as the `CONNECT` one
above (Rut forwards where Envoy fails closed, recorded separately from the
per-request divergence tables because Rut does not merely refuse the
request): a request target containing a `#` fragment.

**Fixed by request admission (#709):** HTTP/1 requests and HTTP/2 `:path`
values containing a literal `#`, including after a query delimiter, are rejected
before ordinary route matching, handler invocation or upstream contact. HTTP/1
returns a generic `400 Bad Request` and closes the connection; HTTP/2 returns a
status-only 400 for the stream. Existing exact/pre-route strict policy fences
retain their zero-byte fail-closed behavior. Percent-encoded `%23` remains legal
request-target data.

The parser already recorded `target_has_fragment`, but the ordinary HTTP/1
entry previously allowed `host: .upstream` policies to copy the raw target
verbatim. ID4 (`Http11PreserveHostLowercase`) had its own policy-level check;
the shared admission check now also protects transparent forwarding, local
routes and the no-route fallback. This fixes the refusal-versus-forwarding
behavior; it does not claim a byte-identical Envoy error response. Focused
`request_admission` network tests cover HTTP/1 and HTTP/2, fragments in paths
and queries, fragmented headers, pipelined successors, absence of upstream
work, close/reclaim, and an encoded-delimiter control.

Per-request divergences found in the PR #692 round-6 review (same
non-gating rule as round-2/round-3 above; verified by reading Envoy v1.39.1
source — no live Envoy/Rut differential run in this round).

| Envoy feature | parser | converter | RUT capability | behavior test | status |
| --- | --- | --- | --- | --- | --- |
| Downstream HTTP/1.0 (or HTTP/0.9) request rejected before any route/filter logic runs: `ServerConnectionImpl::checkProtocolVersion` (`source/common/http/http1/codec_impl.cc:1176-1189`) checks `codec_settings_.accept_http_10_` (`Http1Settings::accept_http_10`, `api/envoy/config/core/v3/protocol.proto:457`, proto3 `bool` — defaults `false`, and the milestone HCM's fixed 6-field allow-list has no `http_protocol_options` at all, so every model this converter can admit leaves it at that default); when false, Envoy sets `error_code_ = Http::Code::UpgradeRequired` and calls `sendProtocolError` (`codec_impl.cc:1387-1406`), which sends the client a real `426 Upgrade Required` local reply (detail `low_version`) without ever reaching `decodeHeaders`/route selection | yes: milestone bootstrap admission does not depend on per-request HTTP version | yes: the emitted route's `request_policy` already pins `version: .http11` (`helpers/envoy/converter.cc:165`), no capability gate | no: an HTTP/1.0 request still reaches this route (Rut's listener accepts any version at the connection level) and only then does `inspect_request_policy_body` (`include/rut/runtime/callbacks_impl.h:5406-5412`) reject it — `conn.req_http_version != HttpVersion::Http11` makes it return `Invalid`, `apply_request_policy` (`callbacks_impl.h:5479-5481`) then returns `false`, and `reject_request_policy` (`callbacks_impl.h:5767-5777`) sends a generic `400 Bad Request` and closes, with no upstream contact | code reading only (`src/runtime/http_parser.cc`, `include/rut/runtime/callbacks_impl.h`); a live check against this branch would need the milestone's own emitted route text, which requires #696/#698/#699 first | PARTIAL |

**SECURITY (P1) — client-forged `x-envoy-*` internal headers are forwarded verbatim.** Found in the PR #692 round-6 review; routed to the runtime team, see docs/envoy-converter.md, "Round-6 review edge cases (PR #692)" for the fix location. **Fixed in PR #696** (ID4 `request_policy_is_stripped_client_envoy_header`, `include/rut/runtime/callbacks_impl.h`): all 15 names below plus `x-forwarded-client-cert` (round-7 review of #696) are stripped unconditionally; the row is kept for the Envoy-side evidence and now reads `PARTIAL` (see the ID4 rows further down).

| Envoy feature | parser | converter | RUT capability | behavior test | status |
| --- | --- | --- | --- | --- | --- |
| `ConnectionManagerUtility::mutateRequestHeaders` (`source/common/http/conn_manager_utility.cc:121-327`) unconditionally removes a client-supplied `x-envoy-internal` header (`request_headers.removeEnvoyInternalRequest()`, line 142) before route selection, and re-adds it only if Envoy's own address-based `internal_request` check (lines 263-265, `config.internalAddressConfig().isInternalAddress(*final_remote_address)`, gated by `allow_trusted_address_checks`, itself only ever set `true` inside `if (config.useRemoteAddress())`) says so; separately, whenever `internal_request` is false, `cleanInternalHeaders(request_headers, edge_request, ...)` (called at line 282; function body at lines 351-388) unconditionally strips `x-envoy-retriable-status-codes`, `x-envoy-retriable-header-names`, `x-envoy-retry-on`, `x-envoy-retry-grpc-on`, `x-envoy-max-retries`, `x-envoy-upstream-alt-stat-name`, `x-envoy-upstream-rq-timeout-ms`, `x-envoy-upstream-rq-per-try-timeout-ms`, `x-envoy-upstream-rq-timeout-alt-response`, `x-envoy-expected-rq-timeout-ms`, `x-envoy-force-trace`, `x-envoy-ip-tags`, `x-envoy-original-url`, `x-envoy-hedge-on-per-try-timeout` (literal names from `source/common/http/headers.h:153-208`, default `x-envoy` prefix), regardless of `edge_request`. The milestone HCM never sets (and its 6-field allow-list cannot express) `use_remote_address`, so `config.useRemoteAddress()` is always `false` for every model this converter admits, which makes `allow_trusted_address_checks` and therefore `internal_request` always `false` too — i.e. for this exact milestone config, all 15 headers above (`x-envoy-internal` plus the 14-header `cleanInternalHeaders` list) are stripped from *every* request, unconditionally, before Envoy ever forwards it upstream. (The additional `edge_request`-only strip list — `x-envoy-decorator-operation`, `x-envoy-downstream-service-cluster`, `x-envoy-downstream-service-node`, `x-envoy-original-path`, `x-envoy-original-host` — never triggers for this milestone config since `edge_request` requires `useRemoteAddress() == true`, which the parser rejects.) | yes: milestone bootstrap admission does not depend on per-request header names, and the parser's fixed HCM allow-list makes `use_remote_address` unreachable, which is exactly why the `internal_request`/`edge_request` computation above collapses to "always false" for every admitted model | yes: the emitted route's `request_policy.strip_headers` (`helpers/envoy/converter.cc:171`) is the fixed closed list `["Connection", "Keep-Alive", "TE", "Expect", "Upgrade", "Proxy-Connection"]` — none of the 15 `x-envoy-*` names above are in it; that closed list is only the static, request-independent part of Rut's mitigation for this row, not the whole mechanism -- the actual per-request stripping for these names is the runtime ID4 mechanism described in the next column (`request_policy_is_stripped_client_envoy_header`, #696's `apply_preserve_host_lowercase_request_policy`), not a grammar feature or a `strip_headers` entry | yes, in the runtime rather than in `strip_headers` (which is a closed literal list the converter writes once at lowering time and cannot express Envoy's address-derived `internal_request`/`edge_request` split): #696's ID4 `request_policy_is_stripped_client_envoy_header` drops every one of the 15 headers, including a client-forged `x-envoy-internal: true`, unconditionally — the "always external" collapse is exactly Envoy's own net behavior for this milestone config — and (round-7) `x-forwarded-client-cert` as well, plus (round-8) a client-supplied `x-envoy-external-address`, which a real Envoy configured this exact way would *not* strip on its own (`mutateRequestHeaders` only ever writes it, gated by `edge_request`, unreachable here) but which Rut drops anyway so a client can never forge the address a trusted hop is meant to assert, seventeen names in total | unit (`tests/test_network.cc`, `request_policy` suite: `/envoy-internal-headers*`, `/envoy-internal-only`, `/xfcc-*`) and integration (`tests/test_integration.cc`, `forward_request_policy_preserve_host_lowercase_strips_client_envoy_internal_headers`) against a `RecordingUpstream`; no pinned-Envoy differential run yet | PARTIAL |

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
| Absolute-form request target (e.g. `GET http://example.com/ HTTP/1.1`); a plain cleartext HCM listener (no explicit proxy-protocol/CONNECT configuration, which this milestone's fixed 6-field HCM allow-list cannot express in the first place) never accepts absolute-form, so Envoy's HTTP/1 codec rejects the request with `400` before route selection ever runs (docs/envoy-converter.md, "Routing": "Envoy's HTTP/1 codec rejects `CONNECT` and absolute-form targets in specific ways") | yes: milestone bootstrap admission does not depend on per-request target form | yes: the emitted route/`unmatched` policy has no request-target-form knob, no capability gate | no: Rut's parser accepts the request line but leaves the canonical routing path null for an absolute-form target, so the generated `route "/"` catch-all misses and the `unmatched` policy (`put_unmatched`, `helpers/envoy/converter.cc:118`) answers with the fixed no-route `404`, not Envoy's pre-routing `400` | code reading only (`helpers/envoy/converter.cc`, `include/rut/runtime/http_parser.h`); no live differential exists yet — filed as a runtime issue to add pre-route absolute-form rejection | PARTIAL |

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

These rows widen the parser's semantic model (`helpers/envoy/include/rut/envoy/parser.h`,
`RouteMatchKind`, `RouteActionKind`) beyond the single-route, single-cluster
milestone above. PR 8 lowers the ordered-route-list shapes (`path`, prefix
ending in `/`, multiple routes, multiple clusters) by construction (owner
decision D3): `rut::envoy::lower_to_rut` builds, for each declared node, a
nested `if`/`else` chain reproducing Envoy's first-match order restricted to
that node (see the algorithm doc comment in `helpers/envoy/converter.cc` and
docs/envoy-converter.md's "Routing" section) instead of rejecting the shape.
**Global shadowing rule (Codex round-9 review on PR #695):** a `prefix`
route `R` is dropped from the plan entirely -- before it is ever registered
as a node, so no dead node is planned and no lexer token budget is spent on
it -- when an EARLIER-declared route `Q` (any method, same virtual host)
already matches every request `R` could ever match: `Q` is a `prefix` whose
raw text is a byte-prefix of `R`'s (Envoy's prefix match is a raw byte-prefix
test with no segment awareness of its own; every accepted `prefix`'s raw
text is `"/"` or ends in `/`, so a shorter accepted prefix is a byte-prefix
of a longer one exactly when it is also that longer one's segment-boundary
ancestor, so segment-boundary ancestry (`is_strict_ancestor`,
`helpers/envoy/converter.cc`) is Envoy's raw byte-prefix relation here with no
extra byte-level helper needed -- e.g. `"/api/"` shadows `"/api/v1/"`).
This generalizes the original report (`"/"` declared before
distinct siblings such as `"/api/"` and `"/admin/"` -- root, being a
byte-prefix of everything, shadows both) to any earlier, textually-shorter
accepted prefix, not just root. Declaration order, not text length, decides
precedence: a broader prefix declared AFTER a narrower one does not shadow
it (see the "Multiple routes per virtual host" row below and the internal
evidence note at the end of this section). A `prefix` shadowing a later
exact `path` route the same way (e.g. `"/api/"` before `"/api/x"`) was
already handled at the arm level since round 7/8 (`has_exact_arm`,
`saw_own_prefix`) and is unchanged by this rule; two identical `path`
declarations for the same literal were already deduped in round 8. Shapes
Rut genuinely cannot express are unaffected and stay rejected the same way:
a lone `prefix: "/api/"` with no catch-all still hits the node's-own-literal
`BLOCKED_BY_RUT` gap below, and the segment-boundary vs. raw-byte-prefix
difference for slash-terminated prefixes is still tracked as its own
NOT_IMPLEMENTED row ("Path normalization" below). `direct_response` and
`redirect` are still rejected with their own `UnsupportedSyntax` diagnostic
(`"direct_response is not lowered yet"`, `"redirect is not lowered yet"`),
checked before the six capability rows above, same as before.

| Envoy feature | parser | converter | RUT capability | behavior test | status |
| --- | --- | --- | --- | --- | --- |
| `match.path` exact match (bytes 0x21-0x7e excluding `?`/`#`/`%`, Envoy's own outer ceiling is 64 bytes but Rut's effective admitted limit is 62 -- Codex sweep-9 review) | yes: modeled as `RouteMatchKind::Path`; both `prefix` and `path` on one match, a `path` not starting with `/`, and reserved/oversized bytes rejected against Envoy's 64-byte ceiling (`kMaxRouteMatchLen`), then a stricter 63-byte-or-longer literal is separately rejected for dispatch safety (`kMaxDispatchableMatchLen` = 62; see `helpers/envoy/include/rut/envoy/parser.h`'s `RouteMatch` doc comment and the row below): `ConnectionBase::req_path` (`include/rut/runtime/connection_base.h`) keeps only 63 usable bytes, and a 63-byte-or-longer exact literal would let dispatch's truncated view of a longer real request collide with this node's own bare literal while `req.pathOnly` (re-derived from the untruncated request inside the handler) still sees it as unequal | yes: an exact `path` becomes a conditional `req.pathOnly == "..."` arm in its owning node's chain; when its literal text equals a node's own text and no other Envoy route ever resolves the node's literal, lowering fails closed instead of emitting a `route exact "N"` fallback (see the row below) | Rut's `req.pathOnly` comparisons cover the conditional-arm case once the six capability rows above are met; golden (c)/(f) and the brute-force equivalence tests cover it; `route_match_rejects_dispatch_unsafe_length` (`tests/test_envoy_parser.cc`) pins the 62/63-byte boundary | none | PARTIAL (golden + equivalence test; pair evidence pending) |
| `match.prefix` ending in `/` (e.g. `"/api/"`), in addition to the catch-all `"/"` | yes: modeled as `RouteMatchKind::Prefix`; validated as `"/"` or starting and ending with `/`, then the same dispatch-safety bound as `match.path` above applies to the RUT node text the trailing slash strips down to -- so a slash-terminated `prefix` admits at most 63 raw bytes (a 64-byte raw prefix strips to a 63-byte node text, over the 62-byte dispatch-safety limit), while the root catch-all `"/"` (1 byte) is always admitted | yes: each distinct prefix becomes its own RUT node (`route "N"` / `route HEAD "N"`); golden (a)/(b)/(f) cover declaration-order variants | same as `match.path` above | none | PARTIAL (golden + equivalence test; pair evidence pending) |
| A node's own literal path with no earlier exact `path` route resolving it (e.g. `prefix: "/api/"` alone, or preceded only by an exact route under a *different* literal): Envoy's no-route 404 for that one literal path | yes: same modeling as the two rows above | no: `route exact "N"`'s strict local-response admission serves only GET/HEAD/POST/OPTIONS/PUT/DELETE/PATCH (`callbacks_impl.h`), so an ANY-method `route exact "N"` 404 would close the connection instead of answering TRACE/CONNECT the way Envoy's real 404 does; lowering fails closed with `"BLOCKED_BY_RUT: a no-route 404 for this node's own literal path has no RUT form that serves every method Envoy would 404"` (Codex P1 on PR #695) | none until an all-method `local_response` surface exists | none | BLOCKED_BY_RUT |
| A `prefix` segment beginning with `:` (e.g. `"/:tenant/"`) | yes: `:` is not a reserved byte, so the parser admits it like any other printable-ASCII byte | rejects: a `prefix` match's text becomes a generated RUT route declaration, and a segment starting with `:` there is a route parameter (`include/rut/runtime/route_trie.h`), so `route "/:tenant"` would capture and forward `/anything/x`, which Envoy's literal byte match never does; rejected with `"route match segments beginning with \":\" would become a RUT route parameter, not a literal match; not lowered"`. An exact `path` match (e.g. `"/:tenant"`) is never emitted as a route declaration — only ever compared as the string literal `req.pathOnly == "/:tenant"` — so it carries no such risk and is not rejected for containing `:` (Codex P1 on PR #695, then narrowed to `prefix`-only on round 3) | n/a | none | BLOCKED_BY_RUT (`prefix` only) |
| Raw (non-segment) `prefix` not ending in `/` (e.g. `"/api"`) | no: rejected at the field with `"only \"/\" or prefixes ending in \"/\" are supported"` | n/a (never reaches the converter) | Rut's route trie is segment-aware; a plain string prefix like Envoy's has no equivalent match today | none | BLOCKED_BY_RUT |
| Multiple routes per virtual host, in list order (`kMaxEnvoyRoutes` = 8, a 9th rejected at its span) | yes: `VirtualHost::routes` is a bounded `FixedVec`, order preserved from the source array; a `prefix` route globally shadowed by an earlier `prefix` route (Codex round-9 review on PR #695: Envoy's prefix match is a raw byte-prefix test, so an earlier `prefix` whose text is a byte-prefix of a later one's makes the later one unreachable for every request, not merely resolvable through it) is dropped by `build_lowering_plan` (`helpers/envoy/converter.cc`) before it is ever registered as a node, so no dead node is planned and no token budget is spent on it; declaration order (not text length) decides precedence, so a broader prefix declared AFTER a narrower one does not shadow it | yes: lowered by construction (see "Routing" above), now minus any node dropped as globally shadowed; a two-route bootstrap still fails closed on the same capability rows the single-route milestone hits until PR3-PR5 land. Codex round-6 review (P1): a route list admitted by `kMaxEnvoyRoutes` can still be un-loadable -- the emitted program is separately bounded by the compiler frontend's lexer token budget (`LexedTokens::kMaxTokens`, 4096 today, raised from 932 by #697), which a `kMaxEnvoyRoutes`-sized route list can still exceed (`capacity_covers_worst_case_node_arm_duplication`, `tests/test_envoy_convert.cc`, pins a still-over-budget `kMaxEnvoyRoutes`-scale shape; a smaller 2-route bootstrap needing an if/else arm on one node, scenario (a) below, needed over the old 932-token budget but fits comfortably under the current 4096-token one). `lower_to_rut` now measures the emitted token count and fails closed with `TooManyTokens` rather than returning an unloadable program | first-match semantics reproduced per node; golden (a) (`tests/fixtures/envoy_routes_a.inc`) is a golden success case again under the raised 4096-token budget (`golden_routes_a_prefix_then_root`, `token_budget_goldens_match_the_real_lexer`; it needed over the old 932-token budget, now fits at 963 tokens); golden (b) is root-only (`/api/` globally shadowed by an earlier `/`, Codex round-9 -- see the internal evidence note below), and (b)/(c)/(f) all pin successful byte-for-byte output; the 40-probe brute-force equivalence test now also cross-checks the real emitted RUT text for its richer 3-node scenario (`rut_dispatch`, alongside the two independent `envoy`/simulated dispatch models), not just the two independent models, now that it fits under the raised budget too; the 10-probe brute-force test continues to cross-check the real emitted RUT text for its smaller 1-node scenario | none | PARTIAL (golden + equivalence test; pair evidence pending; realistic multi-node route lists remain limited by the lexer token budget at `kMaxEnvoyRoutes` scale) |
| Multiple STATIC clusters (`kMaxEnvoyClusters` = 8, a 9th rejected at its span; duplicate names rejected) | yes: `Bootstrap::clusters` is a bounded `FixedVec`; every Forward route's `cluster` must name a declared entry; a duplicate name is rejected at the second declaration's span | yes: every cluster is emitted as `upstream envoy_cluster_<i> at "..."` in declaration order, independent of which routes reference it; a hand-built `Bootstrap` with a duplicate cluster name (bypassing the parser) is rejected defensively too, since `cluster_index_of` would otherwise silently resolve every same-named reference to the first match (Codex P2 on PR #695) | n/a | none | PARTIAL (golden + equivalence test; pair evidence pending) |
| `direct_response.status` + optional `body.inline_string` (≤ 4096 bytes) | yes: modeled as `RouteActionKind::DirectResponse`; other `DataSource` variants (`inline_bytes`, `filename`, ...) rejected as unsupported fields | rejects with `"direct_response is not lowered yet"` at the action's span | Envoy-layout `local_response` for an arbitrary status/body has no RUT emission yet (see PR 9) | none | NOT_IMPLEMENTED |
| `redirect.path_redirect` / `host_redirect` / `response_code` (closed to `MOVED_PERMANENTLY`/`FOUND`/`SEE_OTHER`/`TEMPORARY_REDIRECT`/`PERMANENT_REDIRECT`) | yes: modeled as `RouteActionKind::Redirect`; every other `RedirectAction` field (`https_redirect`, `scheme_redirect`, `port_redirect`, `prefix_rewrite`, `strip_query`, ...) rejected as unsupported | rejects with `"redirect is not lowered yet"` at the action's span | Rut has a `redirect(...)` construct, but equivalent Envoy redirect lowering is not implemented (see PR 10) | none | NOT_IMPLEMENTED |
| Path normalization: `merge_slashes`, percent-decoding, and Rut route-trie segment normalization (`"/api/"` / `"/api//v1"` collapse the same as `"/api"` / `"/api/v1"`) vs. Envoy's literal (unnormalized) string-prefix matching | not modeled: `merge_slashes` is not a recognized field; a configured `prefix` containing an internal `"//"` (the directly-detectable case: two declared prefixes that would collapse to the same node text, e.g. `"/api//v1/"` and `"/api/v1/"`) is rejected at `validate()` with `"route match prefix contains \"//\", which Rut's route trie collapses; not lowered"` (Codex P1 on PR #695 round 3) | n/a | Rut's trie normalizes empty path segments when selecting a node; PR 8's `req.pathOnly` arm comparisons do not; neither matches Envoy's default (no normalization) exactly. This remains a real divergence even with no `"//"` in any declared text: a request whose raw path contains an injected empty segment (e.g. `/api//v1/x`) can reach a declared node (e.g. `"/api/v1"`) and forward through its terminal prefix arm even though Envoy's literal prefix comparison would 404 it — confirmed NOT_IMPLEMENTED, not fixed by the `validate()` check above (which only catches the configured text itself, not every request that could alias into a node through collapsing) | none | NOT_IMPLEMENTED |
| Segment-boundary dispatch | Native Rut literal routes use complete segment-prefix matching | No helper workaround; production `RouteConfig` uses ART SegmentPrefix mode | Scalar and JIT terminal-boundary checks; regression tests cover single/root/nested routes, method fallback and node promotion. Real-process native and two-upstream helper routing tests are registered, alongside an Envoy pair test | Encoded-path and slash normalization matrix remains pending | PARTIAL (boundary fix; full normalization audit pending) |

## Blocked by Rut before the milestone can reach SUPPORTED

Each row needs a runtime/language issue before the converter may emit it. The
converter fails closed on the whole configuration until then.

| Envoy behavior | RUT gap | status |
| --- | --- | --- |
| `Host` preserved unchanged on the upstream request | `request_policy.host: .preserve` (`request_envoy_h1`, PR3) is implemented and unit/wire-tested byte for byte against the recorded Envoy oracle (`tests/fixtures/envoy_oracle_milestone_s.inc`). Also confirmed against the real pinned Envoy binary: every asserted `--pair-milestone-s` case sends `Host: client.example` on the upstream request, and Rut's upstream bytes matched Envoy's own byte for byte (CI run `36069445967`, zero skips; re-validated for all nine asserted cases by run `36070125213`); subject to the same re-run-pending caveat as the pair case table below (round-6 review: neither run has been re-validated under this round's harness hardening yet) | SUPPORTED |
| Client-supplied `x-envoy-*` internal-only request headers stripped for external requests: `ConnectionManagerUtility::mutateRequestHeaders` (`source/common/http/conn_manager_utility.cc`, v1.39.1) removes `x-envoy-internal` unconditionally (`removeEnvoyInternalRequest()`, line 142) and writes it back (lines 278-280) only when `internal_request` is `true`, which needs `allow_trusted_address_checks` — set only inside `if (config.useRemoteAddress())` (lines 163-164) — so it is always `false` under this milestone's fixed HCM shape (no `use_remote_address: true`); every request then reaches `cleanInternalHeaders` (line 282), whose unconditional block strips fourteen more `x-envoy-*` names regardless of `edge_request` (`= !internal_request && config.useRemoteAddress()`, line 275, also always `false`) | Implemented in `apply_preserve_host_lowercase_request_policy` (`request_policy_is_stripped_client_envoy_header`, `include/rut/runtime/callbacks_impl.h`): drops `x-envoy-internal` plus the fourteen headers `cleanInternalHeaders` removes unconditionally for a non-edge external request, regardless of client input — `x-envoy-retriable-status-codes`, `-retriable-header-names`, `-retry-on`, `-retry-grpc-on`, `-max-retries`, `-upstream-alt-stat-name`, `-upstream-rq-timeout-ms`, `-upstream-rq-per-try-timeout-ms`, `-upstream-rq-timeout-alt-response`, `-expected-rq-timeout-ms`, `-force-trace`, `-ip-tags`, `-original-url`, `-hedge-on-per-try-timeout` (fifteen `x-envoy-*` names; seventeen stripped names in total with `x-forwarded-client-cert` and `x-envoy-external-address`, next two rows). `cleanInternalHeaders`'s five `edge_request`-gated removals (`-decorator-operation`, `-downstream-service-cluster`, `-downstream-service-node`, `-original-path`, `-original-host`) are unreachable under this fixed `edge_request == false` shape and are left unstripped, matching Envoy's own net behavior here. Unit-tested (`tests/test_network.cc`, `request_policy` suite) and integration-tested against a `RecordingUpstream` (`tests/test_integration.cc`); no pinned-Envoy differential-pair run yet (PR6), so this stays below `SUPPORTED` | PARTIAL |
| Client-supplied `x-forwarded-client-cert` removed on the upstream request: `ConnectionManagerUtility::mutateXfccRequestHeader` (`source/common/http/conn_manager_utility.cc:324`, body at 662-686) applies the HCM's static `forward_client_cert_details`, whose proto default is `SANITIZE` ("Do not send the XFCC header to the next hop. This is the default value.", `api/envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto`; the milestone HCM allow-list cannot set the field), and `applyForwardClientCertConfig` (lines 541-545) then calls `removeForwardedClientCert()` — for `Sanitize` outright, and independently for any connection that is not mutual TLS, so it fires on this cleartext listener either way | Implemented in the same ID4 stripped set (`request_policy_is_stripped_client_envoy_header`): `x-forwarded-client-cert` is dropped unconditionally, in any casing, on every physical field, so a client-asserted certificate identity can never reach an XFCC-trusting upstream through Rut (Codex round-7 review of #696). Unit-tested (`tests/test_network.cc`, `request_policy` suite, `/xfcc-only`, `/xfcc-mixed`) and integration-tested (`tests/test_integration.cc`); no pinned-Envoy differential-pair run yet (PR6) | PARTIAL |
| Client-supplied `x-envoy-external-address` on the upstream request: this is a per-request divergence, not an Envoy-parity claim. `ConnectionManagerUtility::mutateRequestHeaders` (`source/common/http/conn_manager_utility.cc`, v1.39.1) never removes a client-supplied value for this header — `request_headers.setEnvoyExternalAddress(...)` (line 308) only ever *writes* it, gated by `edge_request` (`= !internal_request && config.useRemoteAddress()`, line 275), which needs `use_remote_address: true` and is therefore always `false` under this milestone's fixed HCM shape; `cleanInternalHeaders`'s fourteen unconditional removals (lines 368-381) do not name it, and the `internal_only_headers` route list it also consults (line 282) is empty by default and unset by this converter. A real Envoy configured exactly this way would forward a client-supplied `x-envoy-external-address` unchanged | Implemented in the same ID4 stripped set (`request_policy_is_stripped_client_envoy_header`): `x-envoy-external-address` is dropped unconditionally, in any casing, regardless of what Envoy itself would do with this exact shape — this header exists so a trusted hop can assert the client address it accepted a connection from, and letting a client forge that assertion for itself defeats its purpose independent of byte-for-byte Envoy parity (Codex round-8 review of #696). Unit-tested (`tests/test_network.cc`, `request_policy` suite, `/envoy-external-address-only`, `/envoy-external-address-mixed`); no pinned-Envoy differential-pair run yet (PR6) | PARTIAL |
| Hop-by-hop headers removed on the upstream request: `connection`, `keep-alive`, `proxy-connection`, `expect`, `upgrade`, and every header the client's `Connection` value nominates; `te` is kept only when one of its comma-separated tokens is `trailers` (stripped otherwise, rewritten to the canonical lowercase token when kept) | `request_policy.strip_headers` six-name list with `host: .preserve` (`request_envoy_h1`, PR3); TE-trailers-token and Connection-token nomination are oracle-driven runtime behavior, not a literal strip-list entry. A `Connection` token nominating `content-length` fails the whole request closed rather than matching Envoy byte-for-byte (Envoy removes the header and forwards; Rut would desync a persistent upstream's framing if it did the same), as does a body-carrying request with an `Expect` field whose trimmed value is non-empty (no `100 Continue` interim-response support exists); an empty or OWS-only `Expect` field carries no actual expectation and is admitted instead, stripped like any other `Expect` field. Nominating `host`, `x-forwarded-for`, `x-forwarded-host`, `x-forwarded-proto`, or a pseudo-header-shaped token (one starting with `:`, e.g. the aliased `:authority`) also fails closed, which does match Envoy's own net behavior for these tokens (`sanitizeConnectionHeader`, `source/common/http/utility.cc`: an explicit reject naming exactly `ForwardedFor`/`ForwardedHost`/`ForwardedProto` or any token whose first byte is `:`; for `host` the header is removed and the resulting Host-less request is then rejected 400 by `ConnectionManagerImpl`'s own Host-presence check) | PARTIAL |
| A second physical occurrence of an Envoy inline (O(1)-slot) request header coalesces into the same wire value instead of forwarding two lines: `HeaderMapImpl::insertByKey`/`appendCopy` (`source/common/http/header_map_impl.cc`) place every name in `INLINE_REQ_HEADERS`/`INLINE_REQ_RESP_HEADERS` (`envoy/http/header_map.h`) and every request-side `Http::RegisterCustomInlineHeader<CustomInlineHeaderRegistry::Type::RequestHeaders>` registration (`gh search code "RegisterCustomInlineHeader" --repo envoyproxy/envoy`, e.g. `cors_filter.cc`, `cache_custom_headers.cc`, `compressor_filter.cc`) into one inline slot, comma-joining a duplicate rather than keeping a second line — for example a second `Content-Type` field | ID4 (`Http11PreserveHostLowercase`) does not replicate this coalescing (Rut has no per-request comma-join transform), so `apply_preserve_host_lowercase_request_policy` (`include/rut/runtime/callbacks_impl.h`, `request_policy_inline_request_header_index`) instead fails the whole request closed (`400`) on a second physical occurrence of any of these names, except the seven already covered by their own dedicated handling above/below (`host`, `content-length`, `te`, `connection`, `expect`, `upgrade`, `x-forwarded-proto`), the two (`keep-alive`, `proxy-connection`) `drop_fixed` already strips unconditionally regardless of duplication, and `transfer-encoding`, which fails the whole request closed outright on its first physical occurrence before this serializer ever runs (not stripped -- a duplicate of it can never reach this duplicate-detection logic either). A non-inline header name (e.g. `x-custom`) is unaffected and still forwarded once per physical field, matching this profile's existing behavior for arbitrary headers. Unit-tested (`tests/test_network.cc`, `request_policy` suite) | PARTIAL |
| HTTP/1.1 header names emitted in lowercase on both upstream request and downstream response | request side landed with `request_envoy_h1` (PR3); response side landed with `response_envoy_h1` (PR4, `response_policy.header_order: .upstream` + `header_names: .lowercase`), unit/wire-tested byte for byte against the recorded Envoy oracle. Also confirmed against the real pinned Envoy binary: every asserted `--pair-milestone-s` case's upstream and downstream header names matched Envoy's own byte for byte (CI run `36069445967`, zero skips; re-validated for all nine asserted cases by run `36070125213`); subject to the same re-run-pending caveat as the pair case table below | SUPPORTED |
| `date` added to the response only when the upstream omits it; an upstream `date` is kept in place otherwise | `response_policy.date: .preserveOrCurrent` (`response_envoy_h1`, PR4) is implemented: an upstream `date` header is preserved in its original position after OWS normalization (leading and trailing whitespace around the value is trimmed, RFC 7230 §3.2.4, the same normalization Envoy's HTTP/1 codec applies to every header value in `ConnectionImpl::onHeaderValueImpl` / `completeCurrentHeader`, `source/common/http/http1/codec_impl.cc`), and `date: <now>` is appended (before `server`) only when the upstream sent none | PARTIAL |
| `server: envoy` overwrites the upstream `server` header in place; appended when absent | `response_policy.server` (`response_envoy_h1`, PR4) replaces the first upstream `server` value in place (a later duplicate is dropped) or appends `server: envoy` when the upstream sent none | PARTIAL |
| `connection: close` present only when the downstream connection is closing; no `connection` header otherwise | `response_policy.connection_header: .closeOnly` (`response_envoy_h1`, PR4) appends `connection: close` last only when the effective persistence is closing; omitted otherwise | PARTIAL |
| Canonical reason phrase on the status line regardless of what the upstream sent | `response_policy.status_reason: .canonical` (`response_envoy_h1`, PR4) looks up the reason phrase from a fixed table mirroring `CodeUtility::toString` (`source/common/http/codes.cc`, Envoy v1.39.1) byte for byte, covering every status the `header_order: .upstream` admission accepts (200..599 minus the no-body exclusions 204/205/304); a status Envoy's table does not name (e.g. 299) gets `"Unknown"`, matching `CodeUtility::toString`'s own fallthrough, instead of being rejected (Codex round-11 review of #698; `tests/test_network.cc: response_policy.upstream_header_order_canonical_reason_covers_admitted_domain`) | PARTIAL |
| Response header order matches the upstream's original order (Envoy does not reorder) | `response_policy.header_order: .upstream` (`response_envoy_h1`, PR4) preserves upstream order for every header it passes through (hop-by-hop names and hidden names are dropped; `server`/`date` handled as above) | PARTIAL |
| Hop-by-hop headers removed on the downstream response: `connection`, `keep-alive`, `proxy-connection`, `upgrade`, `transfer-encoding` — a fixed set of exactly five names, not a scan of the upstream's own `Connection` value and not including `te`/`trailer` (Codex round-19 review of #698, correcting a round-9-era over-broad set in this row and in the runtime). Envoy's `mutateResponseHeaders` (source/common/http/conn_manager_utility.cc) only calls `removeConnection`/`removeUpgrade`/`removeTransferEncoding`/`removeKeepAlive`/`removeProxyConnection` — five calls, never `removeTE`/a `Trailer` removal: `TE` (`Headers::get().TE`) is request-only (`INLINE_REQ_STRING_HEADERS`) and `removeTE()` is called solely from `mutateRequestHeaders` (conn_manager_utility.cc:348); `Trailer` has no inline slot and no `remove*()` call anywhere in that file or the HTTP/1 codec's response encoding path (source/common/http/http1/codec_impl.cc) — both are ordinary headers Envoy forwards unchanged on a fixed-length response. The token-list scan that additionally strips headers *named by* a `Connection: a, b` value (`Utility::sanitizeConnectionHeader`) takes a `RequestHeaderMap` and runs only on the request direction (`ServerConnectionImpl::onHeadersCompleteBase`), never on a response | `response_policy.header_order: .upstream` (`response_envoy_h1`, PR4) strips exactly that five-name fixed set (plus `hide_headers`); `te` and `trailer` are forwarded like any other ordinary header (unit-tested: `response_policy.upstream_header_order_forwards_te_and_trailer_response_fields`, a `Trailer: X-Checksum` + `TE: trailers` response reaching the client unchanged). This profile does not additionally scan the upstream's `Connection` value, matching Envoy's own asymmetry between the request and response directions. `hide_headers` can never suppress `Content-Length` (the sole framing field this profile admits) regardless of what it names. `content-length` is verified byte for byte against `post_fixed` in the recorded oracle; the request-direction Connection-nomination case (`get_hop_by_hop`) is also in the transcript, but no response-direction case is recorded because Envoy does not implement that behavior | PARTIAL |
| `x-envoy-upstream-service-time` response header | no policy exposes a measured value; the `suppress_envoy_headers: true` shape avoids it instead (milestone-S) | BLOCKED_BY_RUT |
| `x-forwarded-proto: http` on the upstream request | `request_policy.forwarded_proto: .http` (`request_envoy_h1`, PR3) is implemented; per the Envoy oracle (`Utility::schemeIsValid`) it keeps a client-supplied `x-forwarded-proto` unchanged in place when its trimmed value is case-insensitively exactly `http`/`https`. An empty, OWS-only, or otherwise invalid value (e.g. `http,https`, `ftp`) is overwritten in place, at that field's original physical position, with `x-forwarded-proto: http` -- matching Envoy's own inline (O(1) slot) storage for this header, which is overwritten rather than cleared and re-appended -- and `x-forwarded-proto: http` is appended as the last header only when the client sent no `x-forwarded-proto` field at all. The append-when-absent and preserve-when-valid halves are now confirmed against the real pinned Envoy binary: the append-when-absent path by `get_smoke`, whose client request sends no `x-forwarded-proto` (CI run `36069445967`, zero skips), and the preserve-when-valid path by `get_hop_by_hop`'s client-supplied `X-Forwarded-Proto: https` (asserted and passing in run `36070125213`, zero skips); the invalid-value-overwritten-in-place nuance itself is not exercised by either pinned pair case and remains covered only by the wire/unit oracle tests. Subject to the same re-run-pending caveat as the pair case table below | SUPPORTED |
| `x-envoy-expected-rq-timeout-ms` on the upstream request | no RUT equivalent; removed by `suppress_envoy_headers: true` (milestone-S) instead of emitted | BLOCKED_BY_RUT |
| Route timeout 15s default over the whole response, disabled entirely by `timeout: "0s"` | `timeout: "0s"` (milestone-S) removes the *default*, but Rut still enforces its own fixed 30s `kDefaultUpstreamTimeout` from upstream-connect-completion to the first response byte regardless of the route's `timeout` (`include/rut/runtime/epoll_event_loop.h:215-224`) and returns a 504 if response bytes do not arrive; a present non-zero `timeout` has no RUT surface at all. The pair differential's cases all respond immediately, so their passing result does not exercise this and does not eliminate the divergence: an upstream slower than 30s to produce headers gets a Rut 504 where Envoy (`timeout: "0s"`) would wait indefinitely — accepting `"0s"` is not behavioral equivalence, only a documented, bounded PARTIAL | PARTIAL |
| Cluster `connect_timeout` (positive, millisecond precision); Envoy's field is optional (proto default 5s, `(validate.rules).duration = {gt {}}`, not `required: true`) but this frontend's own parser requires it present | parsed and validated, but not enforced: Rut has no connect-establishment timeout surface at all — the fixed 30s `kDefaultUpstreamTimeout` bounds connect-completion-to-first-byte, not TCP connect (`include/rut/runtime/event_loop.h`). Since the parser already requires the field, rejecting it would make the milestone unreachable for no gain; `rut-envoy-convert` instead accepts and prints a stderr warning naming the ignored value (D2) | PARTIAL |
| HTTP1-only HCM rejects a client that opens with the h2c connection preface | Rut's cleartext `listen` always recognizes the preface and upgrades (`include/rut/runtime/callbacks_impl.h`, `on_header_received`); `AstListenDecl` has no protocol field to disable it. Verified live: a raw preface + `SETTINGS` frame against a plain `listen` gets an HTTP/2 `SETTINGS` reply. This is permissive, not fail-closed (PR #692 round-7 review): every milestone HCM requires `codec_type: "HTTP1"`, so gating this behind a `RutCapabilities` flag would block every conversion over a per-connection client shape, not a configuration Rut cannot express; `rut-envoy-convert` instead proceeds and prints a stderr warning after a successful conversion (`helpers/envoy/main.cc`, same style as the `connect_timeout` warning, D2 above). Closing the gap for real needs a listener protocol option in Rut | BLOCKED_BY_RUT |
| Chunked request bodies (`Transfer-Encoding: chunked`) forwarded by Envoy | Rut's `Http11FixedStrip` request-policy admission rejects any request carrying `Transfer-Encoding` with `400` before the upstream ever sees the connection (verified live); fail-closed, not mis-forwarded | BLOCKED_BY_RUT |
| Chunked or close-delimited upstream responses forwarded by Envoy | `response_policy.framing` has exactly one legal value, `content_length` (`ResponsePolicyFraming`); a non-content-length upstream response is rejected `502` before any byte reaches the client (verified live); fail-closed, not mis-forwarded | BLOCKED_BY_RUT |
| Unmatched route → 404 with empty body, lowercase headers | `local_response` `header_order: .dateServerLength` (`local_reply_envoy_h1`, PR5) is implemented: `date, server, [connection: close,] content-length: 0`. `OPTIONS *` is unit/wire- and end-to-end-tested byte for byte against the recorded Envoy oracle. Authority-form `CONNECT` gets only partial layout coverage: the end-to-end test (`tests/test_integration.cc:25672-25695`) checks the status line, `date`, `server`, and trailing `content-length: 0` individually rather than a full-buffer comparison against `kEnvoyOracle_connect_authority_downstream`, because Rut omits Envoy's `connection: close` (Rut has no CONNECT-specific persistence override, so a keep-alive CONNECT request stays keep-alive; documented below). `OPTIONS *` is SUPPORTED by the pair differential (run `36070125213`, zero skips); the authority-form CONNECT row stays PARTIAL for the `connection: close` difference only | SUPPORTED for `OPTIONS *`; PARTIAL for CONNECT |
| Connect failure → 503 `upstream connect error or disconnect/reset before headers. reset reason: remote connection failure` (Envoy's exact text) | `failure_policy` `header_order: .lengthTypeDateServer` (`local_reply_envoy_h1`, PR5) admits status 503 with `content-length, content-type, date, server, [connection: close]` and the oracle's exact 98-byte body; unit/wire- and end-to-end-tested (connect-refused) byte for byte against the recorded Envoy oracle. 502 stays exactly today's Synthesized-only contract. Pinned Envoy v1.39.1 pair differential, CI run `36069445967`, zero skips | SUPPORTED |
| Timeout → 504 `upstream request timeout` | no RUT route-timeout surface exists yet (PR12: admit a timeout request-policy ID and `header_order: .upstream` into `response_read_deadline`) | BLOCKED_BY_RUT |

## Envoy-vs-generated-RUT pair differential (envoy-pr-plan.md PR 6)

`tests/test_envoy_differential.cc --pair-milestone-s` runs the milestone-S
bootstrap through the pinned Envoy image and, separately, through
`rut-envoy-convert` piped into the real `rut` binary, on the same
listener/upstream ports against the same recording upstream, and compares
upstream bytes and downstream bytes exactly (only a synthesized `date:`
header value is normalized before the downstream comparison; the preserved
`date` in `get_upstream_date_server` is compared unnormalized). It registers
as CTest `test_envoy_pair_milestone_s` (`integration;envoy;docker`,
`RESOURCE_LOCK envoy-differential`, `SKIP_RETURN_CODE 77`), runs in the
`envoy-required` CI job, and uploads its transcript as the
`envoy-pair-transcript` artifact (`build/envoy_pair_milestone_s.inc`). It has
run in CI twice: run `36069445967` matched on the six then-asserted cases
(`get_smoke`, `get_upstream_date_server`, `get_client_close`, `head_smoke`,
`post_fixed`, `connect_failure`) with zero skips and additionally recorded
`get_hop_by_hop`, `trace` and `options_star` as equal, which promoted those
three to asserted; run `36070125213` then matched all nine asserted cases
with zero skips. `--self-test <rut> <rut-envoy-convert>` exercises the
identical comparison logic locally, without docker, against the committed
Envoy oracle fixture, and passes for all nine asserted cases as of this
revision (see the internal evidence notes below).

Each row below stays `PARTIAL` (or lower) until a passing CI run of
`test_envoy_pair_milestone_s` (zero skips) for that exact case is cited by
run id; the lead promotes a row to `SUPPORTED` at that point, not before.
`connect_authority` is not asserted and is not promoted by either run; nor
are the three forged-header cases below it (`get_forged_envoy_internal`,
`get_forged_xfcc`, `get_forged_envoy_external_address`) -- none of the four
is in `kAssertedCaseNames` (tests/test_envoy_differential.cc), so all four
run record-only and none gates the CTest's exit code.

**Re-run pending (round-6 review):** runs `36069445967` and `36070125213`
both predate this round's hardening of the pair harness itself --
`compare_pair_case` now requires exactly one upstream contact on both sides
for every case expected to forward (not just matching, possibly-empty,
bytes), `EnvoyInstance::stop()` now detects an Envoy/docker child that exited
before intentional teardown, `RutInstance::stop()` now verifies the reaped
exit status rather than trusting any status `waitpid` returns, and
`read_http_message` now checks persistent (non-close) responses for
erroneous trailing wire bytes the same way it already checked close-delimited
ones. The `SUPPORTED` rows below were promoted under the weaker, pre-hardening
harness, so they are not being silently demoted, but they are not yet
re-validated under the strengthened one either: the next CI run of
`test_envoy_pair_milestone_s` with this harness re-validates every promoted
case, the lead will record that run's id here once it lands, and the pair
test now fails loudly (not silently) if any promoted case mismatches under
the stricter checks.

| Pair case | method/path | parser | converter | RUT capability | asserted | status |
| --- | --- | --- | --- | --- | --- | --- |
| GET smoke (headers pass through lowercased, `x-forwarded-proto` appended) | `GET /smoke?q=1` | yes | yes | yes (`request_envoy_h1`, `response_envoy_h1`) | yes | SUPPORTED (pinned Envoy v1.39.1 pair differential, CI run `36069445967`, zero skips; upstream and downstream bytes equal after normalizing only the synthesized `date` value) |
| Upstream `date`/`server` preservation and canonical reason phrase | `GET /date` | yes | yes | yes (`response_envoy_h1`) | yes | SUPPORTED (pinned Envoy v1.39.1 pair differential, CI run `36069445967`, zero skips; upstream and downstream bytes equal after normalizing only the synthesized `date` value) |
| Client close (`connection: close` appended downstream) | `GET /close` | yes | yes | yes (`response_envoy_h1`) | yes | SUPPORTED (pinned Envoy v1.39.1 pair differential, CI run `36069445967`, zero skips; upstream and downstream bytes equal after normalizing only the synthesized `date` value) |
| HEAD (body suppressed both sides) | `HEAD /head` | yes | yes | yes (`response_envoy_h1` `head_mode`) | yes | SUPPORTED (pinned Envoy v1.39.1 pair differential, CI run `36069445967`, zero skips; upstream and downstream bytes equal after normalizing only the synthesized `date` value) |
| Fixed-length POST | `POST /upload` | yes | yes | yes (`request_envoy_h1`, `response_envoy_h1`) | yes | SUPPORTED (pinned Envoy v1.39.1 pair differential, CI run `36069445967`, zero skips; upstream and downstream bytes equal after normalizing only the synthesized `date` value) |
| Connect failure → 503 with Envoy's exact body | `GET /smoke` against a closed upstream port | yes | yes | yes (`local_reply_envoy_h1` `failure_policy`) | yes | SUPPORTED (pinned Envoy v1.39.1 pair differential, CI run `36069445967`, zero skips; upstream and downstream bytes equal after normalizing only the synthesized `date` value) |
| Hop-by-hop handling on one request: `Connection`, `Keep-Alive`, `Proxy-Connection` removed; the one `Connection`-nominated token this case sends, `X-Drop-Me`, removed; `TE: trailers` preserved (rewritten to lowercase), not stripped | `GET /hop` | yes | yes | yes (`request_envoy_h1`) | yes | SUPPORTED for exactly this case's shape (pinned Envoy v1.39.1 pair differential; record-only equal in run `36069445967`, asserted and passing in run `36070125213`, zero skips; bytes equal after normalizing only the synthesized `date` value). Scoped, not general: the `Connection`-nomination coverage is the tested token `X-Drop-Me` only, not Connection-nomination in general -- a token naming `content-length`, for example, fails the whole request closed instead of matching Envoy's remove-and-forward behavior (see the Blocked-by-Rut row above, line 209); and the `TE` coverage is `trailers`-token preservation specifically, not every `TE` value. |
| TRACE | `TRACE /trace` | yes | yes | yes (ordinary forward path) | yes | SUPPORTED (pinned Envoy v1.39.1 pair differential; record-only equal in run `36069445967`, asserted and passing in run `36070125213`, zero skips; bytes equal after normalizing only the synthesized `date` value) |
| OPTIONS * (unmatched → 404) | `OPTIONS *` | yes | yes | yes (`local_reply_envoy_h1` `local_response`) | yes | SUPPORTED (pinned Envoy v1.39.1 pair differential; record-only equal in run `36069445967`, asserted and passing in run `36070125213`, zero skips; bytes equal after normalizing only the synthesized `date` value) |
| CONNECT authority-form (unmatched → 404) | `CONNECT example.com:443` | yes | yes | yes (`local_reply_envoy_h1` `local_response`) | no (record-only) | PARTIAL (record-only; run `36069445967` shows the one difference: Envoy adds `connection: close` to the 404 and closes, Rut keeps the connection open because its local-response persistence rule does not look at the method) |
| Client-forged `X-Envoy-Internal: true` request header stripped before forwarding | `GET /internal` | yes | yes | yes (`request_envoy_h1`; ID4's `request_policy_is_stripped_client_envoy_header()`, `include/rut/runtime/callbacks_impl.h`, already lists `x-envoy-internal` on this branch and strips it unconditionally, matching Envoy's own `removeEnvoyInternalRequest()` behavior for this milestone's fixed `internal_request == false` shape -- see the milestone table above) | no (record-only) | PARTIAL (record-only; expected to MATCH on upstream bytes -- both sides strip this header unconditionally for this milestone config -- but stays below `SUPPORTED` until a pinned-Envoy CI run actually captures and confirms it, per this table's promotion rule) |
| Client-forged `X-Forwarded-Client-Cert` request header stripped before forwarding | `GET /xfcc` | yes | yes | yes (`request_envoy_h1`; same ID4 stripped set as `get_forged_envoy_internal` above -- `x-forwarded-client-cert` is already stripped unconditionally on this branch, matching Envoy's `forward_client_cert_details` defaulting to SANITIZE for this milestone) | no (record-only) | PARTIAL (record-only; expected to MATCH on upstream bytes for the same reason as `get_forged_envoy_internal` above, but stays below `SUPPORTED` until a pinned-Envoy CI run actually captures and confirms it) |
| Client-supplied `X-Envoy-External-Address` request header handling | `GET /external-address` | yes | yes | yes (`request_envoy_h1`; RUT strips this unconditionally, PR #696 round-8 fix ID4) | no (record-only) | PARTIAL (record-only; RUT's unconditional stripping is intentional hardening, but pinned Envoy's own behavior for this milestone's exact config (`use_remote_address: false`) is unresolved -- a worker's reading of Envoy v1.39.1 source found it does NOT remove a client-supplied value in that configuration, contradicting an earlier review's claim that it does. This case records what the pinned Envoy image's upstream bytes actually show; a pinned-Envoy CI run settles the disagreement and determines whether RUT's stripping matches Envoy or is a documented divergence) |

## Not planned in the converter

| Envoy feature | reason |
| --- | --- |
| xDS (`dynamic_resources`, ADS, REST) | control-plane transport belongs to `rut-master` and the Istio helper, not to the converter |
| Envoy admin interface, stats names, access-log format strings | out of scope per docs/envoy-converter.md |
| Non-router HTTP filters (`lua`, `wasm`, `ext_authz`, `ratelimit`, `fault`, ...) | each is a separate capability decision; none is planned for the static converter |

## Internal evidence notes

- Increment 1 (this matrix's first revision): `rut_envoy` library with the
  bounded JSON document parser (`helpers/envoy/include/rut/envoy/json.h`, 4096 nodes, depth
  32, no comments/trailing commas/duplicate keys, escapes validated but never
  decoded, raw string bytes validated as well-formed UTF-8 per RFC 3629
  including lone-surrogate `\uXXXX` escapes) and the milestone semantic
  model. `test_envoy_parser` covers the accepted document, camelCase
  aliasing, optional fields, and 100+ rejection vectors with key-anchored
  spans. No RUT is emitted.
- Increment 2: `rut::envoy::lower_to_rut` and the `rut-envoy-convert` CLI.
  Capability validation (`rut::envoy::RutCapabilities`) gates six
  `BLOCKED_BY_RUT` checks in a fixed order. At increment 2 the shipped table
  was all-`false`, so the CLI failed closed on every input, including
  milestone-S, until PR3-PR5 landed the request/response/local-reply
  capabilities; a test-only overload with all capabilities `true` pinned the
  target RUT text byte for byte (`tests/fixtures/envoy_milestone_s.inc`,
  checked by `tests/test_envoy_convert.cc`) so the golden shape did not drift
  ahead of those PRs. As of PR5, `kShippedRutCapabilities` is all `true` and
  the shipped `rut-envoy-convert` binary converts the milestone-S bootstrap
  end to end (`cli_milestone_s_converts`); no pinned-Envoy differential
  evidence exists yet (PR6).
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
- Increment 4 lowering (PR 8): `rut::envoy::lower_to_rut` now accepts an
  ordered route list of any size up to `kMaxEnvoyRoutes` and multiple
  clusters, lowering them by construction (owner decision D3) instead of
  rejecting the shape; `direct_response` and `redirect` are still rejected.
  Fixture files `tests/fixtures/envoy_routes_{a,b,c,f}.inc` and
  `envoy_routes_shadowed_siblings.inc` exist (all capabilities `true`), and
  (b), (c), (f) (added by Codex sweep-11 review; see below), and the
  shadowed-siblings fixture are byte-exact goldens pinning `lower_to_rut`'s
  output against them (`golden_routes_b_root_then_prefix`:
  catch-all `/` declared before prefix `/api/` -- since the round-9 fix
  below, `/api` is globally shadowed and dropped, so this golden is now
  root-only; `golden_routes_c_exact_then_root`: exact `/healthz` declared
  before catch-all `/`; `shadowed_siblings_dropped_before_registration`:
  Codex's own round-9 example, `/` declared before both `/api/` and
  `/admin/`, also root-only). Scenario (a) — prefix `/api/` declared BEFORE
  the catch-all `/` — lowers to a byte-valid program under
  `RutSource::kCapacity` (128 KiB): back when the compiler frontend's own
  lexer token budget (`LexedTokens::kMaxTokens`, `include/rut/compiler/
  lexer.h`) was 932, `envoy_routes_a.inc`'s 8804-byte text exceeded it
  (`TooManyTokens` at byte 8400), so `golden_routes_a_prefix_then_root`
  asserted that rejection instead of pinning output. Sweep-8: #697 raised
  `kMaxTokens` to 4096, under which this exact text lexes to 963 tokens, so
  `golden_routes_a_prefix_then_root` is a byte-exact golden success case
  again, the same shape as (b)/(c). `token_budget_goldens_match_the_real_
  lexer` checks the converter's conservative token-count estimate
  (`estimate_conservative_token_count` in `helpers/envoy/converter.cc`) against
  the real lexer for all three fixtures, all of which now lex successfully.
  Three further in-bounds shapes still fail closed instead of lowering,
  each covered by a failure test rather than a golden: (1) A lone
  `prefix: "/api/"` with no catch-all declared leaves the literal
  path `/api` itself with no Envoy route, and `route exact` cannot stand in
  for that 404 (its strict local-response admission does not serve every
  method — TRACE/CONNECT close the connection instead of responding), so
  `build_node_plan` fails closed as `BLOCKED_BY_RUT`
  (`blocked_on_node_own_literal_needs_all_method_fallback`, formerly golden
  (d)). (2) The same shape with an exact route declared under the prefix
  (permanently shadowed and dropped from the output) fails closed the same
  way (`blocked_on_shadowed_exact_needs_all_method_fallback`, formerly
  golden (e)). (3) A root with only exact routes (e.g. `/healthz`) and no
  catch-all has the same no-RUT-form-for-a-404 problem at the root's own
  fallthrough — the 404 no-route case —
  (`blocked_root_exact_arms_without_catch_all`). Scenario (f) — an exact
  route declared before its own prefix for the same literal
  (`golden_routes_f_exact_then_own_prefix_not_blocked`) — is also still
  lowered. It originally pinned only four output substrings, not a
  byte-exact golden, even though a summary elsewhere in this same document
  (the route-list table row above) already described (b)/(c)/(f) together as
  "byte-for-byte" — Codex sweep-11 review flagged that mismatch. `tests/
  fixtures/envoy_routes_f.inc` now backs it with the same kind of byte-exact
  golden as (b)/(c), so that claim is accurate; the four substring checks
  stay alongside it as cheaper, more readable documentation of the specific
  shape. A root with no arms at all simply omits `route "/"` and falls
  through to the `unmatched` policy
  (`root_omitted_without_catch_all_or_exact_arms`). A further still-lowered
  scenario IS ALSO byte-exact: two identical exact routes for
  the same literal declared back to back before a catch-all (e.g.
  `/healthz`, `/healthz`, then `/`) used to make `build_node_plan` emit a
  second, unreachable conditional arm plus a duplicated forwarding policy —
  dead weight that could push an otherwise in-budget arm chain past the
  lexer's token limit (Codex round-8 review). `build_node_plan` now tracks
  exact match texts already emitted for a node (`has_exact_arm`,
  `helpers/envoy/converter.cc`) and drops the later duplicate, so this shape
  lowers to output byte-identical to scenario (c)'s golden
  (`golden_routes_g_duplicate_exact_deduped`), reusing
  `tests/fixtures/envoy_routes_c.inc` rather than adding a fourth fixture. A
  brute-force test separately compares Envoy's real first-match semantics
  against an independent reimplementation of the "longest node, then arm
  chain" structure over ~40 probe paths. The lex/parse/analyze/MIR/RIR
  round-trip these goldens will eventually need is deferred to PR3-PR5 (see
  the TODO in `tests/test_envoy_convert.cc`): today's parser does not yet
  accept the `local_response` fields the goldens use, and the single-route
  milestone-S golden already fails the same way, so this is not a PR8
  regression. No differential evidence exists yet.
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
- Round-9 review (Codex on PR #695): a `prefix` route globally shadowed by
  an EARLIER `prefix` route (Envoy's byte-prefix match, not just Rut's
  segment-boundary "under" relation, makes every request the later route
  could match already resolve through the earlier one) used to still be
  registered as its own node, emitting a full dead HEAD/any-method
  forwarding block that only ever forwarded through the earlier route's own
  cluster -- Codex's reported example, `"/"` declared before distinct
  siblings `"/api/"` and `"/admin/"`, cost about 938 real lexer tokens (over
  the 932-token `LexedTokens::kMaxTokens` budget) versus about 356/364 for
  the equivalent root-only program. `build_lowering_plan` now drops such a
  node before it is ever registered (`is_strict_ancestor` against nodes
  already kept earlier in declaration order -- see the "Global shadowing
  rule" paragraph at the top of this section), generalizing the original
  root-only report to any earlier, textually-shorter accepted prefix.
  `golden_routes_b_root_then_prefix` (golden (b)) is now root-only
  (`tests/fixtures/envoy_routes_b.inc` updated, token count 655 -> 360), and
  `shadowed_siblings_dropped_before_registration` pins Codex's own
  three-route example byte for byte
  (`tests/fixtures/envoy_routes_shadowed_siblings.inc`, 364 real lexer
  tokens). `prefix_shadowed_by_earlier_prefix_dropped` and
  `prefix_shadowed_exact_path_arm_dropped` cover the general (non-root)
  prefix-shadows-prefix and prefix-shadows-exact-path cases as clean
  successes (an own-literal exact route resolves each surviving node's
  bare-literal gap instead of a root catch-all, since two real if/else-shaped
  nodes together already exceed the current token budget -- confirmed by
  direct measurement, unrelated to this fix).
  `specific_prefix_before_general_prefix_keeps_both` /
  `general_prefix_before_specific_shadows_specific` are a matched pair
  proving declaration order, not text length, decides shadowing: the same
  three routes with the specific prefix declared first keep both nodes
  (asserted via the resulting `TooManyTokens` failure, since a
  `BLOCKED_BY_RUT` failure happens during planning before any RUT text is
  generated, and a single surviving node this shape would fit comfortably
  under budget), while declaring the general prefix first shadows the
  specific one and succeeds well under budget with only the general node
  emitted.
- PR 6 (envoy-pr-plan.md): added `--pair-milestone-s` to
  `tests/test_envoy_differential.cc` (Envoy first, then `rut-envoy-convert` +
  `rut`, on the same ports against the same recording upstream, sequential;
  see the pair-differential section above) and the `test_envoy_pair_milestone_s`
  CTest entry (gated on `RUT_ENABLE_JIT`, same as the `rut`-binary nginx
  differential tests). Also extended `--self-test` with a RUT-only pass
  (`--self-test <rut> <rut-envoy-convert>`) that runs the same six asserted
  cases through the real `rut` binary against the in-process recording
  upstream and compares them, date-normalized, against the committed Envoy
  oracle fixture (`tests/fixtures/envoy_oracle_milestone_s.inc`) -- no docker
  needed. Locally (no docker in this environment) that pass matched the
  oracle byte for byte on all six asserted cases (`get_smoke`,
  `get_upstream_date_server`, `get_client_close`, `head_smoke`, `post_fixed`,
  `connect_failure`); `--pair-milestone-s` itself skips (77) here for lack of
  docker and has not yet run in CI. No status changes in this PR; every pair
  row above stays `PARTIAL` until a passing `envoy-required` CI run of
  `test_envoy_pair_milestone_s` is cited by run id.
- Promotion, CI run `36069445967`: the `envoy-required` job ran
  `test_envoy_pair_milestone_s` against pinned Envoy v1.39.1 with zero skips.
  The six then-asserted cases matched, and the transcript additionally showed
  `get_hop_by_hop`, `trace` and `options_star` equal, so those three moved
  from record-only to asserted (`kAssertedCaseNames` grew from six to nine
  entries, mirrored in `--self-test`'s RUT-vs-oracle pass). The milestone
  table rows and the `connect_failure`/six originally-asserted pair rows were
  promoted to `SUPPORTED` with this run id; `get_hop_by_hop`, `trace` and
  `options_star` stayed `PARTIAL` pending a run where they are asserted.
  `connect_authority` stays record-only: Envoy adds `connection: close` to
  that 404 and closes, Rut does not.
- Promotion, CI run `36070125213`: the `envoy-required` job ran
  `test_envoy_pair_milestone_s` again, now asserting all nine cases, and
  matched with zero skips. The `get_hop_by_hop`, `trace` and `options_star`
  pair rows were promoted to `SUPPORTED` with this run id. `connect_authority`
  remained the only non-asserted, `PARTIAL` pair row at this point.
- The harness later added three more record-only cases --
  `get_forged_envoy_internal`, `get_forged_xfcc` and
  `get_forged_envoy_external_address` (none is in `kAssertedCaseNames`) --
  so `connect_authority` is no longer the sole non-asserted pair row; all
  four stay `PARTIAL` pending the pinned-Envoy CI evidence each row above
  names. No status changes from this addition alone.
