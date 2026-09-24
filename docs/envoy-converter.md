# Envoy converter architecture

## Goal

The Envoy converter is a compatibility frontend for static Envoy bootstrap
configuration. It follows the same contract as the nginx converter
([nginx-converter.md](nginx-converter.md)): a configuration is accepted only
when every field that affects the supported behavior has a validated Envoy
semantic representation and an equivalent RUT lowering. Unsupported input is a
source-located diagnostic, never a no-op, and a generated program never
silently changes the behavior Envoy would have had.

This document covers the static-configuration route only. The following are
explicitly out of scope and are not implied by anything below:

- xDS (LDS/CDS/RDS/EDS/SDS) over gRPC or REST, and any control-plane protocol;
- Istio or other mesh sidecar integration, `SO_ORIGINAL_DST` transparent
  proxying, SDS certificate delivery;
- the Envoy admin interface (`/stats`, `/clusters`, `/config_dump`), Envoy
  stats naming, and Envoy access-log format strings;
- Envoy extension filters other than the terminal router filter;
- HTTP/2 or HTTP/3 downstream/upstream, gRPC, TLS on either side.

DESIGN.md §16 describes a Rut-native mesh control plane that pushes compiled
code, endpoints and certificates over HTTP. The converter does not change that
direction; it gives existing Envoy users a migration path for static
configuration and produces the same kind of ordinary RUT source that a control
plane would compile.

The converter has three consumers. The first is the single `rut` binary
converting a bootstrap file. The second is `rut-master`, which accepts Envoy
v3 JSON resources through its submission API and compiles the generated RUT
for distribution to compiler-less nodes. The third is an Istio helper program
outside this repository that speaks xDS to istiod and submits the received
resources to `rut-master` as v3 JSON. Only the helper speaks gRPC; the
semantic model here must therefore cover the resource shapes istiod emits, not
only hand-written bootstraps, and its `BLOCKED_BY_RUT` rows double as the
Istio compatibility backlog.

## Input format

Envoy accepts its bootstrap as YAML or JSON. Both are the proto3 JSON mapping
of `envoy.config.bootstrap.v3.Bootstrap`; YAML is only a surface encoding.

The converter accepts the JSON encoding first. Reasons:

- The runtime has no YAML, JSON or protobuf parser and no C++ standard
  library. A bounded JSON parser is the smaller piece of infrastructure and is
  also needed later for `req.body(T)` and `json()`, which the language card
  lists as pending.
- A YAML subset parser can be added as a separate front stage that produces the
  same JSON-shaped document tree. Adding it must not touch the semantic model.

Only the v3 API is accepted. Every `typed_config` must carry an `@type` URL and
the URL is part of the semantic model; an unknown `@type` is an unsupported
diagnostic. `deprecated_v2_api` fields, `api_version` other than `V3`, and any
`envoy.api.v2` type URL are rejected.

Input is one regular file no larger than 1 MiB, kept alive through parsing and
lowering. The converter does not read stdin, resolve `$ref`-style includes,
execute generated RUT, open listeners, or infer the format from file contents.

## First behavioral milestone

The first accepted configuration is the Envoy equivalent of the nginx
`listen 8080 + proxy_pass` fragment: one HTTP listener, one wildcard virtual
host, one catch-all route, one static cluster with one endpoint.

```json
{
  "static_resources": {
    "listeners": [{
      "name": "ingress",
      "address": {"socket_address": {"address": "0.0.0.0", "port_value": 8080}},
      "filter_chains": [{
        "filters": [{
          "name": "envoy.filters.network.http_connection_manager",
          "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
            "stat_prefix": "ingress",
            "generate_request_id": false,
            "route_config": {
              "name": "local",
              "virtual_hosts": [{
                "name": "all",
                "domains": ["*"],
                "routes": [{
                  "match": {"prefix": "/"},
                  "route": {"cluster": "backend"}
                }]
              }]
            },
            "http_filters": [{
              "name": "envoy.filters.http.router",
              "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}
            }]
          }
        }]
      }]
    }],
    "clusters": [{
      "name": "backend",
      "type": "STATIC",
      "connect_timeout": "5s",
      "load_assignment": {
        "cluster_name": "backend",
        "endpoints": [{
          "lb_endpoints": [{
            "endpoint": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": 9000}}}
          }]
        }]
      }
    }]
  }
}
```

`generate_request_id: false` is part of the milestone input rather than a test
normalization. With the default `true`, Envoy injects a random UUID
`x-request-id` into the upstream request, which cannot be compared byte for
byte and which Rut does not generate. Configurations that leave request-id
generation on are rejected until Rut has an equivalent, so that the milestone
does not hide a behavioral difference behind a diff filter.

Support for arbitrary bootstrap files is not implied. An `admin` block, a
`node` block, `dynamic_resources`, `layered_runtime`, `stats_sinks`,
`overload_manager`, `tracing`, and every other top-level field are rejected in
the first increment; they are not ignored.

## Implemented pipeline (target)

```text
Envoy bootstrap JSON
  -> bounded JSON document parser (source spans on every value)
  -> Envoy semantic model (v3 proto shapes, typed by @type URL)
  -> capability validation
  -> RUT source emission
  -> existing RUT lexer -> AST -> HIR -> MIR -> RIR -> JIT/runtime
```

The frontend lives in a separate `rut_envoy` library under `src/envoy/` with
headers in `include/rut/envoy/`, mirroring `src/nginx/`. It must not be added
to the RUT parser. Lowering happens only after the whole accepted document has
passed capability validation, and the converter never constructs `RouteConfig`
directly. If a model value cannot be expressed in RUT source, the feature is
`BLOCKED_BY_RUT` and direct HIR construction is not a fallback.

Output is an owned, bounded `RutSource` buffer with the same strict completion
rule as the nginx converter (`len < kCapacity`, overflow is a diagnostic). The
CLI is:

```text
rut-envoy-convert --format bootstrap-json <input-file>
```

Exit status follows the nginx CLI: 0 success, 2 usage/format error, 1 input,
allocation, parse, lowering or output failure. A conversion failure writes no
program bytes. Diagnostics go to stderr as `file:line:column: detail`; JSON
values carry their own spans so a diagnostic points at the offending field,
not at the enclosing object.

## Semantic model boundary for the first increment

The first parser increment represents, but does not yet lower:

- exactly one listener with one `socket_address`, IPv4 literal, TCP, no
  `additional_addresses`, no `listener_filters`, no `transport_socket`;
- exactly one filter chain with no `filter_chain_match`, containing exactly one
  network filter, which must be the HTTP connection manager;
- HCM: `stat_prefix`, inline `route_config`, `generate_request_id: false`,
  `http_filters` containing exactly the router filter last, no `codec_type`
  other than omitted or `AUTO`/`HTTP1`, no `access_log`, no `tracing`, no
  `common_http_protocol_options`, no `server_name` /
  `server_header_transformation` overrides, no `use_remote_address`,
  no `xff_num_trusted_hops`;
- route config: exactly one virtual host whose `domains` is exactly `["*"]`,
  with exactly one route whose match is `prefix: "/"` and whose action is
  `route.cluster` naming a declared cluster, no `timeout` override, no
  `retry_policy`, no header mutations, no rewrites;
- exactly one cluster: `type: STATIC`, `connect_timeout`, one locality with one
  `lb_endpoints` entry with an IPv4 `socket_address`, no `lb_policy` other
  than omitted or `ROUND_ROBIN`, no `health_checks`, no `circuit_breakers`,
  no `outlier_detection`, no `transport_socket`, no
  `typed_extension_protocol_options`.

Every unknown field, duplicate key, unknown `@type`, unsupported enum value,
`Any` without `@type`, and every field outside this list produces a
source-located unsupported or invalid diagnostic. JSON whitespace is syntax.
Proto3 JSON accepts both `lowerCamelCase` and `snake_case` field names; the
model must accept both spellings for every supported field and treat them as
the same key for duplicate detection.

## Lowering shape

The milestone lowers to ordinary RUT of the following shape. Exact policy
values are recorded from the pinned Envoy oracle during increment 3, not from
this document.

```rut
listen 0.0.0.0:8080
upstream backend at "127.0.0.1:9000"
unmatched { return local_response({ ... Envoy "no route" 404 shape ... }) }
route "/" {
    return forward(backend, request_policy: {
            version: "HTTP/1.1",
            host: "preserve",
            connection: "omit",
            strip_headers: ["Connection", "Keep-Alive", "TE", "Expect", "Upgrade",
                            "Proxy-Connection", "Transfer-Encoding"]
        },
        set_header: {
            "x-forwarded-proto": "http",
            "x-envoy-expected-rq-timeout-ms": "15000"
        },
        response_policy: {
            version: "HTTP/1.1", framing: "content_length", connection: "request",
            server: "envoy", date: "preserve_or_current",
            hide_headers: [ ... ]
        },
        failure_policy: { ... Envoy 503 upstream connect error shape ... },
        timeout_failure_policy: { ... Envoy 504 upstream request timeout shape ... },
        response_read_timeout: 15s)
}
```

Fields shown with `...` or with values that do not exist in today's
`request_policy` / `response_policy` grammar (for example `host: "preserve"`)
are capability dependencies, listed below. The converter must fail closed on
them until the RUT side exists; it must not emit the nearest existing value.

## Envoy semantics the first end-to-end test must preserve

These are the observable behaviors of the milestone configuration that differ
from nginx defaults or from Rut's transparent `forward(...)`. Each one is
either lowered explicitly or is a `BLOCKED_BY_RUT` row. Byte-exact expectations
are recorded from the pinned Envoy build, not assumed.

**Routing**

- `prefix` match is a plain string prefix. `prefix: "/api"` matches `/apifoo`.
  Rut's route trie is segment-aware, so only `prefix: "/"` and prefixes ending
  in `/` have a segment-equivalent meaning. Other prefixes are `PARTIAL`
  until Rut offers a raw-prefix match, and the converter rejects them.
- Routes are evaluated in list order, first match wins. Rut selects the
  longest matching prefix. A route list is accepted only when the converter can
  prove list order and longest-prefix selection agree for every request, and
  it must reject lists where an earlier shorter prefix shadows a later longer
  one.
- Matching is against the path without query. `x-envoy-original-path` is not
  set unless a rewrite happens.
- No matching route: HCM responds 404 with an empty body and no route-level
  headers. No matching virtual host: also 404. Rut's shipped default for
  unmatched requests is a 200 handler, so the converter must emit explicit
  `unmatched` policies for every method and for the catch-all, as the nginx
  converter does.
- Envoy's HTTP/1 codec rejects `CONNECT` and absolute-form targets in specific
  ways, and TRACE is forwarded like any other method. Method-specific behavior
  is recorded per method and each method is a separate matrix row.

**Request to upstream**

- `Host` is preserved unchanged. There is no nginx-style rewrite to the
  upstream address. Rut's `request_policy.host` currently offers `"upstream"`
  only; a `"preserve"` value is a capability dependency.
- Envoy emits all header names in lowercase over HTTP/1.1 (default
  `header_key_format`). nginx and Rut preserve the client's case. This affects
  the recorded upstream bytes for every request and is a capability dependency
  on the request-policy grammar (a header-casing selector).
- Added headers: `x-forwarded-proto: http` and
  `x-envoy-expected-rq-timeout-ms: 15000` (the route timeout default). No
  `x-forwarded-for` is appended unless `use_remote_address: true`. No
  `x-request-id` when generation is disabled; a client-supplied one is passed
  through.
- Hop-by-hop headers are removed: `connection` and every header it names,
  `keep-alive`, `proxy-connection`, `transfer-encoding` when Envoy reframes,
  `te` unless `trailers`, `upgrade` outside an upgrade.
- Upstream codec is HTTP/1.1 with connection pooling. The upstream request
  carries no `connection` header. Bodies with `content-length` are forwarded
  with the same framing; chunked downstream bodies are forwarded chunked. The
  milestone covers bodyless and fixed-length requests only.
- Connect timeout is the cluster `connect_timeout`; route timeout defaults to
  15s and covers the whole upstream response, which maps to
  `response_read_timeout` only for header-only responses. Body-phase timeout
  semantics are recorded separately.

**Response to downstream**

- `server: envoy` overwrites any upstream `server` header
  (`server_header_transformation: OVERWRITE` default).
- `x-envoy-upstream-service-time: <ms>` is added; its value is
  nondeterministic. The oracle test must normalize only this value and `date`,
  or the configuration must set `suppress_envoy_headers: true` on the router
  filter and the converter must then omit the header. The second option is
  preferred because it removes a diff filter, but it also removes the
  `x-envoy-expected-rq-timeout-ms` upstream header, so both shapes are
  separate rows.
- `date` is added only when the upstream omits it; an upstream `date` is
  preserved. Rut's `date: "current"` overwrites, so the milestone either pins
  an upstream without `date` or records a `"preserve_or_current"` dependency.
- Hop-by-hop response headers are removed. `content-length` is preserved.
  Response header names are lowercased.
- Upstream connect failure: 503 with `content-type: text/plain` and body
  `upstream connect error or disconnect/reset before headers. reset reason:
  connection failure` (the exact text is pinned from the oracle). No healthy
  endpoint: 503 `no healthy upstream`. Route timeout: 504 `upstream request
  timeout`. Each is a `failure_policy` / `timeout_failure_policy` row.
- Downstream keep-alive follows the request (`connection: close` is honored;
  HTTP/1.1 default is keep-alive). The `connection` response header is emitted
  only for close.

## Test layers

1. Parser tests (`tests/test_envoy_parser.cc`): JSON document tree, field
   spans, camelCase/snake_case aliasing, `@type` dispatch, and fail-closed
   diagnostics for every field outside the boundary. Label
   `unit;envoy;compiler`.
2. Golden tests (`tests/test_envoy_convert.cc`): bootstrap JSON to
   deterministic RUT source through the `rut-envoy-convert` binary; the emitted
   source must lex and parse with the ordinary RUT frontend. Label
   `unit;envoy;converter`.
3. Differential tests (`tests/test_envoy_differential.cc`): a pinned Envoy image
   (`tests/pinned-envoy-image.txt`, `envoyproxy/envoy@sha256:...`, same
   64-hex validation as the nginx pin) and the generated RUT receive the same
   raw requests against recording upstreams. Compare client status, headers
   and body, and upstream method, version, request-target, headers and body,
   normalizing only `date` and, where a row says so,
   `x-envoy-upstream-service-time`. Labels `integration;envoy;docker`, serial,
   `RESOURCE_LOCK envoy-differential`. Envoy runs with `--concurrency 1`,
   `--disable-hot-restart`, no `admin` block, and the bootstrap file
   bind-mounted read-only. Local absence of docker or the image is an
   explicit skip; CI compatibility evidence cannot treat that skip as a pass.

The Envoy version and image digest used by every differential result must be
recorded. Envoy changes default header behavior across minor versions (for
example header casing options and `x-envoy-*` defaults), so a result from one
version is not evidence for another.

Compatibility claims are recorded in `docs/envoy-compatibility.md` with the
same columns and states as the nginx matrix:

```text
| Envoy feature | parser | converter | RUT capability | behavior test | status |
```

`SUPPORTED` requires differential evidence for the exact row. Golden output
alone is `PARTIAL` at most.

## Increments

1. Bounded JSON document parser with spans, Envoy semantic model for the
   milestone boundary, strict rejection of everything else. No RUT emission.
2. Capability validation and deterministic RUT lowering for the milestone
   model, using only RUT surface that exists today (`listen`, `upstream ... at`,
   `unmatched`, `route "/"`, `forward` with `request_policy`,
   `response_policy`, `failure_policy`, `timeout_failure_policy`,
   `set_header`, `response_read_timeout`). Rows that need a missing policy
   value stay `BLOCKED_BY_RUT` and the converter rejects the configuration.
3. First serialized differential smoke case: header-only HTTP/1.1 GET with a
   final `content-length` response, then fixed-length POST, connect failure,
   and route timeout, each as its own row.
4. Route matching: `path` exact match, `prefix` ending in `/`, multiple routes
   with provable ordering, per-method rows, `direct_response`, `redirect`.
5. Header mutation: `request_headers_to_add/remove`,
   `response_headers_to_add/remove` at route and virtual-host level with
   Envoy's append-vs-overwrite semantics, `prefix_rewrite`,
   `host_rewrite_literal`.
6. Cluster policy: multiple endpoints, `lb_policy` ROUND_ROBIN with weights,
   `health_checks` (HTTP), route `timeout`, `retry_policy` for
   `connect-failure` only, `circuit_breakers.max_requests`.
7. YAML subset front stage producing the same document tree, so `.yaml`
   bootstraps convert without a separate semantic model.

Later increments (multiple listeners, virtual-host `domains` matching,
`safe_regex` paths, header and query matchers, TLS transport sockets,
`STRICT_DNS` clusters, LEAST_REQUEST / RING_HASH, HTTP/2 upstream) each start
as `BLOCKED_BY_RUT` rows tied to a runtime capability issue.

## Known capability dependencies

Everything below is a Rut-side gap the milestone or the next increments hit.
Each needs its own issue before the corresponding row can leave
`BLOCKED_BY_RUT`.

- `request_policy.host: "preserve"`: Envoy never rewrites `Host`; Rut's policy
  grammar only offers rewriting to the upstream address.
- Header-name casing selector on request and response policies: Envoy emits
  lowercase names over HTTP/1.1.
- `response_policy.date: "preserve_or_current"`: add `date` only when absent.
- `response_policy.server: "envoy"` with overwrite semantics, and an explicit
  "pass through upstream `server`" mode for `server_header_transformation:
  PASS_THROUGH`.
- Route-level `set_header` on the upstream request is available for literal
  values; `x-envoy-upstream-service-time` on the response needs a runtime
  measured value, which no policy exposes. Until then only the
  `suppress_envoy_headers: true` shape can be `SUPPORTED`.
- Raw (non-segment) prefix match for `prefix` values not ending in `/`.
- Explicit route-list ordering: Rut resolves by longest prefix. Either the
  converter proves equivalence or the runtime gains an ordered fallback list.
- Host / virtual-host routing: no host dimension in the route trie today.
- Configurable connect, response and idle timeouts per upstream and per route.
  Today only whole-second `response_read_timeout` exists; Envoy defaults are
  `connect_timeout` per cluster and 15s per route. Body-phase timeout and
  `idle_timeout` have no Rut surface.
- Retry policy by status/reset with `num_retries` and `per_try_timeout`; today
  only connect-failure retry with a fixed attempt cap exists.
- `circuit_breakers` and `outlier_detection` values: the mechanisms exist with
  hardcoded constants and a C++-only `max_inflight` API, no DSL.
- Endpoint weights and any `lb_policy` other than round-robin.
- Multiple listeners, listener-level TLS (`DownstreamTlsContext`, SNI,
  `require_client_certificate`), upstream TLS (`UpstreamTlsContext`).
- `STRICT_DNS` / `LOGICAL_DNS` clusters: no resolver; IPv4 literals only, no
  IPv6.
- HCM `access_log` with Envoy format strings: Rut has a single fixed access
  log line.

## Semantic risks to check early

- Proto3 JSON `Duration` values (`"5s"`, `"0.250s"`) and `google.protobuf`
  wrapper types (`{"value": 3}` vs bare `3`) must be modeled exactly; a
  fractional duration that Rut cannot represent is a diagnostic, not a
  rounding.
- Envoy applies `route_config` defaults (`timeout` 15s,
  `x-envoy-expected-rq-timeout-ms`) even when the fields are omitted. The
  converter must make every default explicit in the emitted RUT so that a
  later change to Rut's own defaults cannot silently change the converted
  program's behavior.
- The router filter must be the last `http_filters` entry. Any other filter,
  including `envoy.filters.http.health_check` or `lua`, is unsupported.
- A cluster referenced by a route but not declared is a static bootstrap
  validation error in Envoy (the process refuses to start). The converter
  must reject it too, rather than emitting an upstream with no address.
