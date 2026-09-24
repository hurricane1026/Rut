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

Read consistency (`read_input`, `src/envoy/main.cc`): the converter `fstat`s
the open file, reads it whole, `fstat`s again and requires identical device,
inode, size, mtime and ctime, then reads it whole a second time and requires
the two reads to be byte-identical. Any change that lands between the first
`fstat` and the end of the second read — a same-size in-place rewrite, a torn
first read whose writer then progressed — fails with `input changed while it
was being read`; a content change after the second read cannot affect the
result, since nothing rereads the bytes again. Out of contract: a file that
itself *holds* a torn mixture for the whole read window. Linux buffered reads
(ext4, tmpfs) take no lock against an in-place `write()`, which copies page by
page after already bumping mtime/ctime, so a writer stalled mid-copy leaves a
torn file whose metadata no longer changes; the converter reads those bytes
twice, identically, and converts them as the input — indistinguishable from a
file that simply contains them (validation may still reject them, as it does
for a mixed cluster name).

Writers that need the converter to see only whole revisions must replace the
file atomically: write a temporary file, then `rename()` it over the input.
That publishing model needs a separate, independent check: every `fstat`
above runs on the already-open descriptor, which keeps referring to its
original inode regardless of what the pathname is later renamed onto, so the
device/inode/size/mtime/ctime comparison and the dual-read byte comparison
cannot by themselves observe a rename landing during the read — both reads
still return the pre-rename content faithfully, and a rename lands
successfully no matter when it happens relative to them. After the second
read and the descriptor's close, the converter therefore also `stat()`s the
pathname itself — following symlinks, the same as `open()` did to get the
descriptor in the first place — and requires its device and inode to still
equal the descriptor's own identity (from the `fstat` above); a mismatch means
the pathname now names a different file and fails with `input changed while
it was being read`, the same message as the in-place cases above. This check
runs last, so it extends the detection window through the descriptor's close,
past where the in-place checks stop mattering: a rename that lands at any
point up to and including that close is still caught, and only one landing
strictly after it is invisible to the converter. `tests/test_envoy_convert.cc`
pins all three halves deterministically: `cli_input_rewrite_during_read_is_detected`
pauses the converter under `ptrace` at fixed points in `read_input` and
rewrites the file there, `cli_input_rename_during_read_is_detected` pauses it
the same way and renames a second file onto the input's path at the
descriptor's `close()` instead (and confirms an otherwise-identical run with
no rename converts cleanly), and `cli_input_static_torn_content_is_converted_as_is`
covers the out-of-contract torn file.

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
            "codec_type": "HTTP1",
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

`codec_type: "HTTP1"` is likewise required, not optional. Its default (and
the value used when the field is omitted), `AUTO`, makes Envoy inspect the
connection preface and serve downstream HTTP/2 (h2c) on a plaintext listener.
This converter is HTTP/1-only (see "Input format" above), so admitting `AUTO`
would silently drop support for clients Envoy would have served over HTTP/2.
`HTTP2` and `HTTP3` remain rejected outright.

Requiring `codec_type: "HTTP1"` at the parser only proves the *input*
disclaims h2c; it does not make the *emitted* `listen` line HTTP/1-only. Rut's
cleartext listener unconditionally recognizes the h2c connection preface
(`on_header_received`, `include/rut/runtime/callbacks_impl.h`) and upgrades —
verified by sending the raw preface plus a `SETTINGS` frame to a live `rut`
process on a plain `listen :port` and receiving an HTTP/2 `SETTINGS` reply
back. `AstListenDecl` (`include/rut/compiler/ast.h`) has no protocol field, so
there is no RUT-side knob to disable h2c on a listener today. This is a real
divergence from an Envoy HTTP1-only HCM, which parses the preface as
malformed HTTP/1.1 and rejects it; it is recorded as `BLOCKED_BY_RUT` in
docs/envoy-compatibility.md rather than fixed here — adding a listener
protocol restriction is a runtime/language change out of this increment's
scope (AGENTS.md: don't add new keywords/knobs without weighing whether
existing surface is insufficient first).

This is deliberately not a `RutCapabilities` gate (PR #692 round-7 review):
every milestone bootstrap's HCM requires `codec_type: "HTTP1"`, so a capability
gate here would fail closed on every conversion, not just the ones that meet
an h2c client — the divergence only matters for a client that opens with the
h2c preface, a per-connection shape, not a configuration Rut cannot express.
Instead `rut-envoy-convert` accepts and prints a stderr warning after a
successful conversion (same style as the `connect_timeout` warning, D2
above): "warning: generated listen still accepts the h2c connection preface
and serves HTTP/2 even though this bootstrap's codec_type is \"HTTP1\";
Envoy's HTTP1 codec would reject such a client before routing (see
docs/envoy-compatibility.md, \"HTTP1-only HCM rejects a client that opens
with the h2c connection preface\")". Closing the gap for real needs a listener
protocol option in Rut, not a converter-side gate.

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
  `http_filters` containing exactly the router filter last, `codec_type:
  "HTTP1"` required (omitted, `AUTO`, `HTTP2` and `HTTP3` are all rejected),
  no `access_log`, no `tracing`, no `common_http_protocol_options`,
  no `server_name` / `server_header_transformation` overrides,
  no `use_remote_address`, no `xff_num_trusted_hops`;
- route config: exactly one virtual host whose `domains` is exactly `["*"]`,
  with exactly one route whose match is `prefix: "/"` and whose action is
  `route.cluster` naming a declared cluster, no `timeout` override, no
  `retry_policy`, no header mutations, no rewrites;
- exactly one cluster: `type` omitted or `STATIC` (the proto3
  `cluster_discovery_type` oneof default), `connect_timeout`,
  `load_assignment.cluster_name` required and equal to the cluster `name`
  (Envoy's v3 `ClusterLoadAssignment.cluster_name` has `min_len: 1`, so an
  omitted value is a validation error, not the empty string), one locality
  with one `lb_endpoints` entry with an IPv4 `socket_address`, no `lb_policy`
  field at all (only omission is supported; Envoy's default for an omitted
  `lb_policy` is `ROUND_ROBIN`), no `health_checks`, no
  `circuit_breakers`, no `outlier_detection`, no `transport_socket`, no
  `typed_extension_protocol_options`.

Every unknown field, duplicate key, unknown `@type`, unsupported enum value,
`Any` without `@type`, and every field outside this list produces a
source-located unsupported or invalid diagnostic. JSON whitespace is syntax.
Proto3 JSON accepts both `lowerCamelCase` and `snake_case` field names; the
model must accept both spellings for every supported field and treat them as
the same key for duplicate detection.

## Corrections found while implementing lowering (increment 2)

The lowering shape originally sketched for this document did not parse
against today's RUT grammar (`src/compiler/parser.cc`). Five differences,
folded into the golden below and into the parser/converter implementation:

1. `listen 0.0.0.0:8080` is rejected by the RUT parser
   (`parse_listen`, `kListenerWildcardSpellingDetail`). The wildcard listener
   must be written `listen :8080`; a non-wildcard IPv4 listener is still
   `listen a.b.c.d:port`.
2. `request_policy.strip_headers` accepts exactly the closed list
   `["Connection", "Keep-Alive", "TE", "Expect", "Upgrade"]` with
   `host: "upstream"`, or exactly the six-name list adding
   `"Proxy-Connection"` with `host: "preserve"` (the `request_envoy_h1`
   capability, landed in PR3). `"Transfer-Encoding"` is rejected in every
   combination the converter uses; it is dropped from the lowering. The
   `"TE"` entry does not mean "always strip": per the Envoy oracle
   (`tests/fixtures/envoy_oracle_milestone_s.inc`) and Envoy's own
   `sanitizeConnectionHeader`, `host: "preserve"` keeps a client `te` field
   whenever one of its comma-separated tokens is `trailers` (any casing;
   `TE: gzip, trailers` is kept), rewrites the kept field to exactly
   `te: trailers` (Envoy forwards only that canonical token, never the
   client's other tokens or casing), collapses several such fields to one
   line, and strips a `te` field that carries no `trailers` token.
3. `request_policy` and `set_header` cannot be used together
   (`src/compiler/parser.cc` around lines 2022 and 2568). The milestone
   lowering therefore does not use `set_header`; `x-forwarded-proto` is
   carried by `request_policy.forwarded_proto` instead (a capability
   dependency, see "milestone-S" below), and
   `x-envoy-expected-rq-timeout-ms` has no RUT equivalent at all (it is
   removed by `suppress_envoy_headers: true`, also below).
4. `failure_policy.status` must be exactly 502
   (`forward_failure_policy_spec_valid`, `admitted_forward_failure_policy_valid`)
   until the `local_reply_envoy_h1` capability admits 503 with the Envoy
   connect-failure layout. Envoy's connect failure is a 503, not a 502, so
   the milestone's `failure_policy` is a capability dependency, not a
   same-shape substitution.
5. `local_response(...)` requires all 9 fields, including a non-empty
   `content_type` for 4xx/5xx statuses. Envoy's no-route 404 has no
   `content-type`, so the unmatched 404 is also a capability dependency
   rather than an emittable `local_response` today.

## milestone-S: the first fully specified shape

The plain milestone bootstrap (above) still hits the `x-envoy-upstream-
service-time` and 15s-route-timeout capability gaps unconditionally, because
Envoy applies both by default even when nothing in the bootstrap asks for
them. Rather than leave every input `BLOCKED_BY_RUT` forever, the converter
recognizes one additional shape, "milestone-S", that removes both defaults
explicitly:

- `suppress_envoy_headers: true` on the router filter's `typed_config`
  (`http_filters[].typed_config.suppress_envoy_headers`, v3 `Router` only).
  This is an Envoy-real knob: it removes `x-envoy-upstream-service-time` and
  `x-envoy-expected-rq-timeout-ms` from the upstream-facing behavior, which
  removes the non-deterministic value and the field with no RUT equivalent
  in one step.
- `timeout: "0s"` on the route action (`route.route.timeout`). Envoy treats
  `0s` as "no timeout" (rather than an instant timeout), which removes the
  implicit 15s route timeout default and makes `response_read_timeout`
  unnecessary for this milestone.

Milestone-S is still capability-gated on everything else (request header
casing/host preservation, response header order, and the local-reply
layouts); it only removes the two defaults that would otherwise make no
input convertible before those capabilities land. Bootstraps that omit
either field, or that set a non-zero `timeout`, remain `BLOCKED_BY_RUT` with
a diagnostic naming exactly what to change (see "Capability validation"
below).

## Lowering shape

The milestone-S bootstrap (the accepted-JSON milestone above, plus
`suppress_envoy_headers: true` and `timeout: "0s"`) lowers to the RUT below
once every capability in `rut::envoy::RutCapabilities` is available. The
shipped converter (`rut::envoy::kShippedRutCapabilities`: `request_envoy_h1`
`true` since PR3, `response_envoy_h1` and `local_reply_envoy_h1` still
`false`) fails closed with a `BLOCKED_BY_RUT` diagnostic (at the
`response_envoy_h1` check) instead of emitting this text; the
exact bytes are pinned in `tests/fixtures/envoy_milestone_s.inc` and checked
byte for byte by `tests/test_envoy_convert.cc`
(`api_all_capabilities_matches_golden`). Values shown here (the connect-failure
body, in particular) are provisional pending the pinned Envoy oracle (PR2)
and are marked `// PROVISIONAL: reconcile with oracle` at their source.

```rut
listen :8080
upstream envoy_cluster_0 at "127.0.0.1:9000"
unmatched { return local_response({
  version: "HTTP/1.1", status: 404, reason: "Not Found", server: "envoy",
  date: "current", connection: "request", connection_header: "close_only",
  header_names: "lowercase", header_order: "date_server_length",
  head_mode: "suppress_body", body: b""
}) }
route HEAD "/" {
    return forward(envoy_cluster_0, request_policy: {
            version: "HTTP/1.1",
            host: "preserve",
            connection: "omit",
            header_names: "lowercase",
            forwarded_proto: "http",
            strip_headers: ["Connection", "Keep-Alive", "TE", "Expect", "Upgrade", "Proxy-Connection"]
        },
        response_policy: {
            version: "HTTP/1.1",
            framing: "content_length",
            connection: "request",
            head_mode: "suppress_body",
            header_order: "upstream",
            header_names: "lowercase",
            connection_header: "close_only",
            status_reason: "canonical",
            server: "envoy",
            date: "preserve_or_current",
            hide_headers: []
        },
        failure_policy: {
            version: "HTTP/1.1",
            status: 503,
            reason: "Service Unavailable",
            content_type: "text/plain",
            server: "envoy",
            date: "current",
            connection: "request",
            connection_header: "close_only",
            header_names: "lowercase",
            header_order: "length_type_date_server",
            head_mode: "suppress_body",
            body: b"<kEnvoyConnectFailureBody, PROVISIONAL>"
        }
    )
}
route "/" {
    <identical forward(...), with the two `head_mode: "suppress_body",` lines omitted>
}
```

The upstream identifier is always `envoy_cluster_0` regardless of the
bootstrap's cluster name; the listener line is `listen :<port>` when the
listener address is the IPv4 wildcard and `listen a.b.c.d:<port>` otherwise.
No bytes from the JSON source reach the emitted RUT — only the numeric
listener/endpoint address and port fields are rendered; every other token is
a fixed literal chosen by the converter.

Fields with values that do not exist in today's `request_policy` /
`response_policy` / `local_response` / `failure_policy` grammar (for example
`host: "preserve"`, `header_order: "upstream"`) are capability dependencies,
listed below and gated by `rut::envoy::RutCapabilities`. The converter must
fail closed on them until the RUT side exists; it must not emit the nearest
existing value. The six checks, in order (first failure wins), are:

1. Router `suppress_envoy_headers` must be `true`.
2. Route `timeout` must be present.
3. Route `timeout` must be exactly `0s`.
4. `RutCapabilities::request_envoy_h1` (Host preserve + lowercase request
   headers) must be available.
5. `RutCapabilities::response_envoy_h1` (upstream header order + lowercase +
   preserved date) must be available.
6. `RutCapabilities::local_reply_envoy_h1` (lowercase local-reply layouts)
   must be available.

Each of 1-3 is a plain modeling gap (the bootstrap can be edited to satisfy
it); each of 4-6 is a Rut-side capability gap tracked as a separate PR (see
the project plan) and cannot be worked around from the bootstrap.

Not every Envoy-vs-Rut behavioral difference belongs in this list. This gate
is about configuration semantics: whether the bootstrap can be lowered at all.
A per-request or per-response shape that a correctly-converted, already-
admitted route later sees at runtime is a different kind of gap — see
"Round-2 review edge cases (PR #692)" below and docs/envoy-compatibility.md
for how those are recorded instead.

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
  upstream address. Rut's `request_policy.host` landed a `"preserve"` value
  with `request_envoy_h1` (PR3): the ID4 (`Http11PreserveHostLowercase`)
  profile forwards the client's Host authority verbatim
  (`apply_preserve_host_lowercase_request_policy`,
  `include/rut/runtime/callbacks_impl.h`). Every other `request_policy.host`
  value still writes the fixed upstream Host.
- Envoy emits all header names in lowercase over HTTP/1.1 (default
  `header_key_format`). nginx and Rut preserve the client's case on every
  policy except ID4. The request side landed with `request_envoy_h1` (PR3,
  `header_names: "lowercase"` in `request_policy`): the same serializer
  lowercases every forwarded header name. The **response** side is still a
  capability dependency (`response_envoy_h1`, PR4) — see "Known capability
  dependencies" below.
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
  milestone covers bodyless and fixed-length requests only: verified against a
  live `rut` process using the milestone's `Http11FixedStrip` request-policy
  shape, a client request carrying `Transfer-Encoding` is rejected with
  `400 Bad Request` before any byte reaches the upstream (the upstream never
  saw the connection). This is a real behavioral divergence from Envoy, which
  forwards chunked request bodies; it is `BLOCKED_BY_RUT`, not a converter
  oversight — Rut correctly fails closed rather than mis-forwarding.
- Connect timeout is the cluster `connect_timeout`; Rut has no
  connect-establishment timeout surface at all (parsed and validated but not
  enforced — see D2 in the compatibility matrix). Route timeout defaults to
  15s and covers the whole upstream response; Rut's nearest surface is the
  fixed 30s `kDefaultUpstreamTimeout` (`include/rut/runtime/event_loop.h`),
  which is not a route timeout either — it bounds only the time from upstream
  connect completion to the first response byte, firing a 504 if exceeded, and
  does not cover the body-streaming phase or disable when the route's
  `timeout` is `"0s"`. An upstream that is simply slow to produce headers
  (>30s) gets a Rut 504 in a case Envoy would let run indefinitely.

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
- `response_policy.framing` has exactly one legal value, `content_length`
  (`include/rut/common/response_policy.h`, `ResponsePolicyFraming`); there is
  no accepted way to opt a route into chunked or close-delimited upstream
  responses today. Verified against a live `rut` process: an upstream response
  that is chunked, or that has neither `content-length` nor
  `Transfer-Encoding` and closes the connection instead, is rejected with a
  generic `502 Bad Gateway` before any byte reaches the downstream client. As
  with the request side, this is `BLOCKED_BY_RUT`, and Rut fails closed rather
  than mis-forwarding.
- Upstream connect failure: 503 with `content-type: text/plain` and body
  `upstream connect error or disconnect/reset before headers. reset reason:
  remote connection failure` (98 bytes, the exact text pinned from the
  oracle transcript in `tests/fixtures/envoy_oracle_milestone_s.inc`). No
  healthy endpoint: 503 `no healthy upstream`. Route timeout: 504 `upstream
  request timeout`. Each is a `failure_policy` / `timeout_failure_policy`
  row.
- Downstream keep-alive follows the request (`connection: close` is honored;
  HTTP/1.1 default is keep-alive). The `connection` response header is emitted
  only for close.

**Round-2 review edge cases (PR #692)**

Seven per-request/per-response behaviors of the milestone's any-method
`forward(...)` route, found in the round-2 Codex review of PR #692. These are
not configuration-admission gaps — the bootstrap that produces this route
lowers and (once PR3-PR5 land) converts the same way regardless of them — so
they are not `RutCapabilities` checks and the converter does not gate on them.
Each is a case where Rut's runtime, when it later sees the specific request or
response shape at connection time, safely refuses it with a fixed status
rather than mis-forwarding; docs/envoy-compatibility.md records each as its
own `PARTIAL`/`NOT_IMPLEMENTED` matrix row, the same way the nginx matrix
records nginx-vs-Rut per-request differences.

Each is verified from Envoy v1.39.1 source and from a live `rut` process
built from this tree (`envoy/lower-increment-2`). That branch predates the
request/response/local-reply serializers (#696/#698/#699), so the milestone's
own emitted policy vocabulary (`host: "preserve"`, `header_names:
"lowercase"`, `forwarded_proto`, ...) does not compile there yet; the live
checks instead used the nearest existing nginx-era policy shape
(`tests/fixtures/nginx373_hide.inc`'s `request_policy`/`response_policy`/
`failure_policy` grammar — `host: "upstream"`, no header-casing or dynamic
`Connection`-nomination fields) against a minimal test `.rut` and a scripted
Python origin. This is a stated limitation: none of the mechanisms below read
a policy-specific field like `host` or header casing, so the observed
behavior is the same runtime code path the milestone shape would hit, but it
is not a byte-for-byte run of the milestone's own emitted text.

1. **Fixed-length request body larger than the request slice.** Envoy has no
   body-size cap tied to a single buffer; `Cluster.per_connection_buffer_limit_bytes`
   defaults to a 1 MiB soft watermark, not a hard reject
   (`api/envoy/config/cluster/v3/cluster.proto`), so an ordinary 20 KB POST
   streams through. Rut's `inspect_request_policy_body` requires
   `req.content_length <= conn.recv_buf.capacity() - parser.header_end`
   (`include/rut/runtime/callbacks_impl.h:5461-5463`), and `recv_buf`'s
   capacity is `SlicePool::kSliceSize` = 16384 bytes
   (`include/rut/runtime/io_backend.h:50`). Live: a `POST /` with a 20000-byte
   fixed-length body (20051 bytes total) got `HTTP/1.1 400 Bad Request` with
   no upstream connection attempted.
2. **`Expect: 100-continue`.** Envoy's `ConnectionManagerImpl::ActiveStream::decodeHeaders`
   (`source/common/http/conn_manager_impl.cc`) sends the interim response
   itself (`response_encoder_->encode1xxHeaders(continueHeader())`) and then
   strips `Expect` before forwarding, so a client that waits for `100
   Continue` gets it and the request proceeds. Rut's
   `inspect_request_policy_body` treats `Expect` on a request with a body as
   `Invalid` (`include/rut/runtime/callbacks_impl.h:5451,5460`); there is no
   interim-response surface at all. Live: `POST /` with `Content-Length: 2`
   and `Expect: 100-continue` got `HTTP/1.1 400 Bad Request` with no upstream
   connection attempted.
3. **`TE: trailers`** (`PARTIAL`, not `NOT_IMPLEMENTED` — see below). Envoy's
   `ConnectionManagerUtility::sanitizeTEHeader`
   (`source/common/http/conn_manager_utility.cc`) keeps the request's `TE`
   header set to exactly `trailers` when that value is present and removes
   `TE` entirely otherwise; it is the one hop-by-hop header not stripped
   unconditionally. On this branch, Rut's `request_policy.strip_headers` fixed
   list removes every `TE` field regardless of value (this doc, "Corrections
   found while implementing lowering", item 2), and
   `inspect_request_policy_body` additionally treats `TE` on a
   content-length request as `Invalid`
   (`include/rut/runtime/callbacks_impl.h:5450,5460`). Live: `POST /` with
   `Content-Length: 2` and `TE: trailers` got `HTTP/1.1 400 Bad Request` with
   no upstream connection attempted; a bodyless `GET /` with `TE: trailers`
   was forwarded with the `TE` header silently dropped (the origin received
   `GET / HTTP/1.1\r\nHost: 127.0.0.1:9100\r\n\r\n`, no `TE` field at all) —
   a mis-forward for that case, not a fail-closed refusal. PR #696
   (`envoy/rut-request-envoy-h1`, ID4 `Http11PreserveHostLowercase`,
   `apply_preserve_host_lowercase_request_policy`) adds `TE: trailers`
   preservation once the `request_envoy_h1` capability lands, fixing the
   bodyless mis-forward. **Update (round-4 review):** as of that branch's
   round-3 revision (commit `8200f648`), `inspect_request_policy_body`
   admits a fixed-Content-Length request too, whenever the `TE` value
   carries a `trailers` token among its comma-separated tokens (not only an
   exact whole-value match), and the serializer rewrites the kept header to
   the canonical lowercase `te: trailers` regardless of the client's casing
   or the other tokens in the value — the earlier claim in this item that a
   body-carrying request "still fails closed 400 even after #696" described
   only the pre-round-3 state of `366ad196` and no longer holds; see
   `tests/test_network.cc`'s
   `preserve_host_lowercase_wire_and_fail_closed_host` for the byte-exact
   wire assertions covering both the bodyless and fixed-length cases.
4. **Extension/unrecognized HTTP methods.** Envoy's default HTTP/1 parser
   (`BalsaParser`, used unless `Http1ProtocolOptions.allow_custom_methods` and
   the BalsaParser feature are both on) matches the request method against a
   34-entry hard-coded list that includes WebDAV methods such as `PROPFIND`
   (`source/common/http/http1/balsa_parser.cc`, `kValidMethods`), so `PROPFIND
   / HTTP/1.1` is accepted and reaches the catch-all prefix route. Rut's
   `HttpMethod` enum recognizes exactly nine methods (GET, POST, PUT, DELETE,
   PATCH, HEAD, OPTIONS, CONNECT, TRACE); `parse_method_direct` returns
   `HttpMethod::Unknown` for anything else
   (`src/runtime/http_parser.cc:101-159`), and once the full request head has
   arrived the top-level parser resolves an unknown method to
   `ParseStatus::Error` (`src/runtime/http_parser.cc:360,493-501`) — the
   request is rejected as malformed before any route lookup runs, so no
   any-method route can observe it. Live: `PROPFIND / HTTP/1.1` got
   `HTTP/1.1 400 Bad Request`.
5. **More than 64 response headers.** Envoy's default header-count ceiling is
   100, applied per direction (`HttpProtocolOptions.max_headers_count`,
   `api/envoy/config/core/v3/protocol.proto`: "If unconfigured, the default
   maximum number of headers allowed is 100"), so a 65-100-header response is
   accepted and forwarded. Rut's `kMaxHeaders` is a fixed 64
   (`include/rut/runtime/http_parser.h:46`); the response parser itself
   tolerates more by setting `headers_truncated = true`
   (`src/runtime/http_parser.cc:694-708`), but
   `build_strict_response_headers` then rejects any response with
   `resp.headers_truncated` (`include/rut/runtime/callbacks_impl.h:10169`),
   which trips the route's configured failure response. Live: an origin
   returning 90 headers plus `Content-Length: 5` got the client
   `HTTP/1.1 502 Bad Gateway`.
6. **HTTP/1.0 upstream response.** Envoy's `accept_http_10` `Http1Settings`
   flag gates HTTP/1.0 only on the downstream-facing server codec
   (`ServerConnectionImpl::supportsHttp10()`,
   `source/common/http/http1/codec_impl.h`); the client codec used for
   upstream connections has no such gate, and `BalsaParser`'s version check
   accepts any `HTTP/<digit>.<digit>` line, so a valid HTTP/1.0 response with
   `Content-Length` is parsed and proxied. Rut's `build_strict_response_headers`
   requires `resp.version == HttpVersion::Http11`
   (`include/rut/runtime/callbacks_impl.h:10164`). Live: an origin answering
   `HTTP/1.0 200 OK` with `Content-Length: 5` got the client `HTTP/1.1 502 Bad
   Gateway`.
7. **Empty reason phrase.** RFC 7230 §3.1.2 defines `reason-phrase` as `*(
   HTAB / SP / VCHAR / obs-text )`, explicitly allowing zero length,  and
   Envoy's `BalsaParser` does not reject an empty reason phrase on the
   response status line (`source/common/http/http1/balsa_parser.cc`,
   `OnResponseFirstLineInput`), so `HTTP/1.1 200 ` with a trailing space and
   no text is accepted and forwarded. Rut's `build_strict_response_headers`
   rejects `resp.reason.len == 0`
   (`include/rut/runtime/callbacks_impl.h:10170`). Live: an origin answering
   `HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n` got the client `HTTP/1.1 502
   Bad Gateway`.

**Round-3 review edge cases (PR #692)**

Six more per-request/per-response behaviors of the milestone's any-method
`forward(...)` route, found in the round-3 Codex review of PR #692, plus one
distinct mis-forward bug (`CONNECT`, covered at the end of this section). Same
non-gating rule as round-2: these are per-request behaviors of an
already-admitted, already-converted route, not configuration-admission gaps,
so none is a `RutCapabilities` check.

Verified from Envoy v1.39.1 source and from a live `rut` process built from
this tree (`envoy/lower-increment-2`, head `ec0f9df4`, `--shards 1 --no-pin`).
Same stated limitation as round-2: the live checks used the nginx-era policy
shape (`tests/fixtures/nginx373_hide.inc`) instead of the milestone's own
emitted text, since that still doesn't compile on this branch.

1. **65-100 request headers.** Envoy's default `HttpProtocolOptions.max_headers_count`
   is 100, applied per direction (`api/envoy/config/core/v3/protocol.proto`),
   so a request with up to 100 headers is accepted — the request-side mirror
   of the round-2 response-header-ceiling row. Rut's `kMaxHeaders` is the same
   fixed 64 on both parsers (`include/rut/runtime/http_parser.h:46`); the
   request parser has no `headers_truncated` tolerance the way the response
   parser does, so `HttpParser::parse` resolves straight to
   `ParseStatus::Error` once the count is exceeded, before any route lookup.
   Live: a `GET /` with 73 header fields got the connection closed with no
   response bytes — not the `400 Bad Request` the parser header comment
   documents for `ParseStatus::Error` in general (`include/rut/runtime/http_parser.h:128`,
   "400, close connection"). Confirmed the harness itself reproduces that
   documented `400 Bad Request` for round-2's `PROPFIND` case on the identical
   fixture, so the silent close is specific to the header-count-overflow path,
   not a broken test.
2. **Request or response header block between 16 KiB and 60 KiB.** Envoy's
   default `max_request_headers_kb`/`max_response_headers_kb` is 60 KiB
   (`api/envoy/config/core/v3/protocol.proto`), so a single large header (e.g.
   a big `Cookie` or `X-Big`) well under that is accepted on both directions.
   Rut accumulates the request head in one `SlicePool::kSliceSize` (16384
   byte) receive buffer (`include/rut/runtime/io_backend.h:50`) and the
   upstream response head in the equivalent upstream buffer; `on_header_received`
   closes the downstream connection when that buffer is full and the head is
   still incomplete, and `on_upstream_response`'s `-ENOBUFS` path does the
   same for an oversized upstream head. Live: a `GET /` with one 20000-byte
   header got the connection closed with no response bytes and no upstream
   connection attempted; an upstream response with one 20000-byte header got
   the upstream contacted but the client connection closed with no response
   bytes.
3. **Status-defined no-body responses (204, 304).** Envoy's HTTP/1 codec
   suppresses the body for 204 (and 1xx) and disables chunked framing for 304
   while still forwarding the response
   (`StreamEncoderImpl::encodeHeadersBase`, `source/common/http/http1/codec_impl.cc`),
   so a `204 No Content` or a `304 Not Modified` with a legal `Content-Length`
   reaches the client. Rut's `build_strict_response_headers` unconditionally
   rejects `status_code == 204 || status_code == 205`, and rejects `304`
   unless a `StrictNoBodyMetadataSuccess` purpose is selected
   (`include/rut/runtime/callbacks_impl.h:10165-10168`), which this route's
   plain `forward(...)` does not request. Live: an upstream `204 No Content`
   and a `304 Not Modified` (`Content-Length: 0`) each got the upstream
   contacted but the client connection closed with no response bytes.
4. **Interim (1xx) responses.** Envoy forwards `encode1xxHeaders` unconditionally
   to the downstream connection ahead of the final response — no per-route or
   per-filter gate (`ConnectionManagerImpl::ActiveStream::encode1xxHeaders`,
   `source/common/http/conn_manager_impl.cc`) — so a `103 Early Hints` (or
   `100 Continue`) followed by the real response reaches the client as two
   frames. Rut's strict `response_policy` rejects every 1xx immediately
   (`include/rut/runtime/callbacks_impl.h:11215-11218`, "a strict policy has
   no interim-response ... domain") before the final response is even read.
   Live: an upstream sending `100 Continue` immediately followed by `200 OK`
   got the upstream contacted but the client connection closed with no
   response bytes at all — the final `200 OK` never reached the client either.
5. **Ordinary response headers with no special Envoy handling (`Location`,
   `Refresh`, `Last-Modified`).** Envoy's hop-by-hop stripping
   (`ConnectionManagerUtility`, `source/common/http/conn_manager_utility.cc`)
   only removes `connection` and the headers it names, `keep-alive`,
   `proxy-connection`, `te` (unless `trailers`), `upgrade` outside an upgrade,
   and `transfer-encoding` on reframe; ordinary headers like a redirect's
   `Location` or a cache validator's `Last-Modified` pass through unchanged.
   Rut's `strict_response_forbidden` unconditionally rejects `location`,
   `refresh`, and `last-modified` (`include/rut/runtime/callbacks_impl.h:9856-9868`)
   regardless of the route's `hide_headers` list — this milestone's route
   already requests `hide_headers: []` (hide nothing), so there is no policy
   value that admits these headers even once `response_envoy_h1` lands. Live:
   an upstream `302 Found` with `Location: /login` got the upstream contacted
   but the client connection closed with no response bytes.
6. **Undifferentiated (and sometimes absent) failure replies.** Envoy maps
   `LocalConnectionFailure`/`RemoteConnectionFailure`/`ConnectionTimeout` (a
   refused or timed-out connect attempt) to one local-reply text and
   `ConnectionTermination` (a reset after the stream was established) to
   another, with protocol errors mapped to `502` and other resets to `503`
   (`source/common/router/router.cc`, the `StreamResetReason` →
   `CoreResponseFlag` mapping). Rut's converter emits exactly one
   `failure_policy` per route for every non-timeout upstream failure. Live
   testing found this is not just "one generic text for every cause" as
   originally suspected, but strictly worse for one of the two causes tested:
   stopping the origin entirely (connect refused) got the client the route's
   exact configured `failure_policy` body (`HTTP/1.1 502 Bad Gateway` with the
   nginx-era fixture's HTML body) — but an origin that accepted the
   connection, read the request, and closed without writing any response byte
   got the client connection closed with **no** local-reply text at all, not
   even the generic one. `failure_policy` fires only for a connect-establishment
   failure; a post-accept reset with zero response bytes takes a different,
   silent path.
7. **`CONNECT` matching the any-method route (bug, not a fail-closed
   divergence).** `route_table.h`'s own comment states "method 0 in a route
   entry matches any request method"; a method-omitted `route "/"` therefore
   matches `CONNECT` too. Envoy's HCM rejects a `CONNECT` request whose
   `:path` is non-empty before ever reaching the router
   (`ConnectionManagerImpl::ActiveStream::decodeHeaders`,
   `source/common/http/conn_manager_impl.cc`) — the request never reaches an
   upstream. Live: `CONNECT / HTTP/1.1` against this converter's own emitted
   shape reached the origin (`ORIGIN RECEIVED: b'CONNECT / HTTP/1.1\r\nHost:
   127.0.0.1:29000\r\n\r\n'`) and the origin's `200 OK` response was relayed
   back to the client verbatim — Rut opened the upstream connection and
   forwarded a response Envoy would never have requested. Two converter-level
   fixes were tried and both are infeasible with today's grammar and token
   budget:
   - Splitting the any-method route into one explicit `route <METHOD> "/"`
     per forwarded method (mirroring the `HEAD` route already emitted)
     overflows the lexer's fixed `kMaxTokens = 932`
     (`include/rut/compiler/lexer.h:135`) once duplicated across all 7
     non-HEAD forwarded methods — confirmed by actually compiling that
     11+ KB shape with `rut` (`lex failed: too many tokens`).
   - A `guard req.method == GET || req.method == POST || … else { return
     400 }` inside the existing any-method route stays comfortably within
     the token budget, but `CONNECT` and `TRACE` are both plain identifiers:
     neither has a `req.method == <KW>` expression-position keyword
     (`is_method_keyword`, `src/compiler/parser.cc`, covers only
     GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS) nor a `route <METHOD> "/"`
     declaration spelling of its own — confirmed live that `route TRACE "/"`
     is a parse error (`unexpected token ... (TRACE)`), and that
     `pre_route`/`unmatched` bodies (the only place `CONNECT`/`TRACE` are
     recognized at all) are fixed-shape local-response policies only, never
     a `forward(...)` (`AstPreRouteDecl`/`AstUnmatchedDecl`,
     `include/rut/compiler/ast.h`, carry only a `policy_id`, no statement
     list). A guard that excludes `CONNECT` is therefore indistinguishable
     from one that also excludes `TRACE`, and Envoy forwards `TRACE` like
     any other method (this document, "Routing"), so that guard would trade
     the `CONNECT` mis-forward for a new `TRACE` divergence rather than fix
     anything.

   Fixing this without introducing a new divergence needs a runtime or
   language capability this milestone does not have today: an
   expression-position `CONNECT` (and `TRACE`) method literal, a per-route
   method-exclusion list, or a lexer token budget large enough for one
   explicit route per forwarded method. Recorded as a bug (not a
   `NOT_IMPLEMENTED`/`PARTIAL` row) in docs/envoy-compatibility.md.

**Round-4 review edge cases (PR #692)**

Five findings from the round-4 Codex review of PR #692:

1. **Router filter identity was not revalidated.** `validate()`
   (`src/envoy/converter.cc`) checked `router.suppress_envoy_headers` but
   never `router.name`/`has_typed_config` themselves, so a caller of the
   public `lower_to_rut(model, capabilities)` overload could retarget
   `router.name` at a non-router filter (or clear `has_typed_config`) and
   still get a successful lowering that silently ignored whatever filter the
   model actually named. Fixed by checking both, mirroring the existing
   `route.match.prefix` defensive check from round-3.
2. **`--metrics` shadows a converted `/metrics` route.** A CLI-launch-mode
   interaction, not a converter gap — see "Known capability dependencies"
   above and docs/envoy-compatibility.md, "Operational note: `--metrics`
   shadows a converted `/metrics` route".
3. **`tests/test_envoy_convert.cc`'s TOCTOU stress test forked with a live
   writer thread**, then built `argv` (a `std::vector` — allocates) in the
   child between `fork()` and `exec()`; only async-signal-safe calls are
   valid there with another thread possibly holding an allocator lock at
   fork time. Fixed by building `argv` in the parent before `fork()`.
4. **The same test's `content_a`/`content_b` couldn't detect an actual torn
   read** — both were a single repeated byte, so every torn mixture produced
   the identical byte-zero parse error as a clean read regardless of whether
   the metadata check worked. Replaced with two full, valid milestone
   bootstraps that agree byte-for-byte except one cluster identifier spelled
   three times ("backend0" vs "backend1"), so a read that ends up with the
   two occurrences disagreeing produces a distinct, previously-impossible
   diagnostic ("route cluster does not name a declared cluster") that the
   test explicitly rejects.
5. **Fragment-bearing request targets are a runtime bug, not a converter
   gap** — see the mis-forward bug recorded right after the round-3
   `CONNECT` bug in docs/envoy-compatibility.md, and "Known capability
   dependencies" above.

**Round-6 review edge cases (PR #692)**

Three findings from the round-6 Codex review of PR #692:

1. **`generate_request_id` was not revalidated.** `validate()` checked
   `type_url_span`/`router.name`/`filter_chain.filter_name` for forgery but
   never `hcm.generate_request_id_span` — the model's only evidence that
   `parse_hcm` saw and accepted `generate_request_id: false` (an omitted
   field defaults to `true` in real Envoy, which then adds a random
   `x-request-id` this emitted RUT program never generates). Fixed by
   checking the span the same way as `type_url_span`, immediately after it in
   `validate()` (`src/envoy/converter.cc`); covered by a new
   `cleared_hcm_generate_request_id` case in
   `envoy_convert.api_forged_model_rejected` (`tests/test_envoy_convert.cc`).
2. **Downstream HTTP/1.0 rejection differs in mechanism and status, not just
   text.** With the milestone's fixed HCM shape (no `http_protocol_options`,
   so `accept_http_10` is always the proto3 default `false`), Envoy rejects
   an HTTP/1.0 downstream request at the H1 codec — before route
   selection — with `426 Upgrade Required`
   (`ServerConnectionImpl::checkProtocolVersion`,
   `source/common/http/http1/codec_impl.cc:1176-1189`). Rut's listener
   accepts the connection at any version and only rejects once the emitted
   route's `request_policy` (which already pins `version: "HTTP/1.1"`,
   `src/envoy/converter.cc:165`) is evaluated: `inspect_request_policy_body`
   (`include/rut/runtime/callbacks_impl.h:5406`) returns `Invalid` because
   `conn.req_http_version != HttpVersion::Http11`, and
   `reject_request_policy` (`callbacks_impl.h:5767`) sends a generic `400 Bad
   Request`. Both fail closed with no upstream contact, but the status code
   (426 vs 400) and the layer that rejects (codec vs application policy)
   differ; pinning `version: "HTTP/1.1"` in the request policy does not
   change this; it only determines *that* Rut rejects, not *how*. No
   converter-level fix is possible (there is no RUT grammar surface for a
   codec-level version gate), and this is a per-request divergence, not a
   configuration-admission gap, so it is not gated behind a
   `RutCapabilities` flag — recorded as a `PARTIAL` matrix row in
   docs/envoy-compatibility.md instead, same as the round-2/round-3 rows.
3. **P1: client-forged `x-envoy-*` internal headers are forwarded verbatim
   to the upstream.** For the milestone's fixed HCM shape (`use_remote_address`
   is unreachable through the parser's 6-field allow-list, so
   `config.useRemoteAddress()` is always `false`), Envoy's
   `ConnectionManagerUtility::mutateRequestHeaders`
   (`source/common/http/conn_manager_utility.cc:121-327`) always computes
   `internal_request = false` and therefore always strips 15 `x-envoy-*`
   headers from every request before forwarding — `x-envoy-internal` itself
   (unconditionally removed at line 142 and never re-added, since
   `internal_request` is always false) plus the 14 headers
   `cleanInternalHeaders` (lines 351-388) strips unconditionally:
   `x-envoy-retriable-status-codes`, `x-envoy-retriable-header-names`,
   `x-envoy-retry-on`, `x-envoy-retry-grpc-on`, `x-envoy-max-retries`,
   `x-envoy-upstream-alt-stat-name`, `x-envoy-upstream-rq-timeout-ms`,
   `x-envoy-upstream-rq-per-try-timeout-ms`,
   `x-envoy-upstream-rq-timeout-alt-response`,
   `x-envoy-expected-rq-timeout-ms`, `x-envoy-force-trace`,
   `x-envoy-ip-tags`, `x-envoy-original-url`,
   `x-envoy-hedge-on-per-try-timeout` (literal names from
   `source/common/http/headers.h:153-208`, default `x-envoy` prefix). The
   emitted route's `request_policy.strip_headers`
   (`src/envoy/converter.cc:171`) is the fixed closed list `["Connection",
   "Keep-Alive", "TE", "Expect", "Upgrade", "Proxy-Connection"]` — none of
   the 15 names above are in it, and #696's planned
   `apply_preserve_host_lowercase_request_policy` (Host preservation, header
   lowercasing, the same hop-by-hop list) does not add any either. A client
   can therefore make the converted gateway deliver e.g. a forged
   `x-envoy-internal: true` or `x-envoy-retry-on` to an upstream that would
   never see it from the original Envoy config — a real security-relevant
   divergence, not merely a cosmetic one. **The converter cannot fix this**:
   `strip_headers` is a fixed array written once at lowering time and has no
   way to express Envoy's dynamic, address-derived internal/edge
   determination, so this cannot be closed by adding more literals to the
   converter's emitted text. **The fix belongs in the runtime**, in #696's
   `apply_preserve_host_lowercase_request_policy`
   (`envoy/rut-request-envoy-h1`): strip the same closed
   `x-envoy-*` list unconditionally for every request the milestone's request
   policy handles (equivalent to "always treat as external", which is
   correct for this milestone since `use_remote_address` can never be set).
   Recorded as a prominently marked `BLOCKED_BY_RUT` matrix row in
   docs/envoy-compatibility.md pending that runtime change. **Landed in
   #696** (`request_policy_is_stripped_client_envoy_header`,
   `include/rut/runtime/callbacks_impl.h`): the ID4 policy drops all 15
   names above unconditionally, plus -- from the round-7 review of #696 --
   a client-supplied `x-forwarded-client-cert`, which
   `ConnectionManagerUtility::mutateXfccRequestHeader` (called for every
   request at `conn_manager_utility.cc:324`) removes under the HCM's default
   `forward_client_cert_details: SANITIZE` (`applyForwardClientCertConfig`,
   lines 541-545, also for any non-mTLS connection) -- plus, from the
   round-8 review of #696, a client-supplied `x-envoy-external-address`:
   unlike the sixteen names above, Envoy's own `mutateRequestHeaders` never
   removes a client-supplied value for this one (`setEnvoyExternalAddress`
   at line 308 only *writes* it, gated by `edge_request`, which is
   unreachable under this milestone's fixed shape), so this one is Rut-side
   hardening rather than an Envoy-parity claim -- a client must not be able
   to forge the address a trusted hop asserts, independent of what this
   exact Envoy shape happens to also let through. Seventeen names in
   total; the matrix rows are `PARTIAL` pending the pinned-Envoy
   differential run.

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

- `request_policy.host: "preserve"` (`request_envoy_h1`, PR3): landed. The
  runtime serializer follows the Envoy oracle where it differs from this
  document's original sketch: a single client `x-forwarded-proto` field
  whose trimmed value is a syntactically valid scheme (case-insensitively
  exactly `http` or `https`, matching Envoy's own `Utility::schemeIsValid`,
  `source/common/http/conn_manager_utility.cc`) is kept unchanged in its
  original position rather than overwritten. An empty, OWS-only, or
  otherwise invalid value (e.g. `ftp`, `http,https`) is overwritten in place
  at that same position with `x-forwarded-proto: http` rather than dropped
  and re-appended, matching Envoy's inline (O(1) slot) storage for this
  header. `x-forwarded-proto: http` is appended as the last header only when
  the client sent no `x-forwarded-proto` field at all; more than one
  physical field is rejected outright (`400`), since Envoy coalesces
  duplicates into one value and this profile does not replicate that
  coalescing. See `tests/fixtures/envoy_oracle_milestone_s.inc` and
  `docs/envoy-compatibility.md`.
- Dynamic `Connection`-nominated header stripping on the upstream request:
  Envoy parses the client's `Connection` header value and removes every
  header it names (e.g. `Connection: X-Secret` also removes `X-Secret`). This
  landed on the `host: "preserve"` profile with `request_envoy_h1` (PR3):
  `apply_preserve_host_lowercase_request_policy`
  (`include/rut/runtime/callbacks_impl.h`) parses the client's `Connection`
  header into its comma-separated token list and drops every nominated
  header name, matching Envoy's `get_hop_by_hop` behavior for that profile.
  The fixed, closed `request_policy.strip_headers` literal list
  (`Connection`, `Keep-Alive`, `TE`, `Expect`, `Upgrade`, `Proxy-Connection`)
  parsed at `src/compiler/parser.cc` is unchanged and still cannot express
  dynamic nomination; the gap remains for the `host: "upstream"` request
  policies (ID1/ID2/ID3). (Rut's response path already has the equivalent
  dynamic nomination handling for the upstream→downstream direction —
  `upstream_connection_nominates` in `include/rut/runtime/callbacks_impl.h`.)
  A `Connection` token that nominates `content-length` itself fails the whole
  rewrite closed instead of forwarding an unframed body: dropping that header
  while still copying the already-validated body bytes would desynchronize a
  persistent upstream connection (request smuggling). Envoy's own
  `Utility::sanitizeConnectionHeader` (`source/common/http/utility.cc`) has no
  such exception and does remove a nominated `Content-Length` from the header
  map it forwards to filters/router, but its HTTP/1 client codec then decides
  outbound framing independently of that header at encode time; Rut's
  request-policy serializer writes the body length directly onto the wire, so
  the two are not equivalent and Rut cannot safely replicate Envoy's exact
  byte shape for this nomination without adding chunked-encoding support to
  this path. No recorded oracle case exercises this nomination.
- `Expect: 100-continue` on a body-carrying `host: "preserve"` request: Envoy
  sends the interim `100 Continue` response before reading the body, then
  applies the same hop-by-hop drop as every other request. Rut has no
  interim-response flow anywhere in the runtime (for any route or request
  policy), so `inspect_request_policy_body` fails this shape closed today —
  the client gets an immediate rejection instead of the `100 Continue` it
  expects. This is the same fail-closed behavior the fixed-length request
  policies (ID1/ID2/ID3) already apply to any `Expect` header; `request_envoy_h1`
  does not add interim-response support and this request shape stays outside
  its advertised capability until a `100 Continue` primitive exists.
- `response_policy.header_order: "upstream"` (`response_envoy_h1`, PR4):
  landed. `header_names: "lowercase"`, `connection_header: "close_only"`,
  `status_reason: "canonical"`, and `date: "preserve_or_current"` are admitted
  only together with it (nginx's fixed-order `Synthesized` layout is
  unchanged). The runtime serializer keeps upstream header order, lowercases
  every forwarded name, replaces the first `server` value in place (a later
  duplicate is dropped) or appends `server: envoy` when absent, keeps an
  upstream `date` in place or appends `date: <now>` when absent (`date` then
  `server` when both are absent), appends `connection: close` last only when
  the downstream connection is closing, and looks up the canonical reason
  phrase from a fixed table (failing closed for an unmapped status). Verified
  byte for byte against `tests/fixtures/envoy_oracle_milestone_s.inc`; see
  `docs/envoy-compatibility.md`. An explicit "pass through upstream `server`"
  mode for `server_header_transformation: PASS_THROUGH` is not modeled.
- Route-level `set_header` on the upstream request is available for literal
  values; `x-envoy-upstream-service-time` on the response needs a runtime
  measured value, which no policy exposes. Until then only the
  `suppress_envoy_headers: true` shape can be `SUPPORTED`.
- Raw (non-segment) prefix match for `prefix` values not ending in `/`.
- Explicit route-list ordering: Rut resolves by longest prefix. Either the
  converter proves equivalence or the runtime gains an ordered fallback list.
- Host / virtual-host routing: no host dimension in the route trie today.
- Configurable connect, response and idle timeouts per upstream and per route.
  Rut has no connect-establishment timeout surface at all (not "a different
  default" — no surface); `connect_timeout` is parsed and validated but
  cannot be enforced, and `rut-envoy-convert` prints a stderr warning naming
  the ignored value rather than pretending it did nothing (D2). Today only
  whole-second `response_read_timeout` exists for the response side; Envoy
  defaults are 15s per route (disabled by `timeout: "0s"`, which the milestone
  requires). Rut's fixed 30s `kDefaultUpstreamTimeout` bounds only
  connect-completion-to-first-response-byte and still applies even when the
  route's `timeout` is `"0s"` — it is not a route-timeout substitute and does
  not get disabled by the milestone shape. Body-phase timeout and
  `idle_timeout` have no Rut surface.
- Listener-level protocol restriction: Rut's cleartext `listen` always
  recognizes the h2c connection preface and upgrades
  (`include/rut/runtime/callbacks_impl.h`, `on_header_received`); there is no
  `AstListenDecl` field or runtime flag to make a listener HTTP/1-only. An
  Envoy HCM with `codec_type: "HTTP1"` rejects a client that opens with the
  preface; the lowered Rut listener accepts it. Verified against a live `rut`
  process (raw preface + `SETTINGS` frame answered with an HTTP/2 `SETTINGS`
  frame). This is permissive, not fail-closed: `rut-envoy-convert` proceeds
  and prints a stderr warning rather than gating the whole conversion behind
  a `RutCapabilities` flag, since the divergence is a per-connection client
  shape, not a configuration Rut cannot express (PR #692 round-7 review).
- Non-content-length request/response body framing: `request_policy` has no
  surface admitting `Transfer-Encoding` on the client request, and
  `response_policy.framing` (`include/rut/common/response_policy.h`,
  `ResponsePolicyFraming`) has exactly one legal value, `content_length`. Both
  gaps fail closed rather than mis-forward — verified against a live `rut`
  process: a chunked client request is rejected `400` before reaching the
  upstream, and a chunked or close-delimited upstream response is rejected
  `502` before reaching the client — so no additional capability flag changes
  that behavior; a genuine fix needs new grammar plus runtime support for
  streaming framing on both sides.
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

Per-request/per-response behaviors of an already-converted route (fixed-length
request bodies larger than the 16 KiB request slice, `Expect: 100-continue`,
`TE: trailers`, extension/unrecognized HTTP methods, upstream responses with
more than 64 headers, HTTP/1.0 upstream responses, and upstream responses with
an empty reason phrase) are a different kind of gap from everything above: the
bootstrap still lowers and converts the same way regardless of them, so they
are not `RutCapabilities` dependencies and are not listed here. See "Round-2
review edge cases (PR #692)" below and docs/envoy-compatibility.md for the
Envoy source citations, the exact Rut code paths, and the observed live bytes
for each.

Two more round-4-review findings belong in this same bucket, not as
`RutCapabilities` gates:

- A request target with a `#` fragment (e.g. `GET /admin#frag HTTP/1.1`) is a
  genuine Rut runtime bug, not a converter gap: Envoy rejects it (no HCM
  surface here to enable `strip_fragment_from_path`, and the universal header
  validator rejects `#` in `:path` by default), but Rut's
  `apply_request_policy` (`include/rut/runtime/callbacks_impl.h`) forwards
  `req.path` — which still carries the fragment — to the upstream unchanged,
  never consulting `HttpParser`'s `target_has_fragment`. Verified live (see
  docs/envoy-compatibility.md). This needs a runtime fix in
  `apply_request_policy`, not a converter change — the milestone route's
  method/path shape has no way to exclude it.
- `rut --metrics` reserves `GET /metrics` ahead of route matching on every
  loaded program (`src/main.cc`, `include/rut/runtime/callbacks_impl.h`),
  which would shadow this milestone's converted catch-all route for that one
  path. This is an operator launch-mode choice orthogonal to conversion — the
  generated RUT source is unaffected, and there is no grammar or runtime
  surface for a converted program to opt back into forwarding `/metrics`
  while `--metrics` is set — so it is recorded as a matrix row in
  docs/envoy-compatibility.md rather than gated here.

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
