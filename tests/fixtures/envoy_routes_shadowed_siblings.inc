#pragma once

// Golden RUT output for the Codex round-9 review on PR #695: "/" declared
// before TWO distinct sibling prefixes, "/api/" and "/admin/". Envoy's
// prefix match is a raw byte-prefix test with no segment awareness of its
// own, so the earlier "/" already matches every path either sibling could
// ever match -- both are globally shadowed and neither gets its own node.
// This is Codex's own reported example: before the round-9 fix,
// `build_lowering_plan` (src/envoy/converter.cc) still registered both dead
// nodes, emitting a HEAD/any-method forwarding block for each (all
// forwarding through root's own cluster) -- about 938 real lexer tokens for
// this exact shape, over `LexedTokens::kMaxTokens` (932). After the fix ("a
// route is dropped before it is ever registered as a node when an earlier
// route's prefix is a byte-prefix of its own"), this lowers to the
// root-only text below, about 356 real tokens
// (`shadowed_siblings_stays_under_budget` in tests/test_envoy_convert.cc
// pins the exact count). All three clusters are still declared as
// `upstream` lines (`lower_to_rut` emits one per `model.clusters` entry
// unconditionally), even though only `envoy_cluster_0` is ever reachable by
// a route.
// All RutCapabilities are set to true (see
// tests/fixtures/envoy_milestone_s.inc for why): this pins the target text
// byte for byte ahead of the runtime PRs (PR3-PR5) that make each
// capability real. Recorded from
// rut::envoy::lower_to_rut(model, {true, true, true}) via
// tests/test_envoy_convert.cc's shadowed-siblings golden test.
static constexpr char kEnvoyRoutesShadowedSiblingsGolden[] = R"rut(listen :8080
upstream envoy_cluster_0 at "127.0.0.1:9000"
upstream envoy_cluster_1 at "127.0.0.1:9001"
upstream envoy_cluster_2 at "127.0.0.1:9002"
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
            body: b"upstream connect error or disconnect/reset before headers. reset reason: remote connection failure, transport failure reason: delayed connect error: 111"
        }
    )
}
route "/" {
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
            body: b"upstream connect error or disconnect/reset before headers. reset reason: remote connection failure, transport failure reason: delayed connect error: 111"
        }
    )
}
)rut";
