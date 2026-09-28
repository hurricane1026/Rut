#pragma once

// Golden RUT output for envoy-pr-plan.md's PR 8 route-list lowering,
// scenario (f): exact path "/api" declared before prefix "/api/" naming the
// same literal. Node "/api" ends with the own-prefix arm turned
// unconditional, but the EARLIER conditional exact arm for "/api" already
// resolves the literal path correctly, so the node is NOT blocked (Codex P1
// on PR #695: the converter used to request the `route exact "/api"` 404
// fallback here too, which would have shadowed this earlier arm and returned
// 404 for "/api" instead of forwarding through it).
//
// Codex sweep-11 review on PR #720: `golden_routes_f_exact_then_own_prefix_
// not_blocked` (tests/test_envoy_convert.cc) used to check only four output
// substrings, so docs/envoy-compatibility.md's claim that scenario (f) is
// pinned byte-for-byte like (b)/(c) was false. This fixture makes that claim
// true.
//
// All RutCapabilities are set to true (see tests/fixtures/envoy_milestone_s.inc
// for why): this pins the target text byte for byte ahead of the runtime PRs
// (PR3-PR5) that make each capability real. Recorded from
// rut::envoy::lower_to_rut(model, {true, true, true}) via
// tests/test_envoy_convert.cc's envoy_routes_f golden test.
static constexpr char kEnvoyRoutesFGolden[] = R"rut(listen :8080
upstream envoy_cluster_0 at "127.0.0.1:9001"
upstream envoy_cluster_1 at "127.0.0.1:9002"
unmatched { return local_response({
  version: "HTTP/1.1", status: 404, reason: "Not Found", server: "envoy",
  date: "current", connection: "request", connection_header: "close_only",
  header_names: "lowercase", header_order: "date_server_length",
  head_mode: "suppress_body", body: b""
}) }
route HEAD "/api" {
    if req.pathOnly == "/api" {
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
    } else {
    return forward(envoy_cluster_1, request_policy: {
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
}
route "/api" {
    if req.pathOnly == "/api" {
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
    } else {
    return forward(envoy_cluster_1, request_policy: {
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
}
)rut";
