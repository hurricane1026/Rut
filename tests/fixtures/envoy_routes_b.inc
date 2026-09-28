#pragma once

// Golden RUT output for envoy-pr-plan.md's PR 8 route-list lowering,
// scenario (b): catch-all "/" declared before prefix "/api/". Codex round-9
// review on PR #695: "/" is a byte-prefix ancestor of every other accepted
// prefix, so an earlier "/" makes every later prefix node permanently
// unreachable, not merely resolvable through it -- `build_lowering_plan`
// (src/envoy/converter.cc) now drops such a node before it is ever
// registered, so "/api" never gets its own `route`/`route HEAD` block at
// all (no dead node is planned, and no token budget is spent on it). This
// output is therefore root-only, both `envoy_cluster_0` (used) and
// `envoy_cluster_1` (declared but now unused by any route, still emitted as
// an `upstream` line -- see `lower_to_rut`'s unconditional per-cluster
// loop) present.
// All RutCapabilities are set to true (see tests/fixtures/envoy_milestone_s.inc
// for why): this pins the target text byte for byte ahead of the runtime PRs
// (PR3-PR5) that make each capability real. Recorded from
// rut::envoy::lower_to_rut(model, {true, true, true}) via
// tests/test_envoy_convert.cc's envoy_routes_b golden test.
static constexpr char kEnvoyRoutesBGolden[] = R"rut(listen :8080
upstream envoy_cluster_0 at "127.0.0.1:9000"
upstream envoy_cluster_1 at "127.0.0.1:9001"
unmatched { return local_response({
  version: .http11, status: 404, reason: "Not Found", server: "envoy",
  date: .current, connection: .request, connection_header: .closeOnly,
  header_names: .lowercase, header_order: .dateServerLength,
  head_mode: .suppressBody, body: b""
}) }
route HEAD "/" {
    return forward(envoy_cluster_0, request_policy: {
            version: .http11,
            host: .preserve,
            connection: .omit,
            header_names: .lowercase,
            forwarded_proto: .http,
            strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade, .proxyConnection]
        },
        response_policy: {
            version: .http11,
            framing: .contentLength,
            connection: .request,
            head_mode: .suppressBody,
            header_order: .upstream,
            header_names: .lowercase,
            connection_header: .closeOnly,
            status_reason: .canonical,
            server: "envoy",
            date: .preserveOrCurrent,
            hide_headers: []
        },
        failure_policy: {
            version: .http11,
            status: 503,
            reason: "Service Unavailable",
            content_type: "text/plain",
            server: "envoy",
            date: .current,
            connection: .request,
            connection_header: .closeOnly,
            header_names: .lowercase,
            header_order: .lengthTypeDateServer,
            head_mode: .suppressBody,
            body: b"upstream connect error or disconnect/reset before headers. reset reason: remote connection failure, transport failure reason: delayed connect error: 111"
        }
    )
}
route "/" {
    return forward(envoy_cluster_0, request_policy: {
            version: .http11,
            host: .preserve,
            connection: .omit,
            header_names: .lowercase,
            forwarded_proto: .http,
            strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade, .proxyConnection]
        },
        response_policy: {
            version: .http11,
            framing: .contentLength,
            connection: .request,
            header_order: .upstream,
            header_names: .lowercase,
            connection_header: .closeOnly,
            status_reason: .canonical,
            server: "envoy",
            date: .preserveOrCurrent,
            hide_headers: []
        },
        failure_policy: {
            version: .http11,
            status: 503,
            reason: "Service Unavailable",
            content_type: "text/plain",
            server: "envoy",
            date: .current,
            connection: .request,
            connection_header: .closeOnly,
            header_names: .lowercase,
            header_order: .lengthTypeDateServer,
            body: b"upstream connect error or disconnect/reset before headers. reset reason: remote connection failure, transport failure reason: delayed connect error: 111"
        }
    )
}
)rut";
