#pragma once

// Golden RUT output for envoy-pr-plan.md's PR 8 route-list lowering,
// scenario (a): prefix "/api/" declared before the catch-all "/" (node
// "/api" resolves the literal path "/api" via the root ancestor, not a
// 404). All RutCapabilities are set to true (see
// tests/fixtures/envoy_milestone_s.inc for why).
//
// History (Codex round-6 review, P1, then sweep-8): this scenario used to be
// a golden success case, then briefly a fail-closed one. At 8804 bytes this
// text is comfortably under `RutSource::kCapacity` (128 KiB), but lexing it
// with `rut`'s own frontend lexer (`rut::lex`) failed with `TooManyTokens`
// at byte 8400 back when `LexedTokens::kMaxTokens`
// (include/rut/compiler/lexer.h) was only 932 tokens -- a program the
// converter used to report success for but `rut` itself couldn't load, so
// `lower_to_rut` was made to fail closed on this exact shape instead.
// #697 later raised `kMaxTokens` to 4096, under which this exact,
// unchanged text lexes successfully at 963 tokens
// (`token_budget_goldens_match_the_real_lexer`,
// tests/test_envoy_convert.cc), so `golden_routes_a_prefix_then_root`
// (tests/test_envoy_convert.cc) is a byte-exact golden success test again,
// the same shape as (b)/(c). Recorded from
// rut::envoy::lower_to_rut(model, {true, true, true}).
static constexpr char kEnvoyRoutesAGolden[] = R"rut(listen :8080
upstream envoy_cluster_0 at "127.0.0.1:9000"
upstream envoy_cluster_1 at "127.0.0.1:9001"
unmatched { return local_response({
  version: .http11, status: 404, reason: "Not Found", server: "envoy",
  date: .current, connection: .request, connection_header: .closeOnly,
  header_names: .lowercase, header_order: .dateServerLength,
  head_mode: .suppressBody, body: b""
}) }
route HEAD "/api" {
    if req.pathOnly != "/api" {
    return forward(envoy_cluster_1, request_policy: {
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
            body: b"upstream connect error or disconnect/reset before headers. reset reason: remote connection failure"
        }
    )
    } else {
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
            body: b"upstream connect error or disconnect/reset before headers. reset reason: remote connection failure"
        }
    )
    }
}
route "/api" {
    if req.pathOnly != "/api" {
    return forward(envoy_cluster_1, request_policy: {
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
            body: b"upstream connect error or disconnect/reset before headers. reset reason: remote connection failure"
        }
    )
    } else {
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
            body: b"upstream connect error or disconnect/reset before headers. reset reason: remote connection failure"
        }
    )
    }
}
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
            body: b"upstream connect error or disconnect/reset before headers. reset reason: remote connection failure"
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
            body: b"upstream connect error or disconnect/reset before headers. reset reason: remote connection failure"
        }
    )
}
)rut";
