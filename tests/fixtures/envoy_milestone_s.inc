#pragma once

// Golden RUT output for the milestone-S Envoy bootstrap (docs/envoy-converter.md,
// "milestone-S"; envoy-pr-plan.md, PR1 "Emission") with all RutCapabilities set
// to true. Recorded here so tests/test_envoy_convert.cc can pin the exact
// target text byte for byte ahead of the runtime PRs (PR3-PR5) that make each
// capability real. Listener 0.0.0.0:8080, endpoint 127.0.0.1:9000.
static constexpr char kEnvoyMilestoneSGolden[] = R"rut(listen :8080
upstream envoy_cluster_0 at "127.0.0.1:9000"
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
