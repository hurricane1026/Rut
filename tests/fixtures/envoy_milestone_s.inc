#pragma once

// Golden RUT output for the milestone-S Envoy bootstrap (docs/envoy-converter.md,
// "milestone-S"; envoy-pr-plan.md, PR1 "Emission") with all RutCapabilities set
// to true. Recorded here so tests/test_envoy_convert.cc can pin the exact
// target text byte for byte ahead of the runtime PRs (PR3-PR5) that make each
// capability real. Listener 0.0.0.0:8080, endpoint 127.0.0.1:9000.
static constexpr char kEnvoyMilestoneSGolden[] = R"rut(listen :8080
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
            body: b"upstream connect error or disconnect/reset before headers. reset reason: remote connection failure"
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
            body: b"upstream connect error or disconnect/reset before headers. reset reason: remote connection failure"
        }
    )
}
)rut";
