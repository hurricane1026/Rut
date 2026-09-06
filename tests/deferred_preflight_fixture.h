#pragma once

// Ordinary RUT source for the one verifier-proven post-selection preflight
// shape. Kept shared so frontend, JIT, loader, and runtime tests exercise the
// same policy identity and branch order.
inline constexpr char kDeferredPreflightSource[] = R"rut(
upstream backend at "127.0.0.1:9000"
route GET "/" {
  if req.pathOnly == "/old" {
    return redirect({scheme: "http", authority: "static",
      static_authority: "redirect.example", port: "omit", path: "static",
      query: "discard", date: "current", connection: "close", status: 301,
      reason: "Moved Permanently", server: "nginx/1.29.7", content_type: "text/html",
      header_order: "connection_then_location", target_path: "/new", body: b"fixed"})
  } else {
    return forward(backend,
      request_policy: {version: "HTTP/1.1", host: "upstream", connection: "omit",
        strip_headers: ["Connection", "Keep-Alive", "TE", "Expect", "Upgrade"]},
      response_policy: {version: "HTTP/1.1", framing: "content_length",
        connection: "request", server: "rut", date: "current", hide_headers: []},
      failure_policy: {version: "HTTP/1.1", status: 502, reason: "Bad Gateway",
        content_type: "text/plain", server: "rut", date: "current",
        connection: "request", body: b"bad"},
      timeout_failure_policy: {version: "HTTP/1.1", status: 504,
        reason: "Gateway Time-out", content_type: "text/plain", server: "rut",
        date: "current", connection: "request", body: b"slow"},
      response_read_timeout: 1s,
      response_buffering: "complete_content_length")
  }
}
)rut";
