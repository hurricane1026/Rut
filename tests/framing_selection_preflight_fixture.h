#pragma once

// Ordinary RUT source for the verifier-only request-framing selector. Both
// branches deliberately carry the same timeout bundle; only the immutable
// request policy differs.
inline constexpr char kFramingSelectionPreflightSource[] = R"rut(
upstream backend at "127.0.0.1:9000"
route HEAD "/one" {
  if req.hasContentLength {
    return forward(backend,
      request_policy: {version: "HTTP/1.1", host: "upstream", connection: "omit",
        content_length_position: "after_host",
        strip_headers: ["Connection", "Keep-Alive", "TE", "Expect", "Upgrade"]},
      response_policy: {version: "HTTP/1.1", framing: "content_length",
        connection: "request", server: "rut", date: "current",
        head_mode: "suppress_body", hide_headers: []},
      failure_policy: {version: "HTTP/1.1", status: 502, reason: "Bad Gateway",
        content_type: "text/plain", server: "rut", date: "current",
        connection: "request", head_mode: "suppress_body", body: b"bad"},
      timeout_failure_policy: {version: "HTTP/1.1", status: 504,
        reason: "Gateway Time-out", content_type: "text/plain", server: "rut",
        date: "current", connection: "request", head_mode: "suppress_body", body: b"slow"},
      response_read_timeout: 1s)
  } else {
    return forward(backend,
      request_policy: {version: "HTTP/1.1", host: "upstream", connection: "omit",
        strip_headers: ["Connection", "Keep-Alive", "TE", "Expect", "Upgrade"]},
      response_policy: {version: "HTTP/1.1", framing: "content_length",
        connection: "request", server: "rut", date: "current",
        head_mode: "suppress_body", hide_headers: []},
      failure_policy: {version: "HTTP/1.1", status: 502, reason: "Bad Gateway",
        content_type: "text/plain", server: "rut", date: "current",
        connection: "request", head_mode: "suppress_body", body: b"bad"},
      timeout_failure_policy: {version: "HTTP/1.1", status: 504,
        reason: "Gateway Time-out", content_type: "text/plain", server: "rut",
        date: "current", connection: "request", head_mode: "suppress_body", body: b"slow"},
      response_read_timeout: 1s)
  }
}
)rut";
