#pragma once

// Ordinary RUT source for the verifier-only request-framing selector. Both
// branches deliberately carry the same timeout bundle; only the immutable
// request policy differs.
inline constexpr char kFramingSelectionPreflightSource[] = R"rut(
upstream backend at "127.0.0.1:9000"
route HEAD "/one" {
  if req.hasContentLength {
    return forward(backend,
      request_policy: {version: .http11, host: .upstream, connection: .omit,
        content_length_position: .afterHost,
        strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade]},
      response_policy: {version: .http11, framing: .contentLength,
        connection: .request, server: "rut", date: .current,
        head_mode: .suppressBody, hide_headers: []},
      failure_policy: {version: .http11, status: 502, reason: "Bad Gateway",
        content_type: "text/plain", server: "rut", date: .current,
        connection: .request, head_mode: .suppressBody, body: b"bad"},
      timeout_failure_policy: {version: .http11, status: 504,
        reason: "Gateway Time-out", content_type: "text/plain", server: "rut",
        date: .current, connection: .request, head_mode: .suppressBody, body: b"slow"},
      response_read_timeout: 1s)
  } else {
    return forward(backend,
      request_policy: {version: .http11, host: .upstream, connection: .omit,
        strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade]},
      response_policy: {version: .http11, framing: .contentLength,
        connection: .request, server: "rut", date: .current,
        head_mode: .suppressBody, hide_headers: []},
      failure_policy: {version: .http11, status: 502, reason: "Bad Gateway",
        content_type: "text/plain", server: "rut", date: .current,
        connection: .request, head_mode: .suppressBody, body: b"bad"},
      timeout_failure_policy: {version: .http11, status: 504,
        reason: "Gateway Time-out", content_type: "text/plain", server: "rut",
        date: .current, connection: .request, head_mode: .suppressBody, body: b"slow"},
      response_read_timeout: 1s)
  }
}
)rut";

inline constexpr char kCompleteContentLengthFramingSelectionSource[] = R"rut(
upstream backend at "127.0.0.1:9000"
route GET "/one" {
  if req.hasContentLength {
    return forward(backend,
      request_policy: {version: .http11, host: .upstream, connection: .omit,
        strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade]},
      response_policy: {version: .http11, framing: .contentLength,
        connection: .request, server: "rut", date: .current, hide_headers: []},
      failure_policy: {version: .http11, status: 502, reason: "Bad Gateway",
        content_type: "text/plain", server: "rut", date: .current,
        connection: .request, body: b"bad"},
      timeout_failure_policy: {version: .http11, status: 504,
        reason: "Gateway Time-out", content_type: "text/plain", server: "rut",
        date: .current, connection: .request, body: b"slow"},
      response_read_timeout: 60s,
      response_buffering: .completeContentLength)
  } else {
    return forward(backend,
      request_policy: {version: .http11, host: .upstream, connection: .omit,
        retained_header_value: .trimSpPreserveHtab,
        strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade]},
      response_policy: {version: .http11, framing: .contentLength,
        connection: .request, server: "rut", date: .current, hide_headers: []},
      failure_policy: {version: .http11, status: 502, reason: "Bad Gateway",
        content_type: "text/plain", server: "rut", date: .current,
        connection: .request, body: b"bad"},
      timeout_failure_policy: {version: .http11, status: 504,
        reason: "Gateway Time-out", content_type: "text/plain", server: "rut",
        date: .current, connection: .request, body: b"slow"},
      response_read_timeout: 60s,
      response_buffering: .completeContentLength)
  }
}
)rut";

// Identical to kCompleteContentLengthFramingSelectionSource but exercises the
// Bounded mode on the same id1/id3 GET framing split (both branches must
// carry the same actual mode; see same_framing_bundle in analyze.cc).
inline constexpr char kBoundedFramingSelectionSource[] = R"rut(
upstream backend at "127.0.0.1:9000"
route GET "/one" {
  if req.hasContentLength {
    return forward(backend,
      request_policy: {version: .http11, host: .upstream, connection: .omit,
        strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade]},
      response_policy: {version: .http11, framing: .contentLength,
        connection: .request, server: "rut", date: .current, hide_headers: []},
      failure_policy: {version: .http11, status: 502, reason: "Bad Gateway",
        content_type: "text/plain", server: "rut", date: .current,
        connection: .request, body: b"bad"},
      timeout_failure_policy: {version: .http11, status: 504,
        reason: "Gateway Time-out", content_type: "text/plain", server: "rut",
        date: .current, connection: .request, body: b"slow"},
      response_read_timeout: 60s,
      response_buffering: .bounded)
  } else {
    return forward(backend,
      request_policy: {version: .http11, host: .upstream, connection: .omit,
        retained_header_value: .trimSpPreserveHtab,
        strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade]},
      response_policy: {version: .http11, framing: .contentLength,
        connection: .request, server: "rut", date: .current, hide_headers: []},
      failure_policy: {version: .http11, status: 502, reason: "Bad Gateway",
        content_type: "text/plain", server: "rut", date: .current,
        connection: .request, body: b"bad"},
      timeout_failure_policy: {version: .http11, status: 504,
        reason: "Gateway Time-out", content_type: "text/plain", server: "rut",
        date: .current, connection: .request, body: b"slow"},
      response_read_timeout: 60s,
      response_buffering: .bounded)
  }
}
)rut";
