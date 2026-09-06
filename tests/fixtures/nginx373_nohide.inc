#pragma once

static constexpr char kIssue373NoHideGolden[] = R"rut(listen 127.0.0.1:8080
upstream nginx_upstream at "127.0.0.1:9000"
pre_route TRACE { return local_response({
  version: "HTTP/1.1", status: 405, reason: "Not Allowed", server: "nginx/1.29.7",
  date: "current", content_type: "text/html", connection: "request",
  head_mode: "reject", body: b"<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n<center><h1>405 Not Allowed</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
}) }
unmatched OPTIONS { return local_response({
  version: "HTTP/1.1", status: 400, reason: "Bad Request", server: "nginx/1.29.7",
  date: "current", content_type: "text/html", connection: "request",
  head_mode: "reject", body: b"<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
}) }
unmatched CONNECT { return local_response({
  version: "HTTP/1.1", status: 405, reason: "Not Allowed", server: "nginx/1.29.7",
  date: "current", content_type: "text/html", connection: "request",
  head_mode: "reject", body: b"<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n<center><h1>405 Not Allowed</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
}) }
unmatched { return local_response({
  version: "HTTP/1.1", status: 400, reason: "Bad Request", server: "nginx/1.29.7",
  date: "current", content_type: "text/html", connection: "request",
  head_mode: "suppress_body", body: b"<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
}) }
route HEAD "/" {
    return forward(nginx_upstream, request_policy: {
            version: "HTTP/1.1",
            host: "upstream",
            connection: "omit",
            strip_headers: ["Connection", "Keep-Alive", "TE", "Expect", "Upgrade"]
        },
        response_policy: {
            version: "HTTP/1.1",
            framing: "content_length",
            connection: "request",
            head_mode: "suppress_body",
            server: "nginx/1.29.7",
            date: "current",
            hide_headers: ["Date", "Server", "X-Pad"]
        },
        failure_policy: {
            version: "HTTP/1.1",
            status: 502,
            reason: "Bad Gateway",
            content_type: "text/html",
            server: "nginx/1.29.7",
            date: "current",
            connection: "request",
            head_mode: "suppress_body",
            body: b"<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n<body>\r\n<center><h1>502 Bad Gateway</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
        }
    )
}
route GET "/" {
    return forward(nginx_upstream, request_policy: {
            version: "HTTP/1.1",
            host: "upstream",
            connection: "omit",
            strip_headers: ["Connection", "Keep-Alive", "TE", "Expect", "Upgrade"]
        },
        response_policy: {
            version: "HTTP/1.1",
            framing: "content_length",
            connection: "request",
            server: "nginx/1.29.7",
            date: "current",
            hide_headers: ["Date", "Server", "X-Pad"]
        },
        failure_policy: {
            version: "HTTP/1.1",
            status: 502,
            reason: "Bad Gateway",
            content_type: "text/html",
            server: "nginx/1.29.7",
            date: "current",
            connection: "request",
            body: b"<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n<body>\r\n<center><h1>502 Bad Gateway</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
        },
        timeout_failure_policy: {
            version: "HTTP/1.1",
            status: 504,
            reason: "Gateway Time-out",
            content_type: "text/html",
            server: "nginx/1.29.7",
            date: "current",
            connection: "request",
            body: b"<html>\r\n<head><title>504 Gateway Time-out</title></head>\r\n<body>\r\n<center><h1>504 Gateway Time-out</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
        },
        response_read_timeout: 60s,
        response_buffering: "complete_content_length"
    )
}
route "/" {
    return forward(nginx_upstream, request_policy: {
            version: "HTTP/1.1",
            host: "upstream",
            connection: "omit",
            strip_headers: ["Connection", "Keep-Alive", "TE", "Expect", "Upgrade"]
        },
        response_policy: {
            version: "HTTP/1.1",
            framing: "content_length",
            connection: "request",
            server: "nginx/1.29.7",
            date: "current",
            hide_headers: ["Date", "Server", "X-Pad"]
        },
        failure_policy: {
            version: "HTTP/1.1",
            status: 502,
            reason: "Bad Gateway",
            content_type: "text/html",
            server: "nginx/1.29.7",
            date: "current",
            connection: "request",
            body: b"<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n<body>\r\n<center><h1>502 Bad Gateway</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
        }
    )
}
)rut";
