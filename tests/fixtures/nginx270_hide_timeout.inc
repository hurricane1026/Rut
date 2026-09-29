#pragma once

static constexpr char kIssue270HideTimeoutGolden[] = R"rut(listen 127.0.0.1:8080
upstream nginx_upstream at "127.0.0.1:9000"
pre_route TRACE { return local_response({
  version: .http11, status: 405, reason: "Not Allowed", server: "nginx/1.29.7",
  date: .current, content_type: "text/html", connection: .request,
  head_mode: .reject, body: b"<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n<center><h1>405 Not Allowed</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
}) }
unmatched OPTIONS { return local_response({
  version: .http11, status: 400, reason: "Bad Request", server: "nginx/1.29.7",
  date: .current, content_type: "text/html", connection: .request,
  head_mode: .reject, body: b"<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
}) }
unmatched CONNECT { return local_response({
  version: .http11, status: 405, reason: "Not Allowed", server: "nginx/1.29.7",
  date: .current, content_type: "text/html", connection: .request,
  head_mode: .reject, body: b"<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n<center><h1>405 Not Allowed</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
}) }
unmatched { return local_response({
  version: .http11, status: 400, reason: "Bad Request", server: "nginx/1.29.7",
  date: .current, content_type: "text/html", connection: .request,
  head_mode: .suppressBody, body: b"<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
}) }
route HEAD "/" {
    if req.hasContentLength {
        return forward(nginx_upstream, request_policy: {
            version: .http11,
            host: .upstream,
            connection: .omit,
            content_length_position: .afterHost,
            strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade]
        },
        response_policy: {
            version: .http11,
            framing: .contentLength,
            connection: .request,
            head_mode: .suppressBody,
            server: "nginx/1.29.7",
            date: .current,
            hide_headers: ["Date", "Server", "X-Pad", "X-Ab9_-Ab9_-Ab9_-Ab9_-Ab9_-Ab9_-Ab9_-Ab9_-Cd0E"]
        },
        failure_policy: {
            version: .http11,
            status: 502,
            reason: "Bad Gateway",
            content_type: "text/html",
            server: "nginx/1.29.7",
            date: .current,
            connection: .request,
            head_mode: .suppressBody,
            body: b"<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n<body>\r\n<center><h1>502 Bad Gateway</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
        },
        timeout_failure_policy: {
            version: .http11,
            status: 504,
            reason: "Gateway Time-out",
            content_type: "text/html",
            server: "nginx/1.29.7",
            date: .current,
            connection: .request,
            head_mode: .suppressBody,
            body: b"<html>\r\n<head><title>504 Gateway Time-out</title></head>\r\n<body>\r\n<center><h1>504 Gateway Time-out</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
        },
        response_read_timeout: 1s
    )
    } else {
        return forward(nginx_upstream, request_policy: {
            version: .http11,
            host: .upstream,
            connection: .omit,
            strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade]
        },
        response_policy: {
            version: .http11,
            framing: .contentLength,
            connection: .request,
            head_mode: .suppressBody,
            server: "nginx/1.29.7",
            date: .current,
            hide_headers: ["Date", "Server", "X-Pad", "X-Ab9_-Ab9_-Ab9_-Ab9_-Ab9_-Ab9_-Ab9_-Ab9_-Cd0E"]
        },
        failure_policy: {
            version: .http11,
            status: 502,
            reason: "Bad Gateway",
            content_type: "text/html",
            server: "nginx/1.29.7",
            date: .current,
            connection: .request,
            head_mode: .suppressBody,
            body: b"<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n<body>\r\n<center><h1>502 Bad Gateway</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
        },
        timeout_failure_policy: {
            version: .http11,
            status: 504,
            reason: "Gateway Time-out",
            content_type: "text/html",
            server: "nginx/1.29.7",
            date: .current,
            connection: .request,
            head_mode: .suppressBody,
            body: b"<html>\r\n<head><title>504 Gateway Time-out</title></head>\r\n<body>\r\n<center><h1>504 Gateway Time-out</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
        },
        response_read_timeout: 1s
    )
    }
}
route GET "/" {
    return forward(nginx_upstream, request_policy: {
            version: .http11,
            host: .upstream,
            connection: .omit,
            strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade]
        },
        response_policy: {
            version: .http11,
            framing: .contentLength,
            connection: .request,
            server: "nginx/1.29.7",
            date: .current,
            hide_headers: ["Date", "Server", "X-Pad", "X-Ab9_-Ab9_-Ab9_-Ab9_-Ab9_-Ab9_-Ab9_-Ab9_-Cd0E"]
        },
        failure_policy: {
            version: .http11,
            status: 502,
            reason: "Bad Gateway",
            content_type: "text/html",
            server: "nginx/1.29.7",
            date: .current,
            connection: .request,
            body: b"<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n<body>\r\n<center><h1>502 Bad Gateway</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
        },
        timeout_failure_policy: {
            version: .http11,
            status: 504,
            reason: "Gateway Time-out",
            content_type: "text/html",
            server: "nginx/1.29.7",
            date: .current,
            connection: .request,
            body: b"<html>\r\n<head><title>504 Gateway Time-out</title></head>\r\n<body>\r\n<center><h1>504 Gateway Time-out</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
        },
        response_read_timeout: 1s,
        response_buffering: .bounded
    )
}
route "/" {
    return forward(nginx_upstream, request_policy: {
            version: .http11,
            host: .upstream,
            connection: .omit,
            strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade]
        },
        response_policy: {
            version: .http11,
            framing: .contentLength,
            connection: .request,
            server: "nginx/1.29.7",
            date: .current,
            hide_headers: ["Date", "Server", "X-Pad", "X-Ab9_-Ab9_-Ab9_-Ab9_-Ab9_-Ab9_-Ab9_-Ab9_-Cd0E"]
        },
        failure_policy: {
            version: .http11,
            status: 502,
            reason: "Bad Gateway",
            content_type: "text/html",
            server: "nginx/1.29.7",
            date: .current,
            connection: .request,
            body: b"<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n<body>\r\n<center><h1>502 Bad Gateway</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
        },
        timeout_failure_policy: {
            version: .http11,
            status: 504,
            reason: "Gateway Time-out",
            content_type: "text/html",
            server: "nginx/1.29.7",
            date: .current,
            connection: .request,
            body: b"<html>\r\n<head><title>504 Gateway Time-out</title></head>\r\n<body>\r\n<center><h1>504 Gateway Time-out</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n"
        },
        response_read_timeout: 1s
    )
}
)rut";
