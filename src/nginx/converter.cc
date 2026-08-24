#include "rut/nginx/converter.h"

namespace rut::nginx {
namespace {

constexpr bool eq(Str a, const char* b, u32 n) {
    if (a.ptr == nullptr || a.len != n) return false;
    for (u32 i = 0; i < n; i++) {
        if (a.ptr[i] != b[i]) return false;
    }
    return true;
}

auto invalid_integer(Span span, Str detail) {
    return frontend_error(FrontendError::InvalidInteger, span, detail);
}

auto unsupported(Span span, Str detail) {
    return frontend_error(FrontendError::UnsupportedSyntax, span, detail);
}

auto out_of_memory(Span span, Str detail) {
    return frontend_error(FrontendError::OutOfMemory, span, detail);
}

constexpr bool is_default_span(const Span& span) {
    return span.start == 0 && span.end == 0 && span.line == 1 && span.col == 1;
}

constexpr bool is_valid_span(const Span& span) {
    return span.start < span.end && span.line != 0 && span.col != 0;
}

constexpr bool span_contains(const Span& outer, const Span& inner) {
    return outer.start <= inner.start && inner.end <= outer.end;
}

Span model_span(const Server& server) {
    if (is_valid_span(server.location.span)) return server.location.span;
    if (is_valid_span(server.location.path_span)) return server.location.path_span;
    return server.span;
}

bool has_exact_local_return_inventory(const ExactLocalReturnLocation& location) {
    const LocalReturn& response = location.response;
    return location.present || location.path.ptr != nullptr || location.path.len != 0 ||
           !is_default_span(location.path_span) || !is_default_span(location.span) ||
           response.status != 0 || response.body.ptr != nullptr || response.body.len != 0 ||
           !is_default_span(response.body_span) || !is_default_span(response.span);
}

Span exact_local_return_span(const Server& server) {
    const auto& location = server.exact_local_return;
    if (is_valid_span(location.span)) return location.span;
    if (is_valid_span(location.path_span)) return location.path_span;
    if (is_valid_span(location.response.span)) return location.response.span;
    if (is_valid_span(location.response.body_span)) return location.response.body_span;
    return server.span;
}

FrontendResult<bool> validate_proxy_read_timeout(const Server& server) {
    const ProxyReadTimeout& timeout = server.location.proxy_read_timeout;
    if (!timeout.present) {
        if (timeout.milliseconds != 0 || !is_default_span(timeout.span) ||
            !is_default_span(timeout.value_span)) {
            const Span span = is_valid_span(timeout.span)         ? timeout.span
                              : is_valid_span(timeout.value_span) ? timeout.value_span
                                                                  : model_span(server);
            return unsupported(span, lit_str("invalid absent proxy_read_timeout model"));
        }
        return true;
    }

    const Location& location = server.location;
    const u32 path_offset = location.path_span.start - location.span.start;
    const bool same_line_path_consistent =
        location.path_span.line != location.span.line ||
        (path_offset <= 0xFFFFFFFFu - location.span.col &&
         location.path_span.col == location.span.col + path_offset);
    if (!eq(location.path, "/", 1) || !is_valid_span(location.span) ||
        !is_valid_span(location.path_span) || !span_contains(location.span, location.path_span) ||
        location.path_span.end - location.path_span.start != 1 ||
        location.path_span.line < location.span.line || !same_line_path_consistent) {
        const Span span =
            is_valid_span(location.path_span) ? location.path_span : model_span(server);
        return unsupported(span, lit_str("invalid proxy_read_timeout location model"));
    }

    const u32 value_offset = timeout.value_span.start - timeout.span.start;
    const bool same_line_consistent = timeout.value_span.line != timeout.span.line ||
                                      (value_offset <= 0xFFFFFFFFu - timeout.span.col &&
                                       timeout.value_span.col == timeout.span.col + value_offset);
    if (!is_valid_span(server.location.span) || !is_valid_span(timeout.span) ||
        !is_valid_span(timeout.value_span) || !span_contains(server.location.span, timeout.span) ||
        !span_contains(timeout.span, timeout.value_span) ||
        timeout.value_span.line < timeout.span.line || !same_line_consistent) {
        return unsupported(model_span(server), lit_str("invalid proxy_read_timeout spans"));
    }
    if (timeout.milliseconds < 1000 || timeout.milliseconds > 63000 ||
        timeout.milliseconds % 1000 != 0) {
        return unsupported(timeout.value_span, lit_str("invalid proxy_read_timeout milliseconds"));
    }
    return unsupported(timeout.span, lit_str("proxy_read_timeout lowering is not implemented"));
}

class Writer {
public:
    explicit Writer(RutSource& output) : output_(output) {}

    bool put(Str text) {
        if (text.len > RutSource::kCapacity - output_.len) return false;
        for (u32 i = 0; i < text.len; i++) output_.data[output_.len + i] = text.ptr[i];
        output_.len += text.len;
        return true;
    }

    bool put_lit(const char* text, u32 len) { return put(Str{text, len}); }

    bool put_cstr(const char* text) {
        return put_lit(text, static_cast<u32>(__builtin_strlen(text)));
    }

    bool put_u16(u16 value) {
        char digits[5];
        u32 count = 0;
        do {
            digits[count++] = static_cast<char>('0' + (value % 10));
            value = static_cast<u16>(value / 10);
        } while (value != 0);
        if (count > RutSource::kCapacity - output_.len) return false;
        for (u32 i = 0; i < count; i++) output_.data[output_.len + i] = digits[count - i - 1];
        output_.len += count;
        return true;
    }

    bool put_ipv4(const u8 address[4]) {
        for (u32 i = 0; i < 4; i++) {
            if (!put_u8(address[i])) return false;
            if (i != 3 && !put_lit(".", 1)) return false;
        }
        return true;
    }

private:
    bool put_u8(u8 value) {
        char digits[3];
        u32 count = 0;
        do {
            digits[count++] = static_cast<char>('0' + (value % 10));
            value = static_cast<u8>(value / 10);
        } while (value != 0);
        if (count > RutSource::kCapacity - output_.len) return false;
        for (u32 i = 0; i < count; i++) output_.data[output_.len + i] = digits[count - i - 1];
        output_.len += count;
        return true;
    }

    RutSource& output_;
};

static constexpr char kBadRequestBody[] =
    "<html>\\r\\n"
    "<head><title>400 Bad Request</title></head>\\r\\n"
    "<body>\\r\\n"
    "<center><h1>400 Bad Request</h1></center>\\r\\n"
    "<hr><center>nginx/1.29.7</center>\\r\\n"
    "</body>\\r\\n"
    "</html>\\r\\n";

static constexpr char kNotAllowedBody[] =
    "<html>\\r\\n"
    "<head><title>405 Not Allowed</title></head>\\r\\n"
    "<body>\\r\\n"
    "<center><h1>405 Not Allowed</h1></center>\\r\\n"
    "<hr><center>nginx/1.29.7</center>\\r\\n"
    "</body>\\r\\n"
    "</html>\\r\\n";

static constexpr char kBadGatewayBody[] =
    "<html>\\r\\n<head><title>502 Bad Gateway</title></head>\\r\\n"
    "<body>\\r\\n<center><h1>502 Bad Gateway</h1></center>\\r\\n"
    "<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n"
    "</html>\\r\\n";

static constexpr char kGatewayTimeoutBody[] =
    "<html>\\r\\n<head><title>504 Gateway Time-out</title></head>\\r\\n"
    "<body>\\r\\n<center><h1>504 Gateway Time-out</h1></center>\\r\\n"
    "<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n"
    "</html>\\r\\n";

bool put_unmatched(Writer& writer,
                   const char* selector,
                   u32 selector_len,
                   u16 status,
                   const char* reason,
                   u32 reason_len,
                   const char* body,
                   u32 body_len) {
    static constexpr char kPrefix[] = "unmatched";
    static constexpr char kOpen[] = " { return local_response({\n";
    static constexpr char kStatus[] = "  version: \"HTTP/1.1\", status: ";
    static constexpr char kReason[] = ", reason: \"";
    static constexpr char kServer[] = "\", server: \"nginx/1.29.7\",\n";
    static constexpr char kFields[] =
        "  date: \"current\", content_type: \"text/html\", connection: \"request\",\n";
    static constexpr char kHeadMode[] = "  head_mode: \"";
    static constexpr char kBody[] = "\", body: b\"";
    static constexpr char kClose[] = "\"\n}) }\n";
    const char* head_mode = selector_len == 0 ? "suppress_body" : "reject";
    const u32 head_mode_len = selector_len == 0 ? 13u : 6u;
    return writer.put_lit(kPrefix, sizeof(kPrefix) - 1) &&
           (selector_len == 0 || writer.put_lit(" ", 1)) &&
           writer.put_lit(selector, selector_len) && writer.put_lit(kOpen, sizeof(kOpen) - 1) &&
           writer.put_lit(kStatus, sizeof(kStatus) - 1) && writer.put_u16(status) &&
           writer.put_lit(kReason, sizeof(kReason) - 1) && writer.put_lit(reason, reason_len) &&
           writer.put_lit(kServer, sizeof(kServer) - 1) &&
           writer.put_lit(kFields, sizeof(kFields) - 1) &&
           writer.put_lit(kHeadMode, sizeof(kHeadMode) - 1) &&
           writer.put_lit(head_mode, head_mode_len) && writer.put_lit(kBody, sizeof(kBody) - 1) &&
           writer.put_lit(body, body_len) && writer.put_lit(kClose, sizeof(kClose) - 1);
}

bool put_request_policy(Writer& writer) {
    return writer.put_cstr("request_policy: {\n") &&
           writer.put_cstr("            version: \"HTTP/1.1\",\n") &&
           writer.put_cstr("            host: \"upstream\",\n") &&
           writer.put_cstr("            connection: \"omit\",\n") &&
           writer.put_cstr(
               "            strip_headers: [\"Connection\", \"Keep-Alive\", \"TE\", \"Expect\", "
               "\"Upgrade\"]\n") &&
           writer.put_cstr("        },\n");
}

bool put_response_policy(Writer& writer, bool suppress_body) {
    return writer.put_cstr("        response_policy: {\n") &&
           writer.put_cstr("            version: \"HTTP/1.1\",\n") &&
           writer.put_cstr("            framing: \"content_length\",\n") &&
           writer.put_cstr("            connection: \"request\",\n") &&
           (!suppress_body || writer.put_cstr("            head_mode: \"suppress_body\",\n")) &&
           writer.put_cstr("            server: \"nginx/1.29.7\",\n") &&
           writer.put_cstr("            date: \"current\",\n") &&
           writer.put_cstr("            hide_headers: [\"Date\", \"Server\", \"X-Pad\"]\n") &&
           writer.put_cstr("        },\n");
}

bool put_failure_policy(Writer& writer, bool suppress_body, bool buffered) {
    return writer.put_cstr("        failure_policy: {\n") &&
           writer.put_cstr("            version: \"HTTP/1.1\",\n") &&
           writer.put_cstr("            status: 502,\n") &&
           writer.put_cstr("            reason: \"Bad Gateway\",\n") &&
           writer.put_cstr("            content_type: \"text/html\",\n") &&
           writer.put_cstr("            server: \"nginx/1.29.7\",\n") &&
           writer.put_cstr("            date: \"current\",\n") &&
           writer.put_cstr("            connection: \"request\",\n") &&
           (!suppress_body || writer.put_cstr("            head_mode: \"suppress_body\",\n")) &&
           writer.put_cstr("            body: b\"") &&
           writer.put_lit(kBadGatewayBody, sizeof(kBadGatewayBody) - 1) &&
           writer.put_cstr("\"\n") && writer.put_cstr(buffered ? "        },\n" : "        }\n");
}

bool put_timeout_failure_policy(Writer& writer) {
    return writer.put_cstr("        timeout_failure_policy: {\n") &&
           writer.put_cstr("            version: \"HTTP/1.1\",\n") &&
           writer.put_cstr("            status: 504,\n") &&
           writer.put_cstr("            reason: \"Gateway Time-out\",\n") &&
           writer.put_cstr("            content_type: \"text/html\",\n") &&
           writer.put_cstr("            server: \"nginx/1.29.7\",\n") &&
           writer.put_cstr("            date: \"current\",\n") &&
           writer.put_cstr("            connection: \"request\",\n") &&
           writer.put_cstr("            body: b\"") &&
           writer.put_lit(kGatewayTimeoutBody, sizeof(kGatewayTimeoutBody) - 1) &&
           writer.put_cstr("\"\n") && writer.put_cstr("        },\n");
}

bool put_root_forward(
    Writer& writer, const char* method, u32 method_len, bool suppress_body, bool buffered) {
    return writer.put_cstr("route ") &&
           (method_len == 0
                ? writer.put_cstr("\"/\" {\n")
                : writer.put_lit(method, method_len) && writer.put_cstr(" \"/\" {\n")) &&
           writer.put_cstr("    return forward(nginx_upstream, ") && put_request_policy(writer) &&
           put_response_policy(writer, suppress_body) &&
           put_failure_policy(writer, suppress_body, buffered) &&
           (buffered ? put_timeout_failure_policy(writer) : true) &&
           (buffered ? writer.put_cstr("        response_read_timeout: 60s,\n") : true) &&
           (buffered ? writer.put_cstr("        response_buffering: \"complete_content_length\"\n")
                     : true) &&
           writer.put_cstr("    )\n}\n");
}

}  // namespace

FrontendResult<RutSource> lower_to_rut(const Server& server) {
    if (has_exact_local_return_inventory(server.exact_local_return))
        return unsupported(exact_local_return_span(server),
                           lit_str("exact local return lowering is not implemented"));
    auto timeout = validate_proxy_read_timeout(server);
    if (!timeout) return core::make_unexpected(timeout.error());
    if (server.listen.port == 0)
        return invalid_integer(server.listen.span, lit_str("invalid model listen port"));
    const bool is_root = server.location.path.ptr != nullptr && eq(server.location.path, "/", 1);
    const bool is_api = server.location.path.ptr != nullptr && eq(server.location.path, "/api/", 5);
    if (!is_root && !is_api)
        return unsupported(server.location.path_span,
                           lit_str("converter requires location / or /api/"));
    const ProxyPass& proxy = server.location.proxy_pass;
    if (proxy.port == 0)
        return invalid_integer(server.location.proxy_pass.span,
                               lit_str("invalid model upstream port"));
    if (proxy.has_uri) {
        if (proxy.uri.ptr == nullptr || proxy.uri.len != 1 || proxy.uri.ptr[0] != '/')
            return unsupported(proxy.uri_span, lit_str("converter requires proxy_pass URI /"));
        if (!is_api)
            return unsupported(proxy.uri_span, lit_str("location / cannot use a proxy_pass URI"));
    } else {
        if (proxy.uri.ptr != nullptr || proxy.uri.len != 0)
            return unsupported(proxy.span, lit_str("invalid proxy_pass URI state"));
        if (!is_root)
            return unsupported(server.location.path_span,
                               lit_str("location /api/ requires proxy_pass URI /"));
    }

    RutSource output{};
    Writer writer(output);
    auto put = [&](const char* text) {
        return writer.put_lit(text, static_cast<u32>(__builtin_strlen(text)));
    };
    auto fail_overflow = [&]() -> FrontendResult<RutSource> {
        return out_of_memory(server.span, lit_str("generated RUT source is too large"));
    };

    if (!put("listen :") || !writer.put_u16(server.listen.port) || !put("\n") ||
        !put("upstream nginx_upstream at \"") ||
        !writer.put_ipv4(server.location.proxy_pass.address) || !put(":") ||
        !writer.put_u16(proxy.port) || !put("\"\n"))
        return fail_overflow();

    // These policies cover only the converter's bounded unmatched-request
    // domain. OPTIONS and CONNECT reject exactly, while the method-omitted
    // policy is a fail-closed 400 and suppresses a possible HEAD body.
    if (!put_unmatched(writer,
                       "OPTIONS",
                       7,
                       400,
                       "Bad Request",
                       11,
                       kBadRequestBody,
                       static_cast<u32>(__builtin_strlen(kBadRequestBody))) ||
        !put_unmatched(writer,
                       "CONNECT",
                       7,
                       405,
                       "Not Allowed",
                       11,
                       kNotAllowedBody,
                       static_cast<u32>(__builtin_strlen(kNotAllowedBody))) ||
        !put_unmatched(writer,
                       "",
                       0,
                       400,
                       "Bad Request",
                       11,
                       kBadRequestBody,
                       static_cast<u32>(__builtin_strlen(kBadRequestBody))))
        return fail_overflow();

    if (is_root) {
        if (!put_root_forward(writer, "HEAD", 4, true, false) ||
            !put_root_forward(writer, "GET", 3, false, true) ||
            !put_root_forward(writer, "", 0, false, false))
            return fail_overflow();
        return output;
    }

    static constexpr char kRedirectBody[] =
        "<html>\\r\\n"
        "<head><title>301 Moved Permanently</title></head>\\r\\n"
        "<body>\\r\\n"
        "<center><h1>301 Moved Permanently</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n"
        "</body>\\r\\n"
        "</html>\\r\\n";
    if (!put("route \"/api\" {\n") ||
        !put("    if req.method == GET && req.pathOnly == \"/api\" {\n") ||
        !put("        return redirect({scheme: \"http\", authority: \"request_host\", port: "
             "\"actual_listener\",\n") ||
        !put("            path: \"static\", query: \"preserve_raw\", date: \"current\", "
             "connection: \"close\",\n") ||
        !put("            status: 301, reason: \"Moved Permanently\", server: "
             "\"nginx/1.29.7\",\n") ||
        !put("            content_type: \"text/html\", target_path: \"/api/\", body: b\"") ||
        !writer.put_lit(kRedirectBody, static_cast<u32>(__builtin_strlen(kRedirectBody))) ||
        !put("\"})\n") || !put("    } else {\n") ||
        !put("        return forward(nginx_upstream, target_transform: {\n") ||
        !put("            strip_prefix: \"/api/\",\n") ||
        !put("            replace_prefix: \"/\"\n") || !put("        }, request_policy: {\n") ||
        !put("            version: \"HTTP/1.1\",\n") || !put("            host: \"upstream\",\n") ||
        !put("            connection: \"omit\",\n") ||
        !put("            strip_headers: [\"Connection\", \"Keep-Alive\", \"TE\", \"Expect\", "
             "\"Upgrade\"]\n") ||
        !put("        }, response_policy: {\n") || !put("            version: \"HTTP/1.1\",\n") ||
        !put("            framing: \"content_length\",\n") ||
        !put("            connection: \"request\",\n") ||
        !put("            server: \"nginx/1.29.7\",\n") ||
        !put("            date: \"current\",\n") ||
        !put("            hide_headers: [\"Date\", \"Server\", \"X-Pad\"]\n") ||
        !put("        }, failure_policy: {\n") || !put("            version: \"HTTP/1.1\",\n") ||
        !put("            status: 502,\n") || !put("            reason: \"Bad Gateway\",\n") ||
        !put("            content_type: \"text/html\",\n") ||
        !put("            server: \"nginx/1.29.7\",\n") ||
        !put("            date: \"current\",\n") ||
        !put("            connection: \"request\",\n") ||
        !put("            body: b\"<html>\\r\\n<head><title>502 Bad "
             "Gateway</title></head>\\r\\n<body>\\r\\n<center><h1>502 Bad "
             "Gateway</h1></center>\\r\\n<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</"
             "html>\\r\\n\"\n") ||
        !put("        })\n") || !put("    }\n") || !put("}\n"))
        return fail_overflow();
    return output;
}

}  // namespace rut::nginx
