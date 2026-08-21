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

}  // namespace

FrontendResult<RutSource> lower_to_rut(const Server& server) {
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

    if (is_root) {
        if (!put("route \"/\" {\n") || !put("    if req.method == HEAD {\n") ||
            !put("        return forward(nginx_upstream, request_policy: {\n") ||
            !put("            version: \"HTTP/1.1\",\n") ||
            !put("            host: \"upstream\",\n") ||
            !put("            connection: \"omit\",\n") ||
            !put("            strip_headers: [\"Connection\", \"Keep-Alive\", \"TE\", \"Expect\", "
                 "\"Upgrade\"]\n") ||
            !put("        }, response_policy: {\n") ||
            !put("            version: \"HTTP/1.1\",\n") ||
            !put("            framing: \"content_length\",\n") ||
            !put("            connection: \"request\",\n") ||
            !put("            head_mode: \"suppress_body\",\n") ||
            !put("            server: \"nginx/1.29.7\",\n") ||
            !put("            date: \"current\",\n") ||
            !put("            hide_headers: [\"Date\", \"Server\", \"X-Pad\"]\n") ||
            !put("        }, failure_policy: {\n") ||
            !put("            version: \"HTTP/1.1\",\n") || !put("            status: 502,\n") ||
            !put("            reason: \"Bad Gateway\",\n") ||
            !put("            content_type: \"text/html\",\n") ||
            !put("            server: \"nginx/1.29.7\",\n") ||
            !put("            date: \"current\",\n") ||
            !put("            connection: \"request\",\n") ||
            !put("            head_mode: \"suppress_body\",\n") ||
            !put("            body: b\"<html>\\r\\n<head><title>502 Bad "
                 "Gateway</title></head>\\r\\n<body>\\r\\n<center><h1>502 Bad "
                 "Gateway</h1></center>\\r\\n<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</"
                 "html>\\r\\n\"\n") ||
            !put("        })\n") || !put("    } else {\n") ||
            !put("        return forward(nginx_upstream, request_policy: {\n") ||
            !put("            version: \"HTTP/1.1\",\n") ||
            !put("            host: \"upstream\",\n") ||
            !put("            connection: \"omit\",\n") ||
            !put("            strip_headers: [\"Connection\", \"Keep-Alive\", \"TE\", \"Expect\", "
                 "\"Upgrade\"]\n") ||
            !put("        }, response_policy: {\n") ||
            !put("            version: \"HTTP/1.1\",\n") ||
            !put("            framing: \"content_length\",\n") ||
            !put("            connection: \"request\",\n") ||
            !put("            server: \"nginx/1.29.7\",\n") ||
            !put("            date: \"current\",\n") ||
            !put("            hide_headers: [\"Date\", \"Server\", \"X-Pad\"]\n") ||
            !put("        }, failure_policy: {\n") ||
            !put("            version: \"HTTP/1.1\",\n") || !put("            status: 502,\n") ||
            !put("            reason: \"Bad Gateway\",\n") ||
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
