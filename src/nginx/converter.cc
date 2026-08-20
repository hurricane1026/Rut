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
        return invalid_integer(server.listen.span,
                               lit_str("invalid model listen port"));
    if (server.location.path.ptr == nullptr || !eq(server.location.path, "/", 1))
        return unsupported(server.location.path_span,
                           lit_str("converter requires location /"));
    if (server.location.proxy_pass.port == 0)
        return invalid_integer(server.location.proxy_pass.span,
                               lit_str("invalid model upstream port"));

    RutSource output{};
    Writer writer(output);
    auto put = [&](const char* text) { return writer.put_lit(text, static_cast<u32>(__builtin_strlen(text))); };
    auto fail_overflow = [&]() -> FrontendResult<RutSource> {
        return out_of_memory(server.span, lit_str("generated RUT source is too large"));
    };

    if (!put("listen :") || !writer.put_u16(server.listen.port) || !put("\n") ||
        !put("upstream nginx_upstream at \"") ||
        !writer.put_ipv4(server.location.proxy_pass.address) || !put(":") ||
        !writer.put_u16(server.location.proxy_pass.port) || !put("\"\n") ||
        !put("route \"/\" {\n") ||
        !put("    return forward(nginx_upstream, request_policy: {\n") ||
        !put("        version: \"HTTP/1.1\",\n") ||
        !put("        host: \"upstream\",\n") ||
        !put("        connection: \"omit\",\n") ||
        !put("        strip_headers: [\"Connection\", \"Keep-Alive\", \"TE\", \"Expect\", \"Upgrade\"]\n") ||
        !put("    }, response_policy: {\n") ||
        !put("        version: \"HTTP/1.1\",\n") ||
        !put("        framing: \"content_length\",\n") ||
        !put("        connection: \"keep_alive\",\n") ||
        !put("        server: \"nginx/1.29.7\",\n") ||
        !put("        date: \"current\",\n") ||
        !put("        hide_headers: [\"Date\", \"Server\", \"X-Pad\"]\n") ||
        !put("    })\n") || !put("}\n"))
        return fail_overflow();
    return output;
}

}  // namespace rut::nginx
