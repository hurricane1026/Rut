#include "rut/nginx/parser.h"

namespace rut::nginx {
namespace {

enum class TokenKind : u8 { Word, LBrace, RBrace, Semicolon, End };

struct Token {
    TokenKind kind = TokenKind::End;
    Str text{};
    Span span{};
};

class Lexer {
public:
    explicit Lexer(Str source) : source_(source) {}

    Token next() {
        skip_space_and_comments();
        if (pos_ >= source_.len) return {TokenKind::End, {}, Span{pos_, pos_, line_, col_}};

        const u32 start = pos_;
        const u32 line = line_;
        const u32 col = col_;
        const char c = source_.ptr[pos_];
        if (c == '{' || c == '}' || c == ';') {
            advance();
            const TokenKind kind = c == '{' ? TokenKind::LBrace
                                           : c == '}' ? TokenKind::RBrace : TokenKind::Semicolon;
            return {kind, source_.slice(start, pos_), Span{start, pos_, line, col}};
        }

        while (pos_ < source_.len) {
            const char ch = source_.ptr[pos_];
            if (ch == '#' || ch == '{' || ch == '}' || ch == ';' || is_space(ch)) break;
            advance();
        }
        return {TokenKind::Word, source_.slice(start, pos_), Span{start, pos_, line, col}};
    }

private:
    static bool is_space(char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
    }

    void advance() {
        if (source_.ptr[pos_] == '\n') {
            line_++;
            col_ = 1;
        } else {
            col_++;
        }
        pos_++;
    }

    void skip_space_and_comments() {
        for (;;) {
            while (pos_ < source_.len && is_space(source_.ptr[pos_])) advance();
            if (pos_ >= source_.len || source_.ptr[pos_] != '#') return;
            while (pos_ < source_.len && source_.ptr[pos_] != '\n') advance();
        }
    }

    Str source_{};
    u32 pos_ = 0;
    u32 line_ = 1;
    u32 col_ = 1;
};

constexpr bool eq(Str a, const char* b, u32 n) {
    if (a.len != n) return false;
    for (u32 i = 0; i < n; i++) {
        if (a.ptr[i] != b[i]) return false;
    }
    return true;
}

constexpr bool contains(Str a, char needle) {
    for (u32 i = 0; i < a.len; i++) {
        if (a.ptr[i] == needle) return true;
    }
    return false;
}

auto invalid(Span span, Str detail) {
    return frontend_error(FrontendError::UnexpectedToken, span, detail);
}

auto invalid_integer(Span span, Str detail) {
    return frontend_error(FrontendError::InvalidInteger, span, detail);
}

auto unsupported(Span span, Str detail) {
    return frontend_error(FrontendError::UnsupportedSyntax, span, detail);
}

auto missing(Span span, Str detail) {
    return frontend_error(FrontendError::UnexpectedEof, span, detail);
}

class Parser {
public:
    explicit Parser(Str source) : lexer_(source) { advance(); }

    FrontendResult<Server> run() {
        if (cur_.kind == TokenKind::End) return missing(cur_.span, lit_str("server fragment is empty"));
        if (cur_.kind != TokenKind::Word) return invalid(cur_.span, lit_str("expected server"));
        if (eq(cur_.text, "http", 4) || eq(cur_.text, "events", 6))
            return unsupported(cur_.span, lit_str("http/events wrappers are unsupported"));
        if (!eq(cur_.text, "server", 6)) return invalid(cur_.span, lit_str("expected server"));

        const Span start = cur_.span;
        advance();
        if (!expect(TokenKind::LBrace, lit_str("expected '{' after server")))
            return core::make_unexpected(error_);

        Server result{};
        result.span = start;
        bool have_listen = false;
        bool have_location = false;
        while (cur_.kind != TokenKind::RBrace && cur_.kind != TokenKind::End) {
            if (cur_.kind != TokenKind::Word) {
                return invalid(cur_.span, lit_str("expected server directive"));
            }
            if (eq(cur_.text, "listen", 6)) {
                if (have_listen) return unsupported(cur_.span, lit_str("duplicate listen"));
                auto parsed = parse_listen();
                if (!parsed) return core::make_unexpected(parsed.error());
                result.listen = parsed.value();
                have_listen = true;
            } else if (eq(cur_.text, "location", 8)) {
                if (have_location) return unsupported(cur_.span, lit_str("duplicate location"));
                auto parsed = parse_location();
                if (!parsed) return core::make_unexpected(parsed.error());
                result.location = parsed.value();
                have_location = true;
            } else {
                return unsupported(cur_.span, lit_str("unknown server directive"));
            }
        }
        if (cur_.kind == TokenKind::End) return missing(cur_.span, lit_str("missing '}' for server"));
        result.span.end = cur_.span.end;
        advance();
        if (!have_listen) return unsupported(result.span, lit_str("missing listen"));
        if (!have_location) return unsupported(result.span, lit_str("missing location"));
        if (cur_.kind != TokenKind::End) {
            if (cur_.kind == TokenKind::Word && eq(cur_.text, "server", 6))
                return unsupported(cur_.span, lit_str("multiple servers are unsupported"));
            return invalid(cur_.span, lit_str("trailing unexpected tokens"));
        }
        return result;
    }

private:
    bool expect(TokenKind kind, Str detail) {
        if (cur_.kind == kind) {
            advance();
            return true;
        }
        error_ = cur_.kind == TokenKind::End
                     ? Diagnostic{FrontendError::UnexpectedEof, cur_.span, detail}
                     : Diagnostic{FrontendError::UnexpectedToken, cur_.span, detail};
        return false;
    }

    void advance() { cur_ = lexer_.next(); }

    FrontendResult<Listen> parse_listen() {
        const Span start = cur_.span;
        advance();
        if (cur_.kind != TokenKind::Word) return invalid(cur_.span, lit_str("listen requires a port"));
        const Token port = cur_;
        if (contains(port.text, '$')) return unsupported(port.span, lit_str("variables are unsupported"));
        u16 value = 0;
        if (!parse_port(port.text, &value))
            return invalid_integer(port.span, lit_str("invalid listen port"));
        advance();
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("expected ';' after listen"));
        if (cur_.kind == TokenKind::Word &&
            (eq(cur_.text, "listen", 6) || eq(cur_.text, "location", 8) ||
             eq(cur_.text, "server", 6)))
            return invalid(cur_.span, lit_str("expected ';' after listen"));
        if (cur_.kind != TokenKind::Word && cur_.kind != TokenKind::Semicolon)
            return invalid(cur_.span, lit_str("expected ';' after listen"));
        if (cur_.kind != TokenKind::Semicolon)
            return unsupported(cur_.span, lit_str("listen options are unsupported"));
        const Span end = cur_.span;
        advance();
        return Listen{value, Span{start.start, end.end, start.line, start.col}};
    }

    FrontendResult<Location> parse_location() {
        const Span start = cur_.span;
        advance();
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("location requires a path"));
        if (cur_.kind != TokenKind::Word)
            return invalid(cur_.span, lit_str("location requires a path"));
        const Token path = cur_;
        if (eq(path.text, "=", 1) || eq(path.text, "^~", 2) || eq(path.text, "~", 1) ||
            eq(path.text, "~*", 2))
            return unsupported(path.span, lit_str("location modifiers are unsupported"));
        if (contains(path.text, '$')) return unsupported(path.span, lit_str("variables are unsupported"));
        if (!eq(path.text, "/", 1) && !eq(path.text, "/api/", 5))
            return unsupported(path.span, lit_str("only location / or /api/ is supported"));
        advance();
        if (!expect(TokenKind::LBrace, lit_str("expected '{' after location path")))
            return core::make_unexpected(error_);

        Location result{};
        result.path = path.text;
        result.path_span = path.span;
        bool have_proxy = false;
        while (cur_.kind != TokenKind::RBrace && cur_.kind != TokenKind::End) {
            if (cur_.kind != TokenKind::Word)
                return invalid(cur_.span, lit_str("expected location directive"));
            if (!eq(cur_.text, "proxy_pass", 10))
                return unsupported(cur_.span, lit_str("unknown location directive"));
            if (have_proxy) return unsupported(cur_.span, lit_str("duplicate proxy_pass"));
            auto proxy = parse_proxy_pass();
            if (!proxy) return core::make_unexpected(proxy.error());
            result.proxy_pass = proxy.value();
            have_proxy = true;
        }
        if (cur_.kind == TokenKind::End) return missing(cur_.span, lit_str("missing '}' for location"));
        const Span end = cur_.span;
        advance();
        if (!have_proxy) return unsupported(end, lit_str("missing proxy_pass"));
        const bool is_root = eq(result.path, "/", 1);
        if (is_root && result.proxy_pass.has_uri)
            return unsupported(result.proxy_pass.uri_span,
                               lit_str("location / cannot use a proxy_pass URI"));
        if (!is_root && !result.proxy_pass.has_uri)
            return unsupported(result.path_span,
                               lit_str("location /api/ requires proxy_pass URI /"));
        result.span = Span{start.start, end.end, start.line, start.col};
        return result;
    }

    FrontendResult<ProxyPass> parse_proxy_pass() {
        const Span start = cur_.span;
        advance();
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("proxy_pass requires an upstream"));
        if (cur_.kind != TokenKind::Word)
            return invalid(cur_.span, lit_str("proxy_pass requires an upstream"));
        const Token url = cur_;
        if (contains(url.text, '$')) return unsupported(url.span, lit_str("variables are unsupported"));
        ProxyPass result{};
        const UrlParseStatus url_status = parse_url(url.text, url.span, result);
        if (url_status == UrlParseStatus::InvalidInteger)
            return invalid_integer(url.span, lit_str("invalid upstream IPv4 address or port"));
        if (url_status == UrlParseStatus::UriSuffix)
            return unsupported(url.span, lit_str("proxy_pass URI suffixes are unsupported"));
        if (url_status != UrlParseStatus::Ok)
            return unsupported(url.span, lit_str("only literal IPv4 HTTP upstreams are supported"));
        advance();
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("expected ';' after proxy_pass"));
        if (cur_.kind != TokenKind::Semicolon)
            return invalid(cur_.span, lit_str("expected ';' after proxy_pass"));
        const Span end = cur_.span;
        advance();
        result.span = Span{start.start, end.end, start.line, start.col};
        return result;
    }

    static bool parse_port(Str text, u16* out) {
        if (text.len == 0) return false;
        u32 value = 0;
        for (u32 i = 0; i < text.len; i++) {
            if (text.ptr[i] < '0' || text.ptr[i] > '9') return false;
            value = value * 10u + static_cast<u32>(text.ptr[i] - '0');
            if (value > 65535u) return false;
        }
        if (value == 0) return false;
        *out = static_cast<u16>(value);
        return true;
    }

    enum class UrlParseStatus : u8 { Ok, InvalidInteger, UriSuffix, Unsupported };

    static UrlParseStatus parse_url(Str text, Span span, ProxyPass& out) {
        constexpr Str kPrefix = lit_str("http://");
        if (text.len <= kPrefix.len || !text.slice(0, kPrefix.len).eq(kPrefix))
            return UrlParseStatus::Unsupported;
        u32 pos = kPrefix.len;
        if (text.ptr[pos] < '0' || text.ptr[pos] > '9') return UrlParseStatus::Unsupported;
        for (u32 octet = 0; octet < 4; octet++) {
            if (pos >= text.len) return UrlParseStatus::InvalidInteger;
            u32 value = 0;
            u32 digits = 0;
            while (pos < text.len && text.ptr[pos] >= '0' && text.ptr[pos] <= '9') {
                value = value * 10u + static_cast<u32>(text.ptr[pos++] - '0');
                if (++digits > 3 || value > 255u) return UrlParseStatus::InvalidInteger;
            }
            if (digits == 0) return UrlParseStatus::InvalidInteger;
            out.address[octet] = static_cast<u8>(value);
            if (octet < 3) {
                if (pos >= text.len || text.ptr[pos++] != '.')
                    return UrlParseStatus::InvalidInteger;
            }
        }
        if (pos >= text.len || text.ptr[pos++] != ':') return UrlParseStatus::InvalidInteger;
        const u32 port_start = pos;
        while (pos < text.len && text.ptr[pos] >= '0' && text.ptr[pos] <= '9') pos++;
        if (port_start == pos) return UrlParseStatus::InvalidInteger;
        if (!parse_port(text.slice(port_start, pos), &out.port))
            return UrlParseStatus::InvalidInteger;
        if (pos == text.len) return UrlParseStatus::Ok;
        if (text.ptr[pos] != '/') return UrlParseStatus::InvalidInteger;
        if (pos + 1 != text.len) return UrlParseStatus::UriSuffix;
        out.has_uri = true;
        out.uri = text.slice(pos, text.len);
        out.uri_span = Span{span.start + pos, span.end, span.line, span.col + pos};
        return UrlParseStatus::Ok;
    }

    Lexer lexer_;
    Token cur_{};
    Diagnostic error_{};
};

}  // namespace

FrontendResult<Server> parse(Str source) { return Parser(source).run(); }

}  // namespace rut::nginx
