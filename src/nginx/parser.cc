#include "rut/nginx/parser.h"

#include "rut/common/forward_target_transform.h"
#include "rut/common/strict_local_response.h"

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
        return next_unskipped();
    }

    // nginx quote handling is deliberately not part of the general lexer in
    // this bounded frontend. Only an accepted `return 200` asks for one raw
    // quoted lexeme so its complete source range can be validated without
    // decoding or normalizing it.
    Token next_local_return_body() {
        skip_space_and_comments();
        if (pos_ >= source_.len || source_.ptr[pos_] != '"') return next_unskipped();

        const u32 start = pos_;
        const u32 line = line_;
        const u32 col = col_;
        advance();
        while (pos_ < source_.len) {
            const char ch = source_.ptr[pos_];
            if (ch == '\\') {
                advance();
                if (pos_ < source_.len) advance();
                continue;
            }
            advance();
            if (ch == '"') break;
        }
        return {TokenKind::Word, source_.slice(start, pos_), Span{start, pos_, line, col}};
    }

private:
    Token next_unskipped() {
        if (pos_ >= source_.len) return {TokenKind::End, {}, Span{pos_, pos_, line_, col_}};

        const u32 start = pos_;
        const u32 line = line_;
        const u32 col = col_;
        const char c = source_.ptr[pos_];
        if (c == '{' || c == '}' || c == ';') {
            advance();
            const TokenKind kind = c == '{'   ? TokenKind::LBrace
                                   : c == '}' ? TokenKind::RBrace
                                              : TokenKind::Semicolon;
            return {kind, source_.slice(start, pos_), Span{start, pos_, line, col}};
        }

        while (pos_ < source_.len) {
            const char ch = source_.ptr[pos_];
            if (ch == '#' || ch == '{' || ch == '}' || ch == ';' || is_space(ch)) break;
            advance();
        }
        return {TokenKind::Word, source_.slice(start, pos_), Span{start, pos_, line, col}};
    }
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

static_assert(kMaxProxyPassUriLen == kMaxForwardTargetTransformPrefixLen);
static_assert(kMaxProxyLocationPathLen <= kMaxForwardTargetTransformPrefixLen);
static_assert(kMaxExactLocalReturnPathLen == kMaxExactStrictLocalResponsePathLen);

constexpr bool clean_path_segment_byte_is_unreserved(char value) {
    const u8 byte = static_cast<u8>(value);
    return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
           (byte >= '0' && byte <= '9') || byte == '-' || byte == '.' || byte == '_' || byte == '~';
}

bool proxy_pass_uri_is_clean(Str uri) {
    if (uri.ptr == nullptr || uri.len == 0 || uri.len > kMaxProxyPassUriLen || uri.ptr[0] != '/' ||
        (uri.len > 1 && uri.ptr[uri.len - 1] != '/'))
        return false;
    if (uri.len == 1) return true;

    u32 segment_start = 1;
    for (u32 i = 1; i < uri.len; i++) {
        if (uri.ptr[i] != '/') {
            if (!clean_path_segment_byte_is_unreserved(uri.ptr[i])) return false;
            continue;
        }

        const u32 segment_len = i - segment_start;
        if (segment_len == 0 || (segment_len == 1 && uri.ptr[segment_start] == '.') ||
            (segment_len == 2 && uri.ptr[segment_start] == '.' &&
             uri.ptr[segment_start + 1] == '.'))
            return false;
        segment_start = i + 1;
    }
    return true;
}

bool proxy_location_path_is_clean(Str path) {
    if (path.ptr == nullptr || path.len == 0 || path.len > kMaxProxyLocationPathLen ||
        path.ptr[0] != '/' || (path.len > 1 && path.ptr[path.len - 1] != '/'))
        return false;
    if (path.len == 1) return true;

    u32 segment_start = 1;
    for (u32 i = 1; i < path.len; i++) {
        if (path.ptr[i] != '/') {
            if (!clean_path_segment_byte_is_unreserved(path.ptr[i])) return false;
            continue;
        }

        const u32 segment_len = i - segment_start;
        if (segment_len == 0 || (segment_len == 1 && path.ptr[segment_start] == '.') ||
            (segment_len == 2 && path.ptr[segment_start] == '.' &&
             path.ptr[segment_start + 1] == '.'))
            return false;
        segment_start = i + 1;
    }
    return true;
}

bool exact_local_return_path_is_clean(Str path) {
    if (path.ptr == nullptr || path.len < 2 || path.len > kMaxExactLocalReturnPathLen ||
        path.ptr[0] != '/')
        return false;

    u32 segment_start = 1;
    for (u32 i = 1; i < path.len; i++) {
        if (path.ptr[i] != '/') {
            if (!clean_path_segment_byte_is_unreserved(path.ptr[i])) return false;
            continue;
        }

        const u32 segment_len = i - segment_start;
        if (segment_len == 0 || (segment_len == 1 && path.ptr[segment_start] == '.') ||
            (segment_len == 2 && path.ptr[segment_start] == '.' &&
             path.ptr[segment_start + 1] == '.'))
            return false;
        segment_start = i + 1;
    }

    // A single trailing slash is part of the clean bounded profile. Otherwise
    // the final segment must be non-empty and cannot be a dot segment.
    if (segment_start == path.len) return true;
    const u32 segment_len = path.len - segment_start;
    return !(
        (segment_len == 1 && path.ptr[segment_start] == '.') ||
        (segment_len == 2 && path.ptr[segment_start] == '.' && path.ptr[segment_start + 1] == '.'));
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

struct ParsedLocation {
    bool exact = false;
    Location proxy{};
    ExactLocalReturnLocation local{};
    ExactNoContentReturnLocation no_content{};
    ExactAbsoluteRedirectLocation redirect{};
};

struct ParsedLocalReturn {
    bool no_content = false;
    LocalReturn local{};
    NoContentReturn no_content_response{};
};

class Parser {
public:
    explicit Parser(Str source) : source_(source), lexer_(source) { advance(); }

    FrontendResult<Server> run() {
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("server fragment is empty"));
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
        bool have_proxy_location = false;
        bool have_exact_location = false;
        u32 location_count = 0;
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
                if (location_count == 2)
                    return unsupported(cur_.span, lit_str("third location is unsupported"));
                const Span location_span = cur_.span;
                auto parsed = parse_location();
                if (!parsed) return core::make_unexpected(parsed.error());
                if (parsed.value().exact) {
                    if (have_exact_location)
                        return unsupported(location_span, lit_str("duplicate exact location"));
                    if (parsed.value().local.present)
                        result.exact_local_return = parsed.value().local;
                    else if (parsed.value().no_content.present)
                        result.exact_no_content_return = parsed.value().no_content;
                    else
                        result.exact_absolute_redirect = parsed.value().redirect;
                    have_exact_location = true;
                } else {
                    if (have_proxy_location)
                        return unsupported(location_span, lit_str("duplicate location"));
                    result.location = parsed.value().proxy;
                    have_proxy_location = true;
                }
                location_count++;
            } else if (eq(cur_.text, "proxy_read_timeout", 18)) {
                return unsupported(cur_.span,
                                   lit_str("proxy_read_timeout is unsupported at server level"));
            } else {
                return unsupported(cur_.span, lit_str("unknown server directive"));
            }
        }
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("missing '}' for server"));
        result.span.end = cur_.span.end;
        advance();
        if (!have_listen) return unsupported(result.span, lit_str("missing listen"));
        if (!have_proxy_location) {
            if (have_exact_location) {
                const Span exact_span =
                    result.exact_local_return.present        ? result.exact_local_return.span
                    : result.exact_no_content_return.present ? result.exact_no_content_return.span
                                                             : result.exact_absolute_redirect.span;
                return unsupported(exact_span,
                                   lit_str("exact location requires a root proxy fallback"));
            }
            return unsupported(result.span, lit_str("missing location"));
        }
        if (have_exact_location && !eq(result.location.path, "/", 1))
            return unsupported(result.location.path_span,
                               lit_str("exact location requires location / proxy fallback"));
        // nginx rejects TRACE during request processing before location
        // selection for every accepted proxy-location server in this bounded
        // model.  Keep the provenance at the semantic server level so the
        // profile has one invariant independent of the root-vs-transformed
        // fallback, optional exact location, and declaration order.
        result.pre_route_trace.profile = ImplicitPreRouteProfile::Nginx1297PreLocationTrace405;
        result.pre_route_trace.span = result.span;
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
        if (cur_.kind != TokenKind::Word)
            return invalid(cur_.span, lit_str("listen requires a port"));
        const Token port = cur_;
        if (contains(port.text, '$'))
            return unsupported(port.span, lit_str("variables are unsupported"));
        static constexpr char kIpv4WildcardPrefix[] = "0.0.0.0:";
        static constexpr char kAsteriskWildcardPrefix[] = "*:";
        static constexpr char kExactLoopbackPrefix[] = "127.0.0.1:";
        ListenerAddress address = ListenerAddress::IPv4Wildcard;
        u32 ipv4_host = 0;
        Str port_text = port.text;
        if (port_text.len >= sizeof(kIpv4WildcardPrefix) - 1u &&
            port_text.slice(0, sizeof(kIpv4WildcardPrefix) - 1u).eq(lit_str(kIpv4WildcardPrefix))) {
            port_text = port_text.slice(sizeof(kIpv4WildcardPrefix) - 1u, port_text.len);
        } else if (port_text.len >= sizeof(kAsteriskWildcardPrefix) - 1u &&
                   port_text.slice(0, sizeof(kAsteriskWildcardPrefix) - 1u)
                       .eq(lit_str(kAsteriskWildcardPrefix))) {
            port_text = port_text.slice(sizeof(kAsteriskWildcardPrefix) - 1u, port_text.len);
        } else if (port_text.len >= sizeof(kExactLoopbackPrefix) - 1u &&
                   port_text.slice(0, sizeof(kExactLoopbackPrefix) - 1u)
                       .eq(lit_str(kExactLoopbackPrefix))) {
            address = ListenerAddress::IPv4Exact;
            ipv4_host = 0x7f000001u;
            port_text = port_text.slice(sizeof(kExactLoopbackPrefix) - 1u, port_text.len);
        }
        u16 value = 0;
        if (!parse_port(port_text, &value))
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
        Listen result{};
        result.port = value;
        result.span = Span{start.start, end.end, start.line, start.col};
        result.address = address;
        result.ipv4_host = ipv4_host;
        result.value = port.text;
        result.value_span = port.span;
        return result;
    }

    FrontendResult<ParsedLocation> parse_location() {
        const Span start = cur_.span;
        advance();
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("location requires a path"));
        if (cur_.kind != TokenKind::Word)
            return invalid(cur_.span, lit_str("location requires a path"));
        if (eq(cur_.text, "=", 1)) return parse_exact_location(start);
        const Token path = cur_;
        if (eq(path.text, "^~", 2) || eq(path.text, "~", 1) || eq(path.text, "~*", 2) ||
            (path.text.len != 0 && path.text.ptr[0] == '@'))
            return unsupported(path.span, lit_str("location modifiers are unsupported"));
        if (contains(path.text, '$'))
            return unsupported(path.span, lit_str("variables are unsupported"));
        if (!proxy_location_path_is_clean(path.text))
            return unsupported(path.span,
                               lit_str("location path is outside the bounded clean proxy profile"));
        advance();
        if (!expect(TokenKind::LBrace, lit_str("expected '{' after location path")))
            return core::make_unexpected(error_);

        ParsedLocation parsed{};
        Location& result = parsed.proxy;
        result.path = path.text;
        result.path_span = path.span;
        bool have_proxy = false;
        bool have_proxy_read_timeout = false;
        while (cur_.kind != TokenKind::RBrace && cur_.kind != TokenKind::End) {
            if (cur_.kind != TokenKind::Word)
                return invalid(cur_.span, lit_str("expected location directive"));
            if (eq(cur_.text, "proxy_pass", 10)) {
                if (have_proxy) return unsupported(cur_.span, lit_str("duplicate proxy_pass"));
                auto proxy = parse_proxy_pass();
                if (!proxy) return core::make_unexpected(proxy.error());
                result.proxy_pass = proxy.value();
                have_proxy = true;
            } else if (eq(cur_.text, "proxy_read_timeout", 18)) {
                if (!eq(path.text, "/", 1))
                    return unsupported(
                        cur_.span,
                        lit_str("proxy_read_timeout is unsupported in transformed locations"));
                if (have_proxy_read_timeout)
                    return unsupported(cur_.span, lit_str("duplicate proxy_read_timeout"));
                auto timeout = parse_proxy_read_timeout();
                if (!timeout) return core::make_unexpected(timeout.error());
                result.proxy_read_timeout = timeout.value();
                have_proxy_read_timeout = true;
            } else if (eq(cur_.text, "location", 8)) {
                return unsupported(cur_.span, lit_str("nested locations are unsupported"));
            } else if (eq(cur_.text, "return", 6)) {
                return unsupported(cur_.span, lit_str("return is unsupported in proxy locations"));
            } else {
                return unsupported(cur_.span, lit_str("unknown location directive"));
            }
        }
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("missing '}' for location"));
        const Span end = cur_.span;
        advance();
        if (!have_proxy) return unsupported(end, lit_str("missing proxy_pass"));
        const bool is_root = eq(result.path, "/", 1);
        if (is_root && result.proxy_pass.has_uri)
            return unsupported(result.proxy_pass.uri_span,
                               lit_str("location / cannot use a proxy_pass URI"));
        if (!is_root && !result.proxy_pass.has_uri)
            return unsupported(result.path_span,
                               lit_str("non-root location requires a proxy_pass URI"));
        result.span = Span{start.start, end.end, start.line, start.col};
        return parsed;
    }

    FrontendResult<ParsedLocation> parse_exact_location(Span start) {
        advance();
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("exact location requires a path"));
        if (cur_.kind != TokenKind::Word)
            return invalid(cur_.span, lit_str("exact location requires a path"));
        const Token path = cur_;
        if (contains(path.text, '$'))
            return unsupported(path.span, lit_str("variables are unsupported"));
        const bool adjacent_comment =
            path.span.end < source_.len && source_.ptr[path.span.end] == '#';
        if (adjacent_comment)
            return unsupported(
                path.span, lit_str("exact local return path is outside the bounded clean profile"));
        const bool is_absolute_redirect = eq(path.text, "/old", 4);
        const bool is_local_return =
            !is_absolute_redirect && exact_local_return_path_is_clean(path.text);
        if (!is_local_return && !is_absolute_redirect)
            return unsupported(
                path.span, lit_str("exact local return path is outside the bounded clean profile"));
        advance();
        if (!expect(TokenKind::LBrace, lit_str("expected '{' after exact location path")))
            return core::make_unexpected(error_);

        ParsedLocation parsed{};
        parsed.exact = true;
        ExactLocalReturnLocation& local = parsed.local;
        ExactNoContentReturnLocation& no_content = parsed.no_content;
        ExactAbsoluteRedirectLocation& redirect = parsed.redirect;
        if (!is_local_return) {
            redirect.present = true;
            redirect.path = path.text;
            redirect.path_span = path.span;
        }
        bool have_return = false;
        while (cur_.kind != TokenKind::RBrace && cur_.kind != TokenKind::End) {
            if (cur_.kind != TokenKind::Word)
                return invalid(cur_.span, lit_str("expected exact location directive"));
            if (eq(cur_.text, "return", 6)) {
                if (have_return)
                    return unsupported(cur_.span, lit_str("duplicate return directive"));
                if (is_local_return) {
                    auto response = parse_local_return();
                    if (!response) return core::make_unexpected(response.error());
                    if (response.value().no_content) {
                        no_content.present = true;
                        no_content.path = path.text;
                        no_content.path_span = path.span;
                        no_content.response = response.value().no_content_response;
                    } else {
                        local.present = true;
                        local.path = path.text;
                        local.path_span = path.span;
                        local.response = response.value().local;
                    }
                } else {
                    auto response = parse_absolute_redirect();
                    if (!response) return core::make_unexpected(response.error());
                    redirect.response = response.value();
                }
                have_return = true;
            } else if (eq(cur_.text, "proxy_pass", 10)) {
                return unsupported(cur_.span,
                                   lit_str("proxy_pass is unsupported in exact locations"));
            } else if (eq(cur_.text, "location", 8)) {
                return unsupported(cur_.span, lit_str("nested locations are unsupported"));
            } else {
                return unsupported(cur_.span, lit_str("unknown exact location directive"));
            }
        }
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("missing '}' for exact location"));
        const Span end = cur_.span;
        advance();
        if (!have_return)
            return unsupported(end, lit_str("missing return directive in exact location"));
        if (local.present)
            local.span = Span{start.start, end.end, start.line, start.col};
        else if (no_content.present)
            no_content.span = Span{start.start, end.end, start.line, start.col};
        else
            redirect.span = Span{start.start, end.end, start.line, start.col};
        return parsed;
    }

    FrontendResult<AbsoluteRedirect> parse_absolute_redirect() {
        constexpr Str kTarget = lit_str("http://redirect.example/new");
        constexpr u32 kAuthorityOffset = 7;
        constexpr u32 kAuthorityLen = 16;
        constexpr u32 kPathOffset = kAuthorityOffset + kAuthorityLen;

        const Span start = cur_.span;
        advance();
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("return requires status and target"));
        if (cur_.kind != TokenKind::Word)
            return invalid(cur_.span, lit_str("return requires status and target"));
        const Token status = cur_;
        const bool is_301 = eq(status.text, "301", 3);
        const bool is_302 = eq(status.text, "302", 3);
        if (!is_301 && !is_302)
            return unsupported(status.span,
                               lit_str("only redirect status 301 or 302 is supported"));
        advance();
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("return requires an absolute target"));
        if (cur_.kind != TokenKind::Word)
            return invalid(cur_.span, lit_str("return requires an absolute target"));
        const Token target = cur_;
        if (!target.text.eq(kTarget))
            return unsupported(
                target.span,
                lit_str("only redirect target http://redirect.example/new is supported"));
        advance();
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("expected ';' after return"));
        if (cur_.kind != TokenKind::Semicolon) {
            if (cur_.kind == TokenKind::Word)
                return invalid(cur_.span, lit_str("return accepts exactly status and target"));
            return invalid(cur_.span, lit_str("expected ';' after return"));
        }
        const Span end = cur_.span;
        advance();
        return AbsoluteRedirect{
            static_cast<u16>(is_301 ? 301 : 302),
            status.text,
            status.span,
            target.text,
            target.span,
            target.text.slice(kAuthorityOffset, kAuthorityOffset + kAuthorityLen),
            Span{target.span.start + kAuthorityOffset,
                 target.span.start + kAuthorityOffset + kAuthorityLen,
                 target.span.line,
                 target.span.col + kAuthorityOffset},
            target.text.slice(kPathOffset, target.text.len),
            Span{target.span.start + kPathOffset,
                 target.span.end,
                 target.span.line,
                 target.span.col + kPathOffset},
            Span{start.start, end.end, start.line, start.col}};
    }

    FrontendResult<ParsedLocalReturn> parse_local_return() {
        const Span start = cur_.span;
        advance();
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("return requires status and body"));
        if (cur_.kind != TokenKind::Word)
            return invalid(cur_.span, lit_str("return requires status and body"));
        const Token status = cur_;
        if (eq(status.text, "204", 3)) {
            if (status.span.end < source_.len && source_.ptr[status.span.end] == '#')
                return unsupported(status.span,
                                   lit_str("return 204 status adjacent comment is unsupported"));
            advance();
            if (cur_.kind == TokenKind::End)
                return missing(cur_.span, lit_str("expected ';' after return 204"));
            if (cur_.kind != TokenKind::Semicolon) {
                if (cur_.kind == TokenKind::Word) {
                    if (contains(cur_.text, '$'))
                        return unsupported(cur_.span, lit_str("variables are unsupported"));
                    return unsupported(cur_.span,
                                       lit_str("return 204 body or target is unsupported"));
                }
                return invalid(cur_.span, lit_str("expected ';' after return 204"));
            }
            const Span end = cur_.span;
            advance();
            ParsedLocalReturn result{};
            result.no_content = true;
            result.no_content_response = NoContentReturn{
                204, status.span, Span{start.start, end.end, start.line, start.col}};
            return result;
        }
        if (!eq(status.text, "200", 3))
            return unsupported(status.span, lit_str("only return status 200 is supported"));
        cur_ = lexer_.next_local_return_body();
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("return requires a literal body"));
        if (cur_.kind != TokenKind::Word)
            return invalid(cur_.span, lit_str("return requires a literal body"));
        const Token body = cur_;
        if (!local_return_body_valid(body.text))
            return unsupported(
                body.span,
                lit_str("return body must match the bounded 1..64-byte safe quoted ASCII grammar"));
        advance();
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("expected ';' after return"));
        if (cur_.kind != TokenKind::Semicolon) {
            if (cur_.kind == TokenKind::Word)
                return invalid(cur_.span, lit_str("return accepts exactly status and body"));
            return invalid(cur_.span, lit_str("expected ';' after return"));
        }
        const Span end = cur_.span;
        advance();
        ParsedLocalReturn result{};
        result.local = LocalReturn{
            200,
            body.text.slice(1, body.text.len - 1),
            Span{body.span.start + 1, body.span.end - 1, body.span.line, body.span.col + 1},
            Span{start.start, end.end, start.line, start.col}};
        return result;
    }

    static bool local_return_body_valid(Str text) {
        if (text.len < 3 || text.ptr[0] != '"' || text.ptr[text.len - 1] != '"') return false;
        const u32 body_len = text.len - 2;
        if (body_len == 0 || body_len > kMaxLocalReturnBodyLen) return false;
        for (u32 i = 1; i + 1 < text.len; i++) {
            const u8 value = static_cast<u8>(text.ptr[i]);
            if (value == 0x20) {
                if (i == 1 || i + 2 == text.len) return false;
                continue;
            }
            if (value < 0x21 || value > 0x7e || text.ptr[i] == '"' || text.ptr[i] == '\\' ||
                text.ptr[i] == '$' || text.ptr[i] == '#' || text.ptr[i] == '{' ||
                text.ptr[i] == '}' || text.ptr[i] == ';')
                return false;
        }
        return true;
    }

    FrontendResult<ProxyReadTimeout> parse_proxy_read_timeout() {
        const Span start = cur_.span;
        advance();
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("proxy_read_timeout requires a value"));
        if (cur_.kind != TokenKind::Word)
            return invalid(cur_.span, lit_str("proxy_read_timeout requires a value"));
        if (eq(cur_.text, "proxy_pass", 10) || eq(cur_.text, "proxy_read_timeout", 18) ||
            eq(cur_.text, "location", 8) || eq(cur_.text, "server", 6))
            return invalid(cur_.span, lit_str("proxy_read_timeout requires a value"));
        const Token value = cur_;
        if (contains(value.text, '$'))
            return invalid_integer(value.span, lit_str("invalid proxy_read_timeout value"));

        u32 seconds = 0;
        const TimeoutParseStatus status = parse_timeout_seconds(value.text, &seconds);
        if (status == TimeoutParseStatus::Invalid)
            return invalid_integer(value.span, lit_str("invalid proxy_read_timeout value"));
        if (status == TimeoutParseStatus::Unsupported)
            return unsupported(value.span, lit_str("proxy_read_timeout value form is unsupported"));
        if (seconds == 0 || seconds > 63)
            return unsupported(value.span,
                               lit_str("only proxy_read_timeout 1s through 63s is supported"));

        advance();
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("expected ';' after proxy_read_timeout"));
        if (cur_.kind == TokenKind::Word &&
            (eq(cur_.text, "proxy_pass", 10) || eq(cur_.text, "proxy_read_timeout", 18) ||
             eq(cur_.text, "location", 8) || eq(cur_.text, "server", 6)))
            return invalid(cur_.span, lit_str("expected ';' after proxy_read_timeout"));
        if (cur_.kind != TokenKind::Semicolon) {
            if (cur_.kind == TokenKind::Word)
                return invalid(cur_.span, lit_str("proxy_read_timeout accepts exactly one value"));
            return invalid(cur_.span, lit_str("expected ';' after proxy_read_timeout"));
        }
        const Span end = cur_.span;
        advance();
        return ProxyReadTimeout{
            true, seconds * 1000u, Span{start.start, end.end, start.line, start.col}, value.span};
    }

    FrontendResult<ProxyPass> parse_proxy_pass() {
        const Span start = cur_.span;
        advance();
        if (cur_.kind == TokenKind::End)
            return missing(cur_.span, lit_str("proxy_pass requires an upstream"));
        if (cur_.kind != TokenKind::Word)
            return invalid(cur_.span, lit_str("proxy_pass requires an upstream"));
        const Token url = cur_;
        if (contains(url.text, '$'))
            return unsupported(url.span, lit_str("variables are unsupported"));
        ProxyPass result{};
        const UrlParseStatus url_status = parse_url(url.text, url.span, result);
        if (url_status == UrlParseStatus::InvalidInteger)
            return invalid_integer(url.span, lit_str("invalid upstream IPv4 address or port"));
        if (url_status == UrlParseStatus::InvalidUri)
            return unsupported(result.uri_span,
                               lit_str("proxy_pass URI is outside the bounded clean profile"));
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
            const u32 digit = static_cast<u32>(text.ptr[i] - '0');
            if (value > (65535u - digit) / 10u) return false;
            value = value * 10u + digit;
        }
        if (value == 0) return false;
        *out = static_cast<u16>(value);
        return true;
    }

    enum class TimeoutParseStatus : u8 { Ok, Unsupported, Invalid };

    static TimeoutParseStatus parse_timeout_seconds(Str text, u32* out) {
        if (text.len == 0) return TimeoutParseStatus::Invalid;
        for (u32 i = 0; i < text.len; i++) {
            if (text.ptr[i] == '"' || text.ptr[i] == '\'' || text.ptr[i] == '\\')
                return TimeoutParseStatus::Unsupported;
        }
        if (text.ptr[0] < '0' || text.ptr[0] > '9') return TimeoutParseStatus::Invalid;

        u32 pos = 0;
        while (pos < text.len && text.ptr[pos] >= '0' && text.ptr[pos] <= '9') pos++;
        if (pos + 1 == text.len && text.ptr[pos] == 's') {
            if (text.ptr[0] == '0' && pos > 1) return TimeoutParseStatus::Unsupported;
            if (pos > 2) {
                *out = 64;
                return TimeoutParseStatus::Ok;
            }
            u32 seconds = 0;
            for (u32 i = 0; i < pos; i++)
                seconds = seconds * 10u + static_cast<u32>(text.ptr[i] - '0');
            *out = seconds;
            return TimeoutParseStatus::Ok;
        }
        for (u32 i = pos; i < text.len; i++) {
            if (text.ptr[i] == '.') return TimeoutParseStatus::Invalid;
        }
        // nginx accepts bare seconds, other units, quoted values, and compound
        // time values. They are deliberately excluded from this bounded slice.
        return TimeoutParseStatus::Unsupported;
    }

    enum class UrlParseStatus : u8 { Ok, InvalidInteger, InvalidUri, Unsupported };

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
                if (pos >= text.len) return UrlParseStatus::InvalidInteger;
                const char separator = text.ptr[pos++];
                if (separator != '.') return UrlParseStatus::InvalidInteger;
            }
        }
        if (pos >= text.len) return UrlParseStatus::InvalidInteger;
        const char separator = text.ptr[pos++];
        if (separator != ':') return UrlParseStatus::InvalidInteger;
        const u32 port_start = pos;
        while (pos < text.len && text.ptr[pos] >= '0' && text.ptr[pos] <= '9') pos++;
        if (port_start == pos) return UrlParseStatus::InvalidInteger;
        if (!parse_port(text.slice(port_start, pos), &out.port))
            return UrlParseStatus::InvalidInteger;
        if (pos == text.len) return UrlParseStatus::Ok;
        if (text.ptr[pos] != '/') return UrlParseStatus::InvalidInteger;
        out.uri = text.slice(pos, text.len);
        out.uri_span = Span{span.start + pos, span.end, span.line, span.col + pos};
        if (!proxy_pass_replacement_uri_is_clean(out.uri)) return UrlParseStatus::InvalidUri;
        out.has_uri = true;
        return UrlParseStatus::Ok;
    }

    Str source_{};
    Lexer lexer_;
    Token cur_{};
    Diagnostic error_{};
};

}  // namespace

bool proxy_pass_replacement_uri_is_clean(Str uri) {
    // Preserve the existing path-only grammar and validation branch unchanged.
    if (proxy_pass_uri_is_clean(uri)) return true;
    if (uri.ptr == nullptr || uri.len < 3 || uri.len > kMaxProxyPassUriLen) return false;

    u32 query_delimiter = 0;
    while (query_delimiter < uri.len && uri.ptr[query_delimiter] != '?') query_delimiter++;
    return query_delimiter < uri.len && proxy_pass_uri_is_clean(uri.slice(0, query_delimiter)) &&
           forward_target_transform_replacement_prefix(uri);
}

FrontendResult<Server> parse(Str source) {
    return Parser(source).run();
}

}  // namespace rut::nginx
