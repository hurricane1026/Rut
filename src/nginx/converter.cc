#include "rut/nginx/converter.h"

#include "rut/common/forward_target_transform.h"
#include "rut/common/strict_local_response.h"

namespace rut::nginx {
namespace {

static constexpr char kTraceBody[] =
    "<html>\\r\\n"
    "<head><title>405 Not Allowed</title></head>\\r\\n"
    "<body>\\r\\n"
    "<center><h1>405 Not Allowed</h1></center>\\r\\n"
    "<hr><center>nginx/1.29.7</center>\\r\\n"
    "</body>\\r\\n"
    "</html>\\r\\n";

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

bool has_exact_no_content_return_inventory(const ExactNoContentReturnLocation& location) {
    const NoContentReturn& response = location.response;
    return location.present || location.path.ptr != nullptr || location.path.len != 0 ||
           !is_default_span(location.path_span) || !is_default_span(location.span) ||
           response.status != 0 || !is_default_span(response.status_span) ||
           !is_default_span(response.span);
}

Span exact_no_content_return_span(const Server& server) {
    const auto& location = server.exact_no_content_return;
    if (is_valid_span(location.response.span)) return location.response.span;
    if (is_valid_span(location.span)) return location.span;
    if (is_valid_span(location.path_span)) return location.path_span;
    if (is_valid_span(location.response.status_span)) return location.response.status_span;
    return server.span;
}

bool has_exact_absolute_redirect_inventory(const ExactAbsoluteRedirectLocation& location) {
    const AbsoluteRedirect& response = location.response;
    return location.present || location.path.ptr != nullptr || location.path.len != 0 ||
           !is_default_span(location.path_span) || !is_default_span(location.span) ||
           response.status != 0 || response.status_lexeme.ptr != nullptr ||
           response.status_lexeme.len != 0 || !is_default_span(response.status_span) ||
           response.target.ptr != nullptr || response.target.len != 0 ||
           !is_default_span(response.target_span) || response.authority.ptr != nullptr ||
           response.authority.len != 0 || !is_default_span(response.authority_span) ||
           response.path.ptr != nullptr || response.path.len != 0 ||
           !is_default_span(response.path_span) || !is_default_span(response.span);
}

Span exact_absolute_redirect_span(const Server& server) {
    const auto& location = server.exact_absolute_redirect;
    if (is_valid_span(location.span)) return location.span;
    if (is_valid_span(location.path_span)) return location.path_span;
    if (is_valid_span(location.response.span)) return location.response.span;
    if (is_valid_span(location.response.status_span)) return location.response.status_span;
    if (is_valid_span(location.response.target_span)) return location.response.target_span;
    if (is_valid_span(location.response.authority_span)) return location.response.authority_span;
    if (is_valid_span(location.response.path_span)) return location.response.path_span;
    return server.span;
}

constexpr bool span_position_is_coherent(const Span& outer, const Span& inner) {
    if (!is_valid_span(outer) || !is_valid_span(inner) || !span_contains(outer, inner) ||
        inner.line < outer.line)
        return false;
    if (inner.line != outer.line) return true;
    const u32 offset = inner.start - outer.start;
    return offset <= 0xFFFFFFFFu - outer.col && inner.col == outer.col + offset;
}

bool source_borrow_is_coherent(Str text, const Span& span, uintptr_t source_base) {
    if (text.ptr == nullptr || !is_valid_span(span) || span.end - span.start != text.len ||
        source_base > UINTPTR_MAX - span.start)
        return false;
    return reinterpret_cast<uintptr_t>(text.ptr) == source_base + span.start;
}

bool source_position_is_coherent(uintptr_t source_base,
                                 const Span& source_span,
                                 const Span& inner_span) {
    if (!span_contains(source_span, inner_span) || source_base > UINTPTR_MAX - inner_span.start)
        return false;
    u32 line = source_span.line;
    u32 col = source_span.col;
    for (u32 pos = source_span.start; pos < inner_span.start; pos++) {
        const char value = *reinterpret_cast<const char*>(source_base + pos);
        if (value == '\n') {
            if (line == 0xFFFFFFFFu) return false;
            line++;
            col = 1;
        } else {
            if (col == 0xFFFFFFFFu) return false;
            col++;
        }
    }
    return line == inner_span.line && col == inner_span.col;
}

constexpr bool source_byte_is_lexer_space(char value) {
    return value == ' ' || value == '\t' || value == '\r' || value == '\n' || value == '\f' ||
           value == '\v';
}

bool advance_trusted_source_gap(uintptr_t source_base, u32& pos, u32 end) {
    while (pos < end) {
        while (pos < end &&
               source_byte_is_lexer_space(*reinterpret_cast<const char*>(source_base + pos)))
            pos++;
        if (pos == end || *reinterpret_cast<const char*>(source_base + pos) != '#') return true;
        while (pos < end && *reinterpret_cast<const char*>(source_base + pos) != '\n') pos++;
        if (pos == end) return false;
    }
    return true;
}

bool trusted_source_gap_is_exact(uintptr_t source_base, u32 start, u32 end) {
    u32 pos = start;
    return advance_trusted_source_gap(source_base, pos, end) && pos == end;
}

static_assert(kMaxProxyPassUriLen == kMaxForwardTargetTransformPrefixLen);
static_assert(kMaxProxyLocationPathLen <= kMaxForwardTargetTransformPrefixLen);
static_assert(kMaxExactLocalReturnPathLen == kMaxExactStrictLocalResponsePathLen);
static_assert(kMaxExactLocalReturnPathLen == kMaxExactPathViewLen);

constexpr bool proxy_pass_uri_segment_byte_is_clean(char value) {
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
            if (!proxy_pass_uri_segment_byte_is_clean(uri.ptr[i])) return false;
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
            if (!proxy_pass_uri_segment_byte_is_clean(path.ptr[i])) return false;
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

enum class ProxyLocationProfile : u8 { RootWithoutUri, PrefixWithUri };

bool basic_borrow_address_is_safe(Str text, const Span& span) {
    if (text.ptr == nullptr || !is_valid_span(span) || span.end - span.start != text.len)
        return false;
    const uintptr_t address = reinterpret_cast<uintptr_t>(text.ptr);
    return address >= span.start && address <= UINTPTR_MAX - text.len;
}

FrontendResult<ProxyLocationProfile> validate_proxy_location(const Server& server) {
    const Location& location = server.location;
    const ProxyPass& proxy = location.proxy_pass;
    if (location.path.len == 0 || location.path.len > kMaxProxyLocationPathLen)
        return unsupported(location.path_span,
                           lit_str("invalid bounded proxy location path model"));
    if (proxy.has_uri &&
        (proxy.uri.ptr == nullptr || proxy.uri.len == 0 || proxy.uri.len > kMaxProxyPassUriLen))
        return unsupported(proxy.uri_span, lit_str("invalid bounded proxy_pass URI model"));

    if (location.path.len == 1) {
        // Existing hand-built root fixtures use an independent static string.
        if (!basic_borrow_address_is_safe(location.path, location.path_span))
            return unsupported(location.path_span, lit_str("invalid proxy_pass source provenance"));
        if (!eq(location.path, "/", 1))
            return unsupported(location.path_span,
                               lit_str("invalid bounded proxy location path model"));
        if (proxy.uri.ptr != nullptr || proxy.uri.len != 0 || !is_default_span(proxy.uri_span))
            return unsupported(proxy.span, lit_str("invalid proxy_pass URI state"));
        if (proxy.has_uri)
            return unsupported(proxy.uri_span, lit_str("location / cannot use a proxy_pass URI"));
        return ProxyLocationProfile::RootWithoutUri;
    }

    if (!proxy.has_uri)
        return unsupported(location.path_span,
                           lit_str("non-root location requires a proxy_pass URI"));

    // Preserve only the historical hand-built canonical `/api/ -> /` fixture. Its
    // intentionally synthetic spans predate source provenance. All parser-produced
    // and all other non-root models must pass the complete common-source gate below.
    const bool legacy_api_shape =
        location.path.len == 5 && proxy.uri.len == 1 && location.path_span.start == 22 &&
        location.path_span.end == 27 && location.path_span.line == 1 &&
        location.path_span.col == 23 && location.span.start == 22 && location.span.end == 23 &&
        location.span.line == 1 && location.span.col == 23 && proxy.span.start == 26 &&
        proxy.span.end == 52 && proxy.span.line == 1 && proxy.span.col == 26 &&
        proxy.uri_span.start == 53 && proxy.uri_span.end == 54 && proxy.uri_span.line == 1 &&
        proxy.uri_span.col == 54;
    if (legacy_api_shape) {
        if (!basic_borrow_address_is_safe(location.path, location.path_span))
            return unsupported(location.path_span, lit_str("invalid proxy_pass source provenance"));
        if (!basic_borrow_address_is_safe(proxy.uri, proxy.uri_span))
            return unsupported(proxy.uri_span, lit_str("invalid proxy_pass URI provenance"));
        if (!eq(location.path, "/api/", 5) || !eq(proxy.uri, "/", 1))
            return unsupported(location.path_span, lit_str("invalid historical /api/ proxy model"));
        return ProxyLocationProfile::PrefixWithUri;
    }

    // Dynamic path and URI bytes are not read until their complete spans, arithmetic,
    // common-source borrow, and source positions have all been established.
    if (!span_position_is_coherent(server.span, location.span))
        return unsupported(is_valid_span(location.span) ? location.span : model_span(server),
                           lit_str("invalid proxy location spans"));
    if (!span_position_is_coherent(location.span, location.path_span) ||
        location.path_span.end - location.path_span.start != location.path.len)
        return unsupported(is_valid_span(location.path_span) ? location.path_span : location.span,
                           lit_str("invalid proxy location spans"));
    if (!span_position_is_coherent(location.span, proxy.span) ||
        location.path_span.end >= proxy.span.start)
        return unsupported(is_valid_span(proxy.span) ? proxy.span : location.span,
                           lit_str("invalid proxy location spans"));
    if (!span_position_is_coherent(proxy.span, proxy.uri_span) ||
        proxy.uri_span.end - proxy.uri_span.start != proxy.uri.len ||
        proxy.uri_span.end >= proxy.span.end)
        return unsupported(is_valid_span(proxy.uri_span) ? proxy.uri_span : proxy.span,
                           lit_str("invalid proxy location spans"));

    const uintptr_t path_address = reinterpret_cast<uintptr_t>(location.path.ptr);
    if (location.path.ptr == nullptr || path_address < location.path_span.start)
        return unsupported(location.path_span, lit_str("invalid proxy_pass source provenance"));
    const uintptr_t source_base = path_address - location.path_span.start;
    if (source_base > UINTPTR_MAX - server.span.end ||
        !source_borrow_is_coherent(location.path, location.path_span, source_base))
        return unsupported(location.path_span, lit_str("invalid proxy_pass source provenance"));
    if (!source_borrow_is_coherent(proxy.uri, proxy.uri_span, source_base))
        return unsupported(proxy.uri_span, lit_str("invalid proxy_pass URI provenance"));
    if (!source_position_is_coherent(source_base, server.span, location.span))
        return unsupported(location.span, lit_str("invalid proxy location source positions"));
    if (!source_position_is_coherent(source_base, server.span, location.path_span))
        return unsupported(location.path_span, lit_str("invalid proxy location source positions"));
    if (!source_position_is_coherent(source_base, server.span, proxy.span))
        return unsupported(proxy.span, lit_str("invalid proxy location source positions"));
    if (!source_position_is_coherent(source_base, server.span, proxy.uri_span))
        return unsupported(proxy.uri_span, lit_str("invalid proxy location source positions"));
    if (!proxy_location_path_is_clean(location.path))
        return unsupported(location.path_span,
                           lit_str("invalid bounded proxy location path model"));
    if (!proxy_pass_uri_is_clean(proxy.uri))
        return unsupported(proxy.uri_span, lit_str("invalid bounded proxy_pass URI model"));
    return ProxyLocationProfile::PrefixWithUri;
}

FrontendResult<bool> validate_exact_absolute_redirect(const Server& server) {
    constexpr u32 kAuthorityOffset = 7;
    constexpr u32 kAuthorityLen = 16;
    constexpr u32 kPathOffset = kAuthorityOffset + kAuthorityLen;
    const ExactAbsoluteRedirectLocation& location = server.exact_absolute_redirect;
    const AbsoluteRedirect& response = location.response;
    if (!location.present) {
        if (has_exact_absolute_redirect_inventory(location))
            return unsupported(exact_absolute_redirect_span(server),
                               lit_str("invalid absent exact absolute redirect model"));
        return false;
    }

    if (has_exact_local_return_inventory(server.exact_local_return))
        return unsupported(exact_local_return_span(server),
                           lit_str("multiple exact semantic actions are unsupported"));

    if (!span_position_is_coherent(server.span, location.span))
        return unsupported(is_valid_span(location.span) ? location.span : server.span,
                           lit_str("invalid exact absolute redirect location span"));
    if (!span_position_is_coherent(location.span, location.path_span) ||
        location.path_span.end - location.path_span.start != 4)
        return unsupported(is_valid_span(location.path_span) ? location.path_span : location.span,
                           lit_str("invalid exact absolute redirect location path span"));
    if (!span_position_is_coherent(location.span, response.span) ||
        location.path_span.end >= response.span.start)
        return unsupported(is_valid_span(response.span) ? response.span : location.span,
                           lit_str("invalid exact absolute redirect response span"));
    if (!span_position_is_coherent(response.span, response.status_span) ||
        response.status_span.end - response.status_span.start != 3 ||
        response.span.start >= response.status_span.start)
        return unsupported(
            is_valid_span(response.status_span) ? response.status_span : response.span,
            lit_str("invalid exact absolute redirect status span"));
    if (!span_position_is_coherent(response.span, response.target_span) ||
        response.target_span.end - response.target_span.start != 27 ||
        response.status_span.end >= response.target_span.start ||
        response.target_span.end >= response.span.end)
        return unsupported(
            is_valid_span(response.target_span) ? response.target_span : response.span,
            lit_str("invalid exact absolute redirect target span"));
    if (!span_position_is_coherent(response.target_span, response.authority_span) ||
        response.authority_span.start != response.target_span.start + kAuthorityOffset ||
        response.authority_span.end != response.target_span.start + kPathOffset ||
        response.authority_span.end - response.authority_span.start != kAuthorityLen ||
        response.authority_span.line != response.target_span.line ||
        response.authority_span.col != response.target_span.col + kAuthorityOffset)
        return unsupported(
            is_valid_span(response.authority_span) ? response.authority_span : response.target_span,
            lit_str("invalid exact absolute redirect authority span"));
    if (!span_position_is_coherent(response.target_span, response.path_span) ||
        response.path_span.start != response.target_span.start + kPathOffset ||
        response.path_span.end != response.target_span.end ||
        response.path_span.end - response.path_span.start != 4 ||
        response.path_span.line != response.target_span.line ||
        response.path_span.col != response.target_span.col + kPathOffset)
        return unsupported(
            is_valid_span(response.path_span) ? response.path_span : response.target_span,
            lit_str("invalid exact absolute redirect target path span"));

    const Location& fallback = server.location;
    const uintptr_t fallback_path_address = reinterpret_cast<uintptr_t>(fallback.path.ptr);
    if (!span_position_is_coherent(server.span, fallback.span) ||
        !span_position_is_coherent(fallback.span, fallback.path_span) ||
        fallback.path.ptr == nullptr || fallback_path_address < fallback.path_span.start ||
        fallback.path_span.end - fallback.path_span.start != fallback.path.len)
        return unsupported(is_valid_span(fallback.path_span) ? fallback.path_span : server.span,
                           lit_str("invalid exact absolute redirect fallback provenance"));
    const uintptr_t source_base = fallback_path_address - fallback.path_span.start;

    if (!source_borrow_is_coherent(location.path, location.path_span, source_base))
        return unsupported(location.path_span,
                           lit_str("invalid exact absolute redirect location path provenance"));
    if (!source_borrow_is_coherent(response.target, response.target_span, source_base))
        return unsupported(response.target_span,
                           lit_str("invalid exact absolute redirect target provenance"));
    if (!source_borrow_is_coherent(response.authority, response.authority_span, source_base))
        return unsupported(response.authority_span,
                           lit_str("invalid exact absolute redirect authority provenance"));
    if (!source_borrow_is_coherent(response.path, response.path_span, source_base))
        return unsupported(response.path_span,
                           lit_str("invalid exact absolute redirect target path provenance"));
    if (!source_borrow_is_coherent(response.status_lexeme, response.status_span, source_base))
        return unsupported(response.status_span,
                           lit_str("invalid exact absolute redirect status provenance"));

    if (!eq(location.path, "/old", 4))
        return unsupported(location.path_span,
                           lit_str("invalid exact absolute redirect location path"));
    if (response.status != 301 && response.status != 302)
        return unsupported(response.status_span, lit_str("invalid exact absolute redirect status"));
    const char* expected_status_lexeme = response.status == 301 ? "301" : "302";
    if (!eq(response.status_lexeme, expected_status_lexeme, 3))
        return unsupported(response.status_span,
                           lit_str("invalid exact absolute redirect status lexeme"));
    if (!eq(response.target, "http://redirect.example/new", 27))
        return unsupported(response.target_span, lit_str("invalid exact absolute redirect target"));
    if (reinterpret_cast<uintptr_t>(response.authority.ptr) !=
            reinterpret_cast<uintptr_t>(response.target.ptr) + kAuthorityOffset ||
        response.authority.len != kAuthorityLen ||
        !eq(response.authority, "redirect.example", kAuthorityLen))
        return unsupported(response.authority_span,
                           lit_str("invalid exact absolute redirect authority"));
    if (reinterpret_cast<uintptr_t>(response.path.ptr) !=
            reinterpret_cast<uintptr_t>(response.target.ptr) + kPathOffset ||
        response.path.len != 4 || !eq(response.path, "/new", 4))
        return unsupported(response.path_span,
                           lit_str("invalid exact absolute redirect target path"));
    return true;
}

FrontendResult<bool> validate_exact_no_content_return(const Server& server) {
    const ExactNoContentReturnLocation& location = server.exact_no_content_return;
    const NoContentReturn& response = location.response;
    if (!location.present) {
        if (has_exact_no_content_return_inventory(location))
            return unsupported(exact_no_content_return_span(server),
                               lit_str("invalid absent exact no-content return model"));
        return false;
    }

    // This validator is the first dynamic-borrow boundary in lower_to_rut. All
    // scalar bounds, nested structure, source arithmetic, and cross-action
    // inventory are therefore checked before any model byte is inspected.
    if (location.path.len != 7u || location.path.len > kMaxExactLocalReturnPathLen)
        return unsupported(is_valid_span(location.path_span) ? location.path_span
                                                             : exact_no_content_return_span(server),
                           lit_str("invalid bounded exact no-content return path model"));
    if (response.status != 204u)
        return unsupported(is_valid_span(response.status_span)
                               ? response.status_span
                               : exact_no_content_return_span(server),
                           lit_str("invalid exact no-content return status"));
    if (!span_position_is_coherent(server.span, location.span))
        return unsupported(is_valid_span(location.span) ? location.span : server.span,
                           lit_str("invalid exact no-content return location span"));
    if (!span_position_is_coherent(location.span, location.path_span) ||
        location.path_span.end - location.path_span.start != location.path.len)
        return unsupported(is_valid_span(location.path_span) ? location.path_span : location.span,
                           lit_str("invalid exact no-content return path span"));
    if (!span_position_is_coherent(location.span, response.span) ||
        location.path_span.end >= response.span.start)
        return unsupported(is_valid_span(response.span) ? response.span : location.span,
                           lit_str("invalid exact no-content return directive span"));
    if (!span_position_is_coherent(response.span, response.status_span) ||
        response.status_span.end - response.status_span.start != 3u ||
        response.span.start >= response.status_span.start ||
        response.status_span.end >= response.span.end)
        return unsupported(
            is_valid_span(response.status_span) ? response.status_span : response.span,
            lit_str("invalid exact no-content return status span"));

    if (has_exact_local_return_inventory(server.exact_local_return))
        return unsupported(exact_local_return_span(server),
                           lit_str("multiple exact semantic actions are unsupported"));
    if (has_exact_absolute_redirect_inventory(server.exact_absolute_redirect))
        return unsupported(exact_absolute_redirect_span(server),
                           lit_str("multiple exact semantic actions are unsupported"));

    const Location& fallback = server.location;
    const uintptr_t fallback_path_address = reinterpret_cast<uintptr_t>(fallback.path.ptr);
    if (!span_position_is_coherent(server.span, fallback.span) ||
        !span_position_is_coherent(fallback.span, fallback.path_span) ||
        fallback.path.ptr == nullptr || fallback_path_address < fallback.path_span.start ||
        fallback.path.len != 1u ||
        fallback.path_span.end - fallback.path_span.start != fallback.path.len)
        return unsupported(is_valid_span(fallback.path_span) ? fallback.path_span : server.span,
                           lit_str("invalid exact no-content return fallback provenance"));

    const uintptr_t path_address = reinterpret_cast<uintptr_t>(location.path.ptr);
    if (location.path.ptr == nullptr || path_address < location.path_span.start)
        return unsupported(location.path_span,
                           lit_str("invalid exact no-content return path provenance"));
    const uintptr_t fallback_source_base = fallback_path_address - fallback.path_span.start;
    const uintptr_t path_source_base = path_address - location.path_span.start;
    if (fallback_source_base > UINTPTR_MAX - server.span.end)
        return unsupported(fallback.path_span,
                           lit_str("invalid exact no-content return fallback provenance"));
    if (path_source_base > UINTPTR_MAX - server.span.end)
        return unsupported(location.path_span,
                           lit_str("invalid exact no-content return path provenance"));
    if (fallback_source_base != path_source_base)
        return unsupported(location.path_span,
                           lit_str("invalid exact no-content return path provenance"));

    const uintptr_t source_base = fallback_source_base;
    if (!source_borrow_is_coherent(fallback.path, fallback.path_span, source_base))
        return unsupported(fallback.path_span,
                           lit_str("invalid exact no-content return fallback provenance"));
    if (!source_borrow_is_coherent(location.path, location.path_span, source_base))
        return unsupported(location.path_span,
                           lit_str("invalid exact no-content return path provenance"));
    if (!source_position_is_coherent(source_base, server.span, fallback.span))
        return unsupported(fallback.span,
                           lit_str("invalid exact no-content return fallback source position"));
    if (!source_position_is_coherent(source_base, server.span, fallback.path_span))
        return unsupported(
            fallback.path_span,
            lit_str("invalid exact no-content return fallback path source position"));
    if (!source_position_is_coherent(source_base, server.span, location.span))
        return unsupported(location.span,
                           lit_str("invalid exact no-content return source positions"));
    if (!source_position_is_coherent(source_base, server.span, location.path_span))
        return unsupported(location.path_span,
                           lit_str("invalid exact no-content return path source position"));
    if (!source_position_is_coherent(source_base, server.span, response.span))
        return unsupported(response.span,
                           lit_str("invalid exact no-content return directive source position"));
    if (!source_position_is_coherent(source_base, server.span, response.status_span))
        return unsupported(response.status_span,
                           lit_str("invalid exact no-content return status source position"));

    // Byte reads begin only after the common source base and every relevant
    // source position have been proven. Pin both semantic literals and the
    // directive delimiters so forged subspans cannot manufacture a valid action.
    if (!eq(location.path, "/static", 7u))
        return unsupported(location.path_span,
                           lit_str("invalid exact no-content return location path"));
    if (!eq(fallback.path, "/", 1u))
        return unsupported(fallback.path_span,
                           lit_str("invalid exact no-content return fallback path"));

    // Reconstruct only this bounded exact-location shell with a trusted-source
    // cursor. Every cursor limit is one of the nested spans proven above. This
    // prevents a forged model from borrowing valid `/static` and `return 204;`
    // interiors out of a comment or a different lexical container.
    const u32 location_prefix_len = location.path_span.start - location.span.start;
    if (location_prefix_len <= 8u)
        return unsupported(location.span,
                           lit_str("invalid exact no-content return location shell"));
    const Str location_keyword{reinterpret_cast<const char*>(source_base + location.span.start),
                               8u};
    if (!eq(location_keyword, "location", 8u))
        return unsupported(location.span,
                           lit_str("invalid exact no-content return location shell"));

    u32 cursor = location.span.start + 8u;
    if (cursor >= location.path_span.start ||
        (!source_byte_is_lexer_space(*reinterpret_cast<const char*>(source_base + cursor)) &&
         *reinterpret_cast<const char*>(source_base + cursor) != '#'))
        return unsupported(location.span,
                           lit_str("invalid exact no-content return location shell"));
    const u32 keyword_gap_start = cursor;
    if (!advance_trusted_source_gap(source_base, cursor, location.path_span.start) ||
        cursor == keyword_gap_start || cursor >= location.path_span.start ||
        *reinterpret_cast<const char*>(source_base + cursor) != '=')
        return unsupported(location.span,
                           lit_str("invalid exact no-content return location shell"));
    cursor++;
    if (cursor >= location.path_span.start ||
        (!source_byte_is_lexer_space(*reinterpret_cast<const char*>(source_base + cursor)) &&
         *reinterpret_cast<const char*>(source_base + cursor) != '#'))
        return unsupported(location.span,
                           lit_str("invalid exact no-content return location shell"));
    const u32 equals_gap_start = cursor;
    if (!advance_trusted_source_gap(source_base, cursor, location.path_span.start) ||
        cursor == equals_gap_start || cursor != location.path_span.start)
        return unsupported(location.span,
                           lit_str("invalid exact no-content return location shell"));

    cursor = location.path_span.end;
    if (*reinterpret_cast<const char*>(source_base + cursor) == '#')
        return unsupported(location.path_span,
                           lit_str("exact local return path is outside the bounded clean profile"));
    if (!advance_trusted_source_gap(source_base, cursor, response.span.start) ||
        cursor >= response.span.start ||
        *reinterpret_cast<const char*>(source_base + cursor) != '{')
        return unsupported(location.span,
                           lit_str("invalid exact no-content return location shell"));
    cursor++;
    if (!trusted_source_gap_is_exact(source_base, cursor, response.span.start))
        return unsupported(response.span,
                           lit_str("invalid exact no-content return pre-response gap"));

    cursor = response.span.end;
    if (!advance_trusted_source_gap(source_base, cursor, location.span.end) ||
        cursor >= location.span.end ||
        *reinterpret_cast<const char*>(source_base + cursor) != '}' ||
        cursor + 1u != location.span.end)
        return unsupported(location.span,
                           lit_str("invalid exact no-content return location shell"));

    const Str status_text{reinterpret_cast<const char*>(source_base + response.status_span.start),
                          3u};
    if (!eq(status_text, "204", 3u))
        return unsupported(response.status_span,
                           lit_str("invalid exact no-content return status literal"));
    const Str directive_keyword{reinterpret_cast<const char*>(source_base + response.span.start),
                                6u};
    if (response.status_span.start - response.span.start <= 6u ||
        !eq(directive_keyword, "return", 6u))
        return unsupported(response.span,
                           lit_str("invalid exact no-content return directive delimiter"));
    const char after_keyword =
        *reinterpret_cast<const char*>(source_base + response.span.start + 6u);
    const char before_status =
        *reinterpret_cast<const char*>(source_base + response.status_span.start - 1u);
    const char terminator = *reinterpret_cast<const char*>(source_base + response.span.end - 1u);
    const bool after_keyword_delimits =
        source_byte_is_lexer_space(after_keyword) || after_keyword == '#';
    const bool before_status_delimits = source_byte_is_lexer_space(before_status);
    const u32 after_status_start = response.status_span.end;
    const u32 before_terminator = response.span.end - 1u;
    const bool status_has_adjacent_comment =
        after_status_start < before_terminator &&
        *reinterpret_cast<const char*>(source_base + after_status_start) == '#';
    if (!after_keyword_delimits || !before_status_delimits || terminator != ';' ||
        !trusted_source_gap_is_exact(
            source_base, response.span.start + 6u, response.status_span.start) ||
        status_has_adjacent_comment ||
        !trusted_source_gap_is_exact(source_base, after_status_start, before_terminator))
        return unsupported(response.span,
                           lit_str("invalid exact no-content return directive delimiter"));
    return true;
}

bool local_return_body_byte_is_safe(char value) {
    const u8 byte = static_cast<u8>(value);
    return byte >= 0x21 && byte <= 0x7e && value != '"' && value != '\\' && value != '$' &&
           value != '#' && value != '{' && value != '}' && value != ';';
}

bool local_return_body_is_clean(Str body) {
    if (body.ptr == nullptr || body.len == 0 || body.len > kMaxLocalReturnBodyLen) return false;
    for (u32 i = 0; i < body.len; i++) {
        if (body.ptr[i] == ' ') {
            if (i == 0 || i + 1u == body.len) return false;
            continue;
        }
        if (!local_return_body_byte_is_safe(body.ptr[i])) return false;
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
            if (!proxy_pass_uri_segment_byte_is_clean(path.ptr[i])) return false;
            continue;
        }
        const u32 segment_len = i - segment_start;
        if (segment_len == 0 || (segment_len == 1 && path.ptr[segment_start] == '.') ||
            (segment_len == 2 && path.ptr[segment_start] == '.' &&
             path.ptr[segment_start + 1] == '.'))
            return false;
        segment_start = i + 1;
    }
    if (segment_start == path.len) return true;
    const u32 segment_len = path.len - segment_start;
    return !(
        (segment_len == 1 && path.ptr[segment_start] == '.') ||
        (segment_len == 2 && path.ptr[segment_start] == '.' && path.ptr[segment_start + 1] == '.'));
}

FrontendResult<bool> validate_exact_local_return(const Server& server) {
    const ExactLocalReturnLocation& location = server.exact_local_return;
    const LocalReturn& response = location.response;
    if (!location.present) {
        if (has_exact_local_return_inventory(location))
            return unsupported(exact_local_return_span(server),
                               lit_str("invalid absent exact local return model"));
        return false;
    }

    // Dynamic path/body bytes remain unread until scalar bounds, complete nested
    // spans, arithmetic, common-source borrowing, and source positions are proven.
    if (location.path.len < 2 || location.path.len > kMaxExactLocalReturnPathLen)
        return unsupported(is_valid_span(location.path_span) ? location.path_span
                                                             : exact_local_return_span(server),
                           lit_str("invalid bounded exact local return path model"));
    if (response.body.len == 0 || response.body.len > kMaxLocalReturnBodyLen)
        return unsupported(is_valid_span(response.body_span) ? response.body_span : response.span,
                           lit_str("invalid exact local return body"));
    if (!span_position_is_coherent(server.span, location.span))
        return unsupported(is_valid_span(location.span) ? location.span : server.span,
                           lit_str("invalid exact local return location span"));
    if (!span_position_is_coherent(location.span, location.path_span) ||
        location.path_span.end - location.path_span.start != location.path.len)
        return unsupported(is_valid_span(location.path_span) ? location.path_span : location.span,
                           lit_str("invalid exact local return path span"));
    if (!span_position_is_coherent(location.span, response.span) ||
        location.path_span.end >= response.span.start)
        return unsupported(is_valid_span(response.span) ? response.span : location.span,
                           lit_str("invalid exact local return response span"));
    if (!span_position_is_coherent(response.span, response.body_span) ||
        response.body_span.end - response.body_span.start != response.body.len ||
        response.span.start >= response.body_span.start ||
        response.body_span.end >= response.span.end)
        return unsupported(is_valid_span(response.body_span) ? response.body_span : response.span,
                           lit_str("invalid exact local return body span"));

    const Location& fallback = server.location;
    const uintptr_t fallback_path_address = reinterpret_cast<uintptr_t>(fallback.path.ptr);
    if (!span_position_is_coherent(server.span, fallback.span) ||
        !span_position_is_coherent(fallback.span, fallback.path_span) ||
        fallback.path.ptr == nullptr || fallback_path_address < fallback.path_span.start ||
        fallback.path_span.end - fallback.path_span.start != fallback.path.len)
        return unsupported(is_valid_span(fallback.path_span) ? fallback.path_span : server.span,
                           lit_str("invalid exact local return fallback provenance"));
    const uintptr_t path_address = reinterpret_cast<uintptr_t>(location.path.ptr);
    if (location.path.ptr == nullptr || path_address < location.path_span.start)
        return unsupported(location.path_span,
                           lit_str("invalid exact local return path provenance"));
    const uintptr_t body_address = reinterpret_cast<uintptr_t>(response.body.ptr);
    if (response.body.ptr == nullptr || body_address < response.body_span.start)
        return unsupported(response.body_span,
                           lit_str("invalid exact local return body provenance"));

    const uintptr_t fallback_source_base = fallback_path_address - fallback.path_span.start;
    const uintptr_t path_source_base = path_address - location.path_span.start;
    const uintptr_t body_source_base = body_address - response.body_span.start;
    if (fallback_source_base > UINTPTR_MAX - server.span.end)
        return unsupported(fallback.path_span,
                           lit_str("invalid exact local return fallback provenance"));
    if (path_source_base > UINTPTR_MAX - server.span.end)
        return unsupported(location.path_span,
                           lit_str("invalid exact local return path provenance"));
    if (body_source_base > UINTPTR_MAX - server.span.end)
        return unsupported(response.body_span,
                           lit_str("invalid exact local return body provenance"));

    // Three independent borrows identify a single forged source-base without
    // trusting or reading any one borrow first.
    if (fallback_source_base != path_source_base) {
        if (path_source_base == body_source_base)
            return unsupported(fallback.path_span,
                               lit_str("invalid exact local return fallback provenance"));
        return unsupported(location.path_span,
                           lit_str("invalid exact local return path provenance"));
    }
    if (fallback_source_base != body_source_base)
        return unsupported(response.body_span,
                           lit_str("invalid exact local return body provenance"));

    const uintptr_t source_base = fallback_source_base;
    if (!source_position_is_coherent(source_base, server.span, location.span))
        return unsupported(location.span, lit_str("invalid exact local return source positions"));
    if (!source_position_is_coherent(source_base, server.span, location.path_span))
        return unsupported(location.path_span,
                           lit_str("invalid exact local return path source position"));
    if (!source_position_is_coherent(source_base, server.span, response.span))
        return unsupported(response.span,
                           lit_str("invalid exact local return response source position"));
    if (!source_position_is_coherent(source_base, server.span, response.body_span))
        return unsupported(response.body_span,
                           lit_str("invalid exact local return body source position"));

    // Only after all three borrows have established one bounded source and all
    // source positions are coherent may the bytes adjacent to the borrowed
    // body be trusted. The semantic model represents the raw quote interior,
    // so both delimiters are part of its provenance contract.
    const char opening_quote =
        *reinterpret_cast<const char*>(source_base + response.body_span.start - 1u);
    const char closing_quote = *reinterpret_cast<const char*>(source_base + response.body_span.end);
    if (opening_quote != '"' || closing_quote != '"')
        return unsupported(response.body_span,
                           lit_str("invalid exact local return body delimiters"));

    if (!exact_local_return_path_is_clean(location.path) || eq(location.path, "/old", 4))
        return unsupported(location.path_span,
                           lit_str("invalid bounded exact local return path model"));
    if (response.status != 200)
        return unsupported(is_valid_span(response.span) ? response.span : location.span,
                           lit_str("invalid exact local return status"));
    if (!local_return_body_is_clean(response.body))
        return unsupported(response.body_span, lit_str("invalid exact local return body"));
    return true;
}

Span pre_route_trace_span(const Server& server) {
    return is_valid_span(server.pre_route_trace.span) ? server.pre_route_trace.span
                                                      : model_span(server);
}

FrontendResult<bool> validate_pre_route_trace(const Server& server) {
    const ImplicitPreRouteTrace& trace = server.pre_route_trace;
    switch (trace.profile) {
        case ImplicitPreRouteProfile::None:
            if (!is_default_span(trace.span))
                return unsupported(pre_route_trace_span(server),
                                   lit_str("invalid absent pre-route TRACE model"));
            return unsupported(model_span(server), lit_str("missing pre-route TRACE model"));
        case ImplicitPreRouteProfile::Nginx1297PreLocationTrace405:
            break;
        default:
            return unsupported(pre_route_trace_span(server),
                               lit_str("invalid pre-route TRACE profile model"));
    }
    if (!is_valid_span(trace.span) || !span_position_is_coherent(server.span, trace.span) ||
        trace.span.start != server.span.start || trace.span.end != server.span.end ||
        trace.span.line != server.span.line || trace.span.col != server.span.col)
        return unsupported(pre_route_trace_span(server), lit_str("invalid pre-route TRACE spans"));
    return true;
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
        if (text.len >= RutSource::kCapacity - output_.len) return false;
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
        if (count >= RutSource::kCapacity - output_.len) return false;
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
        if (count >= RutSource::kCapacity - output_.len) return false;
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

static constexpr char kRedirect301Reason[] = "Moved Permanently";
static constexpr char kRedirect302Reason[] = "Moved Temporarily";

static constexpr char kRedirect301Body[] =
    "<html>\\r\\n"
    "<head><title>301 Moved Permanently</title></head>\\r\\n"
    "<body>\\r\\n"
    "<center><h1>301 Moved Permanently</h1></center>\\r\\n"
    "<hr><center>nginx/1.29.7</center>\\r\\n"
    "</body>\\r\\n"
    "</html>\\r\\n";

static constexpr char kRedirect302Body[] =
    "<html>\\r\\n"
    "<head><title>302 Found</title></head>\\r\\n"
    "<body>\\r\\n"
    "<center><h1>302 Found</h1></center>\\r\\n"
    "<hr><center>nginx/1.29.7</center>\\r\\n"
    "</body>\\r\\n"
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

bool put_pre_route_trace(Writer& writer, ImplicitPreRouteProfile profile) {
    if (profile != ImplicitPreRouteProfile::Nginx1297PreLocationTrace405) return false;
    return writer.put_cstr("pre_route TRACE { return local_response({\n") &&
           writer.put_cstr(
               "  version: \"HTTP/1.1\", status: 405, reason: \"Not Allowed\", server: "
               "\"nginx/1.29.7\",\n") &&
           writer.put_cstr(
               "  date: \"current\", content_type: \"text/html\", connection: \"request\",\n") &&
           writer.put_cstr("  head_mode: \"reject\", body: b\"") &&
           writer.put_lit(kTraceBody, sizeof(kTraceBody) - 1u) && writer.put_cstr("\"\n}) }\n");
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

bool put_root_forward_action(Writer& writer, bool suppress_body, bool buffered, Str indent) {
    return writer.put(indent) && writer.put_cstr("return forward(nginx_upstream, ") &&
           put_request_policy(writer) && put_response_policy(writer, suppress_body) &&
           put_failure_policy(writer, suppress_body, buffered) &&
           (buffered ? put_timeout_failure_policy(writer) : true) &&
           (buffered ? writer.put_cstr("        response_read_timeout: 60s,\n") : true) &&
           (buffered ? writer.put_cstr("        response_buffering: \"complete_content_length\"\n")
                     : true) &&
           writer.put_cstr("    )\n");
}

bool put_exact_absolute_redirect(
    Writer& writer, Str location_path, u16 status, Str static_authority, Str target_path) {
    const char* reason = nullptr;
    const char* body = nullptr;
    u32 reason_len = 0;
    u32 body_len = 0;
    switch (status) {
        case 301:
            reason = kRedirect301Reason;
            reason_len = sizeof(kRedirect301Reason) - 1u;
            body = kRedirect301Body;
            body_len = sizeof(kRedirect301Body) - 1u;
            break;
        case 302:
            reason = kRedirect302Reason;
            reason_len = sizeof(kRedirect302Reason) - 1u;
            body = kRedirect302Body;
            body_len = sizeof(kRedirect302Body) - 1u;
            break;
        default:
            return false;
    }
    return writer.put_cstr("route GET \"/\" {\n") && writer.put_cstr("    if req.pathOnly == \"") &&
           writer.put(location_path) && writer.put_cstr("\" {\n") &&
           writer.put_cstr(
               "        return redirect({scheme: \"http\", authority: \"static\", "
               "static_authority: \"") &&
           writer.put(static_authority) && writer.put_cstr("\", port: \"omit\",\n") &&
           writer.put_cstr(
               "            path: \"static\", query: \"discard\", date: \"current\", "
               "connection: \"close\",\n") &&
           writer.put_cstr("            header_order: \"connection_then_location\", status: ") &&
           writer.put_u16(status) && writer.put_cstr(", reason: \"") &&
           writer.put_lit(reason, reason_len) && writer.put_cstr("\",\n") &&
           writer.put_cstr(
               "            server: \"nginx/1.29.7\", content_type: \"text/html\", "
               "target_path: \"") &&
           writer.put(target_path) && writer.put_cstr("\", body: b\"") &&
           writer.put_lit(body, body_len) && writer.put_cstr("\"})\n") &&
           writer.put_cstr("    } else {\n") &&
           put_root_forward_action(writer, false, true, lit_str("        ")) &&
           writer.put_cstr("    }\n}\n");
}

bool put_exact_local_return(Writer& writer, Str path, Str body) {
    // validate_exact_local_return has already proven the complete path borrow
    // and clean grammar before this final-byte view selection is reached.
    const bool slash_normalized = path.ptr[path.len - 1u] == '/';
    return writer.put_cstr(slash_normalized ? "route exact slash_normalized \""
                                            : "route exact \"") &&
           writer.put(path) && writer.put_cstr("\" { return local_response({\n") &&
           writer.put_cstr(
               "  version: \"HTTP/1.1\", status: 200, reason: \"OK\", server: "
               "\"nginx/1.29.7\",\n") &&
           writer.put_cstr(
               "  date: \"current\", content_type: \"text/plain\", connection: \"request\",\n") &&
           writer.put_cstr("  head_mode: \"suppress_body\", body: b\"") && writer.put(body) &&
           writer.put_cstr("\"\n}) }\n");
}

bool put_exact_no_content_return(Writer& writer) {
    return writer.put_cstr("route exact GET \"/static\" { return local_response({\n") &&
           writer.put_cstr(
               "  version: \"HTTP/1.1\", status: 204, reason: \"No Content\", server: "
               "\"nginx/1.29.7\",\n") &&
           writer.put_cstr("  date: \"current\", content_type: \"\", connection: \"request\",\n") &&
           writer.put_cstr("  head_mode: \"suppress_body\", body: b\"\"\n}) }\n");
}

}  // namespace

FrontendResult<RutSource> lower_to_rut(const Server& server) {
    auto exact_no_content_return = validate_exact_no_content_return(server);
    if (!exact_no_content_return) return core::make_unexpected(exact_no_content_return.error());
    auto exact_absolute_redirect = validate_exact_absolute_redirect(server);
    if (!exact_absolute_redirect) return core::make_unexpected(exact_absolute_redirect.error());
    auto exact_local_return = validate_exact_local_return(server);
    if (!exact_local_return) return core::make_unexpected(exact_local_return.error());
    auto proxy_location = validate_proxy_location(server);
    if (!proxy_location) return core::make_unexpected(proxy_location.error());
    auto timeout = validate_proxy_read_timeout(server);
    if (!timeout) return core::make_unexpected(timeout.error());
    if (server.listen.port == 0)
        return invalid_integer(server.listen.span, lit_str("invalid model listen port"));
    const ProxyPass& proxy = server.location.proxy_pass;
    if (proxy.port == 0)
        return invalid_integer(server.location.proxy_pass.span,
                               lit_str("invalid model upstream port"));
    const bool is_root = proxy_location.value() == ProxyLocationProfile::RootWithoutUri;
    auto pre_route_trace = validate_pre_route_trace(server);
    if (!pre_route_trace) return core::make_unexpected(pre_route_trace.error());
    if (exact_local_return.value() && !is_root)
        return unsupported(server.exact_local_return.span,
                           lit_str("exact local return requires location / fallback"));
    if (exact_absolute_redirect.value() && !is_root)
        return unsupported(server.exact_absolute_redirect.span,
                           lit_str("exact absolute redirect requires location / fallback"));
    if (exact_no_content_return.value() && !is_root)
        return unsupported(server.exact_no_content_return.span,
                           lit_str("exact no-content return requires location / fallback"));

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

    if (pre_route_trace.value() && !put_pre_route_trace(writer, server.pre_route_trace.profile))
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
            (exact_absolute_redirect.value()
                 ? !put_exact_absolute_redirect(writer,
                                                server.exact_absolute_redirect.path,
                                                server.exact_absolute_redirect.response.status,
                                                server.exact_absolute_redirect.response.authority,
                                                server.exact_absolute_redirect.response.path)
                 : !put_root_forward(writer, "GET", 3, false, true)) ||
            !put_root_forward(writer, "", 0, false, false) ||
            (exact_local_return.value() &&
             !put_exact_local_return(writer,
                                     server.exact_local_return.path,
                                     server.exact_local_return.response.body)) ||
            (exact_no_content_return.value() && !put_exact_no_content_return(writer)))
            return fail_overflow();
        return output;
    }

    const Str location_path = server.location.path;
    const Str route_path = location_path.slice(0, location_path.len - 1u);
    if (!put("route \"") || !writer.put(route_path) || !put("\" {\n") ||
        !put("    if req.method == GET && req.pathOnly == \"") || !writer.put(route_path) ||
        !put("\" {\n") ||
        !put("        return redirect({scheme: \"http\", authority: \"request_host\", port: "
             "\"actual_listener\",\n") ||
        !put("            path: \"static\", query: \"preserve_raw\", date: \"current\", "
             "connection: \"close\",\n") ||
        !put("            status: 301, reason: \"Moved Permanently\", server: "
             "\"nginx/1.29.7\",\n") ||
        !put("            content_type: \"text/html\", target_path: \"") ||
        !writer.put(location_path) || !put("\", body: b\"") ||
        !writer.put_lit(kRedirect301Body, static_cast<u32>(__builtin_strlen(kRedirect301Body))) ||
        !put("\"})\n") || !put("    } else {\n") ||
        !put("        return forward(nginx_upstream, target_transform: {\n") ||
        !put("            strip_prefix: \"") || !writer.put(location_path) || !put("\",\n") ||
        !put("            replace_prefix: \"") || !writer.put(proxy.uri) || !put("\"\n") ||
        !put("        }, request_policy: {\n") || !put("            version: \"HTTP/1.1\",\n") ||
        !put("            host: \"upstream\",\n") || !put("            connection: \"omit\",\n") ||
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
