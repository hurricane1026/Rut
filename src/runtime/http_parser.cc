#include "rut/runtime/http_parser.h"

#include "core/expected.h"
#include "runtime/simd/simd.h"
#include "rut/runtime/error.h"
#include "rut/runtime/route_canon.h"

namespace rut {

// ============================================================================
// Branch prediction
// ============================================================================

#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

// ============================================================================
// Integer-based helpers
// ============================================================================

static inline u32 load_u32(const u8* p) {
    u32 v;
    __builtin_memcpy(&v, p, 4);
    return v;
}

static inline u64 load_u64(const u8* p) {
    u64 v;
    __builtin_memcpy(&v, p, 8);
    return v;
}

static constexpr u32 u32_lit(char a, char b, char c, char d) {
    return static_cast<u32>(static_cast<u8>(a)) | (static_cast<u32>(static_cast<u8>(b)) << 8) |
           (static_cast<u32>(static_cast<u8>(c)) << 16) |
           (static_cast<u32>(static_cast<u8>(d)) << 24);
}

static constexpr u64 u64_lit(const char* s) {
    u64 v = 0;
    for (int i = 0; i < 8; i++) v |= static_cast<u64>(static_cast<u8>(s[i])) << (i * 8);
    return v;
}

// ============================================================================
// str_ci_eq — u64 batch comparison
// ============================================================================

static inline bool str_ci_eq(const u8* a, const char* b, u32 len) {
    constexpr u64 kMask8 = 0x2020202020202020ULL;
    constexpr u32 kMask4 = 0x20202020U;
    u32 i = 0;
    for (; i + 8 <= len; i += 8) {
        u64 va = load_u64(a + i);
        u64 vb;
        __builtin_memcpy(&vb, b + i, 8);
        if ((va | kMask8) != (vb | kMask8)) return false;
    }
    if (i + 4 <= len) {
        u32 va = load_u32(a + i);
        u32 vb;
        __builtin_memcpy(&vb, b + i, 4);
        if ((va | kMask4) != (vb | kMask4)) return false;
        i += 4;
    }
    for (; i < len; i++) {
        if ((a[i] | 0x20) != (static_cast<u8>(b[i]) | 0x20)) return false;
    }
    return true;
}

// ============================================================================
// parse_uint — branchless digit check
// ============================================================================

// Parse a decimal unsigned integer from `p[0..len)`.
// Returns the parsed value, or error on empty input, non-digit, or overflow.
static inline core::Expected<u32, Error> parse_uint(const u8* p, u32 len) {
    if (UNLIKELY(len == 0))
        return core::make_unexpected(Error::make(EINVAL, Error::Source::HttpParser));
    u32 val = 0;
    for (u32 i = 0; i < len; i++) {
        u32 d = p[i] - '0';
        if (UNLIKELY(d > 9))
            return core::make_unexpected(Error::make(EINVAL, Error::Source::HttpParser));
        // Pre-multiply overflow check: val * 10 + d <= 0xFFFFFFFF
        if (UNLIKELY(val > (0xFFFFFFFFU - d) / 10))
            return core::make_unexpected(Error::make(ERANGE, Error::Source::HttpParser));
        val = val * 10 + d;
    }
    return val;
}

// ============================================================================
// Method parsing — direct pattern match, no scan loop needed.
// Caller passes buf pointing to start of request line.
// Returns method + advances pos past the method + space.
// Returns Unknown on failure without modifying pos.
// ============================================================================

static inline HttpMethod parse_method_direct(const u8* buf, u32 end, u32& pos) {
    if (UNLIKELY(pos + 4 > end)) return HttpMethod::Unknown;

    // Fast path: load first 4 bytes and dispatch
    u32 v4 = load_u32(buf + pos);

    // 3-byte methods: "GET " or "PUT "
    if (v4 == u32_lit('G', 'E', 'T', ' ')) {
        pos += 4;
        return HttpMethod::GET;
    }
    if (v4 == u32_lit('P', 'U', 'T', ' ')) {
        pos += 4;
        return HttpMethod::PUT;
    }

    // 4-byte methods: "POST" + ' ' or "HEAD" + ' '
    if (UNLIKELY(pos + 5 > end)) return HttpMethod::Unknown;
    if (v4 == u32_lit('P', 'O', 'S', 'T') && buf[pos + 4] == ' ') {
        pos += 5;
        return HttpMethod::POST;
    }
    if (v4 == u32_lit('H', 'E', 'A', 'D') && buf[pos + 4] == ' ') {
        pos += 5;
        return HttpMethod::HEAD;
    }

    // 5-byte methods
    if (UNLIKELY(pos + 6 > end)) return HttpMethod::Unknown;
    if (v4 == u32_lit('P', 'A', 'T', 'C') && buf[pos + 4] == 'H' && buf[pos + 5] == ' ') {
        pos += 6;
        return HttpMethod::PATCH;
    }
    if (v4 == u32_lit('T', 'R', 'A', 'C') && buf[pos + 4] == 'E' && buf[pos + 5] == ' ') {
        pos += 6;
        return HttpMethod::TRACE;
    }

    // 6-byte method: "DELETE"
    if (UNLIKELY(pos + 7 > end)) return HttpMethod::Unknown;
    if (v4 == u32_lit('D', 'E', 'L', 'E') && buf[pos + 4] == 'T' && buf[pos + 5] == 'E' &&
        buf[pos + 6] == ' ') {
        pos += 7;
        return HttpMethod::DELETE;
    }

    // 7-byte methods: "OPTIONS" or "CONNECT"
    if (UNLIKELY(pos + 8 > end)) return HttpMethod::Unknown;
    u32 hi = load_u32(buf + pos + 4);
    if (v4 == u32_lit('O', 'P', 'T', 'I') && hi == u32_lit('O', 'N', 'S', ' ')) {
        pos += 8;
        return HttpMethod::OPTIONS;
    }
    if (v4 == u32_lit('C', 'O', 'N', 'N') && hi == u32_lit('E', 'C', 'T', ' ')) {
        pos += 8;
        return HttpMethod::CONNECT;
    }

    return HttpMethod::Unknown;
}

// ============================================================================
// Version constants
// ============================================================================

// Version + CRLF: check "HTTP/1.1\r\n" or "HTTP/1.0\r\n" as u64 + u16
static constexpr u64 kHttp11 = u64_lit("HTTP/1.1");
static constexpr u64 kHttp10 = u64_lit("HTTP/1.0");
static constexpr u16 kCRLF = static_cast<u16>('\r') | (static_cast<u16>('\n') << 8);

// ============================================================================
// Inline fast-path scanners for short data
// These avoid function call overhead for typical short header names/values.
// Fall through to SIMD for long data.
// ============================================================================

// Header name: go straight to SIMD. Even for short names (~10 bytes),
// one vector load + compare + movemask is faster than 10 scalar table lookups.
static inline u32 fast_scan_header_name(const u8* buf, u32 pos, u32 end) {
    return simd::scan_header_name(buf, pos, end);
}

// ============================================================================
// Semantic header matching — first-byte + length dispatch
// Avoids str_ci_eq call for most headers.
// ============================================================================

// Connection: comma-separated token parsing (handles "close, upgrade" etc.)
static inline void match_connection(const u8* val, u32 vlen, ParsedRequest* req) {
    u32 i = 0;
    while (i < vlen) {
        // Skip leading OWS and commas
        while (i < vlen && (val[i] == ' ' || val[i] == '\t' || val[i] == ',')) i++;
        if (i >= vlen) break;

        // Find end of token
        u32 tok_start = i;
        while (i < vlen && val[i] != ',' && val[i] != ' ' && val[i] != '\t') i++;
        u32 tok_len = i - tok_start;

        if (tok_len == 5 && str_ci_eq(val + tok_start, "close", 5)) {
            req->keep_alive = false;
            req->connection_close = true;  // sticky across duplicate Connection fields
            req->upgrade = false;          // close is contradictory with upgrade
            return;                        // close overrides keep-alive (RFC 7230)
        } else if (tok_len == 10 && str_ci_eq(val + tok_start, "keep-alive", 10)) {
            req->keep_alive = true;
        } else if (tok_len == 7 && str_ci_eq(val + tok_start, "upgrade", 7)) {
            // Suppress if a close token was seen in any Connection field — a
            // "close … upgrade" request (even split across fields) is not an upgrade.
            if (!req->connection_close) req->upgrade = true;
        }
    }
}

static inline bool is_transfer_coding_token_char(u8 c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '!' ||
           c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' || c == '+' ||
           c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

// Classify one complete Transfer-Encoding field.  Parameters and duplicate
// fields are deliberately unsupported: local-response connection reuse needs
// one exact, unambiguous request boundary.  The legacy `chunked` bit is parsed
// separately below so this metadata addition does not alter proxy behaviour.
static inline RequestTransferEncoding classify_transfer_encoding(const u8* val, u32 vlen) {
    if (vlen == 0) return RequestTransferEncoding::Unsupported;
    bool saw_token = false;
    bool saw_chunked = false;
    u32 i = 0;
    for (;;) {
        while (i < vlen && (val[i] == ' ' || val[i] == '\t')) i++;
        if (i == vlen || val[i] == ',') return RequestTransferEncoding::Unsupported;

        const u32 start = i;
        while (i < vlen && is_transfer_coding_token_char(val[i])) i++;
        if (i == start) return RequestTransferEncoding::Unsupported;
        saw_token = true;
        const bool is_chunked = i - start == 7 && str_ci_eq(val + start, "chunked", 7);
        if (is_chunked) {
            if (saw_chunked) return RequestTransferEncoding::Unsupported;
            saw_chunked = true;
        }

        while (i < vlen && (val[i] == ' ' || val[i] == '\t')) i++;
        if (i == vlen)
            return saw_token && saw_chunked ? RequestTransferEncoding::FinalChunked
                                            : RequestTransferEncoding::Unsupported;
        if (val[i] != ',') return RequestTransferEncoding::Unsupported;
        // `chunked` must be the final coding, and a comma must introduce a
        // non-empty next token.
        if (is_chunked) return RequestTransferEncoding::Unsupported;
        i++;
    }
}

// Check and apply semantic headers inline.
// Returns quickly for non-semantic headers via first-byte + length dispatch.
static inline ParseStatus apply_semantic_header(
    const u8* name, u32 name_len, const u8* val, u32 vlen, ParsedRequest* req) {
    // Dispatch on (first_byte | 0x20) and length for fast rejection
    u8 first = name[0] | 0x20;

    if (first == 'c') {
        if (name_len == 14 && str_ci_eq(name + 1, "ontent-length", 13)) {
            auto cl = parse_uint(val, vlen);
            if (UNLIKELY(!cl)) return ParseStatus::Error;
            if (UNLIKELY(req->has_content_length)) {
                // Duplicate Content-Length with different value → reject
                if (req->content_length != cl.value()) return ParseStatus::Error;
                return ParseStatus::Complete;
            }
            req->content_length = cl.value();
            req->has_content_length = true;
            return ParseStatus::Complete;
        }
        if (name_len == 10 && str_ci_eq(name + 1, "onnection", 9)) {
            match_connection(val, vlen, req);
            return ParseStatus::Complete;
        }
    } else if (first == 't') {
        if (name_len == 17 && str_ci_eq(name + 1, "ransfer-encoding", 16)) {
            if (req->transfer_encoding != RequestTransferEncoding::Unparsed) {
                req->transfer_encoding = RequestTransferEncoding::Unsupported;
            } else {
                req->transfer_encoding = classify_transfer_encoding(val, vlen);
            }
            // Parse as comma-separated token list, match full "chunked" token
            u32 ti = 0;
            while (ti < vlen) {
                while (ti < vlen && (val[ti] == ' ' || val[ti] == '\t' || val[ti] == ',')) ti++;
                if (ti >= vlen) break;
                u32 tok_start = ti;
                while (ti < vlen && val[ti] != ',' && val[ti] != ' ' && val[ti] != '\t') ti++;
                u32 tok_len = ti - tok_start;
                if (tok_len == 7 && str_ci_eq(val + tok_start, "chunked", 7)) {
                    req->chunked = true;
                    break;
                }
            }
            return ParseStatus::Complete;
        }
    } else if (first == 'u') {
        if (name_len == 7 && str_ci_eq(name + 1, "pgrade", 6)) {
            // Walk the comma-separated token list. has_upgrade_header = any non-OWS token
            // (an empty/whitespace-only Upgrade requests no protocol and must not gate a
            // tunnel). upgrade_is_websocket = a "websocket" token ANYWHERE in the list — a
            // client may offer e.g. "Upgrade: h2c, websocket", and terminate must still see
            // the WebSocket offer. A token may carry a "/version" suffix.
            u32 i = 0;
            while (i < vlen) {
                while (i < vlen && (val[i] == ' ' || val[i] == '\t' || val[i] == ',')) i++;
                if (i >= vlen) break;
                u32 ts = i;
                while (i < vlen && val[i] != ',' && val[i] != ' ' && val[i] != '\t') i++;
                const u32 tlen = i - ts;
                req->has_upgrade_header = true;
                if (tlen >= 9 && str_ci_eq(val + ts, "websocket", 9) &&
                    (tlen == 9 || val[ts + 9] == '/')) {
                    req->upgrade_is_websocket = true;
                }
            }
            return ParseStatus::Complete;
        }
    }
    return ParseStatus::Complete;  // not a semantic header — no-op
}

// ============================================================================
// Core parser — single-pass, no find_header_end pre-scan
// ============================================================================

// Single-pass parser: parses method, URI, version, and headers directly
// from the buffer. Returns Incomplete if the buffer does not contain
// enough data. On ambiguous cases (could be incomplete or malformed),
// falls back to find_header_end() to disambiguate.

ParseStatus HttpParser::parse(const u8* buf, u32 len, ParsedRequest* req) {
    header_end = 0;  // Clear on entry so stale values are never exposed on Incomplete/Error.
    req->reset();

    // Quick check: need at least 4 bytes to try method matching.
    if (UNLIKELY(len < 4)) {
        return ParseStatus::Incomplete;
    }

    // Single-pass: parse directly without find_header_end pre-scan.
    // We check bounds at each step and return Incomplete if needed.
    u32 pos = 0;
    // Declare loop variables here so goto doesn't jump over them.
    u32 hdr_count = 0;
    Header* headers = req->headers;

    // --- Request line: METHOD SP URI SP HTTP/1.x CRLF ---

    // Method — direct pattern match
    req->method = parse_method_direct(buf, len, pos);
    if (UNLIKELY(req->method == HttpMethod::Unknown)) goto maybe_incomplete;

    // URI — SIMD scan for space within full buffer. The same pass also
    // reports canon_end (first '?' or '#' before the space, or the space
    // position) so we can populate path_canon without a second scan.
    //
    // path_canon is only populated for origin-form request-targets
    // (i.e. URIs starting with '/'). Asterisk-form ("*", OPTIONS) and
    // authority-form ("host:port", CONNECT) intentionally leave
    // path_canon as {nullptr, 0}. Both RouteConfig::match (which
    // canonicalizes from raw input) and RouteConfig::match_canonical
    // (the parser-fed fast path) refuse to route non-origin-form
    // targets — match() rejects on `path[0] != '/'` at entry, and
    // match_canonical's null-ptr guard returns nullptr for the
    // sentinel canon. The raw `path` field stays populated so other
    // request-handling code (logging, OPTIONS responder, CONNECT
    // tunnel setup) can still see the original target.
    {
        u32 uri_start = pos;
        u32 canon_end = 0;
        u32 uri_end = simd::scan_uri(buf, pos, len, &canon_end);
        if (uri_end == static_cast<u32>(-1)) return ParseStatus::Error;
        if (UNLIKELY(uri_end >= len)) goto maybe_incomplete;
        if (UNLIKELY(uri_end == uri_start)) return ParseStatus::Error;
        req->path = {reinterpret_cast<const char*>(buf + uri_start), uri_end - uri_start};
        if (buf[uri_start] == '/') {
            req->path_canon = finalize_path_canonical(
                reinterpret_cast<const char*>(buf + uri_start), canon_end - uri_start);
        }
        pos = uri_end + 1;
    }

    // Version + CRLF
    if (UNLIKELY(pos + 10 > len)) goto maybe_incomplete;
    {
        u64 ver = load_u64(buf + pos);
        u16 crlf_val;
        __builtin_memcpy(&crlf_val, buf + pos + 8, 2);
        if (UNLIKELY(crlf_val != kCRLF)) return ParseStatus::Error;
        if (LIKELY(ver == kHttp11)) {
            req->version = HttpVersion::Http11;
            req->keep_alive = true;
        } else if (ver == kHttp10) {
            req->version = HttpVersion::Http10;
            req->keep_alive = false;
        } else {
            return ParseStatus::Error;
        }
    }
    pos += 10;

    // --- Headers (single-pass) ---
    for (;;) {
        // Need at least 2 bytes to check for end-of-headers or start of a header
        if (UNLIKELY(pos + 2 > len)) {
            return ParseStatus::Incomplete;
        }

        // End of headers?
        if (buf[pos] == '\r') {
            if (LIKELY(buf[pos + 1] == '\n')) {
                pos += 2;
                break;
            }
            return ParseStatus::Error;
        }

        // Header name — inline fast path
        u32 name_start = pos;
        u32 colon_pos = fast_scan_header_name(buf, pos, len);
        if (UNLIKELY(colon_pos == static_cast<u32>(-1))) goto maybe_incomplete;
        if (UNLIKELY(colon_pos == name_start)) return ParseStatus::Error;
        u32 name_len = colon_pos - name_start;
        pos = colon_pos + 1;
        const u32 raw_value_start = pos;

        // Skip OWS — hot path: single space after colon
        if (UNLIKELY(pos >= len)) goto maybe_incomplete;
        if (LIKELY(buf[pos] == ' ')) {
            pos++;
        }
        while (UNLIKELY(pos < len && (buf[pos] == ' ' || buf[pos] == '\t'))) pos++;
        if (UNLIKELY(pos >= len)) goto maybe_incomplete;

        {
            // Header value — SIMD scan for \r
            u32 value_start = pos;
            u32 cr_pos = simd::scan_header_value(buf, pos, len);
            if (cr_pos == static_cast<u32>(-1)) return ParseStatus::Error;
            if (UNLIKELY(cr_pos >= len || cr_pos + 1 >= len)) goto maybe_incomplete;
            if (UNLIKELY(buf[cr_pos + 1] != '\n')) return ParseStatus::Error;
            pos = cr_pos;

            // Trim trailing OWS
            u32 value_end = pos;
            if (UNLIKELY(value_end > value_start && buf[value_end - 1] <= ' ')) {
                while (value_end > value_start &&
                       (buf[value_end - 1] == ' ' || buf[value_end - 1] == '\t')) {
                    value_end--;
                }
            }

            // Store header
            if (UNLIKELY(hdr_count >= kMaxHeaders)) return ParseStatus::Error;
            headers[hdr_count].name = {reinterpret_cast<const char*>(buf + name_start), name_len};
            headers[hdr_count].value = {reinterpret_cast<const char*>(buf + value_start),
                                        value_end - value_start};
            headers[hdr_count].raw_value = {reinterpret_cast<const char*>(buf + raw_value_start),
                                            cr_pos - raw_value_start};
            hdr_count++;

            // Semantic header detection
            ParseStatus sem = apply_semantic_header(
                buf + name_start, name_len, buf + value_start, value_end - value_start, req);
            if (UNLIKELY(sem == ParseStatus::Error)) return ParseStatus::Error;
        }

        pos += 2;  // skip \r\n
    }

    req->header_count = hdr_count;
    header_end = pos;

    if (req->transfer_encoding == RequestTransferEncoding::Unparsed)
        req->transfer_encoding = RequestTransferEncoding::None;

    // Reject requests with both Content-Length and Transfer-Encoding: chunked
    // to prevent request-smuggling attacks (RFC 7230 §3.3.3).
    if (UNLIKELY(req->chunked && req->has_content_length)) return ParseStatus::Error;

    return ParseStatus::Complete;

maybe_incomplete:
    // We hit a condition that could mean "need more data" or "malformed".
    // Disambiguate: if \r\n\r\n exists in the buffer, the request is
    // complete but malformed → Error. Otherwise → Incomplete.
    // This check is cold-path only — never called for valid requests.
    if (simd::find_header_end(buf, len, 0) > 0) {
        return ParseStatus::Error;
    }
    return ParseStatus::Incomplete;
}

// ============================================================================
// Response parser — semantic header matching
// ============================================================================

// Connection header parsing for responses (sets both keep_alive and connection_close).
static inline void match_connection_response(const u8* val, u32 vlen, ParsedResponse* resp) {
    u32 i = 0;
    while (i < vlen) {
        // Skip leading OWS and commas
        while (i < vlen && (val[i] == ' ' || val[i] == '\t' || val[i] == ',')) i++;
        if (i >= vlen) break;

        // Find end of token
        u32 tok_start = i;
        while (i < vlen && val[i] != ',' && val[i] != ' ' && val[i] != '\t') i++;
        u32 tok_len = i - tok_start;

        if (tok_len == 5 && str_ci_eq(val + tok_start, "close", 5)) {
            resp->connection_close = true;
            resp->keep_alive = false;
            return;  // close is sticky (RFC 7230)
        } else if (tok_len == 10 && str_ci_eq(val + tok_start, "keep-alive", 10)) {
            resp->keep_alive = true;
        }
    }
}

// Check and apply semantic headers for responses.
static inline ParseStatus apply_semantic_header_response(
    const u8* name, u32 name_len, const u8* val, u32 vlen, ParsedResponse* resp) {
    u8 first = name[0] | 0x20;

    if (first == 'c') {
        if (name_len == 14 && str_ci_eq(name + 1, "ontent-length", 13)) {
            auto cl = parse_uint(val, vlen);
            if (UNLIKELY(!cl)) return ParseStatus::Error;
            if (UNLIKELY(resp->has_content_length)) {
                if (resp->content_length != cl.value()) return ParseStatus::Error;
                return ParseStatus::Complete;
            }
            resp->content_length = cl.value();
            resp->has_content_length = true;
            return ParseStatus::Complete;
        }
        if (name_len == 10 && str_ci_eq(name + 1, "onnection", 9)) {
            match_connection_response(val, vlen, resp);
            return ParseStatus::Complete;
        }
    } else if (first == 't') {
        if (name_len == 17 && str_ci_eq(name + 1, "ransfer-encoding", 16)) {
            u32 ti = 0;
            while (ti < vlen) {
                while (ti < vlen && (val[ti] == ' ' || val[ti] == '\t' || val[ti] == ',')) ti++;
                if (ti >= vlen) break;
                u32 tok_start = ti;
                while (ti < vlen && val[ti] != ',' && val[ti] != ' ' && val[ti] != '\t') ti++;
                u32 tok_len = ti - tok_start;
                if (tok_len == 7 && str_ci_eq(val + tok_start, "chunked", 7)) {
                    resp->chunked = true;
                    break;
                }
            }
            return ParseStatus::Complete;
        }
    }
    return ParseStatus::Complete;
}

// ============================================================================
// Response parser — single-pass
// ============================================================================

ParseStatus HttpResponseParser::parse(const u8* buf, u32 len, ParsedResponse* resp) {
    header_end = 0;

    // Minimum: "HTTP/1.x NNN\r\n\r\n" = 17 bytes for an empty-header response.
    // But we need at least 12 to even begin parsing the status line.
    if (UNLIKELY(len < 12)) {
        return ParseStatus::Incomplete;
    }

    resp->reset();
    u32 pos = 0;
    u32 hdr_count = 0;
    Header* headers = resp->headers;

    // --- Status line: HTTP/1.x SP NNN SP reason CRLF ---

    // Check "HTTP/1." prefix (7 bytes) via u64 load
    if (UNLIKELY(pos + 10 > len)) return ParseStatus::Incomplete;
    {
        u64 ver_prefix = load_u64(buf + pos);
        // Mask off the version digit (byte 7) to check "HTTP/1."
        constexpr u64 kHttpSlash1Dot = u64_lit("HTTP/1.0") & 0x00FFFFFFFFFFFFFFULL;
        if (UNLIKELY((ver_prefix & 0x00FFFFFFFFFFFFFFULL) != kHttpSlash1Dot))
            return ParseStatus::Error;

        u8 ver_digit = buf[pos + 7];
        if (LIKELY(ver_digit == '1')) {
            resp->version = HttpVersion::Http11;
            resp->keep_alive = true;  // HTTP/1.1 default
        } else if (ver_digit == '0') {
            resp->version = HttpVersion::Http10;
            resp->keep_alive = false;  // HTTP/1.0 default
        } else {
            return ParseStatus::Error;
        }
    }
    pos += 8;  // past "HTTP/1.x"

    // Expect SP
    if (UNLIKELY(buf[pos] != ' ')) return ParseStatus::Error;
    pos++;

    // Parse 3-digit status code
    if (UNLIKELY(pos + 3 > len)) return ParseStatus::Incomplete;
    {
        u32 d0 = buf[pos] - '0';
        u32 d1 = buf[pos + 1] - '0';
        u32 d2 = buf[pos + 2] - '0';
        if (UNLIKELY(d0 > 9 || d1 > 9 || d2 > 9)) return ParseStatus::Error;
        u16 code = static_cast<u16>(d0 * 100 + d1 * 10 + d2);
        if (UNLIKELY(code < 100 || code > 599)) return ParseStatus::Error;
        resp->status_code = code;
    }
    pos += 3;

    // Require the RFC status-line separator, then retain the exact reason phrase.
    if (UNLIKELY(pos >= len)) return ParseStatus::Incomplete;
    if (buf[pos] != ' ' && buf[pos] != '\r') return ParseStatus::Error;
    {
        const u32 reason_start = (buf[pos] == ' ') ? pos + 1 : pos;
        u32 scan = pos;
        while (scan < len && buf[scan] != '\r') scan++;
        if (UNLIKELY(scan + 1 >= len)) return ParseStatus::Incomplete;
        if (UNLIKELY(buf[scan + 1] != '\n')) return ParseStatus::Error;
        resp->reason = {reinterpret_cast<const char*>(buf + reason_start), scan - reason_start};
        pos = scan + 2;  // past \r\n
    }

    // --- Headers (single-pass, same as request parser) ---
    for (;;) {
        if (UNLIKELY(pos + 2 > len)) {
            return ParseStatus::Incomplete;
        }

        // End of headers?
        if (buf[pos] == '\r') {
            if (LIKELY(buf[pos + 1] == '\n')) {
                pos += 2;
                break;
            }
            return ParseStatus::Error;
        }

        // Header name
        u32 name_start = pos;
        u32 colon_pos = fast_scan_header_name(buf, pos, len);
        if (UNLIKELY(colon_pos == static_cast<u32>(-1))) goto maybe_incomplete;
        if (UNLIKELY(colon_pos == name_start)) return ParseStatus::Error;
        u32 name_len = colon_pos - name_start;
        pos = colon_pos + 1;
        const u32 raw_value_start = pos;

        // Skip OWS
        if (UNLIKELY(pos >= len)) goto maybe_incomplete;
        if (LIKELY(buf[pos] == ' ')) {
            pos++;
        }
        while (UNLIKELY(pos < len && (buf[pos] == ' ' || buf[pos] == '\t'))) pos++;
        if (UNLIKELY(pos >= len)) goto maybe_incomplete;

        {
            // Header value — SIMD scan for \r
            u32 value_start = pos;
            u32 cr_pos = simd::scan_header_value(buf, pos, len);
            if (cr_pos == static_cast<u32>(-1)) return ParseStatus::Error;
            if (UNLIKELY(cr_pos >= len || cr_pos + 1 >= len)) goto maybe_incomplete;
            if (UNLIKELY(buf[cr_pos + 1] != '\n')) return ParseStatus::Error;
            pos = cr_pos;

            // Trim trailing OWS
            u32 value_end = pos;
            if (UNLIKELY(value_end > value_start && buf[value_end - 1] <= ' ')) {
                while (value_end > value_start &&
                       (buf[value_end - 1] == ' ' || buf[value_end - 1] == '\t')) {
                    value_end--;
                }
            }

            // Store header (skip storage if at capacity — proxy only needs
            // semantic headers, so exceeding kMaxHeaders is not an error).
            if (LIKELY(hdr_count < kMaxHeaders)) {
                headers[hdr_count].name = {reinterpret_cast<const char*>(buf + name_start),
                                           name_len};
                headers[hdr_count].value = {reinterpret_cast<const char*>(buf + value_start),
                                            value_end - value_start};
                headers[hdr_count].raw_value = {
                    reinterpret_cast<const char*>(buf + raw_value_start), cr_pos - raw_value_start};
                hdr_count++;
            } else {
                // Beyond capacity: keep parsing (semantic headers still apply
                // below) but record that headers[] is now truncated.
                resp->headers_truncated = true;
            }

            // Semantic header detection (always runs, even if header not stored)
            ParseStatus sem = apply_semantic_header_response(
                buf + name_start, name_len, buf + value_start, value_end - value_start, resp);
            if (UNLIKELY(sem == ParseStatus::Error)) return ParseStatus::Error;
            if (name_len == 14 && str_ci_eq(buf + name_start + 1, "ontent-length", 13)) {
                if (resp->content_length_count != 255) resp->content_length_count++;
            }
        }

        pos += 2;  // skip \r\n
    }

    resp->header_count = hdr_count;
    header_end = pos;
    return ParseStatus::Complete;

maybe_incomplete:
    if (simd::find_header_end(buf, len, 0) > 0) {
        return ParseStatus::Error;
    }
    return ParseStatus::Incomplete;
}

// ============================================================================
// Utility
// ============================================================================

Str http_method_str(HttpMethod m) {
    switch (m) {
        case HttpMethod::GET:
            return {"GET", 3};
        case HttpMethod::POST:
            return {"POST", 4};
        case HttpMethod::PUT:
            return {"PUT", 3};
        case HttpMethod::DELETE:
            return {"DELETE", 6};
        case HttpMethod::PATCH:
            return {"PATCH", 5};
        case HttpMethod::HEAD:
            return {"HEAD", 4};
        case HttpMethod::OPTIONS:
            return {"OPTIONS", 7};
        case HttpMethod::CONNECT:
            return {"CONNECT", 7};
        case HttpMethod::TRACE:
            return {"TRACE", 5};
        case HttpMethod::Unknown:
            return {"UNKNOWN", 7};
    }
    return {"UNKNOWN", 7};
}

}  // namespace rut
