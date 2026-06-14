/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "rut/common/types.h"

namespace rut {

// Outcome of validating a single response-header pair. Callers map
// these to their own error domains (FrontendError for the compiler,
// a boolean rejection for the runtime's public API).
enum class HttpHeaderValidation : u8 {
    Ok,
    EmptyKey,          // key is zero bytes
    InvalidKeyChar,    // byte not in the HTTP tchar grammar
    InvalidValueChar,  // byte is a control char (< 0x20, except tab) or 0x7f
    ReservedKey,       // key is Content-Length / Transfer-Encoding / Connection
};

// HTTP/1.1 "token" grammar (RFC 7230 §3.2.6). Field names MUST be
// tokens, so we reject anything outside this set — including spaces,
// separators, and control characters. Keeps us safe from header
// injection and from accidentally accepting a key that the formatter
// would serialize as ambiguous (e.g. "Content-Type " with a trailing
// space won't match the default-suppression check).
inline bool is_http_tchar(u8 c) {
    if (c >= '0' && c <= '9') return true;
    if (c >= 'A' && c <= 'Z') return true;
    if (c >= 'a' && c <= 'z') return true;
    switch (c) {
        case '!':
        case '#':
        case '$':
        case '%':
        case '&':
        case '\'':
        case '*':
        case '+':
        case '-':
        case '.':
        case '^':
        case '_':
        case '`':
        case '|':
        case '~':
            return true;
        default:
            return false;
    }
}

// Case-insensitive ASCII compare — returns true iff the two byte
// ranges are equal under ASCII case folding. Header names are
// case-insensitive per HTTP, so duplicate-key checks and reserved-key
// checks use this.
inline bool http_header_name_eq_ci(const char* a, u32 a_len, const char* b, u32 b_len) {
    if (a_len != b_len) return false;
    for (u32 i = 0; i < a_len; i++) {
        u8 ca = static_cast<u8>(a[i]);
        u8 cb = static_cast<u8>(b[i]);
        if (ca >= 'A' && ca <= 'Z') ca = static_cast<u8>(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z') cb = static_cast<u8>(cb + ('a' - 'A'));
        if (ca != cb) return false;
    }
    return true;
}

// Names we don't let users set: they'd conflict with runtime-managed
// framing / hop-by-hop handling. Content-Length is recomputed from
// the body we actually send; Transfer-Encoding would contradict the
// fixed-length framing; Connection is appended by the formatter
// based on the keep-alive decision. Accepting any of these would
// open the door to request-smuggling-style client/proxy confusion.
inline bool is_reserved_response_header_name(const char* name, u32 len) {
    return http_header_name_eq_ci(name, len, "Content-Length", 14) ||
           http_header_name_eq_ci(name, len, "Transfer-Encoding", 17) ||
           http_header_name_eq_ci(name, len, "Connection", 10);
}

// Validate a single (key, value) header pair for use as a
// response-header entry. Returns Ok if acceptable, or a categorical
// error code the caller maps to its own diagnostic.
inline HttpHeaderValidation validate_response_header(const char* key,
                                                     u32 key_len,
                                                     const char* value,
                                                     u32 value_len) {
    if (key_len == 0) return HttpHeaderValidation::EmptyKey;
    for (u32 i = 0; i < key_len; i++) {
        if (!is_http_tchar(static_cast<u8>(key[i]))) {
            return HttpHeaderValidation::InvalidKeyChar;
        }
    }
    if (is_reserved_response_header_name(key, key_len)) {
        return HttpHeaderValidation::ReservedKey;
    }
    for (u32 i = 0; i < value_len; i++) {
        const u8 c = static_cast<u8>(value[i]);
        // Horizontal tab is permitted in values (RFC 7230 field-vchar
        // actually allows obs-fold historically, but modern parsers
        // treat bare tabs OK; CR/LF/NUL and other C0 controls are
        // strict-reject for wire safety).
        if (c == '\t') continue;
        if (c < 0x20 || c == 0x7f) {
            return HttpHeaderValidation::InvalidValueChar;
        }
    }
    return HttpHeaderValidation::Ok;
}

}  // namespace rut
