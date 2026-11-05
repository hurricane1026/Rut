#include "rut/runtime/ws_extensions.h"

#include "rut/common/http_header_validation.h"
#include "rut/common/types.h"
#include "rut/runtime/http_parser.h"

#include <string.h>

namespace rut {
namespace {
struct Value {
    bool present = false;
    u32 number = 0;
    bool decimal = true;
    u32 digits = 0;
    bool leading_zero = false;
};
struct Cursor {
    Str value;
    u32 offset = 0;
    void whitespace() {
        while (offset < value.len && (value.ptr[offset] == ' ' || value.ptr[offset] == '\t'))
            ++offset;
    }
    Str token() {
        const u32 kStart = offset;
        while (offset < value.len && is_http_tchar(static_cast<u8>(value.ptr[offset]))) ++offset;
        return {value.ptr + kStart, offset - kStart};
    }
    bool parameter_value(Value& result) {
        result.present = true;
        if (offset >= value.len) return false;
        const bool kQuoted = value.ptr[offset] == '"';
        if (kQuoted) ++offset;
        bool closed = !kQuoted;
        while (offset < value.len) {
            u8 byte = static_cast<u8>(value.ptr[offset]);
            if (kQuoted && byte == '"') {
                ++offset;
                closed = true;
                break;
            }
            if (kQuoted && byte == '\\') {
                if (++offset == value.len) return false;
                byte = static_cast<u8>(value.ptr[offset]);
            } else if (!kQuoted && !is_http_tchar(byte)) {
                break;
            }
            // RFC 6455 requires the unescaped quoted value to be a token too.
            if (!is_http_tchar(byte)) return false;
            if (result.digits == 0) result.leading_zero = byte == '0';
            if (byte < '0' || byte > '9' || result.digits >= 2)
                result.decimal = false;
            else
                result.number = result.number * 10 + byte - '0';
            ++result.digits;
            ++offset;
        }
        return closed && result.digits != 0;
    }
};

bool window(const Value& value) {
    return value.present && value.decimal && !value.leading_zero && value.number >= 8 &&
           value.number <= 15;
}

bool parse(const Header* headers, u32 count, bool response, WsDeflateAgreement* agreement) {
    if (!agreement || count > kMaxHeaders || (!headers && count)) return false;
    *agreement = {};
    WsDeflateAgreement selected{};
    u32 selections = 0;
    for (u32 i = 0; i < count; ++i) {
        const auto& header = headers[i];
        if (!header.name.ptr ||
            !http_header_name_eq_ci(
                header.name.ptr, header.name.len, "sec-websocket-extensions", 24))
            continue;
        if (!header.value.ptr && header.value.len) return false;
        Cursor cursor{header.value};
        cursor.whitespace();
        while (cursor.offset < cursor.value.len) {
            const Str kName = cursor.token();
            if (kName.len == 0) return false;
            const bool kDeflate = kName.eq(lit_str("permessage-deflate"));
            bool supported = kDeflate;
            WsDeflateAgreement candidate{};
            u32 seen = 0;
            cursor.whitespace();
            while (cursor.offset < cursor.value.len && cursor.value.ptr[cursor.offset] == ';') {
                ++cursor.offset;
                cursor.whitespace();
                const Str kParameter = cursor.token();
                if (!kParameter.len) return false;
                cursor.whitespace();
                Value value{};
                if (cursor.offset < cursor.value.len && cursor.value.ptr[cursor.offset] == '=') {
                    ++cursor.offset;
                    cursor.whitespace();
                    if (!cursor.parameter_value(value)) return false;
                    cursor.whitespace();
                }
                u32 bit = 0;
                if (kParameter.eq(lit_str("server_no_context_takeover"))) {
                    bit = 1;
                    candidate.server_no_context_takeover = true;
                    supported &= !value.present;
                } else if (kParameter.eq(lit_str("client_no_context_takeover"))) {
                    bit = 2;
                    candidate.client_no_context_takeover = true;
                    supported &= !value.present;
                } else if (kParameter.eq(lit_str("server_max_window_bits"))) {
                    bit = 4;
                    candidate.server_window_present = true;
                    supported &= window(value);
                    if (window(value)) candidate.server_window = static_cast<u8>(value.number);
                } else if (kParameter.eq(lit_str("client_max_window_bits"))) {
                    bit = 8;
                    candidate.client_window_present = true;
                    supported &= (!response && !value.present) || window(value);
                    if (window(value)) candidate.client_window = static_cast<u8>(value.number);
                } else {
                    supported = false;
                }
                if (seen & bit) supported = false;
                seen |= bit;
            }
            if (response && (!supported || ++selections != 1)) return false;
            if (supported && !selected.enabled) {
                candidate.enabled = true;
                if (!response) {
                    // Our encoder resets per message. Honor the client's optional
                    // no-context hint; otherwise permit its dictionary takeover.
                    candidate.server_no_context_takeover = true;
                }
                selected = candidate;
            }
            if (cursor.offset == cursor.value.len) break;
            if (cursor.value.ptr[cursor.offset] != ',') return false;
            ++cursor.offset;
            cursor.whitespace();
            if (cursor.offset == cursor.value.len) return false;
        }
    }
    *agreement = selected;
    return true;
}
}  // namespace

bool ws_select_deflate_offer(const Header* headers, u32 count, WsDeflateAgreement* agreement) {
    return parse(headers, count, false, agreement);
}
bool ws_accept_deflate_response(const Header* headers, u32 count, WsDeflateAgreement* agreement) {
    return parse(headers, count, true, agreement);
}

u32 ws_format_deflate_agreement(const WsDeflateAgreement& agreement, char* output, u32 capacity) {
    if (!agreement.enabled || !output || agreement.server_window < 8 ||
        agreement.server_window > 15 || agreement.client_window < 8 || agreement.client_window > 15)
        return 0;
    u32 written = 0;
    auto append = [&](Str text) {
        if (text.len > capacity - written) return false;
        for (u32 i = 0; i < text.len; ++i) output[written++] = text.ptr[i];
        return true;
    };
    auto number = [&](u8 value) {
        const char kDigits[] = {static_cast<char>('0' + value / 10),
                                static_cast<char>('0' + value % 10)};
        return append(value >= 10 ? Str{kDigits, 2} : Str{kDigits + 1, 1});
    };
    if (!append(lit_str("permessage-deflate"))) return 0;
    if (agreement.server_no_context_takeover && !append(lit_str("; server_no_context_takeover")))
        return 0;
    if (agreement.client_no_context_takeover && !append(lit_str("; client_no_context_takeover")))
        return 0;
    if (agreement.server_window_present &&
        (!append(lit_str("; server_max_window_bits=")) || !number(agreement.server_window)))
        return 0;
    if (agreement.client_window_present &&
        (!append(lit_str("; client_max_window_bits=")) || !number(agreement.client_window)))
        return 0;
    return written;
}

namespace {
u32 line_end(const u8* buffer, u32 start, u32 header_len) {
    for (u32 i = start; i + 1 < header_len; ++i)
        if (buffer[i] == '\r' && buffer[i + 1] == '\n') return i;
    return header_len;
}
bool field_is(const u8* buffer, u32 start, u32 end, Str name, u32* colon = nullptr) {
    u32 pos = start;
    while (pos < end && buffer[pos] != ':') ++pos;
    if (colon) *colon = pos;
    return pos < end &&
           http_header_name_eq_ci(
               reinterpret_cast<const char*>(buffer + start), pos - start, name.ptr, name.len);
}
}  // namespace

u32 ws_rewrite_extensions(
    u8* buffer, u32 header_len, u32 total_len, u32 capacity, Str extension_value) {
    if (!buffer || header_len < 4 || total_len < header_len || total_len > capacity ||
        (!extension_value.ptr && extension_value.len) ||
        memcmp(buffer + header_len - 4, "\r\n\r\n", 4) != 0)
        return 0;
    for (u32 i = 0; i < extension_value.len; ++i) {
        const u8 kByte = static_cast<u8>(extension_value.ptr[i]);
        if (kByte < 0x20 || kByte >= 0x7f) return 0;
    }
    const u32 kFirstEnd = line_end(buffer, 0, header_len);
    if (kFirstEnd == header_len || kFirstEnd == 0) return 0;
    u32 removed = 0;
    for (u32 pos = kFirstEnd + 2; pos < header_len - 2;) {
        const u32 kEnd = line_end(buffer, pos, header_len);
        if (kEnd == header_len || kEnd == pos) return 0;
        if (field_is(buffer, pos, kEnd, lit_str("sec-websocket-extensions")))
            removed += kEnd + 2 - pos;
        pos = kEnd + 2;
    }
    constexpr Str kPrefix = lit_str("Sec-WebSocket-Extensions: ");
    const u64 kNewHeader = static_cast<u64>(header_len) - removed +
                           (extension_value.len ? kPrefix.len + extension_value.len + 2ull : 0);
    if (kNewHeader + total_len - header_len > capacity) return 0;
    u32 written = kFirstEnd + 2;
    for (u32 pos = kFirstEnd + 2; pos < header_len - 2;) {
        const u32 kEnd = line_end(buffer, pos, header_len);
        if (!field_is(buffer, pos, kEnd, lit_str("sec-websocket-extensions"))) {
            memmove(buffer + written, buffer + pos, kEnd + 2 - pos);
            written += kEnd + 2 - pos;
        }
        pos = kEnd + 2;
    }
    // Shift the tail after scanning the old header; shrinking must not destroy
    // fields still being read, and growing must not overwrite early frame bytes.
    memmove(buffer + kNewHeader, buffer + header_len, total_len - header_len);
    if (extension_value.len) {
        memcpy(buffer + written, kPrefix.ptr, kPrefix.len);
        written += kPrefix.len;
        memcpy(buffer + written, extension_value.ptr, extension_value.len);
        written += extension_value.len;
        memcpy(buffer + written, "\r\n", 2);
        written += 2;
    }
    memcpy(buffer + written, "\r\n", 2);
    return static_cast<u32>(kNewHeader);
}

Str ws_selected_subprotocol(const u8* header, u32 header_len) {
    if (!header || header_len < 4) return {};
    const u32 kFirstEnd = line_end(header, 0, header_len);
    if (kFirstEnd == header_len) return {};
    for (u32 pos = kFirstEnd + 2; pos < header_len - 2;) {
        const u32 kEnd = line_end(header, pos, header_len);
        if (kEnd == header_len || kEnd == pos) return {};
        u32 colon = 0;
        if (field_is(header, pos, kEnd, lit_str("sec-websocket-protocol"), &colon)) {
            u32 start = colon + 1;
            u32 end = kEnd;
            while (start < end && (header[start] == ' ' || header[start] == '\t')) ++start;
            while (end > start && (header[end - 1] == ' ' || header[end - 1] == '\t')) --end;
            return {reinterpret_cast<const char*>(header + start), end - start};
        }
        pos = kEnd + 2;
    }
    return {};
}
}  // namespace rut
