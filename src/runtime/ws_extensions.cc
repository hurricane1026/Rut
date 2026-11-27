#include "rut/runtime/ws_extensions.h"

#include "rut/common/http_header_validation.h"
#include "rut/common/range_int.h"
#include "rut/common/types.h"
#include "rut/runtime/format_integer.h"
#include "rut/runtime/http_parser.h"

#include <string.h>

namespace rut {
namespace {
struct Value {
    bool present = false;
    i32 number = 0;
    bool decimal = true;
    i64 digits = 0;
    bool leading_zero = false;
};
struct Cursor {
    Str value;
    u32 offset = 0;
    void whitespace() {
        while (offset < value.len && (value.ptr[offset] == ' ' || value.ptr[offset] == '\t'))
            ++offset;
    }
    [[nodiscard]] Str token() {
        const u32 kStart = offset;
        while (offset < value.len && is_http_tchar(__builtin_bit_cast(u8, value.ptr[offset])))
            ++offset;
        const auto start = range_int(kStart);
        const auto length = (range_int(offset) - start).max(range_int<0, 1>{});
        return {value.ptr + start.index(), length.to<u32>()};
    }
    [[nodiscard]] bool parameter_value(Value& result) {
        result.present = true;
        if (offset >= value.len) return false;
        const bool kQuoted = value.ptr[offset] == '"';
        if (kQuoted) ++offset;
        bool closed = !kQuoted;
        while (offset < value.len) {
            u8 byte = __builtin_bit_cast(u8, value.ptr[offset]);
            if (kQuoted && byte == '"') {
                ++offset;
                closed = true;
                break;
            }
            if (kQuoted && byte == '\\') {
                if (++offset == value.len) return false;
                byte = __builtin_bit_cast(u8, value.ptr[offset]);
            } else if (!kQuoted && !is_http_tchar(byte)) {
                break;
            }
            // RFC 6455 requires the unescaped quoted value to be a token too.
            if (!is_http_tchar(byte)) return false;
            if (result.digits == 0) result.leading_zero = byte == '0';
            if (byte < '0' || byte > '9' || result.digits >= 2)
                result.decimal = false;
            else
                result.number = result.number * 10 + (i32{byte} - '0');
            ++result.digits;
            ++offset;
        }
        return closed && result.digits != 0;
    }
};

[[nodiscard]] u8 window_bits(const Value& value) {
    range_int<8, 16> window;
    if (!value.present || !value.decimal || value.leading_zero ||
        !decltype(window)::try_from_i64(value.number, &window))
        return 0;
    return window.to<u8>();
}

[[nodiscard]] bool parse(const Header* headers,
                         u32 count,
                         bool response,
                         WsDeflateAgreement* agreement) {
    if (!agreement || count > kMaxHeaders || (!headers && count)) return false;
    *agreement = {};
    WsDeflateAgreement selected{};
    i32 selections = 0;
    for (i64 i = 0; i < count; ++i) {
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
                    const u8 bits = window_bits(value);
                    supported &= bits != 0;
                    if (bits != 0) candidate.server_window = bits;
                } else if (kParameter.eq(lit_str("client_max_window_bits"))) {
                    bit = 8;
                    candidate.client_window_present = true;
                    const u8 bits = window_bits(value);
                    supported &= (!response && !value.present) || bits != 0;
                    if (bits != 0) candidate.client_window = bits;
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
        const auto start = range_int(written);
        const auto end = start + range_int(text.len);
        if (end.value() > capacity) return false;
        memcpy(output + start.index(), text.ptr, text.len);
        written = end.min(range_int(capacity)).to<u32>();
        return true;
    };
    auto number = [&](u8 value) {
        const char kDigits[] = {last_decimal_digit(value / 10), last_decimal_digit(value)};
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
[[nodiscard]] i64 line_end(const u8* buffer, i64 start, i64 header_len) {
    for (i64 i = start; i + 1 < header_len; ++i)
        if (buffer[i] == '\r' && buffer[i + 1] == '\n') return i;
    return header_len;
}
[[nodiscard]] bool field_is(const u8* buffer, i64 start, i64 end, Str name, i64* colon = nullptr) {
    i64 pos = start;
    while (pos < end && buffer[pos] != ':') ++pos;
    if (colon) *colon = pos;
    return pos < end && pos - start == name.len &&
           http_header_name_eq_ci(
               reinterpret_cast<const char*>(buffer + start), name.len, name.ptr, name.len);
}
}  // namespace

u32 ws_rewrite_extensions(
    u8* buffer, u32 header_len, u32 total_len, u32 capacity, Str extension_value) {
    if (!buffer || header_len < 4 || total_len < header_len || total_len > capacity ||
        (!extension_value.ptr && extension_value.len) ||
        memcmp(buffer + i64{header_len} - 4, "\r\n\r\n", 4) != 0)
        return 0;
    for (u32 i = 0; i < extension_value.len; ++i) {
        const u8 kByte = __builtin_bit_cast(u8, extension_value.ptr[i]);
        if (kByte < 0x20 || kByte >= 0x7f) return 0;
    }
    const i64 fields_end = i64{header_len} - 2;
    const i64 first_end = line_end(buffer, 0, header_len);
    if (first_end == header_len || first_end == 0) return 0;
    const i64 first_field = first_end + 2;
    i64 removed = 0;
    for (i64 pos = first_field; pos < fields_end;) {
        const i64 end = line_end(buffer, pos, header_len);
        if (end == header_len || end == pos) return 0;
        const i64 next = end + 2;
        if (field_is(buffer, pos, end, lit_str("sec-websocket-extensions"))) removed += next - pos;
        pos = next;
    }
    constexpr Str kPrefix = lit_str("Sec-WebSocket-Extensions: ");
    constexpr u32 kLineOverhead = i64{kPrefix.len} + 2;
    const u32 kOverhead = extension_value.len ? kLineOverhead : 0;
    const auto header = range_int(header_len);
    const auto added = range_int(extension_value.len) + range_int(kOverhead);
    // Each removed byte belongs to a distinct scanned field in this header.
    const i64 new_header = header.value() - removed + added.value();
    const auto tail = range_int(total_len) - header;
    u32 new_header_len;
    if (new_header + tail.value() > capacity || !range_int(new_header).to(&new_header_len))
        return 0;
    i64 written = first_field;
    for (i64 pos = first_field; pos < fields_end;) {
        const i64 end = line_end(buffer, pos, header_len);
        const i64 next = end + 2;
        if (!field_is(buffer, pos, end, lit_str("sec-websocket-extensions"))) {
            const i64 line_size = next - pos;
            memmove(buffer + written, buffer + pos, line_size);
            written += line_size;
        }
        pos = next;
    }
    // Shift the tail after scanning the old header; shrinking must not destroy
    // fields still being read, and growing must not overwrite early frame bytes.
    memmove(buffer + new_header, buffer + header.index(), tail.max(range_int<0, 1>{}).to<u32>());
    if (extension_value.len) {
        memcpy(buffer + written, kPrefix.ptr, kPrefix.len);
        written += i64{kPrefix.len};
        memcpy(buffer + written, extension_value.ptr, extension_value.len);
        written += i64{extension_value.len};
        memcpy(buffer + written, "\r\n", 2);
        written += 2;
    }
    memcpy(buffer + written, "\r\n", 2);
    return new_header_len;
}

Str ws_selected_subprotocol(const u8* header, u32 header_len) {
    if (!header || header_len < 4) return {};
    const i64 fields_end = i64{header_len} - 2;
    const i64 first_end = line_end(header, 0, header_len);
    if (first_end == header_len) return {};
    for (i64 pos = first_end + 2; pos < fields_end;) {
        const i64 line_stop = line_end(header, pos, header_len);
        if (line_stop == header_len || line_stop == pos) return {};
        i64 colon = 0;
        if (field_is(header, pos, line_stop, lit_str("sec-websocket-protocol"), &colon)) {
            i64 start = colon + 1;
            i64 end = line_stop;
            while (start < end && (header[start] == ' ' || header[start] == '\t')) ++start;
            while (end > start && (header[end - 1] == ' ' || header[end - 1] == '\t')) --end;
            u32 len;
            if (!range_int(end - start).to(&len)) return {};
            return {reinterpret_cast<const char*>(header + start), len};
        }
        pos = line_stop + 2;
    }
    return {};
}
}  // namespace rut
