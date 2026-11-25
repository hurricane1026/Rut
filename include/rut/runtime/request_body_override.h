#pragma once

#include "rut/common/http_header_validation.h"
#include "rut/common/integer_range.h"
#include "rut/common/types.h"
#include "rut/runtime/http_parser.h"

namespace rut {
// Bounded replacement for one fully buffered HTTP/1 Content-Length body.
inline constexpr u32 kMaxForwardBodyOverride = 65536;

namespace request_body_override_detail {
inline bool content_length_line(const u8* data, u32 header_end, u32* line_start, u32* line_end) {
    const i64 kHeaderEnd = static_cast<i64>(header_end);
    i64 position = 0;
    while (position + 1 < kHeaderEnd && !(data[position] == '\r' && data[position + 1] == '\n'))
        ++position;
    if (position + 1 >= kHeaderEnd) return false;
    position = add_assuming_in_range(position, i64{2});
    u32 found = 0;
    while (position < kHeaderEnd) {
        const i64 start = position;
        while (position + 1 < kHeaderEnd && !(data[position] == '\r' && data[position + 1] == '\n'))
            ++position;
        if (position + 1 >= kHeaderEnd) return false;
        const i64 end = position;
        position = add_assuming_in_range(position, i64{2});
        i64 colon = start;
        while (colon < end && data[colon] != ':') ++colon;
        if (colon == end) continue;
        // Both cursors lie within the validated header length.
        const i64 name_length = subtract_assuming_in_range(colon, start);
        if (!http_header_name_eq_ci(reinterpret_cast<const char*>(data + start),
                                    static_cast<u32>(name_length),
                                    "Content-Length",
                                    14))
            continue;
        if (++found != 1) return false;
        *line_start = static_cast<u32>(start);
        *line_end = static_cast<u32>(end);
    }
    return found == 1;
}
}  // namespace request_body_override_detail

// Rewrites the Content-Length field and body bytes in a complete HTTP/1
// request. The input must have exactly one Content-Length and no chunked or
// other transfer coding. `total`, `header_end` and the buffer are updated in
// place; `capacity` bounds the result. Returns false without mutation for any
// unsupported or ambiguous shape. `expected_body_len` may be 0xffffffffu.
inline bool replace_h1_body_in_place(
    u8* data, u32* total, u32 capacity, u32* header_end, u32 expected_body_len, Str body) {
    if (data == nullptr || total == nullptr || header_end == nullptr ||
        body.len > kMaxForwardBodyOverride)
        return false;
    const u32 old_total = *total;
    const u32 old_header_end = *header_end;
    if (old_header_end > old_total) return false;
    HttpParser parser;
    ParsedRequest request;
    parser.reset();
    request.reset();
    if (parser.parse(data, old_total, &request) != ParseStatus::Complete ||
        parser.header_end != old_header_end || request.chunked ||
        request.transfer_encoding != RequestTransferEncoding::None || !request.has_content_length ||
        request.content_length_count != 1)
        return false;
    const u32 old_body_len = request.content_length;
    if ((expected_body_len != 0xffffffffu && expected_body_len != old_body_len) ||
        static_cast<i64>(old_body_len) >
            static_cast<i64>(old_total) - static_cast<i64>(old_header_end))
        return false;
    u32 line_start = 0;
    u32 line_end = 0;
    if (!request_body_override_detail::content_length_line(
            data, old_header_end, &line_start, &line_end))
        return false;

    char digits[10];
    u32 digit_count = 0;
    u32 value = body.len;
    do {
        digits[digit_count++] =
            static_cast<char>(static_cast<i64>('0') + static_cast<i64>(value % 10));
        value /= 10;
    } while (value);
    const u32 new_line_len = static_cast<u32>(16 + static_cast<i64>(digit_count) + 2);
    const i64 header_delta =
        static_cast<i64>(new_line_len) -
        static_cast<i64>(static_cast<i64>(line_end) + 2 - static_cast<i64>(line_start));
    const i64 tail_len = static_cast<i64>(old_total) - static_cast<i64>(old_header_end) -
                         static_cast<i64>(old_body_len);
    const i64 new_total =
        static_cast<i64>(old_header_end) + header_delta + static_cast<i64>(body.len) + tail_len;
    // Growing the Content-Length line shifts the body and tail up by header_delta
    // before the body is shortened. That intermediate extent can therefore exceed
    // the final total, so bound the larger of the two writes.
    const i64 intermediate_total =
        static_cast<i64>(old_total) + (header_delta > 0 ? header_delta : 0);
    if (tail_len < 0 || new_total < 0 || new_total > static_cast<i64>(capacity) ||
        intermediate_total > static_cast<i64>(capacity))
        return false;

    const u32 after_line = static_cast<u32>(static_cast<i64>(line_end) + 2);
    if (header_delta != 0) {
        __builtin_memmove(
            data + static_cast<i64>(line_start) + static_cast<i64>(new_line_len),
            data + static_cast<i64>(after_line),
            static_cast<u32>(static_cast<i64>(old_total) - static_cast<i64>(after_line)));
    }
    __builtin_memcpy(data + static_cast<i64>(line_start), "Content-Length: ", 16);
    for (u32 i = 0; i < digit_count; ++i)
        data[static_cast<i64>(line_start) + 16 + static_cast<i64>(i)] =
            static_cast<u8>(digits[static_cast<i64>(digit_count) - 1 - static_cast<i64>(i)]);
    data[static_cast<i64>(line_start) + 16 + static_cast<i64>(digit_count)] = '\r';
    data[static_cast<i64>(line_start) + 17 + static_cast<i64>(digit_count)] = '\n';
    const u32 new_header_end = static_cast<u32>(static_cast<i64>(old_header_end) + header_delta);
    const u32 tail_destination =
        static_cast<u32>(static_cast<i64>(new_header_end) + static_cast<i64>(body.len));
    if (tail_len != 0)
        __builtin_memmove(data + static_cast<i64>(tail_destination),
                          data + static_cast<i64>(new_header_end) + static_cast<i64>(old_body_len),
                          static_cast<u32>(tail_len));
    if (body.len != 0)
        __builtin_memcpy(data + static_cast<i64>(new_header_end), body.ptr, body.len);
    *total = static_cast<u32>(new_total);
    *header_end = new_header_end;
    return true;
}
}  // namespace rut
