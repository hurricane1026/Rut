#include "char_tables.h"
#include "simd.h"

namespace rut::simd {

u32 find_header_end(const u8* buf, u32 len, u32 from) {
    u32 start = from > 3 ? static_cast<u32>(static_cast<i64>(from) - 3) : 0;
    for (i64 i = start; i + 3 < static_cast<i64>(len); i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return static_cast<u32>(i + 4);
        }
    }
    return 0;
}

u32 scan_header_value(const u8* buf, u32 pos, u32 end) {
    while (pos < end) {
        if (buf[pos] == '\r') return pos;
        if (!kHeaderValueTable[buf[pos]]) return UINT32_MAX;
        pos++;
    }
    return end;
}

u32 scan_uri(const u8* buf, u32 pos, u32 end, u32* canon_end_out) {
    u32 canon_end = end;
    while (pos < end) {
        u8 b = buf[pos];
        if (b == ' ') {
            *canon_end_out = (canon_end != end) ? canon_end : pos;
            return pos;
        }
        if (!kUriTable[b]) return UINT32_MAX;
        if ((b == '?' || b == '#') && canon_end == end) canon_end = pos;
        pos++;
    }
    *canon_end_out = canon_end;
    return end;
}

u32 scan_header_name(const u8* buf, u32 pos, u32 end) {
    while (pos < end) {
        if (buf[pos] == ':') return pos;
        if (!kTokenTable[buf[pos]]) return UINT32_MAX;
        pos++;
    }
    return UINT32_MAX;
}

}  // namespace rut::simd
