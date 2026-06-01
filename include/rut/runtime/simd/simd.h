#pragma once

#include "rut/common/types.h"

namespace rut::simd {

// Find \r\n\r\n in buffer starting from `from`.
// Returns offset past terminator (first body byte), or 0 if not found.
u32 find_header_end(const u8* buf, u32 len, u32 from);

// Scan header value: find \r while validating chars.
// Returns position of \r, or `end` if not found, or (u32)-1 on invalid char.
u32 scan_header_value(const u8* buf, u32 pos, u32 end);

// Scan URI: find space while validating, and report the canonical-end
// position (first '?' or '#' before space, else the space/end position).
//
// Returns position of space, or `end` if not found, or (u32)-1 on invalid.
// On non-error returns, *canon_end_out receives the canonical-end position:
//   - if '?' or '#' appears before the terminating space, its position
//   - otherwise, the same value as the return (space or end)
// On error return ((u32)-1), *canon_end_out is untouched.
//
// canon_end is the upper bound of the routing-relevant path bytes
// [uri_start, canon_end). Callers strip leading '/' and trim trailing '/'
// in scalar code after the scan to produce the final canonical Str.
u32 scan_uri(const u8* buf, u32 pos, u32 end, u32* canon_end_out);

// Scan header name: find ':' while validating token chars.
// Returns position of ':', or (u32)-1 on invalid/not found.
u32 scan_header_name(const u8* buf, u32 pos, u32 end);

}  // namespace rut::simd
