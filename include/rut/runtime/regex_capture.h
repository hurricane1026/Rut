#pragma once

#include "rut/common/types.h"
#include "rut/runtime/arena.h"

namespace rut {
// Capture regexes are separate from Vectorscan's full-match Boolean databases.
// Their serialized form is the bounded source pattern, recompiled at startup.
// Backend boundary: no engine types escape this header. The runtime-free RE2
// fork still uses C heap allocation independently of the request Arena.
inline constexpr char kCaptureRegexMarker[] = "RUTCAP2:";
inline constexpr u32 kCaptureRegexMarkerLength = 8;
void* capture_regex_compile(Str pattern);
void capture_regex_destroy(void* program);
Str capture_regex_pattern(const void* program);
u32 capture_regex_group_count(const void* program);
// 0 = no participating capture, 1 = present (including empty), 2 = resource/error.
u8 capture_regex_match(void* program, SliceArena& arena, Str subject, u32 group, Str* output);
}  // namespace rut
