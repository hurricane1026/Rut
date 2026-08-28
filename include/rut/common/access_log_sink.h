#pragma once

#include "rut/common/types.h"
#include <type_traits>

namespace rut {

inline constexpr u32 kAccessLogSinkPathMax = 255;

enum class AccessLogFormatProfile : u8 {
    None = 0,
    DownstreamRequestBytesLine = 1,
};

enum class AccessLogPublicationProfile : u8 {
    None = 0,
    LiveEachRecord = 1,
};

static_assert(std::is_same_v<std::underlying_type_t<AccessLogFormatProfile>, u8>);
static_assert(std::is_same_v<std::underlying_type_t<AccessLogPublicationProfile>, u8>);
static_assert(static_cast<u8>(AccessLogFormatProfile::None) == 0u);
static_assert(static_cast<u8>(AccessLogFormatProfile::DownstreamRequestBytesLine) == 1u);
static_assert(static_cast<u8>(AccessLogPublicationProfile::None) == 0u);
static_assert(static_cast<u8>(AccessLogPublicationProfile::LiveEachRecord) == 1u);

// Owned process-start metadata. This declaration remains inert until the sink opener and
// reliable publisher are connected by later capability increments.
struct AccessLogSinkSpec {
    bool present = false;
    AccessLogFormatProfile format = AccessLogFormatProfile::None;
    AccessLogPublicationProfile publication = AccessLogPublicationProfile::None;
    u16 path_len = 0;
    char path[kAccessLogSinkPathMax + 1u]{};
};
static_assert(sizeof(AccessLogSinkSpec::path) == 256u);

inline bool access_log_sink_path_valid(Str path) {
    if (path.ptr == nullptr || path.len < 2u || path.len > kAccessLogSinkPathMax ||
        path.ptr[0] != '/' || path.ptr[path.len - 1u] == '/')
        return false;
    if (path.eq({"/dev/stderr", 11u})) return false;

    u32 segment_start = 1u;
    for (u32 i = 1u; i <= path.len; i++) {
        if (i != path.len) {
            const char c = path.ptr[i];
            const bool allowed = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                 (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' ||
                                 c == '/';
            if (!allowed) return false;
            if (c != '/') continue;
        }

        const u32 segment_len = i - segment_start;
        if (segment_len == 0u || (segment_len == 1u && path.ptr[segment_start] == '.') ||
            (segment_len == 2u && path.ptr[segment_start] == '.' &&
             path.ptr[segment_start + 1u] == '.'))
            return false;
        segment_start = i + 1u;
    }
    return true;
}

inline bool access_log_sink_spec_valid(const AccessLogSinkSpec& spec) {
    if (!spec.present) {
        if (spec.format != AccessLogFormatProfile::None ||
            spec.publication != AccessLogPublicationProfile::None || spec.path_len != 0u)
            return false;
        for (char byte : spec.path)
            if (byte != '\0') return false;
        return true;
    }
    if (spec.format != AccessLogFormatProfile::DownstreamRequestBytesLine ||
        spec.publication != AccessLogPublicationProfile::LiveEachRecord ||
        spec.path_len > kAccessLogSinkPathMax || spec.path[spec.path_len] != '\0')
        return false;
    if (!access_log_sink_path_valid({spec.path, spec.path_len})) return false;
    for (u32 i = spec.path_len + 1u; i < sizeof(spec.path); i++)
        if (spec.path[i] != '\0') return false;
    return true;
}

}  // namespace rut
