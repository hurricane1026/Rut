#pragma once

#include "rut/common/range_int.h"
#include "rut/common/types.h"
#include <type_traits>

namespace rut {

inline constexpr u32 kAccessLogSinkPathMax = 255;

enum class AccessLogFormatProfile : u8 {
    None = 0,
    DownstreamRequestBytesLine = 1,
    DownstreamHost = 2,
};

enum class AccessLogPublicationProfile : u8 {
    None = 0,
    LiveEachRecord = 1,
};

static_assert(std::is_same_v<std::underlying_type_t<AccessLogFormatProfile>, u8>);
static_assert(std::is_same_v<std::underlying_type_t<AccessLogPublicationProfile>, u8>);
static_assert(static_cast<u8>(AccessLogFormatProfile::None) == 0u);
static_assert(static_cast<u8>(AccessLogFormatProfile::DownstreamRequestBytesLine) == 1u);
static_assert(static_cast<u8>(AccessLogFormatProfile::DownstreamHost) == 2u);
static_assert(static_cast<u8>(AccessLogPublicationProfile::None) == 0u);
static_assert(static_cast<u8>(AccessLogPublicationProfile::LiveEachRecord) == 1u);

// Owned process-start metadata. This declaration remains inert until the sink opener and
// reliable publisher are connected by later capability increments.
struct AccessLogSinkSpec {
    bool present = false;
    AccessLogFormatProfile format = AccessLogFormatProfile::None;
    AccessLogPublicationProfile publication = AccessLogPublicationProfile::None;
    u16 path_len = 0;
    char path[static_cast<u32>(static_cast<i64>(kAccessLogSinkPathMax) + 1)]{};
};
static_assert(sizeof(AccessLogSinkSpec::path) == 256u);

inline bool access_log_sink_path_valid(Str path) {
    range_int<2, i64{kAccessLogSinkPathMax} + 1> length;
    if (path.ptr == nullptr || !decltype(length)::try_from_i64(path.len, &length) ||
        path.ptr[0] != '/')
        return false;
    const range_int<1, kAccessLogSinkPathMax> kLast = length - range_int<1, 2>{};
    if (path.ptr[kLast.index()] == '/') return false;
    if (path.eq({"/dev/stderr", 11u})) return false;

    constexpr auto kOne = range_int<1, 2>{};
    range_int<1, i64{UINT32_MAX} + 2> segment_start;
    for (u32 i = 1u; i <= path.len; i++) {
        if (i != path.len) {
            const char c = path.ptr[i];
            const bool allowed = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                 (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' ||
                                 c == '/';
            if (!allowed) return false;
            if (c != '/') continue;
        }

        const auto kSegmentLength = (range_int(i) - segment_start).value();
        if (kSegmentLength == 0 ||
            (kSegmentLength == 1 && path.ptr[segment_start.index()] == '.') ||
            (kSegmentLength == 2 && path.ptr[segment_start.index()] == '.' &&
             path.ptr[(segment_start + kOne).index()] == '.'))
            return false;
        segment_start = range_int(i) + kOne;
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
    if ((spec.format != AccessLogFormatProfile::DownstreamRequestBytesLine &&
         spec.format != AccessLogFormatProfile::DownstreamHost) ||
        spec.publication != AccessLogPublicationProfile::LiveEachRecord ||
        spec.path_len > kAccessLogSinkPathMax || spec.path[spec.path_len] != '\0')
        return false;
    if (!access_log_sink_path_valid({spec.path, spec.path_len})) return false;
    const auto kTail = range_int(spec.path_len) + range_int<1, 2>{};
    for (i64 i = kTail.value(); i < static_cast<i64>(sizeof(spec.path)); i++)
        if (spec.path[i] != '\0') return false;
    return true;
}

}  // namespace rut
