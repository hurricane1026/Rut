#pragma once

#include "rut/common/http_header_validation.h"
#include "rut/runtime/http_parser.h"
#include <cstddef>

namespace rut {

inline constexpr u32 kAccessLogDownstreamHostMax = 128u;
inline constexpr u8 kAccessLogDownstreamHostRecordSchema = 1u;
inline constexpr u32 kAccessLogDownstreamHostLineCapacity = 512u;

enum class AccessLogDownstreamHostState : u8 {
    Unavailable = 0,
    Complete = 1,
    Empty = 2,
    Absent = 3,
    Duplicate = 4,
    OverLimit = 5,
    Invalid = 6,
};

static_assert(static_cast<u8>(AccessLogDownstreamHostState::Unavailable) == 0u);
static_assert(static_cast<u8>(AccessLogDownstreamHostState::Complete) == 1u);
static_assert(static_cast<u8>(AccessLogDownstreamHostState::Empty) == 2u);
static_assert(static_cast<u8>(AccessLogDownstreamHostState::Absent) == 3u);
static_assert(static_cast<u8>(AccessLogDownstreamHostState::Duplicate) == 4u);
static_assert(static_cast<u8>(AccessLogDownstreamHostState::OverLimit) == 5u);
static_assert(static_cast<u8>(AccessLogDownstreamHostState::Invalid) == 6u);

// Owned, versioned sidecar value. A zero schema is deliberately invalid until
// the canonical publisher copies a validated Connection snapshot into it.
struct AccessLogDownstreamHostRecord {
    u32 observed_length = 0u;
    AccessLogDownstreamHostState state = AccessLogDownstreamHostState::Unavailable;
    u8 record_schema = 0u;
    u8 reserved[2]{};
    char value[kAccessLogDownstreamHostMax]{};
};

inline bool access_log_downstream_host_record_is_canonical(
    const AccessLogDownstreamHostRecord& record) {
    if (record.record_schema != kAccessLogDownstreamHostRecordSchema || record.reserved[0] != 0u ||
        record.reserved[1] != 0u)
        return false;
    switch (record.state) {
        case AccessLogDownstreamHostState::Unavailable:
        case AccessLogDownstreamHostState::Empty:
        case AccessLogDownstreamHostState::Absent:
        case AccessLogDownstreamHostState::Duplicate:
        case AccessLogDownstreamHostState::Invalid:
            if (record.observed_length != 0u) return false;
            break;
        case AccessLogDownstreamHostState::Complete:
            if (record.observed_length == 0u ||
                record.observed_length > kAccessLogDownstreamHostMax)
                return false;
            break;
        case AccessLogDownstreamHostState::OverLimit:
            if (record.observed_length <= kAccessLogDownstreamHostMax) return false;
            break;
        default:
            return false;
    }
    const u32 used =
        record.state == AccessLogDownstreamHostState::Complete ? record.observed_length : 0u;
    for (u32 i = used; i < kAccessLogDownstreamHostMax; i++)
        if (record.value[i] != '\0') return false;
    return true;
}

static_assert(offsetof(AccessLogDownstreamHostRecord, observed_length) == 0u);
static_assert(offsetof(AccessLogDownstreamHostRecord, state) == 4u);
static_assert(offsetof(AccessLogDownstreamHostRecord, record_schema) == 5u);
static_assert(offsetof(AccessLogDownstreamHostRecord, reserved) == 6u);
static_assert(offsetof(AccessLogDownstreamHostRecord, value) == 8u);
static_assert(sizeof(AccessLogDownstreamHostRecord) == 136u);
static_assert(alignof(AccessLogDownstreamHostRecord) == 4u);

struct AccessLogEntry;
u32 format_access_log_downstream_host_line(const AccessLogEntry& entry,
                                           const AccessLogDownstreamHostRecord& host,
                                           char* buf,
                                           u32 buf_size);

// Request-owned snapshot. header_end is the checked boundary for the original
// complete request header and remains valid as metadata after recv_buf rewrites.
struct AccessLogDownstreamHostSnapshot {
    u32 episode = 0u;
    u32 original_header_end = 0u;
    AccessLogDownstreamHostRecord record{};
};

static_assert(offsetof(AccessLogDownstreamHostSnapshot, episode) == 0u);
static_assert(offsetof(AccessLogDownstreamHostSnapshot, original_header_end) == 4u);
static_assert(offsetof(AccessLogDownstreamHostSnapshot, record) == 8u);
static_assert(sizeof(AccessLogDownstreamHostSnapshot) == 144u);
static_assert(alignof(AccessLogDownstreamHostSnapshot) == 4u);

inline void clear_access_log_downstream_host_snapshot(AccessLogDownstreamHostSnapshot& snapshot) {
    snapshot.episode = 0u;
    snapshot.original_header_end = 0u;
    snapshot.record.observed_length = 0u;
    snapshot.record.state = AccessLogDownstreamHostState::Unavailable;
    snapshot.record.record_schema = 0u;
    snapshot.record.reserved[0] = 0u;
    snapshot.record.reserved[1] = 0u;
}

inline bool access_log_header_view_in_bounds(Str view,
                                             const u8* receive_data,
                                             u32 receive_length,
                                             u32 header_end) {
    if (view.ptr == nullptr || receive_data == nullptr || header_end == 0u ||
        header_end > receive_length)
        return false;
    const uintptr_t begin = reinterpret_cast<uintptr_t>(receive_data);
    if (begin > UINTPTR_MAX - header_end) return false;
    const uintptr_t end = begin + header_end;
    const uintptr_t address = reinterpret_cast<uintptr_t>(view.ptr);
    if (address < begin || address > end || view.len > end - address) return false;
    return true;
}

// Capture only a complete, strictly parsed HTTP/1 request. Every stored
// header view is checked against the original header span before it is read.
// A failed provenance check produces canonical Invalid state; incomplete or
// non-HTTP/1 input remains Unavailable. Host values are observations, not
// authority validation, and preserve the parser's semantic OWS-trimmed bytes.
inline void capture_access_log_downstream_host_snapshot(AccessLogDownstreamHostSnapshot& snapshot,
                                                        u32 episode,
                                                        const ParsedRequest& request,
                                                        const u8* receive_data,
                                                        u32 receive_length,
                                                        u32 original_header_end,
                                                        bool complete_strict_http1) {
    clear_access_log_downstream_host_snapshot(snapshot);
    if (episode == 0u) return;
    if (!complete_strict_http1 ||
        (request.version != HttpVersion::Http10 && request.version != HttpVersion::Http11)) {
        if (episode != 0u) snapshot.episode = episode;
        return;
    }
    if (request.header_count > kMaxHeaders) {
        snapshot.record.state = AccessLogDownstreamHostState::Invalid;
        snapshot.episode = episode;
        return;
    }
    if (receive_data == nullptr || original_header_end == 0u ||
        original_header_end > receive_length) {
        snapshot.record.state = AccessLogDownstreamHostState::Invalid;
        snapshot.episode = episode;
        return;
    }

    u32 host_count = 0u;
    Str host{nullptr, 0u};
    bool views_valid = true;
    for (u32 i = 0; i < request.header_count; i++) {
        const Header& header = request.headers[i];
        if (!access_log_header_view_in_bounds(
                header.name, receive_data, receive_length, original_header_end) ||
            !access_log_header_view_in_bounds(
                header.value, receive_data, receive_length, original_header_end) ||
            !access_log_header_view_in_bounds(
                header.raw_value, receive_data, receive_length, original_header_end)) {
            views_valid = false;
            break;
        }
        if (!http_header_name_eq_ci(header.name.ptr, header.name.len, "host", 4u)) continue;
        host_count++;
        if (host_count == 1u) host = header.value;
    }
    if (!views_valid) {
        snapshot.record.state = AccessLogDownstreamHostState::Invalid;
    } else if (host_count == 0u) {
        snapshot.record.state = AccessLogDownstreamHostState::Absent;
    } else if (host_count > 1u) {
        snapshot.record.state = AccessLogDownstreamHostState::Duplicate;
    } else if (host.len == 0u) {
        snapshot.record.state = AccessLogDownstreamHostState::Empty;
    } else if (host.len > kAccessLogDownstreamHostMax) {
        snapshot.record.state = AccessLogDownstreamHostState::OverLimit;
        snapshot.record.observed_length = host.len;
    } else {
        snapshot.record.state = AccessLogDownstreamHostState::Complete;
        snapshot.record.observed_length = host.len;
        for (u32 i = 0; i < host.len; i++) snapshot.record.value[i] = host.ptr[i];
    }
    snapshot.original_header_end = original_header_end;
    // Publish the owner last; zero is never a valid request episode.
    snapshot.episode = episode;
}

// Convert the internal snapshot to a canonical, independently owned record.
// A stale or contradictory snapshot becomes explicit Invalid, never a prefix.
inline void canonicalize_access_log_downstream_host_record(
    const AccessLogDownstreamHostSnapshot& snapshot,
    u32 expected_episode,
    AccessLogDownstreamHostRecord& out) {
    out = AccessLogDownstreamHostRecord{};
    out.record_schema = kAccessLogDownstreamHostRecordSchema;
    if (expected_episode == 0u || snapshot.episode != expected_episode ||
        snapshot.record.record_schema != 0u || snapshot.record.reserved[0] != 0u ||
        snapshot.record.reserved[1] != 0u) {
        out.state = AccessLogDownstreamHostState::Invalid;
        return;
    }
    const AccessLogDownstreamHostRecord& source = snapshot.record;
    switch (source.state) {
        case AccessLogDownstreamHostState::Complete:
            if (snapshot.original_header_end == 0u || source.observed_length == 0u ||
                source.observed_length > snapshot.original_header_end ||
                source.observed_length > kAccessLogDownstreamHostMax) {
                out.state = AccessLogDownstreamHostState::Invalid;
                return;
            }
            out.state = source.state;
            out.observed_length = source.observed_length;
            for (u32 i = 0; i < source.observed_length; i++) out.value[i] = source.value[i];
            return;
        case AccessLogDownstreamHostState::OverLimit:
            if (snapshot.original_header_end == 0u ||
                source.observed_length <= kAccessLogDownstreamHostMax ||
                source.observed_length > snapshot.original_header_end) {
                out.state = AccessLogDownstreamHostState::Invalid;
                return;
            }
            out.state = source.state;
            out.observed_length = source.observed_length;
            return;
        case AccessLogDownstreamHostState::Unavailable:
            if (source.observed_length != 0u || snapshot.original_header_end != 0u) {
                out.state = AccessLogDownstreamHostState::Invalid;
                return;
            }
            out.state = source.state;
            return;
        case AccessLogDownstreamHostState::Empty:
        case AccessLogDownstreamHostState::Absent:
        case AccessLogDownstreamHostState::Duplicate:
        case AccessLogDownstreamHostState::Invalid:
            if (source.observed_length != 0u ||
                (source.state != AccessLogDownstreamHostState::Invalid &&
                 snapshot.original_header_end == 0u)) {
                out.state = AccessLogDownstreamHostState::Invalid;
                return;
            }
            out.state = source.state;
            return;
        default:
            out.state = AccessLogDownstreamHostState::Invalid;
            return;
    }
}

}  // namespace rut
