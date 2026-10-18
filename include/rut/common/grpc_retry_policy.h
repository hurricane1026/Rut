#pragma once

#include "rut/common/types.h"

namespace rut {

// Parsed and compiled opt-in gRPC retry metadata. Runtime retry behavior is
// intentionally implemented separately; zero attempts means disabled.
struct GrpcRetryPolicy {
    static constexpr u8 kMinAttempts = 2;
    static constexpr u8 kMaxAttempts = 3;
    static constexpr u32 kMinRequestBytes = 1;
    static constexpr u32 kMaxRequestBytes = 1u << 20;
    static constexpr u32 kMaxBackoffMs = 60000;

    u8 max_attempts = 0;
    u32 max_request_bytes = 0;
    u32 status_mask = 0;
    u32 backoff_ms = 0;

    constexpr bool enabled() const { return max_attempts != 0; }

    constexpr bool valid(bool http2) const {
        if (!enabled()) return max_request_bytes == 0 && status_mask == 0 && backoff_ms == 0;
        constexpr u32 kRetryStatusMask = 0x1fffeu;  // gRPC statuses 1...16; never retry OK.
        return http2 && max_attempts >= kMinAttempts && max_attempts <= kMaxAttempts &&
               max_request_bytes >= kMinRequestBytes && max_request_bytes <= kMaxRequestBytes &&
               status_mask != 0 && (status_mask & ~kRetryStatusMask) == 0 &&
               backoff_ms <= kMaxBackoffMs;
    }
};

}  // namespace rut
