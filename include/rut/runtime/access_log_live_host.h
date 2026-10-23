#pragma once

#include "rut/runtime/access_log_host.h"
#include "rut/runtime/access_log_live.h"
#include <atomic>
#include <cstddef>

namespace rut {

class SourceLiveAccessLogSession;
using SourceLiveAccessLogLeaseSlot = std::atomic<SourceLiveAccessLogSession*>;

inline constexpr u32 kSourceLiveAccessLogHostSchema = 1u;

struct SourceLiveAccessLogHostSlot {
    u64 start_position = 0u;
    AccessLogDownstreamHostRecord record{};
};

static_assert(offsetof(SourceLiveAccessLogHostSlot, start_position) == 0u);
static_assert(offsetof(SourceLiveAccessLogHostSlot, record) == 8u);
static_assert(sizeof(SourceLiveAccessLogHostSlot) == 144u);
static_assert(alignof(SourceLiveAccessLogHostSlot) == 8u);

// Independently owned typed sidecar. The base ring's release publication
// makes the matching slot visible; the exact start cursor prevents stale slot
// reuse from being associated with a later base entry.
struct SourceLiveAccessLogHostRing {
    static constexpr u32 kCapacity = LiveAccessLogRing::kCapacity;
    static constexpr u32 kMask = LiveAccessLogRing::kMask;

    u32 schema = 0u;
    u32 record_size = 0u;
    u32 capacity = 0u;
    u32 reserved = 0u;
    LiveAccessLogRing* owner_ring = nullptr;
    SourceLiveAccessLogLeaseSlot* owner_lease = nullptr;
    SourceLiveAccessLogHostSlot slots[kCapacity]{};

    void init(LiveAccessLogRing* ring, SourceLiveAccessLogLeaseSlot* lease) {
        schema = kSourceLiveAccessLogHostSchema;
        record_size = sizeof(AccessLogDownstreamHostRecord);
        capacity = kCapacity;
        reserved = 0u;
        owner_ring = ring;
        owner_lease = lease;
        for (SourceLiveAccessLogHostSlot& slot : slots) slot = SourceLiveAccessLogHostSlot{};
    }

    bool binding_valid(const LiveAccessLogRing* ring,
                       const SourceLiveAccessLogLeaseSlot* lease) const {
        return ring != nullptr && lease != nullptr && schema == kSourceLiveAccessLogHostSchema &&
               record_size == sizeof(AccessLogDownstreamHostRecord) && capacity == kCapacity &&
               reserved == 0u && owner_ring == ring && owner_lease == lease;
    }
};

}  // namespace rut
