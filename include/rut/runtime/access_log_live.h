#pragma once

#include "rut/common/types.h"
#include "rut/runtime/access_log.h"
#include <atomic>
#include <cstddef>
#include <type_traits>

namespace rut {

struct LiveAccessLogTicket {
    bool valid = false;
    // Exclusive published position. Zero is a valid value after u64 wrap;
    // callers must consult valid rather than treating the position as a sentinel.
    u64 end_position = 0;
};

enum class LiveAccessLogPublishStatus : u8 {
    Published = 0,
    Full = 1,
    InvalidState = 2,
};

struct LiveAccessLogPublishResult {
    LiveAccessLogPublishStatus status = LiveAccessLogPublishStatus::InvalidState;
    LiveAccessLogTicket ticket{};
};

struct LiveAccessLogPeek {
    bool valid = false;
    const AccessLogEntry* entry = nullptr;
    u64 position = 0;
};

// Pure SPSC live-publication protocol. The producer owns published_pos and
// entry writes; the consumer owns committed_pos. A consumer commit is the
// durable-writer acknowledgment boundary for later stages, not a destructive
// pop before I/O succeeds.
struct alignas(64) LiveAccessLogRing {
    static constexpr u32 kCapacity = 512;
    static constexpr u32 kMask = kCapacity - 1u;

    alignas(64) std::atomic<u64> published_pos;
    char _published_pad[64u - sizeof(std::atomic<u64>)]{};
    alignas(64) std::atomic<u64> committed_pos;
    char _committed_pad[64u - sizeof(std::atomic<u64>)]{};
    AccessLogEntry entries[kCapacity];

    void init();

    // Test/design seam for an empty, quiescent ring near u64 wrap. No producer
    // or consumer may be active, and both positions are initialized equally.
    void init_quiescent_empty(u64 position);

    LiveAccessLogPublishResult try_publish(const AccessLogEntry& entry);
    LiveAccessLogPeek peek() const;
    bool commit(u64 position);
    // Modular ordering is unambiguous only within half the u64 range. A ticket
    // must not be retained for 2^63 or more later commits in one session.
    bool acknowledged(LiveAccessLogTicket ticket) const;
};

static_assert(LiveAccessLogRing::kCapacity == 512u);
static_assert((LiveAccessLogRing::kCapacity & (LiveAccessLogRing::kCapacity - 1u)) == 0u);
static_assert(std::atomic<u64>::is_always_lock_free);
static_assert(alignof(LiveAccessLogRing) == 64u);
static_assert(offsetof(LiveAccessLogRing, published_pos) == 0u);
static_assert(offsetof(LiveAccessLogRing, committed_pos) == 64u);
static_assert(offsetof(LiveAccessLogRing, entries) == 128u);
static_assert(sizeof(LiveAccessLogRing) >=
              128u + LiveAccessLogRing::kCapacity * sizeof(AccessLogEntry));
static_assert(std::is_trivially_copyable_v<LiveAccessLogTicket>);

}  // namespace rut
