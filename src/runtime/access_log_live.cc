#include "rut/runtime/access_log_live.h"

namespace rut {

void LiveAccessLogRing::init() {
    init_quiescent_empty(0u);
}

void LiveAccessLogRing::init_quiescent_empty(u64 position) {
    published_pos.store(position, std::memory_order_relaxed);
    committed_pos.store(position, std::memory_order_relaxed);
}

LiveAccessLogPublishResult LiveAccessLogRing::try_publish(const AccessLogEntry& entry) {
    const u64 published = published_pos.load(std::memory_order_relaxed);
    const u64 committed = committed_pos.load(std::memory_order_acquire);
    const u64 pending = published - committed;
    if (pending > kCapacity) return {LiveAccessLogPublishStatus::InvalidState, {}};
    if (pending == kCapacity) return {LiveAccessLogPublishStatus::Full, {}};

    entries[published & kMask] = entry;
    const u64 end_position = published + 1u;
    published_pos.store(end_position, std::memory_order_release);
    return {LiveAccessLogPublishStatus::Published, {true, end_position}};
}

LiveAccessLogPeek LiveAccessLogRing::peek() const {
    const u64 committed = committed_pos.load(std::memory_order_relaxed);
    const u64 published = published_pos.load(std::memory_order_acquire);
    const u64 pending = published - committed;
    if (pending == 0u || pending > kCapacity) return {};
    return {true, &entries[committed & kMask], committed};
}

bool LiveAccessLogRing::commit(u64 position) {
    const u64 committed = committed_pos.load(std::memory_order_relaxed);
    if (position != committed) return false;
    const u64 published = published_pos.load(std::memory_order_acquire);
    const u64 pending = published - committed;
    if (pending == 0u || pending > kCapacity) return false;
    committed_pos.store(committed + 1u, std::memory_order_release);
    return true;
}

bool LiveAccessLogRing::acknowledged(LiveAccessLogTicket ticket) const {
    if (!ticket.valid) return false;
    static constexpr u64 kHalfRange = u64{1} << 63u;
    const u64 committed = committed_pos.load(std::memory_order_acquire);
    return committed - ticket.end_position < kHalfRange;
}

}  // namespace rut
