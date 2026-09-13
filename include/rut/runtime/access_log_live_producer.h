#pragma once

#include "rut/runtime/access_log_live_writer.h"

namespace rut {

enum class SourceLiveAccessLogPublishStatus : u8 {
    Published,
    Fatal,
    InvalidConfiguration,
};

struct SourceLiveAccessLogPublishResult {
    SourceLiveAccessLogPublishStatus status =
        SourceLiveAccessLogPublishStatus::InvalidConfiguration;
    LiveAccessLogTicket ticket{};
};

// A shard-local SPSC producer binding. It owns none of the ring, session, or
// output resources. The caller must keep both pointees alive until reset(), and
// must quiesce the producer before finishing its process-owned session.
class SourceLiveAccessLogProducer {
public:
    bool init(LiveAccessLogRing* ring,
              SourceLiveAccessLogSession* session,
              u32 ring_index,
              SourceLiveAccessLogLeaseSlot* lease = nullptr);
    void reset();

    bool initialized() const { return ring_ != nullptr && session_ != nullptr; }
    LiveAccessLogRing* ring() const { return ring_; }
    SourceLiveAccessLogSession* session() const { return session_; }
    SourceLiveAccessLogLeaseSlot* lease() const { return lease_; }
    u32 ring_index() const { return ring_index_; }

    SourceLiveAccessLogPublishResult publish(const AccessLogEntry& entry);
    void fail_protocol(i32 system_error = 0);

private:
    LiveAccessLogRing* ring_ = nullptr;
    SourceLiveAccessLogSession* session_ = nullptr;
    SourceLiveAccessLogLeaseSlot* lease_ = nullptr;
    u32 ring_index_ = 0u;
};

}  // namespace rut
