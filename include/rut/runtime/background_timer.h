#pragma once

#include "rut/common/shard_limits.h"
#include "rut/runtime/cross_shard.h"
#include "rut/runtime/route_table.h"

namespace rut {

struct BackgroundTimerMessage {
    ShardWorkSchedule schedule;
    i64 generation = 0;
    i64 sequence = 0;
    u32 timer = 0;
};

struct BackgroundTimerDispatch {
    static constexpr i32 kCapacity = RouteConfig::kMaxTimers;

    struct Target {
        ShardWakeChannel wake;
        ShardSpscRing<BackgroundTimerMessage, kCapacity> ring;

        // Shard 0 writes sent. The destination alone writes acknowledged.
        alignas(64) i64 sent[kCapacity]{};
        i64 coalesced = 0;
        i64 full = 0;
        alignas(64) std::atomic<i64> acknowledged[kCapacity]{};

        void stage(BackgroundTimerMessage message) {
            auto& sequence = sent[message.timer];
            if (sequence != acknowledged[message.timer].load(std::memory_order_acquire)) {
                if (coalesced < INT64_MAX) ++coalesced;
                return;
            }
            if (sequence == INT64_MAX) return;
            message.sequence = sequence + 1;
            if (!ring.stage(message)) {
                if (full < INT64_MAX) ++full;
                return;
            }
            sequence = message.sequence;
        }

        void flush() {
            if (ring.publish()) wake.notify_published();
        }

        void acknowledge(const BackgroundTimerMessage& message) {
            acknowledged[message.timer].store(message.sequence, std::memory_order_release);
        }
    };

    Target targets[kMaxShards];
    u32 shard_count = 0;
};

}  // namespace rut
