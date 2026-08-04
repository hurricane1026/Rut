#pragma once

#include "rut/common/types.h"
#include <atomic>

namespace rut {

enum class UpstreamMarkReplayReason : u8 {
    Published = 0,
    StaleOrForeign,
    Unavailable,
    Contended,
    VersionExhausted,
};

struct UpstreamMarkReplayContext {
    u64 workload_event_position = 0;
    u64 correlation_id = 0;
    u32 source_shard_id = 0;
};

inline std::atomic<u64> upstream_mark_replay_workload_sequence{0};
inline thread_local UpstreamMarkReplayContext active_upstream_mark_replay_context{};

inline void set_active_upstream_mark_replay_context(u32 shard_id) {
    const u64 position =
        upstream_mark_replay_workload_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    active_upstream_mark_replay_context = {position, position, shard_id};
}

// A bounded, value-only event emitted for every upstream.mark attempt. The
// event is intentionally independent of the HTTP traffic CaptureEntry format;
// replay artifacts can carry control-plane events without changing the stable
// request record ABI.
struct UpstreamMarkReplayEvent {
    u64 event_sequence = 0;
    u64 workload_event_position = 0;
    u64 correlation_id = 0;
    u32 source_shard_id = 0;
    u64 config_generation = 0;
    u16 upstream_id = 0;
    u16 backend_id = 0;
    bool healthy = false;
    bool accepted = false;
    UpstreamMarkReplayReason reason = UpstreamMarkReplayReason::Unavailable;
    u64 published_version = 0;
    u64 peer_config_generation = 0;
    u64 peer_published_version = 0;
    u64 published_sequence = 0;
    u64 peer_published_sequence = 0;
};

using UpstreamMarkReplaySink = void (*)(void* context, const UpstreamMarkReplayEvent& event);

}  // namespace rut
