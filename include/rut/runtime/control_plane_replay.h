#pragma once

#include "rut/common/types.h"

namespace rut {

enum class UpstreamMarkReplayReason : u8 {
    Published = 0,
    StaleOrForeign,
    Unavailable,
    Contended,
    VersionExhausted,
};

// A bounded, value-only event emitted for every upstream.mark attempt. The
// event is intentionally independent of the HTTP traffic CaptureEntry format;
// replay artifacts can carry control-plane events without changing the stable
// request record ABI.
struct UpstreamMarkReplayEvent {
    u64 event_sequence = 0;
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
