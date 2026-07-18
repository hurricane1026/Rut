#pragma once

#include "rut/common/types.h"
#include <atomic>

namespace rut {

struct RouteConfig;  // forward declare
struct CaptureRing;  // forward declare

// Sentinel: "disable capture". Distinct from nullptr ("no pending change").
// NOLINT: reinterpret_cast of integer to pointer is implementation-defined
// but well-defined on all targets we support (x86-64, aarch64). Using a
// pointer type keeps the atomic<CaptureRing*> interface clean.
static inline CaptureRing* kCaptureDisable = reinterpret_cast<CaptureRing*>(1);

// Per-shard control block. Config, JIT, and capture have independent atomic slots.
// nullptr = no pending update. Non-null = fire-and-forget update.
// Producer: pending_config.store(ptr, release)
// Consumer: pending_config.exchange(nullptr, acq_rel)
// Single atomic op per slot — no flag, no load-clear race.
struct alignas(64) ShardControlBlock {
    std::atomic<const RouteConfig*> pending_config{nullptr};
    std::atomic<void*> pending_jit{nullptr};
    std::atomic<CaptureRing*> pending_capture{nullptr};
    // Written only after pending_config has been adopted at an event-loop
    // command boundary. The config object itself carries the generation, so
    // pointer+generation publication cannot tear across separate atomic slots.
    std::atomic<u64> acknowledged_generation{0};
};

// Per-shard monotonic epoch for RCU progress tracking.
// Incremented on every request enter AND leave/close.
//
// This epoch alone is NOT sufficient for safe reclamation when multiple
// requests overlap. ProgramPinCounters supplies exact HTTP/1 request,
// suspended HTTP/2 stream, and terminate-mode WebSocket counts; a coordinator
// must require both the shard generation acknowledgement and zero pins before
// reclaiming an old program.
//
// Shard thread writes, control plane reads via epoch.load(acquire).
struct alignas(64) ShardEpoch {
    std::atomic<u64> epoch{0};
};

}  // namespace rut
