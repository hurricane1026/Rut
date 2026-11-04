#pragma once

#include "rut/common/types.h"
#include <atomic>

namespace rut {

class PasswordGateway;
struct RouteConfig;  // forward declare
struct CaptureRing;  // forward declare

// Sentinel: "disable capture". Distinct from nullptr ("no pending change").
// NOLINT: reinterpret_cast of integer to pointer is implementation-defined
// but well-defined on all targets we support (x86-64, aarch64). Using a
// pointer type keeps the atomic<CaptureRing*> interface clean.
static inline CaptureRing* kCaptureDisable = reinterpret_cast<CaptureRing*>(1);

// Per-shard control block. Each update has its own atomic slot. A newly started
// password service is published before its requiring config; consumers exchange
// config before service, then install the service before adopting the config.
// nullptr = no pending update. Non-null = fire-and-forget update.
// Producer: pending_config.store(ptr, release)
// Consumer: pending_config.exchange(nullptr, acq_rel)
// Single atomic op per slot — no flag, no load-clear race.
struct alignas(64) ShardControlBlock {
    std::atomic<const RouteConfig*> pending_config{nullptr};
    std::atomic<void*> pending_jit{nullptr};
    std::atomic<PasswordGateway*> pending_password_gateway{nullptr};
    std::atomic<CaptureRing*> pending_capture{nullptr};
};

// Per-shard monotonic epoch for RCU progress tracking.
// Incremented on every request enter AND leave/close.
//
// LIMITATION: This epoch alone is NOT sufficient for safe reclamation
// when multiple requests overlap on one shard. A long-running request
// that started before a config swap can still be active while a newer
// request advances the epoch past the control plane's snapshot.
//
// For safe reclamation, the control plane must ALSO ensure no request
// that could reference the old config is still in flight. Options:
//   1. Pin config per-request (Connection holds the config pointer it
//      started with) — most precise, enables instant reclamation.
//   2. Drain all connections before reclaiming (simplest, current plan
//      for hot reload: drain old shard → swap config → re-accept).
//
// Shard thread writes, control plane reads via epoch.load(acquire).
struct alignas(64) ShardEpoch {
    std::atomic<u64> epoch{0};
};

}  // namespace rut
