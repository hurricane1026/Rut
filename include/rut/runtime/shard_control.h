/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

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
