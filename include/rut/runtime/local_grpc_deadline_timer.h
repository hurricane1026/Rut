#pragma once

#include "rut/common/types.h"

namespace rut {

enum class LocalGrpcDeadlineTimerPhase : u8 { Idle, Armed, CancelPending, Retiring };

struct LocalGrpcDeadlineTimerOwner {
    static constexpr u32 kGenerationMask = 0x7fffffffu;

    i64 timespec_sec = 0;
    i64 timespec_nsec = 0;
    u32 generation = 0;
    u32 owner_generation = 0;
    u32 cancel_generation = 0;
    LocalGrpcDeadlineTimerPhase phase = LocalGrpcDeadlineTimerPhase::Idle;
    bool target_owned = false;
    bool cancel_owned = false;

    bool reusable() const {
        return phase == LocalGrpcDeadlineTimerPhase::Idle && !target_owned && !cancel_owned;
    }

    bool arm(u64 absolute_us) {
        // A retired token must never identify a later timer, even after the
        // connection slot has been reused. Exhaustion quarantines this owner.
        if (!reusable() || absolute_us == 0 || generation == kGenerationMask) return false;
        generation++;
        owner_generation = generation;
        cancel_generation = 0;
        timespec_sec = static_cast<i64>(absolute_us / 1000000ull);
        timespec_nsec = static_cast<i64>((absolute_us % 1000000ull) * 1000ull);
        phase = LocalGrpcDeadlineTimerPhase::Armed;
        target_owned = true;
        return true;
    }

    bool request_cancel() {
        if (!target_owned || cancel_owned || owner_generation == 0) return false;
        cancel_generation = owner_generation;
        cancel_owned = true;
        phase = LocalGrpcDeadlineTimerPhase::CancelPending;
        return true;
    }

    bool reclaim_target(u32 event_generation) {
        if (!target_owned || event_generation != owner_generation) return false;
        target_owned = false;
        phase = cancel_owned ? LocalGrpcDeadlineTimerPhase::Retiring
                             : LocalGrpcDeadlineTimerPhase::Idle;
        if (reusable()) {
            owner_generation = 0;
            timespec_sec = 0;
            timespec_nsec = 0;
        }
        return true;
    }

    bool reclaim_cancel(u32 event_generation) {
        if (!cancel_owned || event_generation != cancel_generation) return false;
        cancel_owned = false;
        cancel_generation = 0;
        phase = target_owned ? LocalGrpcDeadlineTimerPhase::Retiring
                             : LocalGrpcDeadlineTimerPhase::Idle;
        if (reusable()) {
            owner_generation = 0;
            timespec_sec = 0;
            timespec_nsec = 0;
        }
        return true;
    }
};

static_assert(__builtin_offsetof(LocalGrpcDeadlineTimerOwner, timespec_sec) == 0);
static_assert(__builtin_offsetof(LocalGrpcDeadlineTimerOwner, timespec_nsec) == sizeof(i64));

}  // namespace rut
