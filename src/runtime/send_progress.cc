#include "rut/runtime/send_progress.h"

#include "rut/common/types.h"

#include <stdint.h>

namespace rut {
namespace {
consteval bool send_progress_matches(u32 offset, u32 remaining, u32 completed) {
    const u64 kTotal = u64{offset} + remaining;
    const u64 kNext = u64{offset} + completed;
    const bool kValid = kTotal <= INT32_MAX && kNext > offset && kNext <= kTotal;
    u32 next_offset = offset;
    u32 next_remaining = remaining;
    if (advance_send_bytes(next_offset, next_remaining, completed) != kValid) return false;
    if (!kValid) return next_offset == offset && next_remaining == remaining;
    return next_offset == kNext && u64{next_offset} + next_remaining == kTotal;
}

consteval bool send_progress_contract() {
    constexpr u32 kCases[] = {0, 1, 2, 3, INT32_MAX - 1u, INT32_MAX, INT32_MAX + 1u, UINT32_MAX};
    for (const u32 kOffset : kCases)
        for (const u32 kRemaining : kCases)
            for (const u32 kCompleted : kCases)
                if (!send_progress_matches(kOffset, kRemaining, kCompleted)) return false;
    return true;
}

static_assert(send_progress_contract(), "Partial send violates byte accounting contract");
}  // namespace
}  // namespace rut
