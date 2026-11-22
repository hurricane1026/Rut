#include "rut/runtime/yield_heap.h"

#include "rut/common/types.h"

namespace rut::yield_heap {
namespace {

// Each prefix is a min-heap. Siblings are deliberately unordered and two
// deadlines tie, so checking deadlines alone cannot prove survivor identity.
consteval bool removal_preserves_timers() {
    constexpr u64 kDue[] = {1, 4, 2, 9, 4, 3, 8};
    constexpr u32 kCount = sizeof(kDue) / sizeof(kDue[0]);
    for (u32 count = 0; count <= kCount; ++count) {
        for (u32 mask = 0; mask < (1u << count); ++mask) {
            Entry entries[kCount]{};
            u32 expected_survivors = 0;
            for (u32 i = 0; i < count; ++i) {
                const bool kCancel = (mask & (1u << i)) != 0;
                entries[i] = {kDue[i], i, kCancel ? 0u : 1u + i % 2};
                if (!kCancel) expected_survivors |= 1u << i;
            }
            u32 size = count;
            const u32 kRemoved = remove_by_conn(entries, size, 0);
            if (size > count || kRemoved != count - size) return false;
            for (u32 i = 0; i < size; ++i) {
                const auto& entry = entries[i];
                const u32 kGeneration = entry.handler_gen;
                if (kGeneration >= count || !(expected_survivors & (1u << kGeneration)) ||
                    entry.deadline_ns != kDue[kGeneration] || entry.conn_id != 1u + kGeneration % 2)
                    return false;
                expected_survivors &= ~(1u << kGeneration);
                if (i && entries[(i - 1) / 2].deadline_ns > entry.deadline_ns) return false;
            }
            if (expected_survivors != 0) return false;
        }
    }
    return true;
}

static_assert(removal_preserves_timers(),
              "Yield cancellation must preserve surviving timers and heap order");

}  // namespace
}  // namespace rut::yield_heap
