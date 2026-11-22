#pragma once

#include "rut/common/types.h"

namespace rut::yield_heap {

struct Entry {
    u64 deadline_ns;
    u32 handler_gen;
    u32 conn_id;
};

constexpr void sift_down(Entry* entries, u32 size, u32 i) {
    while (true) {
        const u32 kLeft = 2 * i + 1;
        const u32 kRight = 2 * i + 2;
        u32 smallest = i;
        if (kLeft < size && entries[kLeft].deadline_ns < entries[smallest].deadline_ns)
            smallest = kLeft;
        if (kRight < size && entries[kRight].deadline_ns < entries[smallest].deadline_ns)
            smallest = kRight;
        if (smallest == i) break;
        const Entry kSaved = entries[smallest];
        entries[smallest] = entries[i];
        entries[i] = kSaved;
        i = smallest;
    }
}

// Remove every entry with this conn_id in O(n). Compact before rebuilding
// the heap: sifting during the scan can move another matching tail entry
// into an already-scanned prefix and leave a stale timer behind.
constexpr u32 remove_by_conn(Entry* entries, u32& size, u32 conn_id) {
    u32 kept = 0;
    for (u32 i = 0; i < size; ++i) {
        if (entries[i].conn_id != conn_id) entries[kept++] = entries[i];
    }
    const u32 kRemoved = size - kept;
    size = kept;
    if (kRemoved > 0) {
        for (u32 i = size / 2; i > 0; --i) sift_down(entries, size, i - 1);
    }
    return kRemoved;
}

}  // namespace rut::yield_heap
