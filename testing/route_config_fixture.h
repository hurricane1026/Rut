#pragma once

#include "rut/runtime/arena.h"
#include "rut/runtime/route_table.h"

namespace rut::test {

// Configuration snapshots are large and production owners already allocate
// them outside the thread stack. Use the same allocator in multi-snapshot tests.
struct RouteConfigFixture {
    MmapArena arena;
    RouteConfig* config = nullptr;

    RouteConfigFixture() {
        constexpr uintptr_t kAlignmentMask = alignof(RouteConfig) - 1;
        if (!arena.init(sizeof(RouteConfig) + 4096)) return;
        auto* storage = static_cast<u8*>(arena.alloc(sizeof(RouteConfig) + kAlignmentMask));
        if (!storage) return;
        const uintptr_t padding = -reinterpret_cast<uintptr_t>(storage) & kAlignmentMask;
        config = ::new (storage + padding) RouteConfig();
    }
    ~RouteConfigFixture() {
        if (config) config->~RouteConfig();
        arena.destroy();
    }
    RouteConfigFixture(const RouteConfigFixture&) = delete;
    RouteConfigFixture& operator=(const RouteConfigFixture&) = delete;
};

}  // namespace rut::test
