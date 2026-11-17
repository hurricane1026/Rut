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
        if (arena.init(sizeof(RouteConfig) + 4096)) config = arena.alloc_t<RouteConfig>();
    }
    ~RouteConfigFixture() {
        if (config) config->~RouteConfig();
        arena.destroy();
    }
    RouteConfigFixture(const RouteConfigFixture&) = delete;
    RouteConfigFixture& operator=(const RouteConfigFixture&) = delete;
};

}  // namespace rut::test
