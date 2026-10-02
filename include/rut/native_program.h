#pragma once

#include "rut/common/access_log_sink.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/listener.h"
#include "rut/runtime/route_table.h"

namespace rut {
// Owns native code and configuration until every shard has joined.
struct NativeProgram {
    RouteConfig config;
    bool has_listener = false;
    ListenerSpec listener{};
    AccessLogSinkSpec access_log{};
    void* library = nullptr;
    i32 artifact_fd = -1;  // sealed, anonymous artifact; retained for unique dlopen identity
    void** regex_handles = nullptr;
    u32 regex_count = 0;
    MmapArena arena;
    void destroy();
};
bool load_native_program(
    const char* source, NativeProgram& out, char* error, u32 error_size, u8 opt = 2);
void activate_native_program(const NativeProgram& program);
}  // namespace rut
