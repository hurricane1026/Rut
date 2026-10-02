#include "rut/native_artifact.h"

#include "rut/jit/codegen.h"
#include "rut/jit/runtime_helpers.h"
#include "rut/serve_loader.h"

#include <errno.h>
#include <llvm-c/Core.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

namespace rut {
bool write_native_program(LoadedProgram& p, const char* output) {
    if (!p.native_module) return false;
    MmapArena arena;
    if (!arena.init(4096)) return false;
    struct Cleanup {
        MmapArena& a;
        ~Cleanup() { a.destroy(); }
    } cleanup{arena};
    auto& c = p.config;
    u32 view_count = 0;
    u64 string_bytes = 0;
    const uintptr_t begin = reinterpret_cast<uintptr_t>(&c);
    auto internal = [&](const char* ptr, u32 len) {
        auto addr = reinterpret_cast<uintptr_t>(ptr);
        return addr >= begin && addr - begin <= sizeof(c) && len <= sizeof(c) - (addr - begin);
    };
    if (!native::visit_views(c, [&](const char*& ptr, u32 len) {
            if (ptr) {
                view_count++;
                if (!internal(ptr, len)) string_bytes += len + 1;
            }
            return ptr || len == 0;
        }))
        return false;
    const u32 regex_count = p.engine.regex_slot_count;
    struct Database {
        char* data;
        u64 size;
    };
    auto* databases = arena.alloc_array<Database>(regex_count);
    if (regex_count && !databases) return false;
    struct DatabaseCleanup {
        Database* databases;
        u32 count;
        ~DatabaseCleanup() {
            for (u32 i = 0; i < count; i++) free(databases[i].data);
        }
    } database_cleanup{databases, regex_count};
    u64 regex_bytes = 0;
    for (u32 i = 0; i < regex_count; i++) {
        if (!rut_helper_regex_serialize(
                p.engine.regex_slots[i]->db, &databases[i].data, &databases[i].size))
            return false;
        if (databases[i].size > 0xffffffffu) return false;
        regex_bytes += databases[i].size;
    }
    u32 symbol_count = c.timer_count;
    for (u32 i = 0; i < c.route_count; i++) {
        if (c.routes[i].fn) symbol_count++;
        if (c.routes[i].ws_frame_handler) symbol_count++;
    }
    u64 size = sizeof(native::Header) + sizeof(RouteEntry) * c.route_count +
               ((native::metadata_size(c) + 7u) & ~7u) + sizeof(native::Relocation) * view_count +
               sizeof(native::Symbol) * symbol_count + sizeof(native::Regex) * regex_count +
               string_bytes + regex_bytes;
    if (size > 0xffffffffu) return false;
    auto* bytes = static_cast<u8*>(arena.alloc(size));
    if (!bytes) return false;
    memset(bytes, 0, size);
    auto* h = reinterpret_cast<native::Header*>(bytes);
    *h = {native::kMagic,
          native::kVersion,
          sizeof(c),
          size,
          native::metadata_size(c),
          c.route_count,
          view_count,
          symbol_count,
          regex_count,
          c.dispatch_kind(),
          p.has_listener,
          p.listener,
          p.access_log};
    u64 pos = sizeof(*h);
    memcpy(bytes + pos, c.routes, sizeof(RouteEntry) * c.route_count);
    auto* routes = reinterpret_cast<RouteEntry*>(bytes + pos);
    pos += sizeof(RouteEntry) * c.route_count;
    auto* metadata = bytes + pos;
    memcpy(metadata, reinterpret_cast<u8*>(&c) + native::metadata_offset(c), h->metadata_size);
    pos += (h->metadata_size + 7u) & ~7u;
    auto* relocs = reinterpret_cast<native::Relocation*>(bytes + pos);
    pos += sizeof(*relocs) * view_count;
    auto* symbols = reinterpret_cast<native::Symbol*>(bytes + pos);
    pos += sizeof(*symbols) * symbol_count;
    auto* regexes = reinterpret_cast<native::Regex*>(bytes + pos);
    pos += sizeof(*regexes) * regex_count;
    auto field = [&](const void* ptr) {
        return static_cast<u32>(reinterpret_cast<uintptr_t>(ptr) - begin);
    };
    auto clear_field = [&](u32 offset) {
        if (offset < sizeof(RouteEntry) * c.route_count)
            memset(reinterpret_cast<u8*>(routes) + offset, 0, sizeof(void*));
        else
            memset(metadata + offset - native::metadata_offset(c), 0, sizeof(void*));
    };
    u32 r = 0;
    if (!native::visit_views(c, [&](const char*& ptr, u32 len) {
            if (!ptr) return true;
            auto& fix = relocs[r++];
            fix.field = field(reinterpret_cast<const void*>(&ptr));
            if (internal(ptr, len))
                fix.config_offset = field(ptr);
            else {
                fix.blob_offset = pos;
                memcpy(bytes + pos, ptr, len);
                pos += len + 1;
            }
            clear_field(fix.field);
            return true;
        }))
        return false;
    u32 s = 0;
    auto add_symbol = [&](const void* slot, const char* name) {
        auto& sym = symbols[s++];
        sym.field = field(slot);
        snprintf(sym.name, sizeof(sym.name), "%s", name);
        clear_field(sym.field);
    };
    for (u32 i = 0; i < c.route_count; i++) {
        auto& route = c.routes[i];
        if (route.fn) {
            bool found = false;
            for (u32 j = 0; j < p.rir.module.func_count; j++) {
                char name[256];
                jit::format_handler_symbol(p.rir.module.functions[j].name, name, sizeof(name));
                if (p.engine.lookup(name) == reinterpret_cast<void*>(route.fn)) {
                    add_symbol(reinterpret_cast<const void*>(&route.fn), name);
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
        if (route.ws_frame_handler) {
            char name[64];
            // Terminate routes are appended in dense HIR order.
            u32 id = 0;
            for (u32 j = 0; j < i; j++)
                if (c.routes[j].ws_frame_handler) id++;
            jit::format_ws_handler_symbol(id, name, sizeof(name));
            add_symbol(reinterpret_cast<const void*>(&route.ws_frame_handler), name);
        }
    }
    for (u32 i = 0; i < c.timer_count; i++) {
        bool found = false;
        for (u32 j = 0; j < p.rir.module.func_count; j++) {
            char name[256];
            jit::format_handler_symbol(p.rir.module.functions[j].name, name, sizeof(name));
            if (p.engine.lookup(name) == reinterpret_cast<void*>(c.timers[i].fn)) {
                add_symbol(reinterpret_cast<const void*>(&c.timers[i].fn), name);
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    // File descriptors are process local; the serving loader recreates them.
    for (u32 i = 0; i < c.response_body_count; i++) {
        u32 zero = 0;
        memcpy(metadata + field(&c.response_bodies[i].file_ref) - native::metadata_offset(c),
               &zero,
               sizeof(zero));
    }
    for (u32 i = 0; i < regex_count; i++) {
        auto& regex = regexes[i];
        snprintf(regex.symbol, sizeof(regex.symbol), "%s", p.engine.regex_slots[i]->symbol);
        regex.database_offset = pos;
        regex.database_size = static_cast<u32>(databases[i].size);
        memcpy(bytes + pos, databases[i].data, databases[i].size);
        pos += databases[i].size;
        auto db = LLVMGetNamedGlobal(p.native_module, regex.symbol);
        if (!db) return false;
        LLVMSetInitializer(db, LLVMConstNull(LLVMGlobalGetValueType(db)));
        LLVMSetGlobalConstant(db, 0);
    }
    if (s != symbol_count || pos != size) return false;
    auto ctx = LLVMGetModuleContext(p.native_module);
    auto data = LLVMConstStringInContext(
        ctx, reinterpret_cast<const char*>(bytes), static_cast<u32>(size), 1);
    auto global = LLVMAddGlobal(p.native_module, LLVMTypeOf(data), "rut_native_config");
    LLVMSetInitializer(global, data);
    LLVMSetGlobalConstant(global, 1);
    LLVMSetAlignment(global, alignof(native::Header));
    auto size_global =
        LLVMAddGlobal(p.native_module, LLVMInt64TypeInContext(ctx), "rut_native_config_size");
    LLVMSetInitializer(size_global, LLVMConstInt(LLVMInt64TypeInContext(ctx), size, 0));
    LLVMSetGlobalConstant(size_global, 1);
    char object[4096];
    if (snprintf(object, sizeof(object), "%s.o", output) >= static_cast<int>(sizeof(object)))
        return false;
    struct ObjectCleanup {
        const char* path;
        ~ObjectCleanup() { unlink(path); }
    } object_cleanup{object};
    if (!jit::emit_native_object(p.native_module, object, p.engine.opt_level)) return false;
    pid_t child = fork();
    if (child == 0) {
        if (dup2(STDERR_FILENO, STDOUT_FILENO) < 0) _exit(127);
#ifdef __APPLE__
        execl(RUT_NATIVE_LINKER,
              RUT_NATIVE_LINKER,
              "-B",
              RUT_NATIVE_LINKER_DIR,
              "-dynamiclib",
              "-Wl,-undefined,dynamic_lookup",
              object,
              "-o",
              output,
              nullptr);
#else
        execl(RUT_NATIVE_LINKER,
              RUT_NATIVE_LINKER,
              "-B",
              RUT_NATIVE_LINKER_DIR,
              "-shared",
              "-nostdlib",
              "-Wl,-z,now",
              object,
              "-o",
              output,
              nullptr);
#endif
        _exit(127);
    }
    int status = 0;
    bool ok = false;
    if (child > 0) {
        pid_t waited;
        do {
            waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
        ok = waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    return ok;
}
}  // namespace rut
