#pragma once

#include "rut/common/types.h"

#include <pthread.h>

// Forward-declare LLVM C API opaque types to avoid pulling LLVM headers
// into runtime code. The actual LLVM headers are only included in
// jit_engine.cc and codegen.cc.
using LLVMOrcLLJITRef = struct LLVMOrcOpaqueLLJIT*;
using LLVMModuleRef = struct LLVMOpaqueModule*;
using LLVMContextRef = struct LLVMOpaqueContext*;

namespace rut::jit {

// IR optimization level applied to each handler module before LLJIT does
// final codegen. O0 skips the mid-level pipeline entirely (fastest
// compile / startup, least optimized code); O1..O3 run `default<O1..O3>`.
// Higher levels trade longer startup compile time for faster handlers.
enum class OptLevel : u8 {
    O0 = 0,
    O1 = 1,
    O2 = 2,
    O3 = 3,
};

// ── JIT Engine ─────────────────────────────────────────────────────
// Wraps LLVM ORC LLJIT via the C API. Compiles LLVM IR modules to
// native code and resolves symbols (including runtime helpers).
//
// Thread safety:
//   - init() / shutdown() on main thread only
//   - compile() is serialized by JitEngine; lookup() uses LLJIT's internal locks
//   - JIT'd function pointers are plain C calls, no LLVM dependency
//
// Lifetime:
//   - One JitEngine per process (not per shard)
//   - Shard threads never touch JitEngine — only call JIT'd fn ptrs

struct JitEngine {
    LLVMOrcLLJITRef lljit = nullptr;

    // Orphaned LLVMContextRefs from compile(). LLVM < 19 can't wrap an
    // existing context into a ThreadSafeContext, so the module's context
    // must be freed separately after LLJIT destroys the module.
    static constexpr u32 kMaxContexts = 64;
    LLVMContextRef contexts[kMaxContexts];
    u32 ctx_count = 0;

    pthread_mutex_t compile_mutex = PTHREAD_MUTEX_INITIALIZER;

    // Precompiled regex databases referenced by JIT modules. prepare_regex_symbols()
    // writes each compiled database pointer directly into the corresponding LLVM
    // global initializer; slots retain the handles so engine teardown can free them.
    struct RegexSlot {
        char symbol[96];
        void* db = nullptr;
    };
    RegexSlot** regex_slots = nullptr;
    u32 regex_slot_count = 0;
    u32 regex_slot_cap = 0;

    // IR optimization level for compile(). Set before calling compile();
    // defaults to O2. See OptLevel.
    OptLevel opt_level = OptLevel::O2;

    bool init();

    // Compile an LLVM IR module to native code.
    // Always takes ownership of both mod and ctx regardless of return value.
    bool compile(LLVMModuleRef mod, LLVMContextRef ctx);
    RegexSlot* alloc_regex_slot();
    bool prepare_regex_symbols(LLVMModuleRef mod, u32* out_start_count);
    void rollback_regex_symbols(u32 start_count);

    void* lookup(const char* name);
    void shutdown();
};

}  // namespace rut::jit
