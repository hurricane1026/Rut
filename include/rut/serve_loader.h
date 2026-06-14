#pragma once

// Control-plane bridge: compile a `.rut` source file end to end and
// produce a RouteConfig the shards can serve.
//
// This is the seam that connects the three otherwise-separate halves of
// the project — the frontend (lex/parse/analyze), the JIT backend
// (RIR → LLVM → native), and the runtime (shards reading RouteConfig).
// Before this, the only place that wired them together end to end was
// the offline simulate harness (src/sim/), so the production `rut`
// binary could not actually run a user program.
//
// Lifetime contract: a LoadedProgram OWNS everything the running server
// transitively depends on:
//   - the JIT engine (it owns the native handler code the routes call),
//   - the lowered RIR arena (route patterns / response bodies live here),
//   - the source mmap (AST/RIR Str values may point back into it).
// It must therefore outlive every shard. Destroy it only after all
// shards have joined.
//
// Everything here runs once at startup on the main thread. It is NOT a
// hot path, so unlike the runtime it is free to use the compiler's
// heap-allocating frontend APIs.

#include "rut/compiler/diagnostic.h"
#include "rut/compiler/lower_rir.h"
#include "rut/jit/jit_engine.h"
#include "rut/runtime/route_table.h"

namespace rut {

// The pipeline stage a load failed at. Lex..Lower carry a Diagnostic
// (with source span); Codegen..Register do not (the JIT/bridge report
// success/failure as a bool), so format_load_error falls back to a
// static stage description for those.
enum class LoadStage : u8 {
    Read,
    Lex,
    Parse,
    Analyze,
    BuildMir,
    Lower,
    Codegen,
    JitCompile,
    Register,
};

struct LoadError {
    LoadStage stage = LoadStage::Read;
    bool has_diag = false;  // true iff `diag` was populated by the frontend
    Diagnostic diag{};
};

struct LoadedProgram {
    // Source file kept mapped for the whole process: AST/RIR string
    // views may reference these bytes.
    void* src_map = nullptr;
    u64 src_map_len = 0;

    FrontendRirModule rir;  // owns the lowered module + its arena
    jit::JitEngine engine;  // owns the native handler code
    bool jit_inited = false;
    RouteConfig config;  // what the shards read (1.28 MB — heap/BSS only)

    void destroy();
};

// Compile `path` end to end into `out`. On success returns true and
// `out.config` is ready to hand to shards. On failure returns false,
// fills `err`, and leaves `out` safe to destroy(). Fail-closed: a
// program that does not fully compile, JIT, and register yields no
// partial config.
//
// `opt` selects the JIT IR optimization level (higher = faster handlers,
// slower startup compile).
bool load_rut_program(const char* path,
                      LoadedProgram& out,
                      LoadError& err,
                      jit::OptLevel opt = jit::OptLevel::O2);

// Render a one-line, human-readable description of a load failure into
// `buf` (NUL-terminated, no allocation). Returns bytes written
// excluding the terminator.
u32 format_load_error(const LoadError& err, char* buf, u32 buf_size);

}  // namespace rut
