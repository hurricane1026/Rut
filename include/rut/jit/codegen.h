#pragma once

#include "rut/common/types.h"

// Forward declarations — avoid pulling LLVM headers into other code.
using LLVMModuleRef = struct LLVMOpaqueModule*;
using LLVMContextRef = struct LLVMOpaqueContext*;

namespace rut::rir {
struct Module;
}

namespace rut::jit {

// ── Codegen ────────────────────────────────────────────────────────
// Translates an RIR Module into an LLVM IR Module via the LLVM C API.
//
// Phase 1: handles sync handlers only (no yields). Each RIR Function
// becomes a single LLVM function with the HandlerFn signature.
//
// The returned LLVMModuleRef and LLVMContextRef are owned by the caller.
// Pass both to JitEngine::compile() which takes ownership.

struct CodegenResult {
    LLVMModuleRef mod;
    LLVMContextRef ctx;
    bool ok;
};

// Format the JIT handler symbol for an RIR function name.
// Returns the output length excluding the trailing '\0'.
u32 format_handler_symbol(Str name, char* out, u32 out_size);

// Translate all functions in the RIR module to LLVM IR.
// Returns {module, context, true} on success, {null, null, false} on error.
CodegenResult codegen(const rir::Module& rir_mod);

// Format the JIT symbol for a WebSocket frame handler (ws_handler_<id>).
// Returns the output length excluding the trailing '\0'.
u32 format_ws_handler_symbol(u32 id, char* out, u32 out_size);

// Emit a constant-verdict WebSocket terminate-mode frame handler into `mod`:
//   i8 ws_handler_<id>(i8* ctx, i8 opcode, i8* payload, i64 len) { ret i8 <verdict> }
// matching WsMessageHandlerFn (WsFrameAction(*)(void*, WsOpcode, const u8*, u64)). `verdict`
// is the WsFrameAction value (Forward=0/Drop=1/Close=2). A constant verdict needs no message
// inspection, so this bypasses the RIR/MIR HTTP pipeline. Returns false on error.
bool emit_ws_handler(LLVMModuleRef mod, LLVMContextRef ctx, u8 verdict, u32 id);

// Create a fresh LLVM module holding a single constant-verdict frame handler. Mirrors codegen()
// for the WS path; hand {mod,ctx} to JitEngine::compile and look up ws_handler_<id>.
CodegenResult codegen_ws_handler(u8 verdict, u32 id);

}  // namespace rut::jit
