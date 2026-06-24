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

// A `guard frame.len <cmp> bound else { <verdict> }` check for the frame-handler codegen.
// Mirrors HirWsHandler::WsLenGuard but stays hir-free so the serve loader can build it.
struct WsLenGuardSpec {
    u8 accessor;  // WsLenGuard::Accessor ordinal: 0=Len (frame.len, i64 param 3),
                  //                                1=Opcode (frame opcode, i8 param 1)
    u8 cmp;       // WsLenGuard::Cmp ordinal: 0=Lt, 1=Gt, 2=Eq
    u32 bound;    // Len: the byte literal; Opcode: the WsOpcode value (Text=1, Binary=2)
    u8 verdict;   // WsFrameAction yielded when the guard CONDITION is false
};

// Emit a WebSocket terminate-mode frame handler into `mod`:
//   i8 ws_handler_<id>(i8* ctx, i8 opcode, i8* payload, i64 len)
// matching WsMessageHandlerFn (WsFrameAction(*)(void*, WsOpcode, const u8*, u64)). It checks
// each guard against `len` (= frame.len) in order — the first whose condition is FALSE returns
// that guard's verdict — then returns `default_verdict`. Verdicts are WsFrameAction values
// (Forward=0/Drop=1/Close=2). This bypasses the RIR/MIR HTTP pipeline. Returns false on error.
bool emit_ws_handler(LLVMModuleRef mod,
                     LLVMContextRef ctx,
                     u8 default_verdict,
                     const WsLenGuardSpec* guards,
                     u32 guard_count,
                     u32 id);

// Create a fresh LLVM module holding a single frame handler. Mirrors codegen() for the WS path;
// hand {mod,ctx} to JitEngine::compile and look up ws_handler_<id>.
CodegenResult codegen_ws_handler(u8 default_verdict,
                                 const WsLenGuardSpec* guards,
                                 u32 guard_count,
                                 u32 id);

}  // namespace rut::jit
