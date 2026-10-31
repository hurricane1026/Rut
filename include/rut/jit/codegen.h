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

// Format the JIT symbol for a WebSocket message handler (ws_handler_<id>).
// Returns the output length excluding the trailing '\0'.
u32 format_ws_handler_symbol(u32 id, char* out, u32 out_size);

// Postorder message-condition forest, mirroring WsLenGuard without a HIR dependency.
struct WsLenGuardSpec {
    static constexpr u32 kMaxConditions = 32;
    static constexpr u32 kMaxGuards = 4;
    u8 accessor;  // WsLenGuard::Accessor ordinal: 0=Len (message.len, i64 param 3),
                  //                                1=Opcode (internal message type, i8 param 1),
                  //                                2=FromClient (direction, i8 param 4),
                  //                                3=TextMatch (regex over payload, params 2+3)
                  //                                4=And, 5=Or (short-circuit child conditions)
                  //                                6=TextEqual (byte-exact literal equality)
                  //                                7=TextPrefix, 8=TextSuffix, 9=TextContains,
                  //                                10=JsonValid, 11=JsonHasPath
    u8 cmp;       // WsLenGuard::Cmp ordinal: 0=Lt, 1=Gt, 2=Eq
    u32 bound;    // Len: the byte literal; Opcode: the WsOpcode value (Text=1, Binary=2);
                  // FromClient: 1 (client→upstream leg)
    u8 verdict;   // WsFrameAction yielded when the guard CONDITION is false
    // TextMatch/TextEqual/TextPrefix/TextSuffix/TextContains: regex or decoded literal (pattern_len
    // is authoritative).
    const char* pattern;
    u32 pattern_len;
    u8 negate;    // invert this condition, including a compound subtree
    u32 lhs = 0;  // And/Or child indices, strictly less than the parent index
    u32 rhs = 0;
    bool is_operand = false;
};

// Emit a WebSocket terminate-mode message handler into `mod`:
//   i8 ws_handler_<id>(i8* ctx, i8 opcode, i8* payload, i64 len, i8 from_client)
// matching WsMessageHandlerFn (WsFrameAction(*)(void*, WsOpcode, const u8*, u64, bool)). It checks
// each guard root in order, with short-circuit &&/|| — the first FALSE root returns
// its verdict — then returns `default_verdict`. Verdicts are WsFrameAction values
// (Forward=0/Drop=1/Close=2/ForwardText=3/ClosePolicy0..3=4..7/ForwardTextPolicy0..3=8..11).
// ForwardText is the default replacement; indexed branch policies use route-owned metadata. This
// bypasses the RIR/MIR HTTP pipeline. Returns false on error.
bool emit_ws_handler(LLVMModuleRef mod,
                     LLVMContextRef ctx,
                     u8 default_verdict,
                     const WsLenGuardSpec* guards,
                     u32 guard_count,
                     u32 id);

// Create a fresh LLVM module holding a single message handler. Mirrors codegen() for the WS path;
// hand {mod,ctx} to JitEngine::compile and look up ws_handler_<id>.
CodegenResult codegen_ws_handler(u8 default_verdict,
                                 const WsLenGuardSpec* guards,
                                 u32 guard_count,
                                 u32 id);

}  // namespace rut::jit
