#pragma once

#include "rut/common/types.h"
#include "rut/common/ws_control_flow.h"
#include "rut/common/ws_message.h"

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

// A synchronous message entry uses ordinary RIR evaluation, with two additional
// private u8 inputs after HandlerFn's five parameters: opcode and direction.
// The returned module is owned by the caller. A supplied context is borrowed;
// otherwise the result owns its newly created context, as with codegen().
CodegenResult codegen_ws_body(const rir::Module& rir_mod, LLVMContextRef shared_context = nullptr);

// Format the JIT symbol for a WebSocket message handler (ws_handler_<id>).
// Returns the output length excluding the trailing '\0'.
u32 format_ws_handler_symbol(u32 id, char* out, u32 out_size);
u32 format_ws_callback_symbol(u32 id, WsCallbackPhase phase, char* out, u32 out_size);

// Link a separately lowered synchronous body into the route module and expose
// it through the existing ws_handler_<id> callback ABI. No HTTP route is added.
// Failure leaves the module unpublishable; its owner must dispose it.
bool emit_ws_body(LLVMModuleRef module,
                  LLVMContextRef context,
                  const rir::Module& body,
                  u32 handler_id,
                  WsCallbackPhase phase = WsCallbackPhase::Message);

// Postorder message-condition forest, mirroring WsLenGuard without a HIR dependency.
struct WsLenGuardSpec {
    static constexpr u32 kMaxConditions = 32;
    static constexpr u32 kMaxGuards = 4;  // sequential roots; explicit graphs share 32 nodes
    u8 accessor;  // WsLenGuard::Accessor ordinal: 0=Len (message.len, i64 param 3),
                  //                                1=Opcode (internal message type, i8 param 1),
                  //                                2=FromClient (direction, i8 param 4),
                  //                                3=TextMatch (regex over payload, params 2+3)
                  //                                4=And, 5=Or (short-circuit child conditions)
                  //                                6=TextEqual (byte-exact literal equality)
                  //                                7=TextPrefix, 8=TextSuffix, 9=TextContains,
                  //                                10=JsonValid, 11=JsonHasPath,
                  //                                12=JsonStringValid,
                  //                                13=JsonStringEqual,
                  //                                14=JsonStringPrefix,
                  //                                15=JsonStringSuffix,
                  //                                16=JsonStringContains,
                  //                                17=JsonBoolValid,
                  //                                18=JsonBoolEqual,
                  //                                19=JsonIntValid,
                  //                                20=JsonIntCompare,
                  //                                21=JsonKindEqual,
                  //                                22=JsonCountValid,
                  //                                23=JsonCountCompare,
                  //                                24=JsonNumberTextValid,
                  //                                25=JsonNumberTextEqual,
                  //                                26=JsonNumberTextPrefix,
                  //                                27=JsonNumberTextSuffix,
                  //                                28=JsonNumberTextContains,
                  //                                29=JsonStringifyValid,
                  //                                30=JsonStringifyEqual,
                  //                                31=JsonStringifyPrefix,
                  //                                32=JsonStringifySuffix,
                  //                                33=JsonStringifyContains,
                  //                                34=JsonStringRegex (path + regex in value)
                  //                                35=Constant (bound is 0 or 1)
                  //                                36=BoolEqual (lhs/rhs, evaluated once each)
                  //                                37=BoolSelect (bound selector, lhs true, rhs
                  //                                false)
    u8 cmp;       // WsLenGuard::Cmp ordinal: 0=Lt, 1=Gt, 2=Eq
    u32 bound;    // Len: the byte literal; Opcode: the WsOpcode value (Text=1, Binary=2);
                  // FromClient: 1 (client→upstream leg); BoolSelect: selector child index
    u8 verdict;   // WsFrameAction yielded when the guard CONDITION is false
    // TextMatch/TextEqual/TextPrefix/TextSuffix/TextContains: regex or decoded literal (pattern_len
    // is authoritative).
    const char* pattern;
    u32 pattern_len;
    const char* value = nullptr;  // JSON predicates: literal bytes; JsonStringRegex: regex literal.
    u32 value_len = 0;
    // JsonBoolEqual: expected bool, stored in `bound`.
    i64 int_bound = 0;  // JsonIntCompare: i64; JsonCountCompare: validated i32.
    u8 negate;          // invert this condition, including a compound subtree
    u32 lhs = 0;        // And/Or child indices, strictly less than the parent index
    u32 rhs = 0;
    bool is_operand = false;
    // Root-only forward control edges, encoded by common/ws_control_flow.h.
    u32 pass_target = kWsControlNext;
    u32 fail_target = kWsControlNext;
};

// Emit a WebSocket terminate-mode message handler into `mod`:
//   i8 ws_handler_<id>(i8* ctx, i8 opcode, i8* payload, i64 len, i8 from_client)
// matching WsMessageHandlerFn (WsFrameAction(*)(void*, WsOpcode, const u8*, u64, bool)).
// Unset control targets check roots in order: the first false root returns its
// verdict, then the default verdict follows the last root. Explicit targets select
// later roots, forward continuation boundaries, known verdicts or the default.
// Predicate &&/|| remain lazy. Verdicts are WsFrameAction values
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
