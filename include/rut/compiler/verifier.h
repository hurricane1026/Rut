#pragma once

#include "rut/common/request_policy.h"
#include "rut/common/ws_message.h"
#include "rut/compiler/concurrency_verifier.h"
#include "rut/compiler/http_call_profile.h"
#include "rut/compiler/password_profile.h"
#include "rut/compiler/rir.h"
#include "rut/compiler/rir_printer.h"
#include "rut/jit/handler_abi.h"
#include "rut/runtime/route_method.h"

namespace rut {
namespace rir {

enum class VerifyIssueCode : u8 {
    None,
    MissingFunction,
    MissingBlocks,
    MissingEntry,
    BlockIdMismatch,
    MissingInstructions,
    MissingTerminator,
    TerminatorBeforeEnd,
    InvalidBranchTarget,
    InvalidJumpTarget,
    InvalidRedirectPolicyId,
    InvalidUnmatchedPolicyId,
    InvalidExactStrictLocalResponseBinding,
    InvalidStateZeroEntry,
    InvalidResumeBlock,
    MissingYieldResumeMapping,
    MissingYieldMetadata,
    UnsupportedYieldTerminator,
    InvalidYieldKind,
    InvalidYieldNextState,
    DuplicateYieldNextState,
    MissingYieldNextState,
    YieldMetadataMismatch,
    InvalidYieldRuntimeProtocol,
    InvalidHandlerAutomaton,
    InvalidRuntimeStateModel,
    NonYieldingControlCycle,
    HandlerLivelock,
    HandlerDeadlock,
    ConcurrentProtocolFailure,
    ConcurrentVerificationLimit,
    YieldCountMismatch,
    TooManyYieldStates,
    TooManyBlocks,
    UnreachableBlock,
    InvalidForwardPreflight,
    InvalidHttpCachePolicy,
    InvalidPreRoutePolicyId,
    InvalidJwtClaimsLifetime,
    InvalidPasswordPrefix,
    InvalidHttpCallProfile,
    InvalidStrLength,
    InvalidStringOperation,
    InvalidWsMessageField,
    InvalidWsOutput,
    InvalidPhi,
    InvalidBytesSubscript,
    InvalidIntegerParse,
};

struct VerifyIssue {
    VerifyIssueCode code = VerifyIssueCode::None;
    u32 function_index = 0;
    u32 block_index = 0;
    u32 inst_index = 0;
    u32 target_index = 0;
    u32 detail_index = 0;
    static constexpr u32 kMaxTrace = 32;
    u32 trace[kMaxTrace]{};
    u8 trace_actors[kMaxTrace]{};
    u8 trace_count = 0;
    u8 cycle_start = 255;
    bool trace_truncated = false;
    bool trace_is_protocol = false;
    bool trace_has_actors = false;
};

struct VerifySummary {
    u32 function_count = 0;
    u32 block_count = 0;
    u32 reachable_block_count = 0;
    u32 terminal_block_count = 0;
    u32 yield_count = 0;
    u32 branch_edge_count = 0;
};

// Shared boundary validation for Bytes lookup and bounded String operations. Codegen also
// checks direct RIR clients before indexing operands or allocating LLVM arrays.
inline bool valid_bytes_read(const Function& fn, const Instruction& inst) {
    if (inst.op != Opcode::JsonOp) return true;
    const auto spec = json::bytes_read_spec(static_cast<json::Op>(inst.imm.i32_val));
    if (!spec.width) return true;
    const auto kType = [&](ValueId id) -> const Type* {
        return id != kNoValue && id.id < fn.value_count && fn.values ? fn.values[id.id].type
                                                                     : nullptr;
    };
    const auto kExact = [&](ValueId id, TypeKind kind) {
        const Type* type = kType(id);
        return type && type->kind == kind && !type->inner && !type->struct_def;
    };
    const Type* result = kType(inst.result);
    return inst.operand_count == 2 && !inst.extra_operands &&
           kExact(inst.operands[0], TypeKind::Str) && kExact(inst.operands[1], TypeKind::I32) &&
           result && result->kind == TypeKind::Optional && !result->struct_def && result->inner &&
           result->inner->kind == (spec.wide ? TypeKind::I64 : TypeKind::I32) &&
           !result->inner->inner && !result->inner->struct_def;
}

inline bool valid_bytes_field(const Function& fn, const Instruction& inst) {
    if (inst.op != Opcode::JsonOp) return true;
    const auto kOp = static_cast<json::Op>(inst.imm.i32_val);
    if (kOp != json::Op::BytesSlice && kOp != json::Op::BytesFind && kOp != json::Op::BytesConcat)
        return true;
    if (inst.operand_count != 3 || inst.extra_operands) return false;
    const auto kExact = [&](ValueId id, TypeKind kind) {
        if (id == kNoValue || id.id >= fn.value_count || !fn.values) return false;
        const Type* type = fn.values[id.id].type;
        return type && type->kind == kind && !type->inner && !type->struct_def;
    };
    if (!kExact(inst.operands[0], TypeKind::Str) ||
        !kExact(inst.operands[1], kOp == json::Op::BytesSlice ? TypeKind::I32 : TypeKind::Str) ||
        !kExact(inst.operands[2], TypeKind::I32) || inst.result == kNoValue ||
        inst.result.id >= fn.value_count || !fn.values)
        return false;
    const Type* result = fn.values[inst.result.id].type;
    return result && result->kind == TypeKind::Optional && !result->struct_def && result->inner &&
           result->inner->kind == (kOp == json::Op::BytesFind ? TypeKind::I32 : TypeKind::Str) &&
           !result->inner->inner && !result->inner->struct_def;
}

inline bool valid_bytes_construction(const Function& fn, const Instruction& inst) {
    if (inst.op != Opcode::JsonOp) return true;
    const auto kOp = static_cast<json::Op>(inst.imm.i32_val);
    if (kOp != json::Op::FormatInt && kOp != json::Op::BytesFromString) return true;
    if (inst.operand_count != 1 || inst.extra_operands || !fn.values ||
        inst.operands[0] == kNoValue || inst.operands[0].id >= fn.value_count ||
        inst.result == kNoValue || inst.result.id >= fn.value_count)
        return false;
    const Type* input = fn.values[inst.operands[0].id].type;
    const Type* result = fn.values[inst.result.id].type;
    if (!input || input->inner || input->struct_def || !result || result->struct_def) return false;
    if (kOp == json::Op::BytesFromString)
        return input->kind == TypeKind::Str && result->kind == TypeKind::Str && !result->inner;
    return (input->kind == TypeKind::I32 || input->kind == TypeKind::I64) &&
           result->kind == TypeKind::Optional && result->inner &&
           result->inner->kind == TypeKind::Str && !result->inner->inner &&
           !result->inner->struct_def;
}

inline bool valid_integer_parse(const Function& fn, const Instruction& inst) {
    if (inst.op != Opcode::JsonOp) return true;
    const auto op = static_cast<json::Op>(inst.imm.i32_val);
    if (op != json::Op::ParseInt && op != json::Op::ParseInt64) return true;
    if (inst.operand_count != 1 || inst.extra_operands) return false;
    const auto type_of = [&](ValueId id) -> const Type* {
        return id != kNoValue && id.id < fn.value_count && fn.values ? fn.values[id.id].type
                                                                     : nullptr;
    };
    const Type* input = type_of(inst.operands[0]);
    const Type* result = type_of(inst.result);
    return input && input->kind == TypeKind::Str && !input->inner && !input->struct_def && result &&
           result->kind == TypeKind::Optional && !result->struct_def && result->inner &&
           result->inner->kind == (op == json::Op::ParseInt64 ? TypeKind::I64 : TypeKind::I32) &&
           !result->inner->inner && !result->inner->struct_def;
}

inline bool valid_string_instruction(const Function& fn, const Instruction& inst) {
    if (inst.op != Opcode::StrPredicate && inst.op != Opcode::StrInterpolate) return true;
    if (inst.operand_count <= kMaxInlineOperands && inst.extra_operands) return false;
    const auto kExact = [&](ValueId id, TypeKind kind) {
        if (id == kNoValue || id.id >= fn.value_count || !fn.values) return false;
        const Type* type = fn.values[id.id].type;
        return type && type->kind == kind && !type->inner && !type->struct_def;
    };
    if (inst.op == Opcode::StrPredicate) {
        return inst.operand_count == 2 && inst.imm.i32_val >= 0 && inst.imm.i32_val <= 3 &&
               kExact(inst.result, TypeKind::Bool) && kExact(inst.operand(0), TypeKind::Str) &&
               kExact(inst.operand(1), TypeKind::Str);
    }
    if (inst.operand_count == 0 || inst.operand_count > 64 ||
        (inst.operand_count > kMaxInlineOperands && !inst.extra_operands) ||
        !kExact(inst.result, TypeKind::Str))
        return false;
    for (u32 i = 0; i < inst.operand_count; ++i)
        if (!kExact(inst.operand(i), TypeKind::Str)) return false;
    return true;
}

// An optional finite contract for known peers. Bindings refer to this
// function's actual RIR yield blocks; handlers are generated, not hand-copied
// into the peer model. Unknown network peers have no inferred behavior.
struct VerifyPeerBinding {
    u32 block_index = 0;
    u64 submit_set = 0;
    u64 completion_set = 0;
    u64 completion_clear = 0;
};

struct VerifyPeerEnvironment {
    u32 function_index = 0;
    const verify::Model* model = nullptr;
    const VerifyPeerBinding* bindings = nullptr;
    u32 binding_count = 0;
};

struct VerifyOptions {
    // Rut route automata should not carry dead blocks: dead IR makes later
    // verifier traces ambiguous and can hide stale lowering paths.
    bool require_all_blocks_reachable = true;
    verify::Limits concurrency_limits{};
    const VerifyPeerEnvironment* environment = nullptr;
};

struct VerifyResult {
    bool ok = true;
    VerifyIssue issue{};
    VerifySummary summary{};
};

inline VerifyResult verify_fail(VerifySummary summary,
                                VerifyIssueCode code,
                                u32 function_index,
                                u32 block_index = 0,
                                u32 inst_index = 0,
                                u32 target_index = 0,
                                u32 detail_index = 0) {
    VerifyResult result{};
    result.ok = false;
    result.summary = summary;
    result.issue.code = code;
    result.issue.function_index = function_index;
    result.issue.block_index = block_index;
    result.issue.inst_index = inst_index;
    result.issue.target_index = target_index;
    result.issue.detail_index = detail_index;
    return result;
}

inline bool verify_valid_yield_kind(u8 kind) {
    switch (static_cast<jit::YieldKind>(kind)) {
        case jit::YieldKind::Timer:
        case jit::YieldKind::Any:
        case jit::YieldKind::Recv:
        case jit::YieldKind::Send:
        case jit::YieldKind::UpstreamConnect:
        case jit::YieldKind::UpstreamRecv:
        case jit::YieldKind::UpstreamSend:
            return true;
        case jit::YieldKind::HttpGet:
        case jit::YieldKind::HttpPost:
        case jit::YieldKind::Forward:
            return false;
    }
    return false;
}

enum class VerifyYieldRuntimeClass : u8 {
    Timer,
    Event,
    Unsupported,
};

enum class VerifyRuntimePendingOp : u8 {
    None,
    Timer,
    DownstreamRecv,
    DownstreamSend,
    UpstreamConnect,
    UpstreamRecv,
    UpstreamSend,
};

enum class VerifyRuntimeCallbackSlot : u8 {
    None,
    HandlerTimer,
    DownstreamRecv,
    DownstreamSend,
    UpstreamRecv,
    UpstreamSend,
};

enum class VerifyRuntimeProtocolReason : u8 {
    Ok,
    UnsupportedEventYield,
    MissingUpstreamTarget,
};

enum class VerifyRuntimeTransitionKind : u8 {
    Submit,
    Complete,
    FailClosed,
};

struct VerifyRuntimeProtocolCheck {
    bool ok = false;
    VerifyRuntimeProtocolReason reason = VerifyRuntimeProtocolReason::Ok;
    VerifyRuntimePendingOp pending_op = VerifyRuntimePendingOp::None;
    VerifyRuntimeCallbackSlot callback_slot = VerifyRuntimeCallbackSlot::None;
    VerifyRuntimePendingOp secondary_pending_op = VerifyRuntimePendingOp::None;
    VerifyRuntimeCallbackSlot secondary_callback_slot = VerifyRuntimeCallbackSlot::None;
    bool submit_transition = false;
    bool completion_transition = false;
    bool fail_closed_transition = false;
    u8 submit_transition_count = 0;
    u8 completion_transition_count = 0;
    u8 fail_closed_transition_count = 0;
};

struct VerifyRuntimeProtocolModel {
    static VerifyRuntimeProtocolCheck check_yield(u8 kind, u32 payload) {
        VerifyRuntimeProtocolCheck check{};
        switch (static_cast<jit::YieldKind>(kind)) {
            case jit::YieldKind::Timer:
                check.ok = true;
                check.pending_op = VerifyRuntimePendingOp::Timer;
                check.callback_slot = VerifyRuntimeCallbackSlot::HandlerTimer;
                check.submit_transition = true;
                check.completion_transition = true;
                check.fail_closed_transition = true;
                check.submit_transition_count = 1;
                check.completion_transition_count = 1;
                check.fail_closed_transition_count = 1;
                return check;
            case jit::YieldKind::Any:
            case jit::YieldKind::Recv:
            case jit::YieldKind::Send:
                check.ok = true;
                check.pending_op = VerifyRuntimePendingOp::DownstreamRecv;
                check.callback_slot = VerifyRuntimeCallbackSlot::DownstreamRecv;
                check.submit_transition = true;
                check.completion_transition = true;
                check.fail_closed_transition = true;
                check.submit_transition_count = 1;
                check.completion_transition_count = 1;
                check.fail_closed_transition_count = 1;
                if (static_cast<jit::YieldKind>(kind) == jit::YieldKind::Any && payload != 0) {
                    check.secondary_pending_op = VerifyRuntimePendingOp::Timer;
                    check.secondary_callback_slot = VerifyRuntimeCallbackSlot::HandlerTimer;
                    check.submit_transition_count = 2;
                    check.completion_transition_count = 2;
                    check.fail_closed_transition_count = 2;
                }
                if (static_cast<jit::YieldKind>(kind) == jit::YieldKind::Send) {
                    check.pending_op = VerifyRuntimePendingOp::DownstreamSend;
                    check.callback_slot = VerifyRuntimeCallbackSlot::DownstreamSend;
                    return check;
                }
                return check;
            case jit::YieldKind::UpstreamConnect:
                check.pending_op = VerifyRuntimePendingOp::UpstreamConnect;
                check.callback_slot = VerifyRuntimeCallbackSlot::UpstreamSend;
                if (payload == 0) {
                    check.reason = VerifyRuntimeProtocolReason::MissingUpstreamTarget;
                    return check;
                }
                check.ok = true;
                check.submit_transition = true;
                check.completion_transition = true;
                check.fail_closed_transition = true;
                check.submit_transition_count = 1;
                check.completion_transition_count = 1;
                check.fail_closed_transition_count = 1;
                return check;
            case jit::YieldKind::UpstreamRecv:
                check.pending_op = VerifyRuntimePendingOp::UpstreamRecv;
                check.callback_slot = VerifyRuntimeCallbackSlot::UpstreamRecv;
                if (payload == 0) {
                    check.reason = VerifyRuntimeProtocolReason::MissingUpstreamTarget;
                    return check;
                }
                check.ok = true;
                check.submit_transition = true;
                check.completion_transition = true;
                check.fail_closed_transition = true;
                check.submit_transition_count = 1;
                check.completion_transition_count = 1;
                check.fail_closed_transition_count = 1;
                return check;
            case jit::YieldKind::UpstreamSend:
                check.pending_op = VerifyRuntimePendingOp::UpstreamSend;
                check.callback_slot = VerifyRuntimeCallbackSlot::UpstreamSend;
                if (payload == 0) {
                    check.reason = VerifyRuntimeProtocolReason::MissingUpstreamTarget;
                    return check;
                }
                check.ok = true;
                check.submit_transition = true;
                check.completion_transition = true;
                check.fail_closed_transition = true;
                check.submit_transition_count = 1;
                check.completion_transition_count = 1;
                check.fail_closed_transition_count = 1;
                return check;
            case jit::YieldKind::HttpGet:
            case jit::YieldKind::HttpPost:
            case jit::YieldKind::Forward:
                check.reason = VerifyRuntimeProtocolReason::UnsupportedEventYield;
                return check;
        }
        check.reason = VerifyRuntimeProtocolReason::UnsupportedEventYield;
        return check;
    }
};

inline u8 verify_yield_default_arm_mask(u8 kind, u32 payload) {
    switch (static_cast<jit::YieldKind>(kind)) {
        case jit::YieldKind::Timer:
            return 1u << 0;
        case jit::YieldKind::Any:
            return static_cast<u8>((1u << 1) | (payload != 0 ? (1u << 0) : 0));
        case jit::YieldKind::Recv:
            return 1u << 1;
        case jit::YieldKind::Send:
            return 1u << 2;
        case jit::YieldKind::UpstreamConnect:
            return 1u << 3;
        case jit::YieldKind::UpstreamRecv:
            return 1u << 4;
        case jit::YieldKind::UpstreamSend:
            return 1u << 5;
        case jit::YieldKind::HttpGet:
        case jit::YieldKind::HttpPost:
        case jit::YieldKind::Forward:
            return 0;
    }
    return 0;
}

inline u8 verify_runtime_pending_op_arm_mask(VerifyRuntimePendingOp op) {
    switch (op) {
        case VerifyRuntimePendingOp::None:
            return 0;
        case VerifyRuntimePendingOp::Timer:
            return 1u << 0;
        case VerifyRuntimePendingOp::DownstreamRecv:
            return 1u << 1;
        case VerifyRuntimePendingOp::DownstreamSend:
            return 1u << 2;
        case VerifyRuntimePendingOp::UpstreamConnect:
            return 1u << 3;
        case VerifyRuntimePendingOp::UpstreamRecv:
            return 1u << 4;
        case VerifyRuntimePendingOp::UpstreamSend:
            return 1u << 5;
    }
    return 0;
}

inline u8 verify_runtime_callback_slot_mask(VerifyRuntimeCallbackSlot slot) {
    switch (slot) {
        case VerifyRuntimeCallbackSlot::None:
            return 0;
        case VerifyRuntimeCallbackSlot::HandlerTimer:
            return 1u << 0;
        case VerifyRuntimeCallbackSlot::DownstreamRecv:
            return 1u << 1;
        case VerifyRuntimeCallbackSlot::DownstreamSend:
            return 1u << 2;
        case VerifyRuntimeCallbackSlot::UpstreamRecv:
            return 1u << 3;
        case VerifyRuntimeCallbackSlot::UpstreamSend:
            return 1u << 4;
    }
    return 0;
}

enum class VerifyHandlerNodeKind : u8 {
    Terminal,
    Branch,
    Jump,
    Yield,
};

struct VerifyHandlerAutomatonNode {
    VerifyHandlerNodeKind kind = VerifyHandlerNodeKind::Terminal;
    u32 block_index = 0;
    u32 inst_index = 0;
    u32 target_count = 0;
    u32 targets[2]{};
    u8 yield_kind = 0;
    u32 yield_payload = 0;
    u8 wait_arm_mask = 0;
    u16 next_state = 0;
    VerifyRuntimeProtocolCheck runtime{};
};

struct VerifyHandlerAutomaton {
    static constexpr u32 kMaxNodes = 4096;
    VerifyHandlerAutomatonNode nodes[kMaxNodes]{};
    u32 node_count = 0;
    u32 edge_count = 0;
    u32 terminal_count = 0;
    u32 yield_count = 0;
    u32 runtime_submit_count = 0;
    u32 runtime_completion_count = 0;
    u32 runtime_fail_closed_count = 0;
};

VerifyResult verify_handler_concurrency(const VerifyHandlerAutomaton& automaton,
                                        u32 root,
                                        u32 function_index,
                                        VerifySummary summary,
                                        verify::Limits limits,
                                        const VerifyPeerEnvironment* environment);

enum class VerifyHandlerCheckIssueCode : u8 {
    None,
    MissingAutomaton,
    InvalidTarget,
    DeadEnd,
    NonYieldingCycle,
    MissingRuntimeTransition,
    CallbackSlotMismatch,
    WaitArmMaskMismatch,
};

struct VerifyHandlerCheckIssue {
    VerifyHandlerCheckIssueCode code = VerifyHandlerCheckIssueCode::None;
    u32 node_index = 0;
    u32 target_index = 0;
};

struct VerifyHandlerCheckResult {
    bool ok = true;
    VerifyHandlerCheckIssue issue{};
    u32 runtime_state_count = 0;
    u32 runtime_transition_count = 0;
};

inline VerifyYieldRuntimeClass verify_yield_runtime_class(u8 kind) {
    switch (static_cast<jit::YieldKind>(kind)) {
        case jit::YieldKind::Timer:
            return VerifyYieldRuntimeClass::Timer;
        case jit::YieldKind::Any:
        case jit::YieldKind::Recv:
        case jit::YieldKind::Send:
        case jit::YieldKind::UpstreamConnect:
        case jit::YieldKind::UpstreamRecv:
        case jit::YieldKind::UpstreamSend:
            return VerifyYieldRuntimeClass::Event;
        case jit::YieldKind::HttpGet:
        case jit::YieldKind::HttpPost:
        case jit::YieldKind::Forward:
            return VerifyYieldRuntimeClass::Unsupported;
    }
    return VerifyYieldRuntimeClass::Unsupported;
}

inline bool verify_valid_yield_runtime_protocol(u8 kind, u32 payload) {
    return VerifyRuntimeProtocolModel::check_yield(kind, payload).ok;
}

inline const char* verify_yield_kind_name(u8 kind) {
    switch (static_cast<jit::YieldKind>(kind)) {
        case jit::YieldKind::HttpGet:
            return "HttpGet";
        case jit::YieldKind::HttpPost:
            return "HttpPost";
        case jit::YieldKind::Forward:
            return "Forward";
        case jit::YieldKind::Timer:
            return "Timer";
        case jit::YieldKind::Any:
            return "Any";
        case jit::YieldKind::Recv:
            return "Recv";
        case jit::YieldKind::Send:
            return "Send";
        case jit::YieldKind::UpstreamConnect:
            return "UpstreamConnect";
        case jit::YieldKind::UpstreamRecv:
            return "UpstreamRecv";
        case jit::YieldKind::UpstreamSend:
            return "UpstreamSend";
    }
    return "Unknown";
}

inline const char* verify_runtime_pending_op_name(VerifyRuntimePendingOp op) {
    switch (op) {
        case VerifyRuntimePendingOp::None:
            return "None";
        case VerifyRuntimePendingOp::Timer:
            return "Timer";
        case VerifyRuntimePendingOp::DownstreamRecv:
            return "DownstreamRecv";
        case VerifyRuntimePendingOp::DownstreamSend:
            return "DownstreamSend";
        case VerifyRuntimePendingOp::UpstreamConnect:
            return "UpstreamConnect";
        case VerifyRuntimePendingOp::UpstreamRecv:
            return "UpstreamRecv";
        case VerifyRuntimePendingOp::UpstreamSend:
            return "UpstreamSend";
    }
    return "Unknown";
}

inline const char* verify_runtime_callback_slot_name(VerifyRuntimeCallbackSlot slot) {
    switch (slot) {
        case VerifyRuntimeCallbackSlot::None:
            return "None";
        case VerifyRuntimeCallbackSlot::HandlerTimer:
            return "HandlerTimer";
        case VerifyRuntimeCallbackSlot::DownstreamRecv:
            return "DownstreamRecv";
        case VerifyRuntimeCallbackSlot::DownstreamSend:
            return "DownstreamSend";
        case VerifyRuntimeCallbackSlot::UpstreamRecv:
            return "UpstreamRecv";
        case VerifyRuntimeCallbackSlot::UpstreamSend:
            return "UpstreamSend";
    }
    return "Unknown";
}

inline const char* verify_runtime_protocol_reason_name(VerifyRuntimeProtocolReason reason) {
    switch (reason) {
        case VerifyRuntimeProtocolReason::Ok:
            return "Ok";
        case VerifyRuntimeProtocolReason::UnsupportedEventYield:
            return "UnsupportedEventYield";
        case VerifyRuntimeProtocolReason::MissingUpstreamTarget:
            return "MissingUpstreamTarget";
    }
    return "Unknown";
}

inline bool verify_valid_block_target(const Function& fn, BlockId target) {
    return target != kNoBlock && target.id < fn.block_count;
}

inline u8 verify_yield_timer_kind(const Instruction& inst) {
    const u64 packed = static_cast<u64>(inst.imm.i64_val);
    u8 kind = static_cast<u8>((packed >> 48) & 0xffu);
    if (kind == 0) kind = static_cast<u8>(jit::YieldKind::Timer);
    return kind;
}

inline u16 verify_yield_timer_next_state(const Instruction& inst) {
    const u64 packed = static_cast<u64>(inst.imm.i64_val);
    return static_cast<u16>((packed >> 32) & 0xffffu);
}

inline bool build_verify_handler_automaton(const Function* fn, VerifyHandlerAutomaton& out) {
    out = VerifyHandlerAutomaton{};

    if (fn == nullptr || fn->block_count == 0 || fn->blocks == nullptr ||
        fn->block_count > VerifyHandlerAutomaton::kMaxNodes) {
        return false;
    }

    for (u32 bi = 0; bi < fn->block_count; bi++) {
        const Block& block = fn->blocks[bi];
        if (block.inst_count == 0 || block.insts == nullptr) {
            return false;
        }

        const u32 inst_index = block.inst_count - 1;
        const Instruction& term = block.insts[inst_index];
        VerifyHandlerAutomatonNode& node = out.nodes[out.node_count++];
        node.block_index = bi;
        node.inst_index = inst_index;

        if (term.op == Opcode::Br) {
            node.kind = VerifyHandlerNodeKind::Branch;
            node.target_count = 2;
            node.targets[0] = term.imm.block_targets[0].id;
            node.targets[1] = term.imm.block_targets[1].id;
            out.edge_count += 2;
        } else if (term.op == Opcode::Jmp) {
            node.kind = VerifyHandlerNodeKind::Jump;
            node.target_count = 1;
            node.targets[0] = term.imm.block_targets[0].id;
            out.edge_count += 1;
        } else if (term.is_yield()) {
            if (term.op != Opcode::YieldTimer) {
                return false;
            }
            node.kind = VerifyHandlerNodeKind::Yield;
            node.yield_kind = verify_yield_timer_kind(term);
            node.yield_payload = static_cast<u32>(static_cast<u64>(term.imm.i64_val));
            node.next_state = verify_yield_timer_next_state(term);
            if (node.next_state != 0 && node.next_state <= fn->yield_count &&
                fn->yield_arm_masks != nullptr) {
                node.wait_arm_mask = fn->yield_arm_masks[node.next_state - 1];
            } else {
                node.wait_arm_mask =
                    verify_yield_default_arm_mask(node.yield_kind, node.yield_payload);
            }
            node.runtime =
                VerifyRuntimeProtocolModel::check_yield(node.yield_kind, node.yield_payload);
            if (fn->has_explicit_resume_blocks && node.next_state <= fn->yield_count) {
                node.target_count = 1;
                node.targets[0] = fn->resume_blocks[node.next_state];
            } else if (fn->state_zero_enters_entry && fn->resume_terminal_block < fn->block_count) {
                node.target_count = 1;
                node.targets[0] = fn->resume_terminal_block;
            }
            out.yield_count++;
            out.edge_count += 1;
            out.runtime_submit_count += node.runtime.submit_transition_count;
            out.runtime_completion_count += node.runtime.completion_transition_count;
            out.runtime_fail_closed_count += node.runtime.fail_closed_transition_count;
        } else {
            node.kind = VerifyHandlerNodeKind::Terminal;
            out.terminal_count++;
        }
    }

    return true;
}

inline VerifyHandlerCheckResult verify_handler_automaton(const VerifyHandlerAutomaton& automaton) {
    VerifyHandlerCheckResult result{};

    if (automaton.node_count == 0) {
        result.ok = false;
        result.issue.code = VerifyHandlerCheckIssueCode::MissingAutomaton;
        return result;
    }

    for (u32 ni = 0; ni < automaton.node_count; ni++) {
        const VerifyHandlerAutomatonNode& node = automaton.nodes[ni];
        if ((node.kind == VerifyHandlerNodeKind::Branch ||
             node.kind == VerifyHandlerNodeKind::Jump ||
             node.kind == VerifyHandlerNodeKind::Yield) &&
            node.target_count == 0) {
            result.ok = false;
            result.issue.code = VerifyHandlerCheckIssueCode::DeadEnd;
            result.issue.node_index = ni;
            return result;
        }
        for (u32 ti = 0; ti < node.target_count; ti++) {
            if (node.targets[ti] >= automaton.node_count) {
                result.ok = false;
                result.issue.code = VerifyHandlerCheckIssueCode::InvalidTarget;
                result.issue.node_index = ni;
                result.issue.target_index = node.targets[ti];
                return result;
            }
        }
    }

    u8 color[VerifyHandlerAutomaton::kMaxNodes]{};
    u32 stack[VerifyHandlerAutomaton::kMaxNodes]{};
    u32 next_target[VerifyHandlerAutomaton::kMaxNodes]{};
    for (u32 start = 0; start < automaton.node_count; start++) {
        if (color[start] != 0) continue;
        if (automaton.nodes[start].kind != VerifyHandlerNodeKind::Branch &&
            automaton.nodes[start].kind != VerifyHandlerNodeKind::Jump) {
            color[start] = 2;
            continue;
        }

        u32 depth = 0;
        stack[depth++] = start;
        color[start] = 1;
        while (depth > 0) {
            const u32 ni = stack[depth - 1];
            const VerifyHandlerAutomatonNode& node = automaton.nodes[ni];
            if (next_target[ni] >= node.target_count) {
                color[ni] = 2;
                depth--;
                continue;
            }

            const u32 target = node.targets[next_target[ni]++];
            const VerifyHandlerAutomatonNode& target_node = automaton.nodes[target];
            if (target_node.kind != VerifyHandlerNodeKind::Branch &&
                target_node.kind != VerifyHandlerNodeKind::Jump) {
                continue;
            }
            if (color[target] == 1) {
                result.ok = false;
                result.issue.code = VerifyHandlerCheckIssueCode::NonYieldingCycle;
                result.issue.node_index = ni;
                result.issue.target_index = target;
                return result;
            }
            if (color[target] == 0) {
                color[target] = 1;
                stack[depth++] = target;
            }
        }
    }

    return result;
}

inline VerifyHandlerCheckResult verify_handler_runtime_states(
    const VerifyHandlerAutomaton& automaton) {
    VerifyHandlerCheckResult result{};

    if (automaton.node_count == 0) {
        result.ok = false;
        result.issue.code = VerifyHandlerCheckIssueCode::MissingAutomaton;
        return result;
    }

    for (u32 ni = 0; ni < automaton.node_count; ni++) {
        const VerifyHandlerAutomatonNode& node = automaton.nodes[ni];
        if (node.kind != VerifyHandlerNodeKind::Yield) continue;

        result.runtime_state_count += 2;       // handler-running + runtime-waiting
        result.runtime_transition_count += 1;  // submit into runtime-waiting

        if (!node.runtime.ok || !node.runtime.submit_transition ||
            !node.runtime.completion_transition || !node.runtime.fail_closed_transition ||
            node.runtime.submit_transition_count == 0 ||
            node.runtime.completion_transition_count != node.runtime.submit_transition_count ||
            node.runtime.fail_closed_transition_count != node.runtime.submit_transition_count) {
            result.ok = false;
            result.issue.code = VerifyHandlerCheckIssueCode::MissingRuntimeTransition;
            result.issue.node_index = ni;
            return result;
        }

        const u8 callback_mask = static_cast<u8>(
            verify_runtime_callback_slot_mask(node.runtime.callback_slot) |
            verify_runtime_callback_slot_mask(node.runtime.secondary_callback_slot));
        const u8 pending_arm_mask =
            static_cast<u8>(verify_runtime_pending_op_arm_mask(node.runtime.pending_op) |
                            verify_runtime_pending_op_arm_mask(node.runtime.secondary_pending_op));
        if (callback_mask == 0 || pending_arm_mask == 0) {
            result.ok = false;
            result.issue.code = VerifyHandlerCheckIssueCode::CallbackSlotMismatch;
            result.issue.node_index = ni;
            return result;
        }

        if (node.wait_arm_mask != pending_arm_mask) {
            result.ok = false;
            result.issue.code = VerifyHandlerCheckIssueCode::WaitArmMaskMismatch;
            result.issue.node_index = ni;
            result.issue.target_index = node.wait_arm_mask;
            return result;
        }

        result.runtime_transition_count += node.runtime.completion_transition_count;
        result.runtime_transition_count += node.runtime.fail_closed_transition_count;
    }

    return result;
}

// Phi inputs must be available on their incoming edge. Reject a path from
// entry to that edge which bypasses the defining block. This bounded walk
// avoids trusting numeric block ordering (nested expression merges are not
// necessarily appended in dependency order).
inline bool verify_phi_dominates(const Function& fn, BlockId definition, BlockId edge) {
    if (definition.id >= fn.block_count || edge.id >= fn.block_count) return false;
    if (definition == edge || definition.id == 0) return true;
    constexpr u32 kMaxBlocks = 4096;
    if (fn.block_count > kMaxBlocks) return false;
    bool visited[kMaxBlocks]{};
    u32 pending[kMaxBlocks]{};
    u32 count = 0;
    pending[count++] = 0;
    visited[0] = true;
    while (count != 0) {
        const u32 kId = pending[--count];
        if (kId == edge.id) return false;
        const Block& block = fn.blocks[kId];
        if (block.insts == nullptr || block.inst_count == 0) return false;
        const Instruction* term = block.terminator();
        if (term == nullptr) return false;
        const u32 kSuccessors = term->op == Opcode::Br ? 2u : term->op == Opcode::Jmp ? 1u : 0u;
        for (u32 i = 0; i < kSuccessors; ++i) {
            const u32 kNext = term->imm.block_targets[i].id;
            if (kNext >= fn.block_count) return false;
            if (kNext == definition.id || visited[kNext]) continue;
            visited[kNext] = true;
            pending[count++] = kNext;
        }
    }
    return true;
}

inline bool verify_phi_types_equal(const Type* first, const Type* second, u32 depth = 0) {
    if (first == nullptr || second == nullptr || depth > 64 || first->kind != second->kind ||
        first->kind == TypeKind::Void || first->kind > TypeKind::Array)
        return false;
    if (first->kind == TypeKind::Optional || first->kind == TypeKind::Array)
        return verify_phi_types_equal(first->inner, second->inner, depth + 1);
    if (first->kind == TypeKind::Struct)
        return first->struct_def != nullptr && first->struct_def == second->struct_def;
    return first->inner == nullptr && second->inner == nullptr && first->struct_def == nullptr &&
           second->struct_def == nullptr;
}

inline bool valid_collected_instruction(const Function& fn, const Instruction& inst) {
    const bool allocation = inst.op == Opcode::ArrayNew;
    const bool push = inst.op == Opcode::ArrayPush;
    const bool count = inst.op == Opcode::ArrayLen;
    const bool get = inst.op == Opcode::ArrayGet;
    if (!allocation && !push && !count && !get) return true;
    if (!fn.values || inst.result == kNoValue || inst.result.id >= fn.value_count ||
        inst.extra_operands ||
        inst.operand_count != (allocation ? 0u
                               : count    ? 1u
                                          : 2u))
        return false;
    for (u32 i = 0; i < inst.operand_count; ++i)
        if (inst.operands[i] == kNoValue || inst.operands[i].id >= fn.value_count) return false;
    const Type* result = fn.values[inst.result.id].type;
    if (!result || result->struct_def) return false;
    const Type* array = allocation ? result->inner : fn.values[inst.operands[0].id].type;
    if (!array || array->kind != TypeKind::Array || array->struct_def ||
        !collected_element_type(array->inner))
        return false;
    if (allocation)
        return result->kind == TypeKind::Optional && inst.imm.i32_val >= 1 &&
               inst.imm.i32_val <= 64;
    if (count) return result->kind == TypeKind::I32 && !result->inner;
    const Type* second = fn.values[inst.operands[1].id].type;
    if (push)
        return result->kind == TypeKind::Bool && !result->inner &&
               verify_phi_types_equal(array->inner, second);
    return second && second->kind == TypeKind::I32 && !second->inner && !second->struct_def &&
           result->kind == TypeKind::Optional &&
           verify_phi_types_equal(result->inner, array->inner);
}

inline bool verify_phi(const Function& fn, u32 block_index, u32 inst_index) {
    const Block& block = fn.blocks[block_index];
    const Instruction& inst = block.insts[inst_index];
    // Resume entries have additional runtime predecessors. They require a
    // separate persisted-value analysis before using ordinary synchronous SSA.
    if (fn.yield_count != 0 || inst.operand_count != 2 || fn.values == nullptr ||
        inst.result == kNoValue || inst.result.id >= fn.value_count)
        return false;
    for (u32 i = 0; i < inst_index; ++i)
        if (block.insts[i].op != Opcode::Phi) return false;
    const Value& result = fn.values[inst.result.id];
    if (result.def_block.id != block_index || result.def_inst != inst_index) return false;
    const BlockId kFirst = inst.imm.block_targets[0];
    const BlockId kSecond = inst.imm.block_targets[1];
    if (kFirst == kSecond || kFirst.id >= fn.block_count || kSecond.id >= fn.block_count ||
        kFirst.id == block_index || kSecond.id == block_index)
        return false;
    u32 predecessors = 0;
    for (u32 bi = 0; bi < fn.block_count; ++bi) {
        const Block& source = fn.blocks[bi];
        if (source.inst_count == 0 || source.insts == nullptr) return false;
        const Instruction* term = source.terminator();
        if (term == nullptr) return false;
        const u32 kTargets = term->op == Opcode::Br ? 2u : term->op == Opcode::Jmp ? 1u : 0u;
        bool reaches = false;
        for (u32 i = 0; i < kTargets; ++i) reaches |= term->imm.block_targets[i].id == block_index;
        if (!reaches) continue;
        if (bi != kFirst.id && bi != kSecond.id) return false;
        ++predecessors;
    }
    if (predecessors != 2) return false;
    for (u32 i = 0; i < 2; ++i) {
        const ValueId kId = inst.operands[i];
        if (kId == kNoValue || kId == inst.result || kId.id >= fn.value_count) return false;
        const Value& value = fn.values[kId.id];
        if (value.def_block.id >= fn.block_count ||
            !verify_phi_types_equal(result.type, value.type))
            return false;
        const Block& definition = fn.blocks[value.def_block.id];
        if (definition.insts == nullptr || value.def_inst >= definition.inst_count ||
            definition.insts[value.def_inst].result != kId ||
            !verify_phi_dominates(fn, value.def_block, inst.imm.block_targets[i]))
            return false;
    }
    return true;
}

inline VerifyResult verify_function(const Function* fn,
                                    u32 function_index = 0,
                                    VerifyOptions options = {}) {
    VerifySummary summary{};
    summary.function_count = 1;

    if (fn == nullptr) {
        return verify_fail(summary, VerifyIssueCode::MissingFunction, function_index);
    }
    if (fn->block_count == 0) {
        return verify_fail(summary, VerifyIssueCode::MissingEntry, function_index);
    }
    if (fn->blocks == nullptr) {
        return verify_fail(summary, VerifyIssueCode::MissingBlocks, function_index);
    }

    static constexpr u32 kMaxVerifierBlocks = 4096;
    if (fn->block_count > kMaxVerifierBlocks) {
        return verify_fail(summary, VerifyIssueCode::TooManyBlocks, function_index);
    }
    if (fn->yield_count >= Function::kMaxResumeBlocks) {
        return verify_fail(
            summary, VerifyIssueCode::TooManyYieldStates, function_index, 0, 0, fn->yield_count);
    }

    if (!password_prefix_valid(*fn))
        return verify_fail(summary, VerifyIssueCode::InvalidPasswordPrefix, function_index);
    if (!http_call_profile_valid(*fn))
        return verify_fail(summary, VerifyIssueCode::InvalidHttpCallProfile, function_index);

    summary.block_count = fn->block_count;

    bool reachable[kMaxVerifierBlocks]{};
    u32 worklist[kMaxVerifierBlocks]{};
    u32 work_start = 0;
    u32 work_end = 0;

    u32 seen_yield_terminators = 0;
    bool seen_yield_next_state[Function::kMaxResumeBlocks]{};

    if (fn->yield_count > 0 && (fn->yield_payload == nullptr || fn->yield_kinds == nullptr ||
                                fn->yield_arm_masks == nullptr)) {
        return verify_fail(summary, VerifyIssueCode::MissingYieldMetadata, function_index);
    }

    for (u32 bi = 0; bi < fn->block_count; bi++) {
        const Block& block = fn->blocks[bi];
        if (block.id.id != bi) {
            return verify_fail(summary, VerifyIssueCode::BlockIdMismatch, function_index, bi);
        }
        if (block.inst_count > 0 && block.insts == nullptr) {
            return verify_fail(summary, VerifyIssueCode::MissingInstructions, function_index, bi);
        }
        if (block.inst_count == 0 || block.terminator() == nullptr) {
            return verify_fail(summary, VerifyIssueCode::MissingTerminator, function_index, bi);
        }
        for (u32 ii = 0; ii + 1 < block.inst_count; ii++) {
            if (block.insts[ii].is_terminator()) {
                return verify_fail(
                    summary, VerifyIssueCode::TerminatorBeforeEnd, function_index, bi, ii);
            }
        }
        for (u32 ii = 0; ii < block.inst_count; ii++) {
            const Instruction& inst = block.insts[ii];
            if (inst.op == Opcode::Phi && !verify_phi(*fn, bi, ii))
                return verify_fail(summary, VerifyIssueCode::InvalidPhi, function_index, bi, ii);
            if (inst.op == Opcode::WsForward || inst.op == Opcode::WsClose) {
                const auto kExactType = [&](ValueId id, TypeKind kind) {
                    if (id == kNoValue || id.id >= fn->value_count || !fn->values) return false;
                    const Type* type = fn->values[id.id].type;
                    return type && type->kind == kind && !type->inner && !type->struct_def;
                };
                const bool kForward = inst.op == Opcode::WsForward;
                if (inst.operand_count != (kForward ? 1u : 2u) || inst.extra_operands ||
                    !kExactType(inst.result, TypeKind::I32) ||
                    !kExactType(inst.operands[0], kForward ? TypeKind::Str : TypeKind::I32) ||
                    (kForward ? inst.imm.i32_val != 1 && inst.imm.i32_val != 2
                              : !kExactType(inst.operands[1], TypeKind::Str)))
                    return verify_fail(
                        summary, VerifyIssueCode::InvalidWsOutput, function_index, bi, ii);
            }
            if (inst.op == Opcode::WsMessageField) {
                const u32 kField = static_cast<u32>(inst.imm.i32_val);
                const auto kFieldId = static_cast<WsMessageFieldId>(kField);
                const bool kBool = ws_message_field_is_bool(kFieldId);
                const TypeKind kExpected = ws_message_field_is_string(kFieldId) ? TypeKind::Str
                                           : kFieldId == WsMessageFieldId::ConnectionRemoteAddr
                                               ? TypeKind::IP
                                           : kBool ? TypeKind::Bool
                                                   : TypeKind::I32;
                const Type* type = inst.result != kNoValue && inst.result.id < fn->value_count &&
                                           fn->values != nullptr
                                       ? fn->values[inst.result.id].type
                                       : nullptr;
                if (!ws_message_field_valid(kField) || inst.operand_count != 0 || type == nullptr ||
                    type->kind != kExpected || type->inner != nullptr ||
                    type->struct_def != nullptr)
                    return verify_fail(
                        summary, VerifyIssueCode::InvalidWsMessageField, function_index, bi, ii);
            }
            if (!valid_string_instruction(*fn, inst))
                return verify_fail(
                    summary, VerifyIssueCode::InvalidStringOperation, function_index, bi, ii);
            if (inst.op == Opcode::StrLength) {
                const auto kExactType = [&](ValueId id, TypeKind kind) {
                    if (id == kNoValue || id.id >= fn->value_count || fn->values == nullptr)
                        return false;
                    const Type* type = fn->values[id.id].type;
                    return type != nullptr && type->kind == kind && type->inner == nullptr &&
                           type->struct_def == nullptr;
                };
                if (inst.operand_count != 1 || !kExactType(inst.result, TypeKind::I32) ||
                    !kExactType(inst.operand(0), TypeKind::Str))
                    return verify_fail(
                        summary, VerifyIssueCode::InvalidStrLength, function_index, bi, ii);
            }
            if (!valid_collected_instruction(*fn, inst))
                return verify_fail(
                    summary, VerifyIssueCode::InvalidStringOperation, function_index, bi, ii);
            if (!valid_bytes_construction(*fn, inst))
                return verify_fail(
                    summary, VerifyIssueCode::InvalidStringOperation, function_index, bi, ii);
            if (!valid_integer_parse(*fn, inst))
                return verify_fail(
                    summary, VerifyIssueCode::InvalidIntegerParse, function_index, bi, ii);
            if (!valid_bytes_read(*fn, inst) || !valid_bytes_field(*fn, inst))
                return verify_fail(
                    summary, VerifyIssueCode::InvalidBytesSubscript, function_index, bi, ii);
            if (inst.op != Opcode::JwtClaimsValidWithLifetime) continue;
            auto exact_type = [&](ValueId id, TypeKind kind) {
                if (id == kNoValue || id.id >= fn->value_count || fn->values == nullptr)
                    return false;
                const Type* type = fn->values[id.id].type;
                return type != nullptr && type->kind == kind && type->inner == nullptr &&
                       type->struct_def == nullptr;
            };
            bool valid = inst.operand_count == 5 && inst.extra_operands != nullptr &&
                         inst.result != kNoValue && inst.result.id < fn->value_count &&
                         exact_type(inst.result, TypeKind::Bool);
            constexpr TypeKind kOperandTypes[] = {
                TypeKind::Str, TypeKind::Str, TypeKind::Str, TypeKind::I64, TypeKind::I64};
            if (valid) {
                for (u32 oi = 0; oi < 5; ++oi) {
                    if (!exact_type(inst.operand(oi), kOperandTypes[oi])) {
                        valid = false;
                        break;
                    }
                }
            }
            if (!valid)
                return verify_fail(
                    summary, VerifyIssueCode::InvalidJwtClaimsLifetime, function_index, bi, ii);
        }

        const Instruction& term = block.insts[block.inst_count - 1];
        if (term.op == Opcode::Br) {
            if (!verify_valid_block_target(*fn, term.imm.block_targets[0])) {
                return verify_fail(summary,
                                   VerifyIssueCode::InvalidBranchTarget,
                                   function_index,
                                   bi,
                                   block.inst_count - 1,
                                   term.imm.block_targets[0].id);
            }
            if (!verify_valid_block_target(*fn, term.imm.block_targets[1])) {
                return verify_fail(summary,
                                   VerifyIssueCode::InvalidBranchTarget,
                                   function_index,
                                   bi,
                                   block.inst_count - 1,
                                   term.imm.block_targets[1].id);
            }
        } else if (term.op == Opcode::Jmp) {
            if (!verify_valid_block_target(*fn, term.imm.block_targets[0])) {
                return verify_fail(summary,
                                   VerifyIssueCode::InvalidJumpTarget,
                                   function_index,
                                   bi,
                                   block.inst_count - 1,
                                   term.imm.block_targets[0].id);
            }
        } else if (term.op == Opcode::RetRedirect) {
            const i64 policy_id = term.imm.i32_val;
            if (term.operand_count != 0 || policy_id <= 0 || policy_id > 0xffff) {
                return verify_fail(summary,
                                   VerifyIssueCode::InvalidRedirectPolicyId,
                                   function_index,
                                   bi,
                                   block.inst_count - 1,
                                   static_cast<u32>(policy_id));
            }
        } else if (term.is_yield()) {
            if (term.op != Opcode::YieldTimer) {
                return verify_fail(summary,
                                   VerifyIssueCode::UnsupportedYieldTerminator,
                                   function_index,
                                   bi,
                                   block.inst_count - 1,
                                   static_cast<u32>(term.op));
            }
            if (term.op == Opcode::YieldTimer) {
                const u8 kind = verify_yield_timer_kind(term);
                if (!verify_valid_yield_kind(kind)) {
                    return verify_fail(summary,
                                       VerifyIssueCode::InvalidYieldKind,
                                       function_index,
                                       bi,
                                       block.inst_count - 1,
                                       kind);
                }

                const u16 next_state = verify_yield_timer_next_state(term);
                if (next_state == 0 || next_state > fn->yield_count) {
                    return verify_fail(summary,
                                       VerifyIssueCode::InvalidYieldNextState,
                                       function_index,
                                       bi,
                                       block.inst_count - 1,
                                       next_state);
                }
                if (seen_yield_next_state[next_state]) {
                    return verify_fail(summary,
                                       VerifyIssueCode::DuplicateYieldNextState,
                                       function_index,
                                       bi,
                                       block.inst_count - 1,
                                       next_state);
                }
                const u32 yi = static_cast<u32>(next_state - 1);
                const u32 payload = static_cast<u32>(static_cast<u64>(term.imm.i64_val));
                const VerifyRuntimeProtocolCheck runtime_check =
                    VerifyRuntimeProtocolModel::check_yield(kind, payload);
                if (!runtime_check.ok) {
                    return verify_fail(summary,
                                       VerifyIssueCode::InvalidYieldRuntimeProtocol,
                                       function_index,
                                       bi,
                                       block.inst_count - 1,
                                       kind,
                                       payload);
                }
                if (fn->yield_kinds[yi] != kind || fn->yield_payload[yi] != payload) {
                    return verify_fail(summary,
                                       VerifyIssueCode::YieldMetadataMismatch,
                                       function_index,
                                       bi,
                                       block.inst_count - 1,
                                       next_state);
                }
                seen_yield_next_state[next_state] = true;
            }
            seen_yield_terminators++;
        } else {
            summary.terminal_block_count++;
        }
    }

    if (fn->yield_count != seen_yield_terminators) {
        return verify_fail(summary,
                           VerifyIssueCode::YieldCountMismatch,
                           function_index,
                           0,
                           seen_yield_terminators,
                           fn->yield_count);
    }
    for (u32 yi = 1; yi <= fn->yield_count; yi++) {
        if (!seen_yield_next_state[yi]) {
            return verify_fail(
                summary, VerifyIssueCode::MissingYieldNextState, function_index, 0, yi, yi);
        }
    }
    for (u32 yi = 0; yi < fn->yield_count; yi++) {
        if (!verify_valid_yield_kind(fn->yield_kinds[yi])) {
            return verify_fail(summary,
                               VerifyIssueCode::InvalidYieldKind,
                               function_index,
                               0,
                               yi,
                               fn->yield_kinds[yi]);
        }
    }
    summary.yield_count = fn->yield_count;

    if (fn->yield_count > 0 && !fn->has_explicit_resume_blocks && !fn->state_zero_enters_entry) {
        return verify_fail(summary, VerifyIssueCode::MissingYieldResumeMapping, function_index);
    }
    if (fn->state_zero_enters_entry) {
        if (fn->state_zero_entry_block >= fn->block_count ||
            fn->resume_terminal_block >= fn->block_count) {
            return verify_fail(summary, VerifyIssueCode::InvalidStateZeroEntry, function_index);
        }
    }
    if (fn->has_explicit_resume_blocks) {
        if (fn->yield_count >= Function::kMaxResumeBlocks) {
            return verify_fail(summary, VerifyIssueCode::InvalidResumeBlock, function_index);
        }
        for (u32 i = 0; i <= fn->yield_count; i++) {
            if (fn->resume_blocks[i] >= fn->block_count) {
                return verify_fail(summary,
                                   VerifyIssueCode::InvalidResumeBlock,
                                   function_index,
                                   0,
                                   i,
                                   fn->resume_blocks[i]);
            }
        }
    }

    u32 reachable_root = fn->blocks[0].id.id;
    if (fn->has_explicit_resume_blocks) {
        reachable_root = fn->resume_blocks[0];
    } else if (fn->state_zero_enters_entry) {
        reachable_root = fn->state_zero_entry_block;
    }
    reachable[reachable_root] = true;
    worklist[work_end++] = reachable_root;

    while (work_start < work_end) {
        const u32 bi = worklist[work_start++];
        summary.reachable_block_count++;
        const Block& block = fn->blocks[bi];
        const Instruction& term = block.insts[block.inst_count - 1];
        if (term.op == Opcode::Br) {
            const u32 targets[2] = {term.imm.block_targets[0].id, term.imm.block_targets[1].id};
            for (u32 i = 0; i < 2; i++) {
                summary.branch_edge_count++;
                if (!reachable[targets[i]]) {
                    reachable[targets[i]] = true;
                    worklist[work_end++] = targets[i];
                }
            }
        } else if (term.op == Opcode::Jmp) {
            const u32 target = term.imm.block_targets[0].id;
            summary.branch_edge_count++;
            if (!reachable[target]) {
                reachable[target] = true;
                worklist[work_end++] = target;
            }
        } else if (term.op == Opcode::YieldTimer) {
            const u16 next_state = verify_yield_timer_next_state(term);

            if (next_state == 0 || next_state > fn->yield_count) {
                return verify_fail(summary,
                                   VerifyIssueCode::InvalidYieldNextState,
                                   function_index,
                                   bi,
                                   block.inst_count - 1,
                                   next_state);
            }

            if (fn->has_explicit_resume_blocks) {
                const u32 target = fn->resume_blocks[next_state];
                summary.branch_edge_count++;
                if (!reachable[target]) {
                    reachable[target] = true;
                    worklist[work_end++] = target;
                }
            } else if (fn->state_zero_enters_entry) {
                const u32 target = fn->resume_terminal_block;
                summary.branch_edge_count++;
                if (!reachable[target]) {
                    reachable[target] = true;
                    worklist[work_end++] = target;
                }
            }
        }
    }

    if (options.require_all_blocks_reachable) {
        for (u32 bi = 0; bi < fn->block_count; bi++) {
            if (!reachable[bi]) {
                return verify_fail(summary, VerifyIssueCode::UnreachableBlock, function_index, bi);
            }
        }
    }

    VerifyHandlerAutomaton automaton{};
    if (!build_verify_handler_automaton(fn, automaton)) {
        return verify_fail(summary, VerifyIssueCode::InvalidHandlerAutomaton, function_index);
    }
    const VerifyHandlerCheckResult automaton_check = verify_handler_automaton(automaton);
    if (!automaton_check.ok) {
        const VerifyIssueCode code =
            automaton_check.issue.code == VerifyHandlerCheckIssueCode::NonYieldingCycle
                ? VerifyIssueCode::NonYieldingControlCycle
                : VerifyIssueCode::InvalidHandlerAutomaton;
        return verify_fail(summary,
                           code,
                           function_index,
                           automaton_check.issue.node_index,
                           0,
                           automaton_check.issue.target_index);
    }
    const VerifyHandlerCheckResult runtime_state_check = verify_handler_runtime_states(automaton);
    if (!runtime_state_check.ok) {
        return verify_fail(summary,
                           VerifyIssueCode::InvalidRuntimeStateModel,
                           function_index,
                           runtime_state_check.issue.node_index,
                           0,
                           runtime_state_check.issue.target_index);
    }

    const auto* environment =
        options.environment && options.environment->function_index == function_index
            ? options.environment
            : nullptr;
    if (fn->yield_count || environment) {
        const auto concurrent = verify_handler_concurrency(automaton,
                                                           reachable_root,
                                                           function_index,
                                                           summary,
                                                           options.concurrency_limits,
                                                           environment);
        if (!concurrent.ok) return concurrent;
    }

    VerifyResult result{};
    result.ok = true;
    result.summary = summary;
    return result;
}

namespace detail {

inline VerifyResult verify_module_impl(const Module& mod,
                                       VerifyOptions options,
                                       bool internal_strict_local_response_propagation) {
    VerifySummary summary{};
    summary.function_count = mod.func_count;
    if (options.environment && options.environment->function_index >= mod.func_count)
        return verify_fail(summary,
                           VerifyIssueCode::ConcurrentProtocolFailure,
                           options.environment->function_index);

    static_assert(kRouteMethodSlots == kStrictLocalResponseMethodSlots);
    const bool has_exact_strict_local_response_inventory =
        exact_strict_local_response_inventory_present(
            mod.exact_strict_local_response_bindings,
            mod.exact_strict_local_response_binding_count);
    bool has_pre_route_metadata = false;
    bool pre_route_referenced[kMaxStrictLocalResponsePolicies]{};
    if (mod.pre_route_policy_ids[kRouteMethodAny] != 0)
        return verify_fail(summary, VerifyIssueCode::InvalidPreRoutePolicyId, 0);
    for (u32 slot = 1; slot < kStrictLocalResponseMethodSlots; slot++) {
        const u16 id = mod.pre_route_policy_ids[slot];
        if (id == 0) continue;
        has_pre_route_metadata = true;
        if (mod.strict_local_response_policy_count > kMaxStrictLocalResponsePolicies ||
            id > mod.strict_local_response_policy_count || pre_route_referenced[id - 1] ||
            (slot == kRouteMethodHead && mod.strict_local_response_policies[id - 1].head_mode !=
                                             StrictLocalResponseHeadMode::SuppressBody))
            return verify_fail(summary, VerifyIssueCode::InvalidPreRoutePolicyId, 0);
        pre_route_referenced[id - 1] = true;
    }
    const bool unmatched_table_valid =
        internal_strict_local_response_propagation
            ? strict_local_response_policy_table_valid_for_internal_propagation(
                  mod.strict_local_response_policies,
                  mod.strict_local_response_policy_count,
                  mod.unmatched_policy_ids)
            : strict_local_response_policy_table_valid(mod.strict_local_response_policies,
                                                       mod.strict_local_response_policy_count,
                                                       mod.unmatched_policy_ids);
    if (!has_pre_route_metadata && !has_exact_strict_local_response_inventory &&
        (!unmatched_table_valid ||
         (mod.unmatched_policy_ids[kRouteMethodAny] != 0 &&
          mod.strict_local_response_policies[mod.unmatched_policy_ids[kRouteMethodAny] - 1]
                  .head_mode != StrictLocalResponseHeadMode::SuppressBody) ||
         (mod.unmatched_policy_ids[kRouteMethodHead] != 0 &&
          mod.strict_local_response_policies[mod.unmatched_policy_ids[kRouteMethodHead] - 1]
                  .head_mode != StrictLocalResponseHeadMode::SuppressBody)))
        return verify_fail(summary, VerifyIssueCode::InvalidUnmatchedPolicyId, 0);
    const bool source_table_valid =
        internal_strict_local_response_propagation
            ? strict_local_response_source_table_valid_for_internal_propagation(
                  mod.strict_local_response_policies,
                  mod.strict_local_response_policy_count,
                  mod.pre_route_policy_ids,
                  mod.unmatched_policy_ids,
                  mod.exact_strict_local_response_bindings,
                  mod.exact_strict_local_response_binding_count,
                  kMaxExactStrictLocalResponseBindings)
            : strict_local_response_source_table_valid(
                  mod.strict_local_response_policies,
                  mod.strict_local_response_policy_count,
                  mod.pre_route_policy_ids,
                  mod.unmatched_policy_ids,
                  mod.exact_strict_local_response_bindings,
                  mod.exact_strict_local_response_binding_count,
                  kMaxExactStrictLocalResponseBindings);
    if (!source_table_valid)
        return verify_fail(summary, VerifyIssueCode::InvalidExactStrictLocalResponseBinding, 0);

    if (!redirect_policy_table_valid(mod.redirect_policies, mod.redirect_policy_count))
        return verify_fail(summary, VerifyIssueCode::InvalidRedirectPolicyId, 0);

    if (mod.response_policy_count > kMaxResponsePolicies ||
        mod.failure_policy_count > kMaxForwardFailurePolicies ||
        mod.policy_bundle_count > kMaxForwardFailurePolicies)
        return verify_fail(summary, VerifyIssueCode::InvalidForwardPreflight, 0);
    bool module_has_response_read_timeout = false;
    for (u32 i = 0; i < mod.policy_bundle_count; i++) {
        const auto& bundle = mod.policy_bundles[i];
        const u8 seconds = bundle.response_read_timeout_seconds;
        if ((bundle.response_policy_id != 0 &&
             (bundle.response_policy_id > mod.response_policy_count ||
              !response_policy_spec_valid(mod.response_policies[bundle.response_policy_id - 1]))) ||
            (bundle.failure_policy_id != 0 &&
             (bundle.failure_policy_id > mod.failure_policy_count ||
              !forward_failure_policy_spec_valid(
                  mod.failure_policies[bundle.failure_policy_id - 1]))) ||
            (seconds != 0 && !response_read_timeout_seconds_valid(seconds)) ||
            !forward_response_buffering_mode_valid(bundle.response_buffering) ||
            (seconds == 0 && bundle.failure_policy_id == 0) ||
            // `header_order: .upstream` is ordinary-forward-only (see
            // analyze.cc, compile_to_config.h, and route_table.h): it never
            // carries response read timing, response buffering, or a timeout
            // failure policy. Repeat that invariant here so a hand-built
            // module that skipped analyze cannot verify successfully with a
            // bundle the deadline/buffering helpers assume never exists.
            (bundle.response_policy_id != 0 &&
             bundle.response_policy_id <= mod.response_policy_count &&
             mod.response_policies[bundle.response_policy_id - 1].header_order ==
                 ResponsePolicyHeaderOrder::Upstream &&
             (seconds != 0 || bundle.response_buffering != ForwardResponseBufferingMode::None ||
              bundle.timeout_failure_policy_id != 0)) ||
            // Envoy H1 status 503 / header_order: .lengthTypeDateServer is
            // ordinary connect-failure-only (see analyze.cc,
            // compile_to_config.h, and route_table.h): the runtime's
            // response-read-deadline preflight hard-requires the default
            // failure policy's status to be 502 and closes the downstream
            // connection on mismatch, so a bundle pairing this layout with a
            // response read timeout would drop every matching request. This
            // is the fourth trust boundary (verify_module), so reject the
            // same combination a hand-built module could otherwise slip past
            // verification only to be refused later by
            // populate_verified_route_config.
            (bundle.failure_policy_id != 0 &&
             bundle.failure_policy_id <= mod.failure_policy_count &&
             mod.failure_policies[bundle.failure_policy_id - 1].header_order ==
                 FailurePolicyHeaderOrder::LengthTypeDateServer &&
             seconds != 0))
            return verify_fail(summary, VerifyIssueCode::InvalidForwardPreflight, 0);
        if (bundle.response_buffering != ForwardResponseBufferingMode::None &&
            (!forward_response_buffering_uses_content_length_machinery(bundle.response_buffering) ||
             !response_read_timeout_seconds_valid(seconds) || bundle.response_policy_id == 0 ||
             bundle.failure_policy_id == 0 || bundle.timeout_failure_policy_id == 0 ||
             bundle.timeout_failure_policy_id > mod.failure_policy_count ||
             !complete_content_length_buffering_policies_valid(
                 mod.response_policies[bundle.response_policy_id - 1],
                 mod.failure_policies[bundle.failure_policy_id - 1],
                 mod.failure_policies[bundle.timeout_failure_policy_id - 1])))
            return verify_fail(summary, VerifyIssueCode::InvalidForwardPreflight, 0);
        if (bundle.timeout_failure_policy_id != 0) {
            if (bundle.response_policy_id == 0 || bundle.failure_policy_id == 0 ||
                bundle.timeout_failure_policy_id > mod.failure_policy_count ||
                !forward_timeout_failure_policy_spec_valid(
                    mod.failure_policies[bundle.timeout_failure_policy_id - 1]))
                return verify_fail(summary, VerifyIssueCode::InvalidForwardPreflight, 0);
            const bool response_suppress =
                mod.response_policies[bundle.response_policy_id - 1].head_mode ==
                ResponsePolicyHeadMode::SuppressBody;
            const bool failure_suppress =
                mod.failure_policies[bundle.failure_policy_id - 1].head_mode ==
                FailurePolicyHeadMode::SuppressBody;
            const bool timeout_suppress =
                mod.failure_policies[bundle.timeout_failure_policy_id - 1].head_mode ==
                FailurePolicyHeadMode::SuppressBody;
            if (response_suppress != failure_suppress || failure_suppress != timeout_suppress)
                return verify_fail(summary, VerifyIssueCode::InvalidForwardPreflight, 0);
        }
        if (seconds != 0) module_has_response_read_timeout = true;
    }

    if (mod.func_count > 0 && mod.functions == nullptr) {
        return verify_fail(summary, VerifyIssueCode::MissingFunction, 0);
    }

    for (u32 fi = 0; fi < mod.func_count; fi++) {
        const Function& fn = mod.functions[fi];
        if (fn.http_cache_ttl > 86400 || (fn.http_cache_ttl && (fn.http_method != kRouteMethodGet ||
                                                                fn.is_timer || fn.yield_count)))
            return verify_fail(summary, VerifyIssueCode::InvalidHttpCachePolicy, fi);
        const ForwardPreflightMode preflight_mode = fn.forward_preflight_mode;
        const u16 preflight_id = fn.preflight_forward_policy_bundle_id;
        if (!forward_preflight_mode_valid(preflight_mode) ||
            !forward_preflight_metadata_is_verified_runtime_safe(preflight_mode, preflight_id))
            return verify_fail(summary, VerifyIssueCode::InvalidForwardPreflight, fi);
        const bool eager_preflight = preflight_mode == ForwardPreflightMode::EagerDirect;
        const bool deferred_preflight =
            preflight_mode == ForwardPreflightMode::AfterCanonicalSelection;
        const bool framing_preflight =
            preflight_mode == ForwardPreflightMode::AfterRequestFramingSelection;
        const bool has_preflight = eager_preflight || deferred_preflight || framing_preflight;
        if (has_preflight &&
            (preflight_id > mod.policy_bundle_count ||
             !response_read_timeout_seconds_valid(
                 mod.policy_bundles[preflight_id - 1].response_read_timeout_seconds)))
            return verify_fail(summary, VerifyIssueCode::InvalidForwardPreflight, fi);

        const Instruction* sole_timeout_ret = nullptr;
        u32 sole_timeout_block = 0;
        u32 timeout_ret_count = 0;
        auto const_i32 = [&](ValueId id, i32* out) {
            if (out == nullptr || id == kNoValue || id.id >= fn.value_count || fn.values == nullptr)
                return false;
            const Value& value = fn.values[id.id];
            if (value.def_block.id >= fn.block_count || fn.blocks == nullptr) return false;
            const Block& block = fn.blocks[value.def_block.id];
            if (block.insts == nullptr || value.def_inst >= block.inst_count) return false;
            const Instruction& def = block.insts[value.def_inst];
            if (def.op != Opcode::ConstI32 || def.result != id || def.operand_count != 0)
                return false;
            *out = def.imm.i32_val;
            return true;
        };
        for (u32 bi = 0; bi < fn.block_count; bi++) {
            const Block& block = fn.blocks[bi];
            if (block.insts == nullptr) continue;
            for (u32 ii = 0; ii < block.inst_count; ii++) {
                const Instruction& inst = block.insts[ii];
                if (inst.op == Opcode::RetForward || inst.op == Opcode::RetForwardBundle) {
                    const u32 encoded = static_cast<u32>(inst.imm.i32_val);
                    const ForwardLoadBalance lb{static_cast<u16>(encoded >> 8),
                                                static_cast<LoadBalancePolicy>(encoded & 255)};
                    if ((encoded >> 8) > kMaxForwardSites || !forward_load_balance_valid(lb))
                        return verify_fail(
                            summary, VerifyIssueCode::InvalidForwardPreflight, fi, bi, ii);
                }
                if (inst.op != Opcode::RetForwardBundle) continue;
                if (inst.operand_count != 3)
                    return verify_fail(
                        summary, VerifyIssueCode::InvalidForwardPreflight, fi, bi, ii);
                i32 upstream = -1;
                i32 request_policy = -1;
                i32 bundle_id = -1;
                const bool static_operands =
                    const_i32(inst.operand(0), &upstream) &&
                    const_i32(inst.operand(1), &request_policy) &&
                    const_i32(inst.operand(2), &bundle_id) && upstream >= 0 &&
                    static_cast<u64>(upstream) < mod.upstream_count && request_policy >= 0 &&
                    request_policy <= 0xffff &&
                    (request_policy == 0 ||
                     request_policy_is_supported(static_cast<u16>(request_policy))) &&
                    bundle_id > 0 && static_cast<u64>(bundle_id) <= mod.policy_bundle_count;
                if (!static_operands) {
                    if (has_preflight || module_has_response_read_timeout)
                        return verify_fail(
                            summary, VerifyIssueCode::InvalidForwardPreflight, fi, bi, ii);
                    continue;
                }
                const bool duration = response_read_timeout_seconds_valid(
                    mod.policy_bundles[bundle_id - 1].response_read_timeout_seconds);
                if (!duration) continue;
                const auto& policy_bundle = mod.policy_bundles[bundle_id - 1];
                const bool fixed_upload_head_policy =
                    policy_bundle.response_buffering == ForwardResponseBufferingMode::None &&
                    fixed_upload_head_route_method_is_admitted(fn.http_method) &&
                    fixed_upload_head_request_policy_is_admitted(
                        static_cast<u16>(request_policy)) &&
                    policy_bundle.response_policy_id != 0 &&
                    policy_bundle.response_policy_id <= mod.response_policy_count &&
                    policy_bundle.failure_policy_id != 0 &&
                    policy_bundle.failure_policy_id <= mod.failure_policy_count &&
                    policy_bundle.timeout_failure_policy_id != 0 &&
                    policy_bundle.timeout_failure_policy_id <= mod.failure_policy_count &&
                    fixed_upload_head_timeout_policies_valid(
                        mod.response_policies[policy_bundle.response_policy_id - 1],
                        mod.failure_policies[policy_bundle.failure_policy_id - 1],
                        mod.failure_policies[policy_bundle.timeout_failure_policy_id - 1]);
                if (!response_read_deadline_request_policy_is_admitted(
                        static_cast<u16>(request_policy)) &&
                    !fixed_upload_head_policy &&
                    !(forward_response_buffering_uses_content_length_machinery(
                          policy_bundle.response_buffering) &&
                      fn.http_method == kRouteMethodGet &&
                      static_cast<u16>(request_policy) ==
                          static_cast<u16>(RequestPolicyId::Http11FixedTrimSpPreserveHtab)))
                    return verify_fail(
                        summary, VerifyIssueCode::InvalidForwardPreflight, fi, bi, ii);
                const auto buffering = policy_bundle.response_buffering;
                const bool complete_policy =
                    complete_content_length_request_policy_is_admitted(
                        static_cast<u16>(request_policy)) ||
                    (fn.http_method == kRouteMethodGet &&
                     static_cast<u16>(request_policy) ==
                         static_cast<u16>(RequestPolicyId::Http11FixedTrimSpPreserveHtab));
                if (buffering != ForwardResponseBufferingMode::None &&
                    (!forward_response_buffering_uses_content_length_machinery(buffering) ||
                     !complete_content_length_route_method_is_admitted(fn.http_method) ||
                     request_policy < 0 || request_policy > 0xffff || !complete_policy))
                    return verify_fail(
                        summary, VerifyIssueCode::InvalidForwardPreflight, fi, bi, ii);
                if (!has_preflight || bundle_id != preflight_id ||
                    (sole_timeout_ret != nullptr && !framing_preflight))
                    return verify_fail(summary,
                                       VerifyIssueCode::InvalidForwardPreflight,
                                       fi,
                                       bi,
                                       ii,
                                       static_cast<u32>(bundle_id));
                sole_timeout_ret = &inst;
                sole_timeout_block = bi;
                timeout_ret_count++;
            }
        }
        if (eager_preflight) {
            if (sole_timeout_ret == nullptr || timeout_ret_count != 1 || fn.is_timer ||
                fn.block_count != 1 || sole_timeout_block != 0 || fn.blocks == nullptr ||
                fn.blocks[0].inst_count < 4 || fn.yield_count != 0 || fn.state_zero_enters_entry ||
                fn.has_explicit_resume_blocks || fn.rate_limit.count != 0 ||
                fn.throttle_down_bps != 0 || fn.http_cache_ttl != 0)
                return verify_fail(summary, VerifyIssueCode::InvalidForwardPreflight, fi);
            const Block& block = fn.blocks[0];
            for (u32 ii = 0; ii + 1 < block.inst_count; ii++) {
                if (block.insts[ii].op != Opcode::ConstI32)
                    return verify_fail(
                        summary, VerifyIssueCode::InvalidForwardPreflight, fi, 0, ii);
            }
            if (&block.insts[block.inst_count - 1] != sole_timeout_ret)
                return verify_fail(summary, VerifyIssueCode::InvalidForwardPreflight, fi);
        }
        if (framing_preflight) {
            const bool head_framing = fn.http_method == kRouteMethodHead;
            const bool get_framing = fn.http_method == kRouteMethodGet;
            if (timeout_ret_count != 2 || fn.is_timer || (!head_framing && !get_framing) ||
                fn.block_count != 3 || fn.blocks == nullptr || fn.values == nullptr ||
                fn.block_cap < fn.block_count || fn.value_count != 7 ||
                fn.value_cap < fn.value_count || fn.yield_count != 0 ||
                fn.state_zero_enters_entry || fn.has_explicit_resume_blocks ||
                fn.rate_limit.count != 0 || fn.throttle_down_bps != 0 || fn.http_cache_ttl != 0)
                return verify_fail(summary, VerifyIssueCode::InvalidForwardPreflight, fi);
            const Block& entry = fn.blocks[0];
            const Block& then_block = fn.blocks[1];
            const Block& else_block = fn.blocks[2];
            if (entry.id.id != 0 || then_block.id.id != 1 || else_block.id.id != 2 ||
                entry.insts == nullptr || then_block.insts == nullptr ||
                else_block.insts == nullptr || entry.inst_count != 2 ||
                then_block.inst_count != 4 || else_block.inst_count != 4)
                return verify_fail(summary, VerifyIssueCode::InvalidForwardPreflight, fi);
            auto exact_result = [&](const Instruction& inst, u32 block_id, u32 inst_id) {
                return inst.result != kNoValue && inst.result.id < fn.value_count &&
                       fn.values[inst.result.id].def_block.id == block_id &&
                       fn.values[inst.result.id].def_inst == inst_id;
            };
            auto exact_primitive_result =
                [&](const Instruction& inst, u32 block_id, u32 inst_id, TypeKind kind) {
                    if (!exact_result(inst, block_id, inst_id)) return false;
                    const Type* type = fn.values[inst.result.id].type;
                    return type != nullptr && type->kind == kind && type->inner == nullptr &&
                           type->struct_def == nullptr;
                };
            const Instruction& has_content_length = entry.insts[0];
            const Instruction& branch = entry.insts[1];
            const bool entry_shape =
                has_content_length.op == Opcode::ReqHasContentLength &&
                has_content_length.operand_count == 0 && exact_result(has_content_length, 0, 0) &&
                branch.op == Opcode::Br && branch.result == kNoValue && branch.operand_count == 1 &&
                branch.operand(0).id == has_content_length.result.id &&
                branch.imm.block_targets[0].id == 1 && branch.imm.block_targets[1].id == 2 &&
                exact_primitive_result(has_content_length, 0, 0, TypeKind::Bool);
            auto exact_forward = [&](const Block& block,
                                     RequestPolicyId expected_policy,
                                     ForwardResponseBufferingMode expected_buffering) {
                const Instruction& upstream = block.insts[0];
                const Instruction& request_policy = block.insts[1];
                const Instruction& bundle = block.insts[2];
                const Instruction& forward = block.insts[3];
                return upstream.op == Opcode::ConstI32 && upstream.operand_count == 0 &&
                       exact_primitive_result(upstream, block.id.id, 0, TypeKind::I32) &&
                       upstream.imm.i32_val >= 0 &&
                       static_cast<u64>(upstream.imm.i32_val) < mod.upstream_count &&
                       request_policy.op == Opcode::ConstI32 && request_policy.operand_count == 0 &&
                       exact_primitive_result(request_policy, block.id.id, 1, TypeKind::I32) &&
                       request_policy.imm.i32_val == static_cast<i32>(expected_policy) &&
                       bundle.op == Opcode::ConstI32 && bundle.operand_count == 0 &&
                       exact_primitive_result(bundle, block.id.id, 2, TypeKind::I32) &&
                       bundle.imm.i32_val == preflight_id &&
                       forward.op == Opcode::RetForwardBundle && forward.result == kNoValue &&
                       forward.operand_count == 3 && forward.operand(0).id == upstream.result.id &&
                       forward.operand(1).id == request_policy.result.id &&
                       forward.operand(2).id == bundle.result.id &&
                       (expected_buffering == ForwardResponseBufferingMode::None
                            ? mod.policy_bundles[preflight_id - 1].response_buffering ==
                                  ForwardResponseBufferingMode::None
                            : forward_response_buffering_uses_content_length_machinery(
                                  mod.policy_bundles[preflight_id - 1].response_buffering)) &&
                       (expected_buffering == ForwardResponseBufferingMode::None ||
                        (get_framing &&
                         mod.policy_bundles[preflight_id - 1].response_policy_id != 0 &&
                         mod.policy_bundles[preflight_id - 1].failure_policy_id != 0 &&
                         mod.policy_bundles[preflight_id - 1].timeout_failure_policy_id != 0 &&
                         complete_content_length_buffering_policies_valid(
                             mod.response_policies
                                 [mod.policy_bundles[preflight_id - 1].response_policy_id - 1],
                             mod.failure_policies
                                 [mod.policy_bundles[preflight_id - 1].failure_policy_id - 1],
                             mod.failure_policies[mod.policy_bundles[preflight_id - 1]
                                                      .timeout_failure_policy_id -
                                                  1])));
            };
            const bool exact_head =
                head_framing &&
                exact_forward(then_block,
                              RequestPolicyId::Http11FixedStripContentLengthAfterHost,
                              ForwardResponseBufferingMode::None) &&
                exact_forward(else_block,
                              RequestPolicyId::Http11FixedStrip,
                              ForwardResponseBufferingMode::None);
            const bool exact_get =
                get_framing &&
                exact_forward(then_block,
                              RequestPolicyId::Http11FixedStrip,
                              ForwardResponseBufferingMode::CompleteContentLength) &&
                exact_forward(else_block,
                              RequestPolicyId::Http11FixedTrimSpPreserveHtab,
                              ForwardResponseBufferingMode::CompleteContentLength);
            if (!entry_shape || (!exact_head && !exact_get) ||
                then_block.insts[0].imm.i32_val != else_block.insts[0].imm.i32_val ||
                (get_framing && !forward_response_buffering_uses_content_length_machinery(
                                    mod.policy_bundles[preflight_id - 1].response_buffering)) ||
                (head_framing && mod.policy_bundles[preflight_id - 1].response_buffering !=
                                     ForwardResponseBufferingMode::None))
                return verify_fail(summary, VerifyIssueCode::InvalidForwardPreflight, fi);
        }
        if (deferred_preflight) {
            if (sole_timeout_ret == nullptr || timeout_ret_count != 1 || fn.is_timer ||
                fn.http_method == kRouteMethodAny ||
                !complete_content_length_route_method_is_admitted(fn.http_method) ||
                fn.block_count != 3 || fn.blocks == nullptr || fn.values == nullptr ||
                fn.block_cap < fn.block_count || fn.value_count != 6 ||
                fn.value_cap < fn.value_count || fn.yield_count != 0 ||
                fn.state_zero_enters_entry || fn.has_explicit_resume_blocks ||
                fn.rate_limit.count != 0 || fn.throttle_down_bps != 0 || fn.http_cache_ttl != 0)
                return verify_fail(summary, VerifyIssueCode::InvalidForwardPreflight, fi);
            const Block& entry = fn.blocks[0];
            const Block& then_block = fn.blocks[1];
            const Block& else_block = fn.blocks[2];
            if (entry.id.id != 0 || then_block.id.id != 1 || else_block.id.id != 2 ||
                entry.insts == nullptr || then_block.insts == nullptr ||
                else_block.insts == nullptr || entry.inst_count != 4 ||
                then_block.inst_count != 1 || else_block.inst_count != 4)
                return verify_fail(summary, VerifyIssueCode::InvalidForwardPreflight, fi);
            const Instruction& path = entry.insts[0];
            const Instruction& literal = entry.insts[1];
            const Instruction& eq = entry.insts[2];
            const Instruction& branch = entry.insts[3];
            const Instruction& redirect = then_block.insts[0];
            const Instruction& upstream = else_block.insts[0];
            const Instruction& request_policy = else_block.insts[1];
            const Instruction& bundle = else_block.insts[2];
            const Instruction& forward = else_block.insts[3];
            auto exact_result = [&](const Instruction& inst, u32 block_id, u32 inst_id) {
                return inst.result != kNoValue && inst.result.id < fn.value_count &&
                       fn.values[inst.result.id].def_block.id == block_id &&
                       fn.values[inst.result.id].def_inst == inst_id;
            };
            auto exact_primitive_result =
                [&](const Instruction& inst, u32 block_id, u32 inst_id, TypeKind kind) {
                    if (!exact_result(inst, block_id, inst_id)) return false;
                    const Type* type = fn.values[inst.result.id].type;
                    return type != nullptr && type->kind == kind && type->inner == nullptr &&
                           type->struct_def == nullptr;
                };
            const bool entry_shape =
                path.op == Opcode::ReqPathOnly && path.operand_count == 0 &&
                exact_result(path, 0, 0) && literal.op == Opcode::ConstStr &&
                literal.operand_count == 0 && exact_result(literal, 0, 1) &&
                (literal.imm.str_val.len == 0 || literal.imm.str_val.ptr != nullptr) &&
                eq.op == Opcode::CmpEq && eq.operand_count == 2 && exact_result(eq, 0, 2) &&
                eq.operand(0).id == path.result.id && eq.operand(1).id == literal.result.id &&
                branch.op == Opcode::Br && branch.result == kNoValue && branch.operand_count == 1 &&
                branch.operand(0).id == eq.result.id && branch.imm.block_targets[0].id == 1 &&
                branch.imm.block_targets[1].id == 2;
            const bool result_types = exact_primitive_result(path, 0, 0, TypeKind::Str) &&
                                      exact_primitive_result(literal, 0, 1, TypeKind::Str) &&
                                      exact_primitive_result(eq, 0, 2, TypeKind::Bool) &&
                                      exact_primitive_result(upstream, 2, 0, TypeKind::I32) &&
                                      exact_primitive_result(request_policy, 2, 1, TypeKind::I32) &&
                                      exact_primitive_result(bundle, 2, 2, TypeKind::I32);
            const i64 redirect_id = redirect.imm.i32_val;
            const bool redirect_shape =
                redirect.op == Opcode::RetRedirect && redirect.result == kNoValue &&
                redirect.operand_count == 0 && redirect_id > 0 &&
                static_cast<u64>(redirect_id) <= mod.redirect_policy_count &&
                redirect_policy_spec_valid(mod.redirect_policies[redirect_id - 1]);
            const bool forward_shape =
                upstream.op == Opcode::ConstI32 && upstream.operand_count == 0 &&
                exact_result(upstream, 2, 0) && upstream.imm.i32_val >= 0 &&
                static_cast<u64>(upstream.imm.i32_val) < mod.upstream_count &&
                request_policy.op == Opcode::ConstI32 && request_policy.operand_count == 0 &&
                exact_result(request_policy, 2, 1) && request_policy.imm.i32_val >= 0 &&
                request_policy.imm.i32_val <= 0xffff &&
                (complete_content_length_request_policy_is_admitted(
                     static_cast<u16>(request_policy.imm.i32_val)) ||
                 (fn.http_method == kRouteMethodGet &&
                  static_cast<u16>(request_policy.imm.i32_val) ==
                      static_cast<u16>(RequestPolicyId::Http11FixedTrimSpPreserveHtab))) &&
                bundle.op == Opcode::ConstI32 && bundle.operand_count == 0 &&
                exact_result(bundle, 2, 2) && bundle.imm.i32_val == preflight_id &&
                forward.op == Opcode::RetForwardBundle && forward.result == kNoValue &&
                forward.operand_count == 3 && forward.operand(0).id == upstream.result.id &&
                forward.operand(1).id == request_policy.result.id &&
                forward.operand(2).id == bundle.result.id && &forward == sole_timeout_ret &&
                forward_response_buffering_uses_content_length_machinery(
                    mod.policy_bundles[preflight_id - 1].response_buffering);
            if (!entry_shape || !result_types || !redirect_shape || !forward_shape)
                return verify_fail(summary, VerifyIssueCode::InvalidForwardPreflight, fi);
        }
        for (u32 bi = 0; bi < mod.functions[fi].block_count; bi++) {
            const auto& block = mod.functions[fi].blocks[bi];
            if (block.inst_count == 0 || block.insts == nullptr) continue;
            const auto& term = block.insts[block.inst_count - 1];
            if (term.op == Opcode::RetRedirect) {
                const i64 id = term.imm.i32_val;
                if (id <= 0 || static_cast<u64>(id) > mod.redirect_policy_count ||
                    !redirect_policy_spec_valid(mod.redirect_policies[id - 1]))
                    return verify_fail(summary,
                                       VerifyIssueCode::InvalidRedirectPolicyId,
                                       fi,
                                       bi,
                                       block.inst_count - 1,
                                       static_cast<u32>(id));
            }
        }
        VerifyResult result = verify_function(&mod.functions[fi], fi, options);
        if (!result.ok) return result;
        summary.block_count += result.summary.block_count;
        summary.reachable_block_count += result.summary.reachable_block_count;
        summary.terminal_block_count += result.summary.terminal_block_count;
        summary.yield_count += result.summary.yield_count;
        summary.branch_edge_count += result.summary.branch_edge_count;
    }

    VerifyResult result{};
    result.ok = true;
    result.summary = summary;
    return result;
}

}  // namespace detail

inline VerifyResult verify_module(const Module& mod, VerifyOptions options = {}) {
    return detail::verify_module_impl(mod, options, false);
}

inline VerifyResult verify_module_for_internal_propagation(const Module& mod,
                                                           VerifyOptions options = {}) {
    return detail::verify_module_impl(mod, options, true);
}

inline const char* verify_issue_code_name(VerifyIssueCode code) {
    switch (code) {
        case VerifyIssueCode::None:
            return "None";
        case VerifyIssueCode::MissingFunction:
            return "MissingFunction";
        case VerifyIssueCode::MissingBlocks:
            return "MissingBlocks";
        case VerifyIssueCode::MissingEntry:
            return "MissingEntry";
        case VerifyIssueCode::BlockIdMismatch:
            return "BlockIdMismatch";
        case VerifyIssueCode::MissingInstructions:
            return "MissingInstructions";
        case VerifyIssueCode::MissingTerminator:
            return "MissingTerminator";
        case VerifyIssueCode::TerminatorBeforeEnd:
            return "TerminatorBeforeEnd";
        case VerifyIssueCode::InvalidBranchTarget:
            return "InvalidBranchTarget";
        case VerifyIssueCode::InvalidJumpTarget:
            return "InvalidJumpTarget";
        case VerifyIssueCode::InvalidRedirectPolicyId:
            return "InvalidRedirectPolicyId";
        case VerifyIssueCode::InvalidHttpCachePolicy:
            return "InvalidHttpCachePolicy";
        case VerifyIssueCode::InvalidPreRoutePolicyId:
            return "InvalidPreRoutePolicyId";
        case VerifyIssueCode::InvalidUnmatchedPolicyId:
            return "InvalidUnmatchedPolicyId";
        case VerifyIssueCode::InvalidExactStrictLocalResponseBinding:
            return "InvalidExactStrictLocalResponseBinding";
        case VerifyIssueCode::InvalidStateZeroEntry:
            return "InvalidStateZeroEntry";
        case VerifyIssueCode::InvalidResumeBlock:
            return "InvalidResumeBlock";
        case VerifyIssueCode::MissingYieldResumeMapping:
            return "MissingYieldResumeMapping";
        case VerifyIssueCode::MissingYieldMetadata:
            return "MissingYieldMetadata";
        case VerifyIssueCode::UnsupportedYieldTerminator:
            return "UnsupportedYieldTerminator";
        case VerifyIssueCode::InvalidYieldKind:
            return "InvalidYieldKind";
        case VerifyIssueCode::InvalidYieldNextState:
            return "InvalidYieldNextState";
        case VerifyIssueCode::DuplicateYieldNextState:
            return "DuplicateYieldNextState";
        case VerifyIssueCode::MissingYieldNextState:
            return "MissingYieldNextState";
        case VerifyIssueCode::YieldMetadataMismatch:
            return "YieldMetadataMismatch";
        case VerifyIssueCode::InvalidYieldRuntimeProtocol:
            return "InvalidYieldRuntimeProtocol";
        case VerifyIssueCode::InvalidHandlerAutomaton:
            return "InvalidHandlerAutomaton";
        case VerifyIssueCode::InvalidRuntimeStateModel:
            return "InvalidRuntimeStateModel";
        case VerifyIssueCode::NonYieldingControlCycle:
            return "NonYieldingControlCycle";
        case VerifyIssueCode::HandlerLivelock:
            return "HandlerLivelock";
        case VerifyIssueCode::HandlerDeadlock:
            return "HandlerDeadlock";
        case VerifyIssueCode::ConcurrentProtocolFailure:
            return "ConcurrentProtocolFailure";
        case VerifyIssueCode::ConcurrentVerificationLimit:
            return "ConcurrentVerificationLimit";
        case VerifyIssueCode::YieldCountMismatch:
            return "YieldCountMismatch";
        case VerifyIssueCode::TooManyYieldStates:
            return "TooManyYieldStates";
        case VerifyIssueCode::TooManyBlocks:
            return "TooManyBlocks";
        case VerifyIssueCode::UnreachableBlock:
            return "UnreachableBlock";
        case VerifyIssueCode::InvalidForwardPreflight:
            return "InvalidForwardPreflight";
        case VerifyIssueCode::InvalidPasswordPrefix:
            return "InvalidPasswordPrefix";
        case VerifyIssueCode::InvalidHttpCallProfile:
            return "InvalidHttpCallProfile";
        case VerifyIssueCode::InvalidJwtClaimsLifetime:
            return "InvalidJwtClaimsLifetime";
        case VerifyIssueCode::InvalidPhi:
            return "InvalidPhi";
        case VerifyIssueCode::InvalidWsOutput:
            return "InvalidWsOutput";
        case VerifyIssueCode::InvalidWsMessageField:
            return "InvalidWsMessageField";
        case VerifyIssueCode::InvalidStringOperation:
            return "InvalidStringOperation";
        case VerifyIssueCode::InvalidStrLength:
            return "InvalidStrLength";
    }
    return "Unknown";
}

inline void format_verify_result(PrintBuf& buf, const VerifyResult& result) {
    buf.put_cstr("rir verifier: ");
    if (result.ok) {
        buf.put_cstr("ok");
        return;
    }

    buf.put_cstr(verify_issue_code_name(result.issue.code));
    buf.put_cstr(" function=");
    buf.put_u32(result.issue.function_index);
    buf.put_cstr(" block=");
    buf.put_u32(result.issue.block_index);
    buf.put_cstr(" inst=");
    buf.put_u32(result.issue.inst_index);

    if (result.issue.code == VerifyIssueCode::UnsupportedYieldTerminator) {
        buf.put_cstr(" opcode=");
        print_opcode(buf, static_cast<Opcode>(result.issue.target_index));
    } else {
        buf.put_cstr(" target=");
        buf.put_u32(result.issue.target_index);
    }

    if (result.issue.code == VerifyIssueCode::InvalidYieldRuntimeProtocol) {
        const u8 kind = static_cast<u8>(result.issue.target_index);
        const u32 payload = result.issue.detail_index;
        const VerifyRuntimeProtocolCheck runtime_check =
            VerifyRuntimeProtocolModel::check_yield(kind, payload);
        buf.put_cstr(" trace=yield kind=");
        buf.put_cstr(verify_yield_kind_name(kind));
        buf.put_cstr(" payload=");
        buf.put_u32(payload);
        buf.put_cstr(" pending_op=");
        buf.put_cstr(verify_runtime_pending_op_name(runtime_check.pending_op));
        buf.put_cstr(" callback_slot=");
        buf.put_cstr(verify_runtime_callback_slot_name(runtime_check.callback_slot));
        buf.put_cstr(" reason=");
        buf.put_cstr(verify_runtime_protocol_reason_name(runtime_check.reason));
    }
    if ((result.issue.code == VerifyIssueCode::ConcurrentProtocolFailure ||
         result.issue.code == VerifyIssueCode::ConcurrentVerificationLimit) &&
        result.issue.detail_index) {
        buf.put_cstr(" concurrent=");
        buf.put_cstr(verify::issue_name(static_cast<verify::Issue>(result.issue.detail_index)));
    }
    if (result.issue.trace_count) {
        buf.put_cstr(result.issue.trace_is_protocol ? " protocol-path=" : " path=");
        for (u32 i = 0; i < result.issue.trace_count; ++i) {
            if (i) buf.put_cstr("->");
            if (i == result.issue.cycle_start) buf.put_cstr("cycle:");
            if (result.issue.trace_has_actors) {
                buf.put('a');
                buf.put_u32(result.issue.trace_actors[i]);
                buf.put(':');
            }
            buf.put_u32(result.issue.trace[i]);
        }
        if (result.issue.trace_truncated) buf.put_cstr("->...");
    }
}

}  // namespace rir
}  // namespace rut
