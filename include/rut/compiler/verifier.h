#pragma once

#include "rut/common/http_header_validation.h"
#include "rut/common/http_query.h"
#include "rut/common/request_policy.h"
#include "rut/common/ws_message.h"
#include "rut/compiler/concurrency_verifier.h"
#include "rut/compiler/http_call_profile.h"
#include "rut/compiler/password_profile.h"
#include "rut/compiler/rir.h"
#include "rut/compiler/rir_printer.h"
#include "rut/jit/handler_abi.h"
#include "rut/jit/yield_contract.h"
#include "rut/runtime/consistent_hash.h"
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
    if (inst.op == Opcode::StrRegexCapture) {
        if (inst.operand_count != 2 || inst.extra_operands || !fn.values || !fn.blocks ||
            !inst.imm.str_val.ptr || inst.imm.str_val.len == 0 || inst.imm.str_val.len > 1024 ||
            inst.result == kNoValue || inst.result.id >= fn.value_count)
            return false;
        const auto exact = [&](ValueId id, TypeKind kind) {
            if (id == kNoValue || id.id >= fn.value_count) return false;
            const Type* type = fn.values[id.id].type;
            return type && type->kind == kind && !type->inner && !type->struct_def;
        };
        const Type* result = fn.values[inst.result.id].type;
        if (!exact(inst.operands[0], TypeKind::Str) || !exact(inst.operands[1], TypeKind::I32) ||
            !result || result->kind != TypeKind::Optional || result->struct_def || !result->inner ||
            result->inner->kind != TypeKind::Str || result->inner->inner ||
            result->inner->struct_def)
            return false;
        const Value& value = fn.values[inst.operands[1].id];
        if (value.def_block.id >= fn.block_count) return false;
        const Block& block = fn.blocks[value.def_block.id];
        if (!block.insts || value.def_inst >= block.inst_count) return false;
        const Instruction& group = block.insts[value.def_inst];
        return group.op == Opcode::ConstI32 && group.result == inst.operands[1] &&
               group.imm.i32_val >= 0 && group.imm.i32_val <= 8;
    }
    if (inst.op == Opcode::ReqRoutingString || inst.op == Opcode::ReqConnectionScalar) {
        if (inst.operand_count != 0 || inst.extra_operands || inst.imm.i32_val < 0 ||
            inst.imm.i32_val > 2 || inst.result == kNoValue || !fn.values ||
            inst.result.id >= fn.value_count)
            return false;
        const Type* type = fn.values[inst.result.id].type;
        if (!type || type->struct_def) return false;
        if (inst.op == Opcode::ReqConnectionScalar)
            return !type->inner &&
                   type->kind == (inst.imm.i32_val == 2 ? TypeKind::Bool : TypeKind::I32);
        return type->kind == TypeKind::Optional && type->inner &&
               type->inner->kind == TypeKind::Str && !type->inner->inner &&
               !type->inner->struct_def;
    }
    if (inst.op != Opcode::StrPredicate && inst.op != Opcode::StrInterpolate &&
        inst.op != Opcode::StrTrimPrefix && inst.op != Opcode::StrTrimSuffix &&
        inst.op != Opcode::ReqSetPath && inst.op != Opcode::ReqSetHash)
        return true;
    if (inst.operand_count <= kMaxInlineOperands && inst.extra_operands) return false;
    const auto kExact = [&](ValueId id, TypeKind kind) {
        if (id == kNoValue || id.id >= fn.value_count || !fn.values) return false;
        const Type* type = fn.values[id.id].type;
        return type && type->kind == kind && !type->inner && !type->struct_def;
    };
    if (inst.op == Opcode::ReqSetHash) {
        if (inst.result != kNoValue || inst.operand_count != 2 ||
            (!kExact(inst.operand(0), TypeKind::Str) && !kExact(inst.operand(0), TypeKind::IP)) ||
            !kExact(inst.operand(1), TypeKind::Str))
            return false;
        const auto& v = fn.values[inst.operand(1).id];
        if (v.def_block.id >= fn.block_count || !fn.blocks) return false;
        const auto& block = fn.blocks[v.def_block.id];
        if (!block.insts || v.def_inst >= block.inst_count) return false;
        const auto& seed = block.insts[v.def_inst];
        u8 decoded[16];
        return seed.op == Opcode::ConstStr && seed.result == inst.operand(1) &&
               consistent_hash_seed(seed.imm.str_val, decoded);
    }
    if (inst.op == Opcode::ReqSetPath) {
        if (inst.result != kNoValue || inst.operand_count != 1 ||
            !kExact(inst.operand(0), TypeKind::Str) ||
            (inst.imm.i32_val != 0 && inst.imm.i32_val != 1))
            return false;
        if (inst.imm.i32_val == 1) return true;
        const auto& value = fn.values[inst.operand(0).id];
        if (value.def_block.id >= fn.block_count || !fn.blocks) return false;
        const auto& block = fn.blocks[value.def_block.id];
        return block.insts && value.def_inst < block.inst_count &&
               block.insts[value.def_inst].op == Opcode::ConstStr &&
               block.insts[value.def_inst].result == inst.operand(0);
    }
    if (inst.op == Opcode::StrTrimPrefix || inst.op == Opcode::StrTrimSuffix) {
        return inst.operand_count == 2 && kExact(inst.result, TypeKind::Str) &&
               kExact(inst.operand(0), TypeKind::Str) && kExact(inst.operand(1), TypeKind::Str);
    }
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
struct VerifyPeerArm {
    // Exactly one bit from the actual yield's wait_arm_mask.
    u8 arm_mask = 0;
    u64 completion_set = 0;
    u64 completion_clear = 0;
};

struct VerifyPeerBinding {
    u32 block_index = 0;
    u64 submit_set = 0;
    u64 completion_set = 0;
    u64 completion_clear = 0;
    // Explicit alternatives for an OR wait. Legacy fields above describe a
    // single arm only; explicit arms must cover the exact encoded mask.
    u8 arm_count = 0;
    VerifyPeerArm arms[2]{};
    // Assertions expose invalid ownership/acknowledgement dependencies as
    // safety errors rather than hiding them behind a disabled submission.
    u64 submit_require_set = 0;
    u64 submit_require_clear = 0;
};

struct VerifyPeerEnvironment {
    u32 function_index = 0;
    const verify::Model* model = nullptr;
    const VerifyPeerBinding* bindings = nullptr;
    u32 binding_count = 0;
    // A supplied contract is complete by default. Partial contracts must opt
    // into external-completion assumptions explicitly.
    bool require_all_yields_bound = true;
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
    return jit::yield_contract(static_cast<jit::YieldKind>(kind), 0).primary != jit::YieldArm::None;
}

enum class VerifyYieldRuntimeClass : u8 {
    Timer,
    Event,
    Unsupported,
};

using VerifyRuntimePendingOp = jit::YieldArm;

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

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
constexpr VerifyRuntimeCallbackSlot verify_callback_for_arm(jit::YieldArm op) {
    using enum VerifyRuntimeCallbackSlot;
    switch (op) {
        case jit::YieldArm::None:
            return None;
        case jit::YieldArm::Timer:
            return HandlerTimer;
        case jit::YieldArm::DownstreamRecv:
            return DownstreamRecv;
        case jit::YieldArm::DownstreamSend:
            return DownstreamSend;
        case jit::YieldArm::UpstreamRecv:
            return UpstreamRecv;
        case jit::YieldArm::UpstreamConnect:
        case jit::YieldArm::UpstreamSend:
            return UpstreamSend;
    }
    return None;
}
#pragma GCC diagnostic pop

struct VerifyRuntimeProtocolModel {
    static constexpr VerifyRuntimeProtocolCheck check_yield(u8 kind, u32 payload) {
        VerifyRuntimeProtocolCheck check{};
        const auto contract = jit::yield_contract(static_cast<jit::YieldKind>(kind), payload);
        check.pending_op = contract.primary;
        check.callback_slot = verify_callback_for_arm(contract.primary);
        if (contract.primary == jit::YieldArm::None) {
            check.reason = VerifyRuntimeProtocolReason::UnsupportedEventYield;
            return check;
        }
        if (contract.requires_target() && payload == 0) {
            check.reason = VerifyRuntimeProtocolReason::MissingUpstreamTarget;
            return check;
        }
        check.ok = true;
        check.secondary_pending_op = contract.secondary;
        check.secondary_callback_slot = verify_callback_for_arm(contract.secondary);
        check.submit_transition = check.completion_transition = check.fail_closed_transition = true;
        const u8 arms = contract.secondary == jit::YieldArm::None ? 1 : 2;
        check.submit_transition_count = check.completion_transition_count =
            check.fail_closed_transition_count = arms;
        return check;
    }
};

constexpr u8 verify_yield_default_arm_mask(u8 kind, u32 payload) {
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

constexpr u8 verify_runtime_pending_op_arm_mask(VerifyRuntimePendingOp op) {
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

// Owns generated handler/peer actions. Peer invariants remain borrowed and
// must outlive this composition, just as the input peer contract must.
struct VerifyHandlerProtocolModel {
    MmapArena arena{};
    verify::Model model{};
    VerifyHandlerProtocolModel() = default;
    ~VerifyHandlerProtocolModel() { arena.destroy(); }
    VerifyHandlerProtocolModel(const VerifyHandlerProtocolModel&) = delete;
    VerifyHandlerProtocolModel& operator=(const VerifyHandlerProtocolModel&) = delete;
};

// The compiler and offline model exporters use the same composition builder.
// Building is not verification: callers must check the result, then check(model).
VerifyResult build_handler_protocol_model(const VerifyHandlerAutomaton& automaton,
                                          u32 root,
                                          const VerifyPeerEnvironment* environment,
                                          VerifyHandlerProtocolModel& out,
                                          u32 function_index = 0,
                                          VerifySummary summary = {});

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
    const auto arm = jit::yield_contract(static_cast<jit::YieldKind>(kind), 0).primary;
    if (arm == jit::YieldArm::None) return VerifyYieldRuntimeClass::Unsupported;
    return arm == jit::YieldArm::Timer ? VerifyYieldRuntimeClass::Timer
                                       : VerifyYieldRuntimeClass::Event;
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
        if (callback_mask == 0 || pending_arm_mask == 0 ||
            node.runtime.callback_slot != verify_callback_for_arm(node.runtime.pending_op) ||
            node.runtime.secondary_callback_slot !=
                verify_callback_for_arm(node.runtime.secondary_pending_op)) {
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
    const bool header_all = inst.op == Opcode::ReqHeaderAll;
    const bool kQueryAll = inst.op == Opcode::ReqQueryAll;
    const bool kAllocation = inst.op == Opcode::ArrayNew || header_all || kQueryAll;
    const bool push = inst.op == Opcode::ArrayPush;
    const bool count = inst.op == Opcode::ArrayLen;
    const bool get = inst.op == Opcode::ArrayGet;
    if (!kAllocation && !push && !count && !get) return true;
    if (!fn.values || inst.result == kNoValue || inst.result.id >= fn.value_count ||
        inst.extra_operands ||
        inst.operand_count != (kAllocation ? 0u
                               : count     ? 1u
                                           : 2u))
        return false;
    for (u32 i = 0; i < inst.operand_count; ++i)
        if (inst.operands[i] == kNoValue || inst.operands[i].id >= fn.value_count) return false;
    const Type* result = fn.values[inst.result.id].type;
    if (!result || result->struct_def) return false;
    const Type* array = kAllocation ? result->inner : fn.values[inst.operands[0].id].type;
    if (!array || array->kind != TypeKind::Array || array->struct_def ||
        !collected_element_type(array->inner))
        return false;
    if (header_all || kQueryAll) {
        if (result->kind != TypeKind::Optional || array->inner->kind != TypeKind::Str ||
            !inst.imm.str_val.ptr || !inst.imm.str_val.len)
            return false;
        if (kQueryAll) return http_query_name_valid(inst.imm.str_val);
        for (u32 i = 0; i < inst.imm.str_val.len; ++i)
            if (!is_http_tchar(static_cast<u8>(inst.imm.str_val.ptr[i]))) return false;
        return true;
    }
    if (kAllocation)
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

VerifyResult verify_function(const Function* fn,
                             u32 function_index = 0,
                             VerifyOptions options = {});

VerifyResult verify_module(const Module& mod, VerifyOptions options = {});
VerifyResult verify_module_for_internal_propagation(const Module& mod, VerifyOptions options = {});

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
