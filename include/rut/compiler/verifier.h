#pragma once

#include "rut/compiler/rir.h"
#include "rut/compiler/rir_printer.h"
#include "rut/jit/handler_abi.h"

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
    YieldCountMismatch,
    TooManyYieldStates,
    TooManyBlocks,
    UnreachableBlock,
};

struct VerifyIssue {
    VerifyIssueCode code = VerifyIssueCode::None;
    u32 function_index = 0;
    u32 block_index = 0;
    u32 inst_index = 0;
    u32 target_index = 0;
    u32 detail_index = 0;
};

struct VerifySummary {
    u32 function_count = 0;
    u32 block_count = 0;
    u32 reachable_block_count = 0;
    u32 terminal_block_count = 0;
    u32 yield_count = 0;
    u32 branch_edge_count = 0;
};

struct VerifyOptions {
    // Rut route automata should not carry dead blocks: dead IR makes later
    // verifier traces ambiguous and can hide stale lowering paths.
    bool require_all_blocks_reachable = true;
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
            return 1u << 2;
        case VerifyRuntimeCallbackSlot::UpstreamSend:
            return 1u << 3;
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

    VerifyResult result{};
    result.ok = true;
    result.summary = summary;
    return result;
}

inline VerifyResult verify_module(const Module& mod, VerifyOptions options = {}) {
    VerifySummary summary{};
    summary.function_count = mod.func_count;

    if (mod.func_count > 0 && mod.functions == nullptr) {
        return verify_fail(summary, VerifyIssueCode::MissingFunction, 0);
    }

    for (u32 fi = 0; fi < mod.func_count; fi++) {
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
        case VerifyIssueCode::YieldCountMismatch:
            return "YieldCountMismatch";
        case VerifyIssueCode::TooManyYieldStates:
            return "TooManyYieldStates";
        case VerifyIssueCode::TooManyBlocks:
            return "TooManyBlocks";
        case VerifyIssueCode::UnreachableBlock:
            return "UnreachableBlock";
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
}

}  // namespace rir
}  // namespace rut
