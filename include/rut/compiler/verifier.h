#pragma once

#include "rut/compiler/rir.h"
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
    MissingYieldMetadata,
    UnsupportedYieldTerminator,
    InvalidYieldKind,
    InvalidYieldNextState,
    YieldMetadataMismatch,
    YieldCountMismatch,
    TooManyBlocks,
    UnreachableBlock,
};

struct VerifyIssue {
    VerifyIssueCode code = VerifyIssueCode::None;
    u32 function_index = 0;
    u32 block_index = 0;
    u32 inst_index = 0;
    u32 target_index = 0;
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
                                u32 target_index = 0) {
    VerifyResult result{};
    result.ok = false;
    result.summary = summary;
    result.issue.code = code;
    result.issue.function_index = function_index;
    result.issue.block_index = block_index;
    result.issue.inst_index = inst_index;
    result.issue.target_index = target_index;
    return result;
}

inline bool verify_valid_yield_kind(u8 kind) {
    return kind <= static_cast<u8>(jit::YieldKind::UpstreamSend);
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

    summary.block_count = fn->block_count;

    bool reachable[kMaxVerifierBlocks]{};
    u32 worklist[kMaxVerifierBlocks]{};
    u32 work_start = 0;
    u32 work_end = 0;

    reachable[0] = true;
    worklist[work_end++] = 0;

    u32 seen_yield_terminators = 0;

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
    if (fn->yield_count > 0 && (fn->yield_payload == nullptr || fn->yield_kinds == nullptr)) {
        return verify_fail(summary, VerifyIssueCode::MissingYieldMetadata, function_index);
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
            const u8 kind = verify_yield_timer_kind(term);
            const u32 payload = static_cast<u32>(static_cast<u64>(term.imm.i64_val));

            if (next_state == 0 || next_state > fn->yield_count) {
                return verify_fail(summary,
                                   VerifyIssueCode::InvalidYieldNextState,
                                   function_index,
                                   bi,
                                   block.inst_count - 1,
                                   next_state);
            }
            const u32 yi = static_cast<u32>(next_state - 1);
            if (fn->yield_kinds[yi] != kind || fn->yield_payload[yi] != payload) {
                return verify_fail(summary,
                                   VerifyIssueCode::YieldMetadataMismatch,
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

}  // namespace rir
}  // namespace rut
