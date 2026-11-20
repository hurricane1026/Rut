#include "rut/compiler/verifier.h"

#include "rut/common/failure_policy.h"
#include "rut/common/forward_policy_head_mode.h"
#include "rut/common/forward_preflight.h"
#include "rut/common/load_balance.h"
#include "rut/common/redirect_policy.h"
#include "rut/common/request_policy.h"
#include "rut/common/response_policy.h"
#include "rut/common/strict_local_response.h"
#include "rut/common/types.h"
#include "rut/common/ws_message.h"
#include "rut/compiler/http_call_profile.h"
#include "rut/compiler/password_profile.h"
#include "rut/compiler/rir.h"
#include "rut/runtime/route_method.h"

namespace rut::rir {

VerifyResult verify_function(const Function* fn, u32 function_index, VerifyOptions options) {
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

namespace {

VerifyResult verify_module_impl(const Module& mod,
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
                    if ((encoded & 255) == static_cast<u32>(LoadBalancePolicy::ConsistentHash)) {
                        i32 ch_upstream = -1;
                        u32 hashes = 0;
                        for (u32 before = 0; before < ii; ++before)
                            if (block.insts[before].op == Opcode::ReqSetHash) ++hashes;
                        if (hashes != 1 || inst.operand_count == 0 ||
                            !const_i32(inst.operand(0), &ch_upstream) || ch_upstream < 0 ||
                            static_cast<u32>(ch_upstream) >= mod.upstream_count)
                            return verify_fail(
                                summary, VerifyIssueCode::InvalidForwardPreflight, fi, bi, ii);
                        const auto& up = mod.upstreams[ch_upstream];
                        if (!up.has_address || !up.port || up.extra_count > 7)
                            return verify_fail(
                                summary, VerifyIssueCode::InvalidForwardPreflight, fi, bi, ii);
                        for (u32 i = 0; i < up.extra_count; ++i) {
                            if (!up.extra_ports[i] ||
                                (up.extra_ips[i] == up.ip && up.extra_ports[i] == up.port))
                                return verify_fail(
                                    summary, VerifyIssueCode::InvalidForwardPreflight, fi, bi, ii);
                            for (u32 j = 0; j < i; ++j)
                                if (up.extra_ips[i] == up.extra_ips[j] &&
                                    up.extra_ports[i] == up.extra_ports[j])
                                    return verify_fail(summary,
                                                       VerifyIssueCode::InvalidForwardPreflight,
                                                       fi,
                                                       bi,
                                                       ii);
                        }
                    }
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

}  // namespace

VerifyResult verify_module(const Module& mod, VerifyOptions options) {
    return verify_module_impl(mod, options, false);
}

VerifyResult verify_module_for_internal_propagation(const Module& mod, VerifyOptions options) {
    return verify_module_impl(mod, options, true);
}

}  // namespace rut::rir
