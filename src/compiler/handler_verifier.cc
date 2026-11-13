#include "rut/common/types.h"
#include "rut/compiler/concurrency_verifier.h"
#include "rut/compiler/verifier.h"
#include "rut/runtime/arena.h"

namespace rut::rir {
namespace {

VerifyIssueCode issue_code(verify::Issue issue) {
    switch (issue) {
        case verify::Issue::Livelock:
            return VerifyIssueCode::HandlerLivelock;
        case verify::Issue::Deadlock:
            return VerifyIssueCode::HandlerDeadlock;
        case verify::Issue::OutOfMemory:
        case verify::Issue::StateLimit:
        case verify::Issue::EdgeLimit:
        case verify::Issue::WorkLimit:
            return VerifyIssueCode::ConcurrentVerificationLimit;
        case verify::Issue::None:
        case verify::Issue::InvalidModel:
        case verify::Issue::UnsafeAction:
        case verify::Issue::InvariantViolation:
        case verify::Issue::ResourceLeak:
            return VerifyIssueCode::ConcurrentProtocolFailure;
    }
    return VerifyIssueCode::ConcurrentProtocolFailure;
}

VerifyResult failure(const verify::Result& checked,
                     const verify::Model& model,
                     u32 function_index,
                     VerifySummary summary) {
    auto result = verify_fail(summary,
                              issue_code(checked.issue),
                              function_index,
                              checked.witness.locations[0],
                              0,
                              checked.action,
                              static_cast<u32>(checked.issue));
    result.issue.trace_truncated = checked.trace_truncated;
    result.issue.trace_has_actors = model.actor_count > 1;
    for (u32 i = 0; i < checked.trace_count; ++i) {
        if (i == VerifyIssue::kMaxTrace) {
            result.issue.trace_truncated = true;
            break;
        }
        const u32 kAction = checked.trace[i].action;
        const u8 kActor = kAction == verify::kNoIndex ? 0 : model.actions[kAction].actor;
        result.issue.trace_actors[i] = kActor;
        result.issue.trace[result.issue.trace_count++] = checked.trace[i].state.locations[kActor];
        if (i == checked.cycle_start) result.issue.cycle_start = static_cast<u8>(i);
    }
    return result;
}

}  // namespace

VerifyResult build_handler_protocol_model(const VerifyHandlerAutomaton& automaton,
                                          u32 root,
                                          const VerifyPeerEnvironment* environment,
                                          VerifyHandlerProtocolModel& out,
                                          u32 function_index,
                                          VerifySummary summary) {
    out.model = {};
    out.arena.destroy();
    if (!automaton.node_count || automaton.node_count > VerifyHandlerAutomaton::kMaxNodes ||
        root >= automaton.node_count)
        return verify_fail(summary, VerifyIssueCode::InvalidHandlerAutomaton, function_index);
    for (u32 i = 0; i < automaton.node_count; ++i) {
        const auto& node = automaton.nodes[i];
        const u32 kExpected = node.kind == VerifyHandlerNodeKind::Terminal ? 0u
                              : node.kind == VerifyHandlerNodeKind::Branch ? 2u
                                                                           : 1u;
        if (node.kind > VerifyHandlerNodeKind::Yield || node.target_count != kExpected)
            return verify_fail(
                summary, VerifyIssueCode::InvalidHandlerAutomaton, function_index, i);
        if (node.kind == VerifyHandlerNodeKind::Yield &&
            (!node.wait_arm_mask || node.wait_arm_mask >= 64))
            return verify_fail(summary,
                               VerifyIssueCode::ConcurrentProtocolFailure,
                               function_index,
                               i,
                               node.inst_index,
                               node.wait_arm_mask);
        for (u32 j = 0; j < node.target_count; ++j)
            if (node.targets[j] >= automaton.node_count)
                return verify_fail(summary,
                                   VerifyIssueCode::InvalidHandlerAutomaton,
                                   function_index,
                                   i,
                                   node.inst_index,
                                   node.targets[j]);
    }
    if (!out.arena.init(4096))
        return verify_fail(summary, VerifyIssueCode::ConcurrentVerificationLimit, function_index);
    const verify::Model* peers = environment ? environment->model : nullptr;
    const u32 kBindingCount = environment ? environment->binding_count : 0;
    if (environment &&
        (!peers || !peers->actor_count || peers->actor_count >= verify::kMaxActors ||
         (peers->action_count && !peers->actions) || (kBindingCount && !environment->bindings) ||
         kBindingCount > automaton.node_count))
        return verify_fail(summary, VerifyIssueCode::ConcurrentProtocolFailure, function_index);
    // Validate contracts before allocation. OR arms are separate transitions,
    // never a conjunction of completion prerequisites.
    for (u32 i = 0; i < kBindingCount; ++i) {
        const auto& binding = environment->bindings[i];
        if (binding.block_index >= automaton.node_count)
            return verify_fail(summary, VerifyIssueCode::ConcurrentProtocolFailure, function_index);
        const auto& node = automaton.nodes[binding.block_index];
        if (node.kind != VerifyHandlerNodeKind::Yield || !node.wait_arm_mask ||
            binding.arm_count > 2 || (binding.submit_require_set & binding.submit_require_clear))
            return verify_fail(summary,
                               VerifyIssueCode::ConcurrentProtocolFailure,
                               function_index,
                               binding.block_index);
        u8 covered = 0;
        if (binding.arm_count) {
            if (binding.completion_set || binding.completion_clear)
                return verify_fail(summary,
                                   VerifyIssueCode::ConcurrentProtocolFailure,
                                   function_index,
                                   binding.block_index);
            for (u32 arm = 0; arm < binding.arm_count; ++arm) {
                const u8 kMask = binding.arms[arm].arm_mask;
                if (!kMask || (kMask & (kMask - 1)) || (covered & kMask))
                    return verify_fail(summary,
                                       VerifyIssueCode::ConcurrentProtocolFailure,
                                       function_index,
                                       binding.block_index);
                covered |= kMask;
            }
        } else {
            if (node.wait_arm_mask & (node.wait_arm_mask - 1))
                return verify_fail(summary,
                                   VerifyIssueCode::ConcurrentProtocolFailure,
                                   function_index,
                                   binding.block_index);
            covered = node.wait_arm_mask;
        }
        if (covered != node.wait_arm_mask)
            return verify_fail(summary,
                               VerifyIssueCode::ConcurrentProtocolFailure,
                               function_index,
                               binding.block_index);
        for (u32 previous = 0; previous < i; ++previous)
            if (environment->bindings[previous].block_index == binding.block_index)
                return verify_fail(summary,
                                   VerifyIssueCode::ConcurrentProtocolFailure,
                                   function_index,
                                   binding.block_index);
    }
    const u32 kPeerActions = peers ? peers->action_count : 0;
    if (kPeerActions > (1u << 20))
        return verify_fail(summary, VerifyIssueCode::ConcurrentVerificationLimit, function_index);
    auto* actions = out.arena.alloc_array<verify::Action>(automaton.node_count * 2 +
                                                          kBindingCount * 2 + kPeerActions);
    if (!actions)
        return verify_fail(summary, VerifyIssueCode::ConcurrentVerificationLimit, function_index);
    verify::Model model{};
    const u32 kDone = automaton.node_count + kBindingCount;
    model.actor_count = peers ? static_cast<u8>(peers->actor_count + 1) : 1;
    model.actors[0] = {
        static_cast<u16>(kDone + 1), static_cast<u16>(root), static_cast<u16>(kDone)};
    model.actions = actions;
    if (peers) {
        model.initial_bits = peers->initial_bits;
        model.terminal_clear = peers->terminal_clear;
        model.weak_fairness = peers->weak_fairness;
        model.invariants = peers->invariants;
        model.invariant_count = peers->invariant_count;
        for (u32 a = 0; a < peers->actor_count; ++a) model.actors[a + 1] = peers->actors[a];
        for (u32 i = 0; i < kPeerActions; ++i) {
            if (peers->actions[i].actor >= peers->actor_count)
                return verify_fail(
                    summary, VerifyIssueCode::ConcurrentProtocolFailure, function_index);
            auto action = peers->actions[i];
            ++action.actor;
            actions[model.action_count++] = action;
        }
    }
    for (u32 i = 0; i < automaton.node_count; ++i) {
        const auto& node = automaton.nodes[i];
        const VerifyPeerBinding* binding = nullptr;
        u32 binding_index = 0;
        for (u32 j = 0; j < kBindingCount; ++j)
            if (environment->bindings[j].block_index == i) {
                binding = &environment->bindings[j];
                binding_index = j;
                break;
            }
        if (binding) {
            auto& submit = actions[model.action_count++];
            submit.from = static_cast<u16>(i);
            submit.to = static_cast<u16>(automaton.node_count + binding_index);
            submit.set = binding->submit_set;
            submit.assert_set = binding->submit_require_set;
            submit.assert_clear = binding->submit_require_clear;
            const u32 kArms = binding->arm_count ? binding->arm_count : 1;
            for (u32 arm = 0; arm < kArms; ++arm) {
                auto& complete = actions[model.action_count++];
                complete.from = submit.to;
                complete.to = static_cast<u16>(node.targets[0]);
                complete.guard_set = binding->arm_count ? binding->arms[arm].completion_set
                                                        : binding->completion_set;
                complete.clear = binding->arm_count ? binding->arms[arm].completion_clear
                                                    : binding->completion_clear;
            }
            continue;
        }
        if (environment && environment->require_all_yields_bound &&
            node.kind == VerifyHandlerNodeKind::Yield)
            return verify_fail(
                summary, VerifyIssueCode::ConcurrentProtocolFailure, function_index, i);
        const u32 kCount = node.kind == VerifyHandlerNodeKind::Terminal ? 1 : node.target_count;
        for (u32 target = 0; target < kCount; ++target) {
            auto& action = actions[model.action_count++];
            action.from = static_cast<u16>(i);
            action.to = static_cast<u16>(
                node.kind == VerifyHandlerNodeKind::Terminal ? kDone : node.targets[target]);
        }
    }
    out.model = model;
    VerifyResult result{};
    result.summary = summary;
    return result;
}

VerifyResult verify_handler_concurrency(const VerifyHandlerAutomaton& automaton,
                                        u32 root,
                                        u32 function_index,
                                        VerifySummary summary,
                                        verify::Limits limits,
                                        const VerifyPeerEnvironment* environment) {
    VerifyHandlerProtocolModel protocol_model;
    const auto kBuilt = build_handler_protocol_model(
        automaton, root, environment, protocol_model, function_index, summary);
    if (!kBuilt.ok) return kBuilt;
    const auto& model = protocol_model.model;
    const auto* peers = environment ? environment->model : nullptr;
    const u32 kDone = model.actors[0].terminal;
    // A yield edge abstracts eventual completion (or failure) of the submitted
    // operation. It does not assume that errors, a close, or a particular
    // branch will eventually be chosen. A successful-yield cycle is livelock
    // even when it has an optional terminal/error exit.
    verify::Limits route_limits = limits;
    if (!peers) {
        route_limits.states =
            limits.states < automaton.node_count + 1 ? limits.states : automaton.node_count + 1;
        route_limits.edges = limits.edges < model.action_count ? limits.edges : model.action_count;
    }
    const auto kProgress = verify::check(model, route_limits);
    if (!kProgress.ok) {
        auto result = failure(kProgress, model, function_index, summary);
        if (peers) {
            result.issue.trace_is_protocol = true;
            const u32 kLocation = kProgress.witness.locations[0];
            if (kLocation >= automaton.node_count && kLocation < kDone)
                result.issue.block_index =
                    environment->bindings[kLocation - automaton.node_count].block_index;
            else if (kLocation == kDone)
                for (u32 i = 0; i < automaton.node_count; ++i)
                    if (automaton.nodes[i].kind == VerifyHandlerNodeKind::Terminal) {
                        result.issue.block_index = i;
                        break;
                    }
        }
        return result;
    }

    bool checked_masks[64]{};
    for (u32 i = 0; i < automaton.node_count; ++i) {
        const auto& node = automaton.nodes[i];
        if (node.kind != VerifyHandlerNodeKind::Yield) continue;
        const u8 kMask = node.wait_arm_mask;
        if (kMask >= 64)
            return verify_fail(summary,
                               VerifyIssueCode::ConcurrentProtocolFailure,
                               function_index,
                               i,
                               node.inst_index,
                               kMask);
        if (checked_masks[kMask]) continue;
        // Check ordered capability pairs across event kinds and arm counts.
        bool checked_second[64]{};
        for (u32 j = 0; j < automaton.node_count; ++j) {
            const auto& second = automaton.nodes[j];
            if (second.kind != VerifyHandlerNodeKind::Yield) continue;
            const u8 kSecondMask = second.wait_arm_mask;
            if (kSecondMask >= 64)
                return verify_fail(summary,
                                   VerifyIssueCode::ConcurrentProtocolFailure,
                                   function_index,
                                   j,
                                   second.inst_index,
                                   kSecondMask);
            if (checked_second[kSecondMask]) continue;
            verify::WaitProtocolModel protocol{};
            if (!verify::build_wait_protocol_model(kMask, kSecondMask, protocol))
                return verify_fail(summary,
                                   VerifyIssueCode::ConcurrentProtocolFailure,
                                   function_index,
                                   i,
                                   node.inst_index,
                                   kMask);
            verify::Limits protocol_limits = limits;
            protocol_limits.states = limits.states < 32768 ? limits.states : 32768;
            protocol_limits.edges = limits.edges < 262144 ? limits.edges : 262144;
            const auto kRaces = verify::check(protocol.model, protocol_limits);
            if (!kRaces.ok) {
                auto result = failure(kRaces, protocol.model, function_index, summary);
                result.issue.block_index = i;
                result.issue.trace_is_protocol = true;
                return result;
            }
            checked_second[kSecondMask] = true;
        }
        checked_masks[kMask] = true;
    }
    VerifyResult result{};
    result.summary = summary;
    return result;
}

}  // namespace rut::rir
