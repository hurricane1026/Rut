#include "rut/compiler/concurrency_verifier.h"
#include "test.h"

#include <stdio.h>
#include <string.h>

using namespace rut;
using namespace rut::verify;

namespace {

Action step(u8 actor, u16 from, u16 to, u64 need = 0, u64 publish = 0) {
    Action action{};
    action.actor = actor;
    action.from = from;
    action.to = to;
    action.guard_set = need;
    action.set = publish;
    return action;
}

// Replay every returned edge; counterexamples must be executable, not just
// lists of SCC members. UnsafeAction's attempted edge is separate in result.
void replay(rut::test::TestCase* _tc, const Model& model, const Result& result) {
    REQUIRE(result.trace_count > 0);
    State state{};
    state.bits = model.initial_bits;
    for (u32 a = 0; a < model.actor_count; ++a) state.locations[a] = model.actors[a].initial;
    for (u32 i = 0; i < result.trace_count; ++i) {
        const auto& trace = result.trace[i];
        if (i) {
            REQUIRE(trace.action < model.action_count);
            const auto& action = model.actions[trace.action];
            CHECK_EQ(state.locations[action.actor], action.from);
            CHECK_EQ(state.bits & action.guard_set, action.guard_set);
            CHECK_EQ(state.bits & action.guard_clear, 0u);
            state.bits = (state.bits & ~action.clear) | action.set;
            state.locations[action.actor] = action.to;
        } else {
            CHECK_EQ(trace.action, kNoIndex);
        }
        CHECK_EQ(state.bits, trace.state.bits);
        for (u32 a = 0; a < model.actor_count; ++a)
            CHECK_EQ(state.locations[a], trace.state.locations[a]);
    }
    if (result.cycle_start != kNoIndex && !result.trace_truncated) {
        const auto& begin = result.trace[result.cycle_start].state;
        CHECK_EQ(state.bits, begin.bits);
        for (u32 a = 0; a < model.actor_count; ++a)
            CHECK_EQ(state.locations[a], begin.locations[a]);
        CHECK(result.trace_count > result.cycle_start + 1);
    }
}

}  // namespace

TEST(ConcurrencyVerifier, DetectsMutualWaitAfterReachablePrefix) {
    Action actions[] = {step(0, 0, 1), step(1, 0, 1), step(0, 1, 2, 2, 1), step(1, 1, 2, 1, 2)};
    Model model{};
    model.actor_count = 2;
    model.actors[0] = {3, 0, 2};
    model.actors[1] = {3, 0, 2};
    model.actions = actions;
    model.action_count = 4;
    const auto result = check(model);
    CHECK_EQ(result.issue, Issue::Deadlock);
    CHECK_EQ(result.witness.locations[0], 1u);
    CHECK_EQ(result.witness.locations[1], 1u);
    replay(_tc, model, result);
}

TEST(ConcurrencyVerifier, TimeoutBreaksMutualWait) {
    Action actions[] = {step(0, 0, 1, 2, 1), step(1, 0, 1, 1, 2), step(2, 0, 1, 0, 3)};
    actions[2].fairness = 0;
    Model model{};
    model.actor_count = 3;
    for (u32 a = 0; a < 3; ++a) model.actors[a] = {2, 0, 1};
    model.actions = actions;
    model.action_count = 3;
    model.weak_fairness = 1;
    CHECK(check(model).ok);
}

TEST(ConcurrencyVerifier, OrWaitDoesNotMistakeOneBlockedArmForDeadlock) {
    Action actions[] = {step(0, 0, 1, 1), step(0, 0, 1, 2), step(1, 0, 1, 0, 2)};
    Model model{};
    model.actor_count = 2;
    model.actors[0] = {2, 0, 1};
    model.actors[1] = {2, 0, 1};
    model.actions = actions;
    model.action_count = 3;
    CHECK(check(model).ok);
}

TEST(ConcurrencyVerifier, DetectsLivelockEvenWithOptionalTerminalExit) {
    Action actions[] = {step(0, 0, 1), step(0, 1, 0), step(0, 1, 2)};
    actions[0].fairness = actions[1].fairness = actions[2].fairness = 0;
    Model model{};
    model.actor_count = 1;
    model.actors[0] = {3, 0, 2};
    model.actions = actions;
    model.action_count = 3;
    model.weak_fairness = 1;
    const auto result = check(model);
    CHECK_EQ(result.issue, Issue::Livelock);
    CHECK(result.cycle_start != kNoIndex);
    replay(_tc, model, result);
}

TEST(ConcurrencyVerifier, WeakFairnessExcludesSchedulerStarvation) {
    Action actions[] = {step(0, 0, 0), step(0, 0, 1, 1), step(1, 0, 1, 0, 1)};
    actions[0].guard_clear = 1;
    actions[2].fairness = 0;
    Model model{};
    model.actor_count = 2;
    model.actors[0] = {2, 0, 1};
    model.actors[1] = {2, 0, 1};
    model.actions = actions;
    model.action_count = 3;
    CHECK_EQ(check(model).issue, Issue::Livelock);
    model.weak_fairness = 1;
    CHECK(check(model).ok);
}

TEST(ConcurrencyVerifier, IntermittentlyEnabledActionIsNotWeaklyFairExit) {
    Action actions[] = {step(0, 0, 1), step(0, 1, 0), step(0, 0, 2)};
    actions[2].fairness = 0;
    Model model{};
    model.actor_count = 1;
    model.actors[0] = {3, 0, 2};
    model.actions = actions;
    model.action_count = 3;
    model.weak_fairness = 1;
    const auto result = check(model);
    CHECK_EQ(result.issue, Issue::Livelock);
    replay(_tc, model, result);
}

TEST(ConcurrencyVerifier, DetectsOwnershipRaceAcrossActorInterleavings) {
    // Both actors observe "free", suspend, then claim the same resource.
    Action actions[] = {step(0, 0, 1),
                        step(1, 0, 1),
                        step(0, 1, 2, 0, 1),
                        step(1, 1, 2, 0, 2),
                        step(0, 0, 2, 2),
                        step(1, 0, 2, 1)};
    actions[0].guard_clear = actions[1].guard_clear = 3;
    Invariant invariant{1, 0, 0, 2};
    Model model{};
    model.actor_count = 2;
    model.actors[0] = {3, 0, 2};
    model.actors[1] = {3, 0, 2};
    model.actions = actions;
    model.action_count = 6;
    model.invariants = &invariant;
    model.invariant_count = 1;
    const auto result = check(model);
    CHECK_EQ(result.issue, Issue::InvariantViolation);
    CHECK_EQ(result.witness.bits, 3u);
    replay(_tc, model, result);
}

TEST(ConcurrencyVerifier, TerminalDoesNotHideOutstandingResources) {
    Action action = step(0, 0, 1, 0, 1);
    Model model{};
    model.actor_count = 1;
    model.actors[0] = {2, 0, 1};
    model.actions = &action;
    model.action_count = 1;
    model.terminal_clear = 1;
    const auto result = check(model);
    CHECK_EQ(result.issue, Issue::ResourceLeak);
    replay(_tc, model, result);
}

TEST(ConcurrencyVerifier, LimitsAreFailuresNotProofs) {
    Action actions[] = {step(0, 0, 1), step(0, 1, 2)};
    Model model{};
    model.actor_count = 1;
    model.actors[0] = {3, 0, 2};
    model.actions = actions;
    model.action_count = 2;
    CHECK_EQ(check(model, {1, 8}).issue, Issue::StateLimit);
    CHECK_EQ(check(model, {8, 1}).issue, Issue::EdgeLimit);
    CHECK_EQ(check(model, {8, 8, 1}).issue, Issue::WorkLimit);
    CHECK(check(model, {3, 2}).ok);
    CHECK_EQ(check(model, {0, 1}).issue, Issue::InvalidModel);
}

TEST(ConcurrencyVerifier, RejectsInvalidModelsAndChecksInitialInvariants) {
    Model model{};
    CHECK_EQ(check(model).issue, Issue::InvalidModel);
    model.actor_count = 1;
    model.actors[0] = {1, 0, 0};
    Invariant invariant{0, 0, 1, 0};
    model.invariants = &invariant;
    model.invariant_count = 1;
    CHECK_EQ(check(model).issue, Issue::InvariantViolation);
    Action bad{};
    bad.actor = 1;
    model.actions = &bad;
    model.action_count = 1;
    CHECK_EQ(check(model).issue, Issue::InvalidModel);
}

TEST(ConcurrencyVerifier, IndependentActorOrdersMergeWithoutLosingStates) {
    Model model{};
    Action actions[kMaxActors]{};
    model.actor_count = kMaxActors;
    model.actions = actions;
    model.action_count = kMaxActors;
    for (u8 actor = 0; actor < kMaxActors; ++actor) {
        model.actors[actor] = {2, 0, 1};
        actions[actor] = step(actor, 0, 1, 0, u64{1} << actor);
    }
    const auto result = check(model, {256, 1024});
    CHECK(result.ok);
    CHECK_EQ(result.state_count, 256u);
    CHECK_EQ(result.edge_count, 1024u);
}

TEST(ConcurrencyVerifier, LongCounterexampleTruncationDoesNotTurnFailureIntoSuccess) {
    Action actions[150]{};
    Model model{};
    model.actor_count = 1;
    model.actors[0] = {152, 0, 151};
    model.actions = actions;
    model.action_count = 150;
    for (u16 i = 0; i < 149; ++i) actions[i] = step(0, i, static_cast<u16>(i + 1));
    actions[149] = step(0, 149, 149);
    const auto result = check(model, {152, 152});
    CHECK_EQ(result.issue, Issue::Livelock);
    CHECK(result.trace_truncated);
    CHECK_EQ(result.trace_count, Result::kMaxTrace);
    replay(_tc, model, result);
}

TEST(ConcurrencyVerifier, AllSupportedWaitMasksHandleCloseCancelAndNextGeneration) {
    for (u8 mask = 1; mask < 64; ++mask) {
        WaitProtocolModel protocol{};
        const bool built = build_wait_protocol_model(mask, protocol);
        const u32 count = static_cast<u32>(__builtin_popcount(mask));
        CHECK_EQ(built, count <= 2);
        if (!built) continue;
        const auto result = check(protocol.model, {2048, 16384});
        CHECK(result.ok);
        CHECK(result.state_count > 10);
        for (u8 next = 1; next < 64; ++next) {
            if (__builtin_popcount(next) > 2) continue;
            REQUIRE(build_wait_protocol_model(mask, next, protocol));
            CHECK(check(protocol.model, {2048, 16384}).ok);
        }
    }
    WaitProtocolModel protocol{};
    CHECK_FALSE(build_wait_protocol_model(0, protocol));
    CHECK_FALSE(build_wait_protocol_model(64, protocol));
}

TEST(ConcurrencyVerifier, MissingLoserDisarmIsRejected) {
    WaitProtocolModel protocol{};
    REQUIRE(build_wait_protocol_model(3, protocol));
    auto& winner = protocol.actions[protocol.win_actions[0]];
    winner.clear &= ~(u64{1} << 5);  // leave the other arm's callback installed
    const auto result = check(protocol.model, {2048, 16384});
    CHECK_EQ(result.issue, Issue::UnsafeAction);
    replay(_tc, protocol.model, result);
}

TEST(ConcurrencyVerifier, MissingGenerationFenceAllowsDuplicateResume) {
    WaitProtocolModel protocol{};
    REQUIRE(build_wait_protocol_model(3, protocol));
    auto& old_completion = protocol.actions[protocol.win_actions[0]];
    old_completion.guard_set = 1 | (u64{1} << 9);  // old IO delivered during the second wait
    const auto result = check(protocol.model, {2048, 16384});
    CHECK_EQ(result.issue, Issue::UnsafeAction);
    CHECK_EQ(result.witness.locations[0], 7u);
    replay(_tc, protocol.model, result);
}

TEST(ConcurrencyVerifier, MissingCancelDrainLeavesAnOperationStuck) {
    WaitProtocolModel protocol{};
    REQUIRE(build_wait_protocol_model(3, protocol));
    auto& drain = protocol.actions[protocol.drain_actions[0]];
    drain.guard_set |= u64{1} << 63;  // no cancellation target can ever drain
    const auto result = check(protocol.model, {2048, 16384});
    CHECK_EQ(result.issue, Issue::Deadlock);
    replay(_tc, protocol.model, result);
}

TEST(ConcurrencyVerifier, PrematureReclaimIsRejectedBeforeSlotReuse) {
    WaitProtocolModel protocol{};
    REQUIRE(build_wait_protocol_model(3, protocol));
    protocol.actions[protocol.reclaim_action].guard_clear = 0;
    const auto result = check(protocol.model, {2048, 16384});
    CHECK_EQ(result.issue, Issue::UnsafeAction);
    replay(_tc, protocol.model, result);
}

namespace {

struct ReferenceCase {
    Model model{};
    Action actions[8]{};
    Invariant invariant{};
    WaitProtocolModel protocol{};
};

bool reference_case(const char* name, ReferenceCase& out) {
    auto& model = out.model;
    auto* actions = out.actions;
    model.actor_count = 1;
    model.actors[0] = {3, 0, 2};
    model.actions = actions;
    if (!strcmp(name, "mutual")) {
        model.actor_count = 2;
        model.actors[1] = {3, 0, 2};
        actions[0] = step(0, 0, 1);
        actions[1] = step(1, 0, 1);
        actions[2] = step(0, 1, 2, 2, 1);
        actions[3] = step(1, 1, 2, 1, 2);
        model.action_count = 4;
    } else if (!strcmp(name, "timeout") || !strcmp(name, "or_wait")) {
        model.actor_count = 2;
        model.actors[0] = model.actors[1] = {2, 0, 1};
        actions[0] = step(0, 0, 1, 1);
        actions[1] = step(0, 0, 1, 2);
        actions[2] = step(1, 0, 1, 0, 2);
        actions[2].fairness = 0;
        model.action_count = 3;
        model.weak_fairness = 1;
        if (!strcmp(name, "timeout")) {
            model.actor_count = 3;
            model.actors[2] = {2, 0, 1};
            actions[0] = step(0, 0, 1, 2, 1);
            actions[1] = step(1, 0, 1, 1, 2);
            actions[2] = step(2, 0, 1, 0, 3);
            actions[2].fairness = 0;
        }
    } else if (!strcmp(name, "starvation_fair") || !strcmp(name, "starvation_unfair")) {
        model.actor_count = 2;
        model.actors[0] = model.actors[1] = {2, 0, 1};
        actions[0] = step(0, 0, 0);
        actions[0].guard_clear = 1;
        actions[1] = step(0, 0, 1, 1);
        actions[2] = step(1, 0, 1, 0, 1);
        actions[2].fairness = 0;
        model.action_count = 3;
        model.weak_fairness = !strcmp(name, "starvation_fair") ? 1 : 0;
    } else if (!strcmp(name, "livelock") || !strcmp(name, "intermittent")) {
        actions[0] = step(0, 0, 1);
        actions[1] = step(0, 1, 0);
        actions[2] = step(0, !strcmp(name, "intermittent") ? 0 : 1, 2);
        actions[2].fairness = 0;
        if (!strcmp(name, "livelock")) actions[0].fairness = actions[1].fairness = 0;
        model.action_count = 3;
        model.weak_fairness = 1;
    } else if (!strcmp(name, "ownership")) {
        model.actor_count = 2;
        model.actors[1] = {3, 0, 2};
        actions[0] = step(0, 0, 1);
        actions[1] = step(1, 0, 1);
        actions[0].guard_clear = actions[1].guard_clear = 3;
        actions[2] = step(0, 1, 2, 0, 1);
        actions[3] = step(1, 1, 2, 0, 2);
        actions[4] = step(0, 0, 2, 2);
        actions[5] = step(1, 0, 2, 1);
        out.invariant = {1, 0, 0, 2};
        model.invariants = &out.invariant;
        model.invariant_count = 1;
        model.action_count = 6;
    } else {
        if (strcmp(name, "wait_single") && strcmp(name, "wait_any") && strcmp(name, "wait_mixed") &&
            strcmp(name, "wait_mixed_reverse") && strcmp(name, "stale_completion") &&
            strcmp(name, "reclaim") && strcmp(name, "missing_cancel") &&
            strcmp(name, "missing_disarm"))
            return false;
        if (!build_wait_protocol_model(!strcmp(name, "wait_single") ? 1 : 3, out.protocol))
            return false;
        if (!strcmp(name, "wait_mixed"))
            if (!build_wait_protocol_model(1, 3, out.protocol)) return false;
        if (!strcmp(name, "wait_mixed_reverse"))
            if (!build_wait_protocol_model(3, 1, out.protocol)) return false;
        if (!strcmp(name, "stale_completion"))
            out.protocol.actions[out.protocol.win_actions[0]].guard_set = 1 | (u64{1} << 9);
        if (!strcmp(name, "reclaim"))
            out.protocol.actions[out.protocol.reclaim_action].guard_clear = 0;
        if (!strcmp(name, "missing_cancel"))
            out.protocol.actions[out.protocol.drain_actions[0]].guard_set |= u64{1} << 63;
        if (!strcmp(name, "missing_disarm"))
            out.protocol.actions[out.protocol.win_actions[0]].clear &= ~(u64{1} << 5);
        model = out.protocol.model;
    }
    return true;
}

void emit_set(u64 bits) {
    printf("{");
    bool first = true;
    for (u32 bit = 0; bit < 64; ++bit) {
        if (!(bits & (u64{1} << bit))) continue;
        printf("%s%u", first ? "" : ", ", bit);
        first = false;
    }
    printf("}");
}

int export_reference(const char* name) {
    ReferenceCase fixture{};
    if (!reference_case(name, fixture)) return 2;
    const auto& model = fixture.model;
    const auto result = check(model, {2048, 16384});
    if (result.issue == Issue::StateLimit || result.issue == Issue::EdgeLimit ||
        result.issue == Issue::WorkLimit || result.issue == Issue::InvalidModel ||
        result.issue == Issue::OutOfMemory)
        return 1;
    printf(
        "\\* native-result: %s\n---- MODULE concurrency_instance ----\n"
        "EXTENDS concurrency_reference\n",
        issue_name(result.issue));
    printf("ActorCountValue == %u\nInitialValue == <<", model.actor_count);
    for (u32 a = 0; a < model.actor_count; ++a)
        printf("%s%u", a ? ", " : "", model.actors[a].initial);
    printf(">>\nTerminalValue == <<");
    for (u32 a = 0; a < model.actor_count; ++a)
        printf("%s%u", a ? ", " : "", model.actors[a].terminal);
    printf(">>\nInitialBitsValue == ");
    emit_set(model.initial_bits);
    printf("\nTerminalClearValue == ");
    emit_set(model.terminal_clear);
    printf("\nFairGroupsValue == ");
    emit_set(model.weak_fairness);
    printf("\nActionsValue == <<\n");
    for (u32 i = 0; i < model.action_count; ++i) {
        const auto& action = model.actions[i];
        printf("%s[actor |-> %u, source |-> %u, target |-> %u, fair |-> %u, needs |-> ",
               i ? ",\n" : "",
               action.actor + 1,
               action.from,
               action.to,
               action.fairness);
        emit_set(action.guard_set);
        printf(", absent |-> ");
        emit_set(action.guard_clear);
        printf(", add |-> ");
        emit_set(action.set);
        printf(", remove |-> ");
        emit_set(action.clear);
        printf(", assertSet |-> ");
        emit_set(action.assert_set);
        printf(", assertClear |-> ");
        emit_set(action.assert_clear);
        printf("]");
    }
    printf("\n>>\nInvariantsValue == <<\n");
    for (u32 i = 0; i < model.invariant_count; ++i) {
        const auto& invariant = model.invariants[i];
        printf("%s[whenSet |-> ", i ? ",\n" : "");
        emit_set(invariant.when_set);
        printf(", whenClear |-> ");
        emit_set(invariant.when_clear);
        printf(", requireSet |-> ");
        emit_set(invariant.require_set);
        printf(", requireClear |-> ");
        emit_set(invariant.require_clear);
        printf("]");
    }
    printf("\n>>\n====\n");
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    constexpr char kExport[] = "--export-reference=";
    if (argc == 2 && !strncmp(argv[1], kExport, sizeof(kExport) - 1))
        return export_reference(argv[1] + sizeof(kExport) - 1);
    return rut::test::run_all(argc, argv);
}
