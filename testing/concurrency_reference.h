#pragma once

#include "rut/compiler/concurrency_verifier.h"

#include <stdio.h>

namespace rut::test {

inline void emit_reference_set(u64 bits) {
    printf("{");
    bool first = true;
    for (u32 bit = 0; bit < 64; ++bit) {
        if (!(bits & (u64{1} << bit))) continue;
        printf("%s%u", first ? "" : ", ", bit);
        first = false;
    }
    printf("}");
}

inline int export_concurrency_reference(const verify::Model& model, verify::Limits limits = {}) {
    const auto result = verify::check(model, limits);
    if (result.issue == verify::Issue::StateLimit || result.issue == verify::Issue::EdgeLimit ||
        result.issue == verify::Issue::WorkLimit || result.issue == verify::Issue::InvalidModel ||
        result.issue == verify::Issue::OutOfMemory)
        return 1;
    printf(
        "\\* native-result: %s\n---- MODULE concurrency_instance ----\n"
        "EXTENDS concurrency_reference\n",
        verify::issue_name(result.issue));
    printf("ActorCountValue == %u\nInitialValue == <<", model.actor_count);
    for (u32 a = 0; a < model.actor_count; ++a)
        printf("%s%u", a ? ", " : "", model.actors[a].initial);
    printf(">>\nTerminalValue == <<");
    for (u32 a = 0; a < model.actor_count; ++a)
        printf("%s%u", a ? ", " : "", model.actors[a].terminal);
    printf(">>\nInitialBitsValue == ");
    emit_reference_set(model.initial_bits);
    printf("\nTerminalClearValue == ");
    emit_reference_set(model.terminal_clear);
    printf("\nFairGroupsValue == ");
    emit_reference_set(model.weak_fairness);
    printf("\nActionsValue == <<\n");
    for (u32 i = 0; i < model.action_count; ++i) {
        const auto& action = model.actions[i];
        printf("%s[actor |-> %u, source |-> %u, target |-> %u, fair |-> %u, needs |-> ",
               i ? ",\n" : "",
               action.actor + 1,
               action.from,
               action.to,
               action.fairness);
        emit_reference_set(action.guard_set);
        printf(", absent |-> ");
        emit_reference_set(action.guard_clear);
        printf(", add |-> ");
        emit_reference_set(action.set);
        printf(", remove |-> ");
        emit_reference_set(action.clear);
        printf(", assertSet |-> ");
        emit_reference_set(action.assert_set);
        printf(", assertClear |-> ");
        emit_reference_set(action.assert_clear);
        printf("]");
    }
    printf("\n>>\nInvariantsValue == <<\n");
    for (u32 i = 0; i < model.invariant_count; ++i) {
        const auto& invariant = model.invariants[i];
        printf("%s[whenSet |-> ", i ? ",\n" : "");
        emit_reference_set(invariant.when_set);
        printf(", whenClear |-> ");
        emit_reference_set(invariant.when_clear);
        printf(", requireSet |-> ");
        emit_reference_set(invariant.require_set);
        printf(", requireClear |-> ");
        emit_reference_set(invariant.require_clear);
        printf("]");
    }
    printf("\n>>\n====\n");
    return 0;
}

}  // namespace rut::test
