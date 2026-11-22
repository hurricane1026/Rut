#include "rut/common/types.h"

namespace rut {
namespace {

enum class Action : u8 { ArmFirst, ArmSecond, Detach, Rotate };

// A slot with three nodes can lose its first, middle, last or only member.
// Node labels are interchangeable, so contiguous ranges represent all orders.
consteval bool timer_list_transition(u32 first_size, u32 second_size, u32 selected, Action action) {
    ListNode slots[2]{};
    ListNode nodes[3]{};
    const u32 kLinked = first_size + second_size;
    for (auto& head : slots) head.init();
    for (u32 i = 0; i < 3; ++i) {
        nodes[i].init();
        if (i < kLinked) slots[i < first_size ? 0 : 1].prev->insert_after(&nodes[i]);
    }

    ListNode& node = nodes[selected];
    const bool kRotate = action == Action::Rotate;
    if (kRotate && selected >= kLinked) return true;  // Only linked nodes are scanned.
    if (kRotate) {
        // idle_trim_walk_list moves the examined node straight to the old slot's tail.
        node.move_to_tail(slots[selected < first_size ? 0 : 1]);
    } else {
        // TimerWheel::remove detaches, refresh then inserts at the new slot's front.
        node.detach();
        if (action == Action::ArmFirst) slots[0].insert_after(&node);
        if (action == Action::ArmSecond) slots[1].insert_after(&node);
    }

    for (u32 slot = 0; slot < 2; ++slot) {
        ListNode* previous = &slots[slot];
        auto expect_next = [&](ListNode* expected) {
            const bool kMatches = previous->next == expected && expected->prev == previous;
            previous = expected;
            return kMatches;
        };
        const Action kArm = slot == 0 ? Action::ArmFirst : Action::ArmSecond;
        if (action == kArm && !expect_next(&node)) return false;
        const u32 kStart = slot == 0 ? 0 : first_size;
        const u32 kEnd = slot == 0 ? first_size : kLinked;
        for (u32 i = kStart; i < kEnd; ++i)
            if (i != selected && !expect_next(&nodes[i])) return false;
        if (kRotate && selected >= kStart && selected < kEnd && !expect_next(&node)) return false;
        const bool kEmpty = previous == &slots[slot];
        if (slots[slot].empty() != kEmpty || !expect_next(&slots[slot])) return false;
    }
    for (u32 i = 0; i < 3; ++i) {
        const bool kDetached = i == selected ? action == Action::Detach : i >= kLinked;
        if (nodes[i].empty() != kDetached || (kDetached && nodes[i].prev != &nodes[i]))
            return false;
    }
    return true;
}

consteval bool timer_list_contract() {
    constexpr Action kActions[] = {
        Action::ArmFirst, Action::ArmSecond, Action::Detach, Action::Rotate};
    for (u32 first = 0; first <= 3; ++first)
        for (u32 second = 0; first + second <= 3; ++second)
            for (u32 selected = 0; selected < 3; ++selected)
                for (const Action kAction : kActions)
                    if (!timer_list_transition(first, second, selected, kAction)) return false;
    return true;
}

static_assert(timer_list_contract(), "Timer list transition broke slot membership or link order");

}  // namespace
}  // namespace rut
