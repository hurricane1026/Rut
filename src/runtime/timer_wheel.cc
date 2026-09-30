#include "rut/runtime/timer_wheel.h"

#include "rut/runtime/connection.h"

#include <stddef.h>  // offsetof

namespace rut {

// The idle-trim mark should share the cache line timer_node is about to dirty, so
// the clear in add() costs no extra line on every arm. alignof(Connection) is 8 and
// sizeof is 3616 (32 mod 64), so a slot's offsets may sit 32 bytes off a line
// boundary: only a 32-byte-aligned block is guaranteed to share a line in every
// slot. Require the mark and all of timer_node inside one such block.
static_assert(offsetof(Connection, idle_trim_examined) / 32 ==
                  (offsetof(Connection, timer_node) + sizeof(ListNode) - 1) / 32,
              "idle_trim_examined must share a 32-byte block with timer_node");

void TimerWheel::add(Connection* c, u32 seconds) {
    // Every arm and re-arm (refresh() goes through here) starts a fresh examination
    // epoch for the idle-buffer trim sweep: a node that was examined under an
    // earlier arming must not look "already handled" in its new list, whatever
    // timeout and expiry tick the new arming picked.
    c->idle_trim_examined = false;
    u32 slot = (cursor + seconds) & (kSlots - 1);
    slots[slot].insert_after(&c->timer_node);
}

void TimerWheel::refresh(Connection* c, u32 seconds) {
    c->timer_node.remove();
    c->timer_node.init();
    add(c, seconds);
}

void TimerWheel::remove(Connection* c) {
    c->timer_node.remove();
    c->timer_node.init();
}

u64 TimerWheel::timer_node_offset() {
    return offsetof(Connection, timer_node);
}

}  // namespace rut
