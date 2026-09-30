#include "rut/runtime/timer_wheel.h"

#include "rut/runtime/connection.h"

#include <stddef.h>  // offsetof

namespace rut {

// The idle-trim mark must share the cache line timer_node is about to dirty: the
// clear in add() then costs no extra line on every arm.
static_assert(offsetof(Connection, idle_trim_examined) / 64 ==
                  offsetof(Connection, timer_node) / 64,
              "idle_trim_examined must sit on the same cache line as timer_node");

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
