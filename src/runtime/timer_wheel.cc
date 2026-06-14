/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

#include "rut/runtime/timer_wheel.h"

#include "rut/runtime/connection.h"

#include <stddef.h>  // offsetof

namespace rut {

void TimerWheel::add(Connection* c, u32 seconds) {
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
