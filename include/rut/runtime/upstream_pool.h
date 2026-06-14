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

#pragma once

#include "rut/common/types.h"

#include <sys/socket.h>
#include <unistd.h>

namespace rut {

// Per-shard upstream connection pool.
//
// Manages idle (reusable) upstream connections grouped by upstream target.
// Each shard owns one UpstreamPool — no cross-shard sharing.
//
// Phase 2: simple fixed-array pool with free-stack.
// Phase 3: SlabPool-backed, health checking, weighted load balancing.

struct UpstreamConn {
    i32 fd = -1;
    u16 upstream_id = 0;     // which upstream target this connects to
    bool idle = false;       // true = available for reuse
    bool allocated = false;  // true = slot in use (guards double-free)
};

struct UpstreamPool {
    static constexpr u32 kMaxConns = 4096;

    UpstreamConn conns[kMaxConns];
    u32 free_stack[kMaxConns];
    u32 free_top = 0;

    void init() {
        free_top = kMaxConns;
        for (u32 i = 0; i < kMaxConns; i++) {
            conns[i].fd = -1;
            conns[i].upstream_id = 0;
            conns[i].idle = false;
            conns[i].allocated = false;
            free_stack[i] = i;
        }
    }

    // Allocate a new upstream connection slot.
    // Caller must create the socket and initiate connect.
    UpstreamConn* alloc() {
        if (free_top == 0) return nullptr;
        u32 idx = free_stack[--free_top];
        conns[idx].fd = -1;
        conns[idx].upstream_id = 0;
        conns[idx].idle = false;
        conns[idx].allocated = true;
        return &conns[idx];
    }

    // Free an upstream connection slot.
    void free(UpstreamConn* c) {
        if (!c || c < conns || c >= conns + kMaxConns) return;
        if (!c->allocated) return;  // double-free detection
        if (c->fd >= 0) {
            close(c->fd);
            c->fd = -1;
        }
        c->idle = false;
        c->allocated = false;
        u32 idx = static_cast<u32>(c - conns);
        if (free_top >= kMaxConns) return;
        free_stack[free_top++] = idx;
    }

    // Find an idle connection for the given upstream target.
    // Returns nullptr if none available (caller should allocate + connect).
    UpstreamConn* find_idle(u16 upstream_id) {
        for (u32 i = 0; i < kMaxConns; i++) {
            if (conns[i].idle && conns[i].upstream_id == upstream_id && conns[i].fd >= 0) {
                conns[i].idle = false;  // mark as busy
                return &conns[i];
            }
        }
        return nullptr;
    }

    // Return a connection to the idle pool for reuse.
    void return_idle(UpstreamConn* c) {
        if (!c || c < conns || c >= conns + kMaxConns) return;
        if (!c->allocated || c->fd < 0) return;
        c->idle = true;
    }

    // Close all connections and fully reset to initial state.
    void shutdown() {
        for (u32 i = 0; i < kMaxConns; i++) {
            if (conns[i].fd >= 0) {
                close(conns[i].fd);
                conns[i].fd = -1;
            }
            conns[i].idle = false;
            conns[i].allocated = false;
            conns[i].upstream_id = 0;
        }
        // Rebuild free stack (all slots available)
        free_top = kMaxConns;
        for (u32 i = 0; i < kMaxConns; i++) free_stack[i] = i;
    }

    // Create a non-blocking socket for upstream connection.
    // Returns fd on success, -1 on failure.
    static i32 create_socket() {
        i32 fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        return fd;
    }
};

}  // namespace rut
