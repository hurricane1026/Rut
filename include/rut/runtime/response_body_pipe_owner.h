#pragma once

#include "rut/runtime/body_pipe_transport.h"
#include "rut/runtime/response_body_pipe.h"

namespace rut {

// Allocated from the shard's SlicePool. Unlike storage.busy(), this ledger
// includes readiness and cancellation SQEs which also pin the connection slot.
struct ResponseBodyPipeOwner {
    ResponseBodyPipe storage{};
    u32 conn_id = 0;
    i32 downstream_fd = -1;
    i32 upstream_fd = -1;
    u32 upstream_episode = 0;
    u32 deadline_generation = 0;
    u8 profile = 0;
    u8 method = 0xff;
    u32 targets[4]{};
    u32 cancels[4]{};
    u8 cancel_attempted = 0;
    bool closing = false;
    bool retry_registered = false;

    bool direction_idle(bool input) const {
        const u32 i = input ? 0 : 1;
        return targets[i] == 0 && targets[i + 2] == 0 && cancels[i] == 0 && cancels[i + 2] == 0;
    }
    bool busy() const {
        if (storage.busy()) return true;
        for (u32 i = 0; i < 4; ++i)
            if (targets[i] || cancels[i]) return true;
        return false;
    }
    bool needs_cancel_retry() const {
        if (!closing) return false;
        for (u32 i = 0; i < 4; ++i)
            if (targets[i] && !(cancel_attempted & (1u << i))) return true;
        return false;
    }
    // Called only after the backend successfully queued this exact target.
    bool own_target(BodyPipeOperation op, u32 serial) {
        const u32 i = static_cast<u8>(op);
        if (closing || i >= 4 || serial == 0 || !direction_idle((i & 1u) == 0)) return false;
        targets[i] = serial;
        return true;
    }
    bool own_cancel(BodyPipeOperation target) {
        const u32 i = static_cast<u8>(target);
        if (!closing || i >= 4 || !targets[i] || cancels[i] || (cancel_attempted & (1u << i)))
            return false;
        cancels[i] = targets[i];
        cancel_attempted |= static_cast<u8>(1u << i);
        return true;
    }
    // Retires kernel custody only. The caller authenticates the saved semantic
    // identity separately before publishing progress. Closing owners consume
    // positive transfers too, but never expose those bytes as a new response.
    bool retire(const IoEvent& event) {
        if (event.type != IoEventType::BodyPipeTransport || event.conn_id != conn_id ||
            event.non_upstream_generation == 0 || event.aux >= 8 || event.has_buf || event.buf_id ||
            event.more || event.upstream_episode ||
            event.copy_witness != IoEventCopyWitness::None || event.copy_deadline_generation ||
            event.copy_deadline_profile || event.copy_deadline_method != 0xff || event.copy_begin ||
            event.copy_end || event.provided_ring_empty || event.sock_nonempty)
            return false;
        const u32 i = event.aux & 3u;
        const u32 serial = event.non_upstream_generation;
        if (event.aux >= 4) {
            if (cancels[i] != serial || event.result > 0) return false;
            cancels[i] = 0;
            return true;
        }
        if (targets[i] != serial) return false;
        if (i == 0 && !storage.complete_input(serial, event.result)) return false;
        if (i == 1 && !storage.complete_output(serial, event.result)) return false;
        targets[i] = 0;
        cancel_attempted &= static_cast<u8>(~(1u << i));
        return true;
    }
};

}  // namespace rut
