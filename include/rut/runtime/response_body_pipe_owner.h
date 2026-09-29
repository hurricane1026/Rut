#pragma once

#include "rut/runtime/body_pipe_transport.h"
#include "rut/runtime/response_body_pipe.h"

namespace rut {

// Allocated from the shard's SlicePool. Unlike storage.busy(), this ledger
// includes readiness and cancellation SQEs which also pin the connection slot.
struct ResponseBodyPipeOwner {
    ResponseBodyPipe storage{};
    enum class SendKind : u8 { None, Release, Terminal };
    struct SendFrame {
        u32 serial = 0;
        u32 total = 0;
        u32 completed = 0;
        SendKind kind = SendKind::None;
        bool delivering = false;
    } send{};

    u32 logical_bytes() const { return storage.bytes + send.completed - discarded_input_bytes; }
    bool acknowledge_send(u32 serial, u32 length) {
        if (closing || !send.delivering || send.kind == SendKind::None || serial == 0 ||
            serial != send.serial || length != send.total || send.completed != send.total ||
            !direction_idle(false))
            return false;
        send = {};
        return true;
    }
    u32 conn_id = 0;
    i32 downstream_fd = -1;
    i32 upstream_fd = -1;
    u32 upstream_episode = 0;
    u32 deadline_generation = 0;
    u8 profile = 0;
    u8 method = 0xff;
    // One-shot receive evidence produced before response batch arbitration.
    // A new admitted input must clear this proof before it can be submitted.
    u32 received_serial = 0;
    u32 received_begin = 0;
    u32 received_end = 0;
    u32 targets[4]{};
    u32 cancels[4]{};
    u8 cancel_attempted = 0;
    bool closing = false;
    bool retry_registered = false;
    // Fallback preserves this owner until the response boundary so a
    // fragmented response cannot repeatedly re-enter the pipe path.
    bool input_disabled = false;
    bool fallback_pending = false;
    bool input_stopping = false;
    u32 discarded_input_bytes = 0;

    bool direction_idle(bool input) const {
        const u32 i = input ? 0 : 1;
        return targets[i] == 0 && targets[i + 2] == 0 && cancels[i] == 0 && cancels[i + 2] == 0;
    }
    bool busy() const {
        if (storage.busy() || (!closing && send.kind != SendKind::None)) return true;
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
        if (i >= 4 || (!closing && !(input_stopping && (i & 1u) == 0)) || !targets[i] ||
            cancels[i] || (cancel_attempted & (1u << i)))
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
        if (i == 0) {
            if (!storage.complete_input(serial, event.result)) return false;
            if (input_stopping && event.result > 0)
                discarded_input_bytes += static_cast<u32>(event.result);
        }
        if (i == 1) {
            if (send.kind != SendKind::None && event.result > 0 &&
                (send.completed > send.total ||
                 static_cast<u32>(event.result) > send.total - send.completed))
                return false;
            if (!storage.complete_output(serial, event.result)) return false;
            if (send.kind != SendKind::None && event.result > 0)
                send.completed += static_cast<u32>(event.result);
        }
        targets[i] = 0;
        cancel_attempted &= static_cast<u8>(~(1u << i));
        return true;
    }
};

}  // namespace rut
