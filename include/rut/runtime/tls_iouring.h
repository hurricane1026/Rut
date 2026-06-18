#pragma once

// io_uring TLS termination, event-loop layer.
//
// The epoll backend terminates TLS *inside* the backend: its readiness model
// lets SSL_read/SSL_write do their own recv()/send() the moment epoll signals.
// io_uring's completion model can't — bytes already arrived in a kernel buffer,
// so SSL must be driven over the custom zero-copy BIO (TlsEngine) from here.
//
// Interposition relies on splitting ciphertext and plaintext callbacks:
//   * on_recv stays owned by TLS (tls_recv) so kernel recv completions always
//     enter the decrypt path.
//   * tls_pending_on_recv carries the plaintext HTTP/body continuation that the
//     normal state machine would otherwise store in on_recv.
//   * on_send is otherwise unused (full-send is guaranteed by the backend) — so
//     TLS is free to use it as the ciphertext-send completion hook.
//
// Ciphertext-out production (handshake flights and encrypted app data) is gated
// on tls_out_inflight: only one party may write tls_out_slice at a time, or a
// fast loopback peer's next flight could overwrite a flight the kernel is still
// sending.

#include "rut/common/types.h"
#include "rut/runtime/callbacks.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/io_event.h"
#include "rut/runtime/jit_dispatch.h"
#include "rut/runtime/slice_pool.h"
#include "rut/runtime/tls.h"
#include "rut/runtime/tls_engine.h"

namespace rut {

// Defined in callbacks_impl.h — the HTTP recv entrypoint we hand plaintext to.
template <class Self>
void on_header_received(void* lp, Connection& conn, IoEvent ev);

template <class Self>
void tls_on_out_sent(void* lp, Connection& c, IoEvent ev);
template <class Self>
bool tls_pump_send(Self* loop, Connection& c);
template <class Self>
void tls_process(Self* loop, Connection& c);
template <class Self>
void tls_resume_pending_handler_recv(void* lp, Connection& c, IoEvent ev);
template <class Self>
void tls_resume_pending_send_recv(void* lp, Connection& c, IoEvent ev);

// Send ciphertext staged in tls_out_slice. The bytes are already encrypted, so
// this uses the raw (non-TLS) send. Marks the buffer in-flight; the completion
// lands in tls_on_out_sent.
template <class Self>
bool tls_flush_out(Self* loop, Connection& c) {
    const u32 kN = tls_engine_output_len(c.tls_engine);
    if (kN == 0) return true;
    if (c.tls_out_inflight) return true;  // a prior flush is still draining
    if (!loop->submit_send_raw(c, c.tls_out_slice, kN)) return false;
    c.tls_out_inflight = true;
    c.on_send = &tls_on_out_sent<Self>;
    return true;
}

// Encrypt pending plaintext (tls_send_src/off/len) into tls_out_slice and send.
// One TLS record's worth at a time when the plaintext exceeds the slice; the
// rest resumes from tls_on_out_sent once this flight drains.
template <class Self>
bool tls_pump_send(Self* loop, Connection& c) {
    if (c.tls_out_inflight) return true;  // resumes on the send completion
    tls_engine_set_output(c.tls_engine, c.tls_out_slice, SlicePool::kSliceSize);
    while (c.tls_send_off < c.tls_send_len) {
        TlsOp st = TlsOp::Ok;
        const i32 kW = tls_engine_write(
            c.tls_engine, c.tls_send_src + c.tls_send_off, c.tls_send_len - c.tls_send_off, st);
        if (kW > 0) {
            c.tls_send_off += static_cast<u32>(kW);
            continue;
        }
        if (st == TlsOp::WantWrite) break;  // slice full — flush, continue later
        if (st == TlsOp::WantRead) {
            c.tls_pending_on_recv = &tls_resume_pending_send_recv<Self>;
            if (!c.recv_armed && !loop->submit_recv(c)) return false;
            return true;
        }
        return false;  // fatal
    }
    if (tls_engine_output_len(c.tls_engine) == 0) {
        c.tls_send_src = nullptr;  // nothing to send (len 0)
        return true;
    }
    return tls_flush_out<Self>(loop, c);
}

// Ciphertext-send completion. Resumes app-data encryption if plaintext remains,
// otherwise clears send state and drains any request ciphertext buffered while
// the response was in flight.
template <class Self>
void tls_on_out_sent(void* lp, Connection& c, IoEvent ev) {
    auto* loop = static_cast<Self*>(lp);
    c.tls_out_inflight = false;
    if (ev.result < 0) {
        loop->close_conn(c);
        return;
    }
    if (c.tls_send_src && c.tls_send_off < c.tls_send_len) {
        if (!tls_pump_send<Self>(loop, c)) loop->close_conn(c);
        return;
    }
    // App-data send fully drained (or this was a handshake flight: src null).
    const u32 completed_len = c.tls_send_len;
    c.tls_send_src = nullptr;
    c.tls_send_len = 0;
    c.tls_send_off = 0;
    auto pending = c.tls_pending_on_send;
    c.tls_pending_on_send = nullptr;
    if (pending) {
        c.on_send = pending;
        IoEvent sev = {};
        sev.conn_id = c.id;
        sev.type = IoEventType::Send;
        sev.result = static_cast<i32>(completed_len);
        pending(loop, c, sev);
        if (!c.tls_active) return;
    } else {
        c.on_send = nullptr;  // handshake/control flight; no upper-layer continuation
    }
    if (c.tls_engine.ssl && c.pending_handler_fn &&
        yield_kind_matches_event(c.pending_yield_kind, IoEventType::Recv))
        c.tls_pending_on_recv = &tls_resume_pending_handler_recv<Self>;
    if (c.tls_engine.ssl && (!c.tls_engine.handshake_done || c.tls_in_buf.len() > 0)) {
        tls_process<Self>(loop, c);  // continue handshake or drain deferred ciphertext
    } else if (!c.recv_armed && loop) {
        loop->submit_recv(c);
    }
}

// Drive the engine over whatever ciphertext sits in tls_in_buf: advance the
// handshake, then decrypt app data into recv_buf and hand it to the HTTP layer.
// Deferred entirely while a ciphertext send is in flight (see file header).
template <class Self>
void tls_process(Self* loop, Connection& c) {
    if (c.tls_out_inflight) return;  // can't touch tls_out_slice mid-send
    tls_engine_set_input(c.tls_engine, c.tls_in_buf.data(), c.tls_in_buf.len());

    if (!c.tls_engine.handshake_done) {
        tls_engine_set_output(c.tls_engine, c.tls_out_slice, SlicePool::kSliceSize);
        const TlsOp kSt = tls_engine_handshake(c.tls_engine);
        c.tls_in_buf.consume(tls_engine_input_consumed(c.tls_engine));
        if (kSt == TlsOp::Error) {
            loop->close_conn(c);
            return;
        }
        if (tls_engine_output_len(c.tls_engine) > 0 && !tls_flush_out<Self>(loop, c)) {
            loop->close_conn(c);
            return;
        }
        if (!c.tls_engine.handshake_done) {
            loop->submit_recv(c);  // await the client's next flight
            return;
        }
        if (tls_negotiated_protocol(c.tls_engine.ssl) == AlpnProtocol::H2)
            c.protocol = ConnProtocol::Http2;
        c.tls_handshake_complete = true;
        // The handshake-completion flight just flushed (line above) may include
        // the TLS 1.3 NewSessionTicket and is still draining tls_out_slice. Don't
        // fall into the decrypt loop yet — SSL_read can emit control output onto
        // tls_out_slice (post-handshake messages) and would corrupt the in-flight
        // flight. tls_on_out_sent re-enters tls_process once the CQE clears it,
        // with the client's pipelined app data still buffered in tls_in_buf.
        if (c.tls_out_inflight) return;
        // Decrypt any app data the client pipelined after its Finished.
        tls_engine_set_input(c.tls_engine, c.tls_in_buf.data(), c.tls_in_buf.len());
    }

    if (!c.tls_pending_on_recv) {
        if (!c.recv_armed) loop->submit_recv(c);
        return;
    }

    tls_engine_set_output(c.tls_engine, c.tls_out_slice, SlicePool::kSliceSize);
    for (;;) {
        const u32 kBefore = c.recv_buf.len();
        for (;;) {
            const u32 kAvail = c.recv_buf.write_avail();
            if (kAvail == 0) break;
            TlsOp st = TlsOp::Ok;
            const i32 kN = tls_engine_read(c.tls_engine, c.recv_buf.write_ptr(), kAvail, st);
            if (kN > 0) {
                c.recv_buf.commit(static_cast<u32>(kN));
                continue;
            }
            if (st == TlsOp::WantRead) break;  // drained all complete records
            if (st == TlsOp::Closed) {
                if (c.recv_buf.len() == 0) {
                    loop->close_conn(c);
                    return;
                }
                break;
            }
            if (st == TlsOp::WantWrite) {
                c.tls_in_buf.consume(tls_engine_input_consumed(c.tls_engine));
                if (!tls_flush_out<Self>(loop, c)) loop->close_conn(c);
                return;
            }
            loop->close_conn(c);  // fatal
            return;
        }
        const u32 kConsumed = tls_engine_input_consumed(c.tls_engine);
        c.tls_in_buf.consume(kConsumed);
        if (c.recv_buf.len() <= kBefore) {
            if (kConsumed > 0 && c.tls_pending_on_recv == &tls_resume_pending_send_recv<Self>) {
                tls_resume_pending_send_recv<Self>(loop, c, {});
                return;
            }
            break;  // produced nothing this round
        }

        IoEvent pev = {};
        pev.conn_id = c.id;
        pev.type = IoEventType::Recv;
        pev.result = static_cast<i32>(c.recv_buf.len() - kBefore);
        auto pending_recv = c.tls_pending_on_recv;
        if (!pending_recv) pending_recv = &on_header_received<Self>;
        pending_recv(loop, c, pev);

        // on_header_received may have closed the connection synchronously (EOF /
        // malformed request / h2 setup failure / handler-initiated close). The
        // io_uring close path reset()s the slot (tls_active=false, fd=-1, buffers
        // unbound) — touching c past here is use-after-close, and the trailing
        // submit_recv would arm a recv on a dead fd. Bail immediately.
        if (!c.tls_active) return;

        // on_header_received may have started a response send (tls_out_inflight)
        // or drained recv_buf. Stop if we can't safely produce more.
        if (c.tls_out_inflight) return;
        if (!c.tls_pending_on_recv) return;
        if (c.tls_in_buf.len() == 0 || c.recv_buf.write_avail() == 0) break;
        tls_engine_set_input(c.tls_engine, c.tls_in_buf.data(), c.tls_in_buf.len());
    }
    if (!c.tls_out_inflight && !c.recv_armed) loop->submit_recv(c);
}

// on_recv handler for TLS connections: validate the recv, then drive the engine.
template <class Self>
void tls_recv(void* lp, Connection& c, IoEvent ev) {
    auto* loop = static_cast<Self*>(lp);
    if (ev.result <= 0) {  // peer EOF or recv error
        loop->close_conn(c);
        return;
    }
    tls_process<Self>(loop, c);
}

// Plaintext continuation used only while a JIT handler is waiting on downstream
// recv/any. The io_uring backend has copied the CQE bytes into tls_in_buf, so the
// handler must resume after TLS decrypts those bytes into recv_buf, not directly
// from the ciphertext CQE.
template <class Self>
void tls_resume_pending_handler_recv(void* lp, Connection& c, IoEvent ev) {
    auto* loop = static_cast<Self*>(lp);
    c.tls_pending_on_recv = nullptr;
    if (!c.pending_handler_fn) return;
    loop->disarm_yield_timer(c);
    c.resume_event_kind = yield_kind_from_event(IoEventType::Recv);
    c.resume_event_result = ev.result;
    resume_jit_handler<Self>(loop, c);
}

// SSL_write can need peer input for post-handshake TLS control messages. While
// app-data plaintext remains pending, route one recv through TLS and then retry
// encryption instead of treating WANT_READ as a fatal send failure.
template <class Self>
void tls_resume_pending_send_recv(void* lp, Connection& c, IoEvent /*ev*/) {
    auto* loop = static_cast<Self*>(lp);
    c.tls_pending_on_recv = nullptr;
    if (!c.tls_send_src || c.tls_send_off >= c.tls_send_len) return;
    if (!tls_pump_send<Self>(loop, c)) loop->close_conn(c);
}

}  // namespace rut
