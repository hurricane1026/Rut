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
// on tls_out_inflight: only one party may write tls_out_buf at a time, or a
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
// Defined in callbacks_impl.h — proxy body fully forwarded: release the upstream
// slot, complete the request, continue keep-alive. Shared with the io_uring-TLS
// owned-buffer drain path (tls_on_out_drain).
template <typename Loop>
void proxy_stream_complete(Loop* loop, Connection& conn);

template <class Self>
void tls_on_out_drain(void* lp, Connection& c, IoEvent ev);
template <class Self>
void tls_process(Self* loop, Connection& c);
template <class Self>
void tls_resume_pending_handler_recv(void* lp, Connection& c, IoEvent ev);
template <class Self>
void tls_resume_pending_send_recv(void* lp, Connection& c, IoEvent ev);

// Owned ciphertext output buffer primitives (see docs/iouring-tls-output-buffer.md).
// Why fill_output stopped before the whole chunk was consumed.
enum class TlsFill : u8 {
    Done,      // all `len` plaintext encrypted into tls_out_buf
    NeedRoom,  // output buffer filled mid-chunk (SSL_write WantWrite) — resume at drain
    NeedRead,  // SSL_write needs peer input (post-handshake control) — submit a recv
    Fatal,     // crypto error or raw-send submission failure — caller closes
};

// Ensure exactly one raw send is draining tls_out_buf. Submits at most
// kTlsDrainChunk per SQE so the drain handler runs at slice granularity (the
// backend has full-send semantics — see the design doc), and records the
// SQE-captured length so read-ahead appends don't confuse the drain. Returns
// false (caller fails closed) if the send can't be queued.
template <class Self>
bool tls_ensure_draining(Self* loop, Connection& c) {
    if (c.tls_out_inflight) {
        // A send is already draining its chunk; its completion must still reach
        // tls_on_out_drain even if the upper layer overwrote on_send via
        // transition_to_sending() — e.g. a response started while a control/
        // handshake flight is in flight. Otherwise the raw Send CQE is dispatched
        // as the response completion, tls_out_inflight is never cleared, and the
        // output buffer/accounting get stuck.
        c.on_send = &tls_on_out_drain<Self>;
        return true;
    }
    if (c.tls_out_buf.len() == 0) return true;
    const u32 kAvail = c.tls_out_buf.len();
    const u32 kN = kAvail < Self::kTlsDrainChunk ? kAvail : Self::kTlsDrainChunk;
    if (!loop->submit_send_raw(c, c.tls_out_buf.data(), kN)) return false;
    c.tls_out_inflight = true;
    c.tls_out_inflight_len = kN;
    c.on_send = &tls_on_out_drain<Self>;
    return true;
}

// Encrypt plaintext src[0..len) into the owned tls_out_buf, keeping a send
// draining as it fills. Loops on partial SSL_write (SSL_MODE_ENABLE_PARTIAL_WRITE
// means a positive result < len is legal) and commits produced ciphertext every
// pass — the custom BIO writes into the output region before SSL_write returns
// (incl. on WantWrite), so committing each pass keeps those bytes drainable.
// `out_consumed` returns how much plaintext was encrypted.
template <class Self>
TlsFill tls_fill_output(Self* loop, Connection& c, const u8* src, u32 len, u32& out_consumed) {
    u32 off = 0;
    while (off < len) {
        tls_engine_set_output(c.tls_engine, c.tls_out_buf.write_ptr(), c.tls_out_buf.write_avail());
        TlsOp st = TlsOp::Ok;
        const i32 kW = tls_engine_write(c.tls_engine, src + off, len - off, st);
        c.tls_out_buf.commit(tls_engine_output_len(c.tls_engine));  // commit every pass
        if (!tls_ensure_draining<Self>(loop, c)) {
            out_consumed = off;
            return TlsFill::Fatal;
        }
        if (kW > 0) {
            off += static_cast<u32>(kW);
            continue;
        }
        out_consumed = off;
        if (st == TlsOp::WantWrite) return TlsFill::NeedRoom;
        if (st == TlsOp::WantRead) return TlsFill::NeedRead;
        return TlsFill::Fatal;
    }
    out_consumed = len;
    return TlsFill::Done;
}

// Ciphertext-send completion. The io_uring backend has full-send semantics (it
// re-submits a partial IORING_OP_SEND internally and only emits this event once
// the whole submitted chunk drained), so ev.result == tls_out_inflight_len.
// Consume the sent chunk; resume encrypting a parked plaintext remainder; keep a
// send draining while ciphertext remains; once the buffer is empty fire the
// single-shot continuation (tls_pending_on_send) or run the handshake tail.
// Proxy-streaming completion (resp_fully_buffered / watermark) is added in a
// later phase.
template <class Self>
void tls_on_out_drain(void* lp, Connection& c, IoEvent ev) {
    auto* loop = static_cast<Self*>(lp);
    if (ev.result <= 0) {
        loop->close_conn(c);
        return;
    }
    c.tls_out_buf.consume(c.tls_out_inflight_len);
    c.tls_out_inflight = false;
    c.tls_out_inflight_len = 0;

    // (a) Finish a parked plaintext remainder (the buffer filled mid-chunk)
    // before any completion, so the chunk's tail is never lost.
    if (c.tls_send_src && c.tls_send_off < c.tls_send_len) {
        u32 consumed = 0;
        const TlsFill kSt = tls_fill_output<Self>(
            loop, c, c.tls_send_src + c.tls_send_off, c.tls_send_len - c.tls_send_off, consumed);
        c.tls_send_off += consumed;
        if (kSt == TlsFill::Fatal) {
            loop->close_conn(c);
            return;
        }
        if (kSt == TlsFill::NeedRoom) return;  // still full — resume at the next drain
        if (kSt == TlsFill::NeedRead) {
            // SSL_write needs peer input to retry. If no recv is armed and we
            // can't queue one (SQ pressure), nothing will ever deliver that input
            // — fail closed instead of hanging until the idle timeout.
            c.tls_pending_on_recv = &tls_resume_pending_send_recv<Self>;
            if (!c.recv_armed && !loop->submit_recv(c)) loop->close_conn(c);
            return;
        }
        // Done: remainder fully encrypted — fall through.
    }

    if (c.tls_out_buf.len() > 0) {  // more ciphertext queued — push the next chunk
        if (!tls_ensure_draining<Self>(loop, c)) loop->close_conn(c);
        return;
    }

    // Buffer empty: app-data send fully drained (or a handshake/control flight,
    // which has no upper-layer continuation).
    const u32 kCompletedLen = c.tls_send_len;
    c.tls_send_src = nullptr;
    c.tls_send_len = 0;
    c.tls_send_off = 0;
    auto pending = c.tls_pending_on_send;
    c.tls_pending_on_send = nullptr;
    if (pending) {
        // Single-shot send (response / wait(send)): fire the upper-layer
        // continuation now, on the real drain CQE, with the plaintext length.
        c.on_send = pending;
        IoEvent sev = {};
        sev.conn_id = c.id;
        sev.type = IoEventType::Send;
        sev.result = static_cast<i32>(kCompletedLen);
        pending(loop, c, sev);
        if (!c.tls_active) return;
    } else if (c.tls_proxy_stream) {
        // Proxy streaming body (read/drain decoupled): the request completes only
        // when the whole body is buffered AND the buffer is empty. Otherwise the
        // body is still arriving — stay idle and wait for the next upstream recv;
        // do NOT fall into the handshake tail (it would clear on_send / submit a
        // client recv mid-body and read pipelined data out of order).
        if (c.resp_fully_buffered) {
            c.tls_proxy_stream = false;
            proxy_stream_complete<Self>(loop, c);
        }
        return;
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
    if (c.tls_out_inflight) return;  // can't touch tls_out_buf mid-send
    tls_engine_set_input(c.tls_engine, c.tls_in_buf.data(), c.tls_in_buf.len());

    if (!c.tls_engine.handshake_done) {
        tls_engine_set_output(c.tls_engine, c.tls_out_buf.write_ptr(), c.tls_out_buf.write_avail());
        const TlsOp kSt = tls_engine_handshake(c.tls_engine);
        c.tls_in_buf.consume(tls_engine_input_consumed(c.tls_engine));
        if (kSt == TlsOp::Error) {
            loop->close_conn(c);
            return;
        }
        c.tls_out_buf.commit(tls_engine_output_len(c.tls_engine));
        if (!tls_ensure_draining<Self>(loop, c)) {
            loop->close_conn(c);
            return;
        }
        if (!c.tls_engine.handshake_done) {
            if (!c.tls_out_inflight) loop->submit_recv(c);  // await the client's next flight
            return;
        }
        if (tls_negotiated_protocol(c.tls_engine.ssl) == AlpnProtocol::H2)
            c.protocol = ConnProtocol::Http2;
        c.tls_handshake_complete = true;
        // The handshake-completion flight just queued (above) may include the
        // TLS 1.3 NewSessionTicket and is still draining tls_out_buf. Don't fall
        // into the decrypt loop yet — SSL_read can emit control output (post-
        // handshake messages) that we'd append to a buffer the kernel is still
        // sending. tls_on_out_drain re-enters tls_process once the CQE clears it,
        // with the client's pipelined app data still buffered in tls_in_buf.
        if (c.tls_out_inflight) return;
        // Decrypt any app data the client pipelined after its Finished.
        tls_engine_set_input(c.tls_engine, c.tls_in_buf.data(), c.tls_in_buf.len());
    }

    if (!c.tls_pending_on_recv) {
        if (!c.recv_armed) loop->submit_recv(c);
        return;
    }

    for (;;) {
        const u32 kBefore = c.recv_buf.len();
        bool saw_close_notify = false;
        // SSL_read can emit control ciphertext (e.g. a KeyUpdate response) into
        // the output region; point it at the current tls_out_buf write position
        // each round so produced bytes append, never overwrite queued ciphertext.
        tls_engine_set_output(c.tls_engine, c.tls_out_buf.write_ptr(), c.tls_out_buf.write_avail());
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
                saw_close_notify = true;
                c.keep_alive = false;
                break;
            }
            if (st == TlsOp::WantWrite) {
                c.tls_in_buf.consume(tls_engine_input_consumed(c.tls_engine));
                c.tls_out_buf.commit(tls_engine_output_len(c.tls_engine));
                if (!tls_ensure_draining<Self>(loop, c)) loop->close_conn(c);
                return;
            }
            loop->close_conn(c);  // fatal
            return;
        }
        const u32 kConsumed = tls_engine_input_consumed(c.tls_engine);
        c.tls_in_buf.consume(kConsumed);
        const bool kHasControlOutput = tls_engine_output_len(c.tls_engine) > 0;
        if (kHasControlOutput) c.tls_out_buf.commit(tls_engine_output_len(c.tls_engine));
        if (c.recv_buf.len() <= kBefore) {
            if (kConsumed > 0 && c.tls_pending_on_recv == &tls_resume_pending_send_recv<Self>) {
                tls_resume_pending_send_recv<Self>(loop, c, {});
                return;
            }
            if (kHasControlOutput) {
                if (!tls_ensure_draining<Self>(loop, c)) loop->close_conn(c);
                return;
            }
            break;  // produced nothing this round
        }
        if (saw_close_notify) c.keep_alive = false;
        if (kHasControlOutput && !tls_ensure_draining<Self>(loop, c)) {
            loop->close_conn(c);
            return;
        }

        IoEvent pev = {};
        pev.conn_id = c.id;
        pev.type = IoEventType::Recv;
        pev.result = static_cast<i32>(c.recv_buf.len() - kBefore);
        auto pending_recv = c.tls_pending_on_recv;
        if (pending_recv == &tls_resume_pending_send_recv<Self>) {
            c.tls_pending_on_recv = nullptr;
            if (c.tls_send_src && c.tls_send_off < c.tls_send_len) {
                u32 consumed = 0;
                const TlsFill kFs = tls_fill_output<Self>(loop,
                                                          c,
                                                          c.tls_send_src + c.tls_send_off,
                                                          c.tls_send_len - c.tls_send_off,
                                                          consumed);
                c.tls_send_off += consumed;
                if (kFs == TlsFill::Fatal) {
                    loop->close_conn(c);
                    return;
                }
                if (kFs == TlsFill::NeedRead)
                    c.tls_pending_on_recv = &tls_resume_pending_send_recv<Self>;
            }
            pending_recv = &on_header_received<Self>;
        } else if (!pending_recv) {
            pending_recv = &on_header_received<Self>;
        }
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
    // Fail closed if a needed recv can't be armed: reaching here with no armed
    // recv means peer input is required to make progress (e.g. a pending
    // SSL_write WANT_READ), so a failed submit would otherwise hang the conn.
    if (!c.tls_out_inflight && !c.recv_armed && !loop->submit_recv(c)) loop->close_conn(c);
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
    u32 consumed = 0;
    const TlsFill kSt = tls_fill_output<Self>(
        loop, c, c.tls_send_src + c.tls_send_off, c.tls_send_len - c.tls_send_off, consumed);
    c.tls_send_off += consumed;
    if (kSt == TlsFill::Fatal) {
        loop->close_conn(c);
        return;
    }
    if (kSt == TlsFill::NeedRead) {
        // Need peer input again to retry — fail closed if no recv can be armed.
        c.tls_pending_on_recv = &tls_resume_pending_send_recv<Self>;
        if (!c.recv_armed && !loop->submit_recv(c)) loop->close_conn(c);
    }
    // NeedRoom resumes at the next drain; Done drains via tls_on_out_drain.
}

}  // namespace rut
