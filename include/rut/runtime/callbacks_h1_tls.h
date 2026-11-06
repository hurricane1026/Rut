#pragma once

#include "rut/runtime/callbacks.h"
#include "rut/runtime/h1_tls_upstream.h"
#include "rut/runtime/route_table.h"
#include "rut/runtime/slice_pool.h"
#include "rut/runtime/tls_iouring.h"

#include <errno.h>
#include <openssl/ssl.h>

namespace rut {

template <typename Loop>
void h1_tls_read(void*, Connection&, IoEvent);
template <typename Loop>
void h1_tls_sent(void*, Connection&, IoEvent);

template <typename Loop>
bool h1_tls_dispatch_owner_event(Loop* loop, Connection& owner, IoEvent ev) {
    ev.conn_id = owner.id;
    if (ev.type == IoEventType::UpstreamConnect || ev.type == IoEventType::UpstreamSend) {
        if (owner.on_upstream_send) {
            owner.on_upstream_send(loop, owner, ev);
            return true;
        }
    } else if (ev.type == IoEventType::UpstreamRecv && owner.on_upstream_recv) {
        owner.on_upstream_recv(loop, owner, ev);
        return true;
    }
    if (!owner.pending_handler_fn || !yield_kind_matches_event(owner.pending_yield_kind, ev.type))
        return ev.type == IoEventType::UpstreamRecv && owner.on_upstream_send
                   ? (owner.on_upstream_send(loop, owner, ev), true)
                   : false;
    if constexpr (requires { loop->disarm_yield_timer(owner); }) loop->disarm_yield_timer(owner);
    owner.resume_event_kind = yield_kind_from_event(ev.type);
    owner.resume_event_result = ev.result;
    resume_jit_handler<Loop>(loop, owner);
    return true;
}

template <typename Loop>
bool h1_tls_pause(Loop* loop, Connection& owner) {
    auto* state = owner.h1_tls_upstream;
    if (!state) return false;
    state->receiving = false;
    auto& transport = *state->transport;
    if constexpr (requires { loop->pause_recv(transport); })
        return loop->pause_recv(transport);
    else if constexpr (requires { loop->backend.quiesce_recv(transport.id, false, 0); })
        return loop->backend.quiesce_recv(transport.id, false, 0);
    else if constexpr (requires { loop->backend.pause_recv(transport.id, true); }) {
        loop->backend.pause_recv(transport.id, true);
        return true;
    } else
        return false;
}

template <typename Loop>
void h1_tls_detach(Loop* loop, Connection& owner) {
    auto* state = owner.h1_tls_upstream;
    if (!state) return;
    owner.h1_tls_upstream = nullptr;
    owner.upstream_fd = -1;
    state->owner = nullptr;
    if constexpr (requires { loop->close_conn(*state->transport); })
        loop->close_conn(*state->transport);
}

template <typename Loop>
void h1_tls_closed(void* lp, Connection& transport) {
    auto* loop = static_cast<Loop*>(lp);
    auto* state = transport.h1_tls_transport;
    if (!state) return;
    Connection* owner = state->owner;
    SSL* ssl = transport.tls_engine.ssl ? transport.tls_engine.ssl : transport.tls;
    const bool clean = state->ready && ssl && (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN);
    const bool ready = state->ready;
    const bool send_inflight = transport.on_send == &h1_tls_sent<Loop>;
    transport.h1_tls_transport = nullptr;
    if (transport.tls_engine.ssl) tls_engine_free(transport.tls_engine);
    if (transport.tls) {
        destroy_tls_server_ssl(transport.tls);
        transport.tls = nullptr;
    }
    destroy_tls_client_context(state->context);
    loop->pool.free(reinterpret_cast<u8*>(state));
    if (!owner) return;
    owner->h1_tls_upstream = nullptr;
    owner->upstream_fd = -1;
    IoEvent failure{};
    failure.conn_id = owner->id;
    failure.type =
        !ready ? IoEventType::UpstreamConnect
        : send_inflight ||
                (owner->pending_handler_fn &&
                 yield_kind_matches_event(owner->pending_yield_kind, IoEventType::UpstreamSend))
            ? IoEventType::UpstreamSend
        : owner->on_upstream_recv ||
                (owner->pending_handler_fn &&
                 yield_kind_matches_event(owner->pending_yield_kind, IoEventType::UpstreamRecv))
            ? IoEventType::UpstreamRecv
            : IoEventType::UpstreamSend;
    failure.result = clean && failure.type == IoEventType::UpstreamRecv ? 0 : -ECONNRESET;
    // A failed handshake belongs to the connect continuation. After handshake,
    // a pending upload owns send failure; otherwise the response owns EOF.
    if (!h1_tls_dispatch_owner_event(loop, *owner, failure)) loop->close_conn(*owner);
}

template <typename Loop>
bool h1_tls_recv(Loop* loop, Connection& owner) {
    auto* state = owner.h1_tls_upstream;
    if (!state || !state->ready) return false;
    state->receiving = true;
    auto& transport = *state->transport;
    if (state->driving) return true;
    state->driving = true;
    const u32 generation = transport.handler_gen;
    const auto wants_recv = [&]() {
        return owner.on_upstream_recv ||
               (owner.pending_handler_fn &&
                yield_kind_matches_event(owner.pending_yield_kind, IoEventType::UpstreamRecv));
    };
    while (state->receiving && wants_recv() && transport.recv_buf.len() &&
           owner.upstream_recv_buf.write_avail()) {
        const u32 available = owner.upstream_recv_buf.write_avail();
        const u32 n = transport.recv_buf.len() < available ? transport.recv_buf.len() : available;
        owner.upstream_recv_buf.write(transport.recv_buf.data(), n);
        transport.recv_buf.consume(n);
        state->receiving = false;
        IoEvent received{};
        received.conn_id = owner.id;
        received.type = IoEventType::UpstreamRecv;
        received.result = static_cast<i32>(n);
        h1_tls_refresh_timer(loop, owner);
        if (!h1_tls_dispatch_owner_event(loop, owner, received)) return false;
        if (transport.h1_tls_transport != state || transport.handler_gen != generation) return true;
    }
    state->driving = false;
    if (!state->receiving || !wants_recv() || !owner.upstream_recv_buf.write_avail())
        return h1_tls_pause(loop, owner);
    if (state->eof && transport.recv_buf.len() == 0) {
        state->receiving = false;
        IoEvent end{};
        end.conn_id = owner.id;
        end.type = IoEventType::UpstreamRecv;
        return h1_tls_dispatch_owner_event(loop, owner, end);
    }
    transport.recv_paused_for_send = false;
    // For io_uring, keep the ciphertext receive callback installed. The
    // existing TLS driver delivers decrypted bytes to tls_pending_on_recv.
    if constexpr (requires { loop->tls_setup(transport); }) {
        transport.tls_pending_on_recv = &h1_tls_read<Loop>;
        const bool ssl_has_pending_plaintext =
            transport.tls_engine.ssl && SSL_pending(transport.tls_engine.ssl) > 0;
        if (!transport.tls_out_inflight &&
            (transport.tls_in_buf.len() || ssl_has_pending_plaintext)) {
            tls_process(loop, transport);
            return true;
        }
    } else
        transport.on_recv = &h1_tls_read<Loop>;
    return loop->submit_recv(transport);
}

template <typename Loop>
void h1_tls_read(void* lp, Connection& transport, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    auto* state = transport.h1_tls_transport;
    if (!state) return;
    if (!state->ready) {
        if (ev.result < 0) {
            loop->close_conn(transport);
            return;
        }
        h1_tls_ready(loop, transport);
        return;
    }
    if (ev.result < 0 && ev.result != -ENOBUFS) {
        loop->close_conn(transport);
        return;
    }
    if (ev.result == 0) state->eof = true;
    if (state->owner && state->receiving) {
        if (!h1_tls_recv(loop, *state->owner) && transport.h1_tls_transport)
            loop->close_conn(transport);
    } else if (ev.result == -ENOBUFS) {
        if (!state->owner || !h1_tls_pause(loop, *state->owner)) loop->close_conn(transport);
    } else if (state->owner && !h1_tls_pause(loop, *state->owner))
        loop->close_conn(transport);
}

template <typename Loop>
void h1_tls_sent(void* lp, Connection& transport, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    auto* state = transport.h1_tls_transport;
    if (!state || !state->owner) return;
    if (ev.result <= 0) {
        loop->close_conn(transport);
        return;
    }
    Connection* owner = state->owner;
    transport.on_send = nullptr;
    ev.conn_id = owner->id;
    ev.type = IoEventType::UpstreamSend;
    h1_tls_refresh_timer(loop, *owner);
    if (!h1_tls_dispatch_owner_event(loop, *owner, ev)) loop->close_conn(transport);
}

template <typename Loop>
bool h1_tls_send(Loop* loop, Connection& owner, const u8* bytes, u32 length) {
    auto* state = owner.h1_tls_upstream;
    if (!state || !state->ready || !length) return false;
    auto& transport = *state->transport;
    // Never give a child SQE an owner-buffer pointer: owner teardown may
    // release its request/config while child cancellation is still draining.
    const u32 n = length < transport.send_buf.capacity() ? length : transport.send_buf.capacity();
    transport.send_buf.reset();
    transport.send_buf.write(bytes, n);
    transport.on_send = &h1_tls_sent<Loop>;
    return client_send(loop, transport, transport.send_buf.data(), n);
}

template <typename Loop>
void h1_tls_connected(void* lp, Connection& transport, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    auto* state = transport.h1_tls_transport;
    if (!state) return;
    if (ev.result < 0) {
        loop->close_conn(transport);
        return;
    }
    if constexpr (requires { loop->backend.detach_upstream(transport, &transport.fd); }) {
        i32 fd = -1;
        if (!loop->backend.detach_upstream(transport, &fd)) {
            loop->close_conn(transport);
            return;
        }
        transport.fd = fd;
    } else {
        transport.fd = transport.upstream_fd;
        transport.upstream_fd = -1;
    }
    transport.on_upstream_send = nullptr;
    const auto& target = transport.request_config->upstreams[transport.upstream_idx];
    if (!init_tls_client_context(state->context, target.tls, false)) {
        loop->close_conn(transport);
        return;
    }
    if constexpr (requires {
                      loop->tls_setup(transport, &state->context, target.tls.server_name);
                  }) {
        if (!loop->tls_setup(transport, &state->context, target.tls.server_name)) {
            loop->close_conn(transport);
            return;
        }
        transport.tls_pending_on_recv = &h1_tls_read<Loop>;
        tls_process(loop, transport);
    } else {
        auto ssl = create_tls_client_ssl(state->context, transport.fd, target.tls.server_name);
        if (!ssl) {
            loop->close_conn(transport);
            return;
        }
        transport.tls = ssl.value();
        transport.tls_active = true;
        transport.on_recv = &h1_tls_read<Loop>;
        if (!loop->submit_recv(transport)) loop->close_conn(transport);
    }
}

template <typename Loop>
bool h1_tls_connect(Loop* loop, Connection& owner, const void* addr, u32 addr_len) {
    // Strict read-deadline profiles require parent-owned kernel receive tokens.
    // Until that contract includes TLS transports, fail before connecting to the origin
    // rather than silently replacing the configured deadline with the wheel.
    if (owner.response_read_deadline_seconds != 0) return false;
    if (owner.h1_tls_upstream) h1_tls_detach(loop, owner);
    auto* transport = loop->alloc_conn();
    if (!transport) return false;
    if (transport->handler_gen == 0xFFFFFFFFu) {
        loop->free_conn(*transport);
        return false;
    }
    ++transport->handler_gen;
    auto* memory = loop->pool.alloc();
    if (!memory) {
        loop->free_conn(*transport);
        return false;
    }
    static_assert(sizeof(H1TlsUpstream) <= SlicePool::kSliceSize);
    auto* state = reinterpret_cast<H1TlsUpstream*>(memory);
    *state = {};
    state->owner = &owner;
    state->transport = transport;
    owner.h1_tls_upstream = state;
    transport->h1_tls_transport = state;
    transport->on_close = &h1_tls_closed<Loop>;
    transport->set_metrics_client(false);
    transport->state = ConnState::Proxying;
    transport->proxy_resp_started = true;  // its timer closes the transport, not an HTTP response
    transport->request_config = owner.request_config;
    transport->upstream_idx = owner.upstream_idx;
    transport->upstream_fd = owner.upstream_fd;
    transport->on_upstream_send = &h1_tls_connected<Loop>;
    // A TLS handshake can take longer than a TCP connect. Keep an admitted
    // request body in the socket until the initial write can drain recv_buf.
    if (owner.request_body_incomplete() && owner.on_upstream_send == &on_upstream_connected<Loop>) {
        owner.recv_paused_for_send = true;
        bool paused = true;
        if constexpr (requires { loop->pause_recv(owner); })
            paused = loop->pause_recv(owner);
        else if constexpr (requires { loop->backend.pause_recv(owner.id, true); })
            loop->backend.pause_recv(owner.id, true);
        else
            paused = false;
        if (!paused) {
            owner.h1_tls_upstream = nullptr;
            state->owner = nullptr;
            owner.upstream_fd = -1;
            loop->close_conn(*transport);
            return false;
        }
    }
    h1_tls_refresh_timer(loop, owner);
    // Bypass the logical adapter: the transport owns the actual connect CQE.
    if (!loop->submit_connect_impl(*transport, addr, addr_len)) {
        owner.h1_tls_upstream = nullptr;
        state->owner = nullptr;
        owner.upstream_fd = -1;
        loop->close_conn(*transport);
        return false;
    }
    return true;
}

}  // namespace rut
