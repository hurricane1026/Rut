#pragma once

#include "rut/runtime/connection.h"
#include "rut/runtime/http2_conn.h"
#include "rut/runtime/tls.h"

namespace rut {

// CPU-only sidecar, allocated from one shard-local SlicePool slice. The
// transport Connection owns the kernel buffers through the ordinary close
// ledger, including io_uring CQEs that outlive logical request teardown.
struct H1TlsUpstream {
    TlsClientContext context{};
    Connection* owner = nullptr;
    Connection* transport = nullptr;
    bool ready = false;
    bool receiving = false;
    bool driving = false;
    bool eof = false;
};

template <typename Loop>
bool h1_tls_connect(Loop*, Connection&, const void*, u32);
template <typename Loop>
bool h1_tls_send(Loop*, Connection&, const u8*, u32);
template <typename Loop>
bool h1_tls_recv(Loop*, Connection&);
template <typename Loop>
bool h1_tls_pause(Loop*, Connection&);
template <typename Loop>
void h1_tls_detach(Loop*, Connection&);
template <typename Loop>
bool h1_tls_dispatch_owner_event(Loop*, Connection&, IoEvent);
// Logical completions bypass the concrete backend dispatcher. Preserve its
// request timer policy on the owner; the transport never owns a separate wheel
// deadline that could race the request's 504 or a throttle window.
template <typename Loop>
void h1_tls_refresh_timer(Loop* loop, Connection& owner) {
    if constexpr (requires { loop->timer.refresh(&owner, loop->upstream_timeout); }) {
        if (!owner.throttle_paused && !owner.ws_shutdown_deadline_armed)
            loop->timer.refresh(&owner,
                                owner.h2 && (owner.h2->grpc.active || owner.h2->grpc.upstream) ? 1
                                : owner.state == ConnState::Proxying ? loop->upstream_timeout
                                                                     : loop->keepalive_timeout);
    }
}

template <typename Loop>
void h1_tls_ready(Loop* loop, Connection& transport) {
    auto* state = transport.h1_tls_transport;
    if (!state || state->ready || (transport.tls_engine.ssl && transport.tls_out_inflight)) return;
    SSL* ssl = transport.tls_engine.ssl ? transport.tls_engine.ssl : transport.tls;
    if (!tls_client_peer_valid(ssl, false)) {
        loop->close_conn(transport);
        return;
    }
    state->ready = true;
    auto* owner = state->owner;
    if (!owner) {
        loop->close_conn(transport);
        return;
    }
    IoEvent connected{};
    connected.conn_id = owner->id;
    connected.type = IoEventType::UpstreamConnect;
    h1_tls_refresh_timer(loop, *owner);
    if (!h1_tls_dispatch_owner_event(loop, *owner, connected)) loop->close_conn(transport);
}

}  // namespace rut
