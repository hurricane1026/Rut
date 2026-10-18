#pragma once

#include "rut/common/types.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/grpc_message.h"
#include "rut/runtime/tls.h"

namespace rut {
struct ConnectionBase;

// One RPC, allocated from the shard's existing bulk SlicePool. Payloads stay
// opaque (including compressed protobuf messages and binary metadata). Queue
// capacities match the advertised stream window; credit is returned on drain.
struct GrpcExchange {
    static constexpr u32 kWindow = 65535;
    static constexpr u32 kHeaders = 16384;
    static constexpr u32 kMaxResponseMutations = 16;
    struct ResponseMutation {
        u16 name_offset;
        u16 name_len;
        u16 value_offset;
        u16 value_len;
        u8 mode;
    };
    ConnectionBase* downstream;
    ConnectionBase* upstream;
    u32 downstream_stream;
    u32 upstream_stream;
    u64 started_us;
    u64 staged_response_bytes;
    AccessLogEntry log_entry;  // owned path/upstream; never borrow decoded HPACK storage
    u8 response_status;
    bool observed;
    u64 deadline_us;
    u64 request_bytes;
    GrpcMessageLimit request_message;
    GrpcMessageLimit response_message;
    u32 expected_request_bytes;
    bool has_request_length;
    bool request_end;
    bool request_headers_sent;
    bool request_end_sent;
    bool response_end;
    bool response_headers_sent;
    bool response_end_sent;
    u8 failure;
    bool slot_held;
    u16 upstream_id;
    u32 upload_len;
    u32 download_len;
    u64 response_bytes;
    u32 expected_response_bytes;
    u32 request_headers_len;
    u32 request_trailers_len;
    u32 response_headers_len;
    u32 response_trailers_len;
    bool has_response_length;
    u32 response_mutation_bytes;
    u8 response_mutation_count;
    bool response_mutation_overflow;
    ResponseMutation response_mutations[kMaxResponseMutations];
    u8 upload[kWindow];
    u8 download[kWindow];
    u8 request_headers[kHeaders];
    u8 request_trailers[kHeaders];
    u8 response_headers[kHeaders];
    u8 response_trailers[kHeaders];
    u8 response_mutation_storage[kHeaders];

    void init() {
        downstream = upstream = nullptr;
        downstream_stream = upstream_stream = 0;
        started_us = staged_response_bytes = 0;
        log_entry = {};
        response_status = 2;
        observed = false;
        deadline_us = request_bytes = 0;
        request_message.init();
        response_message.init();
        expected_request_bytes = 0;
        has_request_length = request_end = request_headers_sent = request_end_sent = false;
        response_end = response_headers_sent = response_end_sent = false;
        failure = 0;
        slot_held = false;
        upstream_id = 0;
        upload_len = download_len = response_bytes = expected_response_bytes = 0;
        request_headers_len = request_trailers_len = 0;
        response_headers_len = response_trailers_len = 0;
        has_response_length = false;
        response_mutation_bytes = 0;
        response_mutation_count = 0;
        response_mutation_overflow = false;
    }
};

// The same bounded index belongs to downstream and upstream HTTP/2 sessions.
// Only upstream sessions join the shard-local pool; mappings keep stream IDs
// independent on the two hops, allowing multiple downstream clients to share it.
struct GrpcProxyState {
    TlsClientContext client_tls;
    bool tls_verified;
    GrpcExchange* streams[64];
    ConnectionBase* pool_next;
    u32 active;
    u32 cursor;
    u32 control_len;
    u32 pending_cancel_count;
    // At most 64 header-sent streams can be awaiting cancellation.
    u32 pending_cancels[64];
    u64 connected_at_us;
    u64 idle_since_us;
    u64 timer_deadline_us;
    u64 last_ping_us;
    bool upstream;
    bool connecting;
    bool busy;
    bool preface_sent;
    bool session_failure_recorded;
    u8 control[4096];

    void init() {
        client_tls = {};
        tls_verified = false;
        for (auto& stream : streams) stream = nullptr;
        pool_next = nullptr;
        active = cursor = control_len = pending_cancel_count = 0;
        connected_at_us = idle_since_us = timer_deadline_us = last_ping_us = 0;
        upstream = connecting = busy = preface_sent = session_failure_recorded = false;
    }
};
}  // namespace rut
