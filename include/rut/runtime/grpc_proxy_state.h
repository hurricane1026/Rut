#pragma once

#include "rut/common/types.h"

namespace rut {
struct ConnectionBase;

// One RPC, allocated from the shard's existing bulk SlicePool. Payloads stay
// opaque (including compressed protobuf messages and binary metadata). Queue
// capacities match the advertised stream window; credit is returned on drain.
struct GrpcExchange {
    static constexpr u32 kWindow = 65535;
    static constexpr u32 kHeaders = 16384;
    ConnectionBase* downstream;
    ConnectionBase* upstream;
    u32 downstream_stream;
    u32 upstream_stream;
    u64 deadline_us;
    u64 request_bytes;
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
    u32 request_headers_len;
    u32 request_trailers_len;
    u32 response_headers_len;
    u32 response_trailers_len;
    u8 upload[kWindow];
    u8 download[kWindow];
    u8 request_headers[kHeaders];
    u8 request_trailers[kHeaders];
    u8 response_headers[kHeaders];
    u8 response_trailers[kHeaders];

    void init() {
        downstream = upstream = nullptr;
        downstream_stream = upstream_stream = 0;
        deadline_us = request_bytes = 0;
        expected_request_bytes = 0;
        has_request_length = request_end = request_headers_sent = request_end_sent = false;
        response_end = response_headers_sent = response_end_sent = false;
        failure = 0;
        slot_held = false;
        upstream_id = 0;
        upload_len = download_len = request_headers_len = request_trailers_len = 0;
        response_headers_len = response_trailers_len = 0;
    }
};

// The same bounded index belongs to downstream and upstream HTTP/2 sessions.
// Only upstream sessions join the shard-local pool; mappings keep stream IDs
// independent on the two hops, allowing multiple downstream clients to share it.
struct GrpcProxyState {
    GrpcExchange* streams[64];
    ConnectionBase* pool_next;
    u32 active;
    u32 cursor;
    u32 control_len;
    u64 connected_at_us;
    u64 timer_deadline_us;
    bool upstream;
    bool connecting;
    bool busy;
    bool preface_sent;
    u8 control[4096];

    void init() {
        for (auto& stream : streams) stream = nullptr;
        pool_next = nullptr;
        active = cursor = control_len = 0;
        connected_at_us = timer_deadline_us = 0;
        upstream = connecting = busy = preface_sent = false;
    }
};
}  // namespace rut
