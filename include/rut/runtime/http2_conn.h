#pragma once

#include "rut/common/types.h"
#include "rut/runtime/hpack.h"
#include "rut/runtime/http2_frame.h"

// HTTP/2 connection engine (RFC 7540): drives the client preface, the SETTINGS
// handshake, the frame loop, per-stream HEADERS/CONTINUATION assembly (HPACK
// decoded), DATA delivery, and connection/stream flow control. It is transport
// agnostic — the caller feeds inbound bytes and flushes the outbound bytes the
// engine produces (SETTINGS, ACKs, WINDOW_UPDATE, PING ACK, RST_STREAM,
// GOAWAY). Completed request headers and body chunks are delivered via
// callbacks. Wiring into the socket/connection loop happens in a later layer.
namespace rut {

enum class Http2StreamState : u8 {
    Idle,
    Open,
    HalfClosedRemote,  // peer sent END_STREAM; we may still respond
    Closed,
};

struct Http2Stream {
    u32 id;
    Http2StreamState state;
    i32 send_window;  // how much DATA we may send to the peer on this stream
    i32 recv_window;  // how much DATA the peer may send us on this stream
    bool got_headers;
};

struct Http2Conn;

// Result of feeding a chunk of inbound bytes.
struct Http2Result {
    u32 consumed;  // inbound bytes consumed (whole frames + preface only)
    bool close;    // connection error or GOAWAY emitted — flush out, then close
};

struct Http2Conn {
    static constexpr u32 kMaxStreams = 64;
    static constexpr u32 kHeaderBlockCap = 16384;    // assembled HPACK fragments
    static constexpr u32 kHeaderScratchCap = 16384;  // decoded name/value bytes
    static constexpr u32 kMaxHeadersPerReq = 64;

    // Delivered when a stream's header block completes (END_HEADERS). `headers`
    // points into engine scratch valid only for the call.
    using OnHeaders = void (*)(void* ctx,
                               Http2Conn& c,
                               u32 stream_id,
                               const hpack::Header* headers,
                               u32 nheaders,
                               bool end_stream);
    // Delivered per DATA frame (may be called multiple times per stream).
    using OnData =
        void (*)(void* ctx, Http2Conn& c, u32 stream_id, const u8* data, u32 len, bool end_stream);
    // Delivered when a stream is reset by the peer (RST_STREAM).
    using OnReset = void (*)(void* ctx, Http2Conn& c, u32 stream_id, Http2Error error);

    void* cb_ctx;
    OnHeaders on_headers;
    OnData on_data;
    OnReset on_reset;

    hpack::DynamicTable hpack_dec;
    Http2Settings our_settings;
    Http2Settings peer_settings;
    i64 conn_send_window;
    i64 conn_recv_window;
    bool preface_seen;
    bool our_settings_sent;
    bool goaway_sent;
    u32 last_stream_id;    // highest peer-initiated stream id seen
    u32 cont_stream;       // stream awaiting CONTINUATION (0 = none)
    bool cont_end_stream;  // END_STREAM flagged on the pending HEADERS
    u32 hdr_block_len;
    u8 hdr_block[kHeaderBlockCap];
    u8 hdr_scratch[kHeaderScratchCap];

    Http2Stream streams[kMaxStreams];
    u32 nstreams;

    // Set callbacks (any may be null) then call init().
    void init();

    // Consume as many complete frames (and the preface) as `in` holds, writing
    // any required control frames into out[0..out_cap). Partial trailing frames
    // are left unconsumed for the next call. On a connection error a GOAWAY is
    // written and close=true is returned.
    Http2Result process(const u8* in, u32 len, u8* out, u32 out_cap, u32* out_written);

    // Look up a stream by id, or null.
    Http2Stream* find_stream(u32 id);
};

// --- Response serialization (stateless; encoder never indexes) ---

// Write a HEADERS frame for `hs[0..n]` on stream_id into out. Sets END_HEADERS
// (we never split header blocks) and END_STREAM when end_stream. out must hold
// kFrameHeaderSize + encoded header bytes. Returns octets written, or 0 if the
// encoded block would exceed out_cap.
u32 http2_write_headers(
    u8* out, u32 out_cap, u32 stream_id, const hpack::Header* hs, u32 n, bool end_stream);

// Write a DATA frame for data[0..len) on stream_id into out (must hold
// kFrameHeaderSize + len). Returns octets written.
u32 http2_write_data(u8* out, u32 stream_id, const u8* data, u32 len, bool end_stream);

}  // namespace rut
