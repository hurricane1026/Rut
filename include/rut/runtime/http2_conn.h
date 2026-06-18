#pragma once

#include "rut/common/types.h"
#include "rut/runtime/hpack.h"
#include "rut/runtime/http2_frame.h"
#include "rut/runtime/http_parser.h"
#include "rut/runtime/route_params.h"
#include "rut/runtime/route_table.h"

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

// Trivially-constructible mirror of RouteParam (which carries default member
// initializers) so that Http2Conn — allocated from a SlabPool that requires
// trivial constructibility — can snapshot matched route params inline.
struct H2RouteParam {
    const char* name;
    u32 name_len;
    const char* value;
    u32 value_len;
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
    hpack::Encoder hpack_enc;  // response-side encoder (dynamic indexing)
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
    bool cont_discard;     // pending header block should be decoded, then reset
    u32 hdr_block_len;
    u8 hdr_block[kHeaderBlockCap];
    u8 hdr_scratch[kHeaderScratchCap];

    Http2Stream streams[kMaxStreams];
    u32 nstreams;

    // Pending request awaiting DATA frames. For body-reading handlers the
    // serving layer appends DATA after synthesized HTTP/1 request headers; for
    // routes that only need Content-Length validation it keeps only the headers
    // and counts DATA bytes. One at a time for now: pending_stream == 0 means none.
    // A route snapshot is captured at END_HEADERS so delayed DATA handling does not
    // re-match if config swaps between HEADERS and DATA.
    static constexpr u32 kBodySynthCap = 16384;
    u32 pending_stream;
    u32 pending_body_start;
    u32 pending_synth_len;
    u32 pending_body_len;
    u32 pending_content_length;
    bool pending_has_content_length;
    bool pending_buffer_body;
    bool pending_overflow;  // body exceeded kBodySynthCap → respond 413
    // Snapshot of matched route decisions at END_HEADERS time for deferred
    // requests. This keeps delayed DATA handlers stable when config changes
    // between HEADERS and DATA frames.
    const RouteConfig* pending_route_config;
    const RouteEntry* pending_route;
    RouteAction pending_route_action;
    u16 pending_static_status;
    jit::HandlerFn pending_jit_fn;
    H2RouteParam pending_route_params[kMaxRouteParams];
    u32 pending_route_param_count;
    // Route param VALUES point into hdr_scratch, which the engine reuses for the
    // next decoded header block; copy them here at defer time so a concurrently
    // multiplexed stream's HEADERS can't clobber req.param() for the deferred
    // request. Param NAMES point into the snapshotted RouteConfig and stay valid,
    // so only values are copied. Bounded; params whose value won't fit are dropped.
    static constexpr u32 kPendingParamCap = 1024;
    u32 pending_param_len;
    u8 pending_param_buf[kPendingParamCap];
    u8 pending_synth[kBodySynthCap];

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

// Serialize a complete response for stream_id into out using the connection's
// dynamic-indexing encoder: a HEADERS frame (:status, the `nhdrs` caller-
// supplied headers, plus content-length when there is a body), then a DATA frame
// if body_len > 0. END_STREAM is set on the last frame. Returns total octets
// written, or 0 if it would exceed out_cap.
u32 http2_write_response(u8* out,
                         u32 out_cap,
                         hpack::Encoder& enc,
                         u32 stream_id,
                         u16 status,
                         const hpack::Header* hdrs,
                         u32 nhdrs,
                         const u8* body,
                         u32 body_len);

// --- Request bridge ---

// Map a decoded HTTP/2 header list into the ParsedRequest the existing routing
// and JIT handlers consume (handlers read ParsedRequest via the parse-once
// cache, so no codegen change is needed for h2). Pseudo-headers :method and
// :path are required; :authority is rewritten to a synthesized "host" header;
// :scheme is dropped; other fields are copied. path_canon is computed the same
// way the HTTP/1 parser does (leading '/' and trailing '/' run stripped, query
// and fragment excluded). req's Str fields point into the source header bytes,
// except the synthesized host name which points at static storage. Returns false
// on a malformed request (missing/duplicate :method or :path, unknown method,
// or more headers than ParsedRequest holds).
bool h2_headers_to_request(const hpack::Header* hs, u32 n, ParsedRequest* req);

}  // namespace rut
