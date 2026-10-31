#pragma once

#include "rut/runtime/slice_pool.h"
#include "rut/runtime/ws_frame.h"

// WebSocket terminate-mode inspection engine. Sits one layer above the frame codec
// (ws_frame) and message reassembler: it consumes a chunk of received frame bytes for
// one tunnel direction, reassembles each data message, invokes a handler, and emits a
// re-framed output stream (forwarded/passed-through frames) for the opposite direction.
//
// Re-framing model: the gateway owns framing in the data phase (the 101 handshake is
// still relayed). It unmasks inbound frames to read them and re-serializes forwarded
// frames for the outbound side. Because the WebSocket role is the same on both ends of a
// direction (client->upstream is client-role on both; upstream->client is server-role on
// both), a single `masked` flag covers both the inbound unmask and the outbound mask.
//
// This is the pure decision engine — it touches no sockets. The tunnel pump calls
// ws_inspect at the forward boundary and sends the produced bytes.
namespace rut {

inline constexpr u32 kWsMaxCloseReasonBytes = kWsMaxControlPayload - 2;

inline constexpr u32 kWsTerminateMessageCapacity = SlicePool::kSliceSize - kWsMaxHeaderSize;

// Valid UTF-8 for a text message; an empty view is valid.
bool ws_valid_text_payload(Str text);
bool ws_valid_close_reason(Str reason);
// Complete payload validation using the ordinary bounded JSON parser; no view escapes.
bool ws_valid_json_payload(const u8* payload, u64 len);
// True for an existing JSON Pointer node, including JSON null; false on parse/path failure.
bool ws_json_has_path(const u8* payload, u64 len, Str path);

// RFC 6455 §7.4.1: the status codes an endpoint may put on the wire in a Close message.
// Accepts 1000–1003, 1007–1014, and 3000–4999; rejects the unassigned ranges (<1000,
// 1016–2999, >4999) and the local-only/reserved codes (1004/1005/1006/1015). Single source
// of truth shared by the receive-side validator (ws_inspect), the `message.close(code)` analyze
// check, and the add_ws_terminate registration guard, so all three agree on what is sendable.
constexpr bool ws_valid_close_code(u32 code) {
    return (code >= 1000 && code <= 1003) || (code >= 1007 && code <= 1014) ||
           (code >= 3000 && code <= 4999);
}

// What the gateway should do with a fully-reassembled data message.
enum class WsFrameAction : u8 {
    Forward,       // re-serialize the message and send it on
    Drop,          // silently discard it
    Close,         // tear the tunnel down (a Close frame is emitted first)
    ForwardText,   // replace with the route's fixed text, then forward as Text
    ClosePolicy0,  // close using one of the route's bounded branch-specific policies
    ClosePolicy1,
    ClosePolicy2,
    ClosePolicy3,
    ForwardTextPolicy0,  // select a route-owned guard replacement, then forward as Text
    ForwardTextPolicy1,
    ForwardTextPolicy2,
    ForwardTextPolicy3,
};

inline constexpr u32 kWsMaxClosePolicies = 4;
inline constexpr u32 kWsMaxForwardTexts = 4;
struct WsClosePolicy {
    u16 code = 1000;
    Str reason{};  // immutable route-owned UTF-8, at most 123 bytes
};

// Immutable text output recipe. Literal replacement omits the input; affix recipes
// include one complete Text message between route-owned UTF-8 prefix/suffix views.
struct WsTextRewrite {
    Str prefix{};
    Str suffix{};
    bool include_payload = false;
};
bool ws_valid_text_rewrite(const WsTextRewrite& rewrite, u64 max_size);

// Invoked once per complete data message. `opcode` is Text or Binary; `payload` is the
// reassembled, unmasked message of `len` bytes. ForwardText selects a route-owned
// text recipe; the input view remains read-only. `from_client` is the leg the message
// travels on: true for client->upstream, false for upstream->client — so one handler can police a
// single direction (`message.fromClient`). Returns the action.
using WsMessageHandlerFn =
    WsFrameAction (*)(void* ctx, WsOpcode opcode, const u8* payload, u64 len, bool from_client);

enum class WsInspectStatus : u8 {
    Ok,     // all complete frames in the chunk processed; *consumed/*produced set
    Close,  // a Close was seen or the handler asked to close — tunnel should drain+close
    Error,  // protocol violation or a bound exceeded (message/output cap) — fail the tunnel
};

// Per-direction inspection state. One instance per tunnel direction; persists across
// recv chunks because frames and messages span reads.
//
// Extension contract: ws_parse_header rejects any RSV bit, so this engine assumes NO
// per-message extension (e.g. permessage-deflate) is in effect. A terminating tunnel
// MUST therefore strip `Sec-WebSocket-Extensions` from the relayed upgrade handshake
// (enforced at the handshake by the tunnel-wiring slice) so client and backend never
// negotiate one — otherwise valid compressed frames carry RSV1 and are failed here.
struct WsInspector {
    bool masked = false;  // this direction's frames are masked (client->upstream)
    // The leg this inspector handles, passed to the handler as `message.fromClient`. Kept
    // separate from `masked` on purpose: today client->upstream is both masked AND the
    // client leg, but masking is a wire-format property and direction is a routing one —
    // conflating them would break the day they diverge. The caller sets it at arm time.
    bool from_client = false;
    // Immutable route-owned default and branch texts. The pinned route
    // configuration must remain alive until this connection retires.
    WsTextRewrite forward_text{};
    const WsTextRewrite* forward_texts = nullptr;
    u32 forward_text_count = 0;
    u64 mask_rng = 0;          // Reserved for compatibility; masking keys use RAND_bytes.
    u64 max_message_size = 0;  // 0 = unbounded
    // `message.close(code)` support. close_code (INPUT) is the RFC 6455 status the handler's
    // Close verdict should put on the wire — set by the caller from the route config (1000 =
    // Normal Closure default). echo_close_code (OUTPUT) is written by ws_inspect whenever it
    // returns Close: the code the OPPOSITE leg's echo Close should carry. For a handler Close
    // it mirrors close_code; for a peer-sent Close it stays 1000 (the echo behavior is
    // unchanged — the peer's own code is already relayed verbatim on the forward leg).
    Str close_reason{};  // immutable route-owned UTF-8, at most 123 bytes
    const WsClosePolicy* close_policies = nullptr;
    u32 close_policy_count = 0;
    Str echo_close_reason{};  // selected handler reason, empty for a peer-initiated close
    u16 close_code = 1000;
    u16 echo_close_code = 1000;
    // Reject fragmented messages when a caller cannot provide a separate output buffer.
    // The tunnel supplies one and leaves this disabled.
    bool reject_fragmented = false;
    WsMessageAssembler assembler;  // fragmentation state across frames
    u64 message_len = 0;           // bytes accumulated into the message buffer so far
    bool partial_data_frame = false;
    WsFrameHeader partial_header{};
    u64 partial_payload_len = 0;

    void reset() {
        echo_close_reason = {};
        assembler.reset();
        message_len = 0;
        partial_data_frame = false;
        partial_payload_len = 0;
    }
};

// Process every COMPLETE message in `in[0..in_len)`:
//   - data frames: unmask, accumulate into `msg_buf[0..msg_cap)`, and on message
//     completion invoke `handler`; on Forward, re-serialize the message into
//     `out[0..out_cap)`; on Drop, emit nothing; on Close, emit a Close frame and stop.
//     Text messages are rejected (Error) unless the reassembled payload is valid UTF-8.
//   - control frames (Ping/Pong/Close): passed through verbatim into `out`; a Close
//     additionally ends the stream.
// A partial data payload is consumed incrementally into the stable message buffer;
// partial headers and control frames remain unconsumed. A complete frame that cannot
// fit after earlier output is left unconsumed for the next call; an oversized frame
// (advertised length exceeds msg_cap or max_message_size) fails closed immediately rather
// than waiting for its payload. Sets *consumed (input bytes processed) and *produced
// (output bytes written). Returns Error on any framing violation, an over-cap message,
// invalid UTF-8 text, or insufficient output capacity.
//
// PRECONDITION: `msg_buf` (capacity `msg_cap` >= max_message_size) must be the SAME
// stable buffer on every call for this `st` — a fragmented message accumulates into it
// across calls, so a per-read scratch buffer would lose earlier fragments.
WsInspectStatus ws_inspect(WsInspector& st,
                           const u8* in,
                           u32 in_len,
                           u8* out,
                           u32 out_cap,
                           u8* msg_buf,
                           u32 msg_cap,
                           WsMessageHandlerFn handler,
                           void* ctx,
                           u32* consumed,
                           u32* produced);

// Serialize a Close frame carrying RFC 6455 status `code` into out for the terminate close
// handshake. `masked` true for the gateway→backend (client-role) leg, false for
// gateway→client. Returns bytes written, 0 on overflow or random generator failure.
u32 ws_emit_close_frame(
    u8* out, u32 out_cap, bool masked, u64& mask_rng, u16 code = 1000, Str reason = {});

}  // namespace rut
