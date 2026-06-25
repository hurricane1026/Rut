#pragma once

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
// This is the pure decision engine — it touches no sockets. The tunnel pump (a later
// slice) calls ws_inspect at the forward boundary and sends the produced bytes.
namespace rut {

// What the gateway should do with a fully-reassembled data message.
enum class WsFrameAction : u8 {
    Forward,  // re-serialize the message and send it on
    Drop,     // silently discard it
    Close,    // tear the tunnel down (a Close frame is emitted first)
};

// Invoked once per complete data message. `opcode` is Text or Binary; `payload` is the
// reassembled, unmasked message of `len` bytes (read-only this slice — modify/inject
// comes later). `from_client` is the leg the message travels on: true for client->upstream,
// false for upstream->client — so one handler can police a single direction (`frame.fromClient`).
// Returns the action.
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
    // The leg this inspector handles, passed to the handler as `frame.fromClient`. Kept
    // separate from `masked` on purpose: today client->upstream is both masked AND the
    // client leg, but masking is a wire-format property and direction is a routing one —
    // conflating them would break the day they diverge. The caller sets it at arm time.
    bool from_client = false;
    u64 mask_rng = 0;          // PRNG state for fresh per-frame outbound mask keys when
                               // `masked`; the caller MUST seed it with real entropy
                               // (e.g. RAND_bytes) per RFC 6455 §5.3 unpredictability.
    u64 max_message_size = 0;  // 0 = unbounded
    // Reject fragmented messages (a Continuation frame, or a data frame with FIN=0) with
    // Error. The in-place tunnel integration uses this: it re-frames over the recv buffer,
    // which is only sound when a message's output fits its single frame's consumed input —
    // a fragmented message completing in a later (smaller) read would overflow. Single-
    // frame terminate is the v1; spanning-read fragmentation support needs a separate
    // output buffer. Off by default (the engine still reassembles for non-tunnel callers).
    bool reject_fragmented = false;
    WsMessageAssembler assembler;  // fragmentation state across frames
    u64 message_len = 0;           // bytes accumulated into the message buffer so far

    void reset() {
        assembler.reset();
        message_len = 0;
    }
};

// Process every COMPLETE frame in `in[0..in_len)`:
//   - data frames: unmask, accumulate into `msg_buf[0..msg_cap)`, and on message
//     completion invoke `handler`; on Forward, re-serialize the message into
//     `out[0..out_cap)`; on Drop, emit nothing; on Close, emit a Close frame and stop.
//     Text messages are rejected (Error) unless the reassembled payload is valid UTF-8.
//   - control frames (Ping/Pong/Close): passed through verbatim into `out`; a Close
//     additionally ends the stream.
// A partial trailing frame is left unconsumed for the next call; an oversized frame
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

// Serialize a Close frame (status 1000 Normal Closure) into out for the terminate close
// handshake. `masked` true for the gateway→backend (client-role) leg, false for
// gateway→client. Advances mask_rng when masked. Returns bytes written, 0 on overflow.
u32 ws_emit_close_frame(u8* out, u32 out_cap, bool masked, u64& mask_rng);

}  // namespace rut
