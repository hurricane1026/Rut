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
// comes later). Returns the action.
using WsMessageHandlerFn = WsFrameAction (*)(void* ctx,
                                             WsOpcode opcode,
                                             const u8* payload,
                                             u64 len);

enum class WsInspectStatus : u8 {
    Ok,     // all complete frames in the chunk processed; *consumed/*produced set
    Close,  // a Close was seen or the handler asked to close — tunnel should drain+close
    Error,  // protocol violation or a bound exceeded (message/output cap) — fail the tunnel
};

// Per-direction inspection state. One instance per tunnel direction; persists across
// recv chunks because frames and messages span reads.
struct WsInspector {
    bool masked = false;                // this direction's frames are masked (client->upstream)
    u8 out_mask_key[4] = {0, 0, 0, 0};  // key used to mask re-emitted frames when `masked`
    u64 max_message_size = 0;           // 0 = unbounded
    WsMessageAssembler assembler;       // fragmentation state across frames
    u64 message_len = 0;                // bytes accumulated into the message buffer so far

    void reset() {
        assembler.reset();
        message_len = 0;
    }
};

// Process every COMPLETE frame in `in[0..in_len)`:
//   - data frames: unmask, accumulate into `msg_buf[0..msg_cap)`, and on message
//     completion invoke `handler`; on Forward, re-serialize the message into
//     `out[0..out_cap)`; on Drop, emit nothing; on Close, emit a Close frame and stop.
//   - control frames (Ping/Pong/Close): passed through (re-serialized into `out`); a
//     Close additionally ends the stream.
// A partial trailing frame is left unconsumed for the next call. Sets *consumed (input
// bytes processed) and *produced (output bytes written). Returns Error on any framing
// violation, an over-cap message, or insufficient output capacity.
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

}  // namespace rut
