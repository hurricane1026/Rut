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

constexpr bool ws_valid_message_capacity(u32 size) {
    return size != 0 && size <= kWsTerminateMessageCapacity;
}

enum class WsJsonStringMatch : u8 { Equal, Prefix, Suffix, Contains };
enum class WsJsonIntComparison : u8 { Lt, Gt, Eq };
enum class WsJsonStringScanResult : u8 { NoMatch, Match, Error };
using WsJsonStringScanner = WsJsonStringScanResult (*)(void*, Str);

// Decode in the existing thread-local workspace and scan synchronously. The
// scanner must not retain the view or reenter JSON helpers using that workspace.
WsJsonStringScanResult ws_json_scan_string_at_path(
    const u8* payload, u64 len, Str path, WsJsonStringScanner scanner, void* context);

// Valid UTF-8 for a text message; an empty view is valid.
bool ws_valid_text_payload(Str text);
bool ws_valid_close_reason(Str reason);
// Complete payload validation using the ordinary bounded JSON parser; no view escapes.
bool ws_valid_json_payload(const u8* payload, u64 len);
// True for an existing JSON Pointer node, including JSON null; false on parse/path failure.
bool ws_json_has_path(const u8* payload, u64 len, Str path);
bool ws_json_string_at_path(const u8* payload, u64 len, Str path);
bool ws_json_string_equals_at_path(const u8* payload, u64 len, Str path, Str expected);
bool ws_json_string_matches_at_path(
    const u8* payload, u64 len, Str path, Str expected, WsJsonStringMatch operation);
bool ws_json_number_text_at_path(const u8* payload, u64 len, Str path);
bool ws_json_number_text_matches_at_path(
    const u8* payload, u64 len, Str path, Str expected, WsJsonStringMatch operation);
bool ws_json_stringify_at_path(const u8* payload, u64 len, Str path);
bool ws_json_stringify_matches_at_path(
    const u8* payload, u64 len, Str path, Str expected, WsJsonStringMatch operation);
bool ws_json_bool_at_path(const u8* payload, u64 len, Str path);
bool ws_json_bool_equals_at_path(const u8* payload, u64 len, Str path, bool expected);
bool ws_json_int_at_path(const u8* payload, u64 len, Str path);
bool ws_json_int_compare_at_path(
    const u8* payload, u64 len, Str path, i64 expected, WsJsonIntComparison comparison);
bool ws_json_kind_equals_at_path(const u8* payload, u64 len, Str path, Str expected);
bool ws_json_count_at_path(const u8* payload, u64 len, Str path);
bool ws_json_count_compare_at_path(
    const u8* payload, u64 len, Str path, i32 expected, WsJsonIntComparison comparison);

// RFC 6455 §7.4.1: the status codes an endpoint may put on the wire in a Close message.
// Accepts 1000–1003, 1007–1014, and 3000–4999; rejects the unassigned ranges (<1000,
// 1016–2999, >4999) and the local-only/reserved codes (1004/1005/1006/1015). Single source
// of truth shared by the receive-side validator (ws_inspect), the `message.close(code)` analyze
// check, and the add_ws_terminate registration guard, so all three agree on what is sendable.
constexpr bool ws_valid_close_code(u32 code) {
    return (code >= 1000 && code <= 1003) || (code >= 1007 && code <= 1014) ||
           (code >= 3000 && code <= 4999);
}

// Owned Close metadata. 1005 represents an absent wire status, never a status
// encoded on the wire. No view points into receive or callback scratch storage;
// ordinary copies retain the reason independently.
struct WsClosePayload {
    u16 code = 1005;
    u8 reason_len = 0;
    char reason_storage[kWsMaxCloseReasonBytes]{};

    Str reason() const { return {reason_storage, reason_len}; }
    bool assign(u16 status, Str text);
};

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
    ForwardDynamic,  // synchronous callback publication, copied before the next invocation
    CloseDynamic,
};

inline constexpr u32 kWsMaxClosePolicies = 4;
inline constexpr u32 kWsMaxForwardTexts = 4;
struct WsClosePolicy {
    u16 code = 1000;
    Str reason{};  // immutable route-owned UTF-8, at most 123 bytes
};

enum class WsTextSource : u8 {
    Literal,
    MessageText,
    JsonString,
    JsonNumberText,
    JsonStringify,
    LiteralBinary,
    MessageBytes,
    Dynamic  // shared-IR callback may publish a runtime payload or close reason
};

// Immutable text output recipe. Literal replacement omits the input; affix recipes
// surround one bounded dynamic source, if present, with route-owned UTF-8 views.
// JSON paths and fixed strings are pinned with the route config until the send retires.
// LiteralBinary and MessageBytes reuse the ForwardText action ABI, emitting Binary
// with arbitrary bytes. MessageBytes copies the complete borrowed payload, with no
// affixes. Other sources emit validated UTF-8 Text.
struct WsTextRewrite {
    Str prefix{};
    Str suffix{};
    Str source_path{};  // JSON Pointer only for JSON sources; may be empty for root.
    WsTextSource source = WsTextSource::Literal;
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

// Borrowed only during a synchronous callback. Inspection copies data into owned
// send storage before returning or invoking another callback. Close reasons are
// copied separately into the closing inspector, so the other leg cannot retire them.
struct WsHandlerOutput {
    Str payload{};
    u16 close_code = 1000;
    WsOpcode opcode = WsOpcode::Text;
    bool ready = false;
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
    WsHandlerOutput* dynamic_output = nullptr;
    WsTextRewrite forward_text{};
    const WsTextRewrite* forward_texts = nullptr;
    u32 forward_text_count = 0;
    u64 mask_rng = 0;          // Reserved for compatibility; masking keys use RAND_bytes.
    u64 max_message_size = 0;  // 0 = unbounded
    // Handler policy is input; echo metadata is output for the sender's reply.
    // A peer Close preserves its exact status/reason, with 1005 for no status.
    // A handler Close uses the selected policy for both legs.
    Str close_reason{};  // immutable route-owned UTF-8, at most 123 bytes
    const WsClosePolicy* close_policies = nullptr;
    u32 close_policy_count = 0;
    char echo_close_storage[kWsMaxCloseReasonBytes]{};
    u32 echo_close_reason_len = 0;
    Str echo_close_reason() const { return {echo_close_storage, echo_close_reason_len}; }
    bool set_echo_close_reason(Str reason) {
        if (reason.len > kWsMaxCloseReasonBytes || (!reason.ptr && reason.len)) return false;
        for (u32 i = 0; i < reason.len; ++i) echo_close_storage[i] = reason.ptr[i];
        echo_close_reason_len = reason.len;
        return true;
    }
    u16 close_code = 1000;
    u16 echo_close_code = 1000;
    bool received_close = false;  // distinguishes a peer Close from a handler verdict
    // Reject fragmented messages when a caller cannot provide a separate output buffer.
    // The tunnel supplies one and leaves this disabled.
    bool reject_fragmented = false;
    WsMessageAssembler assembler;  // fragmentation state across frames
    u64 message_len = 0;           // bytes accumulated into the message buffer so far
    bool partial_data_frame = false;
    WsFrameHeader partial_header{};
    u64 partial_payload_len = 0;

    void reset() {
        echo_close_reason_len = 0;
        echo_close_code = 1000;
        received_close = false;
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

// Closing receive mode: ignore data without invoking application code or
// publishing output, but retain framing/fragment bounds across reads. Controls
// remain whole; Ping exposes its unmasked body for a same-peer Pong reply.
// Close stores owned echo metadata and received_close in the inspector. Bytes
// following the first Close are left unconsumed for the caller to discard.
enum class WsClosingRead : u8 { NeedMore, Ping, Close, Error };
WsClosingRead ws_read_closing(
    WsInspector& st, const u8* in, u32 in_len, u8* ping_payload, u32* ping_len, u32* consumed);
u32 ws_emit_pong_frame(
    u8* out, u32 out_cap, bool masked, u64& mask_rng, const u8* payload, u32 len);

// Emit owned metadata, preserving an absent status as an empty Close body.
// Unlike ws_emit_close_frame, this accepts the local-only 1005 representation
// only with an empty reason; it never writes that number onto the wire.
u32 ws_emit_close_payload(
    u8* out, u32 out_cap, bool masked, u64& mask_rng, const WsClosePayload& payload);

}  // namespace rut
