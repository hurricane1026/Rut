#include "rut/runtime/ws_terminate.h"

namespace rut {

namespace {
// Advance a splitmix64 PRNG and derive a fresh 4-byte masking key — RFC 6455 §5.3 wants a
// new unpredictable key per client->server frame, so the inspector can't reuse one fixed
// key. Unpredictability comes from the caller's entropy seed (mask_rng); this only spreads
// it across frames.
void next_mask_key(u64& s, u8 key[4]) {
    s += 0x9E3779B97F4A7C15ull;
    u64 z = s;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    z = z ^ (z >> 31);
    key[0] = static_cast<u8>(z);
    key[1] = static_cast<u8>(z >> 8);
    key[2] = static_cast<u8>(z >> 16);
    key[3] = static_cast<u8>(z >> 24);
}

// RFC 6455 §8.1: a Text message's payload MUST be valid UTF-8. Validate the whole
// reassembled message (rejecting overlong forms, surrogates, and out-of-range code
// points), so a terminating gateway fails the connection instead of forwarding or
// handing malformed text to a DSL filter.
bool utf8_valid(const u8* s, u64 n) {
    for (u64 i = 0; i < n;) {
        const u8 c = s[i];
        u64 extra;
        u32 cp;
        u32 min_cp;
        if (c < 0x80) {
            i++;
            continue;
        } else if ((c & 0xE0) == 0xC0) {
            extra = 1;
            cp = c & 0x1F;
            min_cp = 0x80;
        } else if ((c & 0xF0) == 0xE0) {
            extra = 2;
            cp = c & 0x0F;
            min_cp = 0x800;
        } else if ((c & 0xF8) == 0xF0) {
            extra = 3;
            cp = c & 0x07;
            min_cp = 0x10000;
        } else {
            return false;  // 0x80-0xBF lead, or 0xF8+ (5/6-byte forms)
        }
        if (i + extra >= n) return false;  // truncated multibyte sequence
        for (u64 k = 1; k <= extra; k++) {
            const u8 cc = s[i + k];
            if ((cc & 0xC0) != 0x80) return false;  // not a continuation byte
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (cp < min_cp) return false;                   // overlong encoding
        if (cp > 0x10FFFF) return false;                 // beyond Unicode
        if (cp >= 0xD800 && cp <= 0xDFFF) return false;  // UTF-16 surrogate half
        i += extra + 1;
    }
    return true;
}

// RFC 6455 §7.4: status codes an endpoint may put on the wire in a Close frame. Rejects
// the unassigned (<1000, 1016-2999, >4999) and the local-only/reserved 1004/1005/1006/1015.
bool valid_close_code(u32 code) {
    return (code >= 1000 && code <= 1003) || (code >= 1007 && code <= 1014) ||
           (code >= 3000 && code <= 4999);
}

// Re-serialize one frame (header + `len`-byte cleartext payload) into out[*produced..],
// masking the payload with a fresh key when `masked`. Returns false if it won't fit or the
// header is refused.
bool emit_frame(u8* out,
                u32 out_cap,
                u32* produced,
                WsOpcode op,
                const u8* payload,
                u64 len,
                bool masked,
                u64& mask_rng) {
    u8 key[4] = {0, 0, 0, 0};
    if (masked) next_mask_key(mask_rng, key);
    u8 hdr[kWsMaxHeaderSize];
    const u32 hdr_len = ws_write_header(hdr, op, /*fin=*/true, masked, key, len);
    if (hdr_len == 0) return false;
    if (*produced + hdr_len + len > out_cap) return false;
    for (u32 i = 0; i < hdr_len; i++) out[*produced + i] = hdr[i];
    u8* dst = out + *produced + hdr_len;
    for (u64 i = 0; i < len; i++) dst[i] = payload[i];
    if (masked) ws_unmask(dst, len, key);
    *produced += hdr_len + static_cast<u32>(len);
    return true;
}
}  // namespace

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
                           u32* produced) {
    *consumed = 0;
    *produced = 0;

    for (;;) {
        const u32 avail = in_len - *consumed;
        const u8* p = in + *consumed;

        WsFrameHeader h;
        const ParseStatus ps = ws_parse_header(p, avail, st.masked, &h);
        if (ps == ParseStatus::Incomplete) break;  // partial header — wait for more bytes
        if (ps == ParseStatus::Error) return WsInspectStatus::Error;

        // Reject fragmentation the instant the header proves it — before waiting for (or
        // buffering) the payload. The in-place re-frame can't size a message spanning reads,
        // and deferring the check past the whole-frame wait below lets a peer wedge the
        // tunnel by sending only a fragmented frame's header (FIN=0) and then stalling.
        if (st.reject_fragmented && !ws_opcode_is_control(h.opcode) &&
            (h.opcode == WsOpcode::Continuation || !h.fin)) {
            return WsInspectStatus::Error;
        }

        // Fail closed on an oversized data frame as soon as its header is known — before
        // waiting for (and buffering) a payload we'd reject once complete. message_len is
        // the bytes already accumulated for an in-progress fragmented message (0 for a
        // fresh one); the sum is also the exact msg_buf write bound below.
        if (!ws_opcode_is_control(h.opcode)) {
            if (st.message_len + h.payload_len > msg_cap) return WsInspectStatus::Error;
            if (st.max_message_size != 0 && st.message_len + h.payload_len > st.max_message_size) {
                return WsInspectStatus::Error;
            }
        }

        // The whole frame (header + payload) must be present before we act on it.
        const u64 frame_total = static_cast<u64>(h.header_len) + h.payload_len;
        if (avail < frame_total) break;  // partial payload — leave the frame unconsumed
        const u8* payload = p + h.header_len;

        if (ws_opcode_is_control(h.opcode)) {
            // Copy + unmask the control payload (<=125 bytes) so we can validate it and
            // re-serialize it with our own framing — terminate mode owns the outbound
            // side, so it must not leak the client's mask key or relay a malformed body.
            u8 cbuf[kWsMaxControlPayload];
            for (u64 i = 0; i < h.payload_len; i++) cbuf[i] = payload[i];
            if (st.masked) ws_unmask(cbuf, h.payload_len, h.mask_key);

            // §7.4/§5.5.1: a Close body, if present, is a 2-byte status code (which must be
            // a valid wire code) followed by a UTF-8 reason. Fail the tunnel otherwise.
            if (h.opcode == WsOpcode::Close && h.payload_len >= 2) {
                const u32 code = (static_cast<u32>(cbuf[0]) << 8) | cbuf[1];
                if (!valid_close_code(code)) return WsInspectStatus::Error;
                if (!utf8_valid(cbuf + 2, h.payload_len - 2)) return WsInspectStatus::Error;
            }

            if (!emit_frame(out,
                            out_cap,
                            produced,
                            h.opcode,
                            cbuf,
                            h.payload_len,
                            st.masked,
                            st.mask_rng)) {
                return WsInspectStatus::Error;
            }
            *consumed += static_cast<u32>(frame_total);
            if (h.opcode == WsOpcode::Close) return WsInspectStatus::Close;
            continue;
        }

        // Data frame (Text/Binary). Fragmentation was already rejected at the header (above),
        // so reaching here means a whole, final, single-frame message.
        // Accumulate the (unmasked) payload into the reassembly buffer (bound already
        // checked above), then ask the reassembler whether the message is complete.
        for (u64 i = 0; i < h.payload_len; i++) msg_buf[st.message_len + i] = payload[i];
        if (st.masked) ws_unmask(msg_buf + st.message_len, h.payload_len, h.mask_key);

        WsOpcode msg_op;
        u64 total;
        const WsMessageStatus ms =
            ws_message_feed(st.assembler, h, st.max_message_size, &msg_op, &total);
        if (ms == WsMessageStatus::Error) return WsInspectStatus::Error;
        st.message_len += h.payload_len;
        *consumed += static_cast<u32>(frame_total);

        if (ms == WsMessageStatus::NeedMore) continue;  // awaiting more fragments

        // §8.1: a complete Text message must be valid UTF-8, or the connection fails.
        if (msg_op == WsOpcode::Text && !utf8_valid(msg_buf, total)) {
            return WsInspectStatus::Error;
        }

        // Message complete — invoke the handler and act on its verdict.
        const WsFrameAction action = handler(ctx, msg_op, msg_buf, total, st.from_client);
        if (action == WsFrameAction::Forward) {
            // Re-serialize the whole message as a single (unfragmented) frame.
            if (!emit_frame(
                    out, out_cap, produced, msg_op, msg_buf, total, st.masked, st.mask_rng)) {
                return WsInspectStatus::Error;
            }
        } else if (action == WsFrameAction::Close) {
            // Emit an empty Close (no body) and end the stream.
            if (!emit_frame(
                    out, out_cap, produced, WsOpcode::Close, msg_buf, 0, st.masked, st.mask_rng)) {
                return WsInspectStatus::Error;
            }
            st.message_len = 0;
            return WsInspectStatus::Close;
        }
        // Drop: emit nothing. Forward/Drop both reset for the next message.
        st.message_len = 0;
    }

    return WsInspectStatus::Ok;
}

u32 ws_emit_close_frame(u8* out, u32 out_cap, bool masked, u64& mask_rng) {
    const u8 code[2] = {0x03, 0xE8};  // 1000 Normal Closure
    u32 produced = 0;
    if (!emit_frame(out, out_cap, &produced, WsOpcode::Close, code, 2, masked, mask_rng)) return 0;
    return produced;
}

}  // namespace rut
