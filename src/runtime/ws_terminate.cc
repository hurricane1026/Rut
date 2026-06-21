#include "rut/runtime/ws_terminate.h"

namespace rut {

namespace {
// Copy `n` bytes verbatim from `src` into out[*produced..], bounds-checked.
bool emit_verbatim(u8* out, u32 out_cap, u32* produced, const u8* src, u32 n) {
    if (*produced + n > out_cap) return false;
    for (u32 i = 0; i < n; i++) out[*produced + i] = src[i];
    *produced += n;
    return true;
}

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
            // Ping/Pong/Close pass through untouched — they're already valid frames for
            // the outbound side (same role, same masking expectation), so forwarding the
            // exact bytes is correct and avoids re-masking a control payload.
            if (!emit_verbatim(out, out_cap, produced, p, static_cast<u32>(frame_total))) {
                return WsInspectStatus::Error;
            }
            *consumed += static_cast<u32>(frame_total);
            if (h.opcode == WsOpcode::Close) return WsInspectStatus::Close;
            continue;
        }

        // Data frame (Text/Binary/Continuation): accumulate its unmasked payload into the
        // reassembly buffer (bound already checked above), then ask the reassembler
        // whether the message is complete.
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
        const WsFrameAction action = handler(ctx, msg_op, msg_buf, total);
        if (action == WsFrameAction::Forward) {
            // Re-serialize the whole message as a single (unfragmented) frame, with a
            // fresh masking key when this direction is masked.
            u8 key[4] = {0, 0, 0, 0};
            if (st.masked) next_mask_key(st.mask_rng, key);
            u8 hdr[kWsMaxHeaderSize];
            const u32 hdr_len = ws_write_header(hdr, msg_op, /*fin=*/true, st.masked, key, total);
            if (hdr_len == 0) return WsInspectStatus::Error;
            if (*produced + hdr_len + total > out_cap) return WsInspectStatus::Error;
            for (u32 i = 0; i < hdr_len; i++) out[*produced + i] = hdr[i];
            u8* out_payload = out + *produced + hdr_len;
            for (u64 i = 0; i < total; i++) out_payload[i] = msg_buf[i];
            if (st.masked) ws_unmask(out_payload, total, key);
            *produced += hdr_len + static_cast<u32>(total);
        } else if (action == WsFrameAction::Close) {
            // Emit an empty Close (no body) and end the stream.
            u8 key[4] = {0, 0, 0, 0};
            if (st.masked) next_mask_key(st.mask_rng, key);
            u8 hdr[kWsMaxHeaderSize];
            const u32 hdr_len =
                ws_write_header(hdr, WsOpcode::Close, /*fin=*/true, st.masked, key, 0);
            if (*produced + hdr_len > out_cap) return WsInspectStatus::Error;
            for (u32 i = 0; i < hdr_len; i++) out[*produced + i] = hdr[i];
            *produced += hdr_len;
            st.message_len = 0;
            return WsInspectStatus::Close;
        }
        // Drop: emit nothing. Forward/Drop both reset for the next message.
        st.message_len = 0;
    }

    return WsInspectStatus::Ok;
}

}  // namespace rut
