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
        // reassembly buffer, then ask the reassembler whether the message is complete.
        if (st.message_len + h.payload_len > msg_cap) return WsInspectStatus::Error;
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

        // Message complete — invoke the handler and act on its verdict.
        const WsFrameAction action = handler(ctx, msg_op, msg_buf, total);
        if (action == WsFrameAction::Forward) {
            // Re-serialize the whole message as a single (unfragmented) frame.
            u8 hdr[kWsMaxHeaderSize];
            const u32 hdr_len =
                ws_write_header(hdr, msg_op, /*fin=*/true, st.masked, st.out_mask_key, total);
            if (hdr_len == 0) return WsInspectStatus::Error;
            if (*produced + hdr_len + total > out_cap) return WsInspectStatus::Error;
            for (u32 i = 0; i < hdr_len; i++) out[*produced + i] = hdr[i];
            u8* out_payload = out + *produced + hdr_len;
            for (u64 i = 0; i < total; i++) out_payload[i] = msg_buf[i];
            if (st.masked) ws_unmask(out_payload, total, st.out_mask_key);
            *produced += hdr_len + static_cast<u32>(total);
        } else if (action == WsFrameAction::Close) {
            // Emit an empty Close (no body) and end the stream.
            u8 hdr[kWsMaxHeaderSize];
            const u32 hdr_len =
                ws_write_header(hdr, WsOpcode::Close, /*fin=*/true, st.masked, st.out_mask_key, 0);
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
