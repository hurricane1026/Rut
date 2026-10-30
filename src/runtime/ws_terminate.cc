#include "rut/runtime/ws_terminate.h"

#include "rut/common/utf8.h"

#include <openssl/rand.h>

namespace rut {

namespace {
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
    (void)mask_rng;  // Retained for compatibility with the existing inspector API.
    if (masked && RAND_bytes(key, sizeof(key)) != 1) return false;
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

bool ws_valid_text_payload(Str text) {
    return (text.ptr || text.len == 0) &&
           utf8_valid(reinterpret_cast<const u8*>(text.ptr), text.len);
}

bool ws_valid_close_reason(Str reason) {
    return reason.len <= kWsMaxCloseReasonBytes && ws_valid_text_payload(reason);
}

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
    if (st.close_policy_count > kWsMaxClosePolicies ||
        (st.close_policy_count != 0 && !st.close_policies))
        return WsInspectStatus::Error;

    if (st.forward_text_count > kWsMaxForwardTexts ||
        (st.forward_text_count != 0 && !st.forward_texts))
        return WsInspectStatus::Error;

    for (;;) {
        const u32 avail = in_len - *consumed;
        const u8* p = in + *consumed;

        WsFrameHeader h;
        if (st.partial_data_frame) {
            h = st.partial_header;
        } else {
            const ParseStatus ps = ws_parse_header(p, avail, st.masked, &h);
            if (ps == ParseStatus::Incomplete) break;  // partial header — wait for more bytes
            if (ps == ParseStatus::Error) return WsInspectStatus::Error;
        }

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
            // The header alone proves an invalid fragment sequence. Reject it
            // before waiting for the advertised payload.
            if ((h.opcode == WsOpcode::Continuation) != st.assembler.in_fragmented)
                return WsInspectStatus::Error;
            if (st.message_len + h.payload_len > msg_cap) return WsInspectStatus::Error;
            if (st.max_message_size != 0 && st.message_len + h.payload_len > st.max_message_size) {
                return WsInspectStatus::Error;
            }
        }

        // Control payloads are small and processed whole; data payloads can span reads.
        const u32 header_len = st.partial_data_frame ? 0 : h.header_len;
        const u64 frame_total =
            static_cast<u64>(header_len) + h.payload_len - st.partial_payload_len;
        if (ws_opcode_is_control(h.opcode) && avail < frame_total) break;
        if (!ws_opcode_is_control(h.opcode) && avail < frame_total && *produced != 0) break;
        // A completed fragmented message can be larger than this input chunk. Flush
        // already-produced frames first when the next output might not fit; leave this
        // frame and the assembler state untouched for the next call.
        if (*produced != 0) {
            const u64 original_size = st.message_len + h.payload_len;
            u64 data_size =
                original_size > st.forward_text.len ? original_size : st.forward_text.len;
            for (u32 i = 0; i < st.forward_text_count; i++)
                if (st.forward_texts[i].len > data_size) data_size = st.forward_texts[i].len;
            u32 reason_size = st.close_reason.len;
            for (u32 i = 0; i < st.close_policy_count; i++)
                if (st.close_policies[i].reason.len > reason_size)
                    reason_size = st.close_policies[i].reason.len;
            const u64 close_size = 2u + static_cast<u64>(reason_size);
            if (reason_size != 0 && close_size > data_size) data_size = close_size;
            const u64 needed = ws_opcode_is_control(h.opcode)
                                   ? frame_total
                                   : (h.fin ? data_size + kWsMaxHeaderSize : 0);
            if (needed > out_cap - *produced) break;
        }
        const u8* payload = p + header_len;

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
                if (!ws_valid_close_code(code)) return WsInspectStatus::Error;
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
            if (h.opcode == WsOpcode::Close) {
                // Peer-initiated close: the peer's own code was relayed verbatim above; keep
                // the echo to the other side at 1000 (unchanged behavior — see header).
                st.echo_close_code = 1000;
                st.echo_close_reason = {};
                return WsInspectStatus::Close;
            }
            continue;
        }

        // Data frame (Text/Binary or continuation).
        // Accumulate the (unmasked) payload into the reassembly buffer (bound already
        // checked above), then ask the reassembler whether the message is complete.
        const u64 remain = h.payload_len - st.partial_payload_len;
        const u32 available_payload = avail - header_len;
        const u32 chunk = remain < available_payload ? static_cast<u32>(remain) : available_payload;
        u8* dst = msg_buf + st.message_len + st.partial_payload_len;
        for (u32 i = 0; i < chunk; i++) dst[i] = payload[i];
        if (st.masked) ws_unmask_chunk(dst, chunk, h.mask_key, st.partial_payload_len);
        st.partial_payload_len += chunk;
        *consumed += header_len + chunk;
        if (st.partial_payload_len < h.payload_len) {
            st.partial_data_frame = true;
            st.partial_header = h;
            break;
        }
        st.partial_data_frame = false;
        st.partial_payload_len = 0;

        WsOpcode msg_op;
        u64 total;
        const WsMessageStatus ms =
            ws_message_feed(st.assembler, h, st.max_message_size, &msg_op, &total);
        if (ms == WsMessageStatus::Error) return WsInspectStatus::Error;
        st.message_len += h.payload_len;

        if (ms == WsMessageStatus::NeedMore) continue;  // awaiting more fragments

        // §8.1: a complete Text message must be valid UTF-8, or the connection fails.
        if (msg_op == WsOpcode::Text && !utf8_valid(msg_buf, total)) {
            return WsInspectStatus::Error;
        }

        // Message complete — invoke the handler and act on its verdict.
        const WsFrameAction action = handler(ctx, msg_op, msg_buf, total, st.from_client);
        const u8 action_value = static_cast<u8>(action);
        const u8 first_policy = static_cast<u8>(WsFrameAction::ClosePolicy0);
        const bool policy_close =
            action_value >= first_policy && action_value < first_policy + kWsMaxClosePolicies;
        if (policy_close && action_value - first_policy >= st.close_policy_count)
            return WsInspectStatus::Error;
        const u8 first_text_policy = static_cast<u8>(WsFrameAction::ForwardTextPolicy0);
        const bool policy_forward = action_value >= first_text_policy &&
                                    action_value < first_text_policy + kWsMaxForwardTexts;
        if (policy_forward && action_value - first_text_policy >= st.forward_text_count)
            return WsInspectStatus::Error;
        if (action == WsFrameAction::Forward) {
            // Re-serialize the whole message as a single (unfragmented) frame.
            if (!emit_frame(
                    out, out_cap, produced, msg_op, msg_buf, total, st.masked, st.mask_rng)) {
                return WsInspectStatus::Error;
            }
        } else if (action == WsFrameAction::ForwardText || policy_forward) {
            // Input has already been reassembled and validated. Output owns a
            // separate slice, so replacement may grow without overwriting input.
            const Str replacement = policy_forward
                                        ? st.forward_texts[action_value - first_text_policy]
                                        : st.forward_text;
            if ((st.max_message_size != 0 && replacement.len > st.max_message_size) ||
                !ws_valid_text_payload(replacement) ||
                !emit_frame(out,
                            out_cap,
                            produced,
                            WsOpcode::Text,
                            reinterpret_cast<const u8*>(replacement.ptr),
                            replacement.len,
                            st.masked,
                            st.mask_rng))
                return WsInspectStatus::Error;
        } else if (action == WsFrameAction::Close || policy_close) {
            const WsClosePolicy selected = policy_close
                                               ? st.close_policies[action_value - first_policy]
                                               : WsClosePolicy{st.close_code, st.close_reason};
            if (!ws_valid_close_code(selected.code) || !ws_valid_close_reason(selected.reason))
                return WsInspectStatus::Error;
            u8 cc[kWsMaxControlPayload];
            cc[0] = static_cast<u8>(selected.code >> 8);
            cc[1] = static_cast<u8>(selected.code);
            for (u32 i = 0; i < selected.reason.len; i++)
                cc[i + 2] = static_cast<u8>(selected.reason.ptr[i]);
            const u32 hdr = 2u + (st.masked ? 4u : 0u);
            u32 body = 2u + selected.reason.len;
            // Preserve the legacy empty-status fallback only for code-only closes.
            // A configured reason must fit whole; never truncate UTF-8 or silently discard it.
            if (static_cast<u64>(*produced) + hdr + body > out_cap) {
                if (selected.reason.len != 0) return WsInspectStatus::Error;
                body = 0;
            }
            if (!emit_frame(
                    out, out_cap, produced, WsOpcode::Close, cc, body, st.masked, st.mask_rng))
                return WsInspectStatus::Error;
            st.echo_close_reason = selected.reason;
            st.echo_close_code = selected.code;
            st.message_len = 0;
            return WsInspectStatus::Close;
        } else if (action != WsFrameAction::Drop) {
            return WsInspectStatus::Error;
        }
        // Drop: emit nothing. All continuing verdicts reset for the next message.
        st.message_len = 0;
    }

    return WsInspectStatus::Ok;
}

u32 ws_emit_close_frame(u8* out, u32 out_cap, bool masked, u64& mask_rng, u16 code, Str reason) {
    if (!ws_valid_close_code(code) || !ws_valid_close_reason(reason)) return 0;
    u8 body[kWsMaxControlPayload];
    body[0] = static_cast<u8>(code >> 8);
    body[1] = static_cast<u8>(code);
    for (u32 i = 0; i < reason.len; i++) body[i + 2] = static_cast<u8>(reason.ptr[i]);
    u32 produced = 0;
    if (!emit_frame(
            out, out_cap, &produced, WsOpcode::Close, body, 2u + reason.len, masked, mask_rng))
        return 0;
    return produced;
}

}  // namespace rut
