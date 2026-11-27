#include "rut/runtime/ws_frame.h"

#include "rut/common/checked_arithmetic.h"
#include "rut/common/range_int.h"
#include "rut/common/types.h"
#include "rut/runtime/http_parser.h"

namespace rut {

ParseStatus ws_parse_header(
    const u8* buf, u32 len, bool require_mask, WsFrameHeader* out, bool allow_compressed) {
    if (len < 2) return ParseStatus::Incomplete;

    const u8 b0 = buf[0];
    const u8 b1 = buf[1];

    // RFC 7692 owns RSV1 only; no negotiated extension owns RSV2 or RSV3.
    if ((b0 & 0x30) != 0) return ParseStatus::Error;

    const u8 opcode_bits = b0 & 0x0F;
    const WsOpcode opcode = static_cast<WsOpcode>(opcode_bits);
    if (!ws_opcode_valid(opcode)) return ParseStatus::Error;
    const bool kCompressed = (b0 & 0x40) != 0;
    if (kCompressed &&
        (!allow_compressed || (opcode != WsOpcode::Text && opcode != WsOpcode::Binary)))
        return ParseStatus::Error;
    const bool fin = (b0 & 0x80) != 0;
    const bool masked = (b1 & 0x80) != 0;
    const u8 len7 = b1 & 0x7F;

    // §5.5: control frames must not be fragmented and carry <=125 bytes (which also
    // forbids the 126/127 extended-length forms).
    if (ws_opcode_is_control(opcode)) {
        if (!fin) return ParseStatus::Error;
        if (len7 > 125) return ParseStatus::Error;
        // §5.5.1: a Close body, if present, MUST start with a 2-byte status code, so a
        // 1-byte payload is malformed. (0 = no body is fine; 2..125 carry code+reason.)
        if (opcode == WsOpcode::Close && len7 == 1) return ParseStatus::Error;
    }

    // §5.1 mask-direction enforcement: client->server MUST be masked, server->client
    // MUST NOT be.
    if (require_mask != masked) return ParseStatus::Error;

    i64 payload_len = 0;
    u8 offset = 2;
    if (len7 < 126) {
        payload_len = len7;
    } else if (len7 == 126) {
        if (len < 4) return ParseStatus::Incomplete;
        payload_len = (i64{buf[2]} << 8) | i64{buf[3]};
        offset = 4;
        // §5.2: the minimal number of length bytes MUST be used — a 16-bit length below
        // 126 is a non-canonical encoding.
        if (payload_len < 126) return ParseStatus::Error;
    } else {  // len7 == 127
        if (len < 10) return ParseStatus::Incomplete;
        // §5.2: the most significant bit of a 64-bit length MUST be 0.
        u64 wire_length = 0;
        for (u8 i = 0; i < 8; ++i) {
            const auto kPosition = range_int<2, 3>{} + range_int(i);
            // RUT_INTEGER_RANGE: each iteration appends one of exactly eight wire bytes.
            wire_length = (wire_length << 8) | buf[kPosition.index()];
        }
        if (!try_u64_to_i64(wire_length, &payload_len)) return ParseStatus::Error;
        offset = 10;
        // Minimal-length rule: a 64-bit length that fits in 16 bits is non-canonical.
        if (payload_len <= 0xFFFF) return ParseStatus::Error;
    }

    u32 header_length = offset;
    if (masked) {
        const auto kMaskedLength = range_int(offset) + range_int<4, 5>{};
        if (len < kMaskedLength.value()) return ParseStatus::Incomplete;
        header_length = kMaskedLength.to<u32>();
        __builtin_memmove(out->mask_key, buf + range_int(offset).value(), sizeof(out->mask_key));
    } else {
        for (i32 i = 0; i < 4; ++i) out->mask_key[i] = 0;
    }

    out->fin = fin;
    out->masked = masked;
    out->opcode = opcode;
    out->payload_len = payload_len;
    out->header_len = header_length;
    out->compressed = kCompressed;
    return ParseStatus::Complete;
}

void ws_unmask(u8* payload, u64 len, const u8 mask_key[4]) {
    ws_unmask_chunk(payload, len, mask_key, 0);
}

void ws_unmask_chunk(u8* payload, u64 len, const u8 mask_key[4], u64 offset) {
    constexpr u64 kKeySize = 4;
    const auto phase = bounded_remainder<kKeySize>(offset);
    for (u64 i = 0; i < len; i++) {
        const auto combined = phase + bounded_remainder<kKeySize>(i);
        payload[i] ^= mask_key[bounded_remainder<kKeySize>(combined.to_u64()).index()];
    }
}

u32 ws_write_header(u8* out,
                    WsOpcode op,
                    bool fin,
                    bool masked,
                    const u8 mask_key[4],
                    u64 payload_len,
                    bool compressed) {
    // Refuse to serialize anything ws_parse_header would reject, so the writer can never
    // put a protocol-invalid frame on the wire. Return 0 (never a valid header length —
    // the minimum is 2) to signal "rejected, nothing written". This mirrors the parser's
    // control-frame validation exactly (§5.5/§5.5.1) plus the 64-bit reserved bit (§5.2).
    if (!ws_opcode_valid(op)) return 0;
    if (compressed && op != WsOpcode::Text && op != WsOpcode::Binary) return 0;
    if (ws_opcode_is_control(op)) {
        if (!fin) return 0;                                // control frames are never fragmented
        if (payload_len > kWsMaxControlPayload) return 0;  // and never use extended length
        if (op == WsOpcode::Close && payload_len == 1)
            return 0;  // Close body needs the 2-byte code
    }
    if (payload_len >= (u64{1} << 63)) return 0;  // 64-bit length MSB is reserved zero

    const u64 flags = (fin ? u64{0x80} : 0) | (compressed ? u64{0x40} : 0);
    out[0] = bounded_remainder<256>(flags | __builtin_bit_cast(u8, op)).to<u8>();
    const u8 mask_bit = masked ? 0x80 : 0x00;
    u8 offset;
    if (payload_len <= 125) {
        out[1] = bounded_remainder<256>(mask_bit | payload_len).to<u8>();
        offset = 2;
    } else if (payload_len <= 0xFFFF) {
        out[1] = bounded_remainder<256>(mask_bit | 126).to<u8>();
        out[2] = bounded_remainder<256>(payload_len >> 8).to<u8>();
        out[3] = bounded_remainder<256>(payload_len).to<u8>();
        offset = 4;
    } else {
        out[1] = bounded_remainder<256>(mask_bit | 127).to<u8>();
        for (u8 i = 0; i < 8; ++i) {
            const auto kPosition = range_int<2, 3>{} + range_int(i);
            const auto kShift = (range_int<7, 8>{} - range_int(i)).scaled_by<8>();
            // RUT_INTEGER_RANGE: the loop bounds the shift count to [0, 56].
            out[kPosition.index()] = bounded_remainder<256>(payload_len >> kShift.value()).to<u8>();
        }
        offset = 10;
    }
    if (masked) {
        __builtin_memmove(out + range_int(offset).value(), mask_key, 4);
        return (range_int(offset) + range_int<4, 5>{}).to<u32>();
    }
    return offset;
}

WsMessageStatus ws_message_feed(WsMessageAssembler& m,
                                const WsFrameHeader& h,
                                u64 max_message_size,
                                WsOpcode* out_opcode,
                                u64* out_total_len) {
    // Control frames are handled per-frame, never reassembled (§5.4).
    if (!ws_opcode_valid(h.opcode) || ws_opcode_is_control(h.opcode) || h.payload_len < 0)
        return WsMessageStatus::Error;

    if (h.opcode == WsOpcode::Continuation) {
        // A continuation is only meaningful once a message has been started.
        if (!m.in_fragmented || h.compressed) return WsMessageStatus::Error;
    } else {
        // A new Text/Binary frame must not arrive in the middle of another message.
        if (m.in_fragmented) return WsMessageStatus::Error;
        m.message_opcode = h.opcode;
        m.accumulated_len = 0;
        m.in_fragmented = true;
    }

    // RUT_INTEGER_RANGE: an unbounded message may use the full u64 accumulator.
    u64 total = 0;
    if (add_overflow(m.accumulated_len, h.payload_len, &total) ||
        (max_message_size != 0 && total > max_message_size)) {
        m.reset();
        return WsMessageStatus::Error;
    }
    m.accumulated_len = total;

    if (h.fin) {
        *out_opcode = m.message_opcode;
        *out_total_len = m.accumulated_len;
        m.reset();
        return WsMessageStatus::Complete;
    }
    return WsMessageStatus::NeedMore;
}

}  // namespace rut
