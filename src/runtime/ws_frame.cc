#include "rut/runtime/ws_frame.h"

namespace rut {

ParseStatus ws_parse_header(const u8* buf, u32 len, bool require_mask, WsFrameHeader* out) {
    if (len < 2) return ParseStatus::Incomplete;

    const u8 b0 = buf[0];
    const u8 b1 = buf[1];

    // RSV1-3 (0x70) must be zero — no extensions are negotiated (§5.2).
    if ((b0 & 0x70) != 0) return ParseStatus::Error;

    const u8 opcode_bits = b0 & 0x0F;
    switch (opcode_bits) {
        case 0x0:
        case 0x1:
        case 0x2:
        case 0x8:
        case 0x9:
        case 0xA:
            break;
        default:
            return ParseStatus::Error;  // reserved opcodes 0x3-0x7 and 0xB-0xF
    }
    const WsOpcode opcode = static_cast<WsOpcode>(opcode_bits);
    const bool fin = (b0 & 0x80) != 0;
    const bool masked = (b1 & 0x80) != 0;
    const u8 len7 = b1 & 0x7F;

    // §5.5: control frames must not be fragmented and carry <=125 bytes (which also
    // forbids the 126/127 extended-length forms).
    if (ws_opcode_is_control(opcode)) {
        if (!fin) return ParseStatus::Error;
        if (len7 > 125) return ParseStatus::Error;
    }

    // §5.1 mask-direction enforcement: client->server MUST be masked, server->client
    // MUST NOT be.
    if (require_mask != masked) return ParseStatus::Error;

    u64 payload_len = 0;
    u32 offset = 2;
    if (len7 < 126) {
        payload_len = len7;
    } else if (len7 == 126) {
        if (len < 4) return ParseStatus::Incomplete;
        payload_len = (static_cast<u64>(buf[2]) << 8) | static_cast<u64>(buf[3]);
        offset = 4;
        // §5.2: the minimal number of length bytes MUST be used — a 16-bit length below
        // 126 is a non-canonical encoding.
        if (payload_len < 126) return ParseStatus::Error;
    } else {  // len7 == 127
        if (len < 10) return ParseStatus::Incomplete;
        // §5.2: the most significant bit of a 64-bit length MUST be 0.
        if ((buf[2] & 0x80) != 0) return ParseStatus::Error;
        for (u32 i = 0; i < 8; i++) {
            payload_len = (payload_len << 8) | static_cast<u64>(buf[2 + i]);
        }
        offset = 10;
        // Minimal-length rule: a 64-bit length that fits in 16 bits is non-canonical.
        if (payload_len <= 0xFFFF) return ParseStatus::Error;
    }

    if (masked) {
        if (len < offset + 4) return ParseStatus::Incomplete;
        for (u32 i = 0; i < 4; i++) out->mask_key[i] = buf[offset + i];
        offset += 4;
    } else {
        for (u32 i = 0; i < 4; i++) out->mask_key[i] = 0;
    }

    out->fin = fin;
    out->masked = masked;
    out->opcode = opcode;
    out->payload_len = payload_len;
    out->header_len = offset;
    return ParseStatus::Complete;
}

void ws_unmask(u8* payload, u64 len, const u8 mask_key[4]) {
    for (u64 i = 0; i < len; i++) payload[i] ^= mask_key[i & 3];
}

u32 ws_write_header(
    u8* out, WsOpcode op, bool fin, bool masked, const u8 mask_key[4], u64 payload_len) {
    out[0] = static_cast<u8>((fin ? 0x80 : 0x00) | static_cast<u8>(op));
    const u8 mask_bit = masked ? 0x80 : 0x00;
    u32 offset;
    if (payload_len <= 125) {
        out[1] = static_cast<u8>(mask_bit | static_cast<u8>(payload_len));
        offset = 2;
    } else if (payload_len <= 0xFFFF) {
        out[1] = static_cast<u8>(mask_bit | 126);
        out[2] = static_cast<u8>((payload_len >> 8) & 0xFF);
        out[3] = static_cast<u8>(payload_len & 0xFF);
        offset = 4;
    } else {
        out[1] = static_cast<u8>(mask_bit | 127);
        for (u32 i = 0; i < 8; i++) {
            out[2 + i] = static_cast<u8>((payload_len >> ((7 - i) * 8)) & 0xFF);
        }
        offset = 10;
    }
    if (masked) {
        for (u32 i = 0; i < 4; i++) out[offset + i] = mask_key[i];
        offset += 4;
    }
    return offset;
}

}  // namespace rut
