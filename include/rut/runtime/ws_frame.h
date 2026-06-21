#pragma once

#include "rut/common/types.h"
#include "rut/runtime/http_parser.h"  // ParseStatus

// RFC 6455 WebSocket framing primitives (§5). Pure, zero-allocation parse/serialize
// for the 2..14-octet frame header, in-place payload unmasking, and frame-header
// construction. This is the codec foundation for WebSocket terminate mode; message-
// level fragmentation reassembly, flow control, and the tunnel pump live in a later
// layer that consumes these helpers.
namespace rut {

// Frame opcodes (RFC 6455 §5.2). The 0x8 bit marks a control frame.
enum class WsOpcode : u8 {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
};

// Largest possible frame header: 2 base + 8 (64-bit extended length) + 4 (mask key).
static constexpr u32 kWsMaxHeaderSize = 14;
// Control frames (Close/Ping/Pong) MUST be <=125 bytes and not fragmented (§5.5).
static constexpr u64 kWsMaxControlPayload = 125;

// True for Close/Ping/Pong (the 0x8 opcode bit).
inline bool ws_opcode_is_control(WsOpcode op) {
    return (static_cast<u8>(op) & 0x8) != 0;
}

// A parsed frame header — everything before the payload (§5.2).
struct WsFrameHeader {
    bool fin;
    bool masked;
    WsOpcode opcode;
    u8 mask_key[4];   // valid iff masked
    u64 payload_len;  // 7-/16-/64-bit decoded length
    u32 header_len;   // octets this header consumed (2..14); payload starts at buf+header_len
};

// Parse a frame header from `buf` (incremental). Returns:
//   Complete   — `*out` fully populated; payload follows at buf + out->header_len.
//   Incomplete — the header is not fully present yet; call again after more bytes.
//   Error      — protocol violation (any RSV bit set, a reserved/invalid opcode, a
//                control frame with FIN=0 or payload>125, the 64-bit length's top bit
//                set, or a mask-direction violation). The caller must fail the tunnel.
// `require_mask` enforces §5.1: pass true for client->server frames (MUST be masked)
// and false for server->client frames (MUST NOT be masked).
ParseStatus ws_parse_header(const u8* buf, u32 len, bool require_mask, WsFrameHeader* out);

// Unmask (or mask — the operation is its own inverse) `len` payload bytes in place with
// the 4-byte key (§5.3). Safe for len == 0.
void ws_unmask(u8* payload, u64 len, const u8 mask_key[4]);

// Serialize a frame header into `out` (caller guarantees >= kWsMaxHeaderSize bytes).
// When `masked`, writes `mask_key` (the caller masks the payload separately via
// ws_unmask). Returns the number of header octets written (2..14).
u32 ws_write_header(
    u8* out, WsOpcode op, bool fin, bool masked, const u8 mask_key[4], u64 payload_len);

}  // namespace rut
