// Tests for the RFC 6455 WebSocket frame codec (src/runtime/ws_frame.cc): header
// parse/serialize, payload unmasking, and adversarial validation. Includes the
// known-answer frames from RFC 6455 §5.7.

#include "rut/runtime/ws_frame.h"
#include "test.h"
#include <cstring>

using namespace rut;

namespace {
// Pure helpers (no CHECK — the test framework's CHECK only works inside a TEST body).
struct ParseResult {
    ParseStatus st;
    WsFrameHeader h;
};
ParseResult parse(const u8* buf, u32 len, bool require_mask) {
    ParseResult r{};
    r.st = ws_parse_header(buf, len, require_mask, &r.h);
    return r;
}
bool parse_is(const u8* buf, u32 len, bool require_mask, ParseStatus want) {
    WsFrameHeader h{};
    return ws_parse_header(buf, len, require_mask, &h) == want;
}
// Write a header then parse it back; true iff every field round-trips.
bool roundtrips(WsOpcode op, bool fin, bool masked, u64 len) {
    u8 hdr[kWsMaxHeaderSize];
    const u8 key[4] = {0x11, 0x22, 0x33, 0x44};
    u32 n = ws_write_header(hdr, op, fin, masked, key, len);
    WsFrameHeader h{};
    if (ws_parse_header(hdr, n, masked, &h) != ParseStatus::Complete) return false;
    if (h.header_len != n || h.fin != fin || h.masked != masked || h.opcode != op ||
        h.payload_len != len) {
        return false;
    }
    return !masked || memcmp(h.mask_key, key, 4) == 0;
}
}  // namespace

// === RFC 6455 §5.7 known-answer frames ===

TEST(ws_frame_rfc, unmasked_hello_text) {
    const u8 f[] = {0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f};  // unmasked "Hello"
    ParseResult r = parse(f, sizeof(f), /*require_mask=*/false);
    CHECK(r.st == ParseStatus::Complete);
    CHECK(r.h.fin);
    CHECK(!r.h.masked);
    CHECK(r.h.opcode == WsOpcode::Text);
    CHECK_EQ(r.h.payload_len, 5u);
    CHECK_EQ(r.h.header_len, 2u);
    CHECK_EQ(memcmp(f + r.h.header_len, "Hello", 5), 0);
}

TEST(ws_frame_rfc, masked_hello_text_unmasks) {
    u8 f[] = {0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58};  // masked "Hello"
    ParseResult r = parse(f, sizeof(f), /*require_mask=*/true);
    CHECK(r.st == ParseStatus::Complete);
    CHECK(r.h.fin);
    CHECK(r.h.masked);
    CHECK(r.h.opcode == WsOpcode::Text);
    CHECK_EQ(r.h.payload_len, 5u);
    CHECK_EQ(r.h.header_len, 6u);  // 2 + 4 mask
    CHECK_EQ(r.h.mask_key[0], 0x37);
    CHECK_EQ(r.h.mask_key[3], 0x3d);
    ws_unmask(f + r.h.header_len, r.h.payload_len, r.h.mask_key);
    CHECK_EQ(memcmp(f + r.h.header_len, "Hello", 5), 0);
}

TEST(ws_frame_rfc, unmasked_ping_hello) {
    const u8 f[] = {0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f};
    ParseResult r = parse(f, sizeof(f), false);
    CHECK(r.st == ParseStatus::Complete);
    CHECK(r.h.opcode == WsOpcode::Ping);
    CHECK(ws_opcode_is_control(r.h.opcode));
    CHECK_EQ(r.h.payload_len, 5u);
}

// === Length encodings ===

TEST(ws_frame_len, sixteen_bit) {
    const u8 f[] = {0x82, 126, 0x00, 0xC8};  // binary, 16-bit length 200
    ParseResult r = parse(f, sizeof(f), false);
    CHECK(r.st == ParseStatus::Complete);
    CHECK(r.h.opcode == WsOpcode::Binary);
    CHECK_EQ(r.h.payload_len, 200u);
    CHECK_EQ(r.h.header_len, 4u);
}

TEST(ws_frame_len, sixty_four_bit) {
    const u8 f[] = {0x82, 127, 0, 0, 0, 0, 0, 0x01, 0x11, 0x70};  // 0x011170 = 70000
    ParseResult r = parse(f, sizeof(f), false);
    CHECK(r.st == ParseStatus::Complete);
    CHECK_EQ(r.h.payload_len, 70000u);
    CHECK_EQ(r.h.header_len, 10u);
}

TEST(ws_frame_len, fin_clear_fragment) {
    const u8 f[] = {0x01, 0x03, 'a', 'b', 'c'};  // text, FIN=0 (first fragment)
    ParseResult r = parse(f, sizeof(f), false);
    CHECK(r.st == ParseStatus::Complete);
    CHECK(!r.h.fin);
    CHECK(r.h.opcode == WsOpcode::Text);
}

// === Incremental parsing ===

TEST(ws_frame_incomplete, one_byte) {
    const u8 f[] = {0x81};
    CHECK(parse_is(f, 1, false, ParseStatus::Incomplete));
}
TEST(ws_frame_incomplete, missing_16bit_length) {
    const u8 f[] = {0x82, 126, 0x00};  // need 4 bytes for the 16-bit length
    CHECK(parse_is(f, sizeof(f), false, ParseStatus::Incomplete));
}
TEST(ws_frame_incomplete, missing_64bit_length) {
    const u8 f[] = {0x82, 127, 0, 0, 0};  // need 10 bytes
    CHECK(parse_is(f, sizeof(f), false, ParseStatus::Incomplete));
}
TEST(ws_frame_incomplete, missing_mask_key) {
    const u8 f[] = {0x81, 0x85, 0x37, 0xfa};  // masked, only 2 of 4 mask bytes present
    CHECK(parse_is(f, sizeof(f), true, ParseStatus::Incomplete));
}

// === Adversarial validation (must Error) ===

TEST(ws_frame_reject, rsv_bit_set) {
    const u8 f[] = {0xC1, 0x00};  // RSV1 set
    CHECK(parse_is(f, sizeof(f), false, ParseStatus::Error));
}
TEST(ws_frame_reject, reserved_opcode) {
    const u8 f1[] = {0x83, 0x00};  // opcode 0x3 (reserved non-control)
    const u8 f2[] = {0x8B, 0x00};  // opcode 0xB (reserved control)
    CHECK(parse_is(f1, sizeof(f1), false, ParseStatus::Error));
    CHECK(parse_is(f2, sizeof(f2), false, ParseStatus::Error));
}
TEST(ws_frame_reject, fragmented_control_frame) {
    const u8 f[] = {0x09, 0x00};  // ping with FIN=0
    CHECK(parse_is(f, sizeof(f), false, ParseStatus::Error));
}
TEST(ws_frame_reject, oversized_control_frame) {
    const u8 f[] = {0x89, 126, 0x00, 0xC8};  // ping using 16-bit length 200 (>125)
    CHECK(parse_is(f, sizeof(f), false, ParseStatus::Error));
}
TEST(ws_frame_reject, mask_direction_violation) {
    const u8 unmasked[] = {0x81, 0x05, 'H', 'e', 'l', 'l', 'o'};
    CHECK(parse_is(unmasked, sizeof(unmasked), /*require_mask=*/true, ParseStatus::Error));
    const u8 masked[] = {0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58};
    CHECK(parse_is(masked, sizeof(masked), /*require_mask=*/false, ParseStatus::Error));
}
TEST(ws_frame_reject, sixty_four_bit_msb_set) {
    const u8 f[] = {0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 1};  // top bit of 64-bit length set
    CHECK(parse_is(f, sizeof(f), false, ParseStatus::Error));
}
TEST(ws_frame_reject, non_minimal_lengths) {
    const u8 f16[] = {0x82, 126, 0x00, 0x64};  // 16-bit encoding of 100 (fits in 7 bits)
    CHECK(parse_is(f16, sizeof(f16), false, ParseStatus::Error));
    const u8 f64[] = {0x82, 127, 0, 0, 0, 0, 0, 0, 0x00, 0x64};  // 64-bit encoding of 100
    CHECK(parse_is(f64, sizeof(f64), false, ParseStatus::Error));
}
TEST(ws_frame_reject, close_one_byte_payload) {
    // §5.5.1: a Close body must start with a 2-byte status code, so length 1 is malformed.
    const u8 bad[] = {0x88, 0x01, 0x03};  // Close, FIN, 1-byte body
    CHECK(parse_is(bad, sizeof(bad), false, ParseStatus::Error));
    // 0-byte (no body) and 2-byte (status code) Close frames remain valid.
    const u8 empty[] = {0x88, 0x00};
    CHECK(parse_is(empty, sizeof(empty), false, ParseStatus::Complete));
    const u8 code[] = {0x88, 0x02, 0x03, 0xE8};  // status 1000
    CHECK(parse_is(code, sizeof(code), false, ParseStatus::Complete));
}

// === Unmask ===

TEST(ws_frame_unmask, is_its_own_inverse) {
    u8 data[7] = {1, 2, 3, 4, 5, 6, 7};
    const u8 key[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    u8 orig[7];
    memcpy(orig, data, 7);
    ws_unmask(data, 7, key);
    CHECK(memcmp(data, orig, 7) != 0);  // changed
    ws_unmask(data, 7, key);
    CHECK_EQ(memcmp(data, orig, 7), 0);  // restored
}
TEST(ws_frame_unmask, zero_length_is_noop) {
    const u8 key[4] = {1, 2, 3, 4};
    ws_unmask(nullptr, 0, key);  // must not deref
    CHECK(true);
}

// === Serialize (round-trips) ===

TEST(ws_frame_write, roundtrips_all_length_tiers) {
    CHECK(roundtrips(WsOpcode::Text, true, false, 5));          // 7-bit
    CHECK(roundtrips(WsOpcode::Binary, true, true, 5));         // 7-bit masked
    CHECK(roundtrips(WsOpcode::Text, false, false, 200));       // 16-bit
    CHECK(roundtrips(WsOpcode::Binary, true, true, 60000));     // 16-bit masked
    CHECK(roundtrips(WsOpcode::Text, true, false, 70000));      // 64-bit
    CHECK(roundtrips(WsOpcode::Binary, true, true, 1u << 20));  // 64-bit masked
    CHECK(roundtrips(WsOpcode::Pong, true, false, 0));          // control, empty
}

TEST(ws_frame_write, header_lengths) {
    u8 hdr[kWsMaxHeaderSize];
    const u8 key[4] = {0, 0, 0, 0};
    CHECK_EQ(ws_write_header(hdr, WsOpcode::Text, true, false, key, 5), 2u);
    CHECK_EQ(ws_write_header(hdr, WsOpcode::Text, true, true, key, 5), 6u);        // +4 mask
    CHECK_EQ(ws_write_header(hdr, WsOpcode::Text, true, false, key, 200), 4u);     // 16-bit
    CHECK_EQ(ws_write_header(hdr, WsOpcode::Text, true, false, key, 70000), 10u);  // 64-bit
    CHECK_EQ(ws_write_header(hdr, WsOpcode::Text, true, true, key, 70000), 14u);   // +4 mask
}

TEST(ws_frame_write, refuses_frames_the_parser_would_reject) {
    u8 hdr[kWsMaxHeaderSize];
    const u8 key[4] = {0, 0, 0, 0};
    // Control frames cannot use extended length (>125) — would emit a frame the parser
    // rejects (oversized_control_frame). Refused → 0, nothing written.
    CHECK_EQ(ws_write_header(hdr, WsOpcode::Close, true, false, key, 200), 0u);
    CHECK_EQ(ws_write_header(hdr, WsOpcode::Ping, true, false, key, 126), 0u);
    CHECK_EQ(ws_write_header(hdr, WsOpcode::Pong, true, true, key, 1000), 0u);
    // Fragmented control frame (fin=false) — parser rejects (fragmented_control_frame).
    CHECK_EQ(ws_write_header(hdr, WsOpcode::Ping, false, false, key, 0), 0u);
    CHECK_EQ(ws_write_header(hdr, WsOpcode::Close, false, false, key, 2), 0u);
    // Close with a 1-byte body — parser rejects (close_one_byte_payload).
    CHECK_EQ(ws_write_header(hdr, WsOpcode::Close, true, false, key, 1), 0u);
    // 64-bit length with the reserved high bit set (sixty_four_bit_msb_set) → refused.
    CHECK_EQ(ws_write_header(hdr, WsOpcode::Binary, true, false, key, 1ull << 63), 0u);
    // Boundaries that still serialize: control at exactly 125, and an empty/2-byte Close.
    CHECK_EQ(ws_write_header(hdr, WsOpcode::Close, true, false, key, 125), 2u);
    CHECK_EQ(ws_write_header(hdr, WsOpcode::Close, true, false, key, 0), 2u);
    CHECK_EQ(ws_write_header(hdr, WsOpcode::Close, true, false, key, 2), 2u);
}

// === Message reassembly (RFC 6455 §5.4) ===

namespace {
// Minimal header for the assembler (it reads only opcode/fin/payload_len).
WsFrameHeader mh(WsOpcode op, bool fin, u64 len) {
    WsFrameHeader h{};
    h.opcode = op;
    h.fin = fin;
    h.payload_len = len;
    return h;
}
struct FeedResult {
    WsMessageStatus st;
    WsOpcode opcode;
    u64 total;
};
FeedResult feed(WsMessageAssembler& m, WsOpcode op, bool fin, u64 len, u64 max) {
    FeedResult r{};
    r.opcode = WsOpcode::Continuation;
    r.st = ws_message_feed(m, mh(op, fin, len), max, &r.opcode, &r.total);
    return r;
}
}  // namespace

TEST(ws_message, single_unfragmented_text) {
    WsMessageAssembler m;
    FeedResult r = feed(m, WsOpcode::Text, true, 5, 0);
    CHECK(r.st == WsMessageStatus::Complete);
    CHECK(r.opcode == WsOpcode::Text);
    CHECK_EQ(r.total, 5u);
    CHECK(!m.in_fragmented);  // state reset after completion
}

TEST(ws_message, single_unfragmented_binary) {
    WsMessageAssembler m;
    FeedResult r = feed(m, WsOpcode::Binary, true, 9, 0);
    CHECK(r.st == WsMessageStatus::Complete);
    CHECK(r.opcode == WsOpcode::Binary);
    CHECK_EQ(r.total, 9u);
}

TEST(ws_message, fragmented_reassembles) {
    WsMessageAssembler m;
    CHECK(feed(m, WsOpcode::Text, false, 10, 0).st == WsMessageStatus::NeedMore);
    CHECK(feed(m, WsOpcode::Continuation, false, 20, 0).st == WsMessageStatus::NeedMore);
    FeedResult last = feed(m, WsOpcode::Continuation, true, 5, 0);
    CHECK(last.st == WsMessageStatus::Complete);
    CHECK(last.opcode == WsOpcode::Text);  // message opcode from the FIRST frame
    CHECK_EQ(last.total, 35u);
}

TEST(ws_message, continuation_without_start_is_error) {
    WsMessageAssembler m;
    CHECK(feed(m, WsOpcode::Continuation, true, 5, 0).st == WsMessageStatus::Error);
}

TEST(ws_message, new_data_frame_mid_message_is_error) {
    WsMessageAssembler m;
    CHECK(feed(m, WsOpcode::Text, false, 10, 0).st == WsMessageStatus::NeedMore);
    CHECK(feed(m, WsOpcode::Binary, true, 5, 0).st == WsMessageStatus::Error);
}

TEST(ws_message, control_frame_rejected) {
    WsMessageAssembler m;
    CHECK(feed(m, WsOpcode::Ping, true, 0, 0).st == WsMessageStatus::Error);
    CHECK(feed(m, WsOpcode::Close, true, 2, 0).st == WsMessageStatus::Error);
}

TEST(ws_message, max_message_size_single_frame) {
    WsMessageAssembler m;
    CHECK(feed(m, WsOpcode::Text, true, 100, 64).st == WsMessageStatus::Error);  // over cap
    WsMessageAssembler m2;
    CHECK(feed(m2, WsOpcode::Text, true, 64, 64).st == WsMessageStatus::Complete);  // at cap
}

TEST(ws_message, max_message_size_across_fragments) {
    WsMessageAssembler m;
    CHECK(feed(m, WsOpcode::Binary, false, 40, 64).st == WsMessageStatus::NeedMore);
    CHECK(feed(m, WsOpcode::Continuation, true, 30, 64).st == WsMessageStatus::Error);  // 70>64
}

TEST(ws_message, max_message_size_overflow_safe) {
    // payload_len near u64 max must not wrap past the cap check.
    WsMessageAssembler m;
    CHECK(feed(m, WsOpcode::Text, true, ~0ull, 1024).st == WsMessageStatus::Error);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
