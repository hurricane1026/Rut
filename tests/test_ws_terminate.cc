// Tests for the WebSocket terminate-mode inspection engine (src/runtime/ws_terminate.cc):
// reassembly + handler dispatch + re-framing, across both tunnel directions, forward/
// drop/close, fragmentation, control pass-through, partial frames, and bounds.

#include "rut/runtime/ws_frame.h"
#include "rut/runtime/ws_terminate.h"
#include "test.h"
#include <cstring>

using namespace rut;

namespace {

// A recording handler whose verdict is configurable.
struct Recorder {
    int calls = 0;
    WsOpcode last_op = WsOpcode::Text;
    u64 last_len = 0;
    u8 last_first = 0;
    WsFrameAction verdict = WsFrameAction::Forward;
    bool drop_text = false;
    bool close_now = false;
};
WsFrameAction record(void* c, WsOpcode op, const u8* payload, u64 len) {
    auto* r = static_cast<Recorder*>(c);
    r->calls++;
    r->last_op = op;
    r->last_len = len;
    r->last_first = len ? payload[0] : 0;
    if (r->close_now) return WsFrameAction::Close;
    if (r->drop_text && op == WsOpcode::Text) return WsFrameAction::Drop;
    return r->verdict;
}

const u8 kKeyIn[4] = {0x11, 0x22, 0x33, 0x44};

// Build one frame (header + masked-or-plain payload) into buf; return total bytes.
u32 build(u8* buf, WsOpcode op, bool fin, bool masked, const u8* payload, u32 len) {
    u32 n = ws_write_header(buf, op, fin, masked, kKeyIn, len);
    for (u32 i = 0; i < len; i++) buf[n + i] = payload[i];
    if (masked) ws_unmask(buf + n, len, kKeyIn);
    return n + len;
}

// Parse one frame from buf; copy its unmasked payload into pl. Return total frame bytes.
u32 parse_one(const u8* buf, u32 len, bool masked, WsFrameHeader* h, u8* pl) {
    if (ws_parse_header(buf, len, masked, h) != ParseStatus::Complete) return 0;
    for (u64 i = 0; i < h->payload_len; i++) pl[i] = buf[h->header_len + i];
    if (h->masked) ws_unmask(pl, h->payload_len, h->mask_key);
    return h->header_len + static_cast<u32>(h->payload_len);
}

WsInspector make_state(bool masked) {
    WsInspector st;
    st.masked = masked;
    st.max_message_size = 1u << 20;
    st.mask_rng = 0xC0FFEEull;  // deterministic seed (real tunnels seed with entropy)
    return st;
}

}  // namespace

// === Forward (server->client, unmasked) ===

TEST(ws_terminate, forward_unmasked_text) {
    WsInspector st = make_state(/*masked=*/false);
    Recorder r;
    u8 in[64];
    const u8 msg[] = {'h', 'e', 'l', 'l', 'o'};
    u32 in_len = build(in, WsOpcode::Text, true, false, msg, 5);

    u8 out[128], mbuf[256];
    u32 consumed = 0, produced = 0;
    WsInspectStatus s = ws_inspect(
        st, in, in_len, out, sizeof(out), mbuf, sizeof(mbuf), record, &r, &consumed, &produced);
    CHECK(s == WsInspectStatus::Ok);
    CHECK_EQ(consumed, in_len);
    CHECK_EQ(r.calls, 1);
    CHECK(r.last_op == WsOpcode::Text);
    CHECK_EQ(r.last_len, 5u);
    // The forwarded frame parses back to the same payload.
    WsFrameHeader h;
    u8 pl[64];
    u32 fn = parse_one(out, produced, false, &h, pl);
    CHECK_EQ(fn, produced);
    CHECK(h.opcode == WsOpcode::Text);
    CHECK_EQ(h.payload_len, 5u);
    CHECK_EQ(memcmp(pl, msg, 5), 0);
}

// === Forward (client->upstream, masked both ways) ===

TEST(ws_terminate, forward_masked_reframes_with_out_key) {
    WsInspector st = make_state(/*masked=*/true);
    Recorder r;
    u8 in[64];
    const u8 msg[] = {'p', 'i', 'n', 'g'};
    u32 in_len = build(in, WsOpcode::Binary, true, true, msg, 4);

    u8 out[128], mbuf[256];
    u32 consumed = 0, produced = 0;
    WsInspectStatus s = ws_inspect(
        st, in, in_len, out, sizeof(out), mbuf, sizeof(mbuf), record, &r, &consumed, &produced);
    CHECK(s == WsInspectStatus::Ok);
    CHECK_EQ(r.calls, 1);
    CHECK(r.last_op == WsOpcode::Binary);
    // Output is masked; parsing it (require_mask=true) + unmasking with its key recovers msg.
    WsFrameHeader h;
    u8 pl[64];
    CHECK(parse_one(out, produced, true, &h, pl) == produced);
    CHECK(h.masked);
    CHECK_EQ(memcmp(pl, msg, 4), 0);
}

// Each re-framed masked message gets a fresh mask key (RFC 6455 §5.3) — two messages in
// one chunk must not carry the same key.
TEST(ws_terminate, masked_frames_get_fresh_keys) {
    WsInspector st = make_state(/*masked=*/true);
    Recorder r;
    u8 in[64];
    const u8 m1[] = {'a', 'a', 'a', 'a'};
    const u8 m2[] = {'b', 'b', 'b', 'b'};
    u32 n = build(in, WsOpcode::Binary, true, true, m1, 4);
    n += build(in + n, WsOpcode::Binary, true, true, m2, 4);

    u8 out[128], mbuf[256];
    u32 consumed = 0, produced = 0;
    WsInspectStatus s = ws_inspect(
        st, in, n, out, sizeof(out), mbuf, sizeof(mbuf), record, &r, &consumed, &produced);
    CHECK(s == WsInspectStatus::Ok);
    CHECK_EQ(r.calls, 2);
    WsFrameHeader h1, h2;
    u8 pl[16];
    u32 f1 = parse_one(out, produced, true, &h1, pl);
    parse_one(out + f1, produced - f1, true, &h2, pl);
    // Different keys across the two outbound frames.
    CHECK(memcmp(h1.mask_key, h2.mask_key, 4) != 0);
}

// === UTF-8 validation (§8.1) ===

TEST(ws_terminate, valid_utf8_text_forwards) {
    WsInspector st = make_state(false);
    Recorder r;
    u8 in[32];
    const u8 msg[] = {0xC3, 0xA9, 'o'};  // "éo" — valid 2-byte + ASCII
    u32 in_len = build(in, WsOpcode::Text, true, false, msg, 3);

    u8 out[64], mbuf[64];
    u32 consumed = 0, produced = 0;
    WsInspectStatus s = ws_inspect(
        st, in, in_len, out, sizeof(out), mbuf, sizeof(mbuf), record, &r, &consumed, &produced);
    CHECK(s == WsInspectStatus::Ok);
    CHECK_EQ(r.calls, 1);
}

TEST(ws_terminate, invalid_utf8_text_errors) {
    WsInspector st = make_state(false);
    Recorder r;
    u8 in[32];
    const u8 msg[] = {0xFF, 0xFE};  // not valid UTF-8 lead bytes
    u32 in_len = build(in, WsOpcode::Text, true, false, msg, 2);

    u8 out[64], mbuf[64];
    u32 consumed = 0, produced = 0;
    WsInspectStatus s = ws_inspect(
        st, in, in_len, out, sizeof(out), mbuf, sizeof(mbuf), record, &r, &consumed, &produced);
    CHECK(s == WsInspectStatus::Error);
    CHECK_EQ(r.calls, 0);  // failed before reaching the handler
}

TEST(ws_terminate, invalid_utf8_only_rejects_text_not_binary) {
    WsInspector st = make_state(false);
    Recorder r;
    u8 in[32];
    const u8 msg[] = {0xFF, 0xFE};  // same bytes, but as Binary they're fine
    u32 in_len = build(in, WsOpcode::Binary, true, false, msg, 2);

    u8 out[64], mbuf[64];
    u32 consumed = 0, produced = 0;
    WsInspectStatus s = ws_inspect(
        st, in, in_len, out, sizeof(out), mbuf, sizeof(mbuf), record, &r, &consumed, &produced);
    CHECK(s == WsInspectStatus::Ok);
    CHECK_EQ(r.calls, 1);
}

// === Drop ===

TEST(ws_terminate, drop_emits_nothing) {
    WsInspector st = make_state(false);
    Recorder r;
    r.verdict = WsFrameAction::Drop;
    u8 in[64];
    const u8 msg[] = {'x', 'y', 'z'};
    u32 in_len = build(in, WsOpcode::Text, true, false, msg, 3);

    u8 out[128], mbuf[256];
    u32 consumed = 0, produced = 0;
    WsInspectStatus s = ws_inspect(
        st, in, in_len, out, sizeof(out), mbuf, sizeof(mbuf), record, &r, &consumed, &produced);
    CHECK(s == WsInspectStatus::Ok);
    CHECK_EQ(consumed, in_len);  // fully consumed
    CHECK_EQ(produced, 0u);      // nothing forwarded
    CHECK_EQ(r.calls, 1);
}

TEST(ws_terminate, selective_drop_text_forward_binary) {
    WsInspector st = make_state(false);
    Recorder r;
    r.drop_text = true;
    u8 in[128];
    const u8 t[] = {'t', 'x', 't'};
    const u8 b[] = {1, 2, 3, 4};
    u32 n = build(in, WsOpcode::Text, true, false, t, 3);
    n += build(in + n, WsOpcode::Binary, true, false, b, 4);

    u8 out[128], mbuf[256];
    u32 consumed = 0, produced = 0;
    WsInspectStatus s = ws_inspect(
        st, in, n, out, sizeof(out), mbuf, sizeof(mbuf), record, &r, &consumed, &produced);
    CHECK(s == WsInspectStatus::Ok);
    CHECK_EQ(consumed, n);
    CHECK_EQ(r.calls, 2);  // both messages handed to the handler
    // Only the binary message is forwarded.
    WsFrameHeader h;
    u8 pl[64];
    CHECK(parse_one(out, produced, false, &h, pl) == produced);
    CHECK(h.opcode == WsOpcode::Binary);
    CHECK_EQ(memcmp(pl, b, 4), 0);
}

// === Fragmentation ===

TEST(ws_terminate, fragmented_message_handler_sees_whole) {
    WsInspector st = make_state(false);
    Recorder r;
    u8 in[128];
    const u8 a[] = {'A', 'A', 'A'};
    const u8 c[] = {'B', 'B'};
    u32 n = build(in, WsOpcode::Text, /*fin=*/false, false, a, 3);          // first fragment
    n += build(in + n, WsOpcode::Continuation, /*fin=*/true, false, c, 2);  // final fragment

    u8 out[128], mbuf[256];
    u32 consumed = 0, produced = 0;
    WsInspectStatus s = ws_inspect(
        st, in, n, out, sizeof(out), mbuf, sizeof(mbuf), record, &r, &consumed, &produced);
    CHECK(s == WsInspectStatus::Ok);
    CHECK_EQ(r.calls, 1);  // one message, not two frames
    CHECK_EQ(r.last_len, 5u);
    CHECK(r.last_op == WsOpcode::Text);
    // Forwarded as a single coalesced frame.
    WsFrameHeader h;
    u8 pl[64];
    CHECK(parse_one(out, produced, false, &h, pl) == produced);
    CHECK_EQ(h.payload_len, 5u);
    CHECK(h.fin);
    CHECK_EQ(memcmp(pl, "AAABB", 5), 0);  // "AAA" + "BB"
}

// === Control pass-through ===

TEST(ws_terminate, ping_passes_through_verbatim) {
    WsInspector st = make_state(false);
    Recorder r;
    u8 in[16];
    const u8 body[] = {'p'};
    u32 in_len = build(in, WsOpcode::Ping, true, false, body, 1);

    u8 out[16], mbuf[64];
    u32 consumed = 0, produced = 0;
    WsInspectStatus s = ws_inspect(
        st, in, in_len, out, sizeof(out), mbuf, sizeof(mbuf), record, &r, &consumed, &produced);
    CHECK(s == WsInspectStatus::Ok);
    CHECK_EQ(r.calls, 0);        // control frames don't reach the handler
    CHECK_EQ(produced, in_len);  // forwarded unchanged
    CHECK_EQ(memcmp(out, in, in_len), 0);
}

TEST(ws_terminate, close_frame_forwards_and_signals_close) {
    WsInspector st = make_state(false);
    Recorder r;
    u8 in[16];
    const u8 code[] = {0x03, 0xE8};  // 1000
    u32 in_len = build(in, WsOpcode::Close, true, false, code, 2);

    u8 out[16], mbuf[64];
    u32 consumed = 0, produced = 0;
    WsInspectStatus s = ws_inspect(
        st, in, in_len, out, sizeof(out), mbuf, sizeof(mbuf), record, &r, &consumed, &produced);
    CHECK(s == WsInspectStatus::Close);
    CHECK_EQ(produced, in_len);  // the Close was forwarded before signaling
}

TEST(ws_terminate, handler_close_emits_close_and_stops) {
    WsInspector st = make_state(false);
    Recorder r;
    r.close_now = true;
    u8 in[64];
    const u8 msg[] = {'b', 'y', 'e'};
    u32 in_len = build(in, WsOpcode::Text, true, false, msg, 3);

    u8 out[64], mbuf[64];
    u32 consumed = 0, produced = 0;
    WsInspectStatus s = ws_inspect(
        st, in, in_len, out, sizeof(out), mbuf, sizeof(mbuf), record, &r, &consumed, &produced);
    CHECK(s == WsInspectStatus::Close);
    CHECK_EQ(r.calls, 1);
    // A Close frame was emitted.
    WsFrameHeader h;
    u8 pl[8];
    CHECK(parse_one(out, produced, false, &h, pl) == produced);
    CHECK(h.opcode == WsOpcode::Close);
}

// === Partial frames across chunks ===

TEST(ws_terminate, partial_frame_left_unconsumed) {
    WsInspector st = make_state(false);
    Recorder r;
    u8 in[64];
    const u8 msg[] = {'a', 'b', 'c', 'd', 'e', 'f'};
    u32 full = build(in, WsOpcode::Text, true, false, msg, 6);

    u8 out[64], mbuf[64];
    u32 consumed = 0, produced = 0;
    // Feed all but the last 2 payload bytes.
    WsInspectStatus s = ws_inspect(
        st, in, full - 2, out, sizeof(out), mbuf, sizeof(mbuf), record, &r, &consumed, &produced);
    CHECK(s == WsInspectStatus::Ok);
    CHECK_EQ(consumed, 0u);  // incomplete frame — nothing consumed
    CHECK_EQ(produced, 0u);
    CHECK_EQ(r.calls, 0);
    // Now feed the whole frame.
    s = ws_inspect(
        st, in, full, out, sizeof(out), mbuf, sizeof(mbuf), record, &r, &consumed, &produced);
    CHECK(s == WsInspectStatus::Ok);
    CHECK_EQ(consumed, full);
    CHECK_EQ(r.calls, 1);
    CHECK_EQ(r.last_len, 6u);
}

// === Bounds & errors ===

TEST(ws_terminate, max_message_size_exceeded_errors) {
    WsInspector st = make_state(false);
    st.max_message_size = 4;
    Recorder r;
    u8 in[64];
    const u8 msg[] = {1, 2, 3, 4, 5};  // 5 > 4
    u32 in_len = build(in, WsOpcode::Binary, true, false, msg, 5);

    u8 out[64], mbuf[64];
    u32 consumed = 0, produced = 0;
    WsInspectStatus s = ws_inspect(
        st, in, in_len, out, sizeof(out), mbuf, sizeof(mbuf), record, &r, &consumed, &produced);
    CHECK(s == WsInspectStatus::Error);
}

TEST(ws_terminate, malformed_frame_errors) {
    WsInspector st = make_state(false);
    Recorder r;
    const u8 bad[] = {0xC1, 0x00};  // RSV1 set — parser rejects
    u8 out[16], mbuf[16];
    u32 consumed = 0, produced = 0;
    WsInspectStatus s = ws_inspect(st,
                                   bad,
                                   sizeof(bad),
                                   out,
                                   sizeof(out),
                                   mbuf,
                                   sizeof(mbuf),
                                   record,
                                   &r,
                                   &consumed,
                                   &produced);
    CHECK(s == WsInspectStatus::Error);
}

TEST(ws_terminate, output_capacity_exceeded_errors) {
    WsInspector st = make_state(false);
    Recorder r;
    u8 in[64];
    const u8 msg[] = {1, 2, 3, 4, 5, 6, 7, 8};
    u32 in_len = build(in, WsOpcode::Binary, true, false, msg, 8);

    u8 out[4], mbuf[64];  // out too small for a 2+8 frame
    u32 consumed = 0, produced = 0;
    WsInspectStatus s = ws_inspect(
        st, in, in_len, out, sizeof(out), mbuf, sizeof(mbuf), record, &r, &consumed, &produced);
    CHECK(s == WsInspectStatus::Error);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
