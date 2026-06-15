// Tests for the HTTP/2 connection engine (src/runtime/http2_conn.cc): preface,
// SETTINGS handshake, frame demux, HEADERS/CONTINUATION assembly + HPACK decode,
// DATA delivery, flow control, and control-frame generation. Inbound frames are
// built with the engine's own response writers (HPACK encoder), fed through
// process(), and the decoded callbacks + emitted control frames are asserted.

#include "rut/runtime/http2_conn.h"
#include "rut/runtime/http2_frame.h"
#include "test.h"

using namespace rut;

namespace {

struct Capture {
    u32 headers_calls;
    u32 last_stream;
    u32 nh;
    bool end_stream;
    char names[16][64];
    u32 nlen[16];
    char vals[16][256];
    u32 vlen[16];

    u32 data_calls;
    u32 data_stream;
    char data[256];
    u32 data_len;
    bool data_end;

    u32 reset_calls;
    u32 reset_stream;
    Http2Error reset_err;

    void clear() { __builtin_memset(this, 0, sizeof(*this)); }
};

void on_headers(void* ctx, Http2Conn&, u32 sid, const hpack::Header* hs, u32 n, bool end_stream) {
    auto* cap = static_cast<Capture*>(ctx);
    cap->headers_calls++;
    cap->last_stream = sid;
    cap->nh = n;
    cap->end_stream = end_stream;
    for (u32 i = 0; i < n && i < 16; i++) {
        cap->nlen[i] = hs[i].name.len;
        for (u32 j = 0; j < hs[i].name.len && j < 64; j++) cap->names[i][j] = hs[i].name.ptr[j];
        cap->vlen[i] = hs[i].value.len;
        for (u32 j = 0; j < hs[i].value.len && j < 256; j++) cap->vals[i][j] = hs[i].value.ptr[j];
    }
}

void on_data(void* ctx, Http2Conn&, u32 sid, const u8* data, u32 len, bool end_stream) {
    auto* cap = static_cast<Capture*>(ctx);
    cap->data_calls++;
    cap->data_stream = sid;
    cap->data_end = end_stream;
    cap->data_len = len;
    for (u32 i = 0; i < len && i < 256; i++) cap->data[i] = static_cast<char>(data[i]);
}

void on_reset(void* ctx, Http2Conn&, u32 sid, Http2Error err) {
    auto* cap = static_cast<Capture*>(ctx);
    cap->reset_calls++;
    cap->reset_stream = sid;
    cap->reset_err = err;
}

void setup(Http2Conn& c, Capture& cap) {
    cap.clear();
    c.cb_ctx = &cap;
    c.on_headers = on_headers;
    c.on_data = on_data;
    c.on_reset = on_reset;
    c.init();
}

// Build "preface + frames" by prepending the client preface to `frames`.
u32 with_preface(u8* out, const u8* frames, u32 flen) {
    for (u32 i = 0; i < kClientPrefaceLen; i++) out[i] = kClientPreface[i];
    for (u32 i = 0; i < flen; i++) out[kClientPrefaceLen + i] = frames[i];
    return kClientPrefaceLen + flen;
}

// Does `out[0..len)` contain a frame of the given type/flags?
bool has_frame(const u8* out, u32 len, Http2FrameType type, u8 flags_mask, u8 flags_val) {
    u32 pos = 0;
    while (pos + kFrameHeaderSize <= len) {
        Http2FrameHeader h;
        parse_frame_header(out + pos, len - pos, &h);
        if (pos + kFrameHeaderSize + h.length > len) break;
        if (h.type == static_cast<u8>(type) && (h.flags & flags_mask) == flags_val) return true;
        pos += kFrameHeaderSize + h.length;
    }
    return false;
}

bool name_is(const Capture& cap, u32 i, const char* s) {
    u32 n = 0;
    while (s[n]) n++;
    if (cap.nlen[i] != n) return false;
    for (u32 j = 0; j < n; j++)
        if (cap.names[i][j] != s[j]) return false;
    return true;
}
bool val_is(const Capture& cap, u32 i, const char* s) {
    u32 n = 0;
    while (s[n]) n++;
    if (cap.vlen[i] != n) return false;
    for (u32 j = 0; j < n; j++)
        if (cap.vals[i][j] != s[j]) return false;
    return true;
}

}  // namespace

TEST(http2_conn, preface_incomplete_consumes_nothing) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(kClientPreface, 10, out, sizeof(out), &ow);
    CHECK_EQ(r.consumed, 0u);
    CHECK_FALSE(r.close);
    CHECK_EQ(ow, 0u);
}

TEST(http2_conn, preface_then_sends_settings) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(kClientPreface, kClientPrefaceLen, out, sizeof(out), &ow);
    CHECK_EQ(r.consumed, kClientPrefaceLen);
    CHECK_FALSE(r.close);
    // Server must emit its own SETTINGS (not an ACK).
    CHECK(has_frame(out, ow, Http2FrameType::Settings, http2_flag::kAck, 0));
}

TEST(http2_conn, bad_preface_closes_with_goaway) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    u8 bad[kClientPrefaceLen];
    for (u32 i = 0; i < kClientPrefaceLen; i++) bad[i] = kClientPreface[i];
    bad[0] = 'X';
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(bad, sizeof(bad), out, sizeof(out), &ow);
    CHECK(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::Goaway, 0, 0));
}

TEST(http2_conn, peer_settings_gets_ack) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    Http2Settings s;
    s.set_defaults();
    s.initial_window_size = 131072;
    u8 frame[64];
    u32 fn = write_settings_frame(frame, s);
    u8 in[128];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_EQ(r.consumed, inlen);
    CHECK_FALSE(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::Settings, http2_flag::kAck, http2_flag::kAck));
    CHECK_EQ(c.peer_settings.initial_window_size, 131072u);
}

TEST(http2_conn, headers_decode_and_deliver) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    hpack::Header hs[] = {
        {{":method", 7}, {"GET", 3}},
        {{":scheme", 7}, {"https", 5}},
        {{":path", 5}, {"/", 1}},
        {{":authority", 10}, {"example.com", 11}},
    };
    u8 frame[256];
    u32 fn = http2_write_headers(frame, sizeof(frame), 1, hs, 4, /*end_stream=*/true);
    u8 in[384];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_EQ(r.consumed, inlen);
    CHECK_FALSE(r.close);
    CHECK_EQ(cap.headers_calls, 1u);
    CHECK_EQ(cap.last_stream, 1u);
    CHECK_EQ(cap.nh, 4u);
    CHECK(cap.end_stream);
    CHECK(name_is(cap, 0, ":method"));
    CHECK(val_is(cap, 0, "GET"));
    CHECK(name_is(cap, 3, ":authority"));
    CHECK(val_is(cap, 3, "example.com"));
    // Stream recorded.
    Http2Stream* s = c.find_stream(1);
    REQUIRE(s != nullptr);
    CHECK(s->state == Http2StreamState::HalfClosedRemote);
}

TEST(http2_conn, data_delivered_and_window_replenished) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    hpack::Header hs[] = {{{":method", 7}, {"POST", 4}}, {{":path", 5}, {"/up", 3}}};
    u8 frame[512];
    u32 fn = http2_write_headers(frame, sizeof(frame), 1, hs, 2, /*end_stream=*/false);
    fn += http2_write_data(frame + fn, 1, reinterpret_cast<const u8*>("hello"), 5, true);
    u8 in[640];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_EQ(r.consumed, inlen);
    CHECK_EQ(cap.headers_calls, 1u);
    CHECK_EQ(cap.data_calls, 1u);
    CHECK_EQ(cap.data_stream, 1u);
    CHECK_EQ(cap.data_len, 5u);
    CHECK(cap.data_end);
    CHECK_EQ(cap.data[0], 'h');
    // Connection-level WINDOW_UPDATE replenishes the consumed octets.
    CHECK(has_frame(out, ow, Http2FrameType::WindowUpdate, 0, 0));
}

TEST(http2_conn, ping_is_acked) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    u8 ping[kFrameHeaderSize + 8];
    Http2FrameHeader h;
    h.length = 8;
    h.type = static_cast<u8>(Http2FrameType::Ping);
    h.flags = 0;
    h.stream_id = 0;
    write_frame_header(ping, h);
    for (u32 i = 0; i < 8; i++) ping[kFrameHeaderSize + i] = static_cast<u8>(i + 1);
    u8 in[64];
    u32 inlen = with_preface(in, ping, sizeof(ping));
    u8 out[256];
    u32 ow = 0;
    c.process(in, inlen, out, sizeof(out), &ow);
    CHECK(has_frame(out, ow, Http2FrameType::Ping, http2_flag::kAck, http2_flag::kAck));
}

TEST(http2_conn, window_update_grows_send_window) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    // Open a stream first.
    hpack::Header hs[] = {{{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/", 1}}};
    u8 frame[256];
    u32 fn = http2_write_headers(frame, sizeof(frame), 1, hs, 2, false);
    fn += write_window_update(frame + fn, 1, 1000);
    u8 in[384];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    c.process(in, inlen, out, sizeof(out), &ow);
    Http2Stream* s = c.find_stream(1);
    REQUIRE(s != nullptr);
    CHECK_EQ(s->send_window, static_cast<i32>(kDefaultInitialWindowSize) + 1000);
}

TEST(http2_conn, rst_stream_closes_and_notifies) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    hpack::Header hs[] = {{{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/", 1}}};
    u8 frame[256];
    u32 fn = http2_write_headers(frame, sizeof(frame), 1, hs, 2, false);
    fn += write_rst_stream(frame + fn, 1, Http2Error::Cancel);
    u8 in[384];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_EQ(cap.reset_calls, 1u);
    CHECK_EQ(cap.reset_stream, 1u);
    CHECK(cap.reset_err == Http2Error::Cancel);
    CHECK(c.find_stream(1) == nullptr);  // closed streams are not findable
}

TEST(http2_conn, partial_frame_left_unconsumed) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    hpack::Header hs[] = {{{":method", 7}, {"GET", 3}}};
    u8 frame[128];
    u32 fn = http2_write_headers(frame, sizeof(frame), 1, hs, 1, true);
    u8 in[256];
    u32 inlen = with_preface(in, frame, fn);
    // Feed everything except the last 3 bytes of the HEADERS frame.
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen - 3, out, sizeof(out), &ow);
    CHECK_EQ(r.consumed, kClientPrefaceLen);  // preface only; frame is partial
    CHECK_EQ(cap.headers_calls, 0u);
    CHECK_FALSE(r.close);
}

TEST(http2_conn, continuation_assembles_header_block) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    // Hand-build a HEADERS without END_HEADERS carrying :method GET (static idx
    // 2 -> 0x82), then a CONTINUATION with END_HEADERS carrying :path / (0x84).
    u8 frame[64];
    u32 fn = 0;
    Http2FrameHeader hh;
    hh.length = 1;
    hh.type = static_cast<u8>(Http2FrameType::Headers);
    hh.flags = 0;  // no END_HEADERS, no END_STREAM
    hh.stream_id = 1;
    write_frame_header(frame + fn, hh);
    frame[fn + kFrameHeaderSize] = 0x82;
    fn += kFrameHeaderSize + 1;
    Http2FrameHeader ch;
    ch.length = 1;
    ch.type = static_cast<u8>(Http2FrameType::Continuation);
    ch.flags = http2_flag::kEndHeaders;
    ch.stream_id = 1;
    write_frame_header(frame + fn, ch);
    frame[fn + kFrameHeaderSize] = 0x84;
    fn += kFrameHeaderSize + 1;
    u8 in[128];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_FALSE(r.close);
    CHECK_EQ(cap.headers_calls, 1u);
    CHECK_EQ(cap.nh, 2u);
    CHECK(name_is(cap, 0, ":method"));
    CHECK(name_is(cap, 1, ":path"));
}

TEST(http2_conn, push_promise_from_client_is_protocol_error) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    u8 pp[kFrameHeaderSize];
    Http2FrameHeader h;
    h.length = 0;
    h.type = static_cast<u8>(Http2FrameType::PushPromise);
    h.flags = 0;
    h.stream_id = 1;
    write_frame_header(pp, h);
    u8 in[64];
    u32 inlen = with_preface(in, pp, sizeof(pp));
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::Goaway, 0, 0));
}

TEST(http2_conn, response_writers_roundtrip) {
    // The server response writers must produce frames the framing layer parses.
    hpack::Header hs[] = {{{":status", 7}, {"200", 3}}, {{"content-length", 14}, {"5", 1}}};
    u8 buf[256];
    u32 n = http2_write_headers(buf, sizeof(buf), 1, hs, 2, false);
    Http2FrameHeader h;
    CHECK(parse_frame_header(buf, n, &h) == ParseStatus::Complete);
    CHECK_EQ(h.type, static_cast<u8>(Http2FrameType::Headers));
    CHECK_EQ(h.stream_id, 1u);
    CHECK((h.flags & http2_flag::kEndHeaders) != 0);
    CHECK((h.flags & http2_flag::kEndStream) == 0);

    u32 dn = http2_write_data(buf, 1, reinterpret_cast<const u8*>("hello"), 5, true);
    CHECK(parse_frame_header(buf, dn, &h) == ParseStatus::Complete);
    CHECK_EQ(h.type, static_cast<u8>(Http2FrameType::Data));
    CHECK_EQ(h.length, 5u);
    CHECK((h.flags & http2_flag::kEndStream) != 0);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
