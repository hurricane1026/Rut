// Tests for the HTTP/2 connection engine (src/runtime/http2_conn.cc): preface,
// SETTINGS handshake, frame demux, HEADERS/CONTINUATION assembly + HPACK decode,
// DATA delivery, flow control, and control-frame generation. Inbound frames are
// built with the engine's own response writers (HPACK encoder), fed through
// process(), and the decoded callbacks + emitted control frames are asserted.

#include "rut/runtime/callbacks_h2.h"
#include "rut/runtime/http2_conn.h"
#include "rut/runtime/http2_frame.h"
#include "rut/runtime/response_body_storage.h"
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

// Regression: a stream we've already responded to (END_STREAM sent) while the
// peer is still sending must go half-closed(local), so the peer's trailing DATA
// is accepted & discarded — NOT answered with a spurious RST_STREAM (which used
// to happen because h2_close_stream marked the stream fully Closed too early).
TEST(http2_conn, data_after_local_response_discarded_not_reset) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    // Client opens a stream WITHOUT END_STREAM (a request body follows).
    hpack::Header hs[] = {{{":method", 7}, {"POST", 4}}, {{":path", 5}, {"/x", 2}}};
    u8 hf[256];
    u32 hn = http2_write_headers(hf, sizeof(hf), 1, hs, 2, /*end_stream=*/false);
    u8 in[384];
    u32 inlen = with_preface(in, hf, hn);
    u8 out[256];
    u32 ow = 0;
    c.process(in, inlen, out, sizeof(out), &ow);
    Http2Stream* s = c.find_stream(1);
    REQUIRE(s != nullptr);
    CHECK(s->state == Http2StreamState::Open);
    // Serving layer emits an END_STREAM response before the body arrives.
    h2_close_stream(&c, 1);
    CHECK(s->state == Http2StreamState::HalfClosedLocal);
    // Trailing DATA (with END_STREAM) is accepted, not RST'd, and closes the stream.
    u8 df[64];
    u32 dn = http2_write_data(df, 1, reinterpret_cast<const u8*>("body"), 4, /*end_stream=*/true);
    ow = 0;
    c.process(df, dn, out, sizeof(out), &ow);
    CHECK(!has_frame(out, ow, Http2FrameType::RstStream, 0, 0));
    CHECK(c.find_stream(1) == nullptr);  // HalfClosedLocal + peer END_STREAM → Closed
}

// A fully-completed request (peer sent END_STREAM) closes the slot outright when
// we respond, so a long keep-alive connection can keep reusing stream slots.
TEST(http2_conn, complete_request_closes_slot_on_response) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    hpack::Header hs[] = {{{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/", 1}}};
    u8 hf[256];
    u32 hn = http2_write_headers(hf, sizeof(hf), 1, hs, 2, /*end_stream=*/true);
    u8 in[384];
    u32 inlen = with_preface(in, hf, hn);
    u8 out[256];
    u32 ow = 0;
    c.process(in, inlen, out, sizeof(out), &ow);
    Http2Stream* s = c.find_stream(1);
    REQUIRE(s != nullptr);
    CHECK(s->state == Http2StreamState::HalfClosedRemote);
    h2_close_stream(&c, 1);
    CHECK(c.find_stream(1) == nullptr);  // both sides done → Closed, slot reusable
}

// Regression: a RST_STREAM coalesced behind the request that parked the async
// slot (wait/proxy) must still be processed in the same batch and cancel the
// parked work — otherwise we'd open an upstream / arm a timer and later respond
// for a stream the client already cancelled.
TEST(http2_conn, coalesced_rst_cancels_parked_stream) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    c.on_reset = &h2_on_reset_cb;  // serving-layer handler clears the async slot
    hpack::Header hs[] = {{{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/", 1}}};
    u8 hf[256];
    u32 hn = http2_write_headers(hf, sizeof(hf), 1, hs, 2, /*end_stream=*/true);
    u8 in[384];
    u32 inlen = with_preface(in, hf, hn);
    u8 out[256];
    u32 ow = 0;
    c.process(in, inlen, out, sizeof(out), &ow);
    // Serving layer parks stream 1 on the single async slot.
    c.async_stream = 1;
    c.async_kind = H2AsyncKind::Proxy;
    u8 rf[kFrameHeaderSize + 4];
    u32 rn = write_rst_stream(rf, 1, Http2Error::Cancel);
    ow = 0;
    Http2Result r = c.process(rf, rn, out, sizeof(out), &ow);
    CHECK_EQ(r.consumed, rn);  // control frame drained past the park, not buffered
    CHECK_EQ(c.async_stream, 0u);
    CHECK(c.async_kind == H2AsyncKind::None);
}

// Complement: a NEW request's HEADERS coalesced behind a parked stream stays
// buffered (HPACK-order-dependent, starts new work) until the parked stream
// resumes — only control frames are drained past the park.
TEST(http2_conn, parked_stream_buffers_new_request_headers) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    hpack::Header hs[] = {{{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/", 1}}};
    u8 hf[256];
    u32 hn = http2_write_headers(hf, sizeof(hf), 1, hs, 2, /*end_stream=*/true);
    u8 in[384];
    u32 inlen = with_preface(in, hf, hn);
    u8 out[256];
    u32 ow = 0;
    c.process(in, inlen, out, sizeof(out), &ow);
    c.async_stream = 1;
    c.async_kind = H2AsyncKind::Proxy;
    cap.headers_calls = 0;
    hpack::Header hs2[] = {{{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/y", 2}}};
    u8 hf2[256];
    u32 hn2 = http2_write_headers(hf2, sizeof(hf2), 3, hs2, 2, /*end_stream=*/true);
    ow = 0;
    Http2Result r = c.process(hf2, hn2, out, sizeof(out), &ow);
    CHECK_EQ(r.consumed, 0u);         // left buffered for resume
    CHECK_EQ(cap.headers_calls, 0u);  // not dispatched while parked
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

// === Request bridge: h2 headers -> ParsedRequest ===

namespace {
bool req_has_header(const ParsedRequest& r, const char* name, const char* value) {
    u32 nl = 0;
    while (name[nl]) nl++;
    u32 vl = 0;
    while (value[vl]) vl++;
    for (u32 i = 0; i < r.header_count; i++) {
        if (r.headers[i].name.eq(Str{name, nl}) && r.headers[i].value.eq(Str{value, vl}))
            return true;
    }
    return false;
}
}  // namespace

TEST(h2_request, basic_get_maps_method_path_authority) {
    hpack::Header hs[] = {
        {{":method", 7}, {"GET", 3}},
        {{":scheme", 7}, {"https", 5}},
        {{":authority", 10}, {"example.com", 11}},
        {{":path", 5}, {"/", 1}},
        {{"accept", 6}, {"*/*", 3}},
    };
    ParsedRequest req;
    REQUIRE(h2_headers_to_request(hs, 5, &req));
    CHECK(req.method == HttpMethod::GET);
    CHECK(req.version == HttpVersion::Http11);
    CHECK(req.keep_alive);
    CHECK(req.path.eq(Str{"/", 1}));
    CHECK_EQ(req.path_canon.len, 0u);  // "/" canonicalizes to empty, non-null
    CHECK(req.path_canon.ptr != nullptr);
    // :authority became a host header; :scheme dropped; accept kept.
    CHECK(req_has_header(req, "host", "example.com"));
    CHECK(req_has_header(req, "accept", "*/*"));
}

TEST(h2_request, canon_strips_query_and_trailing_slash) {
    hpack::Header hs[] = {{{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/api/users/?id=1", 16}}};
    ParsedRequest req;
    REQUIRE(h2_headers_to_request(hs, 2, &req));
    CHECK(req.path_canon.eq(Str{"api/users", 9}));
}

TEST(h2_request, content_length_parsed) {
    hpack::Header hs[] = {
        {{":method", 7}, {"POST", 4}},
        {{":path", 5}, {"/u", 2}},
        {{"content-length", 14}, {"42", 2}},
    };
    ParsedRequest req;
    REQUIRE(h2_headers_to_request(hs, 3, &req));
    CHECK(req.method == HttpMethod::POST);
    CHECK(req.has_content_length);
    CHECK_EQ(req.content_length, 42u);
}

TEST(h2_request, ten_digit_content_length_parsed) {
    hpack::Header hs[] = {
        {{":method", 7}, {"POST", 4}},
        {{":path", 5}, {"/u", 2}},
        {{"content-length", 14}, {"0000000000", 10}},
    };
    ParsedRequest req;
    REQUIRE(h2_headers_to_request(hs, 3, &req));
    CHECK(req.has_content_length);
    CHECK_EQ(req.content_length, 0u);

    hpack::Header max[] = {
        {{":method", 7}, {"POST", 4}},
        {{":path", 5}, {"/u", 2}},
        {{"content-length", 14}, {"4294967295", 10}},
    };
    REQUIRE(h2_headers_to_request(max, 3, &req));
    CHECK_EQ(req.content_length, 4294967295u);
}

TEST(h2_request, invalid_or_duplicate_content_length_fails) {
    ParsedRequest req;
    hpack::Header bad[] = {{{":method", 7}, {"POST", 4}},
                           {{":path", 5}, {"/u", 2}},
                           {{"content-length", 14}, {"x", 1}}};
    CHECK_FALSE(h2_headers_to_request(bad, 3, &req));
    hpack::Header over[] = {{{":method", 7}, {"POST", 4}},
                            {{":path", 5}, {"/u", 2}},
                            {{"content-length", 14}, {"4294967296", 10}}};
    CHECK_FALSE(h2_headers_to_request(over, 3, &req));
    hpack::Header dup[] = {
        {{":method", 7}, {"POST", 4}},
        {{":path", 5}, {"/u", 2}},
        {{"content-length", 14}, {"1", 1}},
        {{"content-length", 14}, {"1", 1}},
    };
    CHECK_FALSE(h2_headers_to_request(dup, 4, &req));
}

TEST(h2_request, duplicate_pseudo_headers_fail) {
    ParsedRequest req;
    hpack::Header auth[] = {
        {{":method", 7}, {"GET", 3}},
        {{":path", 5}, {"/", 1}},
        {{":authority", 10}, {"a", 1}},
        {{":authority", 10}, {"b", 1}},
    };
    CHECK_FALSE(h2_headers_to_request(auth, 4, &req));
    hpack::Header scheme[] = {
        {{":method", 7}, {"GET", 3}},
        {{":path", 5}, {"/", 1}},
        {{":scheme", 7}, {"https", 5}},
        {{":scheme", 7}, {"http", 4}},
    };
    CHECK_FALSE(h2_headers_to_request(scheme, 4, &req));
}

TEST(h2_request, missing_method_or_path_fails) {
    hpack::Header no_method[] = {{{":path", 5}, {"/", 1}}};
    ParsedRequest req;
    CHECK_FALSE(h2_headers_to_request(no_method, 1, &req));
    hpack::Header no_path[] = {{{":method", 7}, {"GET", 3}}};
    CHECK_FALSE(h2_headers_to_request(no_path, 1, &req));
}

TEST(h2_request, unknown_method_and_duplicates_fail) {
    hpack::Header bad_method[] = {{{":method", 7}, {"FROBNICATE", 10}}, {{":path", 5}, {"/", 1}}};
    ParsedRequest req;
    CHECK_FALSE(h2_headers_to_request(bad_method, 2, &req));
    hpack::Header dup[] = {
        {{":method", 7}, {"GET", 3}}, {{":method", 7}, {"POST", 4}}, {{":path", 5}, {"/", 1}}};
    CHECK_FALSE(h2_headers_to_request(dup, 3, &req));
}

TEST(h2_request, crlf_in_value_rejected) {
    // A CRLF in a header value would split the synthesized HTTP/1 request and
    // inject a header the routing layer never saw (RFC 7540 §10.3).
    hpack::Header inj[] = {{{":method", 7}, {"GET", 3}},
                           {{":path", 5}, {"/", 1}},
                           {{"x-evil", 6}, {"a\r\nx-admin: 1", 13}}};
    ParsedRequest req;
    CHECK_FALSE(h2_headers_to_request(inj, 3, &req));
    // Same for a CRLF smuggled into :path / :authority.
    hpack::Header bad_path[] = {{{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/a\r\nb", 5}}};
    CHECK_FALSE(h2_headers_to_request(bad_path, 2, &req));
}

TEST(h2_request, uppercase_field_name_rejected) {
    hpack::Header up[] = {
        {{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/", 1}}, {{"X-Foo", 5}, {"bar", 3}}};
    ParsedRequest req;
    CHECK_FALSE(h2_headers_to_request(up, 3, &req));
}

TEST(h2_request, connection_specific_headers_rejected) {
    ParsedRequest req;
    hpack::Header conn[] = {
        {{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/", 1}}, {{"connection", 10}, {"close", 5}}};
    CHECK_FALSE(h2_headers_to_request(conn, 3, &req));
    hpack::Header te_bad[] = {
        {{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/", 1}}, {{"te", 2}, {"gzip", 4}}};
    CHECK_FALSE(h2_headers_to_request(te_bad, 3, &req));
    // te: trailers is the one allowed value.
    hpack::Header te_ok[] = {
        {{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/", 1}}, {{"te", 2}, {"trailers", 8}}};
    CHECK(h2_headers_to_request(te_ok, 3, &req));
}

TEST(h2_request, pseudo_header_after_regular_rejected) {
    hpack::Header bad[] = {
        {{":method", 7}, {"GET", 3}}, {{"accept", 6}, {"*/*", 3}}, {{":path", 5}, {"/", 1}}};
    ParsedRequest req;
    CHECK_FALSE(h2_headers_to_request(bad, 3, &req));
}

TEST(h2_request, unknown_pseudo_header_rejected) {
    hpack::Header bad[] = {
        {{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/", 1}}, {{":status", 7}, {"200", 3}}};
    ParsedRequest req;
    CHECK_FALSE(h2_headers_to_request(bad, 3, &req));
}

TEST(h2_proxy_forwardable, accepts_well_formed_request) {
    hpack::Header ok[] = {{{":method", 7}, {"GET", 3}},
                          {{":scheme", 7}, {"http", 4}},
                          {{":path", 5}, {"/", 1}},
                          {{":authority", 10}, {"x", 1}}};
    CHECK(h2_proxy_request_forwardable(ok, 4));
}

TEST(h2_proxy_forwardable, rejects_missing_scheme) {
    // :method + :path + :authority but no :scheme — fine for a local handler,
    // malformed to forward upstream.
    hpack::Header no_scheme[] = {
        {{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/", 1}}, {{":authority", 10}, {"x", 1}}};
    CHECK_FALSE(h2_proxy_request_forwardable(no_scheme, 3));
}

TEST(h2_proxy_forwardable, rejects_ambiguous_host_without_authority) {
    // No :authority and two regular host fields would synthesize duplicate Host
    // headers upstream.
    hpack::Header dup_host[] = {{{":method", 7}, {"GET", 3}},
                                {{":scheme", 7}, {"http", 4}},
                                {{":path", 5}, {"/", 1}},
                                {{"host", 4}, {"a", 1}},
                                {{"host", 4}, {"b", 1}}};
    CHECK_FALSE(h2_proxy_request_forwardable(dup_host, 5));
    // A single host field (no authority) is unambiguous.
    CHECK(h2_proxy_request_forwardable(dup_host, 4));
    // With :authority, regular host fields are dropped by synth → not ambiguous.
    hpack::Header auth_plus_host[] = {{{":method", 7}, {"GET", 3}},
                                      {{":scheme", 7}, {"http", 4}},
                                      {{":path", 5}, {"/", 1}},
                                      {{":authority", 10}, {"x", 1}},
                                      {{"host", 4}, {"a", 1}},
                                      {{"host", 4}, {"b", 1}}};
    CHECK(h2_proxy_request_forwardable(auth_plus_host, 6));
}

TEST(h2_proxy_forwardable, rejects_missing_host_without_authority) {
    hpack::Header no_host[] = {
        {{":method", 7}, {"GET", 3}}, {{":scheme", 7}, {"http", 4}}, {{":path", 5}, {"/", 1}}};
    CHECK_FALSE(h2_proxy_request_forwardable(no_host, 3));

    hpack::Header empty_authority[] = {{{":method", 7}, {"GET", 3}},
                                       {{":scheme", 7}, {"http", 4}},
                                       {{":path", 5}, {"/", 1}},
                                       {{":authority", 10}, {"", 0}}};
    CHECK_FALSE(h2_proxy_request_forwardable(empty_authority, 4));

    hpack::Header empty_authority_with_host[] = {{{":method", 7}, {"GET", 3}},
                                                 {{":scheme", 7}, {"http", 4}},
                                                 {{":path", 5}, {"/", 1}},
                                                 {{":authority", 10}, {"", 0}},
                                                 {{"host", 4}, {"x", 1}}};
    CHECK(h2_proxy_request_forwardable(empty_authority_with_host, 5));
}

// Write a raw frame (header + payload) into out; return bytes written.
namespace {
u32 put_frame(u8* out, Http2FrameType type, u8 flags, u32 stream_id, const u8* payload, u32 plen) {
    Http2FrameHeader h;
    h.length = plen;
    h.type = static_cast<u8>(type);
    h.flags = flags;
    h.stream_id = stream_id;
    write_frame_header(out, h);
    for (u32 i = 0; i < plen; i++) out[kFrameHeaderSize + i] = payload[i];
    return kFrameHeaderSize + plen;
}
}  // namespace

TEST(http2_conn, padded_data_frame) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    hpack::Header hs[] = {{{":method", 7}, {"POST", 4}}, {{":path", 5}, {"/", 1}}};
    u8 frame[256];
    u32 fn = http2_write_headers(frame, sizeof(frame), 1, hs, 2, false);
    // PADDED DATA: [padlen=3]["hi"][3 pad bytes], END_STREAM.
    const u8 kPayload[] = {3, 'h', 'i', 0, 0, 0};
    fn += put_frame(frame + fn,
                    Http2FrameType::Data,
                    http2_flag::kPadded | http2_flag::kEndStream,
                    1,
                    kPayload,
                    sizeof(kPayload));
    u8 in[384];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_FALSE(r.close);
    CHECK_EQ(cap.data_len, 2u);  // padding stripped
    CHECK_EQ(cap.data[0], 'h');
}

TEST(http2_conn, headers_with_priority_flag) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    // HEADERS with PRIORITY: 5 priority octets precede the block fragment.
    u8 block[64];
    block[0] = 0;  // exclusive(1)+stream dep(31)
    block[1] = 0;
    block[2] = 0;
    block[3] = 0;
    block[4] = 15;    // weight
    block[5] = 0x82;  // :method GET
    u8 frame[128];
    u32 fn = put_frame(frame,
                       Http2FrameType::Headers,
                       http2_flag::kEndHeaders | http2_flag::kPriority | http2_flag::kEndStream,
                       1,
                       block,
                       6);
    u8 in[128];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_FALSE(r.close);
    CHECK_EQ(cap.headers_calls, 1u);
    CHECK(name_is(cap, 0, ":method"));
}

TEST(http2_conn, window_update_zero_increment) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    // Connection-level WINDOW_UPDATE with increment 0 → PROTOCOL_ERROR GOAWAY.
    const u8 kZero[4] = {0, 0, 0, 0};
    u8 frame[64];
    u32 fn = put_frame(frame, Http2FrameType::WindowUpdate, 0, 0, kZero, 4);
    u8 in[64];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::Goaway, 0, 0));
}

TEST(http2_conn, settings_initial_window_adjusts_streams) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    hpack::Header hs[] = {{{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/", 1}}};
    u8 frame[256];
    u32 fn = http2_write_headers(frame, sizeof(frame), 1, hs, 2, false);
    // SETTINGS raising INITIAL_WINDOW_SIZE to 100000.
    Http2Settings s;
    s.set_defaults();
    s.initial_window_size = 100000;
    fn += write_settings_frame(frame + fn, s);
    u8 in[384];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    c.process(in, inlen, out, sizeof(out), &ow);
    Http2Stream* st = c.find_stream(1);
    REQUIRE(st != nullptr);
    // 65535 default + (100000 - 65535) delta.
    CHECK_EQ(st->send_window, 100000);
}

TEST(http2_conn, oversized_frame_goaway) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    // Frame header claiming a length above the default max frame size (16384):
    // process rejects on the header alone, before any payload.
    u8 fh[kFrameHeaderSize];
    Http2FrameHeader h;
    h.length = 16385;
    h.type = static_cast<u8>(Http2FrameType::Data);
    h.flags = 0;
    h.stream_id = 1;
    write_frame_header(fh, h);
    u8 in[64];
    u32 inlen = with_preface(in, fh, sizeof(fh));
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::Goaway, 0, 0));
}

TEST(http2_conn, unknown_frame_type_ignored) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    const u8 kBody[] = {1, 2, 3};
    u8 frame[64];
    u32 fn = put_frame(frame, static_cast<Http2FrameType>(0xfa), 0, 0, kBody, sizeof(kBody));
    u8 in[64];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_FALSE(r.close);
    CHECK_EQ(r.consumed, inlen);  // unknown frame consumed, no error
}

TEST(http2_conn, ping_bad_length_goaway) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    const u8 kShort[4] = {0, 0, 0, 0};  // PING must be 8 octets
    u8 frame[64];
    u32 fn = put_frame(frame, Http2FrameType::Ping, 0, 0, kShort, 4);
    u8 in[64];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::Goaway, 0, 0));
}

TEST(http2_conn, data_on_stream_zero_protocol_error) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    const u8 kData[] = {'x'};
    u8 frame[64];
    u32 fn = put_frame(frame, Http2FrameType::Data, 0, 0, kData, 1);
    u8 in[64];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::Goaway, 0, 0));
}

TEST(http2_conn, settings_ack_ignored) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    u8 frame[64];
    u32 fn = put_frame(frame, Http2FrameType::Settings, http2_flag::kAck, 0, nullptr, 0);
    u8 in[64];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_FALSE(r.close);
    CHECK_EQ(r.consumed, inlen);
}

TEST(http2_conn, settings_ack_with_payload_goaway) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    const u8 kPayload[6] = {0, 4, 0, 0, 0, 0};  // ACK must be empty
    u8 frame[64];
    u32 fn = put_frame(frame, Http2FrameType::Settings, http2_flag::kAck, 0, kPayload, 6);
    u8 in[64];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::Goaway, 0, 0));
}

TEST(http2_conn, settings_invalid_value_goaway) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    const u8 kPayload[6] = {0, 0x02, 0, 0, 0, 0x02};  // ENABLE_PUSH=2 (invalid)
    u8 frame[64];
    u32 fn = put_frame(frame, Http2FrameType::Settings, 0, 0, kPayload, 6);
    u8 in[64];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::Goaway, 0, 0));
}

TEST(http2_conn, headers_on_stream_zero_goaway) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    const u8 kBlock[1] = {0x82};
    u8 frame[64];
    u32 fn = put_frame(frame,
                       Http2FrameType::Headers,
                       http2_flag::kEndHeaders | http2_flag::kEndStream,
                       0,
                       kBlock,
                       1);
    u8 in[64];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::Goaway, 0, 0));
}

TEST(http2_conn, continuation_wrong_stream_goaway) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    const u8 kBlock[1] = {0x82};
    u8 frame[64];
    // HEADERS on stream 1 without END_HEADERS, then CONTINUATION on stream 3.
    u32 fn = put_frame(frame, Http2FrameType::Headers, 0, 1, kBlock, 1);
    fn +=
        put_frame(frame + fn, Http2FrameType::Continuation, http2_flag::kEndHeaders, 3, kBlock, 1);
    u8 in[128];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::Goaway, 0, 0));
}

TEST(http2_conn, stray_continuation_goaway) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    // A CONTINUATION with no HEADERS awaiting assembly is a connection error.
    const u8 kBlock[1] = {0x82};
    u8 frame[64];
    u32 fn = put_frame(frame, Http2FrameType::Continuation, http2_flag::kEndHeaders, 1, kBlock, 1);
    u8 in[128];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::Goaway, 0, 0));
}

TEST(http2_conn, window_update_on_idle_stream_goaway) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    // WINDOW_UPDATE on stream 5 before it is ever opened (idle) → PROTOCOL_ERROR.
    u8 frame[64];
    u32 fn = write_window_update(frame, 5, 1000);
    u8 in[128];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::Goaway, 0, 0));
}

TEST(http2_conn, goaway_from_peer_drains) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    const u8 kPayload[8] = {0, 0, 0, 0, 0, 0, 0, 0};  // last_stream_id=0, NO_ERROR
    u8 frame[64];
    u32 fn = put_frame(frame, Http2FrameType::Goaway, 0, 0, kPayload, 8);
    u8 in[64];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_FALSE(r.close);  // peer GOAWAY is not our error; loop drains normally
    CHECK_EQ(r.consumed, inlen);
}

TEST(http2_conn, rst_stream_on_stream_zero_goaway) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    const u8 kErr[4] = {0, 0, 0, 8};  // CANCEL on stream 0 (illegal)
    u8 frame[64];
    u32 fn = put_frame(frame, Http2FrameType::RstStream, 0, 0, kErr, 4);
    u8 in[64];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::Goaway, 0, 0));
}

TEST(http2_conn, window_update_overflow_rsts_stream) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    hpack::Header hs[] = {{{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/", 1}}};
    u8 frame[256];
    u32 fn = http2_write_headers(frame, sizeof(frame), 1, hs, 2, false);
    // Increment that pushes the stream window past 2^31-1 → FLOW_CONTROL_ERROR.
    const u8 kBig[4] = {0x7f, 0xff, 0xff, 0xff};
    fn += put_frame(frame + fn, Http2FrameType::WindowUpdate, 0, 1, kBig, 4);
    u8 in[384];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_FALSE(r.close);  // stream-level error, connection survives
    CHECK(has_frame(out, ow, Http2FrameType::RstStream, 0, 0));
}

TEST(http2_conn, write_response_with_body_and_headers) {
    hpack::Encoder enc;
    enc.init(4096);
    const hpack::Header hdrs[] = {{{"content-type", 12}, {"text/plain", 10}}};
    u8 out[256];
    u32 n = http2_write_response(
        out, sizeof(out), enc, 1, 200, hdrs, 1, reinterpret_cast<const u8*>("hi"), 2);
    // Decode the HEADERS frame and confirm :status, the header, content-length.
    Http2FrameHeader h;
    REQUIRE(parse_frame_header(out, n, &h) == ParseStatus::Complete);
    CHECK_EQ(h.type, static_cast<u8>(Http2FrameType::Headers));
    CHECK((h.flags & http2_flag::kEndStream) == 0);  // body follows
    hpack::DynamicTable dyn;
    dyn.init(4096);
    hpack::Header dh[16];
    u8 scratch[256];
    u32 dn = 0;
    REQUIRE(hpack::decode_header_block(
        dyn, out + kFrameHeaderSize, h.length, scratch, sizeof(scratch), dh, 16, &dn));
    bool has_status = false, has_ct = false, has_cl = false;
    for (u32 i = 0; i < dn; i++) {
        if (dh[i].name.eq(Str{":status", 7}) && dh[i].value.eq(Str{"200", 3})) has_status = true;
        if (dh[i].name.eq(Str{"content-type", 12})) has_ct = true;
        if (dh[i].name.eq(Str{"content-length", 14}) && dh[i].value.eq(Str{"2", 1})) has_cl = true;
    }
    CHECK(has_status);
    CHECK(has_ct);
    CHECK(has_cl);
    // The trailing DATA frame carries the body with END_STREAM.
    Http2FrameHeader df;
    parse_frame_header(out + kFrameHeaderSize + h.length, n - kFrameHeaderSize - h.length, &df);
    CHECK_EQ(df.type, static_cast<u8>(Http2FrameType::Data));
    CHECK((df.flags & http2_flag::kEndStream) != 0);
}

// http2_write_response must refuse (return 0) rather than overflow its fixed 8 KiB
// HPACK scratch when the (untrusted, upstream-forwarded) header block is too large.
// The bound is on raw name+value lengths, so it rejects conservatively regardless
// of Huffman — the proxy turns a 0 return into a 502 instead of smashing the stack.
TEST(http2_conn, write_response_rejects_oversized_headers) {
    hpack::Encoder enc;
    enc.init(4096);
    static char val[600];
    for (char& c : val) c = 'a';
    constexpr u32 kN = 40;  // 40 * 600 = 24 KiB raw; even best-case (~5-bit) Huffman
                            // exceeds the 8 KiB hblock, so the bound must trip.
    char names[kN][5];
    hpack::Header hdrs[kN];
    for (u32 i = 0; i < kN; i++) {
        names[i][0] = 'x';
        names[i][1] = '-';
        names[i][2] = static_cast<char>('a' + i / 10);
        names[i][3] = static_cast<char>('a' + i % 10);
        hdrs[i].name = Str{names[i], 4};
        hdrs[i].value = Str{val, sizeof(val)};
    }
    u8 out[32768];
    u32 n = http2_write_response(out, sizeof(out), enc, 1, 200, hdrs, kN, nullptr, 0);
    CHECK_EQ(n, 0u);  // refused, not overflowed
}

// A header name too long to lowercase in http2_write_response's stack buffer must
// be rejected (return 0 → the proxy answers 502) if it contains uppercase, rather
// than forwarding an invalid uppercase HTTP/2 name. An all-lowercase long name is
// still forwarded.
TEST(http2_conn, write_response_rejects_long_uppercase_name) {
    static char longname[300];
    for (char& c : longname) c = 'x';
    const char val[] = "v";
    // All-lowercase long name: accepted (non-zero).
    {
        hpack::Encoder enc;
        enc.init(4096);
        const hpack::Header hdrs[] = {{{longname, sizeof(longname)}, {val, 1}}};
        u8 out[1024];
        u32 n = http2_write_response(out, sizeof(out), enc, 1, 200, hdrs, 1, nullptr, 0);
        CHECK(n != 0u);
    }
    // One uppercase byte in the over-long name: rejected (0).
    {
        longname[100] = 'X';
        hpack::Encoder enc;
        enc.init(4096);
        const hpack::Header hdrs[] = {{{longname, sizeof(longname)}, {val, 1}}};
        u8 out[1024];
        u32 n = http2_write_response(out, sizeof(out), enc, 1, 200, hdrs, 1, nullptr, 0);
        CHECK_EQ(n, 0u);
    }
}

// The h2 response path must drop connection-specific (hop-by-hop) header names a
// route can still carry from response(headers:) — validate_response_header only
// blocks Connection/Transfer-Encoding/Content-Length, so keep-alive / upgrade /
// proxy-connection / te would otherwise emit an h2-illegal field.
TEST(http2_conn, prohibited_response_header_filter) {
    using namespace rut;
    CHECK(h2_is_prohibited_response_header("connection", 10));
    CHECK(h2_is_prohibited_response_header("Keep-Alive", 10));  // case-insensitive
    CHECK(h2_is_prohibited_response_header("proxy-connection", 16));
    CHECK(h2_is_prohibited_response_header("transfer-encoding", 17));
    CHECK(h2_is_prohibited_response_header("Upgrade", 7));
    CHECK(h2_is_prohibited_response_header("te", 2));
    // Ordinary headers pass through.
    CHECK(!h2_is_prohibited_response_header("content-type", 12));
    CHECK(!h2_is_prohibited_response_header("x-custom", 8));
    CHECK(!h2_is_prohibited_response_header("cache-control", 13));
}

// Open stream 1 (HEADERS without END_STREAM) and return the conn/cap ready for
// more frames. Helper to reduce boilerplate in the branch tests below.
namespace {
u32 open_stream1(u8* frame, u32 cap) {
    const hpack::Header hs[] = {{{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/", 1}}};
    return http2_write_headers(frame, cap, 1, hs, 2, /*end_stream=*/false);
}
}  // namespace

TEST(http2_conn, priority_frame_ignored) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    const u8 kPrio[5] = {0, 0, 0, 0, 16};
    u8 frame[64];
    u32 fn = put_frame(frame, Http2FrameType::Priority, 0, 1, kPrio, 5);
    u8 in[64];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_FALSE(r.close);
    CHECK_EQ(r.consumed, inlen);
}

TEST(http2_conn, connection_window_update_accepted) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    const u8 kInc[4] = {0, 0, 0x10, 0};  // +4096 on the connection
    u8 frame[64];
    u32 fn = put_frame(frame, Http2FrameType::WindowUpdate, 0, 0, kInc, 4);
    u8 in[64];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_FALSE(r.close);
    CHECK_EQ(c.conn_send_window, static_cast<i64>(kDefaultInitialWindowSize) + 4096);
}

TEST(http2_conn, stream_window_update_zero_rsts) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    u8 frame[256];
    u32 fn = open_stream1(frame, sizeof(frame));
    const u8 kZero[4] = {0, 0, 0, 0};
    fn += put_frame(frame + fn, Http2FrameType::WindowUpdate, 0, 1, kZero, 4);
    u8 in[384];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_FALSE(r.close);  // stream-level error
    CHECK(has_frame(out, ow, Http2FrameType::RstStream, 0, 0));
}

TEST(http2_conn, data_without_end_stream_replenishes_stream_window) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    u8 frame[256];
    u32 fn = open_stream1(frame, sizeof(frame));
    fn +=
        http2_write_data(frame + fn, 1, reinterpret_cast<const u8*>("ab"), 2, /*end_stream=*/false);
    u8 in[384];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_EQ(cap.data_len, 2u);
    CHECK_FALSE(cap.data_end);
    // Both connection- and stream-level WINDOW_UPDATE replenish the 2 octets.
    u32 wu = 0;
    u32 pos = 0;
    while (pos + kFrameHeaderSize <= ow) {
        Http2FrameHeader h;
        parse_frame_header(out + pos, ow - pos, &h);
        if (h.type == static_cast<u8>(Http2FrameType::WindowUpdate)) wu++;
        pos += kFrameHeaderSize + h.length;
    }
    CHECK_GE(wu, 2u);
}

TEST(http2_conn, data_on_half_closed_stream_rsts) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    // HEADERS with END_STREAM half-closes the stream; a following DATA is illegal.
    const hpack::Header hs[] = {{{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/", 1}}};
    u8 frame[256];
    u32 fn = http2_write_headers(frame, sizeof(frame), 1, hs, 2, /*end_stream=*/true);
    fn += http2_write_data(frame + fn, 1, reinterpret_cast<const u8*>("x"), 1, /*end_stream=*/true);
    u8 in[384];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_FALSE(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::RstStream, 0, 0));
}

TEST(http2_conn, repeated_headers_on_open_stream_rsts) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    hpack::Header hs[] = {{{":method", 7}, {"POST", 4}}, {{":path", 5}, {"/", 1}}};
    u8 frame[512];
    u32 fn = http2_write_headers(frame, sizeof(frame), 1, hs, 2, /*end_stream=*/false);
    fn += http2_write_headers(frame + fn, sizeof(frame) - fn, 1, hs, 2, /*end_stream=*/true);
    u8 in[640];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_FALSE(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::RstStream, 0, 0));
    CHECK(c.find_stream(1) == nullptr);
}

TEST(http2_conn, duplicate_headers_block_is_decoded_before_reset) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);

    u8 frame[1024];
    const hpack::Header open[] = {{{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/", 1}}};
    u32 fn = http2_write_headers(frame, sizeof(frame), 1, open, 2, /*end_stream=*/false);

    hpack::Encoder enc;
    enc.init(4096);
    u8 dup_block[128];
    u32 dup_len = 0;
    dup_len += enc.encode(dup_block + dup_len, Str{"x-seen", 6}, Str{"v", 1});
    fn += put_frame(
        frame + fn, Http2FrameType::Headers, http2_flag::kEndHeaders, 1, dup_block, dup_len);

    u8 next_block[256];
    u32 next_len = 0;
    next_len += enc.encode(next_block + next_len, Str{":method", 7}, Str{"GET", 3});
    next_len += enc.encode(next_block + next_len, Str{":path", 5}, Str{"/", 1});
    next_len += enc.encode(next_block + next_len, Str{"x-seen", 6}, Str{"v", 1});
    fn += put_frame(frame + fn,
                    Http2FrameType::Headers,
                    http2_flag::kEndHeaders | http2_flag::kEndStream,
                    3,
                    next_block,
                    next_len);

    u8 in[1200];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[512];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_FALSE(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::RstStream, 0, 0));
    CHECK_EQ(cap.headers_calls, 2u);
    CHECK_EQ(cap.last_stream, 3u);
}

TEST(http2_conn, request_trailers_finalize_instead_of_rst) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);

    // POST with a body (no END_STREAM) followed by a DATA frame (no END_STREAM).
    hpack::Header hs[] = {{{":method", 7}, {"POST", 4}}, {{":path", 5}, {"/up", 3}}};
    u8 frame[512];
    u32 fn = http2_write_headers(frame, sizeof(frame), 1, hs, 2, /*end_stream=*/false);
    fn += http2_write_data(
        frame + fn, 1, reinterpret_cast<const u8*>("hello"), 5, /*end_stream=*/false);
    u8 in[640];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_FALSE(r.close);
    CHECK_EQ(cap.data_calls, 1u);
    CHECK_FALSE(cap.data_end);

    // The serving layer would have deferred this upload.
    c.pending_stream = 1;
    c.pending_request_forwardable = true;

    // Trailing HEADERS: END_STREAM, no pseudo-headers → valid request trailers.
    hpack::Header tr[] = {{{"x-checksum", 10}, {"ok", 2}}};
    u8 tframe[128];
    u32 tn = http2_write_headers(tframe, sizeof(tframe), 1, tr, 1, /*end_stream=*/true);
    u8 tout[128];
    u32 tow = 0;
    Http2Result r2 = c.process(tframe, tn, tout, sizeof(tout), &tow);
    CHECK_FALSE(r2.close);
    CHECK_FALSE(has_frame(tout, tow, Http2FrameType::RstStream, 0, 0));  // not reset
    CHECK_EQ(cap.data_calls, 2u);  // end-of-stream delivered to finalize the upload
    CHECK(cap.data_end);
    CHECK_FALSE(c.pending_request_forwardable);  // buffered forwarding must reject lost trailers
    Http2Stream* s = c.find_stream(1);
    REQUIRE(s != nullptr);
    CHECK(s->state == Http2StreamState::HalfClosedRemote);
}

TEST(http2_conn, trailing_header_block_with_pseudo_header_rsts) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    hpack::Header hs[] = {{{":method", 7}, {"POST", 4}}, {{":path", 5}, {"/up", 3}}};
    u8 frame[512];
    u32 fn = http2_write_headers(frame, sizeof(frame), 1, hs, 2, /*end_stream=*/false);
    u8 in[640];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    c.process(in, inlen, out, sizeof(out), &ow);

    ShardMetrics metrics;
    metrics.init();
    metrics.on_request_start();
    c.metrics = &metrics;
    Http2Stream* stream = c.find_stream(1);
    REQUIRE(stream != nullptr);
    stream->metrics_started = true;
    stream->request_start_us = monotonic_us();
    c.on_reset = &h2_on_reset_cb;

    // END_STREAM is set, but a pseudo-header (:path) disqualifies it as trailers
    // (RFC 7540 §8.1.2.1) → reset rather than finalize.
    hpack::Header bad[] = {{{":path", 5}, {"/x", 2}}, {{"x-t", 3}, {"1", 1}}};
    u8 bframe[128];
    u32 bn = http2_write_headers(bframe, sizeof(bframe), 1, bad, 2, /*end_stream=*/true);
    u8 bout[128];
    u32 bow = 0;
    c.process(bframe, bn, bout, sizeof(bout), &bow);
    CHECK(has_frame(bout, bow, Http2FrameType::RstStream, 0, 0));
    CHECK_EQ(metrics.requests_active, 0u);
    CHECK_FALSE(stream->metrics_started);
}

TEST(h2_serving, finalizes_body_without_injecting_content_length) {
    Http2Conn h2;
    h2.init();
    const char* req = "POST /u HTTP/1.1\r\nhost: x\r\n\r\nabc";
    u32 len = 0;
    while (req[len]) {
        h2.pending_synth[len] = static_cast<u8>(req[len]);
        len++;
    }
    h2.pending_body_start = len - 3;
    h2.pending_synth_len = len;
    h2.pending_body_len = 3;
    REQUIRE(h2_finalize_synth_body(h2));
    ParsedRequest parsed;
    HttpParser parser;
    parser.reset();
    CHECK(parser.parse(h2.pending_synth, h2.pending_synth_len, &parsed) == ParseStatus::Complete);
    CHECK_FALSE(parsed.has_content_length);
}

TEST(h2_serving, body_content_length_mismatch_fails) {
    Http2Conn h2;
    h2.init();
    const char* req = "POST /u HTTP/1.1\r\ncontent-length: 4\r\n\r\nabc";
    u32 len = 0;
    while (req[len]) {
        h2.pending_synth[len] = static_cast<u8>(req[len]);
        len++;
    }
    h2.pending_body_start = len - 3;
    h2.pending_synth_len = len;
    h2.pending_body_len = 3;
    h2.pending_content_length = 4;
    h2.pending_has_content_length = true;
    CHECK_FALSE(h2_finalize_synth_body(h2));
}

TEST(h2_serving, inject_content_length_exposes_data_only_body) {
    // A DATA-only h2 body (client omitted content-length) is buffered as raw
    // bytes after the synthesized headers; injecting content-length must make
    // the HTTP/1-shaped parse expose exactly those bytes as the body.
    u8 buf[256];
    const char* req = "POST /u HTTP/1.1\r\nhost: x\r\n\r\nabcde";
    u32 len = 0;
    while (req[len]) {
        buf[len] = static_cast<u8>(req[len]);
        len++;
    }
    const u32 kBodyStart = len - 5;  // just past "\r\n\r\n"
    REQUIRE(h2_inject_content_length(buf, &len, kBodyStart, 5, sizeof(buf)));

    ParsedRequest parsed;
    HttpParser parser;
    parser.reset();
    CHECK(parser.parse(buf, len, &parsed) == ParseStatus::Complete);
    CHECK(parsed.has_content_length);
    CHECK_EQ(parsed.content_length, 5u);
    // The 5 body octets must be the final bytes, intact, after injection.
    CHECK(Str(reinterpret_cast<const char*>(buf + len - 5), 5).eq(Str{"abcde", 5}));
}

TEST(h2_serving, inject_content_length_zero_length_body) {
    u8 buf[128];
    const char* req = "POST /u HTTP/1.1\r\nhost: x\r\n\r\n";
    u32 len = 0;
    while (req[len]) {
        buf[len] = static_cast<u8>(req[len]);
        len++;
    }
    REQUIRE(h2_inject_content_length(buf, &len, len, 0, sizeof(buf)));
    ParsedRequest parsed;
    HttpParser parser;
    parser.reset();
    CHECK(parser.parse(buf, len, &parsed) == ParseStatus::Complete);
    CHECK(parsed.has_content_length);
    CHECK_EQ(parsed.content_length, 0u);
}

TEST(h2_serving, inject_content_length_rejects_overflow) {
    u8 buf[40];
    const char* req = "POST /u HTTP/1.1\r\nhost: x\r\n\r\nab";
    u32 len = 0;
    while (req[len]) {
        buf[len] = static_cast<u8>(req[len]);
        len++;
    }
    // Buffer too small to fit the injected "content-length: 2\r\n" line.
    CHECK_FALSE(h2_inject_content_length(buf, &len, len - 2, 2, sizeof(buf)));
}

namespace {
struct FakeH2Loop {
    bool yield_scheduled = false;
    u32 yield_ms = 0;
    ShardMetrics* metrics = nullptr;

    void epoch_enter() {}
    void epoch_leave() {}

    [[nodiscard]] bool schedule_yield_timer(Connection&, u32 ms) {
        yield_scheduled = true;
        yield_ms = ms;
        return true;
    }
};

u64 h2_mutated_body_then_forward(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    ctx->response_body_mutation_storage = jit::acquire_response_body_mutation_storage();
    ctx->response_body_mutation_set = true;
    ctx->response_body_mutation_len = 1;
    return jit::HandlerResult::make_forward(0).pack();
}

u64 h2_mutated_body_then_timer(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    ctx->response_body_mutation_storage = jit::acquire_response_body_mutation_storage();
    ctx->response_body_mutation_set = true;
    ctx->response_body_mutation_len = 1;
    return jit::HandlerResult::make_yield_payload(1, jit::YieldKind::Timer, 1).pack();
}

u64 h2_status_204(void*, jit::HandlerCtx*, const u8*, u32, void*) {
    return jit::HandlerResult::make_status(204).pack();
}

u32 h2_buffered_forward_calls = 0;
u64 h2_buffered_forward(void*, jit::HandlerCtx*, const u8*, u32, void*) {
    h2_buffered_forward_calls++;
    return jit::HandlerResult::make_buffered_forward(0).pack();
}

u32 h2_buffered_timer_calls = 0;
u64 h2_buffered_timer(void*, jit::HandlerCtx*, const u8*, u32, void*) {
    h2_buffered_timer_calls++;
    return jit::HandlerResult::make_yield_payload(7, jit::YieldKind::Timer, 25).pack();
}

bool h2_handler_saw_content_length = false;
u64 h2_observe_absent_content_length(void*, jit::HandlerCtx*, const u8* req, u32 len, void*) {
    static constexpr char kNeedle[] = "content-length:";
    h2_handler_saw_content_length = false;
    for (u32 i = 0; i + sizeof(kNeedle) - 1 <= len; i++) {
        bool match = true;
        for (u32 j = 0; j < sizeof(kNeedle) - 1; j++)
            match &= req[i + j] == static_cast<u8>(kNeedle[j]);
        if (match) h2_handler_saw_content_length = true;
    }
    return jit::HandlerResult::make_status(204).pack();
}
}  // namespace

TEST(h2_serving, response_status_body_rules_include_reset_content) {
    CHECK(h2_response_status_forbids_body(199));
    CHECK(h2_response_status_forbids_body(204));
    CHECK(h2_response_status_forbids_body(205));
    CHECK(h2_response_status_forbids_body(304));
    CHECK_FALSE(h2_response_status_forbids_body(200));
    CHECK_FALSE(h2_response_status_forbids_body(206));
}

TEST(h2_serving, body_independent_local_branch_avoids_buffered_forward_cap) {
    const hpack::Header headers[] = {{{":method", 7}, {"POST", 4}},
                                     {{":path", 5}, {"/upload", 7}},
                                     {{":scheme", 7}, {"https", 5}},
                                     {{":authority", 10}, {"example", 7}}};
    Http2Conn h2;
    h2.init();
    Connection conn;
    conn.reset();
    conn.h2 = &h2;
    RouteConfig config;
    REQUIRE(config.add_jit_handler("/upload",
                                   kRouteMethodPost,
                                   &h2_status_204,
                                   /*needs_req_body=*/false,
                                   /*needs_control_plane_snapshot=*/false,
                                   /*can_forward_buffered=*/true));
    conn.request_config = &config;
    FakeH2Loop loop;
    u8 response[512]{};
    H2Dispatch<FakeH2Loop> dispatch{&loop, &conn, response, sizeof(response), 0, false};

    h2_dispatch_request(dispatch, 1, headers, 4, /*end_stream=*/false);
    CHECK_EQ(h2.pending_stream, 0u);
    CHECK_GT(dispatch.resp_len, 0u);
}

TEST(h2_serving, selected_buffered_forward_defers_and_buffers_data) {
    const hpack::Header headers[] = {{{":method", 7}, {"POST", 4}},
                                     {{":path", 5}, {"/upload", 7}},
                                     {{":scheme", 7}, {"https", 5}},
                                     {{":authority", 10}, {"example", 7}}};
    Http2Conn h2;
    h2.init();
    Connection conn;
    conn.reset();
    conn.h2 = &h2;
    RouteConfig config;
    REQUIRE(config.add_jit_handler("/upload",
                                   kRouteMethodPost,
                                   &h2_buffered_forward,
                                   /*needs_req_body=*/false,
                                   /*needs_control_plane_snapshot=*/false,
                                   /*can_forward_buffered=*/true));
    conn.request_config = &config;
    FakeH2Loop loop;
    u8 response[512]{};
    H2Dispatch<FakeH2Loop> dispatch{&loop, &conn, response, sizeof(response), 0, false};

    h2_buffered_forward_calls = 0;
    h2_dispatch_request(dispatch, 1, headers, 4, /*end_stream=*/false);
    CHECK_EQ(h2.pending_stream, 1u);
    CHECK(h2.pending_buffer_body);
    CHECK(h2.pending_preinvoked_forward);
    CHECK_EQ(h2_buffered_forward_calls, 1u);
    CHECK_EQ(dispatch.resp_len, 0u);

    static const u8 kBody[] = {'a', 'b', 'c'};
    h2_on_data_cb<FakeH2Loop>(&dispatch, h2, 1, kBody, sizeof(kBody), true);
    CHECK_EQ(h2_buffered_forward_calls, 1u);
    CHECK_EQ(h2.pending_stream, 0u);
    CHECK_EQ(h2.async_stream, 1u);
    CHECK_EQ(h2.async_kind, H2AsyncKind::Proxy);
    CHECK(h2.async_apply_response_mutations);
    h2_clear_async(h2);
}

TEST(h2_serving, body_independent_timer_starts_before_upload_completion) {
    const hpack::Header headers[] = {{{":method", 7}, {"POST", 4}},
                                     {{":path", 5}, {"/upload", 7}},
                                     {{":scheme", 7}, {"https", 5}},
                                     {{":authority", 10}, {"example", 7}}};
    Http2Conn h2;
    h2.init();
    Connection conn;
    conn.reset();
    conn.h2 = &h2;
    RouteConfig config;
    REQUIRE(config.add_jit_handler("/upload",
                                   kRouteMethodPost,
                                   &h2_buffered_timer,
                                   /*needs_req_body=*/false,
                                   /*needs_control_plane_snapshot=*/false,
                                   /*can_forward_buffered=*/true));
    conn.request_config = &config;
    FakeH2Loop loop;
    u8 response[512]{};
    H2Dispatch<FakeH2Loop> dispatch{&loop, &conn, response, sizeof(response), 0, false};

    h2_buffered_timer_calls = 0;
    h2_dispatch_request(dispatch, 1, headers, 4, /*end_stream=*/false);
    CHECK_EQ(h2_buffered_timer_calls, 1u);
    CHECK_EQ(h2.pending_stream, 0u);
    CHECK_EQ(h2.async_stream, 1u);
    CHECK_EQ(h2.async_kind, H2AsyncKind::Timer);
    CHECK_EQ(h2.async_state, 7u);
    CHECK_EQ(h2.async_timer_ms, 25u);
    CHECK_EQ(h2.async_body_len, 0u);
    CHECK(h2.async_inject_content_length_on_forward);
    CHECK(h2.async_wait_for_body_on_forward);
    h2_clear_async(h2);
}

TEST(h2_serving, resumed_timer_defers_body_only_after_selecting_buffered_forward) {
    Http2Conn h2;
    h2.init();
    RouteConfig config;
    RouteEntry route{};
    route.action = RouteAction::JitHandler;
    route.fn = &h2_buffered_timer;
    static constexpr char kSynth[] = "POST /upload HTTP/1.1\r\nhost: example\r\n\r\n";
    for (u32 i = 0; i < sizeof(kSynth) - 1; i++) h2.pending_synth[i] = static_cast<u8>(kSynth[i]);
    h2.async_stream = 1;
    h2.async_kind = H2AsyncKind::Timer;
    h2.async_cfg = &config;
    h2.async_route = &route;
    h2.async_fn = route.fn;
    h2.async_synth_len = sizeof(kSynth) - 1;
    h2.async_body_start = sizeof(kSynth) - 1;
    h2.async_wait_for_body_on_forward = true;

    h2_transfer_timer_to_pending_forward(h2, 1, 7);

    CHECK_EQ(h2.async_stream, 0u);
    CHECK_EQ(h2.pending_stream, 1u);
    CHECK(h2.pending_buffer_body);
    CHECK(h2.pending_preinvoked_forward);
    CHECK_EQ(h2.pending_forward_upstream_id, 7u);
    CHECK_EQ(h2.pending_synth_len, sizeof(kSynth) - 1);
    CHECK_EQ(h2.pending_body_start, sizeof(kSynth) - 1);
    CHECK(h2.pending_route == &route);
    h2_clear_pending(h2);
}

TEST(h2_serving, body_independent_preinvoke_preserves_declared_length_validation) {
    const hpack::Header headers[] = {{{":method", 7}, {"POST", 4}},
                                     {{":path", 5}, {"/upload", 7}},
                                     {{":scheme", 7}, {"https", 5}},
                                     {{":authority", 10}, {"example", 7}},
                                     {{"content-length", 14}, {"100", 3}}};
    Http2Conn h2;
    h2.init();
    Connection conn;
    conn.reset();
    conn.h2 = &h2;
    RouteConfig config;
    REQUIRE(config.add_jit_handler("/upload", kRouteMethodPost, &h2_status_204, false, true));
    conn.request_config = &config;
    FakeH2Loop loop;
    u8 response[512]{};
    H2Dispatch<FakeH2Loop> dispatch{&loop, &conn, response, sizeof(response), 0, false};

    h2_dispatch_request(dispatch, 1, headers, 5, /*end_stream=*/false);
    CHECK_EQ(dispatch.resp_len, 0u);
    CHECK_EQ(h2.pending_stream, 1u);
    CHECK(h2.pending_has_content_length);
    CHECK_EQ(h2.pending_content_length, 100u);

    static const u8 kShortBody[] = {'a', 'b', 'c'};
    h2_on_data_cb<FakeH2Loop>(&dispatch, h2, 1, kShortBody, sizeof(kShortBody), true);
    CHECK_EQ(h2.pending_stream, 0u);
    CHECK_GT(dispatch.resp_len, 0u);
}

TEST(h2_serving, buffered_forward_route_acknowledges_declared_expect_continue) {
    const hpack::Header headers[] = {{{":method", 7}, {"POST", 4}},
                                     {{":path", 5}, {"/upload", 7}},
                                     {{":scheme", 7}, {"https", 5}},
                                     {{":authority", 10}, {"example", 7}},
                                     {{"expect", 6}, {"100-continue", 12}},
                                     {{"content-length", 14}, {"3", 1}}};
    Http2Conn h2;
    h2.init();
    Connection conn;
    conn.reset();
    conn.h2 = &h2;
    RouteConfig config;
    REQUIRE(config.add_jit_handler("/upload", kRouteMethodPost, &h2_buffered_forward, false, true));
    conn.request_config = &config;
    FakeH2Loop loop;
    u8 response[512]{};
    H2Dispatch<FakeH2Loop> dispatch{&loop, &conn, response, sizeof(response), 0, false};

    h2_dispatch_request(dispatch, 1, headers, 6, /*end_stream=*/false);
    CHECK_EQ(h2.pending_stream, 1u);
    REQUIRE_GT(dispatch.resp_len, 0u);
    Http2FrameHeader frame{};
    REQUIRE(parse_frame_header(response, dispatch.resp_len, &frame) == ParseStatus::Complete);
    CHECK_EQ(frame.type, static_cast<u8>(Http2FrameType::Headers));
    CHECK((frame.flags & http2_flag::kEndHeaders) != 0);
    CHECK((frame.flags & http2_flag::kEndStream) == 0);
    h2_clear_pending(h2);
}

TEST(h2_serving, buffered_forward_capability_preserves_absent_content_length_for_handler) {
    Http2Conn h2;
    h2.init();
    Connection conn;
    conn.reset();
    conn.h2 = &h2;
    FakeH2Loop loop;
    u8 response[512]{};
    H2Dispatch<FakeH2Loop> dispatch{&loop, &conn, response, sizeof(response), 0, false};
    RouteConfig config;
    RouteEntry route{};
    route.action = RouteAction::JitHandler;
    route.fn = &h2_observe_absent_content_length;
    route.needs_req_body = false;
    route.can_forward_buffered = true;

    static constexpr char kRequest[] = "POST /upload HTTP/1.1\r\nhost: example\r\n\r\nabc";
    static constexpr u32 kBodyLen = 3;
    for (u32 i = 0; i < sizeof(kRequest) - 1; i++)
        h2.pending_synth[i] = static_cast<u8>(kRequest[i]);
    h2.pending_stream = 1;
    h2.pending_body_start = sizeof(kRequest) - 1 - kBodyLen;
    h2.pending_synth_len = sizeof(kRequest) - 1;
    h2.pending_body_len = kBodyLen;
    h2.pending_has_content_length = false;
    h2.pending_buffer_body = true;
    h2.pending_request_forwardable = true;
    h2.pending_route_action = RouteAction::JitHandler;
    h2.pending_route_config = &config;
    h2.pending_route = &route;
    h2.pending_jit_fn = route.fn;

    h2_handler_saw_content_length = true;
    h2_finish_body(dispatch, 1);
    CHECK_FALSE(h2_handler_saw_content_length);
    CHECK_GT(dispatch.resp_len, 0u);
}

TEST(h2_serving, bodyless_mutated_status_suppresses_dynamic_data) {
    Http2Conn h2;
    h2.init();
    Connection conn;
    conn.reset();
    conn.h2 = &h2;
    FakeH2Loop loop;
    u8 response[256]{};
    H2Dispatch<FakeH2Loop> dispatch{&loop, &conn, response, sizeof(response), 0, false};
    JitDispatchOutcome outcome{};
    outcome.kind = JitDispatchOutcome::Kind::ReturnStatus;
    outcome.status_code = 204;
    outcome.dynamic_response_body = "must-not-be-sent";
    outcome.dynamic_response_body_len = sizeof("must-not-be-sent") - 1;

    h2_emit_outcome(dispatch, 1, outcome, nullptr, false);

    Http2FrameHeader header{};
    REQUIRE(parse_frame_header(response, dispatch.resp_len, &header) == ParseStatus::Complete);
    CHECK_EQ(header.type, static_cast<u8>(Http2FrameType::Headers));
    CHECK((header.flags & http2_flag::kEndStream) != 0);
    CHECK_EQ(dispatch.resp_len, kFrameHeaderSize + header.length);
}

TEST(h2_serving, captured_content_length_is_removed_for_final_204) {
    Http2Conn h2;
    h2.init();
    Connection conn;
    conn.reset();
    conn.h2 = &h2;
    FakeH2Loop loop;
    u8 response[256]{};
    H2Dispatch<FakeH2Loop> dispatch{&loop, &conn, response, sizeof(response), 0, false};
    jit::HandlerCtx response_ctx{};
    response_ctx.captured_response_valid = true;
    response_ctx.captured_response_header_count = 1;
    response_ctx.captured_response_headers[0].name = {"content-length", 14};
    response_ctx.captured_response_headers[0].value = {"123", 3};
    JitDispatchOutcome outcome{};
    outcome.kind = JitDispatchOutcome::Kind::ReturnStatus;
    outcome.status_code = 204;
    outcome.response_ctx = &response_ctx;
    outcome.uses_captured_response = true;

    h2_emit_outcome(dispatch, 1, outcome, nullptr, false);

    Http2FrameHeader header{};
    REQUIRE(parse_frame_header(response, dispatch.resp_len, &header) == ParseStatus::Complete);
    hpack::DynamicTable dyn;
    dyn.init(4096);
    hpack::Header decoded[8];
    u8 scratch[256];
    u32 count = 0;
    REQUIRE(hpack::decode_header_block(dyn,
                                       response + kFrameHeaderSize,
                                       header.length,
                                       scratch,
                                       sizeof(scratch),
                                       decoded,
                                       8,
                                       &count));
    for (u32 i = 0; i < count; i++)
        CHECK_FALSE(decoded[i].name.eq(Str{"content-length", 14}));
}

TEST(h2_serving, mutation_storage_is_released_after_serialization) {
    Http2Conn h2;
    h2.init();
    Connection conn;
    conn.reset();
    conn.h2 = &h2;
    FakeH2Loop loop;
    u8 response[256]{};
    H2Dispatch<FakeH2Loop> dispatch{&loop, &conn, response, sizeof(response), 0, false};
    static constexpr char kBody[] = "owned response";
    jit::HandlerCtx response_ctx{};
    response_ctx.response_body_mutation_storage = jit::acquire_response_body_mutation_storage();
    REQUIRE(response_ctx.response_body_mutation_storage != nullptr);
    __builtin_memcpy(response_ctx.response_body_mutation_storage, kBody, sizeof(kBody) - 1);
    JitDispatchOutcome outcome{};
    outcome.kind = JitDispatchOutcome::Kind::ReturnStatus;
    outcome.status_code = 200;
    outcome.dynamic_response_body = response_ctx.response_body_mutation_storage;
    outcome.dynamic_response_body_len = sizeof(kBody) - 1;
    outcome.response_ctx = &response_ctx;

    h2_emit_outcome(dispatch, 1, outcome, nullptr, false);

    CHECK(response_ctx.response_body_mutation_storage == nullptr);
    REQUIRE(dispatch.resp_len >= sizeof(kBody) - 1);
    CHECK(__builtin_memcmp(
              response + dispatch.resp_len - (sizeof(kBody) - 1), kBody, sizeof(kBody) - 1) == 0);
}

TEST(h2_serving, rejected_handler_outcomes_release_mutation_storage) {
    static constexpr u8 kRequest[] = "GET / HTTP/1.1\r\n\r\n";
    const auto run = [&](jit::HandlerFn fn, bool occupy_async_slot, bool request_forwardable) {
        Http2Conn h2;
        h2.init();
        if (occupy_async_slot) h2.async_stream = 3;
        Connection conn;
        conn.reset();
        conn.h2 = &h2;
        FakeH2Loop loop;
        u8 response[256]{};
        H2Dispatch<FakeH2Loop> dispatch{&loop, &conn, response, sizeof(response), 0, false};
        RouteEntry route{};
        route.fn = fn;

        h2_invoke_emit(dispatch,
                       1,
                       &route,
                       nullptr,
                       0,
                       nullptr,
                       kRequest,
                       sizeof(kRequest) - 1,
                       request_forwardable);

        CHECK(conn.jit_ctx()->response_body_mutation_storage == nullptr);
        CHECK_GT(dispatch.resp_len, 0u);
    };

    run(&h2_mutated_body_then_forward, false, false);
    run(&h2_mutated_body_then_forward, true, true);
    run(&h2_mutated_body_then_timer, true, false);
}

TEST(h2_serving, failed_response_serialization_rolls_back_encoder_state) {
    Http2Conn h2;
    h2.init();
    Connection conn;
    conn.reset();
    conn.h2 = &h2;
    FakeH2Loop loop;
    u8 response[1]{};
    H2Dispatch<FakeH2Loop> dispatch{&loop, &conn, response, sizeof(response), 0, false};
    const hpack::Header header = {{"x-dynamic", 9}, {"inserted", 8}};
    const auto before = h2.hpack_enc;

    h2_emit_response(dispatch, 1, 200, &header, 1, nullptr, 0, /*allow_fallback=*/false);

    CHECK(dispatch.overflow);
    CHECK_EQ(__builtin_memcmp(&h2.hpack_enc, &before, sizeof(before)), 0);
}

TEST(h2_serving, completed_request_is_accounted_once) {
    Http2Conn h2;
    h2.init();
    h2.nstreams = 1;
    h2.streams[0] = {1,
                     Http2StreamState::HalfClosedRemote,
                     kDefaultInitialWindowSize,
                     kDefaultInitialWindowSize,
                     true,
                     false,
                     false,
                     0};

    Connection conn;
    conn.reset();
    conn.h2 = &h2;
    ShardMetrics metrics;
    metrics.init();
    FakeH2Loop loop;
    loop.metrics = &metrics;
    u8 resp[256];
    H2Dispatch<FakeH2Loop> d{&loop, &conn, resp, sizeof(resp), 0, false};
    const hpack::Header hs[] = {{{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/", 1}}};

    h2_on_headers_cb<FakeH2Loop>(&d, h2, 1, hs, 2, true);

    CHECK_EQ(metrics.requests_total, 0u);
    CHECK_EQ(metrics.requests_active, 1u);
    CHECK_EQ(metrics.request_latency.count, 0u);
    CHECK(h2.streams[0].metrics_started);
    CHECK(h2.streams[0].metrics_pending_send);

    h2_complete_sent_request_metrics(h2);

    CHECK_EQ(metrics.requests_total, 1u);
    CHECK_EQ(metrics.requests_active, 0u);
    CHECK_EQ(metrics.request_latency.count, 1u);
    CHECK_FALSE(h2.streams[0].metrics_started);
    CHECK_FALSE(h2.streams[0].metrics_pending_send);
}

TEST(h2_serving, reset_cancels_metrics_after_engine_closes_stream) {
    Http2Conn h2;
    h2.init();
    ShardMetrics metrics;
    metrics.init();
    metrics.on_request_start();
    h2.metrics = &metrics;
    h2.nstreams = 1;
    h2.streams[0] = {1,
                     Http2StreamState::Closed,
                     kDefaultInitialWindowSize,
                     kDefaultInitialWindowSize,
                     true,
                     true,
                     false,
                     monotonic_us()};

    h2_on_reset_cb(nullptr, h2, 1, Http2Error::Cancel);

    CHECK_EQ(metrics.requests_active, 0u);
    CHECK_EQ(metrics.requests_total, 0u);
    CHECK_FALSE(h2.streams[0].metrics_started);
}

TEST(h2_serving, deferred_route_params_copied_to_stable_storage) {
    // A deferred dynamic route's param VALUES point into hdr_scratch, which the
    // engine reuses for the next decoded header block. The snapshot must copy
    // those bytes into stable per-connection storage so a concurrently
    // multiplexed stream's HEADERS can't clobber req.param() for this request.
    Http2Conn h2;
    h2.init();
    Connection conn;
    conn.reset();
    conn.h2 = &h2;

    FakeH2Loop loop;
    u8 resp[256];
    H2Dispatch<FakeH2Loop> d{&loop, &conn, resp, sizeof(resp), 0, false};

    // The path value lives in a mutable buffer standing in for hdr_scratch; the
    // matched param value is a substring of it (as the real matcher produces).
    char path_buf[] = "/users/42";
    RouteParam params[1] = {{"id", 2, path_buf + 7, 2}};  // "42" within the path
    RouteEntry route{};
    route.action = RouteAction::JitHandler;
    route.fn = reinterpret_cast<jit::HandlerFn>(0x1);  // non-null, never invoked

    const hpack::Header hs[] = {{{":method", 7}, {"GET", 3}}, {{":path", 5}, {path_buf, 9}}};
    ParsedRequest req{};
    req.has_content_length = true;
    req.content_length = 0;

    REQUIRE(h2_defer_until_data_end(d,
                                    1,
                                    hs,
                                    2,
                                    req,
                                    /*buffer_body=*/true,
                                    RouteAction::JitHandler,
                                    /*route_config=*/nullptr,
                                    &route,
                                    params,
                                    1,
                                    200));

    // Simulate the engine reusing hdr_scratch for another stream's headers.
    path_buf[7] = '9';
    path_buf[8] = '9';

    REQUIRE(h2.pending_route_param_count == 1u);
    CHECK(h2.pending_buffer_body);
    CHECK_FALSE(h2.pending_request_forwardable);  // missing :scheme
    const H2RouteParam& sp = h2.pending_route_params[0];
    CHECK_EQ(sp.value_len, 2u);
    CHECK(sp.value != path_buf + 7);  // not aliasing the reusable matcher source
    // Value re-anchored into the stable synth "GET /users/42 HTTP/1.1...": the
    // path follows "GET " (offset 4), so "42" sits at offset 4 + len("/users/").
    CHECK(sp.value == reinterpret_cast<const char*>(h2.pending_synth + 4 + 7));
    CHECK(sp.value[0] == '4' && sp.value[1] == '2');  // pre-clobber bytes intact
    CHECK(sp.name == params[0].name);                 // name still points into stable config
}

TEST(h2_serving, terminal_outcome_releases_response_body_snapshots) {
    Http2Conn h2;
    h2.init();
    Connection conn;
    conn.reset();
    conn.h2 = &h2;

    FakeH2Loop loop;
    u8 resp[1024];
    H2Dispatch<FakeH2Loop> dispatch{&loop, &conn, resp, sizeof(resp), 0, false};
    jit::HandlerCtx ctx{};
    const char body[] = "snapshot";
    const char* snapshot = jit::snapshot_response_body(&ctx, body, sizeof(body) - 1);
    REQUIRE(snapshot != nullptr);
    REQUIRE(ctx.response_body_snapshot_storage != nullptr);

    JitDispatchOutcome outcome{};
    outcome.kind = JitDispatchOutcome::Kind::ReturnStatus;
    outcome.status_code = 200;
    outcome.dynamic_response_body = snapshot;
    outcome.dynamic_response_body_len = sizeof(body) - 1;
    outcome.response_ctx = &ctx;
    h2_emit_outcome(dispatch, 1, outcome, nullptr, false);

    CHECK(ctx.response_body_snapshot_storage == nullptr);
    CHECK(ctx.response_body_mutation_storage == nullptr);
}

TEST(h2_serving, suspended_handler_context_is_snapshotted_and_rebased) {
    Http2Conn h2;
    h2.init();
    Connection conn;
    conn.reset();

    auto* live = conn.reset_jit_ctx();
    live->slot_count = 1;
    live->store_slot<i64>(0, 73);

    u8 synth[] = "GET /slow/abcd HTTP/1.1\r\nhost: example\r\n\r\n";
    constexpr u32 kSynthLen = sizeof(synth) - 1;
    live->response_header_pending_count = 1;
    live->response_header_mutations[0].name = {"X-Path", 6};
    live->response_header_mutations[0].value = {reinterpret_cast<const char*>(synth + 4), 10};
    const char raw_path[] = "/slow/abcd";
    RouteParam decoded_param{"id", 2, raw_path + 6, 4};
    RouteParam anchored_param;
    REQUIRE(h2_reanchor_route_params(
        &decoded_param, 1, Str{raw_path, 10}, synth, kSynthLen, &anchored_param));
    live->route_param_count = 1;
    live->route_params[0] = anchored_param;
    static const char kBody[] = "parked-body";
    live->response_body_mutation_storage = jit::acquire_response_body_mutation_storage();
    REQUIRE(live->response_body_mutation_storage != nullptr);
    __builtin_memcpy(live->response_body_mutation_storage, kBody, sizeof(kBody) - 1);
    live->response_body_pending_len = sizeof(kBody) - 1;
    live->response_body_pending_set = true;
    char* live_body_storage = live->response_body_mutation_storage;
    REQUIRE(live_body_storage != nullptr);
    const char* live_body_snapshot =
        jit::snapshot_response_body(live, live_body_storage, sizeof(kBody) - 1);
    REQUIRE(live_body_snapshot != nullptr);

    REQUIRE_EQ(h2_stash_synth(h2, synth, kSynthLen), kSynthLen);
    REQUIRE(h2_snapshot_async_jit_ctx(h2, *live, synth, kSynthLen));
    CHECK(live->response_body_mutation_storage == nullptr);
    CHECK(live->response_body_snapshot_storage == nullptr);
    conn.reset_jit_ctx();
    for (u32 i = 0; i < kSynthLen; i++) synth[i] = 'x';

    const auto* parked = h2.async_jit_ctx();
    CHECK(parked != live);
    CHECK_EQ(parked->load_slot<i64>(0), 73);
    CHECK(parked->response_header_mutations[0].value.eq(Str{"/slow/abcd", 10}));
    CHECK(parked->response_header_mutations[0].value.ptr ==
          reinterpret_cast<const char*>(h2.pending_synth + 4));
    CHECK_EQ(parked->route_params[0].value_len, 4u);
    CHECK(parked->route_params[0].value == reinterpret_cast<const char*>(h2.pending_synth + 10));
    CHECK(parked->response_body_mutation_storage == live_body_storage);
    REQUIRE(parked->response_body_snapshot_storage != nullptr);
    CHECK(__builtin_memcmp(live_body_snapshot, kBody, sizeof(kBody) - 1) == 0);
    const Str parked_body{parked->response_body_mutation_storage,
                          parked->response_body_pending_len};
    CHECK(parked_body.eq(Str{kBody, sizeof(kBody) - 1}));

    h2.async_stream = 1;
    h2.async_kind = H2AsyncKind::Proxy;
    h2.async_apply_response_mutations = true;
    h2_clear_async(h2);
    CHECK(parked->response_body_mutation_storage == nullptr);
    CHECK(parked->response_body_snapshot_storage == nullptr);
}

TEST(h2_serving, arming_suspended_handler_releases_scratch_body_storage) {
    Http2Conn h2;
    h2.init();
    Connection conn;
    conn.reset();
    conn.h2 = &h2;

    auto* scratch = conn.reset_jit_ctx();
    scratch->response_body_mutation_storage = jit::acquire_response_body_mutation_storage();
    REQUIRE(scratch->response_body_mutation_storage != nullptr);
    auto* parked = h2.async_jit_ctx();
    REQUIRE(parked->response_body_snapshot_storage == nullptr);
    parked->response_body_mutation_storage = jit::acquire_response_body_mutation_storage();
    REQUIRE(parked->response_body_mutation_storage != nullptr);
    char* parked_storage = parked->response_body_mutation_storage;

    h2.async_stream = 1;
    h2.async_kind = H2AsyncKind::Timer;
    h2.async_fn = reinterpret_cast<jit::HandlerFn>(0x1);
    h2.async_state = 3;
    h2.async_timer_ms = 25;
    FakeH2Loop loop;
    REQUIRE(h2_arm_async_timer(&loop, conn));

    CHECK(scratch->response_body_mutation_storage == nullptr);
    CHECK(conn.handler_ctx == parked);
    CHECK(parked->response_body_mutation_storage == parked_storage);
    CHECK(loop.yield_scheduled);
    CHECK_EQ(loop.yield_ms, 25u);

    h2_clear_async(h2);
    CHECK(parked->response_body_mutation_storage == nullptr);
    conn.handler_ctx = nullptr;
}

TEST(http2_conn, padded_data_missing_pad_length_is_error) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    u8 frame[256];
    u32 fn = open_stream1(frame, sizeof(frame));
    // PADDED flag set but zero-length payload → no pad-length octet → error.
    fn += put_frame(frame + fn, Http2FrameType::Data, http2_flag::kPadded, 1, nullptr, 0);
    u8 in[384];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::Goaway, 0, 0));
}

TEST(http2_conn, closed_stream_slot_is_reused) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    u8 frame[256];
    u32 fn = open_stream1(frame, sizeof(frame));  // stream 1 (slot 0)
    const u8 kErr[4] = {0, 0, 0, 8};              // RST_STREAM CANCEL on stream 1
    fn += put_frame(frame + fn, Http2FrameType::RstStream, 0, 1, kErr, 4);
    // A new stream (id 3) should reuse the now-Closed slot.
    const hpack::Header hs[] = {{{":method", 7}, {"GET", 3}}, {{":path", 5}, {"/", 1}}};
    fn += http2_write_headers(frame + fn, sizeof(frame) - fn, 3, hs, 2, /*end_stream=*/true);
    u8 in[384];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK_FALSE(r.close);
    CHECK(c.find_stream(3) != nullptr);
    CHECK_EQ(c.nstreams, 1u);  // slot reused, not grown
}

TEST(http2_conn, headers_padded_missing_pad_length_is_error) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    // HEADERS with PADDED set but zero-length payload → no pad-length octet.
    u8 frame[64];
    u32 fn = put_frame(frame,
                       Http2FrameType::Headers,
                       http2_flag::kEndHeaders | http2_flag::kPadded,
                       1,
                       nullptr,
                       0);
    u8 in[64];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::Goaway, 0, 0));
}

TEST(http2_conn, bad_hpack_block_is_compression_error) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    // Indexed header field with index 0 is illegal HPACK → decode fails.
    const u8 kBlock[1] = {0x80};
    u8 frame[64];
    u32 fn = put_frame(frame,
                       Http2FrameType::Headers,
                       http2_flag::kEndHeaders | http2_flag::kEndStream,
                       1,
                       kBlock,
                       1);
    u8 in[64];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::Goaway, 0, 0));
}

TEST(http2_conn, connection_window_update_overflow_goaway) {
    Http2Conn c;
    Capture cap;
    setup(c, cap);
    const u8 kBig[4] = {0x7f, 0xff, 0xff, 0xff};  // +2^31-1 overflows the conn window
    u8 frame[64];
    u32 fn = put_frame(frame, Http2FrameType::WindowUpdate, 0, 0, kBig, 4);
    u8 in[64];
    u32 inlen = with_preface(in, frame, fn);
    u8 out[256];
    u32 ow = 0;
    Http2Result r = c.process(in, inlen, out, sizeof(out), &ow);
    CHECK(r.close);
    CHECK(has_frame(out, ow, Http2FrameType::Goaway, 0, 0));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
