// Tests for the HTTP/2 connection engine (src/runtime/http2_conn.cc): preface,
// SETTINGS handshake, frame demux, HEADERS/CONTINUATION assembly + HPACK decode,
// DATA delivery, flow control, and control-frame generation. Inbound frames are
// built with the engine's own response writers (HPACK encoder), fed through
// process(), and the decoded callbacks + emitted control frames are asserted.

#include "rut/runtime/callbacks_h2.h"
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

TEST(h2_request, invalid_or_duplicate_content_length_fails) {
    ParsedRequest req;
    hpack::Header bad[] = {{{":method", 7}, {"POST", 4}},
                           {{":path", 5}, {"/u", 2}},
                           {{"content-length", 14}, {"x", 1}}};
    CHECK_FALSE(h2_headers_to_request(bad, 3, &req));
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

TEST(h2_serving, finalizes_body_content_length) {
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
    REQUIRE(h2_finalize_synth_body(h2));
    ParsedRequest parsed;
    HttpParser parser;
    parser.reset();
    CHECK(parser.parse(h2.pending_synth, h2.pending_synth_len, &parsed) == ParseStatus::Complete);
    CHECK(parsed.has_content_length);
    CHECK_EQ(parsed.content_length, 3u);
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
    CHECK_FALSE(h2_finalize_synth_body(h2));
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
