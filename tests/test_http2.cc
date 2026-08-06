// Tests for the HTTP/2 framing layer (src/runtime/http2_frame.cc): frame
// header parse/serialize, the client connection preface, and SETTINGS.

#include "rut/runtime/http2_frame.h"
#include "test.h"

using namespace rut;

namespace {
// Round-trip a frame header through write + parse.
Http2FrameHeader roundtrip(u32 length, Http2FrameType type, u8 flags, u32 stream_id) {
    u8 buf[kFrameHeaderSize];
    Http2FrameHeader in;
    in.length = length;
    in.type = static_cast<u8>(type);
    in.flags = flags;
    in.stream_id = stream_id;
    write_frame_header(buf, in);
    Http2FrameHeader out;
    out.length = 0;
    out.type = 0;
    out.flags = 0;
    out.stream_id = 0;
    parse_frame_header(buf, sizeof(buf), &out);
    return out;
}
}  // namespace

TEST(http2_frame, header_roundtrip) {
    Http2FrameHeader h = roundtrip(16384, Http2FrameType::Data, http2_flag::kEndStream, 5);
    CHECK_EQ(h.length, 16384u);
    CHECK_EQ(h.type, static_cast<u8>(Http2FrameType::Data));
    CHECK_EQ(h.flags, http2_flag::kEndStream);
    CHECK_EQ(h.stream_id, 5u);
}

TEST(http2_frame, header_max_values) {
    // Max 24-bit length, max 31-bit stream id.
    Http2FrameHeader h = roundtrip(0xffffff, Http2FrameType::Headers, 0xff, 0x7fffffff);
    CHECK_EQ(h.length, 0xffffffu);
    CHECK_EQ(h.stream_id, 0x7fffffffu);
    CHECK_EQ(h.flags, 0xffu);
}

TEST(http2_frame, parse_masks_reserved_bit) {
    // Reserved high bit of the stream id must be cleared on parse (§4.1).
    u8 buf[kFrameHeaderSize] = {0, 0, 0, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff};
    Http2FrameHeader h;
    CHECK(parse_frame_header(buf, sizeof(buf), &h) == ParseStatus::Complete);
    CHECK_EQ(h.stream_id, 0x7fffffffu);
}

TEST(http2_frame, parse_incomplete_header) {
    u8 buf[4] = {0, 0, 0, 0};
    Http2FrameHeader h;
    CHECK(parse_frame_header(buf, sizeof(buf), &h) == ParseStatus::Incomplete);
}

TEST(http2_frame, write_truncates_oversized_fields) {
    // length beyond 24 bits and stream id beyond 31 bits are masked on write.
    u8 buf[kFrameHeaderSize];
    Http2FrameHeader in;
    in.length = 0xff000001u;  // -> 0x000001 after 24-bit mask
    in.type = static_cast<u8>(Http2FrameType::Ping);
    in.flags = 0;
    in.stream_id = 0xffffffffu;  // -> 0x7fffffff after 31-bit mask
    write_frame_header(buf, in);
    Http2FrameHeader out;
    parse_frame_header(buf, sizeof(buf), &out);
    CHECK_EQ(out.length, 0x000001u);
    CHECK_EQ(out.stream_id, 0x7fffffffu);
}

// === Connection preface ===

TEST(http2_preface, full_match) {
    CHECK(match_client_preface(kClientPreface, kClientPrefaceLen) == ParseStatus::Complete);
}

TEST(http2_preface, prefix_is_incomplete) {
    CHECK(match_client_preface(kClientPreface, 10) == ParseStatus::Incomplete);
    CHECK(match_client_preface(kClientPreface, 0) == ParseStatus::Incomplete);
}

TEST(http2_preface, mismatch_is_error) {
    u8 bad[kClientPrefaceLen];
    for (u32 i = 0; i < kClientPrefaceLen; i++) bad[i] = kClientPreface[i];
    bad[0] = 'X';  // "XRI * HTTP/2.0..."
    CHECK(match_client_preface(bad, kClientPrefaceLen) == ParseStatus::Error);
    // An HTTP/1.1 request line must not be mistaken for the preface.
    const u8 get[] = {'G', 'E', 'T', ' ', '/', ' ', 'H'};
    CHECK(match_client_preface(get, sizeof(get)) == ParseStatus::Error);
}

// === SETTINGS ===

TEST(http2_settings, defaults) {
    Http2Settings s;
    s.set_defaults();
    CHECK_EQ(s.header_table_size, kDefaultHeaderTableSize);
    CHECK_EQ(s.enable_push, 1u);
    CHECK_EQ(s.initial_window_size, kDefaultInitialWindowSize);
    CHECK_EQ(s.max_frame_size, kDefaultMaxFrameSize);
}

TEST(http2_settings, parse_applies_values) {
    Http2Settings s;
    s.set_defaults();
    // INITIAL_WINDOW_SIZE=131072, MAX_CONCURRENT_STREAMS=100.
    u8 payload[] = {0x00,
                    0x04,
                    0x00,
                    0x02,
                    0x00,
                    0x00,  // initial window 131072
                    0x00,
                    0x03,
                    0x00,
                    0x00,
                    0x00,
                    0x64};  // max concurrent 100
    CHECK(parse_settings(payload, sizeof(payload), &s) == Http2Error::NoError);
    CHECK_EQ(s.initial_window_size, 131072u);
    CHECK_EQ(s.max_concurrent_streams, 100u);
    CHECK(s.has_max_concurrent_streams);
}

TEST(http2_settings, parse_applies_optional_and_table_values) {
    Http2Settings s;
    s.set_defaults();
    u8 payload[] = {0x00,
                    0x01,
                    0x00,
                    0x00,
                    0x10,
                    0x00,  // header table size 4096
                    0x00,
                    0x02,
                    0x00,
                    0x00,
                    0x00,
                    0x00,  // disable server push
                    0x00,
                    0x06,
                    0x00,
                    0x00,
                    0x20,
                    0x00};  // max header list size 8192

    CHECK(parse_settings(payload, sizeof(payload), &s) == Http2Error::NoError);
    CHECK_EQ(s.header_table_size, 4096u);
    CHECK_EQ(s.enable_push, 0u);
    CHECK_EQ(s.max_header_list_size, 8192u);
    CHECK(s.has_max_header_list_size);
}

TEST(http2_settings, unknown_id_ignored) {
    Http2Settings s;
    s.set_defaults();
    u8 payload[] = {0xff, 0xff, 0x12, 0x34, 0x56, 0x78};  // id 0xffff — ignore
    CHECK(parse_settings(payload, sizeof(payload), &s) == Http2Error::NoError);
    CHECK_EQ(s.max_frame_size, kDefaultMaxFrameSize);  // untouched
}

TEST(http2_settings, bad_length_is_frame_size_error) {
    Http2Settings s;
    s.set_defaults();
    u8 payload[] = {0x00, 0x04, 0x00};  // 3 bytes, not a multiple of 6
    CHECK(parse_settings(payload, sizeof(payload), &s) == Http2Error::FrameSizeError);
}

TEST(http2_settings, invalid_values_rejected) {
    Http2Settings s;
    s.set_defaults();
    u8 push[] = {0x00, 0x02, 0x00, 0x00, 0x00, 0x02};  // ENABLE_PUSH=2 (invalid)
    CHECK(parse_settings(push, sizeof(push), &s) == Http2Error::ProtocolError);
    u8 frame[] = {0x00, 0x05, 0x00, 0x00, 0x00, 0x01};  // MAX_FRAME_SIZE=1 (< 2^14)
    CHECK(parse_settings(frame, sizeof(frame), &s) == Http2Error::ProtocolError);
    u8 win[] = {0x00, 0x04, 0xff, 0xff, 0xff, 0xff};  // INITIAL_WINDOW_SIZE > 2^31-1
    CHECK(parse_settings(win, sizeof(win), &s) == Http2Error::FlowControlError);
}

TEST(http2_settings, serialize_then_parse_nondefaults) {
    Http2Settings s;
    s.set_defaults();
    s.initial_window_size = 1048576;
    s.max_frame_size = 32768;
    s.max_concurrent_streams = 128;
    s.has_max_concurrent_streams = true;

    u8 buf[64];
    u32 n = write_settings_frame(buf, s);
    // Header reports the payload length; only 3 non-default entries (18 bytes).
    Http2FrameHeader h;
    CHECK(parse_frame_header(buf, n, &h) == ParseStatus::Complete);
    CHECK_EQ(h.type, static_cast<u8>(Http2FrameType::Settings));
    CHECK_EQ(h.flags, 0u);
    CHECK_EQ(h.stream_id, 0u);
    CHECK_EQ(h.length, 18u);
    CHECK_EQ(n, kFrameHeaderSize + 18u);

    Http2Settings parsed;
    parsed.set_defaults();
    CHECK(parse_settings(buf + kFrameHeaderSize, h.length, &parsed) == Http2Error::NoError);
    CHECK_EQ(parsed.initial_window_size, 1048576u);
    CHECK_EQ(parsed.max_frame_size, 32768u);
    CHECK_EQ(parsed.max_concurrent_streams, 128u);
}

TEST(http2_frame, settings_ack) {
    u8 buf[kFrameHeaderSize];
    u32 n = write_settings_ack(buf);
    CHECK_EQ(n, kFrameHeaderSize);
    Http2FrameHeader h;
    parse_frame_header(buf, n, &h);
    CHECK_EQ(h.type, static_cast<u8>(Http2FrameType::Settings));
    CHECK_EQ(h.flags, http2_flag::kAck);
    CHECK_EQ(h.length, 0u);
}

TEST(http2_frame, goaway) {
    u8 buf[kFrameHeaderSize + 8];
    u32 n = write_goaway(buf, 7, Http2Error::ProtocolError);
    CHECK_EQ(n, kFrameHeaderSize + 8u);
    Http2FrameHeader h;
    parse_frame_header(buf, n, &h);
    CHECK_EQ(h.type, static_cast<u8>(Http2FrameType::Goaway));
    CHECK_EQ(h.length, 8u);
    CHECK_EQ(h.stream_id, 0u);
    // last_stream_id then error code, both big-endian u32.
    const u8* p = buf + kFrameHeaderSize;
    CHECK_EQ(p[3], 7u);
    CHECK_EQ(p[7], static_cast<u8>(Http2Error::ProtocolError));
}

TEST(http2_frame, window_update) {
    u8 buf[kFrameHeaderSize + 4];
    u32 n = write_window_update(buf, 3, 65535);
    CHECK_EQ(n, kFrameHeaderSize + 4u);
    Http2FrameHeader h;
    parse_frame_header(buf, n, &h);
    CHECK_EQ(h.type, static_cast<u8>(Http2FrameType::WindowUpdate));
    CHECK_EQ(h.stream_id, 3u);
    CHECK_EQ(h.length, 4u);
}

TEST(http2_frame, rst_stream) {
    u8 buf[kFrameHeaderSize + 4];
    u32 n = write_rst_stream(buf, 9, Http2Error::Cancel);
    CHECK_EQ(n, kFrameHeaderSize + 4u);
    Http2FrameHeader h;
    parse_frame_header(buf, n, &h);
    CHECK_EQ(h.type, static_cast<u8>(Http2FrameType::RstStream));
    CHECK_EQ(h.stream_id, 9u);
    CHECK_EQ(h.length, 4u);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
