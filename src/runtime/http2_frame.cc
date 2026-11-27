#include "rut/runtime/http2_frame.h"

#include "rut/common/range_int.h"

namespace rut {

namespace {

// Big-endian readers/writers. HTTP/2 integers are network byte order.
[[nodiscard]] u32 read_u24(const u8* p) {
    return (range_int{p[0]}.scaled_by<(1 << 16)>() + range_int{p[1]}.scaled_by<(1 << 8)>() +
            range_int{p[2]})
        .to<u32>();
}
[[nodiscard]] u32 read_u32(const u8* p) {
    return (range_int{p[0]}.scaled_by<(1 << 24)>() + range_int{p[1]}.scaled_by<(1 << 16)>() +
            range_int{p[2]}.scaled_by<(1 << 8)>() + range_int{p[3]})
        .to<u32>();
}
[[nodiscard]] u16 read_u16(const u8* p) {
    return (range_int(p[0]).scaled_by<256>() + range_int(p[1])).to<u16>();
}
void write_u24(u8* p, u32 v) {
    p[0] = bounded_remainder<256>(v >> 16).to<u8>();
    p[1] = bounded_remainder<256>(v >> 8).to<u8>();
    p[2] = bounded_remainder<256>(v).to<u8>();
}
void write_u32(u8* p, u32 v) {
    p[0] = bounded_remainder<256>(v >> 24).to<u8>();
    p[1] = bounded_remainder<256>(v >> 16).to<u8>();
    p[2] = bounded_remainder<256>(v >> 8).to<u8>();
    p[3] = bounded_remainder<256>(v).to<u8>();
}
void write_u16(u8* p, u16 v) {
    p[0] = bounded_remainder<256>(v >> 8).to<u8>();
    p[1] = bounded_remainder<256>(v).to<u8>();
}

// Emit a frame header into out and return the byte just past it.
[[nodiscard]] u8* emit_header(u8* out, u32 length, Http2FrameType type, u8 flags, u32 stream_id) {
    Http2FrameHeader h;
    h.length = length;
    h.type = static_cast<u8>(type);
    h.flags = flags;
    h.stream_id = stream_id;
    return out + range_int{write_frame_header(out, h)}.index();
}

}  // namespace

// "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
const u8 kClientPreface[kClientPrefaceLen] = {0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54,
                                              0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
                                              0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a};

[[nodiscard]] ParseStatus parse_frame_header(const u8* buf, u32 len, Http2FrameHeader* out) {
    if (len < kFrameHeaderSize) return ParseStatus::Incomplete;
    out->length = read_u24(buf);
    out->type = buf[3];
    out->flags = buf[4];
    // Mask off the reserved high bit of the stream id (§4.1).
    out->stream_id = read_u32(buf + 5) & 0x7fffffffu;
    return ParseStatus::Complete;
}

[[nodiscard]] u32 write_frame_header(u8* out, const Http2FrameHeader& h) {
    write_u24(out, h.length & 0xffffffu);
    out[3] = h.type;
    out[4] = h.flags;
    write_u32(out + 5, h.stream_id & 0x7fffffffu);
    return kFrameHeaderSize;
}

[[nodiscard]] ParseStatus match_client_preface(const u8* buf, u32 len) {
    const u32 kCmp = len < kClientPrefaceLen ? len : kClientPrefaceLen;
    for (u32 i = 0; i < kCmp; i++) {
        if (buf[i] != kClientPreface[i]) return ParseStatus::Error;
    }
    if (len < kClientPrefaceLen) return ParseStatus::Incomplete;
    return ParseStatus::Complete;
}

[[nodiscard]] Http2Error parse_settings(const u8* payload, u32 len, Http2Settings* s) {
    if (len % 6u != 0u) return Http2Error::FrameSizeError;
    for (i64 i = 0; i < len; i += 6) {
        const u16 kId = read_u16(payload + i);
        const u32 kVal = read_u32(payload + i + 2);
        switch (static_cast<Http2SettingId>(kId)) {
            case Http2SettingId::HeaderTableSize:
                s->header_table_size = kVal;
                break;
            case Http2SettingId::EnablePush:
                if (kVal > 1u) return Http2Error::ProtocolError;
                s->enable_push = kVal;
                break;
            case Http2SettingId::EnableConnectProtocol:
                if (kVal > 1u || (s->enable_connect_protocol == 1u && kVal == 0u))
                    return Http2Error::ProtocolError;
                s->enable_connect_protocol = kVal;
                break;
            case Http2SettingId::MaxConcurrentStreams:
                s->max_concurrent_streams = kVal;
                s->has_max_concurrent_streams = true;
                break;
            case Http2SettingId::InitialWindowSize:
                if (kVal > kMaxWindowSize) return Http2Error::FlowControlError;
                s->initial_window_size = kVal;
                break;
            case Http2SettingId::MaxFrameSize:
                if (kVal < kDefaultMaxFrameSize || kVal > kMaxAllowedFrameSize)
                    return Http2Error::ProtocolError;
                s->max_frame_size = kVal;
                break;
            case Http2SettingId::MaxHeaderListSize:
                s->max_header_list_size = kVal;
                s->has_max_header_list_size = true;
                break;
            default:
                // Unknown setting — ignore (§6.5.2).
                break;
        }
    }
    return Http2Error::NoError;
}

[[nodiscard]] u32 write_settings_frame(u8* out, const Http2Settings& s) {
    u8* p = out + i64{kFrameHeaderSize};
    u8 count = 0;
    auto append = [&](Http2SettingId id, u32 value) {
        write_u16(p, static_cast<u16>(id));
        write_u32(p + 2, value);
        p += 6;
        ++count;
    };
    if (s.enable_connect_protocol)
        append(Http2SettingId::EnableConnectProtocol, s.enable_connect_protocol);
    // Advertise the settings that differ from protocol defaults.
    if (s.header_table_size != kDefaultHeaderTableSize)
        append(Http2SettingId::HeaderTableSize, s.header_table_size);
    if (s.enable_push != 1u) append(Http2SettingId::EnablePush, s.enable_push);
    if (s.has_max_concurrent_streams)
        append(Http2SettingId::MaxConcurrentStreams, s.max_concurrent_streams);
    if (s.initial_window_size != kDefaultInitialWindowSize)
        append(Http2SettingId::InitialWindowSize, s.initial_window_size);
    if (s.max_frame_size != kDefaultMaxFrameSize)
        append(Http2SettingId::MaxFrameSize, s.max_frame_size);

    const auto payload = range_int(count).scaled_by<6>();
    Http2FrameHeader header{payload.to<u32>(), 0, static_cast<u8>(Http2FrameType::Settings), 0};
    if (write_frame_header(out, header) != kFrameHeaderSize) return 0;
    return (range_int<kFrameHeaderSize, i64{kFrameHeaderSize} + 1>{} + payload).to<u32>();
}

[[nodiscard]] u32 write_settings_ack(u8* out) {
    return write_frame_header(
        out, Http2FrameHeader{0, 0, static_cast<u8>(Http2FrameType::Settings), http2_flag::kAck});
}

[[nodiscard]] u32 write_goaway(u8* out, u32 last_stream_id, Http2Error error) {
    u8* p = emit_header(out, 8, Http2FrameType::Goaway, 0, 0);
    write_u32(p, last_stream_id & 0x7fffffffu);
    write_u32(p + 4, static_cast<u32>(error));
    return u32{i64{kFrameHeaderSize} + 8};
}

[[nodiscard]] u32 write_window_update(u8* out, u32 stream_id, u32 increment) {
    u8* p = emit_header(out, 4, Http2FrameType::WindowUpdate, 0, stream_id);
    write_u32(p, increment & 0x7fffffffu);
    return u32{i64{kFrameHeaderSize} + 4};
}

[[nodiscard]] u32 write_rst_stream(u8* out, u32 stream_id, Http2Error error) {
    u8* p = emit_header(out, 4, Http2FrameType::RstStream, 0, stream_id);
    write_u32(p, static_cast<u32>(error));
    return u32{i64{kFrameHeaderSize} + 4};
}

}  // namespace rut
