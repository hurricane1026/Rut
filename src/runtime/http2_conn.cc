#include "rut/runtime/http2_conn.h"

namespace rut {

namespace {

u32 read_u32(const u8* p) {
    return (static_cast<u32>(p[0]) << 24) | (static_cast<u32>(p[1]) << 16) |
           (static_cast<u32>(p[2]) << 8) | static_cast<u32>(p[3]);
}

constexpr i64 kMaxWindow = 2147483647;  // 2^31 - 1

}  // namespace

void Http2Conn::init() {
    hpack_dec.init(kDefaultHeaderTableSize);
    hpack_enc.init(kDefaultHeaderTableSize);
    our_settings.set_defaults();
    // Advertise our limits: bounded concurrent streams; keep the default window.
    our_settings.max_concurrent_streams = kMaxStreams;
    our_settings.has_max_concurrent_streams = true;
    peer_settings.set_defaults();
    conn_send_window = kDefaultInitialWindowSize;
    conn_recv_window = kDefaultInitialWindowSize;
    preface_seen = false;
    our_settings_sent = false;
    goaway_sent = false;
    last_stream_id = 0;
    cont_stream = 0;
    cont_end_stream = false;
    hdr_block_len = 0;
    nstreams = 0;
}

Http2Stream* Http2Conn::find_stream(u32 id) {
    for (u32 i = 0; i < nstreams; i++)
        if (streams[i].id == id && streams[i].state != Http2StreamState::Closed) return &streams[i];
    return nullptr;
}

namespace {

// Reuse a Closed slot or grow; returns null when the table is full of live
// streams (caller should RST_STREAM with REFUSED_STREAM).
Http2Stream* alloc_stream(Http2Conn& c, u32 id) {
    for (u32 i = 0; i < c.nstreams; i++) {
        if (c.streams[i].state == Http2StreamState::Closed) {
            Http2Stream& s = c.streams[i];
            s.id = id;
            s.state = Http2StreamState::Open;
            s.send_window = static_cast<i32>(c.peer_settings.initial_window_size);
            s.recv_window = static_cast<i32>(c.our_settings.initial_window_size);
            s.got_headers = false;
            return &s;
        }
    }
    if (c.nstreams >= Http2Conn::kMaxStreams) return nullptr;
    Http2Stream& s = c.streams[c.nstreams++];
    s.id = id;
    s.state = Http2StreamState::Open;
    s.send_window = static_cast<i32>(c.peer_settings.initial_window_size);
    s.recv_window = static_cast<i32>(c.our_settings.initial_window_size);
    s.got_headers = false;
    return &s;
}

}  // namespace

// --- Response serialization ---

u32 http2_write_headers(
    u8* out, u32 out_cap, u32 stream_id, const hpack::Header* hs, u32 n, bool end_stream) {
    if (out_cap < kFrameHeaderSize) return 0;
    u32 o = kFrameHeaderSize;
    for (u32 i = 0; i < n; i++) {
        // Worst-case per header: name+value+small prefixes. Bail if it won't fit.
        if (o + hs[i].name.len + hs[i].value.len + 8 > out_cap) return 0;
        o += hpack::encode_header(out + o, hs[i].name, hs[i].value);
    }
    const u32 kPayload = o - kFrameHeaderSize;
    u8 flags = http2_flag::kEndHeaders;
    if (end_stream) flags |= http2_flag::kEndStream;
    Http2FrameHeader h;
    h.length = kPayload;
    h.type = static_cast<u8>(Http2FrameType::Headers);
    h.flags = flags;
    h.stream_id = stream_id;
    write_frame_header(out, h);
    return o;
}

u32 http2_write_data(u8* out, u32 stream_id, const u8* data, u32 len, bool end_stream) {
    Http2FrameHeader h;
    h.length = len;
    h.type = static_cast<u8>(Http2FrameType::Data);
    h.flags = end_stream ? http2_flag::kEndStream : 0;
    h.stream_id = stream_id;
    write_frame_header(out, h);
    for (u32 i = 0; i < len; i++) out[kFrameHeaderSize + i] = data[i];
    return kFrameHeaderSize + len;
}

namespace {
// Render an unsigned value as decimal into buf (max 10 digits); returns length.
u32 u32_to_dec(u32 v, char* buf) {
    if (v == 0) {
        buf[0] = '0';
        return 1;
    }
    char tmp[10];
    u32 n = 0;
    while (v > 0) {
        tmp[n++] = static_cast<char>('0' + v % 10);
        v /= 10;
    }
    for (u32 i = 0; i < n; i++) buf[i] = tmp[n - 1 - i];
    return n;
}
}  // namespace

u32 http2_write_response(u8* out,
                         u32 out_cap,
                         hpack::Encoder& enc,
                         u32 stream_id,
                         u16 status,
                         const u8* body,
                         u32 body_len) {
    // Encode the header block: :status, plus content-length when there's a body.
    u8 hblock[64];
    u32 hb = 0;
    char sbuf[3];
    sbuf[0] = static_cast<char>('0' + (status / 100) % 10);
    sbuf[1] = static_cast<char>('0' + (status / 10) % 10);
    sbuf[2] = static_cast<char>('0' + status % 10);
    hb += enc.encode(hblock + hb, Str{":status", 7}, Str{sbuf, 3});
    if (body_len > 0) {
        char clbuf[10];
        const u32 kClLen = u32_to_dec(body_len, clbuf);
        hb += enc.encode(hblock + hb, Str{"content-length", 14}, Str{clbuf, kClLen});
    }

    const bool kEndOnHeaders = (body_len == 0);
    const u32 kNeed = kFrameHeaderSize + hb + (body_len > 0 ? kFrameHeaderSize + body_len : 0u);
    if (kNeed > out_cap) return 0;

    Http2FrameHeader h;
    h.length = hb;
    h.type = static_cast<u8>(Http2FrameType::Headers);
    h.flags =
        static_cast<u8>(http2_flag::kEndHeaders | (kEndOnHeaders ? http2_flag::kEndStream : 0));
    h.stream_id = stream_id;
    write_frame_header(out, h);
    for (u32 i = 0; i < hb; i++) out[kFrameHeaderSize + i] = hblock[i];
    u32 o = kFrameHeaderSize + hb;
    if (body_len > 0)
        o += http2_write_data(out + o, stream_id, body, body_len, /*end_stream=*/true);
    return o;
}

namespace {

bool h2_str_eq(Str a, const char* b) {
    u32 bl = 0;
    while (b[bl]) bl++;
    if (a.len != bl) return false;
    for (u32 i = 0; i < bl; i++)
        if (a.ptr[i] != b[i]) return false;
    return true;
}

HttpMethod h2_method_from_str(Str m) {
    if (h2_str_eq(m, "GET")) return HttpMethod::GET;
    if (h2_str_eq(m, "POST")) return HttpMethod::POST;
    if (h2_str_eq(m, "PUT")) return HttpMethod::PUT;
    if (h2_str_eq(m, "DELETE")) return HttpMethod::DELETE;
    if (h2_str_eq(m, "PATCH")) return HttpMethod::PATCH;
    if (h2_str_eq(m, "HEAD")) return HttpMethod::HEAD;
    if (h2_str_eq(m, "OPTIONS")) return HttpMethod::OPTIONS;
    if (h2_str_eq(m, "CONNECT")) return HttpMethod::CONNECT;
    if (h2_str_eq(m, "TRACE")) return HttpMethod::TRACE;
    return HttpMethod::Unknown;
}

// Canonicalize a request path the way the HTTP/1 parser does: strip one leading
// '/' and any trailing '/' run, exclude query (?) and fragment (#).
Str h2_canon_path(Str path) {
    const char* p = path.ptr;
    u32 end = 0;
    while (end < path.len && p[end] != '?' && p[end] != '#') end++;
    u32 start = 0;
    if (start < end && p[start] == '/') start++;
    while (end > start && p[end - 1] == '/') end--;
    return {p + start, end - start};
}

bool h2_value_to_u32(Str v, u32* out) {
    if (v.len == 0 || v.len > 9) return false;
    u32 acc = 0;
    for (u32 i = 0; i < v.len; i++) {
        if (v.ptr[i] < '0' || v.ptr[i] > '9') return false;
        acc = acc * 10 + static_cast<u32>(v.ptr[i] - '0');
    }
    *out = acc;
    return true;
}

}  // namespace

bool h2_headers_to_request(const hpack::Header* hs, u32 n, ParsedRequest* req) {
    req->reset();
    req->version = HttpVersion::Http11;  // h2 maps to HTTP/1.1 semantics
    req->keep_alive = true;              // h2 connections persist

    bool have_method = false;
    bool have_path = false;
    for (u32 i = 0; i < n; i++) {
        const Str kName = hs[i].name;
        const Str kValue = hs[i].value;
        if (kName.len > 0 && kName.ptr[0] == ':') {
            // Pseudo-header.
            if (h2_str_eq(kName, ":method")) {
                if (have_method) return false;  // duplicate
                req->method = h2_method_from_str(kValue);
                if (req->method == HttpMethod::Unknown) return false;
                have_method = true;
            } else if (h2_str_eq(kName, ":path")) {
                if (have_path) return false;
                if (kValue.len == 0) return false;
                req->path = kValue;
                req->path_canon = h2_canon_path(kValue);
                have_path = true;
            } else if (h2_str_eq(kName, ":authority")) {
                if (req->header_count >= kMaxHeaders) return false;
                req->headers[req->header_count++] = {Str{"host", 4}, kValue};
            }
            // :scheme and any other pseudo-header are dropped.
            continue;
        }
        // Regular header.
        if (req->header_count >= kMaxHeaders) return false;
        req->headers[req->header_count++] = {kName, kValue};
        if (h2_str_eq(kName, "content-length")) {
            u32 cl = 0;
            if (h2_value_to_u32(kValue, &cl)) {
                req->content_length = cl;
                req->has_content_length = true;
            }
        }
    }
    return have_method && have_path;
}

namespace {

// Append-and-bounds helper bound to one process() call.
struct OutWriter {
    u8* out;
    u32 cap;
    u32 len;
    bool room(u32 n) const { return len + n <= cap; }
};

// Decode the accumulated header block and deliver it; reset assembly state.
Http2Error finish_headers(Http2Conn& c, u32 stream_id, bool end_stream) {
    hpack::Header hs[Http2Conn::kMaxHeadersPerReq];
    u32 nh = 0;
    if (!hpack::decode_header_block(c.hpack_dec,
                                    c.hdr_block,
                                    c.hdr_block_len,
                                    c.hdr_scratch,
                                    Http2Conn::kHeaderScratchCap,
                                    hs,
                                    Http2Conn::kMaxHeadersPerReq,
                                    &nh)) {
        return Http2Error::CompressionError;
    }
    c.hdr_block_len = 0;
    c.cont_stream = 0;
    if (c.on_headers) c.on_headers(c.cb_ctx, c, stream_id, hs, nh, end_stream);
    return Http2Error::NoError;
}

// Append a header-block fragment, guarding the assembly buffer.
Http2Error append_fragment(Http2Conn& c, const u8* p, u32 n) {
    if (c.hdr_block_len + n > Http2Conn::kHeaderBlockCap) return Http2Error::CompressionError;
    for (u32 i = 0; i < n; i++) c.hdr_block[c.hdr_block_len + i] = p[i];
    c.hdr_block_len += n;
    return Http2Error::NoError;
}

}  // namespace

// Handle a single fully-buffered frame. Returns a connection error (non-NoError
// → caller sends GOAWAY and closes). Stream-level errors emit RST_STREAM here
// and return NoError.
static Http2Error handle_frame(Http2Conn& c,
                               const Http2FrameHeader& h,
                               const u8* payload,
                               OutWriter& w) {
    const auto kType = static_cast<Http2FrameType>(h.type);

    // A pending CONTINUATION admits only a CONTINUATION on the same stream.
    if (c.cont_stream != 0 &&
        (kType != Http2FrameType::Continuation || h.stream_id != c.cont_stream)) {
        return Http2Error::ProtocolError;
    }

    switch (kType) {
        case Http2FrameType::Settings: {
            if (h.stream_id != 0) return Http2Error::ProtocolError;
            if (h.flags & http2_flag::kAck) {
                if (h.length != 0) return Http2Error::FrameSizeError;
                return Http2Error::NoError;
            }
            const i64 kOldIws = c.peer_settings.initial_window_size;
            const Http2Error kErr = parse_settings(payload, h.length, &c.peer_settings);
            if (kErr != Http2Error::NoError) return kErr;
            // Adjust live stream send windows by the INITIAL_WINDOW_SIZE delta.
            const i64 kDelta = static_cast<i64>(c.peer_settings.initial_window_size) - kOldIws;
            if (kDelta != 0) {
                for (u32 i = 0; i < c.nstreams; i++) {
                    if (c.streams[i].state == Http2StreamState::Closed) continue;
                    const i64 kNw = static_cast<i64>(c.streams[i].send_window) + kDelta;
                    if (kNw > kMaxWindow) return Http2Error::FlowControlError;
                    c.streams[i].send_window = static_cast<i32>(kNw);
                }
            }
            if (w.room(kFrameHeaderSize)) w.len += write_settings_ack(w.out + w.len);
            return Http2Error::NoError;
        }

        case Http2FrameType::Headers: {
            if (h.stream_id == 0 || (h.stream_id & 1u) == 0) return Http2Error::ProtocolError;
            const u8* p = payload;
            u32 n = h.length;
            u8 pad = 0;
            if (h.flags & http2_flag::kPadded) {
                if (n < 1) return Http2Error::ProtocolError;
                pad = p[0];
                p += 1;
                n -= 1;
            }
            if (h.flags & http2_flag::kPriority) {
                if (n < 5) return Http2Error::ProtocolError;
                p += 5;
                n -= 5;
            }
            if (pad > n) return Http2Error::ProtocolError;
            n -= pad;

            Http2Stream* s = c.find_stream(h.stream_id);
            if (!s) {
                if (h.stream_id <= c.last_stream_id) return Http2Error::ProtocolError;
                s = alloc_stream(c, h.stream_id);
                c.last_stream_id = h.stream_id;
                if (!s) {
                    if (w.room(kFrameHeaderSize + 4))
                        w.len +=
                            write_rst_stream(w.out + w.len, h.stream_id, Http2Error::RefusedStream);
                    return Http2Error::NoError;
                }
            }
            s->got_headers = true;
            const bool kEndStream = (h.flags & http2_flag::kEndStream) != 0;
            const Http2Error kAe = append_fragment(c, p, n);
            if (kAe != Http2Error::NoError) return kAe;
            if (h.flags & http2_flag::kEndHeaders) {
                if (kEndStream) s->state = Http2StreamState::HalfClosedRemote;
                return finish_headers(c, h.stream_id, kEndStream);
            }
            c.cont_stream = h.stream_id;
            c.cont_end_stream = kEndStream;
            return Http2Error::NoError;
        }

        case Http2FrameType::Continuation: {
            const Http2Error kAe = append_fragment(c, payload, h.length);
            if (kAe != Http2Error::NoError) return kAe;
            if (h.flags & http2_flag::kEndHeaders) {
                Http2Stream* s = c.find_stream(h.stream_id);
                if (s && c.cont_end_stream) s->state = Http2StreamState::HalfClosedRemote;
                return finish_headers(c, h.stream_id, c.cont_end_stream);
            }
            return Http2Error::NoError;
        }

        case Http2FrameType::Data: {
            if (h.stream_id == 0) return Http2Error::ProtocolError;
            // Connection-level flow control counts the whole frame payload.
            c.conn_recv_window -= static_cast<i64>(h.length);
            if (c.conn_recv_window < 0) return Http2Error::FlowControlError;

            Http2Stream* s = c.find_stream(h.stream_id);
            if (!s || s->state == Http2StreamState::HalfClosedRemote) {
                if (w.room(kFrameHeaderSize + 4))
                    w.len += write_rst_stream(w.out + w.len, h.stream_id, Http2Error::StreamClosed);
                // Still replenish the connection window for the consumed octets.
                c.conn_recv_window += static_cast<i64>(h.length);
                if (h.length > 0 && w.room(kFrameHeaderSize + 4))
                    w.len += write_window_update(w.out + w.len, 0, h.length);
                return Http2Error::NoError;
            }

            const u8* p = payload;
            u32 n = h.length;
            u8 pad = 0;
            if (h.flags & http2_flag::kPadded) {
                if (n < 1) return Http2Error::ProtocolError;
                pad = p[0];
                p += 1;
                n -= 1;
            }
            if (pad > n) return Http2Error::ProtocolError;
            n -= pad;

            s->recv_window -= static_cast<i32>(h.length);
            if (s->recv_window < 0) {
                if (w.room(kFrameHeaderSize + 4))
                    w.len +=
                        write_rst_stream(w.out + w.len, h.stream_id, Http2Error::FlowControlError);
                s->state = Http2StreamState::Closed;
                c.conn_recv_window += static_cast<i64>(h.length);
                return Http2Error::NoError;
            }

            const bool kEndStream = (h.flags & http2_flag::kEndStream) != 0;
            if (c.on_data) c.on_data(c.cb_ctx, c, h.stream_id, p, n, kEndStream);
            if (kEndStream) s->state = Http2StreamState::HalfClosedRemote;

            // Auto-replenish: keep the peer's send windows open.
            c.conn_recv_window += static_cast<i64>(h.length);
            s->recv_window += static_cast<i32>(h.length);
            if (h.length > 0) {
                if (w.room(kFrameHeaderSize + 4))
                    w.len += write_window_update(w.out + w.len, 0, h.length);
                if (!kEndStream && w.room(kFrameHeaderSize + 4))
                    w.len += write_window_update(w.out + w.len, h.stream_id, h.length);
            }
            return Http2Error::NoError;
        }

        case Http2FrameType::WindowUpdate: {
            if (h.length != 4) return Http2Error::FrameSizeError;
            const u32 kInc = read_u32(payload) & 0x7fffffffu;
            if (h.stream_id == 0) {
                if (kInc == 0) return Http2Error::ProtocolError;
                c.conn_send_window += static_cast<i64>(kInc);
                if (c.conn_send_window > kMaxWindow) return Http2Error::FlowControlError;
            } else {
                Http2Stream* s = c.find_stream(h.stream_id);
                if (!s) return Http2Error::NoError;  // window update for a closed stream
                if (kInc == 0) {
                    if (w.room(kFrameHeaderSize + 4))
                        w.len +=
                            write_rst_stream(w.out + w.len, h.stream_id, Http2Error::ProtocolError);
                    s->state = Http2StreamState::Closed;
                    return Http2Error::NoError;
                }
                const i64 kNw = static_cast<i64>(s->send_window) + kInc;
                if (kNw > kMaxWindow) {
                    if (w.room(kFrameHeaderSize + 4))
                        w.len += write_rst_stream(
                            w.out + w.len, h.stream_id, Http2Error::FlowControlError);
                    s->state = Http2StreamState::Closed;
                    return Http2Error::NoError;
                }
                s->send_window = static_cast<i32>(kNw);
            }
            return Http2Error::NoError;
        }

        case Http2FrameType::RstStream: {
            if (h.stream_id == 0 || h.length != 4) return Http2Error::ProtocolError;
            Http2Stream* s = c.find_stream(h.stream_id);
            if (s) s->state = Http2StreamState::Closed;
            if (c.on_reset)
                c.on_reset(c.cb_ctx, c, h.stream_id, static_cast<Http2Error>(read_u32(payload)));
            return Http2Error::NoError;
        }

        case Http2FrameType::Ping: {
            if (h.stream_id != 0 || h.length != 8) return Http2Error::FrameSizeError;
            if (!(h.flags & http2_flag::kAck) && w.room(kFrameHeaderSize + 8)) {
                Http2FrameHeader ack;
                ack.length = 8;
                ack.type = static_cast<u8>(Http2FrameType::Ping);
                ack.flags = http2_flag::kAck;
                ack.stream_id = 0;
                write_frame_header(w.out + w.len, ack);
                for (u32 i = 0; i < 8; i++) w.out[w.len + kFrameHeaderSize + i] = payload[i];
                w.len += kFrameHeaderSize + 8;
            }
            return Http2Error::NoError;
        }

        case Http2FrameType::Goaway:
            return Http2Error::NoError;  // peer is closing; let the loop drain

        case Http2FrameType::PushPromise:
            return Http2Error::ProtocolError;  // clients may not push

        case Http2FrameType::Priority:
        default:
            return Http2Error::NoError;  // PRIORITY and unknown types are ignored
    }
}

Http2Result Http2Conn::process(const u8* in, u32 len, u8* out, u32 out_cap, u32* out_written) {
    OutWriter w{out, out_cap, 0};
    u32 pos = 0;

    if (!preface_seen) {
        const ParseStatus kPs = match_client_preface(in, len);
        if (kPs == ParseStatus::Error) {
            if (w.room(kFrameHeaderSize + 8))
                w.len += write_goaway(w.out + w.len, last_stream_id, Http2Error::ProtocolError);
            goaway_sent = true;
            *out_written = w.len;
            return {0, true};
        }
        if (kPs == ParseStatus::Incomplete) {
            *out_written = 0;
            return {0, false};
        }
        pos += kClientPrefaceLen;
        preface_seen = true;
        if (!our_settings_sent && w.room(64)) {
            w.len += write_settings_frame(w.out + w.len, our_settings);
            our_settings_sent = true;
        }
    }

    while (true) {
        if (len - pos < kFrameHeaderSize) break;
        Http2FrameHeader h;
        parse_frame_header(in + pos, len - pos, &h);
        if (h.length > our_settings.max_frame_size) {
            if (w.room(kFrameHeaderSize + 8))
                w.len += write_goaway(w.out + w.len, last_stream_id, Http2Error::FrameSizeError);
            goaway_sent = true;
            *out_written = w.len;
            return {pos, true};
        }
        if (len - pos < kFrameHeaderSize + h.length) break;  // wait for full payload

        const Http2Error kErr = handle_frame(*this, h, in + pos + kFrameHeaderSize, w);
        pos += kFrameHeaderSize + h.length;
        if (kErr != Http2Error::NoError) {
            if (w.room(kFrameHeaderSize + 8))
                w.len += write_goaway(w.out + w.len, last_stream_id, kErr);
            goaway_sent = true;
            *out_written = w.len;
            return {pos, true};
        }
    }

    *out_written = w.len;
    return {pos, false};
}

}  // namespace rut
