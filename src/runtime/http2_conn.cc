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
    cont_discard = false;
    hdr_block_len = 0;
    nstreams = 0;
    pending_stream = 0;
    pending_body_start = 0;
    pending_synth_len = 0;
    pending_body_len = 0;
    pending_content_length = 0;
    pending_has_content_length = false;
    pending_buffer_body = false;
    pending_request_forwardable = false;
    pending_overflow = false;
    pending_route_config = nullptr;
    pending_route = nullptr;
    pending_route_action = RouteAction::Static;
    pending_static_status = 200;
    pending_jit_fn = nullptr;
    pending_route_param_count = 0;
    for (u32 i = 0; i < kMaxRouteParams; i++) {
        pending_route_params[i] = {};
    }
    async_stream = 0;
    async_kind = H2AsyncKind::None;
    async_cfg = nullptr;
    async_synth_len = 0;
    async_synth_sent = 0;
    async_request_body_followed = false;
    async_request_forwardable = false;
    async_timer_ms = 0;
    async_fn = nullptr;
    async_state = 0;
    async_upstream_id = 0;
    async_resp_len = 0;
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
                         const hpack::Header* hdrs,
                         u32 nhdrs,
                         const u8* body,
                         u32 body_len) {
    // Encode the header block: :status, caller headers, then content-length when
    // there's a body. Sized for the bounded route-config header set + slack.
    u8 hblock[8192];
    u32 hb = 0;
    // A pending dynamic table size update (from a peer SETTINGS_HEADER_TABLE_SIZE
    // change) MUST lead the header block, before any field (RFC 7541 §4.2).
    hb += enc.emit_pending_size_update(hblock + hb);
    char sbuf[3];
    sbuf[0] = static_cast<char>('0' + (status / 100) % 10);
    sbuf[1] = static_cast<char>('0' + (status / 10) % 10);
    sbuf[2] = static_cast<char>('0' + status % 10);
    hb += enc.encode(hblock + hb, Str{":status", 7}, Str{sbuf, 3});
    // Worst-case HPACK literal overhead beyond the raw name+value bytes: one field-
    // line prefix octet plus a length-prefix integer for each of name and value (up
    // to 5 bytes each for 32-bit lengths). The peer (or an upstream we proxy) can
    // supply arbitrary header sizes, so this must bound the write exactly — a header
    // just under the buffer would otherwise encode past hblock instead of returning
    // 0 (→ the caller answers 502).
    static constexpr u32 kHpackFieldOverhead = 11;  // 1 prefix + 5 + 5 length octets
    // Room the trailing content-length line needs when there's a body, reserved
    // during the loop so the loop can't fill hblock and then overflow on the CL.
    const u32 kClReserve = body_len > 0 ? 14 + 10 + kHpackFieldOverhead : 0;
    for (u32 i = 0; i < nhdrs; i++) {
        if (hb + hdrs[i].name.len + hdrs[i].value.len + kHpackFieldOverhead + kClReserve >
            sizeof(hblock))
            return 0;
        // HTTP/2 header names MUST be lowercase (RFC 7540 §8.1.2); the route
        // config (or a proxied upstream) may hold mixed case (HTTP/1 tolerates it).
        // Lowercase into a small buffer before encoding.
        char lname[256];
        Str name = hdrs[i].name;
        if (name.len <= sizeof(lname)) {
            for (u32 j = 0; j < name.len; j++) {
                const char kC = name.ptr[j];
                lname[j] = (kC >= 'A' && kC <= 'Z') ? static_cast<char>(kC - 'A' + 'a') : kC;
            }
            name = Str{lname, name.len};
        } else {
            // Too long to lowercase in our buffer. Forwarding it verbatim would emit
            // an uppercase (invalid) HTTP/2 name, so reject the response (→ 502)
            // unless it's already all-lowercase. A >256-byte field name is
            // pathological regardless.
            for (u32 j = 0; j < name.len; j++) {
                const char kC = name.ptr[j];
                if (kC >= 'A' && kC <= 'Z') return 0;
            }
        }
        hb += enc.encode(hblock + hb, name, hdrs[i].value);
    }
    if (body_len > 0) {
        char clbuf[10];
        const u32 kClLen = u32_to_dec(body_len, clbuf);
        if (hb + 14 + kClLen + kHpackFieldOverhead > sizeof(hblock)) return 0;  // (reserved above)
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
    if (v.len == 0) return false;
    u32 acc = 0;
    for (u32 i = 0; i < v.len; i++) {
        if (v.ptr[i] < '0' || v.ptr[i] > '9') return false;
        const u32 digit = static_cast<u32>(v.ptr[i] - '0');
        if (acc > 429496729u || (acc == 429496729u && digit > 5u)) return false;
        acc = acc * 10 + digit;
    }
    *out = acc;
    return true;
}

// A field value must not contain NUL, CR, or LF (RFC 7540 §10.3). These would
// let a crafted h2 header inject extra headers / split the request once it is
// serialized back into HTTP/1 syntax to prime the handler's parse cache.
bool h2_value_ok(Str v) {
    for (u32 i = 0; i < v.len; i++) {
        const char kCh = v.ptr[i];
        if (kCh == '\0' || kCh == '\r' || kCh == '\n') return false;
    }
    return true;
}

// A regular field name must be a non-empty lowercase HTTP/2 token (§8.1.2): no
// uppercase, no control chars / space / DEL, and no ':' (which would split the
// HTTP/1 line). Pseudo-headers (leading ':') are validated separately.
bool h2_name_ok(Str n) {
    if (n.len == 0) return false;
    for (u32 i = 0; i < n.len; i++) {
        const auto kCh = static_cast<unsigned char>(n.ptr[i]);
        if (kCh >= 'A' && kCh <= 'Z') return false;   // §8.1.2: names are lowercase
        if (kCh < 0x21 || kCh == 0x7f) return false;  // controls, SP, DEL
        if (kCh == ':') return false;                 // not a token char
    }
    return true;
}

// Connection-specific headers MUST be treated as malformed in HTTP/2 (§8.1.2.2).
bool h2_is_connection_header(Str n) {
    return h2_str_eq(n, "connection") || h2_str_eq(n, "transfer-encoding") ||
           h2_str_eq(n, "keep-alive") || h2_str_eq(n, "upgrade") ||
           h2_str_eq(n, "proxy-connection");
}

}  // namespace

bool h2_headers_to_request(const hpack::Header* hs, u32 n, ParsedRequest* req) {
    req->reset();
    req->version = HttpVersion::Http11;  // h2 maps to HTTP/1.1 semantics
    req->keep_alive = true;              // h2 connections persist

    bool have_method = false;
    bool have_path = false;
    bool have_authority = false;
    bool have_scheme = false;
    bool have_content_length = false;
    bool seen_regular = false;
    for (u32 i = 0; i < n; i++) {
        const Str kName = hs[i].name;
        const Str kValue = hs[i].value;
        if (kName.len > 0 && kName.ptr[0] == ':') {
            // Pseudo-header: MUST precede all regular headers (§8.1.2.1), must be
            // a recognized request pseudo-header, and its value must be
            // injection-free (a CRLF in :path/:authority would split the request).
            if (seen_regular) return false;
            if (!h2_value_ok(kValue)) return false;
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
                if (have_authority) return false;
                if (req->header_count >= kMaxHeaders) return false;
                req->headers[req->header_count++] = {Str{"host", 4}, kValue};
                have_authority = true;
            } else if (!h2_str_eq(kName, ":scheme")) {
                // :scheme is recognized and dropped; any other pseudo-header
                // (incl. response pseudo-headers like :status) is malformed.
                return false;
            } else {
                if (have_scheme) return false;
                have_scheme = true;
            }
            continue;
        }
        // Regular header: reject names/values that would corrupt the synthesized
        // HTTP/1 request, plus connection-specific headers (§8.1.2.2).
        seen_regular = true;
        if (!h2_name_ok(kName) || !h2_value_ok(kValue)) return false;
        if (h2_is_connection_header(kName)) return false;
        if (h2_str_eq(kName, "te") && !h2_str_eq(kValue, "trailers")) return false;
        if (req->header_count >= kMaxHeaders) return false;
        req->headers[req->header_count++] = {kName, kValue};
        if (h2_str_eq(kName, "content-length")) {
            u32 cl = 0;
            if (have_content_length || !h2_value_to_u32(kValue, &cl)) return false;
            have_content_length = true;
            req->content_length = cl;
            req->has_content_length = true;
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
    c.cont_discard = false;
    if (c.on_headers) c.on_headers(c.cb_ctx, c, stream_id, hs, nh, end_stream);
    return Http2Error::NoError;
}

// Decode a second header block we will not deliver (illegal repeat, or request
// trailers), keeping the HPACK decoder dynamic table in sync. When has_pseudo is
// non-null it reports whether the block contained any pseudo-header (a ':' name),
// which disqualifies it from being valid trailers (RFC 7540 §8.1.2.1).
Http2Error discard_headers(Http2Conn& c, bool* has_pseudo = nullptr) {
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
    if (has_pseudo) {
        *has_pseudo = false;
        for (u32 i = 0; i < nh; i++) {
            if (hs[i].name.len > 0 && hs[i].name.ptr[0] == ':') {
                *has_pseudo = true;
                break;
            }
        }
    }
    c.hdr_block_len = 0;
    c.cont_stream = 0;
    c.cont_discard = false;
    return Http2Error::NoError;
}

// Append a header-block fragment, guarding the assembly buffer.
Http2Error append_fragment(Http2Conn& c, const u8* p, u32 n) {
    if (c.hdr_block_len + n > Http2Conn::kHeaderBlockCap) return Http2Error::CompressionError;
    for (u32 i = 0; i < n; i++) c.hdr_block[c.hdr_block_len + i] = p[i];
    c.hdr_block_len += n;
    return Http2Error::NoError;
}

void clear_pending_upload(Http2Conn& c, u32 stream_id) {
    if (c.pending_stream != stream_id) return;
    c.pending_stream = 0;
    c.pending_body_start = 0;
    c.pending_synth_len = 0;
    c.pending_body_len = 0;
    c.pending_content_length = 0;
    c.pending_has_content_length = false;
    c.pending_buffer_body = false;
    c.pending_overflow = false;
    c.pending_route_config = nullptr;
    c.pending_route = nullptr;
    c.pending_route_action = RouteAction::Static;
    c.pending_static_status = 200;
    c.pending_jit_fn = nullptr;
    c.pending_route_param_count = 0;
    for (u32 i = 0; i < kMaxRouteParams; i++) {
        c.pending_route_params[i] = {};
    }
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
            // The peer's SETTINGS_HEADER_TABLE_SIZE bounds the dynamic table our
            // encoder may index against. React (resize + arm a §6.3 update for the
            // next response header block) so we never index into a table the peer
            // shrank. No-op when the value is unchanged.
            c.hpack_enc.set_table_size(c.peer_settings.header_table_size);
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
            if (s->got_headers) {
                // A second HEADERS block on an already-open stream is either
                // request trailers (RFC 7540 §8.1: END_STREAM set, stream still
                // receiving body) or an illegal second request header block.
                // Decode it either way to keep the HPACK decoder in sync, then
                // finalize the buffered upload (trailers) or reset the stream.
                const bool kEndStream = (h.flags & http2_flag::kEndStream) != 0;
                const Http2Error kAe = append_fragment(c, p, n);
                if (kAe != Http2Error::NoError) return kAe;
                if (h.flags & http2_flag::kEndHeaders) {
                    bool has_pseudo = false;
                    const Http2Error kDe = discard_headers(c, &has_pseudo);
                    if (kDe != Http2Error::NoError) return kDe;
                    // Valid request trailers: END_STREAM, no pseudo-headers, on a
                    // stream still receiving its body.
                    if (kEndStream && !has_pseudo &&
                        (s->state == Http2StreamState::Open ||
                         s->state == Http2StreamState::HalfClosedLocal)) {
                        // Valid request trailers end the peer's side: close fully if
                        // we already responded (HalfClosedLocal), else half-close remote.
                        s->state = (s->state == Http2StreamState::HalfClosedLocal)
                                       ? Http2StreamState::Closed
                                       : Http2StreamState::HalfClosedRemote;
                        if (c.pending_stream == h.stream_id && c.on_data)
                            c.on_data(c.cb_ctx, c, h.stream_id, nullptr, 0, /*end_stream=*/true);
                        return Http2Error::NoError;
                    }
                    if (w.room(kFrameHeaderSize + 4))
                        w.len +=
                            write_rst_stream(w.out + w.len, h.stream_id, Http2Error::ProtocolError);
                    clear_pending_upload(c, h.stream_id);
                    s->state = Http2StreamState::Closed;
                    return Http2Error::NoError;
                }
                c.cont_stream = h.stream_id;
                c.cont_end_stream = kEndStream;  // carry END_STREAM for trailers
                c.cont_discard = true;
                return Http2Error::NoError;
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
            // A CONTINUATION with no HEADERS awaiting it is a connection error
            // (§6.10). (A mismatched stream id was already rejected at the top.)
            if (c.cont_stream == 0) return Http2Error::ProtocolError;
            const Http2Error kAe = append_fragment(c, payload, h.length);
            if (kAe != Http2Error::NoError) return kAe;
            if (h.flags & http2_flag::kEndHeaders) {
                Http2Stream* s = c.find_stream(h.stream_id);
                if (c.cont_discard) {
                    const bool kTrailerEnd = c.cont_end_stream;  // before discard resets
                    bool has_pseudo = false;
                    const Http2Error kDe = discard_headers(c, &has_pseudo);
                    if (kDe != Http2Error::NoError) return kDe;
                    if (kTrailerEnd && !has_pseudo && s &&
                        (s->state == Http2StreamState::Open ||
                         s->state == Http2StreamState::HalfClosedLocal)) {
                        s->state = (s->state == Http2StreamState::HalfClosedLocal)
                                       ? Http2StreamState::Closed
                                       : Http2StreamState::HalfClosedRemote;
                        if (c.pending_stream == h.stream_id && c.on_data)
                            c.on_data(c.cb_ctx, c, h.stream_id, nullptr, 0, /*end_stream=*/true);
                        return Http2Error::NoError;
                    }
                    if (w.room(kFrameHeaderSize + 4))
                        w.len +=
                            write_rst_stream(w.out + w.len, h.stream_id, Http2Error::ProtocolError);
                    clear_pending_upload(c, h.stream_id);
                    if (s) s->state = Http2StreamState::Closed;
                    return Http2Error::NoError;
                }
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
            // DATA on a HalfClosedLocal stream (we already responded; on_data above
            // discards it) completes the stream once the peer ends it — close fully
            // so the slot frees. An Open stream only half-closes its remote side.
            if (kEndStream)
                s->state = (s->state == Http2StreamState::HalfClosedLocal)
                               ? Http2StreamState::Closed
                               : Http2StreamState::HalfClosedRemote;

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
                if (!s) {
                    // Idle stream (peer-initiated id never opened) is a
                    // connection error (§5.1); a closed stream is benign.
                    if ((h.stream_id & 1u) != 0 && h.stream_id > c.last_stream_id)
                        return Http2Error::ProtocolError;
                    return Http2Error::NoError;
                }
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
            clear_pending_upload(c, h.stream_id);
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

        // A serving callback parked a stream (one-at-a-time wait/proxy). We still
        // drain control frames already coalesced in this buffer — above all a
        // RST_STREAM that cancels the parked stream (the client sent HEADERS +
        // RST_STREAM in one packet): processing it now fires on_reset, which frees
        // the async slot so we never arm a timer / open an upstream and later reply
        // on a cancelled stream. Request frames (HEADERS / CONTINUATION / DATA /
        // PUSH_PROMISE) start new work and are HPACK-order-dependent, so stop at the
        // first one and leave it buffered until the parked stream resumes — else the
        // next coalesced stream would be dispatched now and refused (503).
        if (async_stream != 0) {
            const auto kT = static_cast<Http2FrameType>(h.type);
            if (kT == Http2FrameType::Headers || kT == Http2FrameType::Continuation ||
                kT == Http2FrameType::Data || kT == Http2FrameType::PushPromise)
                break;
        }

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
