#include "rut/common/http_header_validation.h"
#include "rut/common/types.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/callbacks_impl.h"  // IWYU pragma: keep
#include "rut/runtime/chunked_parser.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/connection_base.h"
#include "rut/runtime/epoll_event_loop.h"  // IWYU pragma: keep
#include "rut/runtime/http_parser.h"
#include "rut/runtime/iouring_event_loop.h"  // IWYU pragma: keep
#include "rut/runtime/route_canon.h"
#include "rut/runtime/traffic_capture.h"

namespace rut {

u8 map_log_method(HttpMethod method) {
    switch (method) {
        case HttpMethod::GET:
            return static_cast<u8>(LogHttpMethod::Get);
        case HttpMethod::POST:
            return static_cast<u8>(LogHttpMethod::Post);
        case HttpMethod::PUT:
            return static_cast<u8>(LogHttpMethod::Put);
        case HttpMethod::DELETE:
            return static_cast<u8>(LogHttpMethod::Delete);
        case HttpMethod::PATCH:
            return static_cast<u8>(LogHttpMethod::Patch);
        case HttpMethod::HEAD:
            return static_cast<u8>(LogHttpMethod::Head);
        case HttpMethod::OPTIONS:
            return static_cast<u8>(LogHttpMethod::Options);
        case HttpMethod::CONNECT:
            return static_cast<u8>(LogHttpMethod::Connect);
        case HttpMethod::TRACE:
            return static_cast<u8>(LogHttpMethod::Trace);
        case HttpMethod::Unknown:
            return static_cast<u8>(LogHttpMethod::Other);
    }
    return static_cast<u8>(LogHttpMethod::Other);
}

u8 parse_log_method_fallback(const u8* data, u32 len, u32* method_len) {
    *method_len = 0;
    if (len >= 4 && data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') {
        *method_len = 3;
        return static_cast<u8>(LogHttpMethod::Get);
    }
    if (len >= 5 && data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T' &&
        data[4] == ' ') {
        *method_len = 4;
        return static_cast<u8>(LogHttpMethod::Post);
    }
    if (len >= 4 && data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' ') {
        *method_len = 3;
        return static_cast<u8>(LogHttpMethod::Put);
    }
    if (len >= 7 && data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && data[3] == 'E' &&
        data[4] == 'T' && data[5] == 'E' && data[6] == ' ') {
        *method_len = 6;
        return static_cast<u8>(LogHttpMethod::Delete);
    }
    if (len >= 6 && data[0] == 'P' && data[1] == 'A' && data[2] == 'T' && data[3] == 'C' &&
        data[4] == 'H' && data[5] == ' ') {
        *method_len = 5;
        return static_cast<u8>(LogHttpMethod::Patch);
    }
    if (len >= 5 && data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D' &&
        data[4] == ' ') {
        *method_len = 4;
        return static_cast<u8>(LogHttpMethod::Head);
    }
    if (len >= 8 && data[0] == 'O' && data[1] == 'P' && data[2] == 'T' && data[3] == 'I' &&
        data[4] == 'O' && data[5] == 'N' && data[6] == 'S' && data[7] == ' ') {
        *method_len = 7;
        return static_cast<u8>(LogHttpMethod::Options);
    }
    if (len >= 8 && data[0] == 'C' && data[1] == 'O' && data[2] == 'N' && data[3] == 'N' &&
        data[4] == 'E' && data[5] == 'C' && data[6] == 'T' && data[7] == ' ') {
        *method_len = 7;
        return static_cast<u8>(LogHttpMethod::Connect);
    }
    if (len >= 6 && data[0] == 'T' && data[1] == 'R' && data[2] == 'A' && data[3] == 'C' &&
        data[4] == 'E' && data[5] == ' ') {
        *method_len = 5;
        return static_cast<u8>(LogHttpMethod::Trace);
    }
    return static_cast<u8>(LogHttpMethod::Other);
}

void capture_request_metadata(Connection& conn) {
    conn.req_method = static_cast<u8>(LogHttpMethod::Other);
    conn.req_size = conn.recv_buf.len();
    conn.req_path[0] = '/';
    conn.req_path[1] = '\0';
    // Default canonical view = "" pointing into req_path[] (the canon of
    // origin-form "/"). If neither the strict parser nor the fallback
    // path-extractor recover anything, dispatch still gets a chance to
    // hit a configured "/" catchall — matches pre-round-7 behavior
    // where the dispatch site canonicalized the default conn.req_path
    // on the fly. Parser overrides this with a real canon for origin-
    // form, or clears it to {nullptr, 0} for non-origin-form so those
    // targets cannot fall into the catchall.
    conn.req_path_canon = Str{conn.req_path + 1, 0};
    conn.upstream_us = 0;
    conn.upstream_name[0] = '\0';
    conn.capture_header_len = 0;
    // Reset request body state (prevents stale Chunked mode from
    // previous keep-alive request bleeding into the next).
    conn.req_body_mode = BodyMode::None;
    conn.req_body_remaining = 0;
    conn.req_chunk_parser.reset();
    conn.req_malformed = false;
    conn.req_header_end = 0;
    conn.req_initial_send_len = 0;
    conn.req_content_length = 0;

    const u8* data = conn.recv_buf.data();
    const u32 kLen = conn.recv_buf.len();
    if (!data || kLen == 0) return;

    HttpParser parser;
    ParsedRequest req;
    parser.reset();
    if (parser.parse(data, kLen, &req) == ParseStatus::Complete) {
        conn.req_header_end = parser.header_end;
        conn.req_method = map_log_method(req.method);
        u32 copy_len = req.path.len;
        if (copy_len >= sizeof(conn.req_path)) copy_len = sizeof(conn.req_path) - 1;
        for (u32 i = 0; i < copy_len; i++) conn.req_path[i] = req.path.ptr[i];
        conn.req_path[copy_len] = '\0';
        // Translate the parser's path_canon (a view into recv_buf) into a
        // view over conn.req_path, which has the same byte layout for
        // [0, copy_len). On truncation, clamp so canon stays in-bounds.
        // If the parser left path_canon null (non-origin-form request-
        // target like "*" or "host:port"), clear conn.req_path_canon so
        // dispatch returns null (security: those targets must not fall
        // into a configured "/" catchall via the fast path).
        if (req.path_canon.ptr != nullptr) {
            // canon_off is computed from the FULL parser-input path, but
            // we only mirrored [0, copy_len) into conn.req_path[]. If the
            // URI is longer than kMaxReqPathLen and the leading-slash run
            // is long enough, canon_off can exceed copy_len — forming
            // conn.req_path + canon_off would be out-of-bounds pointer
            // arithmetic (UB sanitizers flag it, and the resulting
            // non-null pointer would then enter routing). Clamp to
            // copy_len so the pointer always lands in [conn.req_path,
            // conn.req_path + copy_len], the range we wrote bytes into.
            u32 canon_off = static_cast<u32>(req.path_canon.ptr - req.path.ptr);
            u32 canon_len = req.path_canon.len;
            if (canon_off >= copy_len) {
                canon_off = copy_len;
                canon_len = 0;
            } else if (canon_off + canon_len > copy_len) {
                canon_len = copy_len - canon_off;
            }
            conn.req_path_canon = Str{conn.req_path + canon_off, canon_len};
        } else {
            conn.req_path_canon = {nullptr, 0};
        }
        u32 chunk_consumed = 0;
        if (req.chunked) {
            conn.req_body_mode = BodyMode::Chunked;
            conn.req_body_remaining = 0;
            conn.req_chunk_parser.reset();
            const u32 kBodyInBuf = kLen > parser.header_end ? kLen - parser.header_end : 0;
            chunk_consumed = kBodyInBuf;
            if (kBodyInBuf > 0) {
                const u8* body_start = data + parser.header_end;
                u32 pos = 0;
                while (pos < kBodyInBuf) {
                    u32 consumed = 0, out_start = 0, out_len = 0;
                    const ChunkStatus kChunkStatus = conn.req_chunk_parser.feed(
                        body_start + pos, kBodyInBuf - pos, &consumed, &out_start, &out_len);
                    pos += consumed;
                    if (kChunkStatus == ChunkStatus::Done || kChunkStatus == ChunkStatus::NeedMore)
                        break;
                    if (kChunkStatus == ChunkStatus::Error) {
                        conn.req_malformed = true;
                        break;
                    }
                }
                chunk_consumed = pos;
            }
            if (conn.req_malformed) {
                conn.req_initial_send_len = 0;
            } else {
                conn.req_initial_send_len = parser.header_end + chunk_consumed;
            }
        } else if (req.has_content_length && req.content_length > 0) {
            conn.req_body_mode = BodyMode::ContentLength;
            conn.req_content_length = req.content_length;
            conn.req_body_remaining = req.content_length;
            const u32 kBodyInBuf = kLen > parser.header_end ? kLen - parser.header_end : 0;
            if (kBodyInBuf >= conn.req_body_remaining)
                conn.req_body_remaining = 0;
            else
                conn.req_body_remaining -= kBodyInBuf;
        }
        if (conn.req_body_mode == BodyMode::None) {
            conn.req_initial_send_len = parser.header_end;
        } else if (conn.req_body_mode == BodyMode::ContentLength) {
            const u32 kBodyInInitial = conn.req_content_length - conn.req_body_remaining;
            conn.req_initial_send_len = parser.header_end + kBodyInInitial;
        }
        if (conn.req_initial_send_len > 0) conn.req_size = conn.req_initial_send_len;
        return;
    }

    u32 method_len = 0;
    conn.req_method = parse_log_method_fallback(data, kLen, &method_len);
    if (method_len == 0 || method_len + 1 >= kLen || data[method_len] != ' ') return;

    const u32 kPathStart = method_len + 1;
    u32 path_len = 0;
    while (kPathStart + path_len < kLen && data[kPathStart + path_len] != ' ' &&
           data[kPathStart + path_len] != '\r' && data[kPathStart + path_len] != '\n') {
        path_len++;
    }

    if (path_len == 0 || data[kPathStart] != '/') {
        // Recognized method + space + something, but the something isn't
        // origin-form (asterisk-form "*", authority-form "host:port",
        // empty path, etc.). Clear the default canon-of-"/" view so the
        // dispatch fast path returns nullptr — non-origin-form targets
        // must not fall into a "/" catchall via the fast path. We
        // intentionally do NOT clear in the earlier method_len==0 case:
        // pure-junk requests with no recognizable structure default to
        // routing the configured "/" route (matches pre-round-7 fail-
        // open behavior; covered by test_traffic_replay's
        // malformed_request_hits_catchall).
        conn.req_path_canon = {nullptr, 0};
        return;
    }

    u32 copy_len = path_len;
    if (copy_len >= sizeof(conn.req_path)) copy_len = sizeof(conn.req_path) - 1;
    for (u32 i = 0; i < copy_len; i++) conn.req_path[i] = static_cast<char>(data[kPathStart + i]);
    conn.req_path[copy_len] = '\0';
    // The strict parser failed (no path_canon emitted), but we recovered
    // a valid origin-form request-target. Synthesize a canonical view
    // over conn.req_path[] so the dispatch hot path can route this
    // request — matches the pre-round-7 behavior where the dispatch
    // site canonicalized conn.req_path on the fly.
    conn.req_path_canon = canonicalize_request(Str{conn.req_path, copy_len});
}

u32 pipeline_leftover(const Connection& conn) {
    const u32 kReqEnd = conn.req_initial_send_len;
    const u32 kBufLen = conn.recv_buf.len();
    if (kReqEnd == 0 || kReqEnd >= kBufLen) return 0;
    return kBufLen - kReqEnd;
}

bool pipeline_shift(Connection& conn) {
    const u32 kLeftover = pipeline_leftover(conn);
    if (kLeftover == 0) return false;
    const u8* src = conn.recv_buf.data() + conn.req_initial_send_len;
    conn.recv_buf.reset();
    u8* dst = conn.recv_buf.write_ptr();
    __builtin_memmove(dst, src, kLeftover);
    conn.recv_buf.commit(kLeftover);
    conn.pipeline_depth++;
    return true;
}

void pipeline_stash(Connection& conn) {
    const u32 kLeftover = pipeline_leftover(conn);
    if (kLeftover == 0) {
        conn.pipeline_stash_len = 0;
        return;
    }
    conn.send_buf.reset();
    if (kLeftover > conn.send_buf.write_avail()) {
        conn.pipeline_stash_len = 0;
        return;
    }
    const u8* src = conn.recv_buf.data() + conn.req_initial_send_len;
    conn.send_buf.write(src, kLeftover);
    conn.pipeline_stash_len = static_cast<u16>(kLeftover);
}

bool pipeline_recover(Connection& conn) {
    const u16 kStashLen = conn.pipeline_stash_len;
    conn.pipeline_stash_len = 0;
    if (kStashLen == 0) return false;
    const u8* src = conn.send_buf.data();
    const u32 kExisting = conn.recv_buf.len();
    if (kExisting == 0) {
        // HTTP/1 pipeline path (and the common WS case): recv_buf is empty, just
        // restore the stash.
        conn.recv_buf.reset();
        u8* dst = conn.recv_buf.write_ptr();
        __builtin_memmove(dst, src, kStashLen);
        conn.recv_buf.commit(kStashLen);
    } else {
        // Bytes already read into recv_buf (client frames that raced in before
        // tunnel install while an io_uring multishot recv stayed armed) came
        // AFTER the stash, so they must follow it — not be dropped. Shift them up
        // by kStashLen and prepend the stash. base == recv_buf.data().
        u8* base = conn.recv_buf.write_ptr() - kExisting;
        u32 keep = kExisting;
        if (static_cast<u32>(kStashLen) + keep > conn.recv_buf.capacity())
            keep = conn.recv_buf.capacity() - kStashLen;  // truncate tail to fit
        __builtin_memmove(base + kStashLen, base, keep);
        __builtin_memmove(base, src, kStashLen);
        conn.recv_buf.set_len(kStashLen + keep);
    }
    conn.send_buf.reset();
    conn.pipeline_depth++;
    return true;
}

extern const char kResponse200[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: 2\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "OK";

extern const char kResponse200Close[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: 2\r\n"
    "Connection: close\r\n"
    "\r\n"
    "OK";

static_assert(sizeof(kResponse200) - 1 == kResponse200Len, "kResponse200Len must match payload");
static_assert(sizeof(kResponse200Close) - 1 == kResponse200CloseLen,
              "kResponse200CloseLen must match payload");

void capture_stage_headers(Connection& conn) {
    conn.capture_header_len = 0;
    if (!conn.capture_buf) return;
    const u8* data = conn.recv_buf.data();
    if (!data) return;
    u32 len = conn.req_header_end;
    if (len == 0) len = conn.recv_buf.len();
    if (len == 0) return;
    u32 copy_len = len;
    if (copy_len > CaptureEntry::kMaxHeaderLen) copy_len = CaptureEntry::kMaxHeaderLen;
    __builtin_memcpy(conn.capture_buf, data, copy_len);
    conn.capture_header_len = static_cast<u16>(copy_len);
}

const char* status_reason(u16 code) {
    switch (code) {
        case 200:
            return "OK";
        case 201:
            return "Created";
        case 204:
            return "No Content";
        case 301:
            return "Moved Permanently";
        case 302:
            return "Found";
        case 304:
            return "Not Modified";
        case 400:
            return "Bad Request";
        case 401:
            return "Unauthorized";
        case 403:
            return "Forbidden";
        case 404:
            return "Not Found";
        case 405:
            return "Method Not Allowed";
        case 429:
            return "Too Many Requests";
        case 500:
            return "Internal Server Error";
        case 502:
            return "Bad Gateway";
        case 503:
            return "Service Unavailable";
        default:
            return "Unknown";
    }
}

// Shared writer: status line + Content-Length + Connection header,
// used by both the default (reason-phrase) body path and the custom
// body path. Leaves the builder positioned just past "\r\n" so the
// caller can write the body bytes (if any). Callers pre-compute the
// reason string so status_reason/strlen only runs once per response.
static void write_response_headers(Connection& conn,
                                   u16 code,
                                   const char* reason,
                                   u32 reason_len,
                                   u32 body_len,
                                   bool keep_alive,
                                   const char* content_type,
                                   u32 content_type_len) {
    conn.send_buf.reset();
    conn.send_buf.write(reinterpret_cast<const u8*>("HTTP/1.1 "), 9);
    char code_buf[3];
    code_buf[0] = static_cast<char>('0' + (code / 100) % 10);
    code_buf[1] = static_cast<char>('0' + (code / 10) % 10);
    code_buf[2] = static_cast<char>('0' + code % 10);
    conn.send_buf.write(reinterpret_cast<const u8*>(code_buf), 3);
    conn.send_buf.write(reinterpret_cast<const u8*>(" "), 1);
    conn.send_buf.write(reinterpret_cast<const u8*>(reason), reason_len);
    conn.send_buf.write(reinterpret_cast<const u8*>("\r\n"), 2);
    // Content-Length: decimal digits, always emitted (even for 0).
    conn.send_buf.write(reinterpret_cast<const u8*>("Content-Length: "), 16);
    if (body_len >= 1000000000u) {
        char d = static_cast<char>('0' + (body_len / 1000000000u) % 10);
        conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    }
    if (body_len >= 100000000u) {
        char d = static_cast<char>('0' + (body_len / 100000000u) % 10);
        conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    }
    if (body_len >= 10000000u) {
        char d = static_cast<char>('0' + (body_len / 10000000u) % 10);
        conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    }
    if (body_len >= 1000000u) {
        char d = static_cast<char>('0' + (body_len / 1000000u) % 10);
        conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    }
    if (body_len >= 100000u) {
        char d = static_cast<char>('0' + (body_len / 100000u) % 10);
        conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    }
    if (body_len >= 10000u) {
        char d = static_cast<char>('0' + (body_len / 10000u) % 10);
        conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    }
    if (body_len >= 1000u) {
        char d = static_cast<char>('0' + (body_len / 1000u) % 10);
        conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    }
    if (body_len >= 100u) {
        char d = static_cast<char>('0' + (body_len / 100u) % 10);
        conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    }
    if (body_len >= 10u) {
        char d = static_cast<char>('0' + (body_len / 10u) % 10);
        conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    }
    char d = static_cast<char>('0' + body_len % 10);
    conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    conn.send_buf.write(reinterpret_cast<const u8*>("\r\n"), 2);
    if (content_type_len > 0) {
        conn.send_buf.write(reinterpret_cast<const u8*>("Content-Type: "), 14);
        conn.send_buf.write(reinterpret_cast<const u8*>(content_type), content_type_len);
        conn.send_buf.write(reinterpret_cast<const u8*>("\r\n"), 2);
    }
    if (keep_alive)
        conn.send_buf.write(reinterpret_cast<const u8*>("Connection: keep-alive\r\n"), 24);
    else
        conn.send_buf.write(reinterpret_cast<const u8*>("Connection: close\r\n"), 19);
    conn.send_buf.write(reinterpret_cast<const u8*>("\r\n"), 2);
}

void format_static_response(Connection& conn, u16 code, bool keep_alive) {
    const char* reason = status_reason(code);
    u32 reason_len = 0;
    while (reason[reason_len]) reason_len++;
    const bool kNoBody = (code < 200 || code == 204 || code == 304);
    const u32 kBodyLen = kNoBody ? 0 : reason_len;
    write_response_headers(conn, code, reason, reason_len, kBodyLen, keep_alive, nullptr, 0);
    if (kBodyLen > 0) conn.send_buf.write(reinterpret_cast<const u8*>(reason), kBodyLen);
}

void format_response_with_body(
    Connection& conn, u16 code, const char* body_data, u32 body_len, bool keep_alive) {
    // 204 / 304 / 1xx carry no body per HTTP spec; fall back to the
    // default formatter for those codes even if a body was supplied.
    const bool kNoBody = (code < 200 || code == 204 || code == 304);
    if (kNoBody) {
        format_static_response(conn, code, keep_alive);
        return;
    }
    const char* reason = status_reason(code);
    u32 reason_len = 0;
    while (reason[reason_len]) reason_len++;
    static const char kDefaultContentType[] = "text/plain; charset=utf-8";
    write_response_headers(conn,
                           code,
                           reason,
                           reason_len,
                           body_len,
                           keep_alive,
                           kDefaultContentType,
                           sizeof(kDefaultContentType) - 1);
    if (body_len > 0) conn.send_buf.write(reinterpret_cast<const u8*>(body_data), body_len);
}

// Case-insensitive compare against a string literal. Templated on the
// array size so the literal length is resolved at compile time — the
// per-header-pair loop in format_response_with_body_and_headers calls
// this on every entry, and we don't want a strlen-equivalent scan
// baked into that loop. `N` includes the trailing NUL, so we subtract
// one to get the byte length.
template <u32 N>
static bool header_name_eq_literal_ci(const char* data, u32 len, const char (&literal)[N]) {
    return http_header_name_eq_ci(data, len, literal, N - 1);
}

// Write a decimal body_len (Content-Length) to the send_buf as ASCII
// digits, leading zeros suppressed. Emits at least one digit even for
// body_len == 0, so "Content-Length: 0\r\n" comes out whole. Mirrors
// the cascading-threshold pattern in write_response_headers so small
// body_len values (the common case) don't pay for ten divisions.
static void write_content_length_digits(Connection& conn, u32 body_len) {
    if (body_len >= 1000000000u) {
        char d = static_cast<char>('0' + (body_len / 1000000000u) % 10);
        conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    }
    if (body_len >= 100000000u) {
        char d = static_cast<char>('0' + (body_len / 100000000u) % 10);
        conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    }
    if (body_len >= 10000000u) {
        char d = static_cast<char>('0' + (body_len / 10000000u) % 10);
        conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    }
    if (body_len >= 1000000u) {
        char d = static_cast<char>('0' + (body_len / 1000000u) % 10);
        conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    }
    if (body_len >= 100000u) {
        char d = static_cast<char>('0' + (body_len / 100000u) % 10);
        conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    }
    if (body_len >= 10000u) {
        char d = static_cast<char>('0' + (body_len / 10000u) % 10);
        conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    }
    if (body_len >= 1000u) {
        char d = static_cast<char>('0' + (body_len / 1000u) % 10);
        conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    }
    if (body_len >= 100u) {
        char d = static_cast<char>('0' + (body_len / 100u) % 10);
        conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    }
    if (body_len >= 10u) {
        char d = static_cast<char>('0' + (body_len / 10u) % 10);
        conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
    }
    char d = static_cast<char>('0' + body_len % 10);
    conn.send_buf.write(reinterpret_cast<const u8*>(&d), 1);
}

// Count ASCII digits needed to represent `v` in base 10 (at least 1).
static u32 decimal_digit_count(u32 v) {
    u32 n = 1;
    while (v >= 10u) {
        v /= 10u;
        n++;
    }
    return n;
}

void format_response_with_body_and_headers(Connection& conn,
                                           u16 code,
                                           const char* body_data,
                                           u32 body_len,
                                           const ResponseHeaderKV* headers,
                                           u32 header_count,
                                           bool keep_alive,
                                           bool body_is_fallback_reason_phrase) {
    const bool kNoBody = (code < 200 || code == 204 || code == 304);
    const u32 body_len_emit = kNoBody ? 0 : body_len;
    const char* reason = status_reason(code);
    u32 reason_len = 0;
    while (reason[reason_len]) reason_len++;

    // Scan user headers once: is there a user-supplied Content-Type?
    // (If so, skip the default "text/plain".) Content-Length is
    // always dropped — we recompute from body_len_emit to keep framing
    // honest regardless of what the user writes.
    bool user_has_content_type = false;
    for (u32 i = 0; i < header_count; i++) {
        if (header_name_eq_literal_ci(headers[i].key_data, headers[i].key_len, "Content-Type")) {
            user_has_content_type = true;
            break;
        }
    }
    // Skip the default Content-Type when the body is a system-
    // generated reason phrase (fallback path). The bytes aren't
    // user content — format_static_response would have emitted no
    // Content-Type at all here, so suppressing it keeps the fallback
    // wire shape consistent regardless of whether headers are present.
    const bool emit_default_content_type =
        !user_has_content_type && body_len_emit > 0 && !body_is_fallback_reason_phrase;

    // Precompute the exact number of bytes we're about to write.
    // Buffer::write() silently truncates on capacity — if we ran past
    // the send_buf we'd ship a response with a Content-Length that
    // doesn't match the bytes actually on the wire, which hangs or
    // poisons clients. Instead, if the full response doesn't fit, we
    // fail closed: emit a 500 + Connection: close via the fallback
    // formatter. The cap is per-connection (send_buf is a 16KB
    // slice), so this only trips on pathological hand-built configs.
    constexpr u32 kStatusLineFixed =
        9 /* "HTTP/1.1 " */ + 3 /* code */ + 1 /* " " */ + 2 /* "\r\n" */;
    constexpr u32 kContentLengthPrefix = 16;  // "Content-Length: "
    constexpr u32 kDefaultContentTypeLine =
        sizeof("Content-Type: text/plain; charset=utf-8\r\n") - 1;
    constexpr u32 kConnKeepAliveLine = 24;  // "Connection: keep-alive\r\n"
    constexpr u32 kConnCloseLine = 19;      // "Connection: close\r\n"
    u64 needed = kStatusLineFixed + reason_len + kContentLengthPrefix +
                 decimal_digit_count(body_len_emit) + 2;
    if (emit_default_content_type) needed += kDefaultContentTypeLine;
    for (u32 i = 0; i < header_count; i++) {
        if (header_name_eq_literal_ci(headers[i].key_data, headers[i].key_len, "Content-Length")) {
            continue;
        }
        needed += headers[i].key_len + 2 /* ": " */ + headers[i].value_len + 2 /* "\r\n" */;
    }
    needed += (keep_alive ? kConnKeepAliveLine : kConnCloseLine);
    needed += 2;  // blank line terminator
    needed += body_len_emit;
    if (needed > conn.send_buf.capacity()) {
        // Fail closed: force connection close and emit a small 500.
        // format_static_response uses the reason-phrase body which is
        // guaranteed to fit. Update conn state too — resp_status and
        // keep_alive were set upstream assuming the happy path; if we
        // leave them, on_response_sent would reuse the socket despite
        // the wire saying "Connection: close" and metrics would log
        // the original status rather than the 500 we actually sent.
        conn.resp_status = 500;
        conn.keep_alive = false;
        format_static_response(conn, 500, /*keep_alive=*/false);
        return;
    }

    conn.send_buf.reset();
    // Status line: "HTTP/1.1 <3-digit code> <reason>\r\n"
    conn.send_buf.write(reinterpret_cast<const u8*>("HTTP/1.1 "), 9);
    char code_buf[3];
    code_buf[0] = static_cast<char>('0' + (code / 100) % 10);
    code_buf[1] = static_cast<char>('0' + (code / 10) % 10);
    code_buf[2] = static_cast<char>('0' + code % 10);
    conn.send_buf.write(reinterpret_cast<const u8*>(code_buf), 3);
    conn.send_buf.write(reinterpret_cast<const u8*>(" "), 1);
    conn.send_buf.write(reinterpret_cast<const u8*>(reason), reason_len);
    conn.send_buf.write(reinterpret_cast<const u8*>("\r\n"), 2);
    // Content-Length (from body_len_emit, not the user's headers).
    conn.send_buf.write(reinterpret_cast<const u8*>("Content-Length: "), 16);
    write_content_length_digits(conn, body_len_emit);
    conn.send_buf.write(reinterpret_cast<const u8*>("\r\n"), 2);
    // Default Content-Type only if the user didn't supply one AND
    // we're actually going to send a body. No-body responses (1xx /
    // 204 / 304 and redirect-style header-only responses) shouldn't
    // advertise a Content-Type — matches format_static_response.
    if (emit_default_content_type) {
        static const char kDefaultContentType[] = "Content-Type: text/plain; charset=utf-8\r\n";
        conn.send_buf.write(reinterpret_cast<const u8*>(kDefaultContentType),
                            sizeof(kDefaultContentType) - 1);
    }
    // User-supplied headers, skipping Content-Length.
    for (u32 i = 0; i < header_count; i++) {
        if (header_name_eq_literal_ci(headers[i].key_data, headers[i].key_len, "Content-Length")) {
            continue;
        }
        conn.send_buf.write(reinterpret_cast<const u8*>(headers[i].key_data), headers[i].key_len);
        conn.send_buf.write(reinterpret_cast<const u8*>(": "), 2);
        conn.send_buf.write(reinterpret_cast<const u8*>(headers[i].value_data),
                            headers[i].value_len);
        conn.send_buf.write(reinterpret_cast<const u8*>("\r\n"), 2);
    }
    // Connection + blank line.
    if (keep_alive)
        conn.send_buf.write(reinterpret_cast<const u8*>("Connection: keep-alive\r\n"), 24);
    else
        conn.send_buf.write(reinterpret_cast<const u8*>("Connection: close\r\n"), 19);
    conn.send_buf.write(reinterpret_cast<const u8*>("\r\n"), 2);

    if (body_len_emit > 0) {
        conn.send_buf.write(reinterpret_cast<const u8*>(body_data), body_len_emit);
    }
}

void prepare_early_response_state(Connection& conn) {
    const bool kHasRemainingBody =
        (conn.req_body_mode == BodyMode::ContentLength && conn.req_body_remaining > 0) ||
        (conn.req_body_mode == BodyMode::Chunked &&
         conn.req_chunk_parser.state != ChunkedParser::State::Complete);
    if (kHasRemainingBody) {
        conn.recv_buf.reset();
        conn.keep_alive = false;
    } else {
        pipeline_stash(conn);
        conn.recv_buf.reset();
    }
    if (conn.upstream_start_us == 0) conn.upstream_start_us = monotonic_us();
}

u32 consume_upstream_sent(Connection& conn) {
    const u32 kSent = conn.upstream_send_len;
    const u32 kTotal = conn.upstream_recv_buf.len();
    conn.upstream_send_len = 0;
    if (kSent >= kTotal) {
        conn.upstream_recv_buf.reset();
        return 0;
    }
    const u32 kRemaining = kTotal - kSent;
    const u8* src = conn.upstream_recv_buf.data() + kSent;
    conn.upstream_recv_buf.reset();
    u8* dst = conn.upstream_recv_buf.write_ptr();
    __builtin_memmove(dst, src, kRemaining);
    conn.upstream_recv_buf.commit(kRemaining);
    return kRemaining;
}

template void on_request_complete<EpollEventLoop>(EpollEventLoop*, Connection&, u16, u32);
template void pipeline_dispatch<EpollEventLoop>(EpollEventLoop*, Connection&);
template void on_header_received<EpollEventLoop>(void*, Connection&, IoEvent);
template void on_response_sent<EpollEventLoop>(void*, Connection&, IoEvent);
template void on_jit_wait_send_sent<EpollEventLoop>(void*, Connection&, IoEvent);
template void on_upstream_connected<EpollEventLoop>(void*, Connection&, IoEvent);
template void on_upstream_request_sent<EpollEventLoop>(void*, Connection&, IoEvent);
template void on_upstream_response<EpollEventLoop>(void*, Connection&, IoEvent);
template void on_proxy_response_sent<EpollEventLoop>(void*, Connection&, IoEvent);
template void on_response_header_sent<EpollEventLoop>(void*, Connection&, IoEvent);
template void on_response_body_recvd<EpollEventLoop>(void*, Connection&, IoEvent);
template void on_response_body_sent<EpollEventLoop>(void*, Connection&, IoEvent);
template void handle_early_upstream_recv<EpollEventLoop>(EpollEventLoop*,
                                                         Connection&,
                                                         IoEvent,
                                                         bool);
template void on_body_send_with_early_response<EpollEventLoop>(void*, Connection&, IoEvent);
template void on_request_body_sent<EpollEventLoop>(void*, Connection&, IoEvent);
template void on_early_upstream_recvd<EpollEventLoop>(void*, Connection&, IoEvent);
template void on_early_upstream_recvd_send_inflight<EpollEventLoop>(void*, Connection&, IoEvent);
template void on_request_body_recvd<EpollEventLoop>(void*, Connection&, IoEvent);
template void on_jit_request_body_recvd<EpollEventLoop>(void*, Connection&, IoEvent);
template void resume_jit_handler<EpollEventLoop>(EpollEventLoop*, Connection&);
template void respond_upstream_timeout<EpollEventLoop>(EpollEventLoop*, Connection&);
template void throttle_resume<EpollEventLoop>(EpollEventLoop*, Connection&);

template void on_request_complete<IoUringEventLoop>(IoUringEventLoop*, Connection&, u16, u32);
template void pipeline_dispatch<IoUringEventLoop>(IoUringEventLoop*, Connection&);
template void on_header_received<IoUringEventLoop>(void*, Connection&, IoEvent);
template void on_response_sent<IoUringEventLoop>(void*, Connection&, IoEvent);
template void on_jit_wait_send_sent<IoUringEventLoop>(void*, Connection&, IoEvent);
template void on_upstream_connected<IoUringEventLoop>(void*, Connection&, IoEvent);
template void on_upstream_request_sent<IoUringEventLoop>(void*, Connection&, IoEvent);
template void on_upstream_response<IoUringEventLoop>(void*, Connection&, IoEvent);
template void on_proxy_response_sent<IoUringEventLoop>(void*, Connection&, IoEvent);
template void on_response_header_sent<IoUringEventLoop>(void*, Connection&, IoEvent);
template void on_response_body_recvd<IoUringEventLoop>(void*, Connection&, IoEvent);
template void on_response_body_sent<IoUringEventLoop>(void*, Connection&, IoEvent);
template void handle_early_upstream_recv<IoUringEventLoop>(IoUringEventLoop*,
                                                           Connection&,
                                                           IoEvent,
                                                           bool);
template void on_body_send_with_early_response<IoUringEventLoop>(void*, Connection&, IoEvent);
template void on_request_body_sent<IoUringEventLoop>(void*, Connection&, IoEvent);
template void on_early_upstream_recvd<IoUringEventLoop>(void*, Connection&, IoEvent);
template void on_early_upstream_recvd_send_inflight<IoUringEventLoop>(void*, Connection&, IoEvent);
template void on_request_body_recvd<IoUringEventLoop>(void*, Connection&, IoEvent);
template void on_jit_request_body_recvd<IoUringEventLoop>(void*, Connection&, IoEvent);
template void resume_jit_handler<IoUringEventLoop>(IoUringEventLoop*, Connection&);
template void respond_upstream_timeout<IoUringEventLoop>(IoUringEventLoop*, Connection&);
template void throttle_resume<IoUringEventLoop>(IoUringEventLoop*, Connection&);

}  // namespace rut
