#include "rut/jit/runtime_helpers.h"

#include "rut/common/shard_limits.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/cache_table.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/http_parser.h"
#include <new>
#include <unordered_map>

#include <hs.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace rut;

// ── Per-invocation parse cache (parse-once) ────────────────────────
//
// The handler ABI passes raw request bytes, and historically every
// rut_helper_req_* re-parsed the whole request from scratch — a handler
// reading method + path + 2 headers parsed 4 times. This cache parses
// the request once per handler invocation and serves all req_* helpers
// from the result.
//
// Safety: a shard event loop is single-threaded and a handler invocation
// runs to completion (yield or return) before the next one starts, so a
// thread-local cache safely serves every helper call within one
// invocation. The JIT emits one rut_helper_parse_prime() call at handler
// entry that force-parses for the current request and marks the cache
// `primed`. Only a primed cache is reused by helpers; an unprimed helper
// call (e.g. a direct caller that never primed) always parses fresh and
// leaves the cache unprimed — so two direct calls on a reused buffer
// whose contents changed never return a stale parse.

namespace {

struct ParseCache {
    const u8* data = nullptr;
    u32 len = 0;
    bool primed = false;  // set only by rut_helper_parse_prime()
    bool ok = false;      // parse reached ParseStatus::Complete
    u32 header_end = 0;   // byte offset past the header block (for body)
    ParsedRequest req;
};

thread_local ParseCache t_parse_cache;

// `time.nowMicros()` is latched per handler invocation: MIR substitutes a
// local's init tree at every use site, so without the latch each use of a
// now-bound local would re-read the clock and see a different value —
// silently wrong for GCRA-style code. The latch resets at parse_prime
// (one per invocation, emitted at handler entry) so "now" is stable
// within a request and fresh across requests.
struct TimeCache {
    i64 value = 0;
    bool valid = false;
};
thread_local TimeCache t_time_cache;
thread_local const u64* t_virtual_time_us = nullptr;

// The event loop invokes one handler at a time per shard and consumes a
// terminal response before invoking another one. A thread-local buffer thus
// gives dynamic JSON stable response lifetime without borrowing send_buf (H1
// header formatting and H2 framing both reuse that buffer). Keep the cap below
// the H2 response scratch so framing overhead remains bounded as well.
struct JsonResponseScratch {
    static constexpr u32 kCapacity = 7 * 1024;
    char data[kCapacity]{};
    u32 len = 0;
    bool ok = true;
};
thread_local JsonResponseScratch t_json_response;

void json_append(const char* data, u32 len) {
    auto& out = t_json_response;
    if (!out.ok) return;
    if (data == nullptr || len > JsonResponseScratch::kCapacity - out.len) {
        out.ok = false;
        return;
    }
    if (len != 0) __builtin_memcpy(out.data + out.len, data, len);
    out.len += len;
}

// Parse (data, len) into `pc`, populating ok / header_end / req. Leaves
// pc.primed untouched — callers set it.
void parse_into(ParseCache& pc, const u8* data, u32 len) {
    pc.data = data;
    pc.len = len;
    HttpParser parser;
    parser.reset();
    pc.req.reset();
    if (parser.parse(data, len, &pc.req) == ParseStatus::Complete) {
        pc.ok = true;
        pc.header_end = parser.header_end;
    } else {
        pc.ok = false;
        pc.header_end = 0;
    }
}

// Used by all req_* helpers. Reuses the primed parse when it matches this
// (data, len) — the JIT fast path where one prime serves every helper in
// the invocation. Otherwise parses fresh and marks the cache unprimed so
// it is never reused for a subsequent (possibly aliasing) direct call.
const ParseCache& parse_cached(const u8* data, u32 len) {
    ParseCache& pc = t_parse_cache;
    if (pc.primed && pc.data == data && pc.len == len) return pc;
    parse_into(pc, data, len);
    pc.primed = false;
    return pc;
}

}  // namespace

void rut_helper_parse_prime(const u8* req_data, u32 req_len) {
    t_time_cache.valid = false;  // fresh "now" per invocation
    // Parse once for this invocation and mark the cache primed so the
    // following req_* helper calls reuse it.
    ParseCache& pc = t_parse_cache;
    parse_into(pc, req_data, req_len);
    pc.primed = true;
}

void rut_helper_parse_unprime() {
    t_time_cache.valid = false;
    // Called at handler exit so the primed parse never outlives the
    // invocation that created it. Without this, a direct caller of
    // rut_helper_req_* on the same thread that happens to reuse the
    // handler's request buffer (same address and length, different bytes)
    // could match the stale primed entry; clearing the flag forces such a
    // caller to reparse.
    t_parse_cache.primed = false;
}

void rut_helper_json_reset() {
    t_json_response.len = 0;
    t_json_response.ok = true;
}

void rut_helper_json_append_raw(const char* data, u32 len) {
    json_append(data, len);
}

void rut_helper_json_append_str(const char* data, u32 len) {
    static constexpr char kHex[] = "0123456789abcdef";
    if (data == nullptr && len != 0) {
        t_json_response.ok = false;
        return;
    }
    json_append("\"", 1);
    for (u32 i = 0; i < len && t_json_response.ok; i++) {
        const u8 c = static_cast<u8>(data[i]);
        switch (c) {
            case '"':
                json_append("\\\"", 2);
                break;
            case '\\':
                json_append("\\\\", 2);
                break;
            case '\b':
                json_append("\\b", 2);
                break;
            case '\f':
                json_append("\\f", 2);
                break;
            case '\n':
                json_append("\\n", 2);
                break;
            case '\r':
                json_append("\\r", 2);
                break;
            case '\t':
                json_append("\\t", 2);
                break;
            default:
                if (c < 0x20) {
                    const char escaped[6] = {'\\', 'u', '0', '0', kHex[c >> 4], kHex[c & 0xf]};
                    json_append(escaped, 6);
                } else {
                    json_append(data + i, 1);
                }
        }
    }
    json_append("\"", 1);
}

void rut_helper_json_append_str_list(const Str* items, u32 len) {
    if (items == nullptr && len != 0) {
        t_json_response.ok = false;
        return;
    }
    json_append("[", 1);
    for (u32 i = 0; i < len && t_json_response.ok; i++) {
        if (i != 0) json_append(",", 1);
        rut_helper_json_append_str(items[i].ptr, items[i].len);
    }
    json_append("]", 1);
}

void rut_helper_json_append_i64(i64 value) {
    char buf[32];
    const int n = snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(value));
    if (n <= 0 || static_cast<u32>(n) >= sizeof(buf)) {
        t_json_response.ok = false;
        return;
    }
    json_append(buf, static_cast<u32>(n));
}

void rut_helper_json_append_bool(u8 value) {
    json_append(value != 0 ? "true" : "false", value != 0 ? 4 : 5);
}

const char* rut_helper_json_capture_data() {
    return t_json_response.ok ? t_json_response.data : nullptr;
}

u32 rut_helper_json_capture_len() {
    return t_json_response.ok ? t_json_response.len : 0xffffffffu;
}

void rut_helper_json_finish(void* ctx) {
    if (ctx == nullptr) return;
    auto* hctx = static_cast<jit::HandlerCtx*>(ctx);
    hctx->response_body_data = nullptr;
    hctx->response_body_len = 0;
    hctx->response_body_valid = 0;
    if (!t_json_response.ok) return;
    hctx->response_body_data = t_json_response.data;
    hctx->response_body_len = t_json_response.len;
    hctx->response_body_valid = 1;
}

// ── Request Access ─────────────────────────────────────────────────

void rut_helper_req_path(const u8* req_data, u32 req_len, const char** out_ptr, u32* out_len) {
    const ParseCache& pc = parse_cached(req_data, req_len);
    if (pc.ok) {
        *out_ptr = pc.req.path.ptr;
        *out_len = pc.req.path.len;
        return;
    }

    // Fallback: minimal manual extraction.
    // Skip method (find first space), extract path until next space.
    u32 i = 0;
    while (i < req_len && req_data[i] != ' ') i++;
    if (i >= req_len) {
        *out_ptr = "/";
        *out_len = 1;
        return;
    }
    i++;  // skip space
    u32 path_start = i;
    while (i < req_len && req_data[i] != ' ' && req_data[i] != '\r') {
        i++;
    }
    *out_ptr = reinterpret_cast<const char*>(req_data + path_start);
    *out_len = i - path_start;
}

void rut_helper_req_path_only(const u8* req_data, u32 req_len, const char** out_ptr, u32* out_len) {
    rut_helper_req_path(req_data, req_len, out_ptr, out_len);
    if (!out_ptr || !out_len || !*out_ptr) return;
    const char* path = *out_ptr;
    const u32 path_len = *out_len;
    for (u32 i = 0; i < path_len; i++) {
        if (path[i] == '?' || path[i] == '#') {
            *out_len = i;
            return;
        }
    }
}

void rut_helper_req_body(const u8* req_data, u32 req_len, const char** out_ptr, u32* out_len) {
    *out_ptr = "";
    *out_len = 0;

    const ParseCache& pc = parse_cached(req_data, req_len);
    if (!pc.ok) return;
    const ParsedRequest& req = pc.req;
    const u32 available = req_len - pc.header_end;
    if (available == 0) return;

    if (req.chunked) return;
    // Without a Content-Length the body framing is undefined: in HTTP/1
    // keep-alive the trailing octets are the next pipelined request, not this
    // request's body. The HTTP/2 bridge synthesizes a Content-Length for
    // DATA-only bodies (see h2_finish_body) so they take the path below.
    if (!req.has_content_length) return;
    if (req.content_length == 0 || available < req.content_length) return;

    *out_ptr = reinterpret_cast<const char*>(req_data + pc.header_end);
    *out_len = req.content_length;
}

void rut_helper_req_http_version(const u8* req_data,
                                 u32 req_len,
                                 const char** out_ptr,
                                 u32* out_len) {
    *out_ptr = "";
    *out_len = 0;

    const ParseCache& pc = parse_cached(req_data, req_len);
    if (!pc.ok) return;
    const ParsedRequest& req = pc.req;

    if (req.version == HttpVersion::Http10) {
        *out_ptr = "HTTP/1.0";
        *out_len = 8;
        return;
    }
    if (req.version == HttpVersion::Http11) {
        *out_ptr = "HTTP/1.1";
        *out_len = 8;
        return;
    }
}

u8 rut_helper_req_flag(const u8* req_data, u32 req_len, u8 flag) {
    const ParseCache& pc = parse_cached(req_data, req_len);
    if (!pc.ok) return 0;
    const ParsedRequest& req = pc.req;
    if (flag == 0) return req.keep_alive ? 1 : 0;
    if (flag == 1) return req.chunked ? 1 : 0;
    if (flag == 2) return req.has_content_length ? 1 : 0;
    if (flag == 3) return req.version == HttpVersion::Http10 ? 1 : 0;
    if (flag == 4) return req.version == HttpVersion::Http11 ? 1 : 0;
    return 0;
}

u8 rut_helper_req_method(const u8* req_data, u32 req_len) {
    const ParseCache& pc = parse_cached(req_data, req_len);
    if (pc.ok) return static_cast<u8>(pc.req.method);

    // Fallback: return Unknown
    return static_cast<u8>(HttpMethod::Unknown);
}

void rut_helper_req_header(const u8* req_data,
                           u32 req_len,
                           const char* name,
                           u32 name_len,
                           u8* out_has_value,
                           const char** out_ptr,
                           u32* out_len) {
    *out_has_value = 0;
    *out_ptr = nullptr;
    *out_len = 0;

    const ParseCache& pc = parse_cached(req_data, req_len);
    if (!pc.ok) return;
    const ParsedRequest& req = pc.req;

    // Linear scan through parsed headers (case-insensitive name match).
    for (u32 i = 0; i < req.header_count; i++) {
        auto& h = req.headers[i];
        if (h.name.len != name_len) continue;
        bool match = true;
        for (u32 j = 0; j < name_len; j++) {
            u8 a = static_cast<u8>(h.name.ptr[j]);
            u8 b = static_cast<u8>(name[j]);
            // ASCII case-insensitive comparison
            if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
            if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
            if (a != b) {
                match = false;
                break;
            }
        }
        if (match) {
            *out_has_value = 1;
            *out_ptr = h.value.ptr;
            *out_len = h.value.len;
            return;
        }
    }
}

// forward(set_path:) — record the path override on the connection. The proxy
// (on_upstream_connected) rewrites the request line from this before forwarding.
void rut_helper_req_set_path(void* conn, const char* path, u32 len) {
    auto* c = static_cast<ConnectionBase*>(conn);
    c->req_path_overridden = true;
    c->req_path_override = Str{path, len};
}

static void record_req_header(
    void* conn, const char* name, u32 nlen, const char* val, u32 vlen, bool append) {
    auto* c = static_cast<ConnectionBase*>(conn);
    // Bounded record. The DSL frontend caps + dedupes entries so overflow is
    // unreachable from compiled .rut, but a direct-RIR route can emit more than the
    // table holds — flag it so apply_request_header_overrides fails the request
    // closed rather than silently dropping (and forwarding without) the override.
    if (c->req_header_override_count >= ConnectionBase::kMaxReqHeaderOverrides) {
        c->req_header_override_overflow = true;
        return;
    }
    const u8 index = c->req_header_override_count++;
    auto& o = c->req_header_overrides[index];
    o.name = Str{name, nlen};
    o.value = Str{val, vlen};
    const u16 bit = static_cast<u16>(1u << index);
    if (append)
        c->req_header_append_mask |= bit;
    else
        c->req_header_append_mask &= static_cast<u16>(~bit);
}

void rut_helper_req_set_header(void* conn, const char* name, u32 nlen, const char* val, u32 vlen) {
    record_req_header(conn, name, nlen, val, vlen, false);
}

void rut_helper_req_add_header(void* conn, const char* name, u32 nlen, const char* val, u32 vlen) {
    record_req_header(conn, name, nlen, val, vlen, true);
}

static bool ascii_header_name_eq(Str h, const char* name, u32 name_len) {
    if (h.len != name_len) return false;
    for (u32 j = 0; j < name_len; j++) {
        u8 a = static_cast<u8>(h.ptr[j]);
        u8 b = static_cast<u8>(name[j]);
        if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
        if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
        if (a != b) return false;
    }
    return true;
}

static void record_resp_header(void* ctx,
                               const char* name,
                               u32 nlen,
                               const char* val,
                               u32 vlen,
                               jit::ResponseHeaderMutationMode mode) {
    if (ctx == nullptr) return;
    auto* hctx = static_cast<jit::HandlerCtx*>(ctx);
    if (hctx->response_header_pending_count >= jit::kMaxResponseHeaderMutations) {
        hctx->response_header_pending_overflow = true;
        return;
    }
    auto& mutation = hctx->response_header_mutations[hctx->response_header_pending_count++];
    mutation.name = {name, nlen};
    mutation.value = {val, vlen};
    mutation.mode = mode;
}

void rut_helper_resp_set_header(void* ctx, const char* name, u32 nlen, const char* val, u32 vlen) {
    record_resp_header(ctx, name, nlen, val, vlen, jit::ResponseHeaderMutationMode::Set);
}

void rut_helper_resp_add_header(void* ctx, const char* name, u32 nlen, const char* val, u32 vlen) {
    record_resp_header(ctx, name, nlen, val, vlen, jit::ResponseHeaderMutationMode::Add);
}

void rut_helper_resp_remove_header(void* ctx, const char* name, u32 nlen) {
    record_resp_header(ctx, name, nlen, nullptr, 0, jit::ResponseHeaderMutationMode::Remove);
}

void rut_helper_resp_set_status(void* ctx, i32 status) {
    if (ctx == nullptr) return;
    auto* hctx = static_cast<jit::HandlerCtx*>(ctx);
    hctx->response_status_pending_set = true;
    hctx->response_status_pending_invalid = status < 100 || status > 599;
    hctx->response_status_pending =
        hctx->response_status_pending_invalid ? 0 : static_cast<u16>(status);
}

void rut_helper_resp_set_body(void* ctx, const char* body, u32 len) {
    if (ctx == nullptr) return;
    auto* hctx = static_cast<jit::HandlerCtx*>(ctx);
    hctx->response_body_pending_set = true;
    hctx->response_body_pending_overflow =
        body == nullptr || len > jit::kMaxResponseBodyMutationBytes;
    if (hctx->response_body_pending_overflow) {
        hctx->response_body_pending_data = nullptr;
        hctx->response_body_pending_len = 0;
        return;
    }
    if (len != 0) __builtin_memmove(hctx->response_body_pending_storage, body, len);
    hctx->response_body_pending_data = hctx->response_body_pending_storage;
    hctx->response_body_pending_len = len;
}

void rut_helper_resp_commit_headers(void* ctx) {
    if (ctx == nullptr) return;
    auto* hctx = static_cast<jit::HandlerCtx*>(ctx);
    hctx->response_header_count = hctx->response_header_pending_count;
    hctx->response_header_overflow = hctx->response_header_pending_overflow;
    hctx->response_status = hctx->response_status_pending;
    hctx->response_status_set = hctx->response_status_pending_set;
    hctx->response_status_invalid = hctx->response_status_pending_invalid;
    hctx->response_body_mutation_data = hctx->response_body_pending_data;
    hctx->response_body_mutation_len = hctx->response_body_pending_len;
    hctx->response_body_mutation_set = hctx->response_body_pending_set;
    hctx->response_body_mutation_overflow = hctx->response_body_pending_overflow;
}

void rut_helper_resp_header(void* ctx,
                            const char* name,
                            u32 nlen,
                            u8 fallback_has,
                            const char* fallback_ptr,
                            u32 fallback_len,
                            u8* out_has,
                            const char** out_ptr,
                            u32* out_len) {
    *out_has = fallback_has;
    *out_ptr = fallback_has ? fallback_ptr : nullptr;
    *out_len = fallback_has ? fallback_len : 0;
    if (ctx == nullptr) return;
    auto* hctx = static_cast<jit::HandlerCtx*>(ctx);
    for (u32 i = 0; i < hctx->response_header_pending_count; i++) {
        const auto& mutation = hctx->response_header_mutations[i];
        if (!ascii_header_name_eq(mutation.name, name, nlen)) continue;
        if (mutation.mode == jit::ResponseHeaderMutationMode::Remove) {
            *out_has = 0;
            *out_ptr = nullptr;
            *out_len = 0;
        } else if (mutation.mode == jit::ResponseHeaderMutationMode::Set || !*out_has) {
            *out_has = 1;
            *out_ptr = mutation.value.ptr;
            *out_len = mutation.value.len;
        }
    }
}

void rut_helper_req_cookie(const u8* req_data,
                           u32 req_len,
                           const char* name,
                           u32 name_len,
                           u8* out_has_value,
                           const char** out_ptr,
                           u32* out_len) {
    *out_has_value = 0;
    *out_ptr = nullptr;
    *out_len = 0;
    if (!name || name_len == 0) return;

    const ParseCache& pc = parse_cached(req_data, req_len);
    if (!pc.ok) return;
    const ParsedRequest& req = pc.req;

    for (u32 i = 0; i < req.header_count; i++) {
        const auto& h = req.headers[i];
        if (!ascii_header_name_eq(h.name, "Cookie", 6)) continue;
        const char* p = h.value.ptr;
        const u32 n = h.value.len;
        u32 pos = 0;
        while (pos < n) {
            while (pos < n && (p[pos] == ' ' || p[pos] == '\t' || p[pos] == ';')) pos++;
            const u32 key_start = pos;
            while (pos < n && p[pos] != '=' && p[pos] != ';') pos++;
            u32 key_end = pos;
            while (key_end > key_start && (p[key_end - 1] == ' ' || p[key_end - 1] == '\t'))
                key_end--;
            if (pos >= n || p[pos] != '=') {
                while (pos < n && p[pos] != ';') pos++;
                continue;
            }
            pos++;
            const u32 value_start = pos;
            while (pos < n && p[pos] != ';') pos++;
            u32 value_end = pos;
            while (value_end > value_start && (p[value_end - 1] == ' ' || p[value_end - 1] == '\t'))
                value_end--;
            const u32 key_len = key_end - key_start;
            if (key_len == name_len && memcmp(p + key_start, name, name_len) == 0) {
                *out_has_value = 1;
                *out_ptr = p + value_start;
                *out_len = value_end - value_start;
                return;
            }
        }
    }
}

void rut_helper_req_query(const u8* req_data,
                          u32 req_len,
                          const char* name,
                          u32 name_len,
                          u8* out_has_value,
                          const char** out_ptr,
                          u32* out_len) {
    *out_has_value = 0;
    *out_ptr = nullptr;
    *out_len = 0;
    if (!name || name_len == 0) return;

    const ParseCache& pc = parse_cached(req_data, req_len);
    if (!pc.ok) return;
    const ParsedRequest& req = pc.req;
    if (req.path.len == 0) return;

    const char* path = req.path.ptr;
    u32 path_len = req.path.len;
    u32 path_pos = 0;
    while (path_pos < path_len && path[path_pos] != '?' && path[path_pos] != '#') {
        path_pos++;
    }
    if (path_pos >= path_len || path[path_pos] != '?') return;
    if (path_pos + 1 >= path_len) return;

    const char* query = path + path_pos + 1;
    u32 query_len = path_len - path_pos - 1;
    for (u32 i = 0; i < query_len; i++) {
        if (query[i] == '#') {
            query_len = i;
            break;
        }
    }
    u32 pos = 0;
    while (pos < query_len) {
        while (pos < query_len && query[pos] == '&') pos++;
        const u32 key_start = pos;
        while (pos < query_len && query[pos] != '&' && query[pos] != '=') pos++;
        const u32 key_end = pos;
        u32 val_start = key_end;
        u32 val_end = key_end;
        if (pos < query_len && query[pos] == '=') {
            pos++;
            val_start = pos;
            while (pos < query_len && query[pos] != '&') pos++;
            val_end = pos;
        }
        const u32 key_len = key_end - key_start;
        if (key_len == name_len && memcmp(query + key_start, name, name_len) == 0) {
            *out_has_value = 1;
            *out_ptr = query + val_start;
            *out_len = val_end - val_start;
            return;
        }
    }
}

u32 rut_helper_req_query_all(
    const u8* req_data, u32 req_len, const char* name, u32 name_len, Str* out, u32 cap) {
    if (!name || name_len == 0) return 0;
    const ParseCache& pc = parse_cached(req_data, req_len);
    if (!pc.ok || pc.req.path.len == 0) return 0;

    const char* path = pc.req.path.ptr;
    const u32 path_len = pc.req.path.len;
    u32 path_pos = 0;
    while (path_pos < path_len && path[path_pos] != '?' && path[path_pos] != '#') path_pos++;
    if (path_pos >= path_len || path[path_pos] != '?' || path_pos + 1 >= path_len) return 0;

    const char* query = path + path_pos + 1;
    u32 query_len = path_len - path_pos - 1;
    for (u32 i = 0; i < query_len; i++) {
        if (query[i] == '#') {
            query_len = i;
            break;
        }
    }

    u32 count = 0;
    u32 pos = 0;
    while (pos < query_len) {
        while (pos < query_len && query[pos] == '&') pos++;
        const u32 key_start = pos;
        while (pos < query_len && query[pos] != '&' && query[pos] != '=') pos++;
        const u32 key_end = pos;
        u32 val_start = key_end;
        u32 val_end = key_end;
        if (pos < query_len && query[pos] == '=') {
            val_start = ++pos;
            while (pos < query_len && query[pos] != '&') pos++;
            val_end = pos;
        }
        if (key_end - key_start == name_len && memcmp(query + key_start, name, name_len) == 0) {
            if (out && count < cap) out[count] = {query + val_start, val_end - val_start};
            count++;
        }
    }
    return count;
}

u32 rut_helper_req_header_all(
    const u8* req_data, u32 req_len, const char* name, u32 name_len, Str* out, u32 cap) {
    if (!name || name_len == 0) return 0;
    const ParseCache& pc = parse_cached(req_data, req_len);
    if (!pc.ok) return 0;
    u32 count = 0;
    for (u32 i = 0; i < pc.req.header_count; i++) {
        const auto& header = pc.req.headers[i];
        if (!ascii_header_name_eq(header.name, name, name_len)) continue;
        if (out && count < cap) out[count] = header.value;
        count++;
    }
    return count;
}

void rut_helper_req_query_string(
    const u8* req_data, u32 req_len, u8* out_has_value, const char** out_ptr, u32* out_len) {
    *out_has_value = 0;
    *out_ptr = nullptr;
    *out_len = 0;

    const ParseCache& pc = parse_cached(req_data, req_len);
    if (!pc.ok) return;
    const ParsedRequest& req = pc.req;
    if (req.path.len == 0) return;

    const char* path = req.path.ptr;
    const u32 path_len = req.path.len;
    u32 pos = 0;
    while (pos < path_len && path[pos] != '?' && path[pos] != '#') pos++;
    if (pos >= path_len || path[pos] != '?') return;

    const char* query = path + pos + 1;
    u32 query_len = path_len - pos - 1;
    for (u32 i = 0; i < query_len; i++) {
        if (query[i] == '#') {
            query_len = i;
            break;
        }
    }

    *out_has_value = 1;
    *out_ptr = query;
    *out_len = query_len;
}

void rut_helper_req_param(
    void* ctx, const char* name, u32 name_len, const char** out_ptr, u32* out_len) {
    *out_ptr = "";
    *out_len = 0;
    if (!ctx || !name) return;
    auto* hctx = static_cast<jit::HandlerCtx*>(ctx);
    const u32 n =
        hctx->route_param_count < kMaxRouteParams ? hctx->route_param_count : kMaxRouteParams;
    for (u32 i = 0; i < n; i++) {
        const RouteParam& p = hctx->route_params[i];
        if (p.name_len != name_len) continue;
        bool match = true;
        for (u32 j = 0; j < name_len; j++) {
            if (p.name[j] != name[j]) {
                match = false;
                break;
            }
        }
        if (!match) continue;
        *out_ptr = p.value ? p.value : "";
        *out_len = p.value ? p.value_len : 0;
        return;
    }
}

u32 rut_helper_req_remote_addr(void* conn) {
    auto* c = static_cast<Connection*>(conn);
    return c->peer_addr;
}

i64 rut_helper_time_now_micros() {
    TimeCache& tc = t_time_cache;
    if (!tc.valid) {
        tc.value = static_cast<i64>(t_virtual_time_us != nullptr ? *t_virtual_time_us
                                                                 : rut::monotonic_us());
        tc.valid = true;
    }
    return tc.value;
}

const u64* rut_helper_time_set_virtual_clock(const u64* now_us) {
    const u64* previous = t_virtual_time_us;
    t_virtual_time_us = now_us;
    t_time_cache.valid = false;
    return previous;
}

void rut_helper_time_unlatch() {
    t_time_cache.valid = false;
}

u64 rut_helper_req_content_length(const u8* req_data, u32 req_len) {
    const ParseCache& pc = parse_cached(req_data, req_len);
    if (!pc.ok) return 0;
    return pc.req.has_content_length ? pc.req.content_length : 0;
}

// ── Cache state ────────────────────────────────────────────────────
// One thread == one shard, so `thread_local` gives per-shard tables that
// both backends and direct-call tests reach without touching the handler
// ABI (the RateLimiter precedent). Tables (re)build lazily against the
// process registry: first touch allocates; a hot-reload capacity change is
// detected by the rounded-capacity compare and resets that instance's state
// (documented); an unchanged capacity persists across config swaps because
// the swap never touches thread-locals.
// Owns the per-shard tables so thread exit unmaps them — a bare
// thread_local CacheTable array has a trivial destructor and would leak
// the mmaps on shard stop/join/restart flows.
namespace rut {
struct CacheLocalState {
    struct ShardTables {
        CacheTable tables[CacheRegistry::kMaxInstances];
        u64 identities[CacheRegistry::kMaxInstances] = {};
        u32 birth_generations[CacheRegistry::kMaxInstances] = {};
        u32 generation = 0;
        bool alloc_failed_logged[CacheRegistry::kMaxInstances] = {};
        void reset() {
            for (auto& t : tables) t.destroy();
            for (u32 i = 0; i < CacheRegistry::kMaxInstances; i++) {
                identities[i] = 0;
                birth_generations[i] = 0;
                alloc_failed_logged[i] = false;
            }
            generation = 0;
        }
        ~ShardTables() { reset(); }
    };

    ShardTables shards[kMaxShards];
};
}  // namespace rut

namespace {

thread_local rut::CacheLocalState t_default_cache_state;
thread_local rut::CacheLocalState* t_active_cache_state = &t_default_cache_state;
thread_local rut::u32 t_active_cache_shard = 0;

rut::CacheLocalState::ShardTables& shard_cache_tables() {
    return t_active_cache_state->shards[t_active_cache_shard];
}

rut::CacheTable* cache_table_for(rut::u32 instance) {
    rut::CacheLocalState::ShardTables& t_state = shard_cache_tables();
    auto* t_tables = t_state.tables;
    auto* t_identities = t_state.identities;
    auto* t_birth_generations = t_state.birth_generations;
    rut::u32& t_generation = t_state.generation;
    auto* t_alloc_failed_logged = t_state.alloc_failed_logged;
    auto& reg = rut::cache_registry();
    // Seqlock-style snapshot: the acquire on `generation` orders the
    // descriptor loads AFTER the bump we observed, but a publish running
    // concurrently could still overwrite them before we read — so re-check
    // the generation after reading and retry. Without this, a reader could
    // pair the old generation with the NEXT publish's half-written
    // descriptors (e.g. observe count == 0 mid-publish and degrade a live
    // handler to miss/no-op, or build a table against a future capacity).
    rut::u32 gen = 0;
    rut::u32 live_count = 0;
    rut::u64 snap_seed = 0;
    rut::u32 snap_caps[rut::CacheRegistry::kMaxInstances];
    rut::u64 snap_idents[rut::CacheRegistry::kMaxInstances];
    rut::u32 snap_births[rut::CacheRegistry::kMaxInstances];
    for (int tries = 0;; tries++) {
        gen = reg.generation.load(std::memory_order_acquire);
        if (gen == 0) return nullptr;  // nothing published yet
        if ((gen & 1u) == 0) {         // odd = publish in progress, retry
            live_count = reg.count.load(std::memory_order_relaxed);
            snap_seed = reg.seed.load(std::memory_order_relaxed);
            for (rut::u32 i = 0; i < rut::CacheRegistry::kMaxInstances; i++) {
                snap_caps[i] = reg.capacities[i].load(std::memory_order_relaxed);
                snap_idents[i] = reg.identities[i].load(std::memory_order_relaxed);
                snap_births[i] = reg.birth_generations[i].load(std::memory_order_relaxed);
            }
            // A seqlock reader needs a read barrier before validation. The
            // release half keeps the descriptor reads above the fence; the
            // acquire half keeps the validation read below it. Otherwise a
            // weak CPU/compiler may validate the old even generation first
            // and only then consume descriptors from the next publication.
            std::atomic_thread_fence(std::memory_order_acq_rel);
            if (reg.generation.load(std::memory_order_acquire) == gen) break;
        }
        if (tries >= 8) return nullptr;  // publish storm — treat as miss
    }
    if (gen != t_generation) {
        // A publish happened since this shard last looked. Drop tables
        // whose instance disappeared, moved (identity change from a
        // rename/reorder), or resized — reusing them would read another
        // logical cache's entries; keeping stale ones would leak the mmap.
        // Identical declarations keep their table (state persists across
        // reloads, documented).
        for (rut::u32 i = 0; i < rut::CacheRegistry::kMaxInstances; i++) {
            if (t_tables[i].slots == nullptr) continue;
            // Birth-generation compare closes the skipped-generation hole:
            // if the instance was removed and re-added while this shard was
            // idle (A→B→C), C's birth differs from the birth this table was
            // built under, even though identity and capacity match A's.
            const bool live =
                i < live_count && snap_idents[i] == t_identities[i] &&
                snap_births[i] == t_birth_generations[i] &&
                rut::CacheTable::round_capacity(snap_caps[i]) == t_tables[i].slot_count;
            if (!live) {
                t_tables[i].destroy();
                t_identities[i] = 0;
                t_birth_generations[i] = 0;
            }
        }
        t_generation = gen;
    }
    if (instance >= live_count) return nullptr;
    const rut::u32 cap = snap_caps[instance];
    if (cap == 0) return nullptr;
    rut::CacheTable& t = t_tables[instance];
    if (t.slot_count != rut::CacheTable::round_capacity(cap)) {
        if (!t.init(cap, snap_seed)) {
            // Fail VISIBLY (fixed-capacity axiom): a silent nullptr would
            // degrade every cache op on this shard to miss/no-op — for a
            // rate limit that silently admits all traffic. Fail-closed
            // needs an error path in the handler ABI; recorded follow-up.
            if (!t_alloc_failed_logged[instance]) {
                t_alloc_failed_logged[instance] = true;
                fprintf(stderr,
                        "rut: cache table mmap failed (instance %u, capacity %u) — cache ops "
                        "degrade to miss/no-op on this shard\n",
                        instance,
                        cap);
            }
            return nullptr;
        }
        t_identities[instance] = snap_idents[instance];
        t_birth_generations[instance] = snap_births[instance];
        t_alloc_failed_logged[instance] = false;
    }
    return &t;
}
}  // namespace

void rut_helper_cache_get(u32 instance, u32 key_ip, u8* out_has, i64* out_val) {
    rut::CacheTable* t = cache_table_for(instance);
    i64 v = 0;
    if (t != nullptr && t->get(key_ip, &v)) {
        *out_has = 1;
        *out_val = v;
        return;
    }
    *out_has = 0;
    *out_val = 0;
}

void rut_helper_cache_set(u32 instance, u32 key_ip, i64 val) {
    rut::CacheTable* t = cache_table_for(instance);
    if (t != nullptr) t->set(key_ip, val);
}

u32 rut_helper_cache_select_local_shard(u32 shard_id) {
    const u32 previous = t_active_cache_shard;
    if (shard_id < rut::kMaxShards) t_active_cache_shard = shard_id;
    return previous;
}

rut::CacheLocalState* rut_helper_cache_select_local_state(rut::CacheLocalState* state) {
    rut::CacheLocalState* previous =
        t_active_cache_state == &t_default_cache_state ? nullptr : t_active_cache_state;
    t_active_cache_state = state != nullptr ? state : &t_default_cache_state;
    return previous;
}

rut::CacheLocalState* rut_helper_cache_create_local_state() {
    return new (std::nothrow) rut::CacheLocalState{};
}

void rut_helper_cache_destroy_local_state(rut::CacheLocalState* state) {
    if (state == nullptr) return;
    if (t_active_cache_state == state) t_active_cache_state = &t_default_cache_state;
    delete state;
}

void rut_helper_cache_reset_state(rut::CacheLocalState* state) {
    if (state == nullptr) return;
    for (auto& shard : state->shards) shard.reset();
}

void rut_helper_cache_reset_local_state() {
    for (auto& state : t_active_cache_state->shards) state.reset();
}

// ── String Operations ──────────────────────────────────────────────

u8 rut_helper_str_has_prefix(const char* s, u32 s_len, const char* pfx, u32 pfx_len) {
    if (pfx_len > s_len) return 0;
    for (u32 i = 0; i < pfx_len; i++) {
        if (s[i] != pfx[i]) return 0;
    }
    return 1;
}

u8 rut_helper_str_eq(const char* a, u32 a_len, const char* b, u32 b_len) {
    if (a_len != b_len) return 0;
    for (u32 i = 0; i < a_len; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

i32 rut_helper_str_cmp(const char* a, u32 a_len, const char* b, u32 b_len) {
    u32 n = a_len < b_len ? a_len : b_len;
    for (u32 i = 0; i < n; i++) {
        unsigned char ac = static_cast<unsigned char>(a[i]);
        unsigned char bc = static_cast<unsigned char>(b[i]);
        if (ac < bc) return -1;
        if (ac > bc) return 1;
    }
    if (a_len < b_len) return -1;
    if (a_len > b_len) return 1;
    return 0;
}

namespace {

struct RegexMatchCtx {
    u32 len = 0;
    bool matched = false;
};

struct RegexHandle {
    hs_database_t* db = nullptr;
    u64 generation = 0;
    u32 active_scans = 0;
    bool closing = false;
    pthread_mutex_t mutex = {};
    pthread_cond_t no_active_scans = {};
};

struct RegexScratchSlot {
    const void* handle = nullptr;
    u64 generation = 0;
    hs_scratch_t* scratch = nullptr;
};

struct RegexScratchCache {
    RegexScratchSlot* slots = nullptr;
    u32 count = 0;
    u32 cap = 0;
    std::unordered_map<u64, u32> generation_to_index;
    RegexScratchCache* next = nullptr;
    RegexScratchCache* prev = nullptr;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    RegexScratchCache();

    ~RegexScratchCache() {
        unregister_cache();
        for (u32 i = 0; i < count; i++) {
            if (slots[i].scratch) hs_free_scratch(slots[i].scratch);
        }
        free(slots);
        pthread_mutex_destroy(&mutex);
    }

    bool reserve(u32 min_cap) {
        if (cap >= min_cap) return true;
        u32 new_cap = cap ? cap * 2 : 32;
        while (new_cap < min_cap) new_cap *= 2;
        void* p = realloc(slots, sizeof(RegexScratchSlot) * new_cap);
        if (!p) return false;
        slots = static_cast<RegexScratchSlot*>(p);
        for (u32 i = cap; i < new_cap; i++) {
            slots[i] = {};
        }
        cap = new_cap;
        return true;
    }

    void remove_at(u32 idx) {
        if (idx >= count) return;
        const u64 generation = slots[idx].generation;
        if (slots[idx].scratch) hs_free_scratch(slots[idx].scratch);
        generation_to_index.erase(generation);
        count--;
        if (idx != count) {
            slots[idx] = slots[count];
            generation_to_index[slots[idx].generation] = idx;
        }
        slots[count] = {};
    }

    hs_scratch_t* get(const RegexHandle* handle) {
        const auto iter = generation_to_index.find(handle->generation);
        if (iter != generation_to_index.end()) {
            return slots[iter->second].scratch;
        }
        hs_scratch_t* scratch = nullptr;
        if (hs_alloc_scratch(handle->db, &scratch) != HS_SUCCESS || !scratch) return nullptr;
        if (!reserve(count + 1)) {
            hs_free_scratch(scratch);
            return nullptr;
        }
        slots[count] = {handle, handle->generation, scratch};
        generation_to_index[handle->generation] = count;
        count++;
        return scratch;
    }

    void prune_handle(const RegexHandle* handle);
    void unregister_cache();
};

struct LiveRegexHandle {
    const void* handle = nullptr;
    u64 generation = 0;
};

thread_local RegexScratchCache t_regex_scratch_cache;
thread_local char t_regex_compile_error[256] = "";
u64 g_regex_generation = 1;

LiveRegexHandle* g_regex_live_handles = nullptr;
u32 g_regex_live_count = 0;
u32 g_regex_live_cap = 0;
pthread_mutex_t g_regex_registry_mutex = PTHREAD_MUTEX_INITIALIZER;

RegexScratchCache* g_regex_caches = nullptr;
pthread_mutex_t g_regex_cache_list_mutex = PTHREAD_MUTEX_INITIALIZER;

RegexScratchCache::RegexScratchCache() {
    pthread_mutex_lock(&g_regex_cache_list_mutex);
    next = g_regex_caches;
    if (next) next->prev = this;
    g_regex_caches = this;
    pthread_mutex_unlock(&g_regex_cache_list_mutex);
}

static bool register_regex_handle(RegexHandle* handle) {
    pthread_mutex_lock(&g_regex_registry_mutex);
    handle->generation = g_regex_generation++;
    if (g_regex_live_count == g_regex_live_cap) {
        u32 next_cap = g_regex_live_cap ? g_regex_live_cap * 2 : 32;
        void* p = realloc(g_regex_live_handles, sizeof(LiveRegexHandle) * next_cap);
        if (p) {
            g_regex_live_handles = static_cast<LiveRegexHandle*>(p);
            g_regex_live_cap = next_cap;
        }
    }
    if (g_regex_live_count < g_regex_live_cap) {
        g_regex_live_handles[g_regex_live_count++] = {handle, handle->generation};
        pthread_mutex_unlock(&g_regex_registry_mutex);
        return true;
    }
    pthread_mutex_unlock(&g_regex_registry_mutex);
    return false;
}

static bool begin_regex_scan(RegexHandle* handle, hs_database_t** db) {
    pthread_mutex_lock(&handle->mutex);
    if (handle->closing || !handle->db) {
        pthread_mutex_unlock(&handle->mutex);
        return false;
    }
    handle->active_scans++;
    *db = handle->db;
    pthread_mutex_unlock(&handle->mutex);
    return true;
}

static void end_regex_scan(RegexHandle* handle) {
    pthread_mutex_lock(&handle->mutex);
    if (handle->active_scans) handle->active_scans--;
    if (handle->closing && handle->active_scans == 0) {
        pthread_cond_signal(&handle->no_active_scans);
    }
    pthread_mutex_unlock(&handle->mutex);
}

static void unregister_regex_handle(const RegexHandle* handle) {
    pthread_mutex_lock(&g_regex_registry_mutex);
    for (u32 i = 0; i < g_regex_live_count; i++) {
        if (g_regex_live_handles[i].handle == handle &&
            g_regex_live_handles[i].generation == handle->generation) {
            g_regex_live_count--;
            if (i != g_regex_live_count)
                g_regex_live_handles[i] = g_regex_live_handles[g_regex_live_count];
            break;
        }
    }
    pthread_mutex_unlock(&g_regex_registry_mutex);

    pthread_mutex_lock(&g_regex_cache_list_mutex);
    for (RegexScratchCache* cache = g_regex_caches; cache; cache = cache->next) {
        pthread_mutex_lock(&cache->mutex);
        cache->prune_handle(handle);
        pthread_mutex_unlock(&cache->mutex);
    }
    pthread_mutex_unlock(&g_regex_cache_list_mutex);
}

void RegexScratchCache::prune_handle(const RegexHandle* handle) {
    const auto iter = generation_to_index.find(handle->generation);
    if (iter != generation_to_index.end() && iter->second < count &&
        slots[iter->second].handle == handle) {
        remove_at(iter->second);
    }
}

void RegexScratchCache::unregister_cache() {
    pthread_mutex_lock(&g_regex_cache_list_mutex);
    if (prev) {
        prev->next = next;
    } else if (g_regex_caches == this) {
        g_regex_caches = next;
    }
    if (next) next->prev = prev;
    next = nullptr;
    prev = nullptr;
    pthread_mutex_unlock(&g_regex_cache_list_mutex);
}

static int on_full_regex_match(
    unsigned int, unsigned long long, unsigned long long to, unsigned int, void* context) {
    auto* ctx = static_cast<RegexMatchCtx*>(context);
    if (to == ctx->len) {
        ctx->matched = true;
        return 1;
    }
    return 0;
}

static void regex_runtime_error(const char* msg) {
    fprintf(stderr, "rut regex runtime error: %s\n", msg);
}

static void set_regex_compile_error(const char* msg) {
    if (!msg) msg = "regex compilation failed";
    snprintf(t_regex_compile_error, sizeof(t_regex_compile_error), "%s", msg);
}

}  // namespace

void* rut_helper_regex_compile(const char* pattern, u32 pattern_len) {
    t_regex_compile_error[0] = '\0';
    if (!pattern) {
        set_regex_compile_error("missing regex pattern");
        return nullptr;
    }
    char* nul_pattern = static_cast<char*>(malloc(static_cast<size_t>(pattern_len) + 7));
    if (!nul_pattern) {
        set_regex_compile_error("out of memory while preparing regex pattern");
        return nullptr;
    }
    nul_pattern[0] = '^';
    nul_pattern[1] = '(';
    nul_pattern[2] = '?';
    nul_pattern[3] = ':';
    memcpy(nul_pattern + 4, pattern, pattern_len);
    nul_pattern[pattern_len + 4] = ')';
    nul_pattern[pattern_len + 5] = '$';
    nul_pattern[pattern_len + 6] = '\0';

    hs_database_t* db = nullptr;
    hs_compile_error_t* compile_error = nullptr;
    hs_error_t rc =
        hs_compile(nul_pattern, HS_FLAG_SINGLEMATCH, HS_MODE_BLOCK, nullptr, &db, &compile_error);
    free(nul_pattern);
    if (rc != 0 || !db) {
        set_regex_compile_error(compile_error ? compile_error->message : nullptr);
        if (compile_error) hs_free_compile_error(compile_error);
        return nullptr;
    }
    auto* handle = static_cast<RegexHandle*>(calloc(1, sizeof(RegexHandle)));
    if (!handle) {
        set_regex_compile_error("out of memory while allocating regex handle");
        hs_free_database(db);
        return nullptr;
    }
    handle->db = db;
    if (pthread_mutex_init(&handle->mutex, nullptr) != 0) {
        set_regex_compile_error("regex mutex initialization failed");
        hs_free_database(db);
        free(handle);
        return nullptr;
    }
    if (pthread_cond_init(&handle->no_active_scans, nullptr) != 0) {
        set_regex_compile_error("regex condition initialization failed");
        pthread_mutex_destroy(&handle->mutex);
        hs_free_database(db);
        free(handle);
        return nullptr;
    }
    if (!register_regex_handle(handle)) {
        set_regex_compile_error("out of regex handle registry slots");
        pthread_cond_destroy(&handle->no_active_scans);
        pthread_mutex_destroy(&handle->mutex);
        hs_free_database(db);
        free(handle);
        return nullptr;
    }
    return handle;
}

const char* rut_helper_regex_last_compile_error() {
    return t_regex_compile_error[0] ? t_regex_compile_error : nullptr;
}

void rut_helper_regex_free(void* db) {
    if (!db) return;
    auto* handle = static_cast<RegexHandle*>(db);
    pthread_mutex_lock(&handle->mutex);
    handle->closing = true;
    while (handle->active_scans) {
        pthread_cond_wait(&handle->no_active_scans, &handle->mutex);
    }
    hs_database_t* regex_db = handle->db;
    handle->db = nullptr;
    pthread_mutex_unlock(&handle->mutex);

    unregister_regex_handle(handle);
    if (regex_db) hs_free_database(regex_db);
    pthread_cond_destroy(&handle->no_active_scans);
    pthread_mutex_destroy(&handle->mutex);
    free(handle);
}

u8 rut_helper_str_regex_match(const char* s, u32 s_len, void* db) {
    if (!s || !db) return 0;
    auto* handle = static_cast<RegexHandle*>(db);
    hs_database_t* regex_db = nullptr;
    if (!begin_regex_scan(handle, &regex_db)) return 0;
    pthread_mutex_lock(&t_regex_scratch_cache.mutex);
    hs_scratch_t* scratch = t_regex_scratch_cache.get(handle);
    if (!scratch) {
        pthread_mutex_unlock(&t_regex_scratch_cache.mutex);
        end_regex_scan(handle);
        regex_runtime_error("scratch allocation failed");
        return 0;
    }

    RegexMatchCtx ctx{};
    ctx.len = s_len;
    hs_error_t rc = hs_scan(regex_db, s, s_len, 0, scratch, on_full_regex_match, &ctx);
    pthread_mutex_unlock(&t_regex_scratch_cache.mutex);
    end_regex_scan(handle);
    return (rc == HS_SUCCESS || rc == HS_SCAN_TERMINATED) && ctx.matched ? 1 : 0;
}

u8 rut_helper_regex_backend_available() {
    return 1;
}

extern "C" u32 rut_helper_regex_scratch_cache_entry_count_for_test() {
    pthread_mutex_lock(&t_regex_scratch_cache.mutex);
    const u32 count = t_regex_scratch_cache.count;
    pthread_mutex_unlock(&t_regex_scratch_cache.mutex);
    return count;
}

void rut_helper_str_trim_prefix(
    const char* s, u32 s_len, const char* pfx, u32 pfx_len, const char** out_ptr, u32* out_len) {
    if (pfx_len <= s_len) {
        bool match = true;
        for (u32 i = 0; i < pfx_len; i++) {
            if (s[i] != pfx[i]) {
                match = false;
                break;
            }
        }
        if (match) {
            *out_ptr = s + pfx_len;
            *out_len = s_len - pfx_len;
            return;
        }
    }
    *out_ptr = s;
    *out_len = s_len;
}
