#pragma once

#include "rut/common/types.h"

namespace rut {
struct CacheLocalState;
}

// Runtime helper functions callable from JIT'd code.
// All use extern "C" linkage with rut_helper_ prefix to avoid
// C++ name mangling. The JIT engine registers these via a custom
// DefinitionGenerator so they're resolved on first use.
//
// These functions bridge the gap between JIT'd code (which operates
// on raw pointers and primitives) and the runtime's parsed request
// data. JIT'd code passes raw request bytes; helpers parse as needed.

extern "C" {

// ── Request Access ─────────────────────────────────────────────────

// Extract request path from raw HTTP request.
// Sets *out_ptr and *out_len to the path string (points into req_data).
void rut_helper_req_path(const rut::u8* req_data,
                         rut::u32 req_len,
                         const char** out_ptr,
                         rut::u32* out_len);

// Extract request path without query or fragment suffix from raw HTTP request.
// Sets *out_ptr and *out_len to a string view pointing into req_data.
void rut_helper_req_path_only(const rut::u8* req_data,
                              rut::u32 req_len,
                              const char** out_ptr,
                              rut::u32* out_len);

// Extract the declared request body bytes, bounded by Content-Length.
// Returns an empty string if headers are incomplete, Content-Length is absent,
// or req_data does not contain the full declared body yet.
void rut_helper_req_body(const rut::u8* req_data,
                         rut::u32 req_len,
                         const char** out_ptr,
                         rut::u32* out_len);

// Extract the HTTP version token from the request line as "HTTP/1.0",
// "HTTP/1.1", or an empty string when parsing fails.
void rut_helper_req_http_version(const rut::u8* req_data,
                                 rut::u32 req_len,
                                 const char** out_ptr,
                                 rut::u32* out_len);

// Read parsed request flags. flag=0 returns keep-alive, flag=1 returns chunked,
// flag=2 returns whether Content-Length was present, flag=3 returns HTTP/1.0,
// flag=4 returns HTTP/1.1.
rut::u8 rut_helper_req_flag(const rut::u8* req_data, rut::u32 req_len, rut::u8 flag);

// Extract HTTP method from raw request. Returns HttpMethod enum value.
rut::u8 rut_helper_req_method(const rut::u8* req_data, rut::u32 req_len);

// Look up a request header by name (case-insensitive).
// Returns Optional(Str): *out_has_value = 1 if found, 0 if not.
// If found, *out_ptr / *out_len point into req_data.
void rut_helper_req_header(const rut::u8* req_data,
                           rut::u32 req_len,
                           const char* name,
                           rut::u32 name_len,
                           rut::u8* out_has_value,
                           const char** out_ptr,
                           rut::u32* out_len);

// Look up a cookie by name from the Cookie request header.
// Returns Optional(Str): *out_has_value = 1 if found, 0 if not.
// If found, *out_ptr / *out_len point into req_data.
void rut_helper_req_cookie(const rut::u8* req_data,
                           rut::u32 req_len,
                           const char* name,
                           rut::u32 name_len,
                           rut::u8* out_has_value,
                           const char** out_ptr,
                           rut::u32* out_len);

// Look up a query value by name from request target.
// Returns Optional(Str): *out_has_value = 1 if found, 0 if not.
// If found, *out_ptr / *out_len point into req_data.
void rut_helper_req_query(const rut::u8* req_data,
                          rut::u32 req_len,
                          const char* name,
                          rut::u32 name_len,
                          rut::u8* out_has_value,
                          const char** out_ptr,
                          rut::u32* out_len);

// Collect every matching query value, preserving request order. Passing a
// null output or cap=0 performs a count-only pass. Returns the total count;
// when out is non-null, writes min(total, cap) string views into it.
rut::u32 rut_helper_req_query_all(const rut::u8* req_data,
                                  rut::u32 req_len,
                                  const char* name,
                                  rut::u32 name_len,
                                  rut::Str* out,
                                  rut::u32 cap);

// Collect every matching request-header field, case-insensitively and in wire
// order. Supports the same count-only contract as req_query_all.
rut::u32 rut_helper_req_header_all(const rut::u8* req_data,
                                   rut::u32 req_len,
                                   const char* name,
                                   rut::u32 name_len,
                                   rut::Str* out,
                                   rut::u32 cap);

// Extract the raw query string from request target, excluding '?' and '#fragment'.
// Returns Optional(Str): *out_has_value = 1 if a query component exists.
// If found, *out_ptr / *out_len point into req_data.
void rut_helper_req_query_string(const rut::u8* req_data,
                                 rut::u32 req_len,
                                 rut::u8* out_has_value,
                                 const char** out_ptr,
                                 rut::u32* out_len);

// Look up a route parameter captured by SegmentTrie route matching.
// Returns an empty Str when the parameter is not present.
void rut_helper_req_param(
    void* ctx, const char* name, rut::u32 name_len, const char** out_ptr, rut::u32* out_len);

// Get remote address from Connection. Returns IPv4 in network order.
rut::u32 rut_helper_req_remote_addr(void* conn);

// Get parsed Content-Length from request bytes. Returns 0 when absent or malformed.
rut::u64 rut_helper_req_content_length(const rut::u8* req_data, rut::u32 req_len);

// Parse-once: force a fresh parse of (req_data, req_len) into the per-thread
// parse cache. The JIT emits exactly one call to this at handler entry so all
// req_* helpers in that invocation share a single parse instead of each
// re-parsing the request. Priming on every entry also prevents a reused
// request buffer from aliasing a previous request's cached parse.
void rut_helper_parse_prime(const rut::u8* req_data, rut::u32 req_len);

// Clear the primed parse cache at handler exit so a primed parse never
// outlives its invocation (see rut_helper_parse_prime). The JIT emits one
// call before each terminal return of a request-reading handler.
void rut_helper_parse_unprime();

// Bounded per-shard JSON response serializer. reset starts one document;
// append_* are no-ops after overflow; finish publishes an all-or-nothing view
// through HandlerCtx. raw is compiler-owned JSON punctuation/key text only.
void rut_helper_json_reset();
void rut_helper_json_append_raw(const char* data, rut::u32 len);
void rut_helper_json_append_str(const char* data, rut::u32 len);
void rut_helper_json_append_str_list(const rut::Str* items, rut::u32 len);
void rut_helper_json_append_i64(rut::i64 value);
void rut_helper_json_append_bool(rut::u8 value);
const char* rut_helper_json_capture_data();
rut::u32 rut_helper_json_capture_len();
void rut_helper_json_finish(void* ctx);

// ── String Operations ──────────────────────────────────────────────

// Check if string s has prefix pfx. Returns 1 (true) or 0 (false).
rut::u8 rut_helper_str_has_prefix(const char* s, rut::u32 s_len, const char* pfx, rut::u32 pfx_len);

// Check if two strings are equal. Returns 1 (true) or 0 (false).
rut::u8 rut_helper_str_eq(const char* a, rut::u32 a_len, const char* b, rut::u32 b_len);

// Lexicographic string comparison. Returns <0, 0, >0 like strcmp.
rut::i32 rut_helper_str_cmp(const char* a, rut::u32 a_len, const char* b, rut::u32 b_len);

// Compile/free a regular-expression database for full-match scans.
void* rut_helper_regex_compile(const char* pattern, rut::u32 pattern_len);
const char* rut_helper_regex_last_compile_error();
void rut_helper_regex_free(void* db);

// Full regular-expression match using a precompiled database.
rut::u8 rut_helper_str_regex_match(const char* s, rut::u32 s_len, void* db);

// Returns 1 when the Vectorscan backend is available.
rut::u8 rut_helper_regex_backend_available();

// Trim prefix from string. If s starts with pfx, out = remainder.
// Otherwise out = s unchanged.
void rut_helper_str_trim_prefix(const char* s,
                                rut::u32 s_len,
                                const char* pfx,
                                rut::u32 pfx_len,
                                const char** out_ptr,
                                rut::u32* out_len);

// forward(set_path:) request mutation — records a request-path override on the
// connection (a JIT handler calls this before returning forward). `conn` is the
// opaque Connection*; `path` must point at stable memory (a JIT string
// constant), since the proxy reads it later when rewriting the request line.
void rut_helper_req_set_path(void* conn, const char* path, rut::u32 len);

// Record a forward(set_header:) override. `name`/`val` must point at stable
// memory (JIT string constants); the proxy injects/replaces the header line in
// the outbound request later. Bounded per connection.
void rut_helper_req_set_header(
    void* conn, const char* name, rut::u32 nlen, const char* val, rut::u32 vlen);
void rut_helper_req_add_header(
    void* conn, const char* name, rut::u32 nlen, const char* val, rut::u32 vlen);
// Response builder mutations are request/stream-owned HandlerCtx state. This
// keeps pending and committed logs isolated across keepalive and H2 streams.
void rut_helper_resp_set_header(
    void* ctx, const char* name, rut::u32 nlen, const char* val, rut::u32 vlen);
void rut_helper_resp_add_header(
    void* ctx, const char* name, rut::u32 nlen, const char* val, rut::u32 vlen);
void rut_helper_resp_remove_header(void* ctx, const char* name, rut::u32 nlen);
void rut_helper_resp_set_status(void* ctx, rut::i32 status);
void rut_helper_resp_set_body(void* ctx, const char* body, rut::u32 len);
void rut_helper_resp_commit_headers(void* ctx);
void rut_helper_resp_header(void* ctx,
                            const char* name,
                            rut::u32 nlen,
                            rut::u8 fallback_has,
                            const char* fallback_ptr,
                            rut::u32 fallback_len,
                            rut::u8* out_has,
                            const char** out_ptr,
                            rut::u32* out_len);

// ── Cache state (DESIGN.md §3.3.6) ──
// Per-shard lossy slot tables; `instance` indexes the process CacheRegistry
// published by the loader. get: *out_has = 1 and *out_val on hit, *out_has =
// 0 on miss (never-seen and evicted are indistinguishable by design). set
// may evict a colliding neighbor. Out-of-range instances: get misses, set is
// a no-op (defensive; analyze bounds the index at compile time).
void rut_helper_cache_get(rut::u32 instance, rut::u32 key_ip, rut::u8* out_has, rut::i64* out_val);
void rut_helper_cache_set(rut::u32 instance, rut::u32 key_ip, rut::i64 val);
// Harness hook for multiplexing logical shards on one thread. Production shard
// threads leave the default shard selected. Returns the previously selected shard.
rut::u32 rut_helper_cache_select_local_shard(rut::u32 shard_id);
// Harness hook for selecting an independently owned Cache context. A null
// context selects the production thread-local state. The returned pointer is
// the previously selected context (null means production state).
rut::CacheLocalState* rut_helper_cache_select_local_state(rut::CacheLocalState* state);
rut::CacheLocalState* rut_helper_cache_create_local_state();
void rut_helper_cache_destroy_local_state(rut::CacheLocalState* state);
void rut_helper_cache_reset_state(rut::CacheLocalState* state);
// Harness/shard-lifecycle hook: destroy every logical-shard Cache table owned by
// the current thread. It never mutates the process registry or another thread's state.
void rut_helper_cache_reset_local_state();
// ── Time ──
// Monotonic microseconds (fresh clock_gettime with a thread-local clamp).
// Backs the `time.nowMicros()` builtin.
rut::i64 rut_helper_time_now_micros();

// Install a deterministic clock for the current thread. The pointed-to value
// may advance between handler resumes. Returns the previous source for scoped
// restoration; nullptr selects the production monotonic clock.
const rut::u64* rut_helper_time_set_virtual_clock(const rut::u64* now_us);

// Reset the per-invocation time latch. Normally a side effect of
// parse_prime/unprime; the JIT emits this at the prologue of handlers that
// sample time.nowMicros() without reading the request, so their clock does
// not freeze at the thread's first sampled value.
void rut_helper_time_unlatch();

}  // extern "C"
