#pragma once

#include "rut/common/types.h"

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

// ── Time ──
// Monotonic microseconds (fresh clock_gettime with a thread-local clamp).
// Backs the `time.nowMicros()` builtin.
rut::i64 rut_helper_time_now_micros();

}  // extern "C"
