#pragma once

#include "rut/common/types.h"

namespace rut {

inline constexpr u32 kMaxJwtHs256PayloadBytes = 8192;
inline constexpr u32 kMaxJwtHs256TokenBytes = 11004;
inline constexpr u32 kMaxJwtHs256KeyBytes = 4096;

// Issue the fixed HS256 profile with only sub, iss, aud, iat and exp claims.
// Strings must be nonempty valid UTF-8 and contain no NUL or ASCII controls;
// quote and backslash are JSON-escaped. The key is 32..4096 bytes. `now` is a
// positive Unix second and TTL is 1..86400 seconds with checked addition.
// Output is caller-owned, bounded, unpadded base64url compact JWT. No input or
// output view is retained. `output` must not overlap key, subject, issuer or
// audience. `output_len` must not overlap output or any input span. It is set
// to zero on failure; output bytes are unspecified on failure.
[[nodiscard]] bool jwt_hs256_issue(Str key,
                                   Str subject,
                                   Str issuer,
                                   Str audience,
                                   i64 unix_seconds,
                                   i64 ttl_seconds,
                                   char* output,
                                   u32 capacity,
                                   u32& output_len);

// Same bounded native profile with one additional `jti` string claim. The ID
// must be nonempty valid UTF-8 with no NUL/ASCII controls and shares the 8192
// byte escaped-payload limit; uniqueness is the caller's responsibility.
// Output must not overlap the ID, and output_len must not overlap its span.
[[nodiscard]] bool jwt_hs256_issue_with_id(Str key,
                                           Str subject,
                                           Str issuer,
                                           Str audience,
                                           Str token_id,
                                           i64 unix_seconds,
                                           i64 ttl_seconds,
                                           char* output,
                                           u32 capacity,
                                           u32& output_len);

// Same bounded profile with caller-provided jti and an OAuth scope list.
// One or more nonempty ASCII scope-tokens separated by single spaces; order
// and duplicates are preserved. Leading/trailing/repeated spaces are rejected.
// The full escaped payload still fits 8192 bytes; ID uniqueness remains the
// caller's responsibility. Output is caller-owned and aliasing is rejected.
[[nodiscard]] bool jwt_hs256_issue_with_id_and_scope(Str key,
                                                     Str subject,
                                                     Str issuer,
                                                     Str audience,
                                                     Str token_id,
                                                     Str scope,
                                                     i64 unix_seconds,
                                                     i64 ttl_seconds,
                                                     char* output,
                                                     u32 capacity,
                                                     u32& output_len);

}  // namespace rut
