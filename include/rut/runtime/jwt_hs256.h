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

}  // namespace rut
