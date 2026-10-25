#pragma once

#include "rut/common/types.h"

namespace rut {

// Bounded, allocation-free authentication primitives. Lengths are public;
// equal-length secret contents are compared using the existing CRYPTO_memcmp.
inline constexpr u32 kMaxBasicCredentialBytes = 1024;
inline constexpr u32 kMaxBearerKeyBytes = 4096;
inline constexpr u32 kMaxBearerTokenBytes = 24 * 1024;

// Borrowed token view, or {nullptr, 0} for a missing/malformed Bearer credential.
Str bearer_token(Str authorization);

// RFC 6750 b64token syntax. An empty key is never an enabled credential.
bool bearer_key_valid(Str key);
bool bearer_matches(Str authorization, Str key);

// credentials = user-id ':' password. User-id must be nonempty and neither
// field may contain a control byte. Password may contain colons or be empty.
// Bytes are compared exactly, without Unicode normalization.
bool basic_credentials_valid(Str credentials);
bool basic_matches(Str authorization, Str credentials);

}  // namespace rut
