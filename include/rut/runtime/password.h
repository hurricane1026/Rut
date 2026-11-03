#pragma once

#include "rut/common/types.h"

namespace rut {

inline constexpr u32 kPasswordMaxBytes = 1024;
inline constexpr u32 kPasswordSaltBytes = 16;
inline constexpr u32 kPasswordIterations = 600000;
inline constexpr u32 kPasswordRecordBytes = 123;

// Native offline/worker API: deliberately expensive and synchronous. Never call
// on a gateway shard. Caller supplies a fresh CSPRNG-generated 16-byte salt for
// each password; salt generation/storage and worker scheduling belong to caller.
// Passwords are exact nonempty bytes (including embedded NUL), bounded to 1 KiB.
// Output is a versioned fixed-cost ASCII record, without a terminating NUL.
// Failure sets output_len to zero and leaves output unchanged. No allocation or
// retained input views. The salt and record are public; do not log passwords.
bool password_hash(Str password, Str salt, char* output, u32 capacity, u32& output_len);

// Only accepts our canonical fixed-cost record, rejecting malformed/unsupported
// records before doing the KDF. Constant-time derived-key comparison. Both an
// invalid record and an incorrect password return false. Not a Basic helper.
bool password_verify(Str password, Str record);

}  // namespace rut
