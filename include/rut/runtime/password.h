#pragma once

#include "rut/common/http_header_validation.h"
#include "rut/common/types.h"

namespace rut {

inline constexpr u32 kPasswordMaxBytes = 1024;
inline constexpr u32 kPasswordSaltBytes = 16;
inline constexpr u32 kPasswordIterations = 600000;
inline constexpr u32 kPasswordRecordBytes = 123;

// Fixed public record/profile validation; never performs password derivation.
inline bool password_record_valid(Str record) {
    constexpr auto kPrefix = lit_str("$rut-pbkdf2-sha256$600000$");
    if (!record.ptr || record.len != kPasswordRecordBytes ||
        !Str{record.ptr, kPrefix.len}.eq(kPrefix) || record.ptr[kPrefix.len + 32] != '$')
        return false;
    for (u32 i = kPrefix.len; i < record.len; ++i) {
        if (i == kPrefix.len + 32) continue;
        const char c = record.ptr[i];
        if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f')) return false;
    }
    return true;
}
inline bool password_header_policy_valid(Str header, Str record, u32 timeout_ms) {
    if (!header.ptr || header.len == 0 || header.len > 128 || timeout_ms == 0 ||
        timeout_ms > 60000 || !password_record_valid(record))
        return false;
    for (u32 i = 0; i < header.len; ++i)
        if (!is_http_tchar(static_cast<u8>(header.ptr[i]))) return false;
    return true;
}

// Native offline/worker API: deliberately expensive and synchronous. Never call
// on a gateway shard. Caller supplies a fresh CSPRNG-generated 16-byte salt for
// each password; salt generation/storage and worker scheduling belong to caller.
// Passwords are exact nonempty bytes (including embedded NUL), bounded to 1 KiB.
// Output is a versioned fixed-cost ASCII record, without a terminating NUL.
// Failure sets output_len to zero and leaves output unchanged. No allocation or
// retained input views. The salt and record are public; do not log passwords.
bool password_hash(Str password, Str salt, char* output, u32 capacity, u32& output_len);

// Preferred creation overload: obtains a fresh salt from the OS CSPRNG.
// One nonblocking getrandom read on Linux; getentropy on other supported hosts.
// Entropy error, interruption or short read fails closed without writing output.
// Same offline/worker-only, expensive synchronous contract as the explicit-salt
// overload above. No fallback entropy, allocation, or retained views.
bool password_hash(Str password, char* output, u32 capacity, u32& output_len);

// Only accepts our canonical fixed-cost record, rejecting malformed/unsupported
// records before doing the KDF. Constant-time derived-key comparison. Both an
// invalid record and an incorrect password return false. Not a Basic helper.
bool password_verify(Str password, Str record);

}  // namespace rut
