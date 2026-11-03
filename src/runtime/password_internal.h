#pragma once

#include "rut/runtime/crypto_c.h"
#include "rut/runtime/password.h"

namespace rut::detail {

// Shared production/test implementation, following generate_uuid's entropy
// callback pattern. One bounded read: error, interruption and short read fail
// closed. Callers must supply cryptographic entropy, never a fallback PRNG.
template <typename ReadEntropy>
bool password_hash_random(
    Str password, char* output, u32 capacity, u32& output_len, ReadEntropy read_entropy) {
    output_len = 0;
    if (!password.ptr || password.len == 0 || password.len > kPasswordMaxBytes || !output ||
        capacity < kPasswordRecordBytes)
        return false;
    u8 salt[kPasswordSaltBytes]{};
    bool ok = false;
    if (read_entropy(salt, kPasswordSaltBytes) == static_cast<i32>(kPasswordSaltBytes))
        ok = password_hash(password,
                           {reinterpret_cast<const char*>(salt), kPasswordSaltBytes},
                           output,
                           capacity,
                           output_len);
    rut_crypto_clear_v1(salt, sizeof(salt));
    return ok;
}

}  // namespace rut::detail
