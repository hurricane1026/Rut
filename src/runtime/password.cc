#include "rut/runtime/password.h"

#include "rut/common/types.h"
#include "rut/runtime/hash.h"

#include <openssl/crypto.h>
#include <stddef.h>

namespace rut {
namespace {
constexpr auto kPrefix = lit_str("$rut-pbkdf2-sha256$600000$");
constexpr char kHex[] = "0123456789abcdef";
static_assert(kPasswordRecordBytes == kPrefix.len + 32 + 1 + 64);

bool valid_password(Str password) {
    return password.ptr && password.len && password.len <= kPasswordMaxBytes;
}

// RFC 8018 PBKDF2, one 32-byte block, using the existing allocation-free HMAC.
// Intermediate keys and the HMAC implementation's internal scratch are wiped.
bool derive(Str password, Str salt, u8 (&result)[32]) {
    const char kCounter[4] = {0, 0, 0, 1};
    const Str kParts[] = {salt, {kCounter, 4}};
    u8 u[32]{};
    u32 length = 0;
    bool ok = hash_digest_parts(HashAlgorithm::Sha256, kParts, 2, password, true, u, 32, length);
    if (ok) {
        for (u32 j = 0; j < 32; ++j) result[j] = u[j];
        for (u32 i = 1; i < kPasswordIterations; ++i) {
            // hash_digest stages its result before writing output, allowing the
            // previous U value to be consumed before replacement.
            if (!hash_digest(HashAlgorithm::Sha256,
                             {reinterpret_cast<const char*>(u), 32},
                             password,
                             true,
                             u,
                             32,
                             length)) {
                ok = false;
                break;
            }
            for (u32 j = 0; j < 32; ++j) result[j] ^= u[j];
        }
    }
    OPENSSL_cleanse(u, sizeof(u));
    return ok;
}

void hex(const u8* bytes, u32 count, char* output) {
    for (u32 i = 0; i < count; ++i) {
        output[2 * static_cast<size_t>(i)] = kHex[bytes[i] >> 4];
        output[2 * static_cast<size_t>(i) + 1] = kHex[bytes[i] & 15];
    }
}

int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

bool unhex(const char* input, u32 count, u8* output) {
    for (u32 i = 0; i < count; ++i) {
        const int kA = nibble(input[2 * static_cast<size_t>(i)]);
        const int kB = nibble(input[2 * static_cast<size_t>(i) + 1]);
        if (kA < 0 || kB < 0) return false;
        output[i] = static_cast<u8>((kA << 4) | kB);
    }
    return true;
}
}  // namespace

bool password_hash(Str password, Str salt, char* output, u32 capacity, u32& output_len) {
    output_len = 0;
    if (!valid_password(password) || !salt.ptr || salt.len != kPasswordSaltBytes || !output ||
        capacity < kPasswordRecordBytes)
        return false;
    u8 key[32]{};
    // Stage the record so even overlapping input/output cannot overwrite salt.
    char record[kPasswordRecordBytes];
    const bool kOk = derive(password, salt, key);
    if (kOk) {
        for (u32 i = 0; i < kPrefix.len; ++i) record[i] = kPrefix.ptr[i];
        hex(reinterpret_cast<const u8*>(salt.ptr), kPasswordSaltBytes, record + kPrefix.len);
        record[kPrefix.len + 32] = '$';
        hex(key, 32, record + kPrefix.len + 33);
        for (u32 i = 0; i < kPasswordRecordBytes; ++i) output[i] = record[i];
        output_len = kPasswordRecordBytes;
    }
    OPENSSL_cleanse(key, sizeof(key));
    return kOk;
}

bool password_verify(Str password, Str record) {
    if (!valid_password(password) || !record.ptr || record.len != kPasswordRecordBytes ||
        !Str{record.ptr, kPrefix.len}.eq(kPrefix) || record.ptr[kPrefix.len + 32] != '$')
        return false;
    u8 salt[kPasswordSaltBytes]{};
    u8 expected[32]{};
    if (!unhex(record.ptr + kPrefix.len, kPasswordSaltBytes, salt) ||
        !unhex(record.ptr + kPrefix.len + 33, 32, expected))
        return false;
    u8 key[32]{};
    const bool kOk = derive(password, {reinterpret_cast<const char*>(salt), sizeof(salt)}, key) &&
                     CRYPTO_memcmp(key, expected, sizeof(key)) == 0;
    OPENSSL_cleanse(key, sizeof(key));
    return kOk;
}
}  // namespace rut
