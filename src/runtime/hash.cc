#include "rut/runtime/hash.h"

#include "crypto_hash_internal.h"
#include "rut/runtime/crypto_c.h"

namespace rut {
static_assert(static_cast<u32>(HashAlgorithm::Md5) == RUT_CRYPTO_MD5_V1);
static_assert(static_cast<u32>(HashAlgorithm::Sha1) == RUT_CRYPTO_SHA1_V1);
static_assert(static_cast<u32>(HashAlgorithm::Sha224) == RUT_CRYPTO_SHA224_V1);
static_assert(static_cast<u32>(HashAlgorithm::Sha256) == RUT_CRYPTO_SHA256_V1);
static_assert(static_cast<u32>(HashAlgorithm::Sha384) == RUT_CRYPTO_SHA384_V1);
static_assert(static_cast<u32>(HashAlgorithm::Sha512) == RUT_CRYPTO_SHA512_V1);
bool hash_digest(HashAlgorithm algorithm,
                 Str data,
                 Str key,
                 bool keyed,
                 u8* output,
                 u32 capacity,
                 u32& output_len) {
    return hash_digest_parts(algorithm, &data, 1, key, keyed, output, capacity, output_len);
}

bool hash_digest_parts(HashAlgorithm algorithm,
                       const Str* parts,
                       u32 count,
                       Str key,
                       bool keyed,
                       u8* output,
                       u32 capacity,
                       u32& output_len) {
    output_len = 0;
    if ((!parts && count) || count > 16) return false;
    rut_crypto_span_v1 spans[16]{};
    for (u32 i = 0; i < count; ++i)
        spans[i] = {reinterpret_cast<const u8*>(parts[i].ptr), parts[i].len};
    return rut_crypto_digest_unbounded_internal(static_cast<u32>(algorithm),
                                                spans,
                                                count,
                                                reinterpret_cast<const u8*>(key.ptr),
                                                key.len,
                                                keyed ? 1u : 0u,
                                                output,
                                                capacity,
                                                &output_len);
}

bool hash_hex(HashAlgorithm algorithm,
              Str data,
              Str key,
              bool keyed,
              char (&output)[kMaxHashHexBytes],
              u32& output_len) {
    output_len = 0;
    if (data.len > kMaxHashInputBytes || (keyed && key.len > kMaxHashKeyBytes)) return false;
    u8 bytes[kMaxHashDigestBytes]{};
    u32 length = 0;
    if (!rut_crypto_digest_v1(static_cast<u32>(algorithm),
                              reinterpret_cast<const u8*>(data.ptr),
                              data.len,
                              keyed ? reinterpret_cast<const u8*>(key.ptr) : nullptr,
                              keyed ? key.len : 0,
                              keyed ? 1u : 0u,
                              bytes,
                              sizeof(bytes),
                              &length))
        return false;
    constexpr char kHex[] = "0123456789abcdef";
    for (u32 i = 0; i < length; ++i) {
        const u32 kOffset = 2 * i;
        output[kOffset] = kHex[bytes[i] >> 4];
        output[kOffset + 1] = kHex[bytes[i] & 15];
    }
    output_len = length * 2;
    rut_crypto_clear_v1(bytes, sizeof(bytes));
    return true;
}

}  // namespace rut
