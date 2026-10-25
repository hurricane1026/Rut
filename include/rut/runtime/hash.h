#pragma once

#include "rut/common/types.h"

namespace rut {

enum class HashAlgorithm : u8 { Md5, Sha1, Sha224, Sha256, Sha384, Sha512 };
inline constexpr u32 kMaxHashInputBytes = 1024 * 1024;
inline constexpr u32 kMaxHashKeyBytes = 4096;
inline constexpr u32 kMaxHashDigestBytes = 64;
inline constexpr u32 kMaxHashHexBytes = 128;
inline constexpr u32 kHashRequestBudget = 256 * 1024;
inline constexpr u32 kHashHmacFlag = 0x100;

// Exact byte input, including empty/binary spans. HMAC accepts an empty key as
// specified by RFC 2104; authentication policy must reject disabled credentials.
// Stack scratch only; no allocation or retained input/output views. Raw digest
// callers bound their own inputs; hash_hex enforces the public 1 MiB / 4 KiB limits.
bool hash_digest(HashAlgorithm algorithm,
                 Str data,
                 Str key,
                 bool keyed,
                 u8* output,
                 u32 capacity,
                 u32& output_len);
bool hash_hex(HashAlgorithm algorithm,
              Str data,
              Str key,
              bool keyed,
              char (&output)[kMaxHashHexBytes],
              u32& output_len);

}  // namespace rut
