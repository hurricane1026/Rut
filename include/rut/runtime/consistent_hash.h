#pragma once

#include "rut/common/load_balance.h"
#include "rut/common/range_int.h"
#include "rut/runtime/hash.h"

#include <netinet/in.h>

namespace rut {
inline bool consistent_hash_seed(Str text, u8 (&seed)[16]) {
    if (text.len != 32 || !text.ptr) return false;
    u8 nonzero = 0;
    for (u32 i = 0; i < 16; ++i) {
        u8 value = 0;
        for (u32 j = 0; j < 2; ++j) {
            const char c = text.ptr[static_cast<i64>(i) * 2 + static_cast<i64>(j)];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
            value = static_cast<u8>((value << 4) | (c <= '9' ? static_cast<i64>(c - '0')
                                                             : static_cast<i64>(c - 'a') + 10));
        }
        seed[i] = value;
        nonzero |= value;
    }
    return nonzero != 0;
}

inline bool consistent_hash_digest(Str key, u8 type, Str seed_text, u8 (&digest)[32]) {
    if (!key.ptr || key.len == 0 || key.len > 4096 || (type != 1 && type != 2) ||
        (type == 2 && key.len != 4))
        return false;
    u8 seed[16];
    if (!consistent_hash_seed(seed_text, seed)) return false;
    const u8 prefix[5] = {type,
                          static_cast<u8>(key.len >> 24),
                          static_cast<u8>(key.len >> 16),
                          static_cast<u8>(key.len >> 8),
                          static_cast<u8>(key.len)};
    const Str parts[] = {{"rut-lb-key-v1", 13}, {reinterpret_cast<const char*>(prefix), 5}, key};
    u32 length = 0;
    const bool ok = hash_digest_parts(HashAlgorithm::Sha256,
                                      parts,
                                      3,
                                      {reinterpret_cast<const char*>(seed), 16},
                                      true,
                                      digest,
                                      32,
                                      length) &&
                    length == 32;
    __builtin_memset(seed, 0, sizeof(seed));
    return ok;
}

inline u64 consistent_hash_cost(u64 hash) {
    if (hash == 0) hash = 1;
    constexpr int kFractionBits = 32;
    using LeadingZeros = range_int<0, 65>;
    const auto leading_zeros = LeadingZeros::count_leading_zeros(hash);
    using Wide = unsigned __int128;
    Wide x = static_cast<Wide>(hash) << leading_zeros.to_u64();
    u32 fraction = 0;
    // Visit each fractional bit exactly once, from most to least significant.
    for (u32 bit = u32{1} << (kFractionBits - 1); bit != 0; bit >>= 1) {
        Wide y = (x * x) >> 63;
        if (y >= (static_cast<Wide>(1) << 64)) {
            y >>= 1;
            fraction |= bit;
        }
        x = y;
    }
    const auto whole = leading_zeros + range_int<1, 2>::constant<1>();
    constexpr i64 kFractionScale = u64{1} << kFractionBits;
    const auto cost = whole.scaled_by<kFractionScale>() - range_int(fraction);
    return cost.to_u64();
}

inline bool consistent_hash_score(const u8 (&digest)[32], const sockaddr_in& address, u64& cost) {
    u8 endpoint[7] = {4};
    __builtin_memcpy(endpoint + 1, &address.sin_addr.s_addr, 4);
    __builtin_memcpy(endpoint + 5, &address.sin_port, 2);
    const Str parts[] = {{"rut-lb-hrw-v1", 13},
                         {reinterpret_cast<const char*>(digest), 32},
                         {reinterpret_cast<const char*>(endpoint), 7}};
    u8 output[32];
    u32 length = 0;
    if (!hash_digest_parts(HashAlgorithm::Sha256, parts, 3, {}, false, output, 32, length) ||
        length != 32)
        return false;
    u64 hash = 0;
    for (u32 i = 0; i < 8; ++i) hash = (hash << 8) | output[i];
    cost = consistent_hash_cost(hash);
    return true;
}

inline bool consistent_hash_endpoint_less(const sockaddr_in& a, const sockaddr_in& b) {
    const auto* ap = reinterpret_cast<const u8*>(&a.sin_addr.s_addr);
    const auto* bp = reinterpret_cast<const u8*>(&b.sin_addr.s_addr);
    for (u32 i = 0; i < 4; ++i) {
        if (ap[i] != bp[i]) return ap[i] < bp[i];
    }
    return ntohs(a.sin_port) < ntohs(b.sin_port);
}

// No cursor, allocation, floating point or declaration-order dependency.
inline u32 select_consistent_hash(const ForwardLoadBalance& spec,
                                  const sockaddr_in* addresses,
                                  const u16* weights,
                                  u32 count,
                                  u8 eligible) {
    if (spec.hash_status != 1 || !addresses || !weights || count > 8) return count;
    u32 best = count;
    u64 best_cost = 0;
    for (u32 i = 0; i < count; ++i) {
        if (addresses[i].sin_family != AF_INET || addresses[i].sin_port == 0) return count;
        for (u32 j = 0; j < i; ++j) {
            if (addresses[i].sin_addr.s_addr == addresses[j].sin_addr.s_addr &&
                addresses[i].sin_port == addresses[j].sin_port)
                return count;
        }
        if (!weights[i] || !(eligible & (1u << i))) continue;
        u64 cost = 0;
        if (!consistent_hash_score(spec.hash_digest, addresses[i], cost)) return count;
        if (best == count || cost * weights[best] < best_cost * weights[i] ||
            (cost * weights[best] == best_cost * weights[i] &&
             consistent_hash_endpoint_less(addresses[i], addresses[best]))) {
            best = i;
            best_cost = cost;
        }
    }
    return best;
}
}  // namespace rut
