#pragma once

#include "rut/common/types.h"

struct evp_pkey_st;
struct ec_point_st;
struct bignum_st;
struct bignum_ctx;

namespace rut {

// Configuration-owned public P-256 key. Import before publication; retain the
// generation until all readers drain. No private keys or explicit curve groups.
class EcP256PublicKey {
    friend class EcP256Sha256Verifier;
    evp_pkey_st* key = nullptr;

public:
    static constexpr u32 kMaxDerBytes = 8192;
    EcP256PublicKey() = default;
    ~EcP256PublicKey();
    EcP256PublicKey(const EcP256PublicKey&) = delete;
    EcP256PublicKey& operator=(const EcP256PublicKey&) = delete;
    [[nodiscard]] bool load(Str der);
    [[nodiscard]] bool load_es256_jwk(Str jwk);
    [[nodiscard]] bool load_es256_jwks(Str jwks, Str configured_kid);
    void reset();
    [[nodiscard]] bool valid() const { return key != nullptr; }
};

// Mutable, shard-owned ECDSA verification scratch. Activation retains its own
// key reference and preallocates/warm-ups all math storage. Never share between
// concurrent shards. Only verification of public inputs is provided, not signing.
class EcP256Sha256Verifier {
    evp_pkey_st* key = nullptr;
    ec_point_st* points[4]{};
    bignum_st* values[7]{};
    bignum_ctx* scratch = nullptr;

public:
    EcP256Sha256Verifier() = default;
    ~EcP256Sha256Verifier();
    EcP256Sha256Verifier(const EcP256Sha256Verifier&) = delete;
    EcP256Sha256Verifier& operator=(const EcP256Sha256Verifier&) = delete;
    [[nodiscard]] bool init(const EcP256PublicKey& key);
    void reset();
    [[nodiscard]] bool valid() const { return key != nullptr; }
    // SHA-256 over exact message bytes <=1 MiB; signature is precisely the JOSE
    // 64-byte R||S form, each component 1..n-1. Both valid S representatives are
    // accepted. DER signatures, other curves and algorithm fallback are absent.
    [[nodiscard]] bool verify(Str message, Str signature);
};

// Trusted, immutable subset of one bounded JWKS. Every approved ID must select
// an ES256 key; unrelated entries never acquire trust by appearing in the set.
class Es256KeySet {
    friend class Es256VerifierSet;
    static constexpr u32 kCapacity = 16;
    EcP256PublicKey keys[kCapacity];
    char ids[kCapacity][128]{};
    u32 lengths[kCapacity]{};
    u32 count = 0;

public:
    static constexpr u32 kMaxKeys = kCapacity;
    static constexpr u32 kMaxKidBytes = 128;
    Es256KeySet() = default;
    Es256KeySet(const Es256KeySet&) = delete;
    Es256KeySet& operator=(const Es256KeySet&) = delete;
    [[nodiscard]] bool load(Str jwks, const Str* approved_ids, u32 count);
    void reset();
    [[nodiscard]] bool valid() const { return count != 0; }
    [[nodiscard]] u32 size() const { return count; }
    Str kid_at(u32 index) const { return index < count ? Str{ids[index], lengths[index]} : Str{}; }
};

class Es256VerifierSet {
    EcP256Sha256Verifier verifiers[Es256KeySet::kMaxKeys];
    char ids[Es256KeySet::kMaxKeys][Es256KeySet::kMaxKidBytes]{};
    u32 lengths[Es256KeySet::kMaxKeys]{};
    u32 count = 0;

public:
    struct Selection {
        EcP256Sha256Verifier* verifier = nullptr;
        Str kid{};
    };
    Es256VerifierSet() = default;
    Es256VerifierSet(const Es256VerifierSet&) = delete;
    Es256VerifierSet& operator=(const Es256VerifierSet&) = delete;
    [[nodiscard]] bool init(const Es256KeySet& keys);
    void reset();
    [[nodiscard]] bool valid() const { return count != 0; }
    [[nodiscard]] u32 size() const { return count; }
    [[nodiscard]] Selection select(Str kid);
};

}  // namespace rut
