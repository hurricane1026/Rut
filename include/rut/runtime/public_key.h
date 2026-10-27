#pragma once

#include "rut/common/types.h"

struct evp_pkey_st;
struct bignum_st;
struct bignum_ctx;
struct bn_mont_ctx_st;

namespace rut {

// Configuration-generation owned RSA public key. Load before publishing the
// generation and destroy only after its last reader has drained. Never load on
// the request path. The crypto library owns its internal configuration storage.
class RsaPublicKey {
    friend class RsaSha256Verifier;
    evp_pkey_st* key_ = nullptr;

public:
    static constexpr u32 kMaxDerBytes = 8192;
    RsaPublicKey() = default;
    ~RsaPublicKey();
    RsaPublicKey(const RsaPublicKey&) = delete;
    RsaPublicKey& operator=(const RsaPublicKey&) = delete;

    // Exactly one canonical SubjectPublicKeyInfo DER object; RSA 2048..4096
    // bits, exponent 65537. No certificates, private keys, PEM or RSA-PSS keys.
    // Failure leaves an empty owner empty and never replaces a loaded key.
    [[nodiscard]] bool load(Str der);
    // Configuration-only single public RSA JWK, fixed RS256 verification profile.
    // Requires kty=RSA, alg=RS256, minimal base64urlUInt n and e=65537.
    // Optional use/key_ops must be sig/[verify]. Never fetches key URLs or
    // selects by kid. Rejects private parameters. Same ownership/bounds as load.
    [[nodiscard]] bool load_rs256_jwk(Str jwk);
    // Configuration-only JWK Set selection by a trusted, nonempty kid <=128 bytes.
    // At most 16 object entries, all with unique nonempty bounded string kids.
    // Selected entry must satisfy load_rs256_jwk. No fallback or URL fetching.
    [[nodiscard]] bool load_rs256_jwks(Str jwks, Str configured_kid);
    void reset();
    [[nodiscard]] bool valid() const { return key_ != nullptr; }
    [[nodiscard]] u32 bits() const;
};

// Single-shard mutable workspace for fixed RSASSA-PKCS1-v1_5 / SHA-256.
// Initialize on the execution shard before serving requests (including its
// crypto thread-local state). init/reset are activation work. Owns a key reference, so the source
// owner may be released afterwards. Never share a verifier between concurrent shards.
class RsaSha256Verifier {
    evp_pkey_st* key_ = nullptr;
    const bignum_st* modulus_ = nullptr;
    const bignum_st* exponent_ = nullptr;
    bignum_st* input_ = nullptr;
    bignum_st* output_ = nullptr;
    bignum_ctx* scratch_ = nullptr;
    bn_mont_ctx_st* mont_ = nullptr;
    u32 bytes_ = 0;

public:
    RsaSha256Verifier() = default;
    ~RsaSha256Verifier();
    RsaSha256Verifier(const RsaSha256Verifier&) = delete;
    RsaSha256Verifier& operator=(const RsaSha256Verifier&) = delete;
    [[nodiscard]] bool init(const RsaPublicKey& key);
    void reset();
    [[nodiscard]] bool valid() const { return bytes_ != 0; }
    // Exact signed bytes (up to 1 MiB), fixed-width raw signature (not Base64).
    // Borrows inputs synchronously, retains no request views, returns false on
    // malformed input, uninitialized context, signature mismatch or crypto error.
    [[nodiscard]] bool verify(Str message, Str signature);
};

// Trusted configuration subset of a local JWK Set. Load before publication;
// each approved ID must select an RS256 key. Other JWKs never become trusted
// merely by appearing in the input. Owns keys and copied decoded ID bytes.
class Rs256KeySet {
    friend class Rs256VerifierSet;
    static constexpr u32 kCapacity = 16;
    RsaPublicKey keys_[kCapacity];
    char ids_[kCapacity][128]{};
    u32 lengths_[kCapacity]{};
    u32 count_ = 0;

public:
    static constexpr u32 kMaxKeys = kCapacity;
    static constexpr u32 kMaxKidBytes = 128;
    Rs256KeySet() = default;
    Rs256KeySet(const Rs256KeySet&) = delete;
    Rs256KeySet& operator=(const Rs256KeySet&) = delete;
    // Nonempty approved subset, unique IDs, <=16 keys and <=8192 input bytes.
    // Failed preparation rolls back all entries. A valid set cannot be replaced
    // without reset; prepare a separate generation while readers drain.
    [[nodiscard]] bool load(Str jwks, const Str* approved_ids, u32 count);
    void reset();
    [[nodiscard]] bool valid() const { return count_ != 0; }
    [[nodiscard]] u32 size() const { return count_; }
};

// Shard-owned verification workspace. Initialize on the execution shard before
// serving requests; never share mutable verifiers across concurrent shards.
// Retains independent key references and copies IDs, so the source set may be
// released after activation. Request selection is bounded and allocation-free.
class Rs256VerifierSet {
    RsaSha256Verifier verifiers_[Rs256KeySet::kMaxKeys];
    char ids_[Rs256KeySet::kMaxKeys][Rs256KeySet::kMaxKidBytes]{};
    u32 lengths_[Rs256KeySet::kMaxKeys]{};
    u32 count_ = 0;

public:
    struct Selection {
        RsaSha256Verifier* verifier = nullptr;
        Str kid{};  // borrowed canonical configuration ID, not proof of authentication
    };
    Rs256VerifierSet() = default;
    Rs256VerifierSet(const Rs256VerifierSet&) = delete;
    Rs256VerifierSet& operator=(const Rs256VerifierSet&) = delete;
    [[nodiscard]] bool init(const Rs256KeySet& keys);
    void reset();
    [[nodiscard]] bool valid() const { return count_ != 0; }
    [[nodiscard]] u32 size() const { return count_; }
    // Exact decoded ID bytes, case-sensitive; no default key or fallback.
    // Returned views/pointers expire at reset/destruction of this verifier set.
    [[nodiscard]] Selection select(Str kid);
};

}  // namespace rut
