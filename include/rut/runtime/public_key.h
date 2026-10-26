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

}  // namespace rut
