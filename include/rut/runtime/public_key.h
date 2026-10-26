#pragma once

#include "rut/common/types.h"

struct evp_pkey_st;

namespace rut {

// Configuration-generation owned RSA public key. Load before publishing the
// generation and destroy only after its last reader has drained. Never load on
// the request path. The crypto library owns its internal configuration storage.
class RsaPublicKey {
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
    void reset();
    [[nodiscard]] bool valid() const { return key_ != nullptr; }
    [[nodiscard]] u32 bits() const;
};

}  // namespace rut
