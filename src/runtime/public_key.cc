#include "rut/runtime/public_key.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

namespace rut {
namespace {
struct ErrorScope {
    bool marked = ERR_set_mark() != 0;
    ~ErrorScope() {
        if (marked)
            (void)ERR_pop_to_mark();
        else
            ERR_clear_error();
    }
};
}  // namespace

RsaPublicKey::~RsaPublicKey() {
    reset();
}

void RsaPublicKey::reset() {
    EVP_PKEY_free(key_);
    key_ = nullptr;
}

u32 RsaPublicKey::bits() const {
    return key_ ? static_cast<u32>(EVP_PKEY_bits(key_)) : 0;
}

bool RsaPublicKey::load(Str der) {
    if (key_ || !der.ptr || der.len == 0 || der.len > kMaxDerBytes) return false;
    ErrorScope errors;
    const auto* start = reinterpret_cast<const unsigned char*>(der.ptr);
    const unsigned char* cursor = start;
    EVP_PKEY* candidate = d2i_PUBKEY(nullptr, &cursor, der.len);
    if (!candidate) return false;
    bool accepted = false;
    do {
        if (cursor != start + der.len || EVP_PKEY_id(candidate) != EVP_PKEY_RSA) break;
        const int size = EVP_PKEY_bits(candidate);
        if (size < 2048 || size > 4096) break;
        const RSA* rsa = EVP_PKEY_get0_RSA(candidate);
        if (!rsa) break;
        const BIGNUM* modulus = nullptr;
        const BIGNUM* exponent = nullptr;
        RSA_get0_key(rsa, &modulus, &exponent, nullptr);
        if (!modulus || !exponent || !BN_is_odd(modulus) || !BN_is_word(exponent, 65537)) break;

        // d2i accepts some BER encodings too. Re-encode into bounded scratch so
        // configuration has one byte-exact format rather than parser aliases.
        const int canonical_size = i2d_PUBKEY(candidate, nullptr);
        if (canonical_size <= 0 || static_cast<u32>(canonical_size) != der.len) break;
        unsigned char canonical[kMaxDerBytes];
        unsigned char* output = canonical;
        if (i2d_PUBKEY(candidate, &output) != canonical_size) break;
        bool identical = true;
        for (u32 i = 0; i < der.len; ++i) {
            if (canonical[i] != start[i]) identical = false;
        }
        if (!identical) break;
        accepted = true;
    } while (false);
    if (!accepted) {
        EVP_PKEY_free(candidate);
        return false;
    }
    key_ = candidate;
    return true;
}

}  // namespace rut
