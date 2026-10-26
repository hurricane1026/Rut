#include "rut/runtime/public_key.h"

#include "rut/runtime/hash.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>
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

RsaSha256Verifier::~RsaSha256Verifier() {
    reset();
}

void RsaSha256Verifier::reset() {
    BN_free(input_);
    BN_free(output_);
    BN_CTX_free(scratch_);
    BN_MONT_CTX_free(mont_);
    EVP_PKEY_free(key_);
    key_ = nullptr;
    modulus_ = nullptr;
    exponent_ = nullptr;
    input_ = nullptr;
    output_ = nullptr;
    scratch_ = nullptr;
    mont_ = nullptr;
    bytes_ = 0;
}

bool RsaSha256Verifier::init(const RsaPublicKey& key) {
    if (key_ || !key.key_) return false;
    ErrorScope errors;
    if (!EVP_PKEY_up_ref(key.key_)) return false;
    key_ = key.key_;
    const RSA* rsa = EVP_PKEY_get0_RSA(key_);
    RSA_get0_key(rsa, &modulus_, &exponent_, nullptr);
    input_ = BN_new();
    output_ = BN_new();
    scratch_ = BN_CTX_new();
    mont_ = BN_MONT_CTX_new();
    if (!input_ || !output_ || !scratch_ || !mont_ || !BN_MONT_CTX_set(mont_, modulus_, scratch_)) {
        reset();
        return false;
    }
    // Reserve operands and warm the public-exponent BN workspace at full key
    // width during activation. No attacker-controlled key or exponent is used.
    const int bits = BN_num_bits(modulus_);
    if (!BN_set_bit(input_, bits + 64) || !BN_set_bit(output_, bits + 64) ||
        !BN_copy(input_, modulus_) || !BN_sub_word(input_, 1) ||
        !BN_mod_exp_mont(output_, input_, exponent_, modulus_, scratch_, mont_)) {
        reset();
        return false;
    }
    BN_zero(input_);
    BN_zero(output_);
    bytes_ = static_cast<u32>((bits + 7) / 8);
    return true;
}

bool RsaSha256Verifier::verify(Str message, Str signature) {
    if (!valid() || signature.ptr == nullptr || signature.len != bytes_ ||
        message.len > kMaxHashInputBytes || (!message.ptr && message.len != 0))
        return false;
    ErrorScope errors;
    if (!BN_bin2bn(reinterpret_cast<const unsigned char*>(signature.ptr),
                   static_cast<int>(bytes_),
                   input_) ||
        BN_cmp(input_, modulus_) >= 0 ||
        !BN_mod_exp_mont(output_, input_, exponent_, modulus_, scratch_, mont_))
        return false;
    u8 actual[512];
    if (BN_bn2binpad(output_, actual, static_cast<int>(bytes_)) != static_cast<int>(bytes_))
        return false;

    // RFC 8017 9.2: encode a fixed SHA-256 DigestInfo and compare the COMPLETE
    // EM, avoiding permissive ASN.1 or padding parsing of attacker input.
    static constexpr u8 kDigestInfo[] = {0x30,
                                         0x31,
                                         0x30,
                                         0x0d,
                                         0x06,
                                         0x09,
                                         0x60,
                                         0x86,
                                         0x48,
                                         0x01,
                                         0x65,
                                         0x03,
                                         0x04,
                                         0x02,
                                         0x01,
                                         0x05,
                                         0x00,
                                         0x04,
                                         0x20};
    u8 expected[512];
    const u32 padding_end = bytes_ - sizeof(kDigestInfo) - 32 - 1;
    expected[0] = 0;
    expected[1] = 1;
    for (u32 i = 2; i < padding_end; ++i) expected[i] = 0xff;
    expected[padding_end] = 0;
    for (u32 i = 0; i < sizeof(kDigestInfo); ++i) expected[padding_end + 1 + i] = kDigestInfo[i];
    u32 digest_len = 0;
    if (!hash_digest(
            HashAlgorithm::Sha256, message, {}, false, expected + bytes_ - 32, 32, digest_len) ||
        digest_len != 32)
        return false;
    return CRYPTO_memcmp(actual, expected, bytes_) == 0;
}

}  // namespace rut
