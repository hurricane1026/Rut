#include "rut/runtime/public_key.h"

#include "rut/runtime/hash.h"
#include "rut/runtime/json.h"

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

namespace {
bool jwk_string(json::Document& document, u32 node, Str expected) {
    if (document.nodes[node].kind != json::Kind::String) return false;
    json::Writer writer{document.other};
    return document.string(node, writer) && Str{document.other, writer.len}.eq(expected);
}

// RFC 7518 Base64urlUInt is unsigned and minimally encoded, with no ASN.1
// sign-padding byte. Decode only bounded RSA moduli; exponent is fixed below.
bool jwk_modulus(Str input, unsigned char (&output)[512], u32& length) {
    length = 0;
    if (input.len == 0 || input.len > 683 || input.len % 4 == 1) return false;
    u32 accumulator = 0;
    u32 bits = 0;
    for (u32 i = 0; i < input.len; ++i) {
        const char c = input.ptr[i];
        u32 value = 0;
        if (c >= 'A' && c <= 'Z')
            value = static_cast<u32>(c - 'A');
        else if (c >= 'a' && c <= 'z')
            value = static_cast<u32>(c - 'a' + 26);
        else if (c >= '0' && c <= '9')
            value = static_cast<u32>(c - '0' + 52);
        else if (c == '-')
            value = 62;
        else if (c == '_')
            value = 63;
        else
            return false;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (length == sizeof(output)) return false;
            output[length++] = static_cast<unsigned char>((accumulator >> bits) & 255);
        }
    }
    return length >= 256 && output[0] != 0 &&
           (bits == 0 || (accumulator & ((1u << bits) - 1)) == 0);
}
}  // namespace

bool RsaPublicKey::load_rs256_jwk(Str jwk) {
    if (key_ || !jwk.ptr || jwk.len == 0 || jwk.len > kMaxDerBytes) return false;
    ErrorScope errors;
    json::Document document;
    if (!document.parse(jwk) || document.nodes[0].kind != json::Kind::Object) return false;
    bool has_type = false, has_algorithm = false, has_modulus = false, has_exponent = false;
    unsigned char modulus[512];
    u32 modulus_length = 0;
    for (u32 node = document.nodes[0].child; node != json::kNone;
         node = document.nodes[node].next) {
        json::Writer writer{document.scratch};
        if (!document.string(document.nodes[node].key, writer)) return false;
        const Str name{document.scratch, writer.len};
        if (name.eq(lit_str("kty"))) {
            if (!jwk_string(document, node, lit_str("RSA"))) return false;
            has_type = true;
        } else if (name.eq(lit_str("alg"))) {
            if (!jwk_string(document, node, lit_str("RS256"))) return false;
            has_algorithm = true;
        } else if (name.eq(lit_str("n"))) {
            if (document.nodes[node].kind != json::Kind::String) return false;
            json::Writer value{document.other};
            if (!document.string(node, value) ||
                !jwk_modulus({document.other, value.len}, modulus, modulus_length))
                return false;
            has_modulus = true;
        } else if (name.eq(lit_str("e"))) {
            if (!jwk_string(document, node, lit_str("AQAB"))) return false;
            has_exponent = true;
        } else if (name.eq(lit_str("use"))) {
            if (!jwk_string(document, node, lit_str("sig"))) return false;
        } else if (name.eq(lit_str("key_ops"))) {
            const u32 child = document.nodes[node].child;
            if (document.nodes[node].kind != json::Kind::Array || child == json::kNone ||
                document.nodes[child].next != json::kNone ||
                !jwk_string(document, child, lit_str("verify")))
                return false;
        } else if (name.eq(lit_str("d")) || name.eq(lit_str("p")) || name.eq(lit_str("q")) ||
                   name.eq(lit_str("dp")) || name.eq(lit_str("dq")) || name.eq(lit_str("qi")) ||
                   name.eq(lit_str("oth")))
            return false;
    }
    if (!has_type || !has_algorithm || !has_modulus || !has_exponent) return false;
    RSA* rsa = RSA_new();
    BIGNUM* n = BN_bin2bn(modulus, static_cast<int>(modulus_length), nullptr);
    BIGNUM* e = BN_new();
    EVP_PKEY* owner = EVP_PKEY_new();
    bool accepted = false;
    if (rsa && n && e && owner && BN_set_word(e, 65537) && RSA_set0_key(rsa, n, e, nullptr)) {
        n = nullptr;
        e = nullptr;
        if (EVP_PKEY_set1_RSA(owner, rsa)) {
            unsigned char der[kMaxDerBytes];
            const int size = i2d_PUBKEY(owner, nullptr);
            if (size > 0 && static_cast<u32>(size) <= sizeof(der)) {
                unsigned char* cursor = der;
                if (i2d_PUBKEY(owner, &cursor) == size)
                    accepted = load({reinterpret_cast<const char*>(der), static_cast<u32>(size)});
            }
        }
    }
    BN_free(n);
    BN_free(e);
    RSA_free(rsa);
    EVP_PKEY_free(owner);
    return accepted;
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
