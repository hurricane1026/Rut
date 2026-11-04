#include "es256_fixtures.h"
#include "public_key_fixtures.h"
#include "rut/runtime/ec_public_key.h"
#include "test.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <stdlib.h>

using namespace rut;

namespace {
thread_local bool count_allocations = false;
thread_local u64 allocations = 0;
thread_local i64 allocation_budget = -1;

void* crypto_alloc(size_t size, const char*, int) {
    if (count_allocations) ++allocations;
    if (allocation_budget == 0) return nullptr;
    if (allocation_budget > 0) --allocation_budget;
    return malloc(size);
}
void* crypto_realloc(void* pointer, size_t size, const char*, int) {
    if (count_allocations) ++allocations;
    if (allocation_budget == 0) return nullptr;
    if (allocation_budget > 0) --allocation_budget;
    return realloc(pointer, size);
}
void crypto_free(void* pointer, const char*, int) {
    free(pointer);
}

template <size_t N>
Str bytes(const unsigned char (&data)[N]) {
    return {reinterpret_cast<const char*>(data), static_cast<u32>(N)};
}

Str combine(char* output, u32 capacity, Str first, Str second, Str third = {}) {
    if (first.len > capacity || second.len > capacity - first.len ||
        third.len > capacity - first.len - second.len)
        return {};
    __builtin_memcpy(output, first.ptr, first.len);
    __builtin_memcpy(output + first.len, second.ptr, second.len);
    if (third.len) __builtin_memcpy(output + first.len + second.len, third.ptr, third.len);
    return {output, first.len + second.len + third.len};
}

Str replace(char* output, Str source, Str before, Str after) {
    for (u32 i = 0; i + before.len <= source.len; ++i) {
        if (Str{source.ptr + i, before.len}.eq(before))
            return combine(output,
                           2048,
                           {source.ptr, i},
                           after,
                           {source.ptr + i + before.len, source.len - i - before.len});
    }
    return {};
}
}  // namespace

TEST(ec_public_key, rfc7515_signature_and_independent_workspace_ownership) {
    EcP256PublicKey key;
    EcP256Sha256Verifier verifier;
    CHECK(!verifier.init(key));
    char input[512];
    REQUIRE(kEs256Jwk.len < sizeof(input));
    __builtin_memcpy(input, kEs256Jwk.ptr, kEs256Jwk.len);
    REQUIRE(key.load_es256_jwk({input, kEs256Jwk.len}));
    __builtin_memset(input, 0, sizeof(input));
    CHECK(!key.load_es256_jwk(kEs256Jwk));
    REQUIRE(verifier.init(key));
    CHECK(!verifier.init(key));
    key.reset();
    key.reset();
    CHECK(verifier.verify(kEs256SigningInput, bytes(kEs256Signature)));
    CHECK(!verifier.verify(lit_str("different signed bytes"), bytes(kEs256Signature)));
    verifier.reset();
    verifier.reset();
    CHECK(!verifier.verify(kEs256SigningInput, bytes(kEs256Signature)));
    REQUIRE(key.load_es256_jwk(kEs256Jwk));
    REQUIRE(verifier.init(key));
    CHECK(verifier.verify(kEs256SigningInput, bytes(kEs256Signature)));
}

TEST(ec_public_key, wrong_curve_algorithm_private_or_malformed_coordinates_reject) {
    char changed[2048];
    const Str from[] = {lit_str("\"EC\""),
                        lit_str("\"ES256\""),
                        lit_str("\"P-256\""),
                        lit_str("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"),
                        lit_str("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"),
                        lit_str("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")};
    const Str to[] = {lit_str("\"RSA\""),
                      lit_str("\"RS256\""),
                      lit_str("\"P-384\""),
                      lit_str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                      lit_str("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEV"),
                      lit_str("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU=")};
    for (u32 i = 0; i < sizeof(from) / sizeof(from[0]); ++i) {
        EcP256PublicKey key;
        REQUIRE(!replace(changed, kEs256Jwk, from[i], to[i]).empty());
        CHECK(!key.load_es256_jwk(replace(changed, kEs256Jwk, from[i], to[i])));
        CHECK(!key.valid());
        REQUIRE(key.load_es256_jwk(kEs256Jwk));
    }
    const Str additions[] = {lit_str(R"(,"d":"private"})"),
                             lit_str(R"(,"use":"enc"})"),
                             lit_str(R"(,"key_ops":["sign","verify"]})"),
                             lit_str(R"(,"x":"duplicate"})"),
                             lit_str(R"(,"\u0078":"duplicate"})")};
    for (Str suffix : additions) {
        EcP256PublicKey key;
        const Str text =
            combine(changed, sizeof(changed), {kEs256Jwk.ptr, kEs256Jwk.len - 1}, suffix);
        CHECK(!key.load_es256_jwk(text));
        CHECK(!key.valid());
    }
    EcP256PublicKey key;
    CHECK(!key.load(bytes(kRfcRsaSpki)));
    CHECK(!key.load(bytes(kEd25519Spki)));
    CHECK(!key.load({nullptr, 1}));
    CHECK(!key.load_es256_jwk(lit_str("{}")));
}

TEST(ec_public_key, both_s_representatives_and_integer_bounds) {
    EcP256PublicKey key;
    EcP256Sha256Verifier verifier;
    REQUIRE(key.load_es256_jwk(kEs256Jwk));
    REQUIRE(verifier.init(key));
    unsigned char modified[64];
    __builtin_memcpy(modified, kEs256Signature, sizeof(modified));
    BIGNUM* order = nullptr;
    REQUIRE(BN_hex2bn(&order, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"));
    BIGNUM* s = BN_bin2bn(kEs256Signature + 32, 32, nullptr);
    REQUIRE(s);
    REQUIRE(BN_sub(s, order, s));
    REQUIRE_EQ(BN_bn2binpad(s, modified + 32, 32), 32);
    CHECK(verifier.verify(kEs256SigningInput, bytes(modified)));
    BN_free(s);
    const u32 offsets[] = {0, 32};
    for (u32 offset : offsets) {
        __builtin_memcpy(modified, kEs256Signature, sizeof(modified));
        __builtin_memset(modified + offset, 0, 32);
        CHECK(!verifier.verify(kEs256SigningInput, bytes(modified)));
        REQUIRE_EQ(BN_bn2binpad(order, modified + offset, 32), 32);
        CHECK(!verifier.verify(kEs256SigningInput, bytes(modified)));
        __builtin_memset(modified + offset, 255, 32);
        CHECK(!verifier.verify(kEs256SigningInput, bytes(modified)));
    }
    BN_free(order);
    for (u32 length = 0; length < 64; ++length)
        CHECK(!verifier.verify(kEs256SigningInput,
                               {reinterpret_cast<const char*>(kEs256Signature), length}));
    CHECK(!verifier.verify(kEs256SigningInput, {nullptr, 64}));
    CHECK(!verifier.verify({nullptr, 1}, bytes(kEs256Signature)));
}

TEST(ec_public_key, first_request_and_adversarial_signatures_allocate_nothing) {
    EcP256PublicKey key;
    EcP256Sha256Verifier verifier;
    REQUIRE(key.load_es256_jwk(kEs256Jwk));
    REQUIRE(verifier.init(key));
    unsigned char signature[64];
    allocations = 0;
    count_allocations = true;
    bool accepted = verifier.verify(kEs256SigningInput, bytes(kEs256Signature));
    bool all_rejected = true;
    for (u32 i = 0; i < 128; ++i) {
        __builtin_memcpy(signature, kEs256Signature, sizeof(signature));
        signature[i / 2] ^= static_cast<u8>(1u << (i % 8));
        all_rejected &= !verifier.verify(kEs256SigningInput, bytes(signature));
    }
    __builtin_memset(signature, 0, sizeof(signature));
    all_rejected &= !verifier.verify(kEs256SigningInput, bytes(signature));
    __builtin_memset(signature, 255, sizeof(signature));
    all_rejected &= !verifier.verify(kEs256SigningInput, bytes(signature));
    accepted &= verifier.verify(kEs256SigningInput, bytes(kEs256Signature));
    count_allocations = false;
    CHECK(accepted);
    CHECK(all_rejected);
    CHECK_EQ(allocations, 0u);
}

TEST(ec_public_key, approved_subset_is_copied_exact_and_rolls_back_on_failure) {
    char jwks[2048];
    char entry[1024];
    const Str keyed = combine(
        entry, sizeof(entry), {kEs256Jwk.ptr, kEs256Jwk.len - 1}, lit_str(R"(,"kid":"approved"})"));
    const Str document = combine(jwks,
                                 sizeof(jwks),
                                 lit_str(R"({"keys":[)"),
                                 keyed,
                                 lit_str(R"(,{"kid":"untrusted","kty":"RSA"}]})"));
    Es256KeySet keys;
    const Str approved[] = {lit_str("approved")};
    REQUIRE(keys.load(document, approved, 1));
    Es256VerifierSet verifiers;
    REQUIRE(verifiers.init(keys));
    keys.reset();
    __builtin_memset(jwks, 0, sizeof(jwks));
    auto selected = verifiers.select(lit_str("approved"));
    REQUIRE(selected.verifier);
    CHECK(selected.kid.eq(lit_str("approved")));
    CHECK(selected.verifier->verify(kEs256SigningInput, bytes(kEs256Signature)));
    CHECK(!verifiers.select(lit_str("Approved")).verifier);
    CHECK(!verifiers.select(lit_str("untrusted")).verifier);
    verifiers.reset();
    CHECK(!verifiers.select(lit_str("approved")).verifier);

    const Str again = combine(jwks,
                              sizeof(jwks),
                              lit_str(R"({"keys":[)"),
                              keyed,
                              lit_str(R"(,{"kid":"untrusted","kty":"RSA"}]})"));
    const Str mixed[] = {lit_str("approved"), lit_str("untrusted")};
    CHECK(!keys.load(again, mixed, 2));
    CHECK(!keys.valid());
    REQUIRE(keys.load(again, approved, 1));
}

TEST(ec_public_key, crypto_errors_are_scoped_and_preserve_callers_error) {
    ERR_clear_error();
    EcP256PublicKey key;
    CHECK(!key.load(lit_str("malformed")));
    CHECK_EQ(ERR_peek_error(), 0ul);
    ERR_put_error(ERR_LIB_USER, 0, 42, __FILE__, __LINE__);
    const unsigned long previous = ERR_peek_last_error();
    REQUIRE(previous != 0);
    CHECK(!key.load(lit_str("malformed")));
    CHECK_EQ(ERR_peek_last_error(), previous);
    ERR_clear_error();
}

TEST(ec_public_key, canonical_der_import_rejects_truncation_trailing_and_ber) {
    EcP256PublicKey key;
    for (u32 i = 0; i < sizeof(kEs256Spki); ++i) {
        CHECK(!key.load({reinterpret_cast<const char*>(kEs256Spki), i}));
        CHECK(!key.valid());
    }
    unsigned char alternate[sizeof(kEs256Spki) + 1];
    __builtin_memcpy(alternate, kEs256Spki, sizeof(kEs256Spki));
    alternate[sizeof(kEs256Spki)] = 0;
    CHECK(!key.load(bytes(alternate)));
    alternate[0] = 0x30;
    alternate[1] = 0x81;
    alternate[2] = kEs256Spki[1];
    __builtin_memcpy(alternate + 3, kEs256Spki + 2, sizeof(kEs256Spki) - 2);
    CHECK(!key.load(bytes(alternate)));
    REQUIRE(key.load(bytes(kEs256Spki)));
    EcP256Sha256Verifier verifier;
    REQUIRE(verifier.init(key));
    CHECK(verifier.verify(kEs256SigningInput, bytes(kEs256Signature)));
}

TEST(ec_public_key, generator_and_negative_generator_have_no_lazy_math_allocation) {
    const Str keys[] = {kEs256GeneratorJwk, kEs256NegativeGeneratorJwk};
    const Str signatures[] = {bytes(kEs256GeneratorSignature),
                              bytes(kEs256NegativeGeneratorSignature)};
    for (u32 i = 0; i < 2; ++i) {
        EcP256PublicKey key;
        EcP256Sha256Verifier verifier;
        REQUIRE(key.load_es256_jwk(keys[i]));
        REQUIRE(verifier.init(key));
        allocations = 0;
        count_allocations = true;
        const bool accepted = verifier.verify(lit_str("edge"), signatures[i]);
        const bool rejected = !verifier.verify(lit_str("different"), signatures[i]);
        count_allocations = false;
        CHECK(accepted);
        CHECK(rejected);
        CHECK_EQ(allocations, 0u);
    }
}

TEST(ec_public_key, activation_allocation_failure_rolls_back_and_can_restart) {
    EcP256PublicKey key;
    REQUIRE(key.load_es256_jwk(kEs256Jwk));
    EcP256Sha256Verifier verifier;
    bool reached_success = false;
    for (i64 budget = 0; budget < 256; ++budget) {
        allocation_budget = budget;
        const bool ready = verifier.init(key);
        allocation_budget = -1;
        CHECK_EQ(verifier.valid(), ready);
        if (ready) {
            CHECK(verifier.verify(kEs256SigningInput, bytes(kEs256Signature)));
            reached_success = true;
        }
        verifier.reset();
        REQUIRE(verifier.init(key));
        CHECK(verifier.verify(kEs256SigningInput, bytes(kEs256Signature)));
        verifier.reset();
        if (reached_success) break;
    }
    CHECK(reached_success);
}

int main(int argc, char** argv) {
    if (!CRYPTO_set_mem_functions(crypto_alloc, crypto_realloc, crypto_free)) return 1;
    return rut::test::run_all(argc, argv);
}
