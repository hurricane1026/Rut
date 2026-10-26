#include "public_key_fixtures.h"
#include "rut/runtime/public_key.h"
#include "test.h"

#include <openssl/err.h>

using namespace rut;

template <size_t N>
static Str der(const unsigned char (&bytes)[N]) {
    return {reinterpret_cast<const char*>(bytes), static_cast<u32>(N)};
}

TEST(public_key, owner_retains_parsed_key_not_the_configuration_view) {
    RsaPublicKey key;
    CHECK(!key.valid());
    CHECK_EQ(key.bits(), 0u);
    char source[sizeof(kRfcRsaSpki)];
    for (u32 i = 0; i < sizeof(source); ++i) source[i] = kRfcRsaSpki[i];
    REQUIRE(key.load({source, sizeof(source)}));
    for (char& byte : source) byte = 0;
    CHECK(key.valid());
    CHECK_EQ(key.bits(), 2048u);
    CHECK(!key.load(der(kRfcRsaSpki)));
    CHECK_EQ(key.bits(), 2048u);
    key.reset();
    key.reset();
    CHECK(!key.valid());
    CHECK_EQ(key.bits(), 0u);
    REQUIRE(key.load(der(kRfcRsaSpki)));
}

TEST(public_key, invalid_input_does_not_publish_a_partial_key) {
    RsaPublicKey key;
    CHECK(!key.load({nullptr, 0}));
    CHECK(!key.load({nullptr, 10}));
    CHECK(!key.load({"", 0}));
    char too_big[RsaPublicKey::kMaxDerBytes + 1]{};
    CHECK(!key.load({too_big, sizeof(too_big)}));
    const Str full = der(kRfcRsaSpki);
    for (u32 len = 1; len < full.len; ++len) {
        CHECK(!key.load({full.ptr, len}));
        CHECK(!key.valid());
    }
    char trailing[sizeof(kRfcRsaSpki) + 1];
    for (u32 i = 0; i < sizeof(kRfcRsaSpki); ++i) trailing[i] = kRfcRsaSpki[i];
    trailing[sizeof(kRfcRsaSpki)] = 0;
    CHECK(!key.load({trailing, sizeof(trailing)}));
    CHECK(!key.load(lit_str("-----BEGIN PUBLIC KEY-----")));
    CHECK(!key.valid());
    REQUIRE(key.load(full));
}

TEST(public_key, rsa_profile_rejects_key_type_size_and_exponent_confusion) {
    const Str invalid[] = {
        der(kExponentThreeSpki), der(kWeakRsaSpki), der(kOversizeRsaSpki), der(kEd25519Spki)};
    for (u32 repeat = 0; repeat < 32; ++repeat) {
        RsaPublicKey key;
        for (Str input : invalid) {
            CHECK(!key.load(input));
            CHECK(!key.valid());
        }
        REQUIRE(key.load(der(kRfcRsaSpki)));
        CHECK_EQ(key.bits(), 2048u);
    }
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}

TEST(public_key, noncanonical_ber_is_not_an_alternate_key_configuration) {
    RsaPublicKey key;
    unsigned char ber[sizeof(kRfcRsaSpki) + 1];
    REQUIRE_EQ(kRfcRsaSpki[1], 0x82u);
    ber[0] = kRfcRsaSpki[0];
    ber[1] = 0x83;
    ber[2] = 0;
    for (u32 i = 2; i < sizeof(kRfcRsaSpki); ++i) ber[i + 1] = kRfcRsaSpki[i];
    CHECK(!key.load(der(ber)));
    CHECK(!key.valid());
    REQUIRE(key.load(der(kRfcRsaSpki)));
}

TEST(public_key, parse_failures_do_not_pollute_the_callers_crypto_errors) {
    ERR_clear_error();
    RsaPublicKey key;
    CHECK(!key.load(lit_str("malformed")));
    CHECK_EQ(ERR_peek_error(), 0ul);
    ERR_put_error(ERR_LIB_USER, 0, 42, __FILE__, __LINE__);
    const unsigned long previous = ERR_peek_last_error();
    REQUIRE(previous != 0);
    CHECK(!key.load(lit_str("malformed")));
    CHECK_EQ(ERR_peek_last_error(), previous);
    ERR_clear_error();
}
