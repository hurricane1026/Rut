#include "rut/runtime/hash.h"
#include "test.h"

using namespace rut;

namespace {
void expect_hash(rut::test::TestCase* _tc,
                 HashAlgorithm algorithm,
                 Str data,
                 Str key,
                 bool keyed,
                 Str expected) {
    char output[kMaxHashHexBytes];
    u32 length = 0;
    REQUIRE(hash_hex(algorithm, data, key, keyed, output, length));
    CHECK((Str{output, length}.eq(expected)));
}
}  // namespace

TEST(hash, digests_empty) {
    expect_hash(
        _tc, HashAlgorithm::Md5, {"", 0}, {}, false, lit_str("d41d8cd98f00b204e9800998ecf8427e"));
    expect_hash(_tc,
                HashAlgorithm::Sha1,
                {"", 0},
                {},
                false,
                lit_str("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    expect_hash(_tc,
                HashAlgorithm::Sha224,
                {"", 0},
                {},
                false,
                lit_str("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"));
    expect_hash(_tc,
                HashAlgorithm::Sha256,
                {"", 0},
                {},
                false,
                lit_str("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    expect_hash(_tc,
                HashAlgorithm::Sha384,
                {"", 0},
                {},
                false,
                lit_str("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe7"
                        "6f65fbd51ad2f14898b95b"));
    expect_hash(_tc,
                HashAlgorithm::Sha512,
                {"", 0},
                {},
                false,
                lit_str("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d"
                        "85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"));
}

TEST(hash, digests_abc) {
    expect_hash(_tc,
                HashAlgorithm::Md5,
                {"\x61\x62\x63", 3},
                {},
                false,
                lit_str("900150983cd24fb0d6963f7d28e17f72"));
    expect_hash(_tc,
                HashAlgorithm::Sha1,
                {"\x61\x62\x63", 3},
                {},
                false,
                lit_str("a9993e364706816aba3e25717850c26c9cd0d89d"));
    expect_hash(_tc,
                HashAlgorithm::Sha224,
                {"\x61\x62\x63", 3},
                {},
                false,
                lit_str("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"));
    expect_hash(_tc,
                HashAlgorithm::Sha256,
                {"\x61\x62\x63", 3},
                {},
                false,
                lit_str("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    expect_hash(_tc,
                HashAlgorithm::Sha384,
                {"\x61\x62\x63", 3},
                {},
                false,
                lit_str("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1"
                        "e7cc2358baeca134c825a7"));
    expect_hash(_tc,
                HashAlgorithm::Sha512,
                {"\x61\x62\x63", 3},
                {},
                false,
                lit_str("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a27"
                        "4fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
}

TEST(hash, digests_binary) {
    expect_hash(_tc,
                HashAlgorithm::Md5,
                {"\x61\x00\x62\xff", 4},
                {},
                false,
                lit_str("0dd4df5b5be53b9566c53387ec9a7bac"));
    expect_hash(_tc,
                HashAlgorithm::Sha1,
                {"\x61\x00\x62\xff", 4},
                {},
                false,
                lit_str("63fcb4a9187af3e3e3319584f43e809426e0b000"));
    expect_hash(_tc,
                HashAlgorithm::Sha224,
                {"\x61\x00\x62\xff", 4},
                {},
                false,
                lit_str("6aa2a868a9c3ce5b5410a8873d4d7dac6d755965e4836f79dd30fe47"));
    expect_hash(_tc,
                HashAlgorithm::Sha256,
                {"\x61\x00\x62\xff", 4},
                {},
                false,
                lit_str("a37cc3026aae4d519e0b19c298fa913b4dccfdf0658cbccbb7deaa0226d5acdb"));
    expect_hash(_tc,
                HashAlgorithm::Sha384,
                {"\x61\x00\x62\xff", 4},
                {},
                false,
                lit_str("47f55ceefdbee8e10c2d3621c27916990d7dc39155a09dffc95096d05b7f920f60218dc4a0"
                        "e184b24a6a3a68b90f5765"));
    expect_hash(_tc,
                HashAlgorithm::Sha512,
                {"\x61\x00\x62\xff", 4},
                {},
                false,
                lit_str("1e76645fa15e740d214209146606412765717327c1ec1f3f8ef0bb29af267ff80fbc4a4594"
                        "20a32b19508e17520e7ded1cf6a9633186d1f1381aa67dc075ef39"));
}

TEST(hash, hmac_rfc_jefe) {
    expect_hash(_tc,
                HashAlgorithm::Md5,
                {"\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20"
                 "\x6e\x6f\x74\x68\x69\x6e\x67\x3f",
                 28},
                {"\x4a\x65\x66\x65", 4},
                true,
                lit_str("750c783e6ab0b503eaa86e310a5db738"));
    expect_hash(_tc,
                HashAlgorithm::Sha1,
                {"\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20"
                 "\x6e\x6f\x74\x68\x69\x6e\x67\x3f",
                 28},
                {"\x4a\x65\x66\x65", 4},
                true,
                lit_str("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"));
    expect_hash(_tc,
                HashAlgorithm::Sha224,
                {"\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20"
                 "\x6e\x6f\x74\x68\x69\x6e\x67\x3f",
                 28},
                {"\x4a\x65\x66\x65", 4},
                true,
                lit_str("a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44"));
    expect_hash(_tc,
                HashAlgorithm::Sha256,
                {"\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20"
                 "\x6e\x6f\x74\x68\x69\x6e\x67\x3f",
                 28},
                {"\x4a\x65\x66\x65", 4},
                true,
                lit_str("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    expect_hash(_tc,
                HashAlgorithm::Sha384,
                {"\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20"
                 "\x6e\x6f\x74\x68\x69\x6e\x67\x3f",
                 28},
                {"\x4a\x65\x66\x65", 4},
                true,
                lit_str("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e"
                        "69e2c78b3239ecfab21649"));
    expect_hash(_tc,
                HashAlgorithm::Sha512,
                {"\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20"
                 "\x6e\x6f\x74\x68\x69\x6e\x67\x3f",
                 28},
                {"\x4a\x65\x66\x65", 4},
                true,
                lit_str("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c0"
                        "5a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"));
}

TEST(hash, hmac_long_key) {
    char key[131];
    for (char& c : key) c = static_cast<char>(0xaa);
    expect_hash(_tc,
                HashAlgorithm::Md5,
                {"\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65\x72\x20\x54\x68"
                 "\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a\x65\x20\x4b\x65\x79\x20\x2d\x20"
                 "\x48\x61\x73\x68\x20\x4b\x65\x79\x20\x46\x69\x72\x73\x74",
                 54},
                {key, sizeof(key)},
                true,
                lit_str("bfecaf4efff90a3a668f3922fec3762d"));
    expect_hash(_tc,
                HashAlgorithm::Sha1,
                {"\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65\x72\x20\x54\x68"
                 "\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a\x65\x20\x4b\x65\x79\x20\x2d\x20"
                 "\x48\x61\x73\x68\x20\x4b\x65\x79\x20\x46\x69\x72\x73\x74",
                 54},
                {key, sizeof(key)},
                true,
                lit_str("90d0dace1c1bdc957339307803160335bde6df2b"));
    expect_hash(_tc,
                HashAlgorithm::Sha224,
                {"\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65\x72\x20\x54\x68"
                 "\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a\x65\x20\x4b\x65\x79\x20\x2d\x20"
                 "\x48\x61\x73\x68\x20\x4b\x65\x79\x20\x46\x69\x72\x73\x74",
                 54},
                {key, sizeof(key)},
                true,
                lit_str("95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e"));
    expect_hash(_tc,
                HashAlgorithm::Sha256,
                {"\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65\x72\x20\x54\x68"
                 "\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a\x65\x20\x4b\x65\x79\x20\x2d\x20"
                 "\x48\x61\x73\x68\x20\x4b\x65\x79\x20\x46\x69\x72\x73\x74",
                 54},
                {key, sizeof(key)},
                true,
                lit_str("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
    expect_hash(_tc,
                HashAlgorithm::Sha384,
                {"\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65\x72\x20\x54\x68"
                 "\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a\x65\x20\x4b\x65\x79\x20\x2d\x20"
                 "\x48\x61\x73\x68\x20\x4b\x65\x79\x20\x46\x69\x72\x73\x74",
                 54},
                {key, sizeof(key)},
                true,
                lit_str("4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab40"
                        "30fe8296248df163f44952"));
    expect_hash(_tc,
                HashAlgorithm::Sha512,
                {"\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65\x72\x20\x54\x68"
                 "\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a\x65\x20\x4b\x65\x79\x20\x2d\x20"
                 "\x48\x61\x73\x68\x20\x4b\x65\x79\x20\x46\x69\x72\x73\x74",
                 54},
                {key, sizeof(key)},
                true,
                lit_str("80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e0"
                        "5f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"));
}

TEST(hash, hmac_empty_key) {
    expect_hash(_tc,
                HashAlgorithm::Md5,
                {"", 0},
                {"", 0},
                true,
                lit_str("74e6f7298a9c2d168935f58c001bad88"));
    expect_hash(_tc,
                HashAlgorithm::Sha1,
                {"", 0},
                {"", 0},
                true,
                lit_str("fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"));
    expect_hash(_tc,
                HashAlgorithm::Sha224,
                {"", 0},
                {"", 0},
                true,
                lit_str("5ce14f72894662213e2748d2a6ba234b74263910cedde2f5a9271524"));
    expect_hash(_tc,
                HashAlgorithm::Sha256,
                {"", 0},
                {"", 0},
                true,
                lit_str("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"));
    expect_hash(_tc,
                HashAlgorithm::Sha384,
                {"", 0},
                {"", 0},
                true,
                lit_str("6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d3551289e75e8"
                        "209cd4b792302840234adc"));
    expect_hash(_tc,
                HashAlgorithm::Sha512,
                {"", 0},
                {"", 0},
                true,
                lit_str("b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421"
                        "b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47"));
}

TEST(hash, hmac_binary_key_and_data) {
    expect_hash(_tc,
                HashAlgorithm::Md5,
                {"\x61\x00\x62\xff", 4},
                {"\x6b\x65\x79\x00\x73\x65\x63\x72\x65\x74", 10},
                true,
                lit_str("4ca47cabea28b0ff625bd51ee7a99009"));
    expect_hash(_tc,
                HashAlgorithm::Sha1,
                {"\x61\x00\x62\xff", 4},
                {"\x6b\x65\x79\x00\x73\x65\x63\x72\x65\x74", 10},
                true,
                lit_str("983556e8c2281a87b44ffa7ed34cb1395907dbcc"));
    expect_hash(_tc,
                HashAlgorithm::Sha224,
                {"\x61\x00\x62\xff", 4},
                {"\x6b\x65\x79\x00\x73\x65\x63\x72\x65\x74", 10},
                true,
                lit_str("f5501978dabb0520e3593258b2509644e13c6d6dd7451176c32b1ac7"));
    expect_hash(_tc,
                HashAlgorithm::Sha256,
                {"\x61\x00\x62\xff", 4},
                {"\x6b\x65\x79\x00\x73\x65\x63\x72\x65\x74", 10},
                true,
                lit_str("25ae054ebc485b2958453378b3d060442cb69825e7836451673a73c22a9a191c"));
    expect_hash(_tc,
                HashAlgorithm::Sha384,
                {"\x61\x00\x62\xff", 4},
                {"\x6b\x65\x79\x00\x73\x65\x63\x72\x65\x74", 10},
                true,
                lit_str("8ed74017663c1696a464732ec1a8f74b683d1caacbcbb759450ea60ac54ba97626af77e203"
                        "e8513ee67b22af716f21f4"));
    expect_hash(_tc,
                HashAlgorithm::Sha512,
                {"\x61\x00\x62\xff", 4},
                {"\x6b\x65\x79\x00\x73\x65\x63\x72\x65\x74", 10},
                true,
                lit_str("7caba61fd31e06171f13bfb0697b4b0e051c08c7d1048ca017e334e41acfd64644d8734438"
                        "4f9f38f655d2eb1cc1ab14f22a83d1ca5b77eef7db7aab2fc90af9"));
}

TEST(hash, invalid_spans_algorithms_and_output_capacity_fail_closed) {
    char output[kMaxHashHexBytes];
    u32 length = 123;
    CHECK(!hash_hex(HashAlgorithm::Sha256, {nullptr, 1}, {}, false, output, length));
    CHECK_EQ(length, 0u);
    CHECK(!hash_hex(HashAlgorithm::Sha256, {}, {nullptr, 1}, true, output, length));
    CHECK(!hash_hex(static_cast<HashAlgorithm>(255), {}, {}, false, output, length));
    CHECK(
        !hash_hex(HashAlgorithm::Sha256, {"x", kMaxHashInputBytes + 1}, {}, false, output, length));
    CHECK(!hash_hex(HashAlgorithm::Sha256, {}, {"x", kMaxHashKeyBytes + 1}, true, output, length));
    u8 raw[kMaxHashDigestBytes];
    CHECK(!hash_digest(HashAlgorithm::Sha256, {}, {}, false, raw, 31, length));
    CHECK(!hash_digest(HashAlgorithm::Sha256, {}, {}, false, nullptr, sizeof(raw), length));
    CHECK_EQ(length, 0u);
}

TEST(hash, exact_public_capacity_limits) {
    static char data[kMaxHashInputBytes];
    char key[kMaxHashKeyBytes];
    for (char& c : data) c = 'm';
    for (char& c : key) c = 'k';
    expect_hash(_tc,
                HashAlgorithm::Sha512,
                {data, sizeof(data)},
                {key, sizeof(key)},
                true,
                lit_str("a8a75863562f7b04f81f8550357ec4a8616bc86f418ecb3853739ad1a8f32770f5d222ba65"
                        "9c81f9eb125f55db3c5a024b9116442aba247ba0a44b956a7595fb"));
    expect_hash(_tc,
                HashAlgorithm::Md5,
                {data, sizeof(data)},
                {},
                false,
                lit_str("12564a07eb1f09728e729910398fd87f"));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
