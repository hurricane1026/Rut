#include "rut/runtime/hash.h"
#include "rut/runtime/webhook.h"
#include "test.h"

#include <openssl/crypto.h>
#include <stdlib.h>

using namespace rut;
namespace {
constexpr Str kId = lit_str("msg_p5jXN8AQM9LWM0D4loKWxJek");
constexpr Str kTime = lit_str("1700000000");
constexpr Str kBody = lit_str(R"({"test": 2432232314})");
// Inputs from upstream Python fixtures, frozen at 1700000000; expected HMAC
// independently generated with Python hashlib/hmac + standard Base64.
// https://github.com/standard-webhooks/standard-webhooks/blob/main/libraries/python/tests/test_webhooks.py
constexpr Str kKey = {
    "\x31\xf2\x90\xf6\xbf\x06\x29\x8a\xab\x4f\x08\xd4\x3c\x3f\x08\x2c\xf6\x48\xa3\x62\xda\x2d\xa4"
    "\xb0",
    24};
constexpr Str kSignature = lit_str("v1,hw6D+jquXiPwVQiZTwb2ek9FSrOofldv7tv4JVMsFUY=");
bool tracking = false;
u32 allocations = 0;
void* counted_malloc(size_t n, const char*, int) {
    if (tracking) ++allocations;
    return malloc(n);
}
void* counted_realloc(void* p, size_t n, const char*, int) {
    if (tracking) ++allocations;
    return realloc(p, n);
}
void counted_free(void* p, const char*, int) {
    free(p);
}
bool valid(Str signature = kSignature, i64 now = 1700000000, u32 tolerance = 300) {
    return standard_webhook_valid(kId, kTime, signature, kBody, kKey, now, tolerance);
}
}  // namespace

TEST(webhook, independent_vectors_and_signed_fields) {
    REQUIRE(valid());
    CHECK(standard_webhook_valid(kId,
                                 kTime,
                                 lit_str("v1,SD4La63LqI/55GXL7keho7EQPRxH8uX05GUYX4CjFc8="),
                                 {},
                                 kKey,
                                 1700000000));
    CHECK(standard_webhook_valid(kId,
                                 kTime,
                                 lit_str("v1,gXBDTL3ylVosZ4YM+wgx/9jJlZEyMuHcP9L5MudsMuQ="),
                                 {"a\0b\xff", 4},
                                 kKey,
                                 1700000000));
    CHECK(!standard_webhook_valid(lit_str("other"), kTime, kSignature, kBody, kKey, 1700000000));
    CHECK(!standard_webhook_valid(kId, lit_str("1700000001"), kSignature, kBody, kKey, 1700000000));
    CHECK(!standard_webhook_valid(
        kId, kTime, kSignature, lit_str(R"({"test":2432232314})"), kKey, 1700000000));
    CHECK(!standard_webhook_valid(kId, kTime, kSignature, kBody, lit_str("wrong"), 1700000000));
    CHECK(valid());  // Freshness is not deduplication: a replay still verifies.
}
TEST(webhook, freshness_boundaries_and_invalid_metadata) {
    CHECK(valid(kSignature, 1699999700));
    CHECK(valid(kSignature, 1700000300));
    CHECK(!valid(kSignature, 1699999699));
    CHECK(!valid(kSignature, 1700000301));
    CHECK(valid(kSignature, 1700000000, 0));
    CHECK(!valid(kSignature, 1700000001, 0));
    CHECK(!valid(kSignature, 1700000000, 301));
    CHECK(!valid(kSignature, 0));
    CHECK(!valid(kSignature, -1));
    const Str timestamps[] = {lit_str(""),
                              lit_str("0"),
                              lit_str("01700000000"),
                              lit_str("+1700000000"),
                              lit_str("-1"),
                              lit_str("1700000000 "),
                              lit_str("1700000000.0"),
                              lit_str("1e9"),
                              lit_str("9223372036854775808"),
                              lit_str("9999999999999999999"),
                              {nullptr, 1}};
    for (Str timestamp : timestamps)
        CHECK(!standard_webhook_valid(kId, timestamp, kSignature, kBody, kKey, 1700000000));
    const Str ids[] = {{},
                       {nullptr, 1},
                       lit_str("a.b"),
                       lit_str("a b"),
                       lit_str("a\tb"),
                       lit_str("a\rb"),
                       lit_str("a\nb"),
                       {"a\0b", 3},
                       {"\xff", 1},
                       {"x", 257}};
    for (Str id : ids)
        CHECK(!standard_webhook_valid(id, kTime, kSignature, kBody, kKey, 1700000000));
    CHECK(!standard_webhook_valid(kId, kTime, kSignature, {nullptr, 1}, kKey, 1700000000));
    CHECK(!standard_webhook_valid(
        kId, kTime, kSignature, {"x", kMaxHashInputBytes + 1}, kKey, 1700000000));
    CHECK(!standard_webhook_valid(kId, kTime, kSignature, kBody, {}, 1700000000));
    CHECK(!standard_webhook_valid(kId, kTime, kSignature, kBody, {nullptr, 1}, 1700000000));
    CHECK(!standard_webhook_valid(kId, kTime, kSignature, kBody, {"x", 4097}, 1700000000));
}
TEST(webhook, rotation_unknown_versions_and_entire_list_validation) {
    const Str bad[] = {{},
                       {nullptr, 1},
                       {"x", 4097},
                       lit_str("v2,opaque"),
                       lit_str("v1,hw6D+jquXiPwVQiZTwb2ek9FSrOofldv7tv4JVMsFUY"),
                       lit_str("v1,hw6D+jquXiPwVQiZTwb2ek9FSrOofldv7tv4JVMsFUZ="),
                       lit_str("v1,hw6D-jquXiPwVQiZTwb2ek9FSrOofldv7tv4JVMsFUY="),
                       lit_str(" v1,hw6D+jquXiPwVQiZTwb2ek9FSrOofldv7tv4JVMsFUY="),
                       lit_str("v1,hw6D+jquXiPwVQiZTwb2ek9FSrOofldv7tv4JVMsFUY= "),
                       lit_str("v1,hw6D+jquXiPwVQiZTwb2ek9FSrOofldv7tv4JVMsFUY=  v2,x"),
                       lit_str("v1,hw6D+jquXiPwVQiZTwb2ek9FSrOofldv7tv4JVMsFUY= v1,bad"),
                       lit_str("v1,hw6D+jquXiPwVQiZTwb2ek9FSrOofldv7tv4JVMsFUY= v2,"),
                       lit_str("v1,hw6D+jquXiPwVQiZTwb2ek9FSrOofldv7tv4JVMsFUY= v2,x,y"),
                       lit_str("v1,hw6D+jquXiPwVQiZTwb2ek9FSrOofldv7tv4JVMsFUY= v2,x\r\n"),
                       lit_str("V1,hw6D+jquXiPwVQiZTwb2ek9FSrOofldv7tv4JVMsFUY=")};
    for (Str signature : bad) CHECK(!valid(signature));
    CHECK(valid(lit_str("v2,opaque v1,hw6D+jquXiPwVQiZTwb2ek9FSrOofldv7tv4JVMsFUY=")));
    CHECK(
        valid(lit_str("v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= "
                      "v1,hw6D+jquXiPwVQiZTwb2ek9FSrOofldv7tv4JVMsFUY= v1a,opaque")));
    char list[1024];
    const u32 counts[] = {16u, 17u};
    for (u32 count : counts) {
        u32 length = 0;
        for (u32 i = 0; i < count; ++i) {
            if (i) list[length++] = ' ';
            for (u32 j = 0; j < kSignature.len; ++j) list[length++] = kSignature.ptr[j];
        }
        CHECK_EQ(valid({list, length}), count == 16);
    }
    char maximum[4097];
    for (u32 i = 0; i < kSignature.len; ++i) maximum[i] = kSignature.ptr[i];
    u32 offset = kSignature.len;
    maximum[offset++] = ' ';
    maximum[offset++] = 'v';
    maximum[offset++] = '2';
    maximum[offset++] = ',';
    for (u32 i = offset; i < sizeof(maximum); ++i) maximum[i] = 'x';
    CHECK(valid({maximum, 4096}));
    CHECK(!valid({maximum, 4097}));
}
TEST(webhook, bounded_scatter_hash_and_request_allocations) {
    REQUIRE(valid());
    tracking = true;
    for (u32 i = 0; i < 10; ++i) {
        CHECK(valid());
        CHECK(!valid(kSignature, 1700000301));
    }
    tracking = false;
    CHECK_EQ(allocations, 0u);
    const Str parts[] = {lit_str("a"), {}, {"\0b", 2}};
    u8 contiguous[64], split[64];
    u32 left = 0, right = 0;
    const HashAlgorithm algorithms[] = {HashAlgorithm::Md5,
                                        HashAlgorithm::Sha1,
                                        HashAlgorithm::Sha224,
                                        HashAlgorithm::Sha256,
                                        HashAlgorithm::Sha384,
                                        HashAlgorithm::Sha512};
    for (HashAlgorithm algorithm : algorithms) {
        const bool modes[] = {false, true};
        for (bool keyed : modes) {
            REQUIRE(hash_digest(algorithm, {"a\0b", 3}, kKey, keyed, contiguous, 64, left));
            REQUIRE(hash_digest_parts(algorithm, parts, 3, kKey, keyed, split, 64, right));
            CHECK_EQ(left, right);
            for (u32 i = 0; i < left; ++i) CHECK_EQ(contiguous[i], split[i]);
        }
    }
    CHECK(!hash_digest_parts(HashAlgorithm::Sha256, nullptr, 1, kKey, true, split, 64, right));
    CHECK_EQ(right, 0u);
    CHECK(!hash_digest_parts(HashAlgorithm::Sha256, parts, 17, kKey, true, split, 64, right));
    const Str invalid[] = {{nullptr, 1}};
    CHECK(!hash_digest_parts(HashAlgorithm::Sha256, invalid, 1, kKey, true, split, 64, right));
}
TEST(webhook, maximum_sizes_and_clock_arithmetic) {
    static char body[kMaxHashInputBytes];
    char id[256];
    for (char& c : body) c = 'm';
    for (char& c : id) c = 'a';
    CHECK(standard_webhook_valid({id, sizeof(id)},
                                 kTime,
                                 lit_str("v1,R9ZUcb8gElyKtkha+Xp01k9bXq2s2paOL2ZSVmQTDTs="),
                                 {body, sizeof(body)},
                                 kKey,
                                 1700000000));
    constexpr Str kMax = lit_str("9223372036854775807");
    constexpr Str kHighSignature = lit_str("v1,ivTu0nVznvilnVLKLgcczSvM5Qw6L5/310RUd61H+w8=");
    CHECK(standard_webhook_valid(
        lit_str("a"), kMax, kHighSignature, {}, kKey, 9223372036854775807LL));
    CHECK(standard_webhook_valid(
        lit_str("a"), kMax, kHighSignature, {}, kKey, 9223372036854775507LL));
    CHECK(!standard_webhook_valid(
        lit_str("a"), kMax, kHighSignature, {}, kKey, 9223372036854775506LL));
    CHECK(!standard_webhook_valid(lit_str("a"), kMax, kHighSignature, {}, kKey, 1));
    char key[4096];
    for (char& c : key) c = 'k';
    constexpr Str kLowSignature = lit_str("v1,9SO7sGuWrMkuW4dfHW6RAsm7eDLqtt73gA40g7/km7o=");
    CHECK(standard_webhook_valid(
        lit_str("a"), lit_str("1"), kLowSignature, {}, {key, sizeof(key)}, 1));
    CHECK(standard_webhook_valid(
        lit_str("a"), lit_str("1"), kLowSignature, {}, {key, sizeof(key)}, 301));
    CHECK(!standard_webhook_valid(
        lit_str("a"), lit_str("1"), kLowSignature, {}, {key, sizeof(key)}, 302));
    CHECK(!standard_webhook_valid(
        lit_str("a"), lit_str("1"), kLowSignature, {}, {key, sizeof(key)}, 9223372036854775807LL));
}
int main(int argc, char** argv) {
    if (!CRYPTO_set_mem_functions(counted_malloc, counted_realloc, counted_free)) return 2;
    return rut::test::run_all(argc, argv);
}
