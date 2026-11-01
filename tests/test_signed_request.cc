#include "rut/runtime/signed_request.h"
#include "test.h"

#include <openssl/crypto.h>
#include <stdlib.h>

using namespace rut;
namespace {
constexpr Str kGetDate = lit_str("Wed, 21 Oct 2015 07:28:00 GMT");
constexpr Str kGetDigest = lit_str("SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
constexpr Str kGetAuth = lit_str(
    "Signature keyId=\"key-1\",algorithm=\"hmac-sha256\",headers=\"@request-target date digest\","
    "signature=\"aXAPP5PHaRkQ03BHoTSPxmnTK/DmwBPY8WnLziletmQ=\"");
constexpr Str kPostDate = lit_str("Tue, 14 Nov 2023 22:13:20 GMT");
constexpr Str kPostDigest = lit_str("SHA-256=KrAu3xp6jgTV9B5KgztSeRRT6OQKLXXoURU47mms6ZA=");
constexpr Str kPostAuth = lit_str(
    "Signature keyId=\"kid-A\",algorithm=\"hmac-sha256\",headers=\"@request-target date digest\","
    "signature=\"hsd9DbOVH6MWfFBx+1QaLwOPi7kt8mELWkoxY0Scmj8=\"");
constexpr char kPostBodyBytes[] = {
    '\0', 'a', static_cast<char>(0xff), '\r', '\n', 'b', 'o', 'd', 'y'};
constexpr Str kPostBody = {kPostBodyBytes, sizeof(kPostBodyBytes)};
constexpr Str kPostSecret = lit_str("webhook-secret");
char g_oversized_input[1024 * 1024 + 1];
char g_max_target[8192];
char g_max_key_id[128];
char g_max_secret[4096];
char g_max_auth[512];

bool append(char* output, u32 capacity, u32& length, Str value) {
    if (!value.ptr || value.len > capacity - length) return false;
    __builtin_memcpy(output + length, value.ptr, value.len);
    length += value.len;
    return true;
}

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

bool get_valid(Str method = lit_str("GET"),
               Str target = lit_str("/v1/items?x=a%2Fb"),
               Str auth = kGetAuth,
               Str date = kGetDate,
               Str digest = kGetDigest,
               Str body = {},
               Str kid = lit_str("key-1"),
               Str secret = lit_str("fixed-secret-0123456789"),
               i64 now = 1445412480) {
    return signed_request_hmac_sha256_valid(
        method, target, auth, date, digest, body, kid, secret, now);
}

}  // namespace

TEST(signed_request, independent_python_vectors_cover_empty_and_binary_body) {
    // Frozen independently generated Python hashlib.sha256 / hmac / base64 vectors.
    CHECK(get_valid());
    CHECK(signed_request_hmac_sha256_valid(lit_str("POST"),
                                           lit_str("/hooks?mode=raw"),
                                           kPostAuth,
                                           kPostDate,
                                           kPostDigest,
                                           kPostBody,
                                           lit_str("kid-A"),
                                           kPostSecret,
                                           1700000000));

    const Str reordered = lit_str(
        "Signature headers=\"@request-target date digest\", keyId=\"key-1\",\t"
        "signature=\"aXAPP5PHaRkQ03BHoTSPxmnTK/DmwBPY8WnLziletmQ=\",algorithm=\"hmac-sha256\"");
    CHECK(get_valid(lit_str("GET"), lit_str("/v1/items?x=a%2Fb"), reordered));
    CHECK(get_valid());  // Repeated verification is permitted; this profile does not deduplicate.
}

TEST(signed_request, rejects_changes_to_every_signed_input) {
    CHECK_FALSE(get_valid(lit_str("POST")));
    CHECK_FALSE(get_valid(lit_str("GET"), lit_str("/v1/items?x=a/b")));
    CHECK_FALSE(get_valid(lit_str("GET"), lit_str("/v1/items?x=a%2Fb#part")));
    CHECK_FALSE(get_valid(lit_str("GET"),
                          lit_str("/v1/items?x=a%2Fb"),
                          kGetAuth,
                          lit_str("Wed, 21 Oct 2015 07:28:01 GMT")));
    CHECK_FALSE(get_valid(lit_str("GET"),
                          lit_str("/v1/items?x=a%2Fb"),
                          kGetAuth,
                          kGetDate,
                          kGetDigest,
                          lit_str("x")));
    CHECK_FALSE(get_valid(lit_str("GET"),
                          lit_str("/v1/items?x=a%2Fb"),
                          kGetAuth,
                          kGetDate,
                          kGetDigest,
                          {},
                          lit_str("other")));
    CHECK_FALSE(get_valid(lit_str("GET"),
                          lit_str("/v1/items?x=a%2Fb"),
                          kGetAuth,
                          kGetDate,
                          kGetDigest,
                          {},
                          lit_str("key-1"),
                          lit_str("wrong-secret")));
    CHECK_FALSE(get_valid(lit_str("GET"),
                          lit_str("/v1/items?x=a%2Fb"),
                          kGetAuth,
                          kGetDate,
                          lit_str("SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFV=")));
    CHECK_FALSE(get_valid(lit_str("GET"),
                          lit_str("/v1/items?x=a%2Fb"),
                          kGetAuth,
                          kGetDate,
                          lit_str("SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuF!=")));
}

TEST(signed_request, authorization_shape_is_closed_and_exact) {
    const Str cases[] = {
        lit_str(
            "Signature keyId=\"key-1\",algorithm=\"hmac-sha256\",headers=\"@request-target date "
            "digest\",signature=\"aXAPP5PHaRkQ03BHoTSPxmnTK/DmwBPY8WnLziletmQ=\",extra=\"x\""),
        lit_str("Signature "
                "keyId=\"key-1\",keyId=\"key-1\",algorithm=\"hmac-sha256\",headers=\"@request-"
                "target date digest\",signature=\"aXAPP5PHaRkQ03BHoTSPxmnTK/DmwBPY8WnLziletmQ=\""),
        lit_str("Signature keyId=\"key-1\",algorithm=\"hmac-sha256\",headers=\"@request-target "
                "date digest\""),
        lit_str("Signature keyId=\"key-1\",algorithm=\"HMAC-SHA256\",headers=\"@request-target "
                "date digest\",signature=\"aXAPP5PHaRkQ03BHoTSPxmnTK/DmwBPY8WnLziletmQ=\""),
        lit_str(
            "Signature keyId=\"key-1\",algorithm=\"hmac-sha256\",headers=\"date @request-target "
            "digest\",signature=\"aXAPP5PHaRkQ03BHoTSPxmnTK/DmwBPY8WnLziletmQ=\""),
        lit_str("Signature keyId=\"key-1\",algorithm=\"hmac-sha256\",headers=\"@request-target "
                "date digest\",signature=\"aXAPP5PHaRkQ03BHoTSPxmnTK/DmwBPY8WnLziletmQ==\""),
        lit_str("Signature keyId=\"key-1\",algorithm=\"hmac-sha256\",headers=\"@request-target "
                "date digest\",signature=\"aXAPP5PHaRkQ03BHoTSPxmnTK/DmwBPY8WnLziletmQ!\""),
        lit_str("Signature keyId=\"key-1\",algorithm=\"hmac-sha256\",headers=\"@request-target "
                "date digest\",signature=\"aXAPP5PHaRkQ03BHoTSPxmnTK/DmwBPY8WnLziletmQ=\" garbage"),
        lit_str("Signature keyId=\"key-1\",algorithm=\"hmac-sha256\",headers=\"@request-target "
                "date digest\",signature=\"aXAPP5PHaRkQ03BHoTSPxmnTK/DmwBPY8WnLziletmQ=\"\r\n"),
    };
    for (Str auth : cases)
        CHECK_FALSE(get_valid(lit_str("GET"), lit_str("/v1/items?x=a%2Fb"), auth));
}

TEST(signed_request, validates_date_target_key_and_body_bounds) {
    CHECK_FALSE(get_valid({nullptr, 3}));
    CHECK_FALSE(get_valid(lit_str("GET"), {nullptr, 3}));
    CHECK_FALSE(get_valid(lit_str("GET"), lit_str("/v1/items?x=a%2Fb"), kGetAuth, {nullptr, 29}));
    CHECK_FALSE(
        get_valid(lit_str("GET"), lit_str("/v1/items?x=a%2Fb"), kGetAuth, kGetDate, {nullptr, 44}));
    CHECK_FALSE(get_valid(lit_str("GET"),
                          lit_str("/v1/items?x=a%2Fb"),
                          kGetAuth,
                          kGetDate,
                          kGetDigest,
                          {nullptr, 1}));
    CHECK_FALSE(get_valid(lit_str("GET"),
                          lit_str("/v1/items?x=a%2Fb"),
                          kGetAuth,
                          kGetDate,
                          kGetDigest,
                          {},
                          {nullptr, 5}));
    CHECK_FALSE(get_valid(lit_str("GET"),
                          lit_str("/v1/items?x=a%2Fb"),
                          kGetAuth,
                          kGetDate,
                          kGetDigest,
                          {},
                          lit_str("key-1"),
                          {nullptr, 5}));
    CHECK_FALSE(get_valid(lit_str("CONNECT")));
    CHECK_FALSE(get_valid(lit_str("get")));
    CHECK_FALSE(get_valid(lit_str("GET"), lit_str("*")));
    CHECK_FALSE(get_valid(lit_str("GET"), lit_str("/bad target")));
    CHECK_FALSE(get_valid(lit_str("GET"), lit_str("/bad\x7fpath")));
    CHECK_FALSE(get_valid(lit_str("GET"), lit_str("/fragment#x")));

    const Str invalid_dates[] = {
        lit_str("Thu, 21 Oct 2015 07:28:00 GMT"),  // wrong weekday
        lit_str("Wed, 32 Oct 2015 07:28:00 GMT"),
        lit_str("Wed, 29 Feb 2015 07:28:00 GMT"),
        lit_str("Wed, 21 Oct 2015 24:00:00 GMT"),
        lit_str("Wed, 21 Oct 2015 07:28:60 GMT"),
        lit_str("Wed, 21 Oct 2015 07:28:00 gmt"),
        lit_str("Wed, 21 Oct 2015 07:28:00 GMT "),
    };
    for (Str date : invalid_dates)
        CHECK_FALSE(get_valid(lit_str("GET"), lit_str("/v1/items?x=a%2Fb"), kGetAuth, date));

    CHECK_FALSE(get_valid(lit_str("GET"),
                          lit_str("/v1/items?x=a%2Fb"),
                          kGetAuth,
                          kGetDate,
                          kGetDigest,
                          {},
                          lit_str("bad\"kid")));
    __builtin_memset(g_oversized_input, 'a', 8193);
    g_oversized_input[0] = '/';
    CHECK_FALSE(get_valid(lit_str("GET"), {g_oversized_input, 8193}));
    __builtin_memset(g_oversized_input, 'a', 129);
    CHECK_FALSE(get_valid(lit_str("GET"),
                          lit_str("/v1/items?x=a%2Fb"),
                          kGetAuth,
                          kGetDate,
                          kGetDigest,
                          {},
                          {g_oversized_input, 129}));
    __builtin_memset(g_oversized_input, 'k', 4097);
    CHECK_FALSE(get_valid(lit_str("GET"),
                          lit_str("/v1/items?x=a%2Fb"),
                          kGetAuth,
                          kGetDate,
                          kGetDigest,
                          {},
                          lit_str("key-1"),
                          {g_oversized_input, 4097}));
    __builtin_memset(g_oversized_input, 'x', sizeof(g_oversized_input));
    CHECK_FALSE(get_valid(lit_str("GET"),
                          lit_str("/v1/items?x=a%2Fb"),
                          kGetAuth,
                          kGetDate,
                          kGetDigest,
                          {g_oversized_input, sizeof(g_oversized_input)}));
    __builtin_memset(g_oversized_input, 'x', 4097);
    CHECK_FALSE(get_valid(lit_str("GET"), lit_str("/v1/items?x=a%2Fb"), {g_oversized_input, 4097}));
}

TEST(signed_request, accepts_combined_inclusive_size_limits) {
    __builtin_memset(g_max_key_id, 'k', sizeof(g_max_key_id));
    __builtin_memset(g_max_secret, 's', sizeof(g_max_secret));
    __builtin_memset(g_max_target, 'p', sizeof(g_max_target));
    g_max_target[0] = '/';
    __builtin_memset(g_oversized_input, 'x', 1024 * 1024);

    u32 auth_len = 0;
    REQUIRE(append(g_max_auth, sizeof(g_max_auth), auth_len, lit_str("Signature keyId=\"")));
    REQUIRE(append(g_max_auth, sizeof(g_max_auth), auth_len, {g_max_key_id, sizeof(g_max_key_id)}));
    REQUIRE(append(
        g_max_auth,
        sizeof(g_max_auth),
        auth_len,
        lit_str(
            "\",algorithm=\"hmac-sha256\",headers=\"@request-target date digest\",signature=\"")));
    REQUIRE(append(g_max_auth,
                   sizeof(g_max_auth),
                   auth_len,
                   lit_str("TYmHPIsiplyvJG2XDoqewHfk/jKKITWUr5BUF/Zr0Qc=")));
    REQUIRE(append(g_max_auth, sizeof(g_max_auth), auth_len, lit_str("\"")));

    CHECK(signed_request_hmac_sha256_valid(
        lit_str("POST"),
        {g_max_target, sizeof(g_max_target)},
        {g_max_auth, auth_len},
        kPostDate,
        lit_str("SHA-256=j5kLoLV3tRzwCeoEk2jBa72hsh4bk74HqCR1i7JTw5s="),
        {g_oversized_input, 1024 * 1024},
        {g_max_key_id, sizeof(g_max_key_id)},
        {g_max_secret, sizeof(g_max_secret)},
        1700000000));
}

TEST(signed_request, freshness_boundaries_and_clock_overflow_cases) {
    CHECK(signed_request_hmac_sha256_valid(lit_str("POST"),
                                           lit_str("/hooks?mode=raw"),
                                           kPostAuth,
                                           kPostDate,
                                           kPostDigest,
                                           kPostBody,
                                           lit_str("kid-A"),
                                           kPostSecret,
                                           1699999700));
    CHECK(signed_request_hmac_sha256_valid(lit_str("POST"),
                                           lit_str("/hooks?mode=raw"),
                                           kPostAuth,
                                           kPostDate,
                                           kPostDigest,
                                           kPostBody,
                                           lit_str("kid-A"),
                                           kPostSecret,
                                           1700000300));
    CHECK_FALSE(signed_request_hmac_sha256_valid(lit_str("POST"),
                                                 lit_str("/hooks?mode=raw"),
                                                 kPostAuth,
                                                 kPostDate,
                                                 kPostDigest,
                                                 kPostBody,
                                                 lit_str("kid-A"),
                                                 kPostSecret,
                                                 1699999699));
    CHECK_FALSE(signed_request_hmac_sha256_valid(lit_str("POST"),
                                                 lit_str("/hooks?mode=raw"),
                                                 kPostAuth,
                                                 kPostDate,
                                                 kPostDigest,
                                                 kPostBody,
                                                 lit_str("kid-A"),
                                                 kPostSecret,
                                                 1700000301));
    CHECK_FALSE(signed_request_hmac_sha256_valid(lit_str("POST"),
                                                 lit_str("/hooks?mode=raw"),
                                                 kPostAuth,
                                                 kPostDate,
                                                 kPostDigest,
                                                 kPostBody,
                                                 lit_str("kid-A"),
                                                 kPostSecret,
                                                 -1));
    CHECK_FALSE(signed_request_hmac_sha256_valid(lit_str("POST"),
                                                 lit_str("/hooks?mode=raw"),
                                                 kPostAuth,
                                                 kPostDate,
                                                 kPostDigest,
                                                 kPostBody,
                                                 lit_str("kid-A"),
                                                 kPostSecret,
                                                 0));
    CHECK_FALSE(signed_request_hmac_sha256_valid(lit_str("POST"),
                                                 lit_str("/hooks?mode=raw"),
                                                 kPostAuth,
                                                 kPostDate,
                                                 kPostDigest,
                                                 kPostBody,
                                                 lit_str("kid-A"),
                                                 kPostSecret,
                                                 9223372036854775807LL));
}

TEST(signed_request, successful_verification_has_no_crypto_allocations) {
    REQUIRE(get_valid());
    allocations = 0;
    tracking = true;
    for (u32 i = 0; i < 32; ++i) CHECK(get_valid());
    tracking = false;
    CHECK_EQ(allocations, 0u);
}

int main(int argc, char** argv) {
    if (!CRYPTO_set_mem_functions(counted_malloc, counted_realloc, counted_free)) return 2;
    return rut::test::run_all(argc, argv);
}
