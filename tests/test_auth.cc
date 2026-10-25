#include "rut/runtime/auth.h"
#include "test.h"

#include <openssl/evp.h>

using namespace rut;

TEST(auth, bearer_scheme_and_token_grammar) {
    const Str key = lit_str("aZ09-._~+/==");
    CHECK(bearer_matches(lit_str("Bearer aZ09-._~+/=="), key));
    CHECK(bearer_matches(lit_str("bEaReR   aZ09-._~+/=="), key));
    const Str invalid[] = {lit_str(""),
                           lit_str("Bearer"),
                           lit_str("Bearer "),
                           lit_str("Bearer\taZ09-._~+/=="),
                           lit_str("Basic aZ09-._~+/=="),
                           lit_str("Bearer aZ09-._~+/== wrong"),
                           lit_str("Bearer aZ09-._~+/==,wrong"),
                           lit_str("Bearer aZ09-._~+/== "),
                           lit_str("Bearer xZ09-._~+/==")};
    for (Str value : invalid) CHECK(!bearer_matches(value, key));
    const Str invalid_keys[] = {lit_str(""),
                                lit_str("="),
                                lit_str("a=b"),
                                lit_str("a b"),
                                lit_str("a:b"),
                                lit_str("a,b"),
                                lit_str("a\0b")};
    for (Str value : invalid_keys) CHECK(!bearer_key_valid(value));
    CHECK(!bearer_matches({nullptr, 99}, key));
    CHECK(!bearer_key_valid({nullptr, 1}));
}

TEST(auth, basic_canonical_encoding_and_password_colons) {
    CHECK(basic_matches(lit_str("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
                        lit_str("Aladdin:open sesame")));
    CHECK(basic_matches(lit_str("bAsIc   dXNlcjpwYXNz"), lit_str("user:pass")));
    CHECK(basic_matches(lit_str("Basic dXNlcjo="), lit_str("user:")));
    CHECK(basic_matches(lit_str("Basic dTpwOnE="), lit_str("u:p:q")));
    const Str invalid[] = {lit_str(""),
                           lit_str("Basic"),
                           lit_str("Basic "),
                           lit_str("Basic\tdXNlcjpwYXNz"),
                           lit_str("Bearer dXNlcjpwYXNz"),
                           lit_str("Basic dXNlcjpwYXN6"),
                           lit_str("Basic dXNlcjpwYXNz,xxx"),
                           lit_str("Basic dXNlcjpw YXNz"),
                           lit_str("Basic dXNlcjpwYXNz="),
                           lit_str("Basic dXNlcjpwYXNz\n")};
    for (Str value : invalid) CHECK(!basic_matches(value, lit_str("user:pass")));
    // Same decoded bytes with nonzero pad bits must not be accepted.
    CHECK(!basic_matches(lit_str("Basic dXNlcjp="), lit_str("user:")));
    CHECK(!basic_matches(lit_str("Basic dXNlcjo"), lit_str("user:")));
    const Str invalid_credentials[] = {lit_str(""),
                                       lit_str("user"),
                                       lit_str(":pass"),
                                       lit_str("u:p\n"),
                                       lit_str("u:p\0"),
                                       lit_str("u:p\x7f")};
    for (Str value : invalid_credentials) CHECK(!basic_credentials_valid(value));
    CHECK(!basic_matches({nullptr, 99}, lit_str("user:pass")));
}

TEST(auth, credential_capacity_boundaries) {
    char credentials[kMaxBasicCredentialBytes + 1];
    for (char& c : credentials) c = 'a';
    credentials[1] = ':';
    CHECK(basic_credentials_valid({credentials, kMaxBasicCredentialBytes}));
    CHECK(!basic_credentials_valid({credentials, kMaxBasicCredentialBytes + 1}));
    u8 encoded[((kMaxBasicCredentialBytes + 2) / 3) * 4 + 1];
    const size_t kEncodedLen = EVP_EncodeBlock(
        encoded, reinterpret_cast<const u8*>(credentials), kMaxBasicCredentialBytes);
    char header[6 + sizeof(encoded)];
    const char prefix[] = "Basic ";
    for (u32 i = 0; i < 6; ++i) header[i] = prefix[i];
    for (u32 i = 0; i < kEncodedLen; ++i) header[i + 6] = static_cast<char>(encoded[i]);
    CHECK(basic_matches({header, static_cast<u32>(kEncodedLen + 6)},
                        {credentials, kMaxBasicCredentialBytes}));
    CHECK(!basic_matches({header, static_cast<u32>(kEncodedLen + 6)},
                         {credentials, kMaxBasicCredentialBytes + 1}));
    char key[kMaxBearerKeyBytes + 1];
    for (char& c : key) c = 'a';
    CHECK(bearer_key_valid({key, kMaxBearerKeyBytes}));
    CHECK(!bearer_key_valid({key, kMaxBearerKeyBytes + 1}));
}

TEST(auth, bearer_token_is_a_bounded_borrowed_view) {
    const Str authorization = lit_str("bEaReR   a.b.c");
    const Str token = bearer_token(authorization);
    CHECK(token.eq(lit_str("a.b.c")));
    CHECK_EQ(token.ptr, authorization.ptr + 9);
    CHECK(bearer_token(lit_str("Bearer ")).ptr == nullptr);
    CHECK(bearer_token(lit_str("Bearer a,b")).ptr == nullptr);
    CHECK(bearer_token(lit_str("Basic a.b.c")).ptr == nullptr);
}

TEST(auth, hmac_sha256_standard_vectors) {
    // RFC 4231 cases 1, 2 and 6 (including a key longer than one SHA-256 block).
    char key[131];
    for (char& c : key) c = 0x0b;
    CHECK(hmac_sha256_matches(
        lit_str("Hi There"),
        {key, 20},
        lit_str("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")));
    CHECK(hmac_sha256_matches(
        lit_str("what do ya want for nothing?"),
        lit_str("Jefe"),
        lit_str("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")));
    for (char& c : key) c = static_cast<char>(0xaa);
    CHECK(hmac_sha256_matches(
        lit_str("Test Using Larger Than Block-Size Key - Hash Key First"),
        {key, sizeof(key)},
        lit_str("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")));
    // Published GitHub webhook validation vector.
    CHECK(hmac_sha256_matches(
        lit_str("Hello, World!"),
        lit_str("It's a Secret to Everybody"),
        lit_str("757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17")));
}

TEST(auth, hmac_sha256_rejects_tampering_and_noncanonical_signatures) {
    const Str digest = lit_str("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    CHECK(!hmac_sha256_matches(lit_str("what do ya want for nothing!"), lit_str("Jefe"), digest));
    CHECK(!hmac_sha256_matches(lit_str("what do ya want for nothing?"), lit_str("Jeff"), digest));
    CHECK(!hmac_sha256_matches(
        lit_str("what do ya want for nothing?"),
        lit_str("Jefe"),
        lit_str("5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843")));
    CHECK(!hmac_sha256_matches(lit_str(""), lit_str(""), digest));
    CHECK(!hmac_sha256_matches({nullptr, 1}, lit_str("Jefe"), digest));
    CHECK(!hmac_sha256_matches(lit_str(""), {nullptr, 4}, digest));
    CHECK(!hmac_sha256_matches(lit_str(""), lit_str("Jefe"), {nullptr, 64}));
    CHECK(!hmac_sha256_matches(lit_str(""), lit_str("Jefe"), {digest.ptr, 63}));
    CHECK(!hmac_sha256_matches(lit_str(""), lit_str("Jefe"), {digest.ptr, 65}));
    // Invalid oversized spans are rejected before dereferencing their payloads.
    CHECK(!hmac_sha256_matches({"x", kMaxHmacMessageBytes + 1}, lit_str("key"), digest));
    CHECK(!hmac_sha256_matches(lit_str(""), {"x", kMaxHmacKeyBytes + 1}, digest));
}

TEST(auth, hmac_sha256_empty_message) {
    CHECK(hmac_sha256_matches(
        {"", 0},
        {"\x6b\x65\x79", 3},
        lit_str("5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0")));
}

TEST(auth, hmac_sha256_binary_message) {
    CHECK(hmac_sha256_matches(
        {"\x61\x00\x62\xff", 4},
        {"\x6b\x65\x79\x00\x73\x65\x63\x72\x65\x74", 10},
        lit_str("25ae054ebc485b2958453378b3d060442cb69825e7836451673a73c22a9a191c")));
}

TEST(auth, hmac_sha256_accepts_exact_capacity_limits) {
    static char message[kMaxHmacMessageBytes];
    char key[kMaxHmacKeyBytes];
    for (char& c : message) c = 'm';
    for (char& c : key) c = 'k';
    CHECK(hmac_sha256_matches(
        {message, sizeof(message)},
        {key, sizeof(key)},
        lit_str("198353ab61ddf53adf464b03d9348b87971198036f5ce991ebe901ee1b23df18")));
}

TEST(auth, hmac_sha256_prefix_is_an_exact_trusted_marker) {
    const Str signature =
        lit_str("sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17");
    const Str message = lit_str("Hello, World!");
    const Str key = lit_str("It's a Secret to Everybody");
    CHECK(hmac_sha256_matches(message, key, signature, lit_str("sha256=")));
    CHECK(!hmac_sha256_matches(message, key, signature));
    CHECK(!hmac_sha256_matches(message, key, signature, lit_str("SHA256=")));
    CHECK(!hmac_sha256_matches(message, key, signature, {nullptr, 7}));
    CHECK(!hmac_sha256_matches(message, key, signature, {"x", 65}));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
