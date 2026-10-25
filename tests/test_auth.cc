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

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
