#include "es256_fixture.h"
#include "es256_fixtures.h"
#include "rut/runtime/es256_policy.h"
#include "rut/runtime/json.h"
#include "rut/runtime/jwt_es256.h"
#include "test.h"

#include <string.h>

using namespace rut;

TEST(jwt_es256, published_rfc_decode_and_failure_publication) {
    EcP256PublicKey key;
    EcP256Sha256Verifier verifier;
    REQUIRE(key.load_es256_jwk(kEs256Jwk));
    REQUIRE(verifier.init(key));
    json::Document document;
    char payload[8192];
    u32 length = 42;
    REQUIRE(jwt_es256_decode(verifier, document, kEs256Token, payload, sizeof(payload), length));
    CHECK(length > 0);
    CHECK(document.valid);
    CHECK(document.source.ptr == payload);
    char token[1024];
    __builtin_memcpy(token, kEs256Token.ptr, kEs256Token.len);
    for (u32 i = 0; i < kEs256Token.len; ++i) {
        const char original = token[i];
        token[i] = original == 'A' ? 'B' : 'A';
        CHECK(!jwt_es256_decode(
            verifier, document, {token, kEs256Token.len}, payload, sizeof(payload), length));
        CHECK_EQ(length, 0u);
        CHECK(!document.valid);
        CHECK_EQ(document.count, 0u);
        CHECK(document.source.ptr == nullptr);
        token[i] = original;
    }
    CHECK(!jwt_es256_decode(verifier, document, kEs256Token, payload, 1, length));
    CHECK(!jwt_es256_decode(verifier, document, {nullptr, 1}, payload, sizeof(payload), length));
    // The RFC payload intentionally lacks this resource-server profile's sub/aud.
    CHECK(!jwt_es256_validate(verifier,
                              document,
                              kEs256Token,
                              lit_str("joe"),
                              lit_str("gateway"),
                              1300819300,
                              payload,
                              sizeof(payload),
                              length));
    CHECK(!document.valid);
}

TEST(jwt_es256, authenticated_algorithm_header_and_claims_rejections) {
    test::Es256Fixture fixture;
    REQUIRE(fixture.init());
    Es256Policies policies;
    const Str configurations[] = {fixture.policy};
    REQUIRE(policies.load(configurations, 1));
    REQUIRE(policies.activate(0));
    json::Document document;
    char payload[8192], token[16384];
    u32 length = 0;
    auto check = [&](Str header, Str claims) {
        const Str signed_token = fixture.sign(header, claims, token);
        if (signed_token.empty()) return false;
        return policies.verify(0,
                               fixture.policy,
                               document,
                               signed_token,
                               1700000000,
                               payload,
                               sizeof(payload),
                               length);
    };
    CHECK(check(test::Es256Fixture::header, test::Es256Fixture::claims));
    const Str headers[] = {lit_str("{}"),
                           lit_str("[]"),
                           lit_str(R"({"alg":"none","kid":"current"})"),
                           lit_str(R"({"alg":"HS256","kid":"current"})"),
                           lit_str(R"({"alg":"RS256","kid":"current"})"),
                           lit_str(R"({"alg":"ES384","kid":"current"})"),
                           lit_str(R"({"alg":"ES256","kid":"missing"})"),
                           lit_str(R"({"alg":"ES256"})"),
                           lit_str(R"({"alg":"ES256","kid":"current","crit":[]})"),
                           lit_str(R"({"alg":"ES256","kid":"current","b64":true})"),
                           lit_str(R"({"alg":"ES256","kid":"current","\u006bid":"current"})"),
                           lit_str(R"({"alg":"ES256","a\u006cg":"ES256","kid":"current"})")};
    for (Str header : headers) {
        CHECK(!check(header, test::Es256Fixture::claims));
        CHECK_EQ(length, 0u);
        CHECK(!document.valid);
    }
    const Str claims[] = {
        lit_str("{}"),
        lit_str("[]"),
        lit_str(R"({"sub":"","iss":"issuer","aud":"gateway","exp":4102444800})"),
        lit_str(R"({"sub":"alice","iss":"other","aud":"gateway","exp":4102444800})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"other","exp":4102444800})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1700000000})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":"4102444800"})"),
        lit_str(
            R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":4102444800,"nbf":1700000001})"),
        lit_str(
            R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":4102444800,"iat":1700000001})"),
        lit_str(
            R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":4102444800,"sub":"other"})")};
    for (Str claim : claims) {
        CHECK(!check(test::Es256Fixture::header, claim));
        CHECK_EQ(length, 0u);
        CHECK(!document.valid);
    }
}

TEST(jwt_es256, shard_activation_configuration_ownership_and_revocation) {
    test::Es256Fixture fixture;
    REQUIRE(fixture.init());
    char policy_bytes[4096];
    json::Writer text{policy_bytes};
    text.text({fixture.policy.ptr, fixture.policy.len - 1});
    text.text(lit_str(R"(,"revokedJtis":["revoked"],"issuedAfter":100})"));
    REQUIRE(text.ok);
    const Str policy{policy_bytes, text.len};
    const Str configurations[] = {policy};
    Es256Policies policies;
    REQUIRE(policies.load(configurations, 1));
    json::Document document;
    char payload[8192], token[4096];
    u32 length = 0;
    Str signed_token = fixture.sign(test::Es256Fixture::header, test::Es256Fixture::claims, token);
    CHECK(!policies.verify(
        0, policy, document, signed_token, 1700000000, payload, sizeof(payload), length));
    REQUIRE(policies.activate(0));
    REQUIRE(policies.activate(2));
    CHECK(!policies.activate(kMaxShards));
    const Str tails[] = {lit_str(R"(,"jti":"live","iat":101})"),
                         lit_str(R"(,"jti":"revoked","iat":101})"),
                         lit_str(R"(,"jti":"live","iat":100})"),
                         lit_str(R"(,"jti":"live"})"),
                         lit_str(R"(,"iat":101})")};
    for (u32 i = 0; i < sizeof(tails) / sizeof(tails[0]); ++i) {
        char claim_bytes[1024];
        json::Writer claims{claim_bytes, sizeof(claim_bytes)};
        claims.text({test::Es256Fixture::claims.ptr, test::Es256Fixture::claims.len - 1});
        claims.text(tails[i]);
        REQUIRE(claims.ok);
        signed_token = fixture.sign(test::Es256Fixture::header, {claim_bytes, claims.len}, token);
        REQUIRE(!signed_token.empty());
        CHECK_EQ(
            policies.verify(
                2, policy, document, signed_token, 1700000000, payload, sizeof(payload), length),
            i == 0);
        if (i != 0) {
            CHECK_EQ(length, 0u);
            CHECK(!document.valid);
        }
    }
    policies.destroy();
    policies.destroy();
    CHECK(!policies.verify(
        2, policy, document, signed_token, 1700000000, payload, sizeof(payload), length));
    Es256Policy invalid;
    json::Writer remote{policy_bytes};
    remote.text({fixture.policy.ptr, fixture.policy.len - 1});
    remote.text(lit_str(R"(,"remoteJwks":{}})"));
    CHECK(!invalid.load({policy_bytes, remote.len}));
}

int main(int argc, char** argv) {
    if (argc == 2 && strcmp(argv[1], "--emit-fixture") == 0) {
        test::Es256Fixture fixture;
        if (!fixture.init()) return 1;
        char output[16384], policy[4096], token[4096];
        json::Writer trust{policy, sizeof(policy)};
        trust.text({fixture.policy.ptr, fixture.policy.len - 1});
        trust.text(lit_str(R"(,"revokedJtis":["revoked"],"issuedAfter":100})"));
        json::Writer result{output, sizeof(output)};
        result.text(lit_str(R"({"policy":)"));
        result.text({policy, trust.len});
        const Str names[] = {lit_str("valid"),
                             lit_str("scope"),
                             lit_str("issuer"),
                             lit_str("expired"),
                             lit_str("revoked"),
                             lit_str("algorithm"),
                             lit_str("unknown_kid")};
        for (u32 i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
            char claims_bytes[1024];
            json::Writer claims{claims_bytes, sizeof(claims_bytes)};
            claims.text(lit_str(R"({"sub":"alice","aud":"gateway","iat":101,"iss":)"));
            if (!json::quote(i == 2 ? lit_str("wrong") : lit_str("issuer"), claims)) return 1;
            claims.text(lit_str(R"(,"exp":)"));
            claims.text(i == 3 ? lit_str("1") : lit_str("4102444800"));
            claims.text(lit_str(R"(,"scope":)"));
            if (!json::quote(i == 1 ? lit_str("other") : lit_str("orders:read"), claims)) return 1;
            claims.text(lit_str(R"(,"jti":)"));
            if (!json::quote(i == 4 ? lit_str("revoked") : lit_str("live"), claims)) return 1;
            claims.put('}');
            const Str header = i == 5   ? lit_str(R"({"alg":"RS256","kid":"current"})")
                               : i == 6 ? lit_str(R"({"alg":"ES256","kid":"unknown"})")
                                        : test::Es256Fixture::header;
            const Str signed_token = fixture.sign(header, {claims_bytes, claims.len}, token);
            if (!claims.ok || signed_token.empty()) return 1;
            result.put(',');
            if (!json::quote(names[i], result)) return 1;
            result.put(':');
            if (!json::quote(signed_token, result)) return 1;
        }
        result.put('}');
        if (!trust.ok || !result.ok || fwrite(output, 1, result.len, stdout) != result.len)
            return 1;
        return fflush(stdout) == 0 ? 0 : 1;
    }
    return rut::test::run_all(argc, argv);
}
