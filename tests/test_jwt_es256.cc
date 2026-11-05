#include "es256_fixture.h"
#include "es256_fixtures.h"
#include "rut/runtime/es256_policy.h"
#include "rut/runtime/json.h"
#include "rut/runtime/jwt_es256.h"
#include "test.h"

#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

using namespace rut;
namespace {
bool tracking = false;
u32 allocations = 0;
void* crypto_alloc(size_t size, const char*, int) {
    if (tracking) ++allocations;
    return malloc(size);
}
void* crypto_realloc(void* pointer, size_t size, const char*, int) {
    if (tracking) ++allocations;
    return realloc(pointer, size);
}
void crypto_free(void* pointer, const char*, int) {
    free(pointer);
}
}  // namespace

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
    if (!CRYPTO_set_mem_functions(crypto_alloc, crypto_realloc, crypto_free)) return 1;
    if (argc == 2 && strcmp(argv[1], "--emit-fixture") == 0) {
        test::Es256Fixture fixture;
        if (!fixture.init()) return 1;
        char output[16384], policy[4096], token[4096];
        json::Writer trust{policy, sizeof(policy)};
        trust.text({fixture.policy.ptr, fixture.policy.len - 1});
        trust.text(
            lit_str(R"(,"revokedJtis":["revoked"],"issuedAfter":100,"requiredType":"at+jwt"})"));
        json::Writer result{output, sizeof(output)};
        result.text(lit_str(R"({"policy":)"));
        result.text({policy, trust.len});
        const Str names[] = {lit_str("valid"),
                             lit_str("scope"),
                             lit_str("issuer"),
                             lit_str("expired"),
                             lit_str("revoked"),
                             lit_str("algorithm"),
                             lit_str("unknown_kid"),
                             lit_str("missing_type"),
                             lit_str("wrong_type"),
                             lit_str("duplicate_type")};
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
            const Str header =
                i == 5   ? lit_str(R"({"alg":"RS256","kid":"current","typ":"at+jwt"})")
                : i == 6 ? lit_str(R"({"alg":"ES256","kid":"unknown","typ":"at+jwt"})")
                : i == 7 ? test::Es256Fixture::header
                : i == 8 ? lit_str(R"({"alg":"ES256","kid":"current","typ":"JWT"})")
                : i == 9
                    ? lit_str(
                          R"({"alg":"ES256","kid":"current","typ":"at+jwt","t\u0079p":"at+jwt"})")
                    : lit_str(R"({"alg":"ES256","kid":"current","typ":"at+jwt"})");
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

static Str policy_with_type_options(test::Es256Fixture& fixture, Str options, char* bytes) {
    json::Writer writer{bytes, Es256Policy::kMaxText};
    writer.text({fixture.policy.ptr, fixture.policy.len - 1});
    writer.text(options);
    writer.put('}');
    return writer.ok ? Str{bytes, writer.len} : Str{};
}

TEST(jwt_es256, explicit_type_binds_protected_header_before_identity_publication) {
    test::Es256Fixture fixture;
    REQUIRE(fixture.init());
    char plain_bytes[8192], typed_bytes[8192];
    const Str plain = policy_with_type_options(fixture, {}, plain_bytes);
    const Str typed =
        policy_with_type_options(fixture, lit_str(R"(,"requiredType":"at+jwt")"), typed_bytes);
    const Str configurations[] = {plain, typed};
    Es256Policies policies;
    REQUIRE(policies.load(configurations, 2));
    REQUIRE(policies.activate(0));
    REQUIRE(policies.activate(1));
    const struct {
        Str header;
        bool typed;
        bool plain;
    } cases[] = {
        {lit_str(R"({"alg":"ES256","kid":"current","typ":"at+jwt"})"), true, true},
        {lit_str(R"({"alg":"ES256","kid":"current","t\u0079p":"at\u002bjwt"})"), true, true},
        {lit_str(R"({"alg":"ES256","kid":"current"})"), false, true},
        {lit_str(R"({"alg":"ES256","kid":"current","typ":"JWT"})"), false, true},
        {lit_str(R"({"alg":"ES256","kid":"current","typ":"AT+JWT"})"), false, true},
        {lit_str(R"({"alg":"ES256","kid":"current","typ":"application/at+jwt"})"), false, true},
        {lit_str(R"({"alg":"ES256","kid":"current","typ":"at+jwt-other"})"), false, true},
        {lit_str(R"({"alg":"ES256","kid":"current","typ":" at+jwt"})"), false, true},
        {lit_str(R"({"alg":"ES256","kid":"current","typ":"at+jwt\u0000"})"), false, true},
        {lit_str(R"({"alg":"ES256","kid":"current","typ":""})"), false, true},
        {lit_str(R"({"alg":"ES256","kid":"current","typ":null})"), false, true},
        {lit_str(R"({"alg":"ES256","kid":"current","typ":123})"), false, true},
        {lit_str(R"({"alg":"ES256","kid":"current","typ":["at+jwt"]})"), false, true},
        {lit_str(R"({"alg":"ES256","kid":"current","typ":"at+jwt","t\u0079p":"at+jwt"})"),
         false,
         false},
        {lit_str(R"({"alg":"HS256","kid":"current","typ":"at+jwt"})"), false, false},
        {lit_str(R"({"alg":"ES256","kid":"unknown","typ":"at+jwt"})"), false, false},
        {lit_str(R"({"alg":"ES256","kid":"current","cty":"at+jwt"})"), false, true},
        {lit_str(R"({"alg":"ES256","kid":"current","typ":"at+jwt"})"), true, true},
    };
    for (u32 index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const auto& item = cases[index];
        char token[4096], payload[8192];
        const Str value = fixture.sign(
            item.header,
            lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"typ":"at+jwt"})"),
            token);
        REQUIRE(value.len);
        for (u32 shard = 0; shard < 2; ++shard) {
            for (u32 policy = 0; policy < 2; ++policy) {
                json::Document document;
                REQUIRE(document.parse(lit_str("{}")));
                u32 length = 99;
                allocations = 0;
                tracking = true;
                const bool accepted = policies.verify(shard,
                                                      configurations[policy],
                                                      document,
                                                      value,
                                                      100,
                                                      payload,
                                                      sizeof(payload),
                                                      length);
                tracking = false;
                CHECK_EQ(allocations, 0u);
                CHECK_EQ(accepted, policy ? item.typed : item.plain);
                CHECK_EQ(document.valid, accepted);
                if (!accepted) {
                    CHECK_EQ(length, 0u);
                    CHECK_EQ(document.count, 0u);
                    CHECK_EQ(document.source.len, 0u);
                }
            }
        }
    }
    char token[4096], payload[8192];
    test::Es256Fixture other;
    REQUIRE(other.init());
    Str value = other.sign(lit_str(R"({"alg":"ES256","kid":"current","typ":"at+jwt"})"),
                           lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200})"),
                           token);
    REQUIRE(value.len);
    json::Document document;
    u32 length = 99;
    CHECK(!policies.verify(0, typed, document, value, 100, payload, sizeof(payload), length));
    CHECK_EQ(length, 0u);
    CHECK(!document.valid);
}

TEST(jwt_es256, explicit_type_configuration_is_bounded_owned_and_strict) {
    test::Es256Fixture fixture;
    REQUIRE(fixture.init());
    const Str invalid[] = {
        lit_str(R"(,"requiredType":"")"),
        lit_str(R"(,"requiredType":null)"),
        lit_str(R"(,"requiredType":true)"),
        lit_str(R"(,"requiredType":123)"),
        lit_str(R"(,"requiredType":{})"),
        lit_str(R"(,"requiredType":["at+jwt"])"),
        lit_str(R"(,"requiredType":"at jwt")"),
        lit_str(R"(,"requiredType":"at+jwt\t")"),
        lit_str(R"(,"requiredType":"at+jwt\u0000")"),
        lit_str(R"(,"requiredType":"\u007f")"),
        lit_str(R"(,"requiredType":"\u00e9")"),
        lit_str(R"(,"requiredType":"JWT","required\u0054ype":"at+jwt")"),
    };
    char bytes[8192];
    for (Str options : invalid) {
        const Str text = policy_with_type_options(fixture, options, bytes);
        Es256Policy policy;
        CHECK(!policy.load(text));
        CHECK(!policy.keys().valid());
    }
    for (u32 size = 128; size <= 129; ++size) {
        char options[256];
        json::Writer writer{options};
        writer.text(lit_str(R"(,"requiredType":")"));
        for (u32 i = 0; i < size; ++i) writer.put('a');
        writer.put('"');
        REQUIRE(writer.ok);
        const Str text = policy_with_type_options(fixture, {options, writer.len}, bytes);
        Es256Policy policy;
        CHECK_EQ(policy.load(text), size == 128);
        if (size != 128) continue;
        __builtin_memset(bytes, '!', text.len);
        CHECK_EQ(policy.required_type().len, 128u);
        for (u32 i = 0; i < 128; ++i) CHECK_EQ(policy.required_type().ptr[i], 'a');
        // The bound applies to decoded bytes; actual token verification must agree.
        char header[512], token[4096], payload[8192];
        json::Writer head{header};
        head.text(lit_str(R"({"alg":"ES256","kid":"current","typ":)"));
        REQUIRE(json::quote(policy.required_type(), head));
        head.put('}');
        REQUIRE(head.ok);
        const Str value =
            fixture.sign({header, head.len},
                         lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200})"),
                         token);
        REQUIRE(value.len);
        Es256VerifierSet keys;
        REQUIRE(keys.init(policy.keys()));
        json::Document document;
        u32 length = 0;
        Str selected;
        CHECK(jwt_es256_validate_set(keys,
                                     document,
                                     value,
                                     policy.issuer(),
                                     policy.audience(),
                                     100,
                                     payload,
                                     sizeof(payload),
                                     length,
                                     selected,
                                     policy.required_type()));
        CHECK(selected.eq(lit_str("current")));
        // Invalid native policy input also fails without publishing a selected key.
        CHECK(!jwt_es256_validate_set(keys,
                                      document,
                                      value,
                                      policy.issuer(),
                                      policy.audience(),
                                      100,
                                      payload,
                                      sizeof(payload),
                                      length,
                                      selected,
                                      {nullptr, 1}));
        CHECK_EQ(selected.len, 0u);
        CHECK_EQ(length, 0u);
        CHECK(!document.valid);
    }
}

TEST(jwt_es256, failed_type_policy_does_not_leak_into_separately_trusted_jwks_import) {
    test::Es256Fixture fixture;
    REQUIRE(fixture.init());
    char bytes[8192];
    const Str bad = policy_with_type_options(
        fixture, lit_str(R"(,"requiredType":"at+jwt","unsupported":true)"), bytes);
    Es256Policy policy;
    REQUIRE(!policy.load(bad));
    REQUIRE(!policy.keys().valid());
    json::Document document;
    REQUIRE(document.parse(fixture.policy));
    Str jwks;
    for (u32 node = document.nodes[0].child; node != json::kNone;
         node = document.nodes[node].next) {
        json::Writer name{document.scratch};
        REQUIRE(document.string(document.nodes[node].key, name));
        if (Str{document.scratch, name.len}.eq(lit_str("jwks"))) jwks = document.raw(node);
    }
    REQUIRE(jwks.len);
    const Str ids[] = {lit_str("current")};
    REQUIRE(policy.load_jwks(jwks, lit_str("issuer"), lit_str("gateway"), ids, 1));
    CHECK_EQ(policy.required_type().len, 0u);
    Es256VerifierSet keys;
    REQUIRE(keys.init(policy.keys()));
    char token[4096], payload[8192];
    const Str value = fixture.sign(test::Es256Fixture::header, test::Es256Fixture::claims, token);
    REQUIRE(value.len);
    Str selected;
    u32 length = 0;
    CHECK(jwt_es256_validate_set(keys,
                                 document,
                                 value,
                                 policy.issuer(),
                                 policy.audience(),
                                 1700000000,
                                 payload,
                                 sizeof(payload),
                                 length,
                                 selected,
                                 policy.required_type()));
}
