#include "rut/common/types.h"
#include "rut/runtime/json.h"
#include "rut/runtime/jwt_claims.h"
#include "rut/runtime/oauth_introspection.h"
#include "test.h"

using namespace rut;

TEST(jwt_claims, required_claims_and_time_boundaries) {
    json::Document scratch;
    const auto valid = [&](Str value, i64 now = 1000) {
        return jwt_claims_valid(scratch, value, lit_str("issuer"), lit_str("gateway"), now);
    };
    CHECK(valid(lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001})")));
    CHECK(valid(lit_str(
        R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"nbf":1000,"iat":1000})")));
    CHECK(valid(lit_str(
        R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":9223372036854775807,"nbf":-1,"iat":-1})")));
    const Str invalid[] = {
        lit_str(R"({"iss":"issuer","aud":"gateway","exp":1001})"),
        lit_str(R"({"sub":"","iss":"issuer","aud":"gateway","exp":1001})"),
        lit_str(R"({"sub":7,"iss":"issuer","aud":"gateway","exp":1001})"),
        lit_str(R"({"sub":"alice","aud":"gateway","exp":1001})"),
        lit_str(R"({"sub":"alice","iss":"other","aud":"gateway","exp":1001})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"other","exp":1001})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway"})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1000})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":"1001"})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001.5})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1e9})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":9223372036854775808})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"nbf":1001})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"nbf":null})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"iat":1001})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"iat":"0"})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"\u0065xp":1002})"),
        lit_str("[]"),
        lit_str("null"),
        lit_str("{}"),
    };
    for (Str value : invalid) CHECK(!valid(value));
    CHECK(!valid(lit_str(R"({"sub":"a","iss":"issuer","aud":"gateway","exp":1001})"), 0));
    CHECK(!valid(lit_str(R"({"sub":"a","iss":"issuer","aud":"gateway","exp":1001})"), -1));
}

TEST(jwt_claims, lifetime_policy_requires_iat_and_bounds_age_and_token_lifetime) {
    json::Document scratch;
    const auto valid = [&](Str claims, i64 now = 1000, i64 max_age = 100, i64 max_lifetime = 200) {
        return jwt_claims_valid_with_lifetime(
            scratch, claims, lit_str("issuer"), lit_str("gateway"), now, max_age, max_lifetime);
    };
    CHECK(
        valid(lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":1000,"exp":1200})")));
    CHECK(valid(lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":900,"exp":1100})")));
    CHECK(
        !valid(lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":899,"exp":1100})")));
    CHECK(!valid(lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":900,"exp":1101})"),
                 1000,
                 100,
                 200));

    const Str invalid[] = {
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1100})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":0,"exp":1100})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":-1,"exp":1100})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":"900","exp":1100})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":900.0,"exp":1100})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":9e2,"exp":1100})"),
        lit_str(
            R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":9223372036854775808,"exp":9223372036854775809})"),
        lit_str(
            R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":-9223372036854775809,"exp":1100})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":1000,"exp":1000})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":1001,"exp":1100})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":900,"exp":900})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":900,"iat":900,"exp":1100})"),
        lit_str(
            R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":900,"exp":1100,"e\u0078p":1100})"),
        lit_str("broken"),
    };
    for (Str claims : invalid) CHECK(!valid(claims));
    const Str claims =
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":900,"exp":1100})");
    CHECK(!valid(claims, 1000, 0, 200));
    CHECK(!valid(claims, 1000, -1, 200));
    CHECK(!valid(claims, 1000, 100, 0));
    CHECK(!valid(claims, 1000, 100, -1));
    CHECK(!valid(claims, 1100, 1000, 1000));
    CHECK(!valid(claims, 0, 1000, 1000));
    CHECK(!jwt_claims_valid_with_lifetime(
        scratch, claims, lit_str("other"), lit_str("gateway"), 1000, 100, 200));
    CHECK(!jwt_claims_valid_with_lifetime(
        scratch, claims, lit_str("issuer"), lit_str("other"), 1000, 100, 200));
    CHECK(!valid(lit_str(R"({"iss":"issuer","aud":"gateway","iat":900,"exp":1100})")));
    CHECK(!valid(lit_str(
        R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":900,"exp":1100,"nbf":1001})")));

    const Str extreme = lit_str(
        R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":1,"exp":9223372036854775807})");
    CHECK(valid(extreme, 9223372036854775806, 9223372036854775805, 9223372036854775806));
    CHECK(!valid(extreme, 9223372036854775807, 9223372036854775806, 9223372036854775806));
    CHECK(valid(claims));
}

TEST(jwt_claims, audience_arrays_and_exact_decoded_string_comparison) {
    json::Document scratch;
    const auto valid = [&](Str value) {
        return jwt_claims_valid(scratch, value, lit_str("issuer"), lit_str("gateway"), 1000);
    };
    CHECK(valid(lit_str(R"({"sub":"a","iss":"issuer","aud":["other","gateway"],"exp":1001})")));
    CHECK(valid(lit_str(R"({"sub":"a","iss":"iss\u0075er","aud":["gate\u0077ay"],"exp":1001})")));
    const Str invalid[] = {
        lit_str(R"({"sub":"a","iss":"issuer","aud":[],"exp":1001})"),
        lit_str(R"({"sub":"a","iss":"issuer","aud":["other"],"exp":1001})"),
        lit_str(R"({"sub":"a","iss":"issuer","aud":["gateway",null],"exp":1001})"),
        lit_str(R"({"sub":"a","iss":"issuer","aud":["gateway",7],"exp":1001})"),
        lit_str(R"({"sub":"a","iss":"issuer","aud":["gateway",[]],"exp":1001})"),
        lit_str(R"({"sub":"a","iss":"issuer","aud":["gateway",""],"exp":1001})"),
        lit_str(R"({"sub":"a","iss":"Issuer","aud":"gateway","exp":1001})"),
        lit_str(R"({"sub":"a","iss":"issuer","aud":"Gateway","exp":1001})"),
    };
    for (Str value : invalid) CHECK(!valid(value));
    const Str claims = lit_str(R"({"sub":"a","iss":"issuer","aud":"gateway","exp":1001})");
    CHECK(!jwt_claims_valid(scratch, claims, lit_str(""), lit_str("gateway"), 1000));
    CHECK(!jwt_claims_valid(scratch, claims, lit_str("issuer"), lit_str(""), 1000));
    CHECK(!jwt_claims_valid(scratch, {nullptr, 1}, lit_str("issuer"), lit_str("gateway"), 1000));
}

TEST(jwt_claims, scope_membership_is_exact_and_validates_the_entire_list) {
    json::Document scratch;
    const auto has = [&](Str claims, Str required = lit_str("orders:read")) {
        return jwt_has_scope(scratch, claims, required);
    };
    CHECK(has(lit_str(R"({"scope":"orders:read"})")));
    CHECK(has(lit_str(R"({"scope":"profile orders:read orders:write"})")));
    CHECK(has(lit_str(R"({"scope":"orders:read orders:read"})")));
    CHECK(has(lit_str(R"({"sc\u006fpe":"orders:re\u0061d"})")));
    CHECK(has(lit_str(R"({"scope":"! # [ ] ~"})"), lit_str("~")));
    const Str denied[] = {
        lit_str(R"({"scope":"orders:reader"})"),
        lit_str(R"({"scope":"xorders:read"})"),
        lit_str(R"({"scope":"Orders:read"})"),
        lit_str(R"({"scope":" orders:read"})"),
        lit_str(R"({"scope":"orders:read "})"),
        lit_str(R"({"scope":"orders:read  profile"})"),
        lit_str(R"({"scope":"orders:read\tprofile"})"),
        lit_str(R"({"scope":"orders:read profile\n"})"),
        lit_str(R"({"scope":"orders:read \u0000"})"),
        lit_str(R"({"scope":"orders:read \""})"),
        lit_str(R"({"scope":"orders:read \\"})"),
        lit_str(R"({"scope":"orders:read \u00e9"})"),
        lit_str(R"({"scope":""})"),
        lit_str(R"({"scope":null})"),
        lit_str(R"({"scope":["orders:read"]})"),
        lit_str(R"({"scope":true})"),
        lit_str(R"({"scope":"orders:read","sc\u006fpe":"profile"})"),
        lit_str(R"({"nested":{"scope":"orders:read"}})"),
        lit_str("[]"),
        lit_str("{}"),
        lit_str("null"),
        lit_str("broken"),
    };
    for (Str claims : denied) CHECK(!has(claims));
    const Str claims = lit_str(R"({"scope":"orders:read"})");
    const Str invalid_requirements[] = {
        lit_str(""),
        lit_str("orders:read profile"),
        lit_str("orders:read\t"),
        lit_str("\\"),
        lit_str("\""),
        {nullptr, 1},
    };
    for (Str required : invalid_requirements) CHECK(!has(claims, required));
    CHECK(!has({nullptr, 1}));
    // Failure must not poison the reusable shard-local scratch document.
    CHECK(has(claims));
}

TEST(jwt_claims, group_membership_is_exact_and_validates_the_entire_array) {
    json::Document scratch;
    const auto has = [&](Str claims, Str required = lit_str("orders:read")) {
        return jwt_has_group(scratch, claims, required);
    };
    CHECK(has(lit_str(R"({"groups":["orders:read"]})")));
    CHECK(has(lit_str(R"({"groups":["profile","orders:read","admin"]})")));
    CHECK(has(lit_str(R"({"groups":["orders:read","orders:read"]})")));
    CHECK(has(lit_str(R"({"groups":["orders:re\u0061d"]})")));
    CHECK(has(lit_str(R"({"groups":["sécurité"]})"), lit_str("sécurité")));
    CHECK(has(lit_str(R"({"groups":["x\u0000y"]})"), {"x\0y", 3}));

    const Str denied[] = {
        lit_str(R"({})"),
        lit_str(R"({"nested":{"groups":["orders:read"]}})"),
        lit_str(R"({"groups":[]})"),
        lit_str(R"({"groups":"orders:read"})"),
        lit_str(R"({"groups":null})"),
        lit_str(R"({"groups":7})"),
        lit_str(R"({"groups":true})"),
        lit_str(R"({"groups":[""]})"),
        lit_str(R"({"groups":[null,"orders:read"]})"),
        lit_str(R"({"groups":[7,"orders:read"]})"),
        lit_str(R"({"groups":[true,"orders:read"]})"),
        lit_str(R"({"groups":[{},"orders:read"]})"),
        lit_str(R"({"groups":[[],"orders:read"]})"),
        lit_str(R"({"groups":["orders:read",""]})"),
        lit_str(R"({"groups":["orders:read",null]})"),
        lit_str(R"({"groups":["orders:read",7]})"),
        lit_str(R"({"groups":["orders:read",{}]})"),
        lit_str(R"({"groups":["Orders:read"]})"),
        lit_str(R"({"groups":["orders:reader"]})"),
        lit_str(R"({"groups":["xorders:read"]})"),
        lit_str(R"({"groups":["other",["orders:read"]]})"),
        lit_str(R"({"groups":["orders:read"],"groups":["other"]})"),
        lit_str(R"({"groups":["orders:read"],"gr\u006fups":["orders:read"]})"),
        lit_str("[]"),
        lit_str("null"),
        lit_str("broken"),
    };
    for (Str claims : denied) CHECK(!has(claims));
    const Str valid = lit_str(R"({"groups":["orders:read"]})");
    CHECK(!has(valid, lit_str("")));
    CHECK(!has(valid, {nullptr, 1}));
    char oversized[json::kMaxBytes + 1];
    for (char& c : oversized) c = 'x';
    CHECK(!has(valid, {oversized, sizeof(oversized)}));
    CHECK(!has({nullptr, 1}));
    // A failed call leaves the caller-owned document reusable.
    CHECK(has(valid));
}

TEST(jwt_claims, scope_list_grammar_and_membership_share_strict_boundaries) {
    const Str valid[] = {lit_str("read"),
                         lit_str("read write"),
                         lit_str("write read read"),
                         lit_str("! # [ ] ~"),
                         lit_str("Read read")};
    for (Str value : valid) CHECK(jwt_scope_list_valid(value));
    const char nul[] = {'r', ' ', 'w', '\0'};
    const char non_ascii[] = {'r', ' ', static_cast<char>(0x80)};
    const Str invalid[] = {{nullptr, 1},
                           {},
                           lit_str(" "),
                           lit_str(" read"),
                           lit_str("read "),
                           lit_str("read  write"),
                           lit_str("read\twrite"),
                           lit_str("read write\r"),
                           lit_str("read write\n"),
                           lit_str("read write\""),
                           lit_str("read write\\"),
                           {nul, sizeof(nul)},
                           {non_ascii, sizeof(non_ascii)}};
    for (Str value : invalid) CHECK(!jwt_scope_list_valid(value));
    // A valid first scope must not mask malformed permission text later on.
    json::Document document;
    const Str malformed[] = {lit_str(R"({"scope":"read write "})"),
                             lit_str(R"({"scope":"read  write"})"),
                             lit_str(R"({"scope":"read write\t"})"),
                             lit_str(R"({"scope":"read write\u0000"})")};
    for (Str claims : malformed) CHECK(!jwt_has_scope(document, claims, lit_str("read")));
    char bounded[json::kMaxBytes + 1];
    for (char& byte : bounded) byte = 'a';
    CHECK(jwt_scope_list_valid({bounded, json::kMaxBytes}));
    CHECK(!jwt_scope_list_valid({bounded, sizeof(bounded)}));
    CHECK(!jwt_scope_token_valid(lit_str("read write")));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}

TEST(introspection, active_expiry_audience_and_optional_metadata) {
    json::Document scratch;
    const auto valid = [&](Str value, i64 now = 1000) {
        return oauth_introspection_valid(scratch, value, lit_str("reports-api"), now);
    };
    CHECK(valid(lit_str(R"({"active":true,"exp":1001,"aud":"reports-api"})")));
    CHECK(valid(lit_str(
        R"({"active":true,"exp":1001,"aud":["other","reports-api"],"nbf":1000,"iat":0,"scope":"read write","token_type":"bearer"})")));
    CHECK(valid(lit_str(R"({"active":true,"exp":9223372036854775807,"aud":"reports-api"})")));
    CHECK(valid(lit_str(R"({"act\u0069ve":true,"exp":1001,"aud":"reports\u002dapi"})")));
    const Str bad[] = {
        lit_str(R"({"active":false})"),
        lit_str(R"({"active":"true","exp":1001,"aud":"reports-api"})"),
        lit_str(R"({"active":1,"exp":1001,"aud":"reports-api"})"),
        lit_str(R"({"exp":1001,"aud":"reports-api"})"),
        lit_str(R"({"active":true,"aud":"reports-api"})"),
        lit_str(R"({"active":true,"exp":1000,"aud":"reports-api"})"),
        lit_str(R"({"active":true,"exp":-1,"aud":"reports-api"})"),
        lit_str(R"({"active":true,"exp":"1001","aud":"reports-api"})"),
        lit_str(R"({"active":true,"exp":1001.0,"aud":"reports-api"})"),
        lit_str(R"({"active":true,"exp":1e9,"aud":"reports-api"})"),
        lit_str(R"({"active":true,"exp":9223372036854775808,"aud":"reports-api"})"),
        lit_str(R"({"active":true,"exp":1001,"aud":"Reports-api"})"),
        lit_str(R"({"active":true,"exp":1001,"aud":"reports-api-other"})"),
        lit_str(R"({"active":true,"exp":1001,"aud":[]})"),
        lit_str(R"({"active":true,"exp":1001,"aud":["reports-api",4]})"),
        lit_str(R"({"active":true,"exp":1001,"aud":["reports-api",""]})"),
        lit_str(R"({"active":true,"exp":1001,"aud":["reports-api",["other"]]})"),
        lit_str(R"({"active":true,"exp":1001,"aud":"reports-api\u0000"})"),
        lit_str(R"({"active":true,"exp":1001,"aud":"reports-api","nbf":1001})"),
        lit_str(R"({"active":true,"exp":1001,"aud":"reports-api","iat":1001})"),
        lit_str(R"({"active":true,"exp":1001,"aud":"reports-api","iat":-1})"),
        lit_str(R"({"active":true,"exp":1001,"aud":"reports-api","nbf":null})"),
        lit_str(R"({"active":true,"exp":1001,"aud":"reports-api","scope":["read"]})"),
        lit_str(R"({"active":true,"exp":1001,"aud":"reports-api","scope":"read  write"})"),
        lit_str(R"({"active":true,"exp":1001,"aud":"reports-api","token_type":"MAC"})"),
        lit_str(R"({"active":true,"exp":1001,"aud":"reports-api","token_type":true})"),
        lit_str(R"({"active":true,"exp":1001,"aud":"reports-api","act\u0069ve":false})"),
        lit_str(R"({"active":true,"exp":1001,"aud":"reports-api","\u0065xp":1002})"),
        lit_str("[]"),
        lit_str("null"),
        lit_str("true"),
        lit_str("{}"),
        lit_str("{")};
    for (Str value : bad) CHECK(!valid(value));
    const auto claims = lit_str(R"({"active":true,"exp":1001,"aud":"reports-api"})");
    CHECK(!valid(claims, 0));
    CHECK(!valid(claims, -1));
    CHECK(!oauth_introspection_valid(scratch, claims, lit_str(""), 1000));
}

TEST(introspection, authenticated_request_form_encoding_and_bounds) {
    char bytes[8192];
    json::Writer output{bytes};
    REQUIRE(oauth_introspection_request(
        lit_str("ab+/=="), lit_str("Basic Y2xpZW50OnNlY3JldA=="), output));
    json::Document doc;
    REQUIRE(doc.parse({bytes, output.len}));
    char decoded[4096];
    json::Writer body{decoded, sizeof(decoded)};
    REQUIRE(doc.string(doc.pointer(lit_str("/body")), body));
    CHECK(
        (Str{decoded, body.len}.eq(lit_str("token=ab%2B%2F%3D%3D&token_type_hint=access_token"))));
    json::Writer auth{decoded, sizeof(decoded)};
    REQUIRE(doc.string(doc.pointer(lit_str("/headers/Authorization")), auth));
    CHECK((Str{decoded, auth.len}.eq(lit_str("Basic Y2xpZW50OnNlY3JldA=="))));
    const Str invalid[] = {lit_str(""),
                           lit_str("a&token=stolen"),
                           lit_str("a=b"),
                           lit_str("a b"),
                           lit_str("a\r\nb"),
                           {nullptr, 1}};
    for (Str token : invalid) {
        json::Writer writer{bytes};
        CHECK(!oauth_introspection_request(token, lit_str("Bearer service"), writer));
    }
    const Str bad_auth[] = {lit_str(""),
                            lit_str("Basic "),
                            lit_str("Bearer "),
                            lit_str("Digest abc"),
                            lit_str("Bearer a\r\nInjected: true"),
                            {nullptr, 8}};
    for (Str value : bad_auth) {
        json::Writer writer{bytes};
        CHECK(!oauth_introspection_request(lit_str("token"), value, writer));
    }
    char maximum[1025];
    for (auto& byte : maximum) byte = '+';
    json::Writer accepted{bytes};
    CHECK(oauth_introspection_request({maximum, 1024}, lit_str("Bearer service"), accepted));
    CHECK(doc.parse({bytes, accepted.len}));
    json::Writer rejected{bytes};
    CHECK(!oauth_introspection_request({maximum, 1025}, lit_str("Bearer service"), rejected));
    char tiny[8];
    json::Writer full{tiny, sizeof(tiny)};
    CHECK(!oauth_introspection_request(lit_str("token"), lit_str("Bearer service"), full));
}

TEST(oauth_client, scoped_form_encoding_rejects_injection_and_bounds) {
    char output_bytes[8192];
    json::Writer output{output_bytes};
    REQUIRE(oauth_client_credentials_request(lit_str("reports:read reports:write a+b/x=%&"),
                                             lit_str("Basic Y2xpZW50OnNlY3JldA=="),
                                             output));
    json::Document document;
    REQUIRE(document.parse({output_bytes, output.len}));
    char decoded[4096];
    json::Writer body{decoded, sizeof(decoded)};
    REQUIRE(document.string(document.pointer(lit_str("/body")), body));
    CHECK(
        (Str{decoded, body.len}.eq(lit_str("grant_type=client_credentials&scope=reports%3Aread%"
                                           "20reports%3Awrite%20a%2Bb%2Fx%3D%25%26"))));
    json::Writer authorization{decoded, sizeof(decoded)};
    REQUIRE(document.string(document.pointer(lit_str("/headers/Authorization")), authorization));
    CHECK((Str{decoded, authorization.len}.eq(lit_str("Basic Y2xpZW50OnNlY3JldA=="))));
    json::Writer preserved{output_bytes};
    REQUIRE(oauth_client_credentials_request(
        lit_str("Write read Write"), lit_str("bAsIc YTpi"), preserved));
    REQUIRE(document.parse({output_bytes, preserved.len}));
    json::Writer ordered{decoded, sizeof(decoded)};
    REQUIRE(document.string(document.pointer(lit_str("/body")), ordered));
    CHECK((Str{decoded, ordered.len}.eq(
        lit_str("grant_type=client_credentials&scope=Write%20read%20Write"))));
    const Str kInvalid[] = {lit_str(""),
                            lit_str(" read"),
                            lit_str("read "),
                            lit_str("read  write"),
                            lit_str("read\twrite"),
                            lit_str("read\nwrite"),
                            lit_str("read\"write"),
                            lit_str("read\\write"),
                            lit_str("r\xc3\xa9"),
                            {"read\0write", 10},
                            {nullptr, 1}};
    for (const Str kScopes : kInvalid) {
        json::Writer writer{output_bytes};
        CHECK(!oauth_client_credentials_request(kScopes, lit_str("Basic YTpi"), writer));
        CHECK_EQ(writer.len, 0u);
    }
    const Str kBadAuthorization[] = {lit_str(""),
                                     lit_str("Basic "),
                                     lit_str("Bearer service"),
                                     lit_str("Basic a\r\nInjected: yes"),
                                     lit_str("Basic a\x7f"),
                                     {nullptr, 8}};
    for (const Str kAuth : kBadAuthorization) {
        json::Writer writer{output_bytes};
        CHECK(!oauth_client_credentials_request(lit_str("read"), kAuth, writer));
        CHECK_EQ(writer.len, 0u);
    }
    char scopes[1025];
    for (auto& byte : scopes) byte = '&';
    json::Writer maximum{output_bytes};
    REQUIRE(oauth_client_credentials_request({scopes, 1024}, lit_str("Basic YTpi"), maximum));
    REQUIRE(document.parse({output_bytes, maximum.len}));
    json::Writer encoded{decoded, sizeof(decoded)};
    REQUIRE(document.string(document.pointer(lit_str("/body")), encoded));
    CHECK_EQ(encoded.len, 36u + 3u * 1024u);
    for (u32 i = 36; i < encoded.len; i += 3) {
        CHECK_EQ(decoded[i], '%');
        CHECK_EQ(decoded[i + 1], '2');
        CHECK_EQ(decoded[i + 2], '6');
    }
    json::Writer oversized{output_bytes};
    CHECK(!oauth_client_credentials_request({scopes, 1025}, lit_str("Basic YTpi"), oversized));
    char auth[2049];
    for (auto& byte : auth) byte = 'a';
    auth[0] = 'B';
    auth[1] = 'a';
    auth[2] = 's';
    auth[3] = 'i';
    auth[4] = 'c';
    auth[5] = ' ';
    json::Writer accepted_auth{output_bytes};
    CHECK(oauth_client_credentials_request(lit_str("read"), {auth, 2048}, accepted_auth));
    json::Writer rejected_auth{output_bytes};
    CHECK(!oauth_client_credentials_request(lit_str("read"), {auth, 2049}, rejected_auth));
    char tiny[8];
    json::Writer short_output{tiny, sizeof(tiny)};
    CHECK(!oauth_client_credentials_request(lit_str("read"), lit_str("Basic YTpi"), short_output));
    CHECK(!short_output.ok);
}

TEST(oauth_client, resource_request_preserves_identifier_and_rejects_unsafe_uris) {
    char bytes[8192], decoded[4096];
    json::Document document;
    const auto kResource =
        lit_str("https://api.example.test/reports?tenant=a+b&scope=write%2Fread");
    json::Writer output{bytes};
    REQUIRE(oauth_client_credentials_request(
        lit_str("read write"), lit_str("Basic YTpi"), kResource, output));
    REQUIRE(document.parse({bytes, output.len}));
    json::Writer body{decoded, sizeof(decoded)};
    REQUIRE(document.string(document.pointer(lit_str("/body")), body));
    CHECK((Str{decoded, body.len}.eq(
        lit_str("grant_type=client_credentials&scope=read%20write&resource=https%3A%2F%2Fapi."
                "example.test%2Freports%3Ftenant%3Da%2Bb%26scope%3Dwrite%252Fread"))));
    const Str kValid[] = {lit_str("https://api.example.test"),
                          lit_str("HTTPS://API.Example.test:8443/a%23b"),
                          lit_str("https://127.0.0.1:443/"),
                          lit_str("https://[::1]/a"),
                          lit_str("https://[2001:db8::1]:65535/?a=b?c=d"),
                          lit_str("https://api.example.test/!$&'()*+,;=:@~_-.09")};
    for (const Str kUri : kValid) {
        json::Writer writer{bytes};
        CHECK(
            oauth_client_credentials_request(lit_str("read"), lit_str("Basic YTpi"), kUri, writer));
    }
    const Str kInvalid[] = {lit_str(""),
                            lit_str("/relative"),
                            lit_str("//api.example.test/"),
                            lit_str("http://api.example.test/"),
                            lit_str("urn:example:reports"),
                            lit_str("https://"),
                            lit_str("https:///path"),
                            lit_str("https://?x=y"),
                            lit_str("https://user:secret@api.example.test/"),
                            lit_str("https://api.example.test/#"),
                            lit_str("https://api.example.test/a#b"),
                            lit_str("https://api.example.test/white space"),
                            lit_str("https://api.example.test/\\path"),
                            lit_str("https://api.example.test/\r\n"),
                            lit_str("https://api.example.test/\x7f"),
                            lit_str("https://api.example.test/r\xc3\xa9"),
                            lit_str("https://api.example.test/%"),
                            lit_str("https://api.example.test/%2"),
                            lit_str("https://api.example.test/%zz"),
                            lit_str("https://api.example.test/[]"),
                            lit_str("https://api.example.test/\""),
                            lit_str("https://api.example.test/<>"),
                            lit_str("https://api.example.test/{}"),
                            lit_str("https://api.example.test/|"),
                            lit_str("https://api.example.test/`"),
                            lit_str("https://[::1"),
                            lit_str("https://[bad]/"),
                            lit_str("https://[::1\0evil]/"),
                            lit_str("https://[::1]extra/"),
                            lit_str("https://[::1]:/"),
                            lit_str("https://[::1]:0/"),
                            lit_str("https://host:/"),
                            lit_str("https://host:65536/"),
                            lit_str("https://host:999999999999/"),
                            lit_str("https://host:-1/"),
                            lit_str("https://host:x/"),
                            lit_str("https://-host/"),
                            lit_str("https://host-/"),
                            lit_str("https://host..test/"),
                            lit_str("https://host./"),
                            lit_str("https://ho_st/"),
                            {"https://host/\0tail", 18},
                            {nullptr, 12}};
    for (const Str kUri : kInvalid) {
        json::Writer writer{bytes};
        CHECK(!oauth_client_credentials_request(
            lit_str("read"), lit_str("Basic YTpi"), kUri, writer));
        CHECK_EQ(writer.len, 0u);
    }
    char hostname[262];
    __builtin_memcpy(hostname, "https://", 8);
    for (u32 i = 0; i < 254; ++i) hostname[8 + i] = i == 63 || i == 127 || i == 191 ? '.' : 'a';
    json::Writer label_limit{bytes};
    CHECK(oauth_client_credentials_request(
        lit_str("read"), lit_str("Basic YTpi"), {hostname, 71}, label_limit));
    hostname[71] = 'a';  // A 64-byte label, without a trailing dot.
    json::Writer label_over{bytes};
    CHECK(!oauth_client_credentials_request(
        lit_str("read"), lit_str("Basic YTpi"), {hostname, 72}, label_over));
    hostname[71] = '.';
    json::Writer host_limit{bytes};
    CHECK(oauth_client_credentials_request(
        lit_str("read"), lit_str("Basic YTpi"), {hostname, 261}, host_limit));
    json::Writer host_over{bytes};
    CHECK(!oauth_client_credentials_request(
        lit_str("read"), lit_str("Basic YTpi"), {hostname, 262}, host_over));
    char maximum[1025];
    __builtin_memcpy(maximum, "https://host/", 13);
    for (u32 i = 13; i < sizeof(maximum); ++i) maximum[i] = 'a';
    json::Writer limit{bytes};
    CHECK(oauth_client_credentials_request(
        lit_str("read"), lit_str("Basic YTpi"), {maximum, 1024}, limit));
    json::Writer oversized{bytes};
    CHECK(!oauth_client_credentials_request(
        lit_str("read"), lit_str("Basic YTpi"), {maximum, 1025}, oversized));
    char scope[1024];
    for (auto& byte : scope) byte = '&';
    for (u32 i = 13; i < 1024; ++i) maximum[i] = '&';
    // 36-byte prefix + 3072-byte encoded scope + 10-byte resource prefix +
    // 21-byte encoded URI authority + 957 path bytes = the 4096-byte body limit.
    for (u32 i = 13; i < 1024; ++i) maximum[i] = 'a';
    json::Writer exact{bytes};
    REQUIRE(oauth_client_credentials_request(
        {scope, sizeof(scope)}, lit_str("Basic YTpi"), {maximum, 970}, exact));
    REQUIRE(document.parse({bytes, exact.len}));
    json::Writer exact_body{decoded, sizeof(decoded)};
    REQUIRE(document.string(document.pointer(lit_str("/body")), exact_body));
    CHECK_EQ(exact_body.len, 4096u);
    json::Writer one_over{bytes};
    CHECK(!oauth_client_credentials_request(
        {scope, sizeof(scope)}, lit_str("Basic YTpi"), {maximum, 971}, one_over));
    CHECK_EQ(one_over.len, 0u);
    for (u32 i = 13; i < 1024; ++i) maximum[i] = '&';
    json::Writer exhausted{bytes};
    CHECK(!oauth_client_credentials_request(
        {scope, sizeof(scope)}, lit_str("Basic YTpi"), {maximum, 1024}, exhausted));
    CHECK_EQ(exhausted.len,
             0u);  // Combined encoded body exceeds the existing 4096-byte callout bound.
    json::Writer bad_scope{bytes};
    CHECK(!oauth_client_credentials_request(
        lit_str("read  write"), lit_str("Basic YTpi"), kResource, bad_scope));
    json::Writer bad_auth{bytes};
    CHECK(!oauth_client_credentials_request(
        lit_str("read"), lit_str("Bearer forbidden"), kResource, bad_auth));
    char tiny[8];
    json::Writer short_output{tiny, sizeof(tiny)};
    CHECK(!oauth_client_credentials_request(
        lit_str("read"), lit_str("Basic YTpi"), kResource, short_output));
    CHECK(!short_output.ok);
}

TEST(oauth_client, token_exchange_has_fixed_types_and_strict_policy) {
    const auto kPolicy = lit_str(
        R"({"scope":"read write a+b&x=y","resource":"https://api.example.test/a?b=c+d&x=%2F"})");
    char bytes[8192], decoded[4096];
    json::Document scratch, document;
    json::Writer output{bytes};
    REQUIRE(oauth_token_exchange_request(
        scratch, lit_str("subject+/=="), lit_str("Basic YTpi"), kPolicy, output));
    REQUIRE(document.parse({bytes, output.len}));
    json::Writer body{decoded, sizeof(decoded)};
    REQUIRE(document.string(document.pointer(lit_str("/body")), body));
    CHECK((Str{decoded, body.len}.eq(
        lit_str("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"
                "&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
                "&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
                "&subject_token=subject%2B%2F%3D%3D&scope=read%20write%20a%2Bb%26x%3Dy"
                "&resource=https%3A%2F%2Fapi.example.test%2Fa%3Fb%3Dc%2Bd%26x%3D%252F"))));
    const Str kBadSubject[] = {lit_str(""),
                               lit_str("a b"),
                               lit_str("a&scope=admin"),
                               lit_str("a=b"),
                               lit_str("a\r\n"),
                               lit_str("a\0b"),
                               lit_str("t\xc3\xa9"),
                               {nullptr, 1}};
    for (const Str kSubject : kBadSubject) {
        json::Writer writer{bytes};
        CHECK(!oauth_token_exchange_request(
            scratch, kSubject, lit_str("Basic YTpi"), kPolicy, writer));
        CHECK_EQ(writer.len, 0u);
    }
    const Str kBadPolicy[] = {
        lit_str(""),
        lit_str("{"),
        lit_str("[]"),
        lit_str("null"),
        lit_str("{}"),
        lit_str(R"({"scope":"read"})"),
        lit_str(R"({"resource":"https://api.test/"})"),
        lit_str(R"({"scope":"read","resource":"https://api.test/","actor_token":"forged"})"),
        lit_str(R"({"scope":"read","resource":"https://api.test/","audience":"forged"})"),
        lit_str(
            R"({"scope":"read","resource":"https://api.test/","requested_token_type":"id_token"})"),
        lit_str(R"({"scope":"read","resource":"https://api.test/","scope":"admin"})"),
        lit_str(R"({"scope":"read","resource":"https://api.test/","\u0073cope":"admin"})"),
        lit_str(R"({"scope":["read"],"resource":"https://api.test/"})"),
        lit_str(R"({"scope":"read","resource":null})"),
        lit_str(R"({"scope":"read  write","resource":"https://api.test/"})"),
        lit_str(R"({"scope":"read","resource":"https://api.test/#fragment"})"),
        lit_str(R"({"scope":"read","resource":"https://[::1\u0000evil]/"})"),
        {nullptr, 1}};
    for (const Str kConfig : kBadPolicy) {
        json::Writer writer{bytes};
        CHECK(!oauth_token_exchange_request(
            scratch, lit_str("subject"), lit_str("Basic YTpi"), kConfig, writer));
        CHECK_EQ(writer.len, 0u);
    }
    char subject[1025];
    for (auto& byte : subject) byte = 'a';
    json::Writer maximum{bytes};
    CHECK(oauth_token_exchange_request(
        scratch, {subject, 1024}, lit_str("Basic YTpi"), kPolicy, maximum));
    json::Writer oversized{bytes};
    CHECK(!oauth_token_exchange_request(
        scratch, {subject, 1025}, lit_str("Basic YTpi"), kPolicy, oversized));
    const Str kBadAuth[] = {lit_str("Bearer forbidden"), lit_str("Basic "), lit_str("Basic a\r\n")};
    for (const Str kAuth : kBadAuth) {
        json::Writer writer{bytes};
        CHECK(!oauth_token_exchange_request(scratch, lit_str("subject"), kAuth, kPolicy, writer));
    }
    char policy[4096];
    json::Writer config{policy, sizeof(policy)};
    config.text(lit_str("{\"scope\":\""));
    for (u32 i = 0; i < 1024; ++i) config.put('&');
    config.text(lit_str("\",\"resource\":\"https://api.test/\"}"));
    json::Writer accepted_scope{bytes};
    CHECK(oauth_token_exchange_request(
        scratch, lit_str("s"), lit_str("Basic YTpi"), {policy, config.len}, accepted_scope));
    json::Writer exhausted{bytes};
    CHECK(!oauth_token_exchange_request(
        scratch, {subject, 1024}, lit_str("Basic YTpi"), {policy, config.len}, exhausted));
    CHECK_EQ(exhausted.len, 0u);
    json::Writer resource_config{policy, sizeof(policy)};
    resource_config.text(lit_str("{\"scope\":\"read\",\"resource\":\"https://host/"));
    for (u32 i = 13; i < 1024; ++i) resource_config.put('a');
    resource_config.text(lit_str("\"}"));
    json::Writer resource_limit{bytes};
    CHECK(oauth_token_exchange_request(scratch,
                                       lit_str("s"),
                                       lit_str("Basic YTpi"),
                                       {policy, resource_config.len},
                                       resource_limit));
    // Extend the decoded identifier by one byte while keeping policy JSON valid.
    policy[resource_config.len - 2] = 'a';
    policy[resource_config.len - 1] = '"';
    policy[resource_config.len] = '}';
    json::Writer resource_over{bytes};
    CHECK(!oauth_token_exchange_request(scratch,
                                        lit_str("s"),
                                        lit_str("Basic YTpi"),
                                        {policy, resource_config.len + 1},
                                        resource_over));
    char tiny[8];
    json::Writer short_output{tiny, sizeof(tiny)};
    CHECK(!oauth_token_exchange_request(
        scratch, lit_str("subject"), lit_str("Basic YTpi"), kPolicy, short_output));
    CHECK(!short_output.ok);
}

TEST(jwt_claims, certificate_binding_requires_exact_canonical_confirmation) {
    json::Document scratch;
    const Str fingerprint =
        lit_str("0000000000000000000000000000000000000000000000000000000000000000");
    const Str valid =
        lit_str(R"({"cnf":{"x5t#S256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}})");
    CHECK(jwt_certificate_bound(scratch, valid, fingerprint));
    CHECK(jwt_certificate_bound(
        scratch,
        lit_str(R"({"c\u006ef":{"x5t#S25\u0036":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}})"),
        fingerprint));
    CHECK(jwt_certificate_bound(
        scratch,
        lit_str(R"({"cnf":{"x5t#S256":"__________________________________________8"}})"),
        lit_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")));
    CHECK(jwt_certificate_bound(
        scratch,
        lit_str(
            R"({"cnf":{"x5t#S256":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"},"sub":"alice"})"),
        lit_str("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")));
    CHECK(jwt_certificate_bound(
        scratch,
        lit_str(R"({"cnf":{"x5t#S256":"\u0041AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}})"),
        fingerprint));
    CHECK(!jwt_certificate_bound(
        scratch,
        lit_str(R"({"cnf":{"x5t#S256":"//////////////////////////////////////////8"}})"),
        lit_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")));
    CHECK(!jwt_certificate_bound(
        scratch,
        lit_str(R"({"cnf":{"x5t#S256":"__________________________________________9"}})"),
        lit_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")));
    const Str invalid[] = {
        lit_str("{}"),
        lit_str("[]"),
        lit_str("null"),
        lit_str("broken"),
        lit_str(R"({"cnf":null})"),
        lit_str(R"({"cnf":[]})"),
        lit_str(R"({"cnf":{}})"),
        lit_str(R"({"cnf":{"x5t":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}})"),
        lit_str(R"({"cnf":{"x5t#S256":null}})"),
        lit_str(R"({"cnf":{"x5t#S256":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]}})"),
        lit_str(R"({"cnf":{"x5t#S256":""}})"),
        lit_str(R"({"cnf":{"x5t#S256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}})"),
        lit_str(R"({"cnf":{"x5t#S256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"}})"),
        lit_str(R"({"cnf":{"x5t#S256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"}})"),
        lit_str(R"({"cnf":{"x5t#S256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\u0000"}})"),
        lit_str(
            R"({"cnf":{"x5t#S256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","jkt":"other"}})"),
        lit_str(
            R"({"cnf":{"x5t#S256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","x5t#S25\u0036":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}})"),
        lit_str(
            R"({"cnf":{"x5t#S256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"c\u006ef":{}})"),
        lit_str(R"({"nested":{"cnf":{"x5t#S256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}})"),
    };
    for (Str claims : invalid) CHECK(!jwt_certificate_bound(scratch, claims, fingerprint));
    CHECK(!jwt_certificate_bound(scratch, {nullptr, 1}, fingerprint));
    CHECK(!jwt_certificate_bound(scratch, valid, {nullptr, 64}));
    CHECK(!jwt_certificate_bound(scratch, valid, lit_str("")));
    CHECK(!jwt_certificate_bound(
        scratch,
        valid,
        lit_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")));
    CHECK(!jwt_certificate_bound(
        scratch,
        valid,
        lit_str("A000000000000000000000000000000000000000000000000000000000000000")));
    char changed[64];
    for (u32 index = 0; index < 64; ++index) {
        for (u32 i = 0; i < 64; ++i) changed[i] = '0';
        changed[index] = '1';
        CHECK(!jwt_certificate_bound(scratch, valid, {changed, 64}));
    }
    CHECK(jwt_certificate_bound(scratch, valid, fingerprint));
}
