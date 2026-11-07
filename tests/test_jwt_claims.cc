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
