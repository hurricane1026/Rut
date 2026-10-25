#include "rut/runtime/json.h"
#include "rut/runtime/jwt_claims.h"
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

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
