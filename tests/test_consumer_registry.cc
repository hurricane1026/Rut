#include "rut/common/types.h"
#include "rut/runtime/consumer_registry.h"
#include "test.h"

#include <stdio.h>
#include <string.h>

using namespace rut;
namespace {
constexpr Str kRegistry = lit_str(
    R"({"version":1,"consumers":[{"id":"alice","enabled":true,"groups":["readers","staff"]},{"id":"bob","enabled":false,"groups":[]}],"credentials":[{"id":"a-current","consumerId":"alice","method":"bearer","secret":"alice-current","enabled":true},{"id":"a-old","consumerId":"alice","method":"bearer","secret":"alice-old","enabled":false},{"id":"a-basic","consumerId":"alice","method":"basic","secret":"alice:password","enabled":true},{"id":"b-key","consumerId":"bob","method":"header","secret":"bob-key","enabled":true}]})");
Str view(const char* value) {
    return {value, static_cast<u32>(strlen(value))};
}
bool contains(Str haystack, Str needle) {
    if (!haystack.ptr || !needle.ptr || needle.len > haystack.len) return false;
    for (u32 i = 0; i <= haystack.len - needle.len; ++i)
        if (memcmp(haystack.ptr + i, needle.ptr, needle.len) == 0) return true;
    return false;
}
}  // namespace
TEST(consumer_registry, identity_projection_and_revocation) {
    json::Document document;
    CHECK(consumer_registry_valid(document, kRegistry));
    char bytes[8192]{};
    json::Writer output{bytes};
    CHECK(consumer_registry_authenticate(
        document, kRegistry, lit_str("bearer"), lit_str("Bearer alice-current"), output));
    CHECK(!strstr(bytes, "secret"));
    CHECK(!strstr(bytes, "alice-current"));
    CHECK((Str{bytes, output.len}.eq(lit_str(
        R"({"consumerId":"alice","credentialId":"a-current","method":"bearer","groups":["readers","staff"]})"))));
    output.len = 0;
    CHECK(consumer_registry_authenticate(
        document, kRegistry, lit_str("basic"), lit_str("Basic YWxpY2U6cGFzc3dvcmQ="), output));
    const Str denied[] = {lit_str("Bearer alice-old"),
                          lit_str("Bearer other"),
                          lit_str(""),
                          lit_str("Basic YWxpY2U6cGFzc3dvcmQ=")};
    for (Str value : denied) {
        output.len = 0;
        CHECK(
            !consumer_registry_authenticate(document, kRegistry, lit_str("bearer"), value, output));
        CHECK(output.len == 0);
    }
    output.len = 0;
    CHECK(!consumer_registry_authenticate(
        document, kRegistry, lit_str("header"), lit_str("bob-key"), output));
}
TEST(consumer_registry, rejects_invalid_whole_snapshots) {
    json::Document document;
    const Str invalid[] = {
        lit_str(R"({"version":2,"consumers":[],"credentials":[]})"),
        lit_str(R"({"version":1,"consumers":[],"credentials":[],"unknown":true})"),
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":["x",7]}],"credentials":[]})"),
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":["x","x"]}],"credentials":[]})"),
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]},{"id":"\u0061","enabled":true,"groups":[]}],"credentials":[]})"),
        lit_str(
            R"({"version":1,"consumers":[],"credentials":[{"id":"key","consumerId":"absent","method":"header","secret":"key","enabled":true}]})"),
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"key","consumerId":"a","method":"unknown","secret":"key","enabled":true}]})"),
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"key","consumerId":"a","method":"header","secret":"","enabled":false}]})"),
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":"true","groups":[]}],"credentials":[]})"),
    };
    for (Str value : invalid) CHECK(!consumer_registry_valid(document, value));
    CHECK(consumer_registry_valid(document,
                                  lit_str(R"({"version":1,"consumers":[],"credentials":[]})")));
}
TEST(consumer_registry, snapshot_capacity_and_ambiguous_secrets) {
    json::Document document;
    char bytes[8192];
    for (u32 count = 32; count <= 33; ++count) {
        u32 length =
            static_cast<u32>(snprintf(bytes, sizeof(bytes), "{\"version\":1,\"consumers\":["));
        for (u32 i = 0; i < count; ++i)
            length += static_cast<u32>(snprintf(bytes + length,
                                                sizeof(bytes) - length,
                                                "%s{\"id\":\"c%u\",\"enabled\":true,\"groups\":[]}",
                                                i ? "," : "",
                                                i));
        length += static_cast<u32>(
            snprintf(bytes + length, sizeof(bytes) - length, "],\"credentials\":[]}"));
        CHECK(consumer_registry_valid(document, {bytes, length}) == (count == 32));
    }
    CHECK(!consumer_registry_valid(
        document,
        view(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]},{"id":"b","enabled":true,"groups":[]}],"credentials":[{"id":"k1","consumerId":"a","method":"header","secret":"shared","enabled":true},{"id":"k2","consumerId":"b","method":"header","secret":"shared","enabled":false}]})")));
}
TEST(consumer_registry, mtls_fingerprints_are_public_pins_and_method_is_separated) {
    constexpr Str kFirst =
        lit_str("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    constexpr Str kSecond =
        lit_str("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    constexpr Str kRegistry = lit_str(
        R"({"version":1,"consumers":[{"id":"alice","enabled":true,"groups":["readers"]},{"id":"bob","enabled":true,"groups":[]}],"credentials":[{"id":"alice-cert","consumerId":"alice","method":"mtls","secret":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","enabled":true},{"id":"bob-cert","consumerId":"bob","method":"mtls","secret":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","enabled":false}]})");
    json::Document document;
    CHECK(consumer_registry_valid(document, kRegistry));
    char bytes[8192]{};
    json::Writer output{bytes};
    CHECK(consumer_registry_authenticate_mtls(document, kRegistry, kFirst, output));
    CHECK((Str{bytes, output.len}.eq(lit_str(
        R"({"consumerId":"alice","credentialId":"alice-cert","method":"mtls","groups":["readers"]})"))));
    output = json::Writer{bytes};
    CHECK(!consumer_registry_authenticate(document, kRegistry, lit_str("mtls"), kFirst, output));
    output = json::Writer{bytes};
    CHECK(!consumer_registry_authenticate_mtls(document, kRegistry, kSecond, output));
    CHECK_EQ(output.len, 0u);
    output = json::Writer{bytes};
    CHECK(!consumer_registry_authenticate_mtls(
        document,
        lit_str(
            R"({"version":1,"consumers":[{"id":"alice","enabled":false,"groups":[]}],"credentials":[{"id":"cert","consumerId":"alice","method":"mtls","secret":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","enabled":true}]})"),
        lit_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        output));
    CHECK_EQ(output.len, 0u);
    output = json::Writer{bytes};
    CHECK(!consumer_registry_authenticate_mtls(
        document,
        lit_str(
            R"({"version":1,"consumers":[{"id":"alice","enabled":true,"groups":[]}],"credentials":[{"id":"cert","consumerId":"alice","method":"mtls","secret":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","enabled":true}]})"),
        lit_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        output));
    output = json::Writer{bytes};
    CHECK(!consumer_registry_authenticate_fields(
        document,
        kRegistry,
        lit_str("cert"),
        lit_str("cert=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        false,
        output));
    CHECK_EQ(output.len, 0u);
    output = json::Writer{bytes};
    CHECK(!consumer_registry_authenticate_mtls(
        document,
        kRegistry,
        lit_str("ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"),
        output));
    CHECK_EQ(output.len, 0u);
    CHECK(!consumer_registry_valid(
        document,
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"cert","consumerId":"a","method":"mtls","secret":"ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789","enabled":false}]})")));
    CHECK(!consumer_registry_valid(
        document,
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]},{"id":"b","enabled":true,"groups":[]}],"credentials":[{"id":"one","consumerId":"a","method":"mtls","secret":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","enabled":true},{"id":"two","consumerId":"b","method":"mtls","secret":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","enabled":false}]})")));
}
TEST(consumer_registry, time_window_schema_and_matching_boundaries) {
    const Str valid = lit_str(
        R"({"version":1,"consumers":[{"id":"alice","enabled":true,"groups":[]}],"credentials":[{"id":"legacy","consumerId":"alice","method":"bearer","secret":"legacy-key","enabled":true},{"id":"timed","consumerId":"alice","method":"bearer","secret":"timed-key","enabled":true,"notBefore":100,"expiresAt":200},{"id":"starts-unbounded","consumerId":"alice","method":"bearer","secret":"starts-key","enabled":true,"notBefore":0,"expiresAt":200},{"id":"ends-unbounded","consumerId":"alice","method":"bearer","secret":"ends-key","enabled":true,"notBefore":100,"expiresAt":0},{"id":"header","consumerId":"alice","method":"header","secret":"header-key","enabled":true,"notBefore":100,"expiresAt":200},{"id":"disabled-window","consumerId":"alice","method":"header","secret":"disabled-header","enabled":false,"notBefore":100,"expiresAt":200},{"id":"basic","consumerId":"alice","method":"basic","secret":"alice:password","enabled":true,"notBefore":100,"expiresAt":200},{"id":"mtls","consumerId":"alice","method":"mtls","secret":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","enabled":true,"notBefore":100,"expiresAt":200}]})");
    json::Document document;
    CHECK(consumer_registry_valid(document, valid));
    CHECK(consumer_registry_valid(
        document,
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"max","consumerId":"a","method":"bearer","secret":"x","enabled":true,"notBefore":9223372036854775807}]})")));
    const Str invalid[] = {
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"k","consumerId":"a","method":"bearer","secret":"x","enabled":true,"notBefore":"10"}]})"),
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"k","consumerId":"a","method":"bearer","secret":"x","enabled":true,"notBefore":-1}]})"),
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"k","consumerId":"a","method":"bearer","secret":"x","enabled":true,"notBefore":1.5}]})"),
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"k","consumerId":"a","method":"bearer","secret":"x","enabled":true,"notBefore":1e2}]})"),
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"k","consumerId":"a","method":"bearer","secret":"x","enabled":true,"notBefore":9223372036854775808}]})"),
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"k","consumerId":"a","method":"bearer","secret":"x","enabled":true,"notBefore":200,"expiresAt":200}]})"),
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"k","consumerId":"a","method":"bearer","secret":"x","enabled":true,"notBefore":100,"notBefore":101}]})"),
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"k","consumerId":"a","method":"bearer","secret":"x","enabled":true,"notBefore":100,"not\u0042efore":101}]})"),
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"k","consumerId":"a","method":"bearer","secret":"x","enabled":true,"expiresAt":200,"extra":1}]})")};
    for (Str value : invalid) CHECK(!consumer_registry_valid(document, value));

    char output_bytes[8192];
    const i64 times[] = {99, 100, 199, 200, 0};
    for (i64 now : times) {
        const bool active = now == 100 || now == 199;
        json::Writer bearer{output_bytes};
        CHECK(consumer_registry_authenticate_at(
                  document, valid, lit_str("bearer"), lit_str("Bearer timed-key"), now, bearer) ==
              active);
        json::Writer header{output_bytes};
        CHECK(consumer_registry_authenticate_at(
                  document, valid, lit_str("header"), lit_str("header-key"), now, header) ==
              active);
        json::Writer basic{output_bytes};
        CHECK(consumer_registry_authenticate_at(document,
                                                valid,
                                                lit_str("basic"),
                                                lit_str("Basic YWxpY2U6cGFzc3dvcmQ="),
                                                now,
                                                basic) == active);
        json::Writer mtls{output_bytes};
        CHECK(consumer_registry_authenticate_mtls_at(
                  document,
                  valid,
                  lit_str("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
                  now,
                  mtls) == active);
        json::Writer query{output_bytes};
        CHECK(consumer_registry_authenticate_fields_at(document,
                                                       valid,
                                                       lit_str("api_key"),
                                                       lit_str("/private?api_key=header-key"),
                                                       true,
                                                       now,
                                                       query) == active);
        json::Writer form{output_bytes};
        CHECK(consumer_registry_authenticate_fields_at(document,
                                                       valid,
                                                       lit_str("api_key"),
                                                       lit_str("api_key=header-key"),
                                                       false,
                                                       now,
                                                       form) == active);
    }
    json::Writer legacy{output_bytes};
    CHECK(consumer_registry_authenticate_at(
        document, valid, lit_str("bearer"), lit_str("Bearer legacy-key"), 150, legacy));
    json::Writer failed_clock{output_bytes};
    CHECK(!consumer_registry_authenticate_at(
        document, valid, lit_str("bearer"), lit_str("Bearer legacy-key"), 0, failed_clock));
    json::Writer disabled{output_bytes};
    CHECK(!consumer_registry_authenticate_at(
        document, valid, lit_str("header"), lit_str("disabled-header"), 150, disabled));
    const i64 partial_times[] = {99, 100, 199, 200};
    for (i64 now : partial_times) {
        json::Writer starts_unbounded{output_bytes};
        CHECK(consumer_registry_authenticate_at(document,
                                                valid,
                                                lit_str("bearer"),
                                                lit_str("Bearer starts-key"),
                                                now,
                                                starts_unbounded) == (now < 200));
        json::Writer ends_unbounded{output_bytes};
        CHECK(consumer_registry_authenticate_at(document,
                                                valid,
                                                lit_str("bearer"),
                                                lit_str("Bearer ends-key"),
                                                now,
                                                ends_unbounded) == (now >= 100));
    }
    const Str legacy_only = lit_str(
        R"({"version":1,"consumers":[{"id":"alice","enabled":true,"groups":[]}],"credentials":[{"id":"legacy","consumerId":"alice","method":"bearer","secret":"legacy-key","enabled":true}]})");
    json::Writer no_clock_legacy{output_bytes};
    CHECK(consumer_registry_authenticate_at(document,
                                            legacy_only,
                                            lit_str("bearer"),
                                            lit_str("Bearer legacy-key"),
                                            0,
                                            no_clock_legacy));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}

TEST(consumer_registry, explicit_encoded_sources_remove_only_authenticated_field) {
    const Str registry = lit_str(
        R"({"version":1,"consumers":[{"id":"alice","enabled":true,"groups":["staff"]}],"credentials":[{"id":"key","consumerId":"alice","method":"header","secret":"custom-key","enabled":true}]})");
    json::Document document;
    char bytes[8192];
    const Str values[] = {lit_str("api_key=custom-key"),
                          lit_str("a=one+two&api%5Fkey=custom%2Dkey&b=%2F"),
                          lit_str("api_key=custom-key&a="),
                          lit_str("a=one&api_key=custom-key")};
    const Str expected[] = {
        lit_str(""), lit_str("a=one+two&b=%2F"), lit_str("a="), lit_str("a=one")};
    for (u32 i = 0; i < 4; ++i) {
        json::Writer output{bytes};
        REQUIRE(consumer_registry_authenticate_fields(
            document, registry, lit_str("api_key"), values[i], false, output));
        bytes[output.len] = 0;
        CHECK(!strstr(bytes, "custom"));
        REQUIRE(document.parse({bytes, output.len}));
        char decoded[4096];
        json::Writer decoded_output{decoded};
        REQUIRE(document.string(document.pointer(lit_str("/remaining")), decoded_output));
        CHECK((Str{decoded, decoded_output.len}.eq(expected[i])));
    }
    json::Writer output{bytes};
    CHECK(consumer_registry_authenticate_fields(document,
                                                registry,
                                                lit_str("api_key"),
                                                lit_str("/submit?api_key=custom-key&item=1"),
                                                true,
                                                output));
    const Str invalid[] = {lit_str(""),
                           lit_str("api_key="),
                           lit_str("api_key=wrong"),
                           lit_str("api_key=custom-key&api%5fkey=custom-key"),
                           lit_str("api_key=custom-key&x=1&x=2"),
                           lit_str("api_key=custom-key&"),
                           lit_str("&api_key=custom-key"),
                           lit_str("api_key=custom-key;x=1"),
                           lit_str("api_key=custom-key&x=%00"),
                           lit_str("api_key=custom-key&x=%GG"),
                           lit_str("api_key=custom-key&x=%"),
                           lit_str("api_key=custom-key&x=%0a"),
                           lit_str("api_key=custom-key&x=%ff"),
                           lit_str("api_key=custom-key&%2561=1"),
                           lit_str("api_key=custom-key&bare"),
                           lit_str("api_key=custom-key&=empty"),
                           lit_str("api_key=custom-key#fragment")};
    for (Str value : invalid) {
        output = json::Writer{bytes};
        CHECK(!consumer_registry_authenticate_fields(
            document, registry, lit_str("api_key"), value, false, output));
        CHECK_EQ(output.len, 0u);
    }
    const Str invalid_targets[] = {lit_str("/submit"),
                                   lit_str("/submit?api_key=custom-key#fragment"),
                                   lit_str("https://host/?api_key=custom-key")};
    for (Str target : invalid_targets) {
        output = json::Writer{bytes};
        CHECK(!consumer_registry_authenticate_fields(
            document, registry, lit_str("api_key"), target, true, output));
    }
    CHECK(!consumer_credential_name_valid(lit_str("")));
    CHECK(!consumer_credential_name_valid(lit_str("api key")));
    CHECK(!consumer_credential_name_valid(lit_str("api%5fkey")));
}

TEST(consumer_registry, encoded_source_capacity_and_output_fail_closed) {
    const Str registry = lit_str(
        R"({"version":1,"consumers":[{"id":"alice","enabled":true,"groups":[]}],"credentials":[{"id":"key","consumerId":"alice","method":"header","secret":"key","enabled":true}]})");
    json::Document document;
    char input[8192], bytes[8192];
    u32 length = 0;
    for (u32 i = 0; i < 65; ++i) {
        length += static_cast<u32>(snprintf(
            input + length, sizeof(input) - length, i == 0 ? "api_key=key" : "&f%u=value", i));
        json::Writer output{bytes};
        CHECK(consumer_registry_authenticate_fields(
                  document, registry, lit_str("api_key"), {input, length}, false, output) ==
              (i < 64));
    }
    __builtin_memset(input, 'x', 4097);
    json::Writer output{bytes};
    CHECK(!consumer_registry_authenticate_fields(
        document, registry, lit_str("api_key"), {input, 4097}, false, output));
    output = json::Writer{bytes, 8};
    CHECK(!consumer_registry_authenticate_fields(
        document, registry, lit_str("api_key"), lit_str("api_key=key"), false, output));
    output = json::Writer{bytes};
    CHECK(!consumer_registry_authenticate_fields(
        document, registry, lit_str("other"), lit_str("api_key=key"), false, output));
}

TEST(consumer_registry, form_plus_decodes_once_and_never_accepts_a_second_interpretation) {
    const Str registry = lit_str(
        R"({"version":1,"consumers":[{"id":"alice","enabled":true,"groups":[]}],"credentials":[{"id":"key","consumerId":"alice","method":"header","secret":"a+b/c==","enabled":true}]})");
    json::Document document;
    char bytes[8192];
    json::Writer output{bytes};
    CHECK(consumer_registry_authenticate_fields(
        document, registry, lit_str("key"), lit_str("key=a%2Bb%2Fc%3D%3D"), false, output));
    const Str invalid[] = {lit_str("key=a+b/c=="),
                           lit_str("key=a%252Bb%2Fc%3D%3D"),
                           lit_str("key=a%2Bb%2Fc%3D%3D&%6bey=a%2Bb%2Fc%3D%3D")};
    for (Str input : invalid) {
        output = json::Writer{bytes};
        CHECK(!consumer_registry_authenticate_fields(
            document, registry, lit_str("key"), input, false, output));
        CHECK_EQ(output.len, 0u);
    }
}

TEST(consumer_registry, sha256_verifiers_match_all_supported_key_sources) {
    constexpr Str kDigest =
        lit_str("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const Str registry = lit_str(
        R"({"version":1,"consumers":[{"id":"alice","enabled":true,"groups":["staff"]}],"credentials":[{"id":"bearer-hash","consumerId":"alice","method":"bearer","secretSha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","enabled":true,"notBefore":100,"expiresAt":200},{"id":"header-hash","consumerId":"alice","method":"header","secretSha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","enabled":true}]})");
    json::Document document;
    CHECK(consumer_registry_valid(document, registry));
    char bytes[8192]{};
    json::Writer bearer{bytes};
    CHECK(consumer_registry_authenticate_at(
        document, registry, lit_str("bearer"), lit_str("Bearer abc"), 100, bearer));
    json::Writer expired{bytes};
    CHECK(!consumer_registry_authenticate_at(
        document, registry, lit_str("bearer"), lit_str("Bearer abc"), 200, expired));
    json::Writer header{bytes};
    CHECK(consumer_registry_authenticate(
        document, registry, lit_str("header"), lit_str("abc"), header));
    json::Writer query{bytes};
    CHECK(consumer_registry_authenticate_fields(
        document, registry, lit_str("api_key"), lit_str("/private?api_key=abc"), true, query));
    json::Writer form{bytes};
    CHECK(consumer_registry_authenticate_fields(
        document, registry, lit_str("api_key"), lit_str("api_key=abc"), false, form));
    char digest_token[72] = "Bearer ";
    __builtin_memcpy(digest_token + 7, kDigest.ptr, kDigest.len);
    json::Writer hash_as_token{bytes};
    CHECK(!consumer_registry_authenticate(document,
                                          registry,
                                          lit_str("bearer"),
                                          {digest_token, sizeof(digest_token) - 1},
                                          hash_as_token));
    json::Writer wrong{bytes};
    CHECK(!consumer_registry_authenticate(document, registry, lit_str("header"), kDigest, wrong));
}

TEST(consumer_registry, sha256_verifier_schema_and_ambiguity_fail_closed) {
    const Str
        invalid
            [] = {lit_str(
                      R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"k","consumerId":"a","method":"bearer","secret":"abc","secretSha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","enabled":true}]})"),
                  lit_str(
                      R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"k","consumerId":"a","method":"basic","secretSha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","enabled":true}]})"),
                  lit_str(
                      R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"k","consumerId":"a","method":"bearer","secretSha256":"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD","enabled":true}]})"),
                  lit_str(
                      R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"k","consumerId":"a","method":"bearer","secretSha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","enabled":true,"extra":1}]})"),
                  lit_str(
                      R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"k","consumerId":"a","method":"bearer","secretSha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","secret\u0053ha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","enabled":true}]})"),
                  lit_str(
                      R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"k1","consumerId":"a","method":"header","secret":"abc","enabled":false},{"id":"k2","consumerId":"a","method":"header","secretSha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","enabled":true}]})"),
                  lit_str(
                      R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"k1","consumerId":"a","method":"bearer","secretSha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","enabled":false},{"id":"k2","consumerId":"a","method":"bearer","secret":"abc","enabled":true}]})"),
                  lit_str(
                      R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":[]}],"credentials":[{"id":"k1","consumerId":"a","method":"bearer","secretSha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","enabled":false},{"id":"k2","consumerId":"a","method":"bearer","secretSha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","enabled":true}]})")};
    json::Document document;
    for (Str value : invalid) CHECK(!consumer_registry_valid(document, value));
}

TEST(consumer_registry, credential_groups_inherit_narrow_and_project_across_methods) {
    const Str registry = lit_str(
        R"({"version":1,"consumers":[{"id":"alice","enabled":true,"groups":["readers","writers","staff"]}],"credentials":[{"id":"inherit","consumerId":"alice","method":"bearer","secret":"inherit-key","enabled":true},{"id":"none","consumerId":"alice","method":"bearer","secret":"none-key","enabled":true,"groups":[]},{"id":"subset","consumerId":"alice","method":"bearer","secret":"subset-key","enabled":true,"groups":["readers"],"notBefore":100,"expiresAt":200},{"id":"basic","consumerId":"alice","method":"basic","secret":"alice:pw","enabled":true,"groups":[]},{"id":"header","consumerId":"alice","method":"header","secret":"header-key","enabled":true,"groups":["writers"]},{"id":"query","consumerId":"alice","method":"header","secret":"query-key","enabled":true,"groups":["readers"]},{"id":"hash-bearer","consumerId":"alice","method":"bearer","secretSha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","enabled":true,"groups":["readers"]},{"id":"hash-header","consumerId":"alice","method":"header","secretSha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","enabled":true,"groups":["writers"]},{"id":"mtls","consumerId":"alice","method":"mtls","secret":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","enabled":true,"groups":["staff"]}]})");
    json::Document document;
    CHECK(consumer_registry_valid(document, registry));
    char bytes[8192]{};
    json::Writer inherited{bytes};
    CHECK(consumer_registry_authenticate(
        document, registry, lit_str("bearer"), lit_str("Bearer inherit-key"), inherited));
    CHECK((Str{bytes, inherited.len}.eq(lit_str(
        R"({"consumerId":"alice","credentialId":"inherit","method":"bearer","groups":["readers","writers","staff"]})"))));
    json::Writer no_groups{bytes};
    CHECK(consumer_registry_authenticate(
        document, registry, lit_str("bearer"), lit_str("Bearer none-key"), no_groups));
    CHECK((Str{bytes, no_groups.len}.eq(
        lit_str(R"({"consumerId":"alice","credentialId":"none","method":"bearer","groups":[]})"))));
    json::Writer subset{bytes};
    CHECK(consumer_registry_authenticate_at(
        document, registry, lit_str("bearer"), lit_str("Bearer subset-key"), 100, subset));
    CHECK((Str{bytes, subset.len}.eq(lit_str(
        R"({"consumerId":"alice","credentialId":"subset","method":"bearer","groups":["readers"]})"))));
    json::Writer subset_expired{bytes};
    CHECK(!consumer_registry_authenticate_at(
        document, registry, lit_str("bearer"), lit_str("Bearer subset-key"), 200, subset_expired));
    json::Writer basic{bytes};
    CHECK(consumer_registry_authenticate(
        document, registry, lit_str("basic"), lit_str("Basic YWxpY2U6cHc="), basic));
    CHECK((Str{bytes, basic.len}.eq(
        lit_str(R"({"consumerId":"alice","credentialId":"basic","method":"basic","groups":[]})"))));
    json::Writer header{bytes};
    CHECK(consumer_registry_authenticate(
        document, registry, lit_str("header"), lit_str("header-key"), header));
    CHECK((Str{bytes, header.len}.eq(lit_str(
        R"({"consumerId":"alice","credentialId":"header","method":"header","groups":["writers"]})"))));
    json::Writer query{bytes};
    CHECK(consumer_registry_authenticate_fields(document,
                                                registry,
                                                lit_str("api_key"),
                                                lit_str("/private?api_key=query-key"),
                                                true,
                                                query));
    CHECK(contains({bytes, query.len}, lit_str(R"("groups":["readers"])")));
    json::Writer form{bytes};
    CHECK(consumer_registry_authenticate_fields(
        document, registry, lit_str("api_key"), lit_str("api_key=query-key"), false, form));
    CHECK(contains({bytes, form.len}, lit_str(R"("groups":["readers"])")));
    json::Writer hashed_bearer{bytes};
    CHECK(consumer_registry_authenticate(
        document, registry, lit_str("bearer"), lit_str("Bearer abc"), hashed_bearer));
    CHECK((Str{bytes, hashed_bearer.len}.eq(lit_str(
        R"({"consumerId":"alice","credentialId":"hash-bearer","method":"bearer","groups":["readers"]})"))));
    json::Writer hashed_header{bytes};
    CHECK(consumer_registry_authenticate(
        document, registry, lit_str("header"), lit_str("abc"), hashed_header));
    CHECK((Str{bytes, hashed_header.len}.eq(lit_str(
        R"({"consumerId":"alice","credentialId":"hash-header","method":"header","groups":["writers"]})"))));
    json::Writer mtls{bytes};
    CHECK(consumer_registry_authenticate_mtls(
        document,
        registry,
        lit_str("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        mtls));
    CHECK((Str{bytes, mtls.len}.eq(lit_str(
        R"({"consumerId":"alice","credentialId":"mtls","method":"mtls","groups":["staff"]})"))));
}

TEST(consumer_registry, credential_group_schema_is_strict_and_membership_is_snapshot_validated) {
    const Str invalid[] = {
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":["readers"]}],"credentials":[{"id":"k","consumerId":"a","method":"bearer","secret":"key","enabled":true,"groups":"readers"}]})"),
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":["readers"]}],"credentials":[{"id":"k","consumerId":"a","method":"bearer","secret":"key","enabled":true,"groups":["unknown"]}]})"),
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":["readers"]}],"credentials":[{"id":"k","consumerId":"a","method":"bearer","secret":"key","enabled":false,"groups":["readers","\u0072eaders"]}]})"),
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":["readers"]}],"credentials":[{"id":"k","consumerId":"a","method":"bearer","secret":"key","enabled":false,"groups":["r\u00e9aders"]}]})"),
        lit_str(
            R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":["readers"]}],"credentials":[{"id":"k","consumerId":"a","method":"bearer","secret":"key","enabled":false,"groups":["readers"],"\u0067roups":[]}]})")};
    json::Document document;
    for (Str value : invalid) CHECK(!consumer_registry_valid(document, value));

    char bytes[8192];
    const u32 length = static_cast<u32>(snprintf(
        bytes,
        sizeof(bytes),
        R"({"version":1,"consumers":[{"id":"a","enabled":true,"groups":["g0","g1","g2","g3","g4","g5","g6","g7","g8","g9","g10","g11","g12","g13","g14","g15"]}],"credentials":[{"id":"k","consumerId":"a","method":"header","secret":"key","enabled":false,"groups":["g0","g1","g2","g3","g4","g5","g6","g7","g8","g9","g10","g11","g12","g13","g14","g15","g16"]}]})"));
    CHECK(!consumer_registry_valid(document, {bytes, length}));

    const Str expanded_snapshot = lit_str(
        R"({"version":1,"consumers":[{"id":"alice","enabled":true,"groups":["reader","admin"]}],"credentials":[{"id":"limited","consumerId":"alice","method":"bearer","secret":"limited-key","enabled":true,"groups":["reader"]},{"id":"inherited","consumerId":"alice","method":"bearer","secret":"inherited-key","enabled":true}]})");
    json::Writer limited{bytes};
    CHECK(consumer_registry_authenticate(
        document, expanded_snapshot, lit_str("bearer"), lit_str("Bearer limited-key"), limited));
    CHECK((Str{bytes, limited.len}.eq(lit_str(
        R"({"consumerId":"alice","credentialId":"limited","method":"bearer","groups":["reader"]})"))));
    json::Writer inherited{bytes};
    CHECK(consumer_registry_authenticate(document,
                                         expanded_snapshot,
                                         lit_str("bearer"),
                                         lit_str("Bearer inherited-key"),
                                         inherited));
    CHECK((Str{bytes, inherited.len}.eq(lit_str(
        R"({"consumerId":"alice","credentialId":"inherited","method":"bearer","groups":["reader","admin"]})"))));
}
