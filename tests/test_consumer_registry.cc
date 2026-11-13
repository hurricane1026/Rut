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
