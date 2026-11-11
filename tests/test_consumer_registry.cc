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
