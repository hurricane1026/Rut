#include "rut/runtime/remote_jwks.h"
#include "test.h"

#include <stdio.h>
#include <string.h>

using namespace rut;
namespace {
RemoteJwks policy() {
    RemoteJwks result;
    strcpy(result.endpoint.tls.server_name, "issuer.example");
    strcpy(result.endpoint.path, "/keys");
    result.endpoint.port = 443;
    strcpy(result.discovery_issuer, "https://issuer.example/tenant");
    strcpy(result.allowed_addresses[0], "192.0.2.1");
    result.allowed_count = 1;
    return result;
}
}  // namespace
TEST(remote_jwks_metadata, exact_issuer_uri_and_duplicate_rejection) {
    auto configuration = policy();
    json::Document document;
    CHECK(jwks_discovery_valid(
        document,
        lit_str(
            R"({"issuer":"https://issuer.example/tenant","jwks_uri":"https://issuer.example/keys"})"),
        configuration));
    CHECK(jwks_discovery_valid(
        document,
        lit_str(
            R"({"issuer":"https://issuer.example/tenant","jwks_uri":"https://issuer.example:443/keys","extra":true})"),
        configuration));
    const Str invalid[] = {
        lit_str(R"({"issuer":"https://other/tenant","jwks_uri":"https://issuer.example/keys"})"),
        lit_str(
            R"({"issuer":"https://issuer.example/tenant","jwks_uri":"http://issuer.example/keys"})"),
        lit_str(
            R"({"issuer":"https://issuer.example/tenant","jwks_uri":"https://issuer.example/keys#fragment"})"),
        lit_str(
            R"({"issuer":"https://issuer.example/tenant","jwks_uri":"https://evil.example/keys"})"),
        lit_str(
            R"({"issuer":"https://issuer.example/tenant","issuer":"https://issuer.example/tenant","jwks_uri":"https://issuer.example/keys"})"),
        lit_str(R"({"issuer":"https://issuer.example/tenant","jwks_uri":7})"),
        lit_str(R"({"issuer":"https://issuer.example/tenant"})"),
    };
    for (Str body : invalid) CHECK(!jwks_discovery_valid(document, body, configuration));
}
TEST(remote_jwks_metadata, dns_wire_allowlist_and_rebinding) {
    auto configuration = policy();
    const unsigned char query[] = {0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1};
    unsigned char reply[] = {0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0,  0, 1, 'a', 0, 0, 1, 0,
                             1,    0xc0, 0x0c, 0,    1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 1};
    const Str request{reinterpret_cast<const char*>(query), sizeof(query)};
    const auto answer = [&] { return Str{reinterpret_cast<const char*>(reply), sizeof(reply)}; };
    char address[16]{};
    CHECK(jwks_dns_answer(answer(), request, configuration, address));
    CHECK(strcmp(address, "192.0.2.1") == 0);
    reply[sizeof(reply) - 1] = 2;
    CHECK(!jwks_dns_answer(answer(), request, configuration, address));
    strcpy(configuration.allowed_addresses[1], "192.0.2.2");
    configuration.allowed_count = 2;
    CHECK(jwks_dns_answer(answer(), request, configuration, address));
    reply[0] = 0xff;
    CHECK(!jwks_dns_answer(answer(), request, configuration, address));
    reply[0] = 0x12;
    reply[2] |= 2;
    CHECK(!jwks_dns_answer(answer(), request, configuration, address));
    reply[2] &= 0xfd;
    reply[21] = 0;
    reply[22] = 5;
    CHECK(!jwks_dns_answer(answer(), request, configuration, address));
    reply[22] = 1;
    for (u32 length = 0; length < sizeof(reply); ++length)
        CHECK(!jwks_dns_answer(
            {reinterpret_cast<const char*>(reply), length}, request, configuration, address));
}
int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}

TEST(remote_jwks_metadata, rejects_invalid_configuration_issuer_uris) {
    const char* invalid[] = {"http://issuer.example",
                             "https://user@issuer.example",
                             "https://issuer.example?query",
                             "https://issuer.example/#fragment",
                             "https://issuer.example/%zz",
                             "https://issuer.example/{path}",
                             "https://issuer.example:0",
                             "https://issuer.example:65536",
                             "https://-bad.example"};
    const auto valid = [](const char* issuer) {
        char bytes[4096];
        const int size = snprintf(
            bytes,
            sizeof(bytes),
            "{\"address\":\"192.0.2.1\",\"port\":443,\"serverName\":\"issuer.example\",\"ca\":\"ca."
            "pem\",\"path\":\"/"
            "keys\",\"refreshSeconds\":1,\"maxAgeSeconds\":3,\"timeoutSeconds\":1,"
            "\"discoveryPath\":\"/.well-known/openid-configuration\",\"discoveryIssuer\":\"%s\"}",
            issuer);
        if (size <= 0 || static_cast<u32>(size) >= sizeof(bytes)) return false;
        json::Document document;
        RemoteJwks configuration;
        return document.parse({bytes, static_cast<u32>(size)}) && configuration.load(document, 0);
    };
    for (const char* issuer : invalid) CHECK(!valid(issuer));
    CHECK(valid("https://issuer.example/tenant%2Fblue"));
    CHECK(valid("https://issuer.example:443"));
}
