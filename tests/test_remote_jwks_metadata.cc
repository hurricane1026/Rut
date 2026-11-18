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
    JwksDnsAddresses addresses;
    CHECK(jwks_dns_answer(answer(), request, configuration, addresses));
    CHECK_EQ(addresses.count, 1u);
    CHECK(strcmp(addresses.values[0], "192.0.2.1") == 0);
    reply[sizeof(reply) - 1] = 2;
    CHECK(!jwks_dns_answer(answer(), request, configuration, addresses));
    strcpy(configuration.allowed_addresses[1], "192.0.2.2");
    configuration.allowed_count = 2;
    CHECK(jwks_dns_answer(answer(), request, configuration, addresses));
    reply[0] = 0xff;
    CHECK(!jwks_dns_answer(answer(), request, configuration, addresses));
    reply[0] = 0x12;
    reply[2] |= 2;
    CHECK(!jwks_dns_answer(answer(), request, configuration, addresses));
    reply[2] &= 0xfd;
    reply[3] |= 64;
    CHECK(!jwks_dns_answer(answer(), request, configuration, addresses));
    reply[3] &= 191;
    reply[21] = 0;
    reply[22] = 5;
    CHECK(!jwks_dns_answer(answer(), request, configuration, addresses));
    reply[22] = 1;
    for (u32 length = 0; length < sizeof(reply); ++length)
        CHECK(!jwks_dns_answer(
            {reinterpret_cast<const char*>(reply), length}, request, configuration, addresses));
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

TEST(remote_jwks_metadata, dns_configuration_pairs_bounds_and_failure_reset) {
    const char* base =
        "\"address\":\"192.0.2.1\",\"port\":443,\"serverName\":\"issuer.example\",\"ca\":\"ca."
        "pem\",\"path\":\"/keys\",\"refreshSeconds\":1,\"maxAgeSeconds\":3,\"timeoutSeconds\":1";
    const char* invalid[] = {
        ",\"dnsAddress\":\"192.0.2.53\"",
        ",\"allowedAddresses\":[\"192.0.2.1\"]",
        ",\"dnsPort\":53",
        ",\"dnsAddress\":\"invalid\",\"allowedAddresses\":[\"192.0.2.1\"]",
        ",\"dnsAddress\":\"192.0.2.53\",\"allowedAddresses\":[]",
        ",\"dnsAddress\":\"192.0.2.53\",\"allowedAddresses\":{}}",
        ",\"dnsAddress\":\"192.0.2.53\",\"allowedAddresses\":[7]",
        ",\"dnsAddress\":\"192.0.2.53\",\"allowedAddresses\":[\"invalid\"]",
        ",\"dnsAddress\":\"192.0.2.53\",\"allowedAddresses\":[\"192.0.2.1\\u0000\"]",
        ",\"dnsAddress\":\"192.0.2.53\",\"allowedAddresses\":[\"192.0.2.1\",\"192.0.2.2\",\"192.0."
        "2.3\",\"192.0.2.4\",\"192.0.2.5\",\"192.0.2.6\",\"192.0.2.7\",\"192.0.2.8\",\"192.0.2."
        "9\"]",
        ",\"discoveryPath\":\"/discovery\"",
        ",\"discoveryIssuer\":\"https://issuer.example\"",
        ",\"discoveryPath\":\"unsafe\",\"discoveryIssuer\":\"https://issuer.example\"",
        ",\"unknown\":1",
        ",\"unknown\":true",
        ",\"dnsPort\":65536",
        ",\"timeoutSeconds\":61",
        ",\"refreshSeconds\":3601",
        ",\"maxAgeSeconds\":86401"};
    json::Document document;
    RemoteJwks configuration = policy();
    char bytes[4096];
    for (const char* extra : invalid) {
        const int length = snprintf(bytes, sizeof(bytes), "{%s%s}", base, extra);
        const bool parsed = document.parse({bytes, static_cast<u32>(length)});
        CHECK(!parsed || !configuration.load(document, 0));
        if (parsed) CHECK_EQ(configuration.allowed_count, 0u);
    }
    const int length = snprintf(
        bytes,
        sizeof(bytes),
        "{%s,\"dnsAddress\":\"192.0.2.53\",\"dnsPort\":5353,\"allowedAddresses\":[\"192.0.2.1\"]}",
        base);
    REQUIRE(document.parse({bytes, static_cast<u32>(length)}));
    REQUIRE(configuration.load(document, 0));
    CHECK_EQ(configuration.dns_port, 5353u);
    CHECK_EQ(configuration.allowed_count, 1u);
    CHECK(!configuration.load(document, document.count));
    CHECK_EQ(configuration.allowed_count, 0u);
}

namespace {
struct DnsPacket {
    u8 bytes[1024]{};
    u32 length = 12;
    u32 question_length = 0;
    u16 answers = 0;
    explicit DnsPacket(const char* host = "a.example") {
        bytes[0] = 0x12;
        bytes[1] = 0x34;
        bytes[2] = 0x81;
        bytes[3] = 0x80;
        bytes[5] = 1;
        name(host);
        word(1);
        word(1);
        question_length = length;
    }
    void word(u16 value) {
        bytes[length++] = static_cast<u8>(value >> 8);
        bytes[length++] = static_cast<u8>(value);
    }
    void name(const char* host) {
        for (const char* start = host; *start;) {
            const char* end = strchr(start, '.');
            if (!end) end = start + strlen(start);
            bytes[length++] = static_cast<u8>(end - start);
            while (start != end) bytes[length++] = static_cast<u8>(*start++);
            if (*start == '.') ++start;
        }
        bytes[length++] = 0;
    }
    void pointer(u32 target) { word(static_cast<u16>(0xc000 | target)); }
    u32 record(const char* owner, u16 type, u32 ttl = 30) {
        if (owner)
            name(owner);
        else
            pointer(12);
        word(type);
        word(1);
        word(static_cast<u16>(ttl >> 16));
        word(static_cast<u16>(ttl));
        const u32 size = length;
        word(0);
        ++answers;
        bytes[6] = static_cast<u8>(answers >> 8);
        bytes[7] = static_cast<u8>(answers);
        return size;
    }
    void size(u32 at) {
        const u32 value = length - at - 2;
        bytes[at] = static_cast<u8>(value >> 8);
        bytes[at + 1] = static_cast<u8>(value);
    }
    u32 cname(const char* owner, const char* target, u32 ttl = 30) {
        const u32 at = record(owner, 5, ttl), target_at = length;
        name(target);
        size(at);
        return target_at;
    }
    void a(const char* owner, u8 last = 1, u32 ttl = 30) {
        const u32 at = record(owner, 1, ttl);
        bytes[length++] = 192;
        bytes[length++] = 0;
        bytes[length++] = 2;
        bytes[length++] = last;
        size(at);
    }
    Str view() const { return {reinterpret_cast<const char*>(bytes), length}; }
    Str query(u8 (&storage)[272]) const {
        memcpy(storage, bytes, question_length);
        storage[2] = 1;
        storage[3] = 0;
        storage[6] = storage[7] = 0;
        return {reinterpret_cast<const char*>(storage), question_length};
    }
};
bool accepts(const DnsPacket& packet, RemoteJwks& configuration, JwksDnsAddresses& addresses) {
    u8 query[272]{};
    return jwks_dns_answer(packet.view(), packet.query(query), configuration, addresses);
}
void rejected(rut::test::TestCase* _tc, const DnsPacket& packet, RemoteJwks& configuration) {
    JwksDnsAddresses addresses{{"unchanged"}, 1};
    CHECK(!accepts(packet, configuration, addresses));
    CHECK_EQ(addresses.count, 1u);
    CHECK(strcmp(addresses.values[0], "unchanged") == 0);
}
}  // namespace

TEST(remote_jwks_metadata, cname_chain_literal_compressed_reordered_and_limits) {
    auto configuration = policy();
    strcpy(configuration.allowed_addresses[1], "192.0.2.2");
    configuration.allowed_count = 2;
    JwksDnsAddresses addresses;
    DnsPacket literal;
    literal.cname(nullptr, "keys.example");
    literal.a("keys.example");
    CHECK(accepts(literal, configuration, addresses));
    CHECK(strcmp(addresses.values[0], "192.0.2.1") == 0);

    DnsPacket compressed;
    const u32 target = compressed.cname(nullptr, "keys.example");
    compressed.pointer(target);
    const u32 header = compressed.length;
    compressed.word(1);
    compressed.word(1);
    compressed.word(0);
    compressed.word(30);
    compressed.word(4);
    compressed.bytes[compressed.length++] = 192;
    compressed.bytes[compressed.length++] = 0;
    compressed.bytes[compressed.length++] = 2;
    compressed.bytes[compressed.length++] = 2;
    compressed.bytes[7] = 2;
    CHECK(header > target);
    CHECK(accepts(compressed, configuration, addresses));
    CHECK(strcmp(addresses.values[0], "192.0.2.2") == 0);

    // CNAME RDATA may combine a new label with an already decoded suffix.
    DnsPacket suffix;
    const u32 suffix_size = suffix.record(nullptr, 5);
    suffix.bytes[suffix.length++] = 4;
    for (char value : "keys")
        if (value) suffix.bytes[suffix.length++] = static_cast<u8>(value);
    suffix.pointer(14);  // The question's example label.
    suffix.size(suffix_size);
    suffix.a("keys.example");
    CHECK(accepts(suffix, configuration, addresses));

    DnsPacket reordered("A.Example");
    reordered.a("KEYS.example", 2);
    reordered.cname("a.EXAMPLE", "keys.EXAMPLE");
    reordered.a("keys.example");
    reordered.a("keys.example", 2);
    CHECK(accepts(reordered, configuration, addresses));
    CHECK_EQ(addresses.count, 2u);
    CHECK(strcmp(addresses.values[0], "192.0.2.2") == 0);
    CHECK(strcmp(addresses.values[1], "192.0.2.1") == 0);

    DnsPacket four;
    four.cname(nullptr, "b.example");
    four.cname("b.example", "c.example");
    four.cname("c.example", "d.example");
    four.cname("d.example", "e.example");
    for (u32 i = 0; i < 4; ++i) four.a("e.example", static_cast<u8>(1 + i % 2));
    CHECK(accepts(four, configuration, addresses));
    four.a("e.example");
    rejected(_tc, four, configuration);
}

TEST(remote_jwks_metadata, cname_graph_and_address_poisoning_fail_closed) {
    auto configuration = policy();
    DnsPacket absent;
    absent.cname(nullptr, "keys.example");
    rejected(_tc, absent, configuration);
    DnsPacket cycle;
    cycle.cname(nullptr, "b.example");
    cycle.cname("b.example", "a.example");
    rejected(_tc, cycle, configuration);
    DnsPacket self;
    self.cname(nullptr, "a.example");
    rejected(_tc, self, configuration);
    DnsPacket fork;
    fork.cname(nullptr, "keys.example");
    fork.cname(nullptr, "other.example");
    fork.a("keys.example");
    rejected(_tc, fork, configuration);
    DnsPacket duplicate;
    duplicate.cname(nullptr, "keys.example");
    duplicate.cname(nullptr, "keys.example");
    duplicate.a("keys.example");
    rejected(_tc, duplicate, configuration);
    DnsPacket mixed;
    mixed.cname(nullptr, "keys.example");
    mixed.a(nullptr);
    mixed.a("keys.example");
    rejected(_tc, mixed, configuration);
    DnsPacket unrelated;
    unrelated.cname(nullptr, "keys.example");
    unrelated.a("keys.example");
    unrelated.a("other.example");
    rejected(_tc, unrelated, configuration);
    DnsPacket poison;
    poison.cname(nullptr, "keys.example");
    poison.a("keys.example");
    poison.a("keys.example", 2);
    rejected(_tc, poison, configuration);
    DnsPacket five;
    five.cname(nullptr, "b.example");
    five.cname("b.example", "c.example");
    five.cname("c.example", "d.example");
    five.cname("d.example", "e.example");
    five.cname("e.example", "f.example");
    five.a("f.example");
    rejected(_tc, five, configuration);
    const u32 invalid_ttls[] = {0u, 0x80000000u};
    for (u32 ttl : invalid_ttls) {
        DnsPacket alias_ttl;
        alias_ttl.cname(nullptr, "keys.example", ttl);
        alias_ttl.a("keys.example");
        rejected(_tc, alias_ttl, configuration);
        DnsPacket address_ttl;
        address_ttl.cname(nullptr, "keys.example");
        address_ttl.a("keys.example", 1, ttl);
        rejected(_tc, address_ttl, configuration);
    }
    DnsPacket aaaa;
    const u32 at = aaaa.record(nullptr, 28);
    for (u32 i = 0; i < 16; ++i) aaaa.bytes[aaaa.length++] = 0;
    aaaa.size(at);
    rejected(_tc, aaaa, configuration);
    DnsPacket glue;
    glue.a(nullptr);
    glue.bytes[11] = 1;
    rejected(_tc, glue, configuration);
}

TEST(remote_jwks_metadata, cname_compression_rdata_and_truncation_are_strict) {
    auto configuration = policy();
    DnsPacket valid;
    valid.cname(nullptr, "keys.example");
    valid.a("keys.example");
    for (u32 length = 0; length < valid.length; ++length) {
        DnsPacket cut = valid;
        cut.length = length;
        rejected(_tc, cut, configuration);
    }
    DnsPacket trailing = valid;
    trailing.bytes[trailing.length++] = 0;
    rejected(_tc, trailing, configuration);
    DnsPacket oversized = valid;
    oversized.length = 513;
    rejected(_tc, oversized, configuration);
    DnsPacket malformed;
    const u32 at = malformed.record(nullptr, 5);
    malformed.bytes[malformed.length++] = 0xc0;
    malformed.size(at);
    rejected(_tc, malformed, configuration);
    const u32 invalid_targets[] = {0u, 13u, 511u};
    for (u32 target : invalid_targets) {
        DnsPacket bad;
        const u32 size = bad.record(nullptr, 5);
        bad.pointer(target);
        bad.size(size);
        rejected(_tc, bad, configuration);
    }
    // Offset 13 is inside a valid label, but would itself decode as 48 a's
    // under a decoder that accepts arbitrary backwards offsets.
    char host[50]{};
    host[0] = '0';
    memset(host + 1, 'a', 48);
    DnsPacket middle(host);
    const u32 middle_size = middle.record(nullptr, 5);
    middle.pointer(13);
    middle.size(middle_size);
    rejected(_tc, middle, configuration);
    DnsPacket self;
    const u32 self_size = self.record(nullptr, 5);
    self.pointer(self.length);
    self.size(self_size);
    rejected(_tc, self, configuration);
    DnsPacket extra;
    const u32 size = extra.record(nullptr, 5);
    extra.name("keys.example");
    extra.bytes[extra.length++] = 0;
    extra.size(size);
    extra.a("keys.example");
    rejected(_tc, extra, configuration);
    DnsPacket wrong;
    wrong.cname(nullptr, "keys.example");
    wrong.a("keys.example");
    wrong.bytes[2] |= 2;
    rejected(_tc, wrong, configuration);
}

TEST(remote_jwks_metadata, cname_hostname_bounds) {
    auto configuration = policy();
    JwksDnsAddresses addresses;
    char host[255]{};
    memset(host, 'a', 63);
    DnsPacket label63(host);
    label63.a(nullptr);
    CHECK(accepts(label63, configuration, addresses));
    host[63] = 'a';
    DnsPacket label64(host);
    label64.a(nullptr);
    rejected(_tc, label64, configuration);
    memset(host, 'a', 253);
    host[63] = host[127] = host[191] = '.';
    DnsPacket expanded253(host);
    expanded253.a(nullptr);
    CHECK(accepts(expanded253, configuration, addresses));
    host[253] = 'a';
    DnsPacket expanded254(host);
    expanded254.a(nullptr);
    rejected(_tc, expanded254, configuration);
    const char* invalid[] = {"-a.example", "a-.example", ""};
    for (const char* name : invalid) {
        DnsPacket bad(name);
        bad.a(nullptr);
        rejected(_tc, bad, configuration);
    }
}

TEST(remote_jwks_metadata, retry_configuration_defaults_order_bounds_and_reset) {
    const char* base =
        "\"address\":\"192.0.2.1\",\"port\":443,\"serverName\":\"issuer.example\","
        "\"ca\":\"ca.pem\",\"path\":\"/keys\",\"refreshSeconds\":7,"
        "\"maxAgeSeconds\":9,\"timeoutSeconds\":1";
    char bytes[1024];
    json::Document document;
    RemoteJwks configuration;
    int length = snprintf(bytes, sizeof(bytes), "{%s}", base);
    CHECK(document.parse({bytes, static_cast<u32>(length)}));
    CHECK(configuration.load(document, 0));
    CHECK_EQ(configuration.retry_seconds, 7u);
    const u32 valid[] = {1, 3600, 8};
    for (u32 value : valid) {
        length = snprintf(bytes, sizeof(bytes), "{\"retrySeconds\":%u,%s}", value, base);
        CHECK(document.parse({bytes, static_cast<u32>(length)}));
        CHECK(configuration.load(document, 0));
        CHECK_EQ(configuration.refresh_seconds, 7u);
        CHECK_EQ(configuration.retry_seconds, value);
        length = snprintf(bytes, sizeof(bytes), "{%s,\"retrySeconds\":%u}", base, value);
        CHECK(document.parse({bytes, static_cast<u32>(length)}));
        CHECK(configuration.load(document, 0));
        CHECK_EQ(configuration.retry_seconds, value);
    }
    CHECK_EQ(configuration.retry_seconds, 8u);
    length = snprintf(bytes, sizeof(bytes), "{%s,\"retrySeconds\":2,\"retrySeconds\":3}", base);
    CHECK(!document.parse({bytes, static_cast<u32>(length)}));
    const char* invalid[] = {
        "0", "-1", "3601", "1.5", "true", "null", "\"2\"", "[]", "{}", "18446744073709551615"};
    for (const char* value : invalid) {
        configuration.retry_seconds = 42;
        length = snprintf(bytes, sizeof(bytes), "{%s,\"retrySeconds\":%s}", base, value);
        CHECK(document.parse({bytes, static_cast<u32>(length)}));
        CHECK(!configuration.load(document, 0));
        CHECK_EQ(configuration.retry_seconds, 0u);
        CHECK(!configuration.enabled());
    }
}

TEST(remote_jwks_metadata, completion_deadline_intervals_and_overflow) {
    // A slow attempt completes after its previous refresh interval. Its retry
    // still waits a full configured interval from this later completion time.
    CHECK_EQ(jwks_refresh_deadline(12500, 2), 14500u);
    CHECK_EQ(jwks_refresh_deadline(12500, 7), 19500u);
    CHECK_EQ(jwks_refresh_deadline(1, 3600), 3600001u);
    CHECK_EQ(jwks_refresh_deadline(~u64{0} - 1000, 1), ~u64{0});
    CHECK_EQ(jwks_refresh_deadline(~u64{0} - 999, 1), ~u64{0});
    CHECK_EQ(jwks_refresh_deadline(~u64{0}, 3600), ~u64{0});
}

TEST(remote_jwks_metadata, conditional_requests_boolean_and_reset) {
    const char* base =
        "\"address\":\"192.0.2.1\",\"port\":443,\"serverName\":\"issuer.example\","
        "\"ca\":\"ca.pem\",\"path\":\"/keys\",\"refreshSeconds\":1,"
        "\"maxAgeSeconds\":3,\"timeoutSeconds\":1";
    char bytes[1024];
    json::Document document;
    RemoteJwks configuration;
    int length = snprintf(bytes, sizeof(bytes), "{%s}", base);
    CHECK(document.parse({bytes, static_cast<u32>(length)}));
    CHECK(configuration.load(document, 0));
    CHECK(!configuration.conditional_requests);
    const char* valid[] = {"true", "false"};
    for (const char* value : valid) {
        length = snprintf(bytes, sizeof(bytes), "{%s,\"conditionalRequests\":%s}", base, value);
        CHECK(document.parse({bytes, static_cast<u32>(length)}));
        CHECK(configuration.load(document, 0));
        CHECK_EQ(configuration.conditional_requests, strcmp(value, "true") == 0);
    }
    const char* invalid[] = {"0", "1", "\"true\"", "null", "[]", "{}"};
    for (const char* value : invalid) {
        configuration.conditional_requests = true;
        length = snprintf(bytes, sizeof(bytes), "{%s,\"conditionalRequests\":%s}", base, value);
        CHECK(document.parse({bytes, static_cast<u32>(length)}));
        CHECK(!configuration.load(document, 0));
        CHECK(!configuration.conditional_requests);
    }
    length = snprintf(bytes,
                      sizeof(bytes),
                      "{%s,\"conditionalRequests\":true,\"conditionalRequests\":false}",
                      base);
    CHECK(!document.parse({bytes, static_cast<u32>(length)}));
}

TEST(remote_jwks_metadata, owned_strong_etag_address_binding_and_hard_expiry) {
    CHECK(strong_etag_valid(lit_str("\"\"")));
    CHECK(strong_etag_valid(lit_str("\"opaque,tag\\value\"")));
    const Str invalid[] = {lit_str("W/\"weak\""),
                           lit_str("w/\"weak\""),
                           lit_str("unquoted"),
                           lit_str("\"bad tag\""),
                           lit_str("\"bad\ttag\""),
                           lit_str("\"bad\"tag\""),
                           lit_str("\"a\",\"b\""),
                           lit_str("\"bad\r\ntag\""),
                           lit_str("\"\xff\"")};
    for (Str value : invalid) CHECK(!strong_etag_valid(value));
    char limit[129]{};
    memset(limit, 'a', sizeof(limit));
    limit[0] = limit[127] = '"';
    CHECK(strong_etag_valid({limit, 128}));
    limit[127] = 'a';
    limit[128] = '"';
    CHECK(!strong_etag_valid({limit, 129}));
    JwksValidator validator;
    CHECK(!validator.matching(lit_str("192.0.2.1")).len);
    char tag[] = "\"owned\"";
    char address[] = "192.0.2.1";
    CHECK(validator.bind({tag, 7}, {address, 9}));
    tag[1] = 'x';
    address[8] = '2';
    CHECK(validator.matching(lit_str("192.0.2.1")).eq(lit_str("\"owned\"")));
    CHECK(!validator.matching(lit_str("192.0.2.2")).len);
    JwksValidator attempt = validator;
    validator.clear();
    CHECK(!validator.matching(lit_str("192.0.2.1")).len);
    CHECK(attempt.matching(lit_str("192.0.2.1")).eq(lit_str("\"owned\"")));
    CHECK(!attempt.bind(lit_str("W/\"bad\""), lit_str("192.0.2.1")));
    CHECK(!attempt.tag[0]);
    CHECK(!attempt.bind(lit_str("\"good\""), lit_str("invalid")));
    CHECK(!attempt.tag[0] && !attempt.address[0]);
    CHECK(jwks_cache_fresh(3999, 1000, 3));
    CHECK(!jwks_cache_fresh(4000, 1000, 3));
    CHECK(!jwks_cache_fresh(999, 1000, 3));
    CHECK(!jwks_cache_fresh(0, 1000, 3));
    CHECK(!jwks_cache_fresh(1000, 0, 3));
    CHECK(jwks_cache_fresh(~u64{0} - 1, ~u64{0} - 2, 3));
}

TEST(remote_jwks_metadata, conditional_response_etag_is_unique_and_strong) {
    const char* invalid[] = {"ETag: W/\"weak\"\r\n",
                             "ETag: \"bad tag\"\r\n",
                             "ETag: unquoted\r\n",
                             "ETag: \"a\"\r\netag: \"a\"\r\n"};
    for (const char* extra : invalid) {
        char bytes[512];
        const int length = snprintf(bytes,
                                    sizeof(bytes),
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                    "Content-Length: 2\r\n%s\r\n{}",
                                    extra);
        BoundedJsonResponse response;
        response.reset_conditional_jwks();
        CHECK(response.append({bytes, static_cast<u32>(length)}) ==
              BoundedJsonResponse::Result::Complete);
        ParsedResponse headers{};
        CHECK(response.headers(headers));
        Str tag{};
        CHECK(!jwks_response_etag(headers, tag));
    }
    BoundedJsonResponse response;
    response.reset_conditional_jwks();
    CHECK(response.append(lit_str("HTTP/1.1 304 Not Modified\r\neTaG: \"v1\"\r\n\r\n")) ==
          BoundedJsonResponse::Result::Complete);
    ParsedResponse headers{};
    CHECK(response.headers(headers));
    Str tag{};
    CHECK(jwks_response_etag(headers, tag));
    CHECK(tag.eq(lit_str("\"v1\"")));
    response.reset_conditional_jwks();
    CHECK(response.append(lit_str("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                  "Content-Length: 2\r\n\r\n{}")) ==
          BoundedJsonResponse::Result::Complete);
    CHECK(response.headers(headers));
    CHECK(jwks_response_etag(headers, tag));
    CHECK(!tag.len);
}
