#include "rut/common/types.h"
#include "rut/runtime/parse_ip.h"
#include "test.h"

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

using namespace rut;

TEST(parse_ip, canonical_ipv4_preserves_network_bytes) {
    for (u32 part = 0; part < 4; ++part) {
        for (u32 value = 0; value < 256; ++value) {
            u8 octets[] = {1, 2, 3, 4};
            octets[part] = static_cast<u8>(value);
            char text[16];
            const auto kLength = snprintf(
                text, sizeof(text), "%u.%u.%u.%u", octets[0], octets[1], octets[2], octets[3]);
            u32 address = 123;
            REQUIRE(parse_ipv4_address({text, static_cast<u32>(kLength)}, address));
            CHECK_EQ(memcmp(&address, octets, sizeof(address)), 0);
        }
    }
    u32 address = 123;
    REQUIRE(parse_ipv4_address(lit_str("0.0.0.0"), address));
    CHECK_EQ(address, 0u);
    REQUIRE(parse_ipv4_address(lit_str("255.255.255.255"), address));
    CHECK_EQ(address, 0xffffffffu);
}

TEST(parse_ip, invalid_text_never_modifies_output) {
    const Str kBad[] = {
        lit_str(""),
        lit_str("127.1"),
        lit_str("127.0.1"),
        lit_str("127.0.0.1."),
        lit_str(".127.0.0.1"),
        lit_str("1..2.3"),
        lit_str("256.1.2.3"),
        lit_str("1.2.3.256"),
        lit_str("01.2.3.4"),
        lit_str("1.02.3.4"),
        lit_str("1.2.003.4"),
        lit_str("1.2.3.00"),
        lit_str("0000.0.0.0"),
        lit_str("+1.2.3.4"),
        lit_str("-1.2.3.4"),
        lit_str(" 1.2.3.4"),
        lit_str("1.2.3.4 "),
        lit_str("1.2.3.4\n"),
        lit_str("1.2.3.4\0"),
        lit_str("1.2\0.3.4"),
        lit_str("１.2.3.4"),
        lit_str("localhost"),
        lit_str("0x7f.0.0.1"),
        lit_str("2130706433"),
        lit_str("1.2.3.4:80"),
        lit_str("1.2.3.4/24"),
        lit_str("::1"),
        lit_str("::ffff:1.2.3.4"),
        lit_str("[::1]"),
        lit_str("fe80::1%lo"),
        {nullptr, 0},
        {nullptr, 7},
        {reinterpret_cast<const char*>(1), 16},
    };
    for (auto text : kBad) {
        u32 address = 0x12345678;
        CHECK_FALSE(parse_ipv4_address(text, address));
        CHECK_EQ(address, 0x12345678u);
    }
}

TEST(parse_ip, bounded_unterminated_spans_end_at_a_guard_page) {
    const auto kPage = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto* memory = static_cast<char*>(
        mmap(nullptr, kPage * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    REQUIRE(memory != MAP_FAILED);
    REQUIRE_EQ(mprotect(memory + kPage, kPage, PROT_NONE), 0);
    const Str kCases[] = {
        lit_str("1.2.3.4"), lit_str("255.255.255.255"), lit_str("01.2.3.4"), lit_str("1.2.3.4x")};
    for (const auto kText : kCases) {
        char* end = memory + kPage - kText.len;
        memcpy(end, kText.ptr, kText.len);
        u32 address = 123;
        const bool kValid = kText.eq(lit_str("1.2.3.4")) || kText.eq(lit_str("255.255.255.255"));
        CHECK_EQ(parse_ipv4_address({end, kText.len}, address), kValid);
    }
    REQUIRE_EQ(munmap(memory, kPage * 2), 0);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
