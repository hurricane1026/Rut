#include "rut/runtime/parse_integer.h"
#include "test.h"

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

using namespace rut;

namespace {
// Independent per-digit cutoff oracle: no length specialization or packed arithmetic.
bool reference(Str text, bool wide, i64& output) {
    if (!text.ptr || !text.len) return false;
    u32 i = 0;
    const bool negative = text.ptr[0] == '-';
    if (negative || text.ptr[0] == '+') ++i;
    if (i == text.len) return false;
    const u64 limit = (wide ? 9223372036854775807ULL : 2147483647ULL) + negative;
    u64 value = 0;
    for (; i < text.len; ++i) {
        const u32 digit = static_cast<u8>(text.ptr[i]) - static_cast<u32>('0');
        if (digit > 9 || value > (limit - digit) / 10) return false;
        value = value * 10 + digit;
    }
    output =
        negative ? -static_cast<i64>(value - (value != 0)) - (value != 0) : static_cast<i64>(value);
    return true;
}
void compare(rut::test::TestCase* _tc, Str text) {
    const bool widths[] = {false, true};
    for (bool wide : widths) {
        i64 expected = 123;
        i64 actual = 123;
        const bool valid = reference(text, wide, expected);
        CHECK_EQ(wide ? parse_integer<true>(text, actual) : parse_integer<false>(text, actual),
                 valid);
        CHECK_EQ(actual, expected);
        actual = 123;
        CHECK_EQ(wide ? parse_integer64(text, actual) : parse_integer32(text, actual), valid);
        CHECK_EQ(actual, expected);
    }
}
}  // namespace

TEST(parse_integer, strict_decimal_contract_and_signed_boundaries) {
    const Str cases[] = {lit_str(""),
                         lit_str("0"),
                         lit_str("+0"),
                         lit_str("-0"),
                         lit_str("42"),
                         lit_str("-42"),
                         lit_str("+42"),
                         lit_str("0000042"),
                         lit_str("2147483647"),
                         lit_str("2147483648"),
                         lit_str("-2147483648"),
                         lit_str("-2147483649"),
                         lit_str("9223372036854775807"),
                         lit_str("9223372036854775808"),
                         lit_str("-9223372036854775808"),
                         lit_str("-9223372036854775809"),
                         lit_str("18446744073709551615"),
                         lit_str("+"),
                         lit_str("-"),
                         lit_str("++1"),
                         lit_str("--1"),
                         lit_str("1.0"),
                         lit_str("1e2"),
                         lit_str("0x10"),
                         lit_str(" 42"),
                         lit_str("42 "),
                         lit_str("42\r\n"),
                         lit_str("4\0"),
                         lit_str("４２"),
                         lit_str("99999999"),
                         lit_str("100000000"),
                         lit_str("123456789012"),
                         lit_str("00000000000000000000000000000000000000000000000042"),
                         lit_str("-00000000000000000000000000000000000000000000000000"),
                         lit_str("0000000000000000000000000000000000000000000000000x")};
    for (const auto text : cases) compare(_tc, text);
    compare(_tc, {nullptr, 0});
    compare(_tc, {nullptr, 20});
    i64 value = 0;
    CHECK(parse_integer<false>(lit_str("-2147483648"), value));
    CHECK_EQ(value, -2147483648LL);
    CHECK_FALSE(parse_integer<false>(lit_str("2147483648"), value));
    CHECK_EQ(value, -2147483648LL);
    CHECK(parse_integer<true>(lit_str("-9223372036854775808"), value));
    CHECK_EQ(value, (-9223372036854775807LL - 1));
}

TEST(parse_integer, packed_digits_match_cutoff_oracle) {
    char text[160];
    for (u32 number = 0; number < 10000; ++number) {
        u32 n = number;
        for (u32 j = 4; j; --j) {
            text[j - 1] = static_cast<char>('0' + n % 10);
            n /= 10;
        }
        compare(_tc, {text, 4});
        for (u32 i = 0; i < 4; ++i) text[4 + i] = static_cast<char>('1' + i);
        compare(_tc, {text, 8});
    }
    const Str bases[] = {lit_str("12345678"),
                         lit_str("123456789012"),
                         lit_str("1234567890123456"),
                         lit_str("1234567890123456789")};
    for (const auto base : bases) {
        memcpy(text, base.ptr, base.len);
        for (u32 i = 0; i < base.len; ++i) {
            for (u32 byte = 0; byte < 256; ++byte) {
                text[i] = static_cast<char>(byte);
                compare(_tc, {text, base.len});
            }
            text[i] = base.ptr[i];
        }
    }
    u64 random = 0x937bf093d28e1f3bULL;
    for (u32 trial = 0; trial < 40000; ++trial) {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        const u32 length = static_cast<u32>(random % sizeof(text));
        for (u32 i = 0; i < length; ++i) {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            text[i] = static_cast<char>(trial % 3 ? '0' + random % 10 : random & 255);
        }
        if (length && trial % 4 == 0) text[0] = trial % 8 ? '+' : '-';
        compare(_tc, {text, length});
    }
}

TEST(parse_integer, spans_can_end_at_an_unreadable_page) {
    const auto page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    void* mapping =
        mmap(nullptr, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(mapping != MAP_FAILED);
    char* end = static_cast<char*>(mapping) + page;
    REQUIRE_EQ(mprotect(end, page, PROT_NONE), 0);
    for (u32 length = 0; length < 128; ++length) {
        char* data = end - length;
        memset(data, '1', length);
        compare(_tc, {data, length});
        memset(data, '0', length);
        compare(_tc, {data, length});
        if (length) {
            data[0] = '-';
            compare(_tc, {data, length});
        }
    }
    CHECK_EQ(munmap(mapping, page * 2), 0);
}

int main(int argc, char** argv) {
    rut::test::out("Integer parser architecture: ");
    rut::test::out(parse_integer_arch());
    rut::test::out("\n");
    return rut::test::run_all(argc, argv);
}
