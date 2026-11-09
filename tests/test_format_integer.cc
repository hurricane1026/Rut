#include "rut/runtime/format_integer.h"
#include "test.h"

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

using namespace rut;
namespace {
void compare(rut::test::TestCase* _tc, i64 value) {
    char scratch[20];
    memset(scratch, 0x5a, sizeof(scratch));
    char expected[32];
    const int kLength = snprintf(expected, sizeof(expected), "%lld", static_cast<long long>(value));
    const Str kActual = format_integer(value, scratch);
    CHECK(kLength > 0);
    CHECK_EQ(kActual.len, static_cast<u32>(kLength));
    CHECK(kActual.ptr >= scratch && kActual.ptr + kActual.len == scratch + sizeof(scratch));
    CHECK_EQ(memcmp(kActual.ptr, expected, kActual.len), 0);
    for (const char* p = scratch; p < kActual.ptr; ++p) CHECK_EQ(*p, 0x5a);
}
}  // namespace

TEST(format_integer, canonical_decimal_and_signed_limits) {
    const i64 kValues[] = {0,
                           1,
                           -1,
                           9,
                           -9,
                           10,
                           -10,
                           99,
                           -99,
                           100,
                           -100,
                           2147483647LL,
                           -2147483648LL,
                           9223372036854775807LL,
                           -9223372036854775807LL - 1};
    for (i64 value : kValues) compare(_tc, value);
    const i64 kOffsets[] = {-1, 0, 1};
    for (i64 power = 10; power <= 1000000000000000000LL; power *= 10) {
        for (i64 offset : kOffsets) {
            compare(_tc, power + offset);
            compare(_tc, -power + offset);
        }
        if (power == 1000000000000000000LL) break;
    }
    u64 state = 1048;
    for (u32 i = 0; i < 100000; ++i) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        i64 value;
        memcpy(&value, &state, sizeof(value));
        compare(_tc, value);
    }
}

TEST(format_integer, scratch_can_end_at_an_unreadable_page) {
    const auto kPage = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto* memory = static_cast<char*>(
        mmap(nullptr, kPage * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    REQUIRE(memory != MAP_FAILED);
    REQUIRE_EQ(mprotect(memory + kPage, kPage, PROT_NONE), 0);
    auto& scratch = *reinterpret_cast<char (*)[20]>(memory + kPage - 20);
    const i64 kValues[] = {0, 123, -123, 9223372036854775807LL, -9223372036854775807LL - 1};
    for (i64 value : kValues) {
        memset(memory, 0x5a, kPage);
        const Str kActual = format_integer(value, scratch);
        char expected[32];
        const int kLength =
            snprintf(expected, sizeof(expected), "%lld", static_cast<long long>(value));
        CHECK_EQ(kActual.len, static_cast<u32>(kLength));
        CHECK_EQ(memcmp(kActual.ptr, expected, kActual.len), 0);
        CHECK_EQ(memory[kPage - 21], 0x5a);
    }
    CHECK_EQ(munmap(memory, kPage * 2), 0);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
