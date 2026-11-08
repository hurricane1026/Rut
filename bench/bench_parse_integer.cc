// See docs/parse-integers.md for standalone per-ISA builds.
// CSV: corpus, implementation, best ns/call (five trials), consumed checksum.
#include "rut/runtime/parse_integer.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

struct Entry {
    char text[160];
    uint32_t len;
};
static Entry entries[4096];
static uint64_t random_state = 0x123456789abcdef;
static uint64_t rng() {
    random_state ^= random_state << 13;
    random_state ^= random_state >> 7;
    random_state ^= random_state << 17;
    return random_state;
}
template <bool Wide>
static bool finish(uint64_t n, bool negative, int64_t& result) {
    const uint64_t limit = (Wide ? 9223372036854775807ULL : 2147483647ULL) + negative;
    if (n > limit) return false;
    result = negative ? static_cast<int64_t>(uint64_t(0) - n) : static_cast<int64_t>(n);
    return true;
}
template <bool Wide>
__attribute__((noinline)) static bool scalar(const char* p, uint32_t len, int64_t& result) {
    if (!len) return false;
    bool negative = *p == '-';
    if (negative || *p == '+') {
        ++p;
        if (!--len) return false;
    }
    uint64_t n = 0;
    const uint64_t limit = (Wide ? 9223372036854775807ULL : 2147483647ULL) + negative;
    for (uint32_t i = 0; i < len; ++i) {
        uint32_t digit = static_cast<unsigned char>(p[i]) - uint32_t('0');
        if (digit > 9 || n > (limit - digit) / 10) return false;
        n = n * 10 + digit;
    }
    return finish<Wide>(n, negative, result);
}
template <bool Wide>
__attribute__((noinline)) static bool parse(const char* data, uint32_t length, int64_t& value) {
    return rut::parse_integer<Wide>({data, length}, value);
}
template <bool Wide>
__attribute__((noinline)) static bool selected(const char* data, uint32_t length, int64_t& value) {
    if constexpr (Wide) return rut::parse_integer64({data, length}, value);
    return rut::parse_integer32({data, length}, value);
}
static double now() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<double>(ts.tv_sec) + static_cast<double>(ts.tv_nsec) * 1e-9;
}
int main() {
    using Fn = bool (*)(const char*, uint32_t, int64_t&);
    const bool widths[] = {false, true};
    for (bool wide : widths) {
        random_state = 0x123456789abcdef;
        Fn functions[] = {wide ? scalar<true> : scalar<false>,
                          wide ? parse<true> : parse<false>,
                          wide ? selected<true> : selected<false>};
        const char* names[] = {"scalar_cutoff", "portable_swar", rut::parse_integer_arch()};
        const char* sets[] = {
            "short_1_3", "i32_8_10", "i64_16_19", "mixed_1_19", "malformed", "leading_zeros"};
        for (unsigned set = 0; set < 6; ++set) {
            for (auto& e : entries) {
                uint64_t value = rng() >> 1;
                if (set == 0) value %= 1000;
                if (set == 1) value = 10000000 + value % 2137483648ULL;
                if (set == 2) value = 1000000000000000ULL + value % 9222372036854775808ULL;
                if (set == 3) {
                    unsigned digits = 1 + rng() % 19;
                    uint64_t scale = 1;
                    for (unsigned i = 0; i < digits; ++i) scale *= 10;
                    value %= scale;
                }
                bool neg = (rng() % 4) == 0;
                int count = snprintf(
                    e.text, sizeof(e.text), "%s%llu", neg ? "-" : "", (unsigned long long)value);
                e.len = uint32_t(count);
                if (set == 4) {
                    const char* bad[] = {"",
                                         "+",
                                         "-",
                                         " 123",
                                         "123 ",
                                         "12x34",
                                         "123\r\n",
                                         "9223372036854775808",
                                         "-9223372036854775809",
                                         "1.0",
                                         "--1",
                                         "+-1",
                                         "123e4"};
                    const char* text = bad[rng() % (sizeof(bad) / sizeof(bad[0]))];
                    e.len = uint32_t(strlen(text));
                    memcpy(e.text, text, e.len);
                }
                if (set == 5) {
                    e.len = 8 + rng() % 120;
                    memset(e.text, '0', e.len);
                    e.text[e.len - 1] = static_cast<char>('1' + rng() % 9);
                }
            }
            for (auto& e : entries) {
                int64_t expected = 0;
                bool ok = functions[0](e.text, e.len, expected);
                for (auto f : functions) {
                    int64_t actual = 0;
                    bool got = f(e.text, e.len, actual);
                    if (got != ok || (got && actual != expected)) {
                        fprintf(stderr, "mismatch set=%u text=%.*s\n", set, e.len, e.text);
                        return 1;
                    }
                }
            }
            for (unsigned which = 0; which < 3; ++which) {
                double best = 1e10;
                uint64_t checksum = 0;
                for (unsigned trial = 0; trial < 5; ++trial) {
                    double start = now();
                    for (unsigned repeat = 0; repeat < 512; ++repeat)
                        for (auto& e : entries) {
                            int64_t value = 0;
                            bool ok = functions[which](e.text, e.len, value);
                            checksum += ok ? uint64_t(value) : 13;
                        }
                    double elapsed = now() - start;
                    if (elapsed < best) best = elapsed;
                }
                printf("%u,%s,%s,%.3f,%llu\n",
                       wide ? 64u : 32u,
                       sets[set],
                       names[which],
                       best * 1e9 / (512 * 4096),
                       (unsigned long long)checksum);
            }
        }
    }
}
