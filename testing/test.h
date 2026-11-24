#pragma once

// Lightweight test framework — zero stdlib dependency.
//
// Usage:
//   #include "rut/test.h"
//
//   TEST(suite, name) {
//       CHECK(1 + 1 == 2);
//       CHECK_EQ(foo(), 42);
//       REQUIRE(ptr != nullptr);  // stops test on failure
//   }
//
//   struct MyFixture {
//       int value = 1;
//       void SetUp() {}
//       void TearDown() {}
//   };
//
//   TEST_F(MyFixture, uses_state) {
//       CHECK_EQ(self.value, 1);
//   }
//
//   int main(int argc, char** argv) { return rut::test::run_all(argc, argv); }
//
// Filtering:
//   ./test_foo                       # run all
//   ./test_foo timer                 # run tests where suite or name contains "timer"
//   ./test_foo timer.refresh         # run suite "timer", test "refresh"
//   ./test_foo -l                    # list all tests without running
//   ./test_foo --filter=timer,math.addition # allow-list filter
//   ./test_foo --shard-index=0 --shard-count=2
//   ./test_foo --help                # show usage

#include <limits.h>
#include <stdint.h>
#include <unistd.h>  // write

namespace rut::test {

// --- Output ---

inline void out(const char* s) {
    const char* end = s;
    while (*end) ++end;
    (void)::write(1, s, static_cast<size_t>(end - s));
}

inline void out_int(int v) {
    if (v == 0) {
        (void)::write(1, "0", 1);
        return;
    }
    unsigned uv;
    if (v < 0) {
        (void)::write(1, "-", 1);
        uv = 0u - static_cast<unsigned>(v);
    } else {
        uv = static_cast<unsigned>(v);
    }
    char buf[16];
    const char* end = buf + sizeof(buf);
    char* digit = buf + sizeof(buf);
    while (uv > 0) {
        *--digit = static_cast<char>('0' + uv % 10);
        uv /= 10;
    }
    while (digit != end) (void)::write(1, digit++, 1);
}

inline bool str_starts_with(const char* s, const char* prefix) {
    while (*prefix) {
        if (*s == '\0' || *s != *prefix) return false;
        s++;
        prefix++;
    }
    return true;
}

// --- String helpers (no stdlib) ---

inline bool str_eq(const char* a, const char* b) {
    for (;; a++, b++) {
        if (*a != *b) return false;
        if (*a == '\0') return true;
    }
}

inline bool str_eq_safe(const char* a, const char* b) {
    if (a == b) return true;
    if (!a || !b) return false;
    return str_eq(a, b);
}

inline bool str_contains(const char* haystack, const char* needle) {
    if (!needle[0]) return true;
    for (const char* start = haystack; *start; ++start) {
        const char* candidate = start;
        const char* pattern = needle;
        while (*pattern && *candidate == *pattern) {
            ++candidate;
            ++pattern;
        }
        if (!*pattern) return true;
    }
    return false;
}

// --- Test registry ---

struct TestCase {
    const char* suite;
    const char* name;
    void (*fn)(TestCase*);
    TestCase* next;
    int checks_passed;
    int checks_failed;
    const char* fail_file;
    int fail_line;
    const char* fail_expr;
    bool skipped;
    const char* skip_reason;
    char external_failure[192]{};
};

inline TestCase* g_head = nullptr;
inline TestCase** g_tail = &g_head;
inline thread_local TestCase* g_current_test_case = nullptr;

inline void add_check_count(int& count, int addend) {
    if (__builtin_add_overflow(count, addend, &count)) {
        out("test check count exceeds INT_MAX\n");
        _exit(1);
    }
}

inline void increment_check_count(int& count) {
    add_check_count(count, 1);
}

inline void report_external_failure(const char* file, int line, const char* expr) {
    TestCase* tc = g_current_test_case;
    if (tc == nullptr) return;
    increment_check_count(tc->checks_failed);
    tc->fail_file = file;
    tc->fail_line = line;
    unsigned length = 0;
    while (expr[length] != '\0' && length + 1 < sizeof(tc->external_failure)) {
        tc->external_failure[length] = expr[length];
        length++;
    }
    tc->external_failure[length] = '\0';
    tc->fail_expr = tc->external_failure;
    out("    check: ");
    out(file);
    out(":");
    out_int(line);
    out(" -> ");
    out(expr);
    out("\n");
}

inline void register_test(TestCase* tc) {
    tc->next = nullptr;
    *g_tail = tc;
    g_tail = &tc->next;
}

// --- Check macros ---

#define RUT_TEST_REPORT_FAILURE(kind, expr_str)                 \
    do {                                                        \
        ::rut::test::increment_check_count(_tc->checks_failed); \
        _tc->fail_file = __FILE__;                              \
        _tc->fail_line = __LINE__;                              \
        _tc->fail_expr = expr_str;                              \
        ::rut::test::out("    ");                               \
        ::rut::test::out(kind);                                 \
        ::rut::test::out(": ");                                 \
        ::rut::test::out(__FILE__);                             \
        ::rut::test::out(":");                                  \
        ::rut::test::out_int(__LINE__);                         \
        ::rut::test::out(" -> ");                               \
        ::rut::test::out(expr_str);                             \
        ::rut::test::out("\n");                                 \
    } while (0)

#define CHECK(expr)                                                 \
    do {                                                            \
        if (expr) {                                                 \
            ::rut::test::increment_check_count(_tc->checks_passed); \
        } else {                                                    \
            RUT_TEST_REPORT_FAILURE("check", #expr);                \
        }                                                           \
    } while (0)

#define CHECK_EQ(a, b) CHECK((a) == (b))
#define CHECK_NE(a, b) CHECK((a) != (b))
#define CHECK_GT(a, b) CHECK((a) > (b))
#define CHECK_GE(a, b) CHECK((a) >= (b))
#define CHECK_LT(a, b) CHECK((a) < (b))
#define CHECK_LE(a, b) CHECK((a) <= (b))
#define CHECK_TRUE(v) CHECK((v))
#define CHECK_FALSE(v) CHECK(!(v))
#define CHECK_STREQ(a, b) CHECK(::rut::test::str_eq_safe((a), (b)))
#define CHECK_MSG(expr, msg)                                        \
    do {                                                            \
        if (expr) {                                                 \
            ::rut::test::increment_check_count(_tc->checks_passed); \
        } else {                                                    \
            RUT_TEST_REPORT_FAILURE("check", msg);                  \
        }                                                           \
    } while (0)

#define REQUIRE(expr)                                               \
    do {                                                            \
        if (expr) {                                                 \
            ::rut::test::increment_check_count(_tc->checks_passed); \
        } else {                                                    \
            RUT_TEST_REPORT_FAILURE("require", #expr);              \
            return;                                                 \
        }                                                           \
    } while (0)

#define REQUIRE_EQ(a, b) REQUIRE((a) == (b))
#define REQUIRE_NE(a, b) REQUIRE((a) != (b))
#define REQUIRE_LT(a, b) REQUIRE((a) < (b))
#define REQUIRE_LE(a, b) REQUIRE((a) <= (b))
#define REQUIRE_GT(a, b) REQUIRE((a) > (b))
#define REQUIRE_GE(a, b) REQUIRE((a) >= (b))
#define REQUIRE_TRUE(v) REQUIRE((v))
#define REQUIRE_FALSE(v) REQUIRE(!(v))
#define REQUIRE_STREQ(a, b) REQUIRE(::rut::test::str_eq_safe((a), (b)))
#define REQUIRE_MSG(expr, msg)                                      \
    do {                                                            \
        if (expr) {                                                 \
            ::rut::test::increment_check_count(_tc->checks_passed); \
        } else {                                                    \
            RUT_TEST_REPORT_FAILURE("require", msg);                \
            return;                                                 \
        }                                                           \
    } while (0)

#define EXPECT(expr) CHECK(expr)
#define EXPECT_EQ(a, b) CHECK_EQ((a), (b))
#define EXPECT_NE(a, b) CHECK_NE((a), (b))
#define EXPECT_GT(a, b) CHECK_GT((a), (b))
#define EXPECT_GE(a, b) CHECK_GE((a), (b))
#define EXPECT_LT(a, b) CHECK_LT((a), (b))
#define EXPECT_LE(a, b) CHECK_LE((a), (b))
#define EXPECT_TRUE(v) CHECK_TRUE(v)
#define EXPECT_FALSE(v) CHECK_FALSE(v)
#define EXPECT_STREQ(a, b) CHECK_STREQ((a), (b))
#define EXPECT_MSG(expr, msg) CHECK_MSG((expr), (msg))

#define ASSERT(expr) REQUIRE(expr)
#define ASSERT_EQ(a, b) REQUIRE_EQ((a), (b))
#define ASSERT_NE(a, b) REQUIRE_NE((a), (b))
#define ASSERT_GT(a, b) REQUIRE_GT((a), (b))
#define ASSERT_GE(a, b) REQUIRE_GE((a), (b))
#define ASSERT_LT(a, b) REQUIRE_LT((a), (b))
#define ASSERT_LE(a, b) REQUIRE_LE((a), (b))
#define ASSERT_TRUE(v) REQUIRE_TRUE(v)
#define ASSERT_FALSE(v) REQUIRE_FALSE(v)
#define ASSERT_STREQ(a, b) REQUIRE_STREQ((a), (b))
#define ASSERT_MSG(expr, msg) REQUIRE_MSG((expr), (msg))

#define FAIL(msg) REQUIRE_MSG(false, msg)

#define SKIP(msg)                       \
    do {                                \
        if (_tc->checks_failed == 0) {  \
            _tc->skipped = true;        \
            _tc->skip_reason = (msg);   \
        } else {                        \
            _tc->skipped = false;       \
            _tc->skip_reason = nullptr; \
        }                               \
        return;                         \
    } while (0)

// --- Test definition ---

#define TEST(suite, name)                                                                          \
    static void test_##suite##_##name(rut::test::TestCase*);                                       \
    static rut::test::TestCase tc_##suite##_##name = {                                             \
        #suite, #name, test_##suite##_##name, nullptr, 0, 0, nullptr, 0, nullptr, false, nullptr}; \
    __attribute__((constructor)) static void reg_##suite##_##name() {                              \
        rut::test::register_test(&tc_##suite##_##name);                                            \
    }                                                                                              \
    static void test_##suite##_##name([[maybe_unused]] rut::test::TestCase* _tc)

#define TEST_F(Suite, name)                                                                        \
    static void test_##Suite##_##name##_impl(Suite& self, rut::test::TestCase* _tc);               \
    static void test_##Suite##_##name(rut::test::TestCase* _tc);                                   \
    static rut::test::TestCase tc_##Suite##_##name = {                                             \
        #Suite, #name, test_##Suite##_##name, nullptr, 0, 0, nullptr, 0, nullptr, false, nullptr}; \
    __attribute__((constructor)) static void reg_##Suite##_##name() {                              \
        rut::test::register_test(&tc_##Suite##_##name);                                            \
    }                                                                                              \
    static void test_##Suite##_##name(rut::test::TestCase* _tc) {                                  \
        Suite self;                                                                                \
        self.SetUp();                                                                              \
        if (!_tc->skipped) {                                                                       \
            test_##Suite##_##name##_impl(self, _tc);                                               \
        }                                                                                          \
        self.TearDown();                                                                           \
    }                                                                                              \
    static void test_##Suite##_##name##_impl(Suite& self, [[maybe_unused]] rut::test::TestCase* _tc)

// --- Filter matching ---
// "timer"         → suite or name contains "timer"
// "timer.refresh" → suite contains "timer" AND name contains "refresh"

struct Filter {
    static constexpr int kMaxFilters = 8;
    static constexpr int kMaxTokenLen = 128;
    const char* suite_filter[kMaxFilters];
    const char* name_filter[kMaxFilters];
    char suite_storage[kMaxFilters][kMaxTokenLen];
    char name_storage[kMaxFilters][kMaxTokenLen];
    int filter_count;

    Filter() { clear(); }

    Filter(const Filter& other) { copy_from(other); }

    Filter& operator=(const Filter& other) {
        if (this != &other) copy_from(other);
        return *this;
    }

    void clear() {
        filter_count = 0;
        for (int i = 0; i < kMaxFilters; i++) {
            suite_filter[i] = nullptr;
            name_filter[i] = nullptr;
            suite_storage[i][0] = '\0';
            name_storage[i][0] = '\0';
        }
    }

    void set_filter(
        int idx, const char* suite, size_t suite_len, const char* name, size_t name_len) {
        if (idx < 0 || idx >= kMaxFilters) return;

        suite_filter[idx] = nullptr;
        name_filter[idx] = nullptr;

        if (suite) {
            size_t copy_len = suite_len < (kMaxTokenLen - 1) ? suite_len : (kMaxTokenLen - 1);
            for (size_t i = 0; i < copy_len; i++) suite_storage[idx][i] = suite[i];
            suite_storage[idx][copy_len] = '\0';
            suite_filter[idx] = suite_storage[idx];
        } else {
            suite_storage[idx][0] = '\0';
        }

        if (name) {
            size_t copy_len = name_len < (kMaxTokenLen - 1) ? name_len : (kMaxTokenLen - 1);
            for (size_t i = 0; i < copy_len; i++) name_storage[idx][i] = name[i];
            name_storage[idx][copy_len] = '\0';
            name_filter[idx] = name_storage[idx];
        } else {
            name_storage[idx][0] = '\0';
        }
    }

    void copy_from(const Filter& other) {
        filter_count = other.filter_count;
        for (int i = 0; i < kMaxFilters; i++) {
            for (int j = 0; j < kMaxTokenLen; j++) {
                suite_storage[i][j] = other.suite_storage[i][j];
                name_storage[i][j] = other.name_storage[i][j];
            }
            suite_filter[i] = other.suite_filter[i] ? suite_storage[i] : nullptr;
            name_filter[i] = other.name_filter[i] ? name_storage[i] : nullptr;
        }
    }

    bool token_match(const char* value, const char* token) const {
        if (!value || !token) return false;

        const char* first_star = nullptr;
        const char* last_star = nullptr;
        const char* end = token;
        for (; *end; ++end) {
            if (*end != '*') continue;
            if (!first_star)
                first_star = end;
            else if (last_star != first_star)
                return false;
            last_star = end;
        }
        if (!first_star) return str_contains(value, token);
        if (token[0] == '*' && token[1] == '\0') return true;

        const bool kLeadingStar = first_star == token;
        const bool kTrailingStar = last_star + 1 == end;
        if (first_star != last_star) {
            if (!kLeadingStar || !kTrailingStar) return false;
            char core[128];
            char* out = core;
            for (const char* in = token + 1; in != last_star && out != core + 127; ++in)
                *out++ = *in;
            *out = '\0';
            return str_contains(value, core);
        }
        if (kLeadingStar) {
            const char* suffix = token + 1;
            const size_t kSuffixLength = __builtin_strlen(suffix);
            const size_t kValueLength = __builtin_strlen(value);
            if (kSuffixLength > kValueLength) return false;
            return str_eq(value + (kValueLength - kSuffixLength), suffix);
        }
        if (kTrailingStar) {
            for (const char* in = token; in != last_star; ++in, ++value)
                if (*in != *value) return false;
            return true;
        }
        return false;
    }

    bool matches(const TestCase* tc) const {
        if (filter_count == 0) return true;
        for (int i = 0; i < filter_count; i++) {
            const char* sf = suite_filter[i];
            const char* nf = name_filter[i];
            if (sf && nf) {
                if (token_match(tc->suite, sf) && token_match(tc->name, nf)) return true;
                continue;
            }
            const char* token = sf ? sf : nf;
            if (token_match(tc->suite, token) || token_match(tc->name, token)) return true;
        }
        return false;
    }
};

inline Filter parse_filter(const char* arg) {
    Filter filter;
    filter.clear();
    if (!arg || !arg[0]) return filter;

    const char* start = arg;
    for (const char* end = arg;; ++end) {
        if (*end != ',' && *end != '\0') continue;
        const int index = filter.filter_count;
        if (index >= Filter::kMaxFilters) break;
        if (start != end) {
            const char* split = start;
            while (split != end && *split != '.') ++split;
            if (split != end) {
                const char* name = split + 1;
                filter.set_filter(index,
                                  start,
                                  static_cast<size_t>(split - start),
                                  name,
                                  static_cast<size_t>(end - name));
            } else {
                filter.set_filter(index, nullptr, 0, start, static_cast<size_t>(end - start));
            }
            filter.filter_count = index + 1;
        }
        if (*end == '\0') break;
        start = end + 1;
    }
    return filter;
}

inline Filter merge_filter(const Filter& a, const Filter& b) {
    Filter merged;
    merged.clear();

    for (int src = 0; src < 2; src++) {
        const Filter& cur = src == 0 ? a : b;
        for (int i = 0; i < cur.filter_count && merged.filter_count < Filter::kMaxFilters; i++) {
            const char* sf = cur.suite_filter[i];
            const char* nf = cur.name_filter[i];
            const int index = merged.filter_count;
            merged.set_filter(
                index, sf, sf ? __builtin_strlen(sf) : 0, nf, nf ? __builtin_strlen(nf) : 0);
            merged.filter_count = index + 1;
        }
    }
    return merged;
}

// --- Deterministic sharding ---
//
// Hash the exact bytes of "suite.name" using 32-bit FNV-1a.  Each char is
// treated as an unsigned byte and multiplication wraps modulo 2^32.

inline uint32_t test_name_hash(const char* suite, const char* name) {
    uint32_t hash = UINT32_C(2166136261);
    const char* parts[] = {suite, ".", name};
    for (const char* part : parts) {
        for (const char* byte = part; *byte; ++byte) {
            hash ^= static_cast<unsigned char>(*byte);
            hash *= UINT32_C(16777619);
        }
    }
    return hash;
}

struct Shard {
    uint32_t index;
    uint32_t count;
    bool has_index;
    bool has_count;

    bool enabled() const { return has_index && has_count; }

    bool matches(const TestCase* tc) const {
        return !enabled() || test_name_hash(tc->suite, tc->name) % count == index;
    }
};

inline bool parse_uint32(const char* value, uint32_t* result) {
    if (!value || !value[0]) return false;
    uint32_t parsed = 0;
    for (const char* byte = value; *byte; ++byte) {
        if (*byte < '0' || *byte > '9') return false;
        const uint32_t digit = static_cast<uint32_t>(*byte - '0');
        if (parsed > (UINT32_MAX - digit) / 10) return false;
        parsed = parsed * 10 + digit;
    }
    *result = parsed;
    return true;
}

inline bool selected(const TestCase* tc, const Filter& filter, const Shard& shard) {
    return filter.matches(tc) && shard.matches(tc);
}

inline int run_all(int argc = 0, char** argv = nullptr) {
    // Parse args
    bool list_only = false;
    bool ask_help = false;
    Filter filter{};
    Shard shard{0, 0, false, false};

    for (int i = 1; i < argc; i++) {
        if (str_eq(argv[i], "-l") || str_eq(argv[i], "--list")) {
            list_only = true;
        } else if (str_eq(argv[i], "--help") || str_eq(argv[i], "-h")) {
            ask_help = true;
        } else if (str_starts_with(argv[i], "--filter=")) {
            filter = merge_filter(filter, parse_filter(argv[i] + 9));
        } else if (str_starts_with(argv[i], "--shard-index")) {
            if (shard.has_index || !str_starts_with(argv[i], "--shard-index=") ||
                !parse_uint32(argv[i] + 14, &shard.index)) {
                out("error: invalid --shard-index; expected --shard-index=N\n");
                return 2;
            }
            shard.has_index = true;
        } else if (str_starts_with(argv[i], "--shard-count")) {
            if (shard.has_count || !str_starts_with(argv[i], "--shard-count=") ||
                !parse_uint32(argv[i] + 14, &shard.count)) {
                out("error: invalid --shard-count; expected --shard-count=N\n");
                return 2;
            }
            shard.has_count = true;
        } else {
            filter = merge_filter(filter, parse_filter(argv[i]));
        }
    }

    if (shard.has_index != shard.has_count) {
        out("error: --shard-index and --shard-count must be specified together\n");
        return 2;
    }
    if (shard.enabled() && (shard.count == 0 || shard.index >= shard.count)) {
        out("error: shard count must be positive and shard index must be less than count\n");
        return 2;
    }

    if (ask_help) {
        out("Usage: ");
        out(argv[0]);
        out(" [options]\n");
        out("  -h, --help           print this message\n");
        out("  -l, --list           list matching tests and exit\n");
        out("  --filter=<expr>      allow-list filter by suite/name or suite.name\n");
        out("                       comma-separated, e.g. framework.aliases,math.*\n");
        out("  --shard-index=N      zero-based deterministic shard index\n");
        out("  --shard-count=N      positive deterministic shard count (paired with index)\n");
        out("  <expr>               filter by suite/name or suite.name\n");
        return 0;
    }

    // List mode
    if (list_only) {
        for (TestCase* tc = g_head; tc; tc = tc->next) {
            if (selected(tc, filter, shard)) {
                out(tc->suite);
                out(".");
                out(tc->name);
                out("\n");
            }
        }
        return 0;
    }

    // Run
    int total_pass = 0;
    int total_fail = 0;
    int total_skip = 0;
    int total_checks = 0;
    int total_check_fail = 0;
    const char* prev_suite = nullptr;

    for (TestCase* tc = g_head; tc; tc = tc->next) {
        if (!selected(tc, filter, shard)) {
            increment_check_count(total_skip);
            continue;
        }

        if (str_starts_with(tc->name, "DISABLED_")) {
            tc->skipped = true;
            tc->skip_reason = "disabled";
        } else {
            tc->skipped = false;
            tc->skip_reason = nullptr;
        }

        // Suite header
        if (!prev_suite || !str_eq(prev_suite, tc->suite)) {
            out("=== ");
            out(tc->suite);
            out(" ===\n");
            prev_suite = tc->suite;
        }

        tc->checks_passed = 0;
        tc->checks_failed = 0;
        tc->fail_file = nullptr;
        tc->fail_line = 0;
        tc->fail_expr = nullptr;
        tc->external_failure[0] = '\0';
        if (!str_starts_with(tc->name, "DISABLED_")) tc->skip_reason = nullptr;

        if (!tc->skipped) {
            out("RUN: ");
            out(tc->suite);
            out(".");
            out(tc->name);
            out("\n");
            g_current_test_case = tc;
            tc->fn(tc);
            g_current_test_case = nullptr;
        }
        add_check_count(total_checks, tc->checks_passed);
        add_check_count(total_check_fail, tc->checks_failed);
        add_check_count(total_checks, tc->checks_failed);

        if (tc->skipped) {
            out("  SKIP: ");
            out(tc->name);
            if (tc->skip_reason) {
                out(" (");
                out(tc->skip_reason);
                out(")");
            }
            out("\n");
            increment_check_count(total_skip);
        } else if (tc->checks_failed == 0) {
            out("  PASS: ");
            out(tc->name);
            out("\n");
            increment_check_count(total_pass);
        } else {
            out("  FAIL: ");
            out(tc->name);
            if (tc->fail_file) {
                out(" (");
                out(tc->fail_file);
                out(":");
                out_int(tc->fail_line);
                out(": ");
                out(tc->fail_expr);
                out(")");
            }
            out("\n");
            increment_check_count(total_fail);
        }
    }

    out("\n");
    out_int(total_pass);
    out(" passed, ");
    out_int(total_fail);
    out(" failed, ");
    out_int(total_checks);
    out(" checks, ");
    out_int(total_check_fail);
    out(" failed checks");
    if (total_skip > 0) {
        out(", ");
        out_int(total_skip);
        out(" skipped");
    }
    out("\n");

    return total_fail > 0 ? 1 : 0;
}

}  // namespace rut::test
