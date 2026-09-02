// Verify the test framework itself works.
#include "test.h"
#include <algorithm>
#include <iterator>
#include <string>
#include <vector>

#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

const char* g_program_path = nullptr;

struct ChildResult {
    int exit_code;
    std::string output;
};

ChildResult run_child(const std::vector<const char*>& arguments) {
    int output_pipe[2];
    if (pipe(output_pipe) != 0) return {255, "pipe failed"};

    const pid_t pid = fork();
    if (pid == 0) {
        (void)close(output_pipe[0]);
        if (dup2(output_pipe[1], STDOUT_FILENO) < 0 || dup2(output_pipe[1], STDERR_FILENO) < 0) {
            _exit(126);
        }
        (void)close(output_pipe[1]);

        std::vector<char*> child_argv;
        child_argv.push_back(const_cast<char*>(g_program_path));
        for (const char* argument : arguments) {
            child_argv.push_back(const_cast<char*>(argument));
        }
        child_argv.push_back(nullptr);
        execvp(g_program_path, child_argv.data());
        _exit(127);
    }

    (void)close(output_pipe[1]);
    if (pid < 0) {
        (void)close(output_pipe[0]);
        return {255, "fork failed"};
    }

    std::string output;
    char buffer[1024];
    for (;;) {
        const ssize_t count = read(output_pipe[0], buffer, sizeof(buffer));
        if (count > 0) {
            output.append(buffer, static_cast<size_t>(count));
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        break;
    }
    (void)close(output_pipe[0]);

    int status = 0;
    pid_t waited = -1;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != pid) return {255, output};
    if (!WIFEXITED(status)) return {255, output};
    return {WEXITSTATUS(status), output};
}

std::vector<std::string> output_lines(const std::string& output) {
    std::vector<std::string> lines;
    size_t start = 0;
    while (start < output.size()) {
        const size_t end = output.find('\n', start);
        lines.push_back(output.substr(start, end == std::string::npos ? end : end - start));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return lines;
}

bool self_check(bool condition, const char* description) {
    rut::test::out(condition ? "SELF-CHECK PASS: " : "SELF-CHECK FAIL: ");
    rut::test::out(description);
    rut::test::out("\n");
    return condition;
}

int run_sharding_self_test() {
    bool ok = true;
    ok &= self_check(rut::test::test_name_hash("framework", "check_pass") == UINT32_C(1428683963),
                     "FNV-1a hashes exact suite.name bytes");
    ok &= self_check(rut::test::test_name_hash("OrderingFixture", "sharding_order_probe") ==
                         UINT32_C(1497208354),
                     "FNV-1a fixture hash is stable");

    struct InvalidShardCase {
        std::vector<const char*> arguments;
        const char* expected_diagnostic;
        const char* description;
    };
    const std::vector<InvalidShardCase> invalid_cases = {
        {{"--shard-index=0"},
         "error: --shard-index and --shard-count must be specified together\n",
         "missing shard count is rejected by the parser"},
        {{"--shard-count=2"},
         "error: --shard-index and --shard-count must be specified together\n",
         "missing shard index is rejected by the parser"},
        {{"--shard-index=0", "--shard-count=0"},
         "error: shard count must be positive and shard index must be less than count\n",
         "zero shard count is rejected by the parser"},
        {{"--shard-index=2", "--shard-count=2"},
         "error: shard count must be positive and shard index must be less than count\n",
         "out-of-range shard index is rejected by the parser"},
        {{"--shard-index=x", "--shard-count=2"},
         "error: invalid --shard-index; expected --shard-index=N\n",
         "non-numeric shard index is rejected by the parser"},
        {{"--shard-index=4294967296", "--shard-count=2"},
         "error: invalid --shard-index; expected --shard-index=N\n",
         "overflowing shard index is rejected by the parser"},
        {{"--shard-index=0", "--shard-count=4294967296"},
         "error: invalid --shard-count; expected --shard-count=N\n",
         "overflowing shard count is rejected by the parser"},
        {{"--shard-index", "--shard-count=2"},
         "error: invalid --shard-index; expected --shard-index=N\n",
         "missing shard index value is rejected by the parser"},
        {{"--shard-index=0", "--shard-index=0", "--shard-count=2"},
         "error: invalid --shard-index; expected --shard-index=N\n",
         "duplicate shard index is rejected by the parser"},
        {{"--shard-index=0", "--shard-count=2", "--shard-count=2"},
         "error: invalid --shard-count; expected --shard-count=N\n",
         "duplicate shard count is rejected by the parser"},
    };
    for (const auto& invalid_case : invalid_cases) {
        const auto result = run_child(invalid_case.arguments);
        ok &=
            self_check(result.exit_code == 2 && result.output == invalid_case.expected_diagnostic &&
                           result.output.find("RUN:") == std::string::npos &&
                           result.output.find("===") == std::string::npos,
                       invalid_case.description);
    }

    const auto full = run_child({"--list"});
    const auto shard_0 = run_child({"--list", "--shard-index=0", "--shard-count=2"});
    const auto shard_1 = run_child({"--list", "--shard-index=1", "--shard-count=2"});
    ok &= self_check(full.exit_code == 0 && shard_0.exit_code == 0 && shard_1.exit_code == 0,
                     "full and sharded list commands succeed");

    auto full_lines = output_lines(full.output);
    auto shard_0_lines = output_lines(shard_0.output);
    auto shard_1_lines = output_lines(shard_1.output);
    std::sort(full_lines.begin(), full_lines.end());
    std::sort(shard_0_lines.begin(), shard_0_lines.end());
    std::sort(shard_1_lines.begin(), shard_1_lines.end());
    std::vector<std::string> shard_union;
    std::set_union(shard_0_lines.begin(),
                   shard_0_lines.end(),
                   shard_1_lines.begin(),
                   shard_1_lines.end(),
                   std::back_inserter(shard_union));
    std::vector<std::string> shard_intersection;
    std::set_intersection(shard_0_lines.begin(),
                          shard_0_lines.end(),
                          shard_1_lines.begin(),
                          shard_1_lines.end(),
                          std::back_inserter(shard_intersection));
    ok &= self_check(shard_union == full_lines, "sorted shard-list union equals full list");
    ok &= self_check(shard_intersection.empty(), "shard-list intersection is empty");

    const auto filtered_0 = run_child({"--list",
                                       "--filter=OrderingFixture.sharding_order_probe",
                                       "--shard-index=0",
                                       "--shard-count=2"});
    const auto filtered_1 = run_child({"--list",
                                       "--filter=OrderingFixture.sharding_order_probe",
                                       "--shard-index=1",
                                       "--shard-count=2"});
    ok &= self_check(filtered_0.exit_code == 0 &&
                         filtered_0.output == "OrderingFixture.sharding_order_probe\n" &&
                         filtered_1.exit_code == 0 && filtered_1.output.empty(),
                     "filter and shard selection intersect");

    const auto ordering = run_child({"--filter=OrderingFixture.sharding_order_probe"});
    ok &= self_check(ordering.exit_code == 0 &&
                         ordering.output.find("RUN: OrderingFixture.sharding_order_probe\n"
                                              "SETUP: OrderingFixture.sharding_order_probe\n"
                                              "BODY: OrderingFixture.sharding_order_probe\n") !=
                             std::string::npos,
                     "RUN is emitted before fixture SetUp and test body");

    return ok ? 0 : 1;
}

}  // namespace

TEST(framework, check_pass) {
    CHECK(1 + 1 == 2);
    CHECK_EQ(3 * 3, 9);
    CHECK_NE(0, 1);
    CHECK_GT(5, 3);
    CHECK_LT(3, 5);
}

TEST(framework, check_fail_reported) {
    // This test intentionally has a failing check.
    // The framework should report it but continue.
    CHECK(true);
    CHECK(2 + 2 == 5);  // will fail
    CHECK(true);        // still runs after failure
}

TEST(framework, require_stops) {
    CHECK(true);
    REQUIRE(true);
    // If REQUIRE failed, we wouldn't reach here
    CHECK(true);
}

TEST(framework, aliases) {
    EXPECT(1 + 1 == 2);
    EXPECT_EQ(7 - 2, 5);
    EXPECT_MSG(1u < 3u, "unsigned compare works");
    ASSERT_TRUE(true);
    ASSERT_NE(9, 4);
}

struct MyFixture {
    int value = 1;
    void SetUp() { value = 10; }
    void TearDown() { value = 0; }
};

TEST_F(MyFixture, uses_state) {
    CHECK_EQ(self.value, 10);
    ASSERT_GT(self.value, 0);
    EXPECT_STREQ("x", "x");
}

struct OrderingFixture {
    void SetUp() { rut::test::out("SETUP: OrderingFixture.sharding_order_probe\n"); }
    void TearDown() {}
};

TEST_F(OrderingFixture, sharding_order_probe) {
    (void)self;
    rut::test::out("BODY: OrderingFixture.sharding_order_probe\n");
    CHECK(true);
}

TEST(framework, explicit_skip) {
    SKIP("feature unavailable in this environment");
    CHECK(false);
}

TEST(framework, DISABLED_skip_by_name) {
    CHECK(false);
}

TEST(framework, wildcard_prefix_filter_matches_exact_prefix) {
    rut::test::Filter filter{};
    filter.clear();
    CHECK(filter.token_match("abc", "abc*"));
    CHECK(filter.token_match("abcd", "abc*"));
    CHECK(!filter.token_match("ab", "abc*"));
}

TEST(framework, wildcard_suffix_and_wrapped_match_expected_shapes) {
    rut::test::Filter filter{};
    filter.clear();
    CHECK(filter.token_match("alphabet", "*bet"));
    CHECK(!filter.token_match("alpha", "*bet"));
    CHECK(filter.token_match("alphabet", "*pha*"));
    CHECK(filter.token_match("pha", "*pha*"));
    CHECK(!filter.token_match("zzz", "*pha*"));
}

TEST(framework, wildcard_with_middle_star_is_rejected) {
    rut::test::Filter filter{};
    filter.clear();
    CHECK(!filter.token_match("abcd", "ab*cd"));
    CHECK(!filter.token_match("abxcd", "ab*cd"));
}

TEST(framework, wildcard_with_extra_edge_stars_is_rejected) {
    rut::test::Filter filter{};
    filter.clear();
    CHECK(!filter.token_match("abc", "*abc**"));
    CHECK(!filter.token_match("abc", "**abc*"));
    CHECK(!filter.token_match("abc", "***"));
    CHECK(!filter.token_match("alphabet", "*pha**"));
}

static rut::test::TestCase make_test_case(const char* suite, const char* name) {
    return {suite, name, nullptr, nullptr, 0, 0, nullptr, 0, nullptr, false, nullptr};
}

TEST(framework, dotted_filter_with_empty_name_preserves_suite_semantics) {
    const auto filter = rut::test::parse_filter("framework.");
    auto suite_match = make_test_case("framework", "aliases");
    auto suite_miss = make_test_case("math", "framework");

    CHECK(filter.matches(&suite_match));
    CHECK(!filter.matches(&suite_miss));
}

TEST(framework, dotted_filter_with_empty_suite_preserves_name_semantics) {
    const auto filter = rut::test::parse_filter(".aliases");
    auto name_match = make_test_case("framework", "aliases");
    auto name_miss = make_test_case("aliases", "other");

    CHECK(filter.matches(&name_match));
    CHECK(!filter.matches(&name_miss));
}

TEST(framework, merged_filters_keep_own_storage) {
    const auto merged = rut::test::merge_filter(
        rut::test::parse_filter("math.addition"),
        rut::test::merge_filter(rut::test::parse_filter("framework.aliases"),
                                rut::test::parse_filter("math.mul*")));
    const auto overwritten = rut::test::parse_filter("other.value,another.case");

    auto addition = make_test_case("math", "addition");
    auto aliases = make_test_case("framework", "aliases");
    auto multiplication = make_test_case("math", "multiplication");
    auto miss = make_test_case("framework", "check_pass");

    CHECK_EQ(overwritten.filter_count, 2);
    CHECK(merged.matches(&addition));
    CHECK(merged.matches(&aliases));
    CHECK(merged.matches(&multiplication));
    CHECK(!merged.matches(&miss));
}

TEST(framework, copied_filter_rebinds_internal_storage) {
    rut::test::Filter copied;
    copied = rut::test::parse_filter("framework.aliases,math.mul*");
    const auto overwritten = rut::test::parse_filter("other.value");

    auto aliases = make_test_case("framework", "aliases");
    auto multiplication = make_test_case("math", "multiplication");
    auto miss = make_test_case("framework", "check_pass");

    CHECK_EQ(overwritten.filter_count, 1);
    CHECK(copied.matches(&aliases));
    CHECK(copied.matches(&multiplication));
    CHECK(!copied.matches(&miss));
}

TEST(framework, copy_constructed_filter_rebinds_internal_storage) {
    const auto parsed = rut::test::parse_filter("framework.aliases,*lication");
    const rut::test::Filter copied(parsed);
    const auto overwritten = rut::test::parse_filter("other.value,third.case");

    auto aliases = make_test_case("framework", "aliases");
    auto multiplication = make_test_case("math", "multiplication");
    auto miss = make_test_case("framework", "check_pass");

    CHECK_EQ(overwritten.filter_count, 2);
    CHECK(copied.matches(&aliases));
    CHECK(copied.matches(&multiplication));
    CHECK(!copied.matches(&miss));
}

TEST(math, addition) {
    CHECK_EQ(1 + 1, 2);
    CHECK_EQ(0 + 0, 0);
    CHECK_EQ(-1 + 1, 0);
}

TEST(math, multiplication) {
    CHECK_EQ(2 * 3, 6);
    CHECK_EQ(0 * 100, 0);
}

int main(int argc, char** argv) {
    g_program_path = argv[0];
    if (argc == 2 && rut::test::str_eq(argv[1], "--sharding-self-test")) {
        return run_sharding_self_test();
    }
    return rut::test::run_all(argc, argv);
}
