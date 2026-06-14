/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

// Verify the test framework itself works.
#include "test.h"

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
    return rut::test::run_all(argc, argv);
}
