#include "rut/runtime/rate_limit_enforce.h"
#include "test.h"

using namespace rut;

static constexpr u64 kTestRateLimitIds[kMaxRateLimitRules] = {1, 2, 3, 4};

TEST(rate_limit_enforce, missing_global_rejects_before_consuming_shard_budget) {
    RateLimiter shard{};
    RateLimitRuleSet rules{};
    REQUIRE_EQ(rules.add_rule(1, 60), 0);
    REQUIRE_EQ(rules.add_rule(1, 60, 1, RateLimitScope::Global), 1);
    RateLimitKeyInput input{};
    input.peer_addr = 1;
    CHECK(rate_limit_exceeded_with_limiters(shard, nullptr, rules, kTestRateLimitIds, input, 1000));
    // The failed configuration must not spend an earlier shard rule's budget.
    rules.count = 1;
    CHECK(
        !rate_limit_exceeded_with_limiters(shard, nullptr, rules, kTestRateLimitIds, input, 1000));
    CHECK(rate_limit_exceeded_with_limiters(shard, nullptr, rules, kTestRateLimitIds, input, 1000));
}

TEST(rate_limit_enforce, missing_global_member_fails_closed) {
    struct Loop {
        RateLimiter rate_limiter{};
    } loop;
    RateLimitRuleSet rules{};
    REQUIRE_EQ(rules.add_rule(1, 60, 1, RateLimitScope::Global), 0);
    RateLimitKeyInput input{};
    CHECK(rate_limit_exceeded(&loop, rules, kTestRateLimitIds, input, 1000));
}

TEST(rate_limit_enforce, null_global_pointer_fails_closed) {
    struct Loop {
        RateLimiter rate_limiter{};
        GlobalRateLimiter* global_rl = nullptr;
    } loop;
    RateLimitRuleSet rules{};
    REQUIRE_EQ(rules.add_rule(1, 60, 1, RateLimitScope::Global), 0);
    RateLimitKeyInput input{};
    CHECK(rate_limit_exceeded(&loop, rules, kTestRateLimitIds, input, 1000));
}

TEST(rate_limit_enforce, disabled_global_does_not_require_shared_limiter) {
    RateLimiter shard{};
    RateLimitRuleSet rules{};
    REQUIRE_EQ(rules.add_rule(0, 60, 1, RateLimitScope::Global), 0);
    RateLimitKeyInput input{};
    CHECK(
        !rate_limit_exceeded_with_limiters(shard, nullptr, rules, kTestRateLimitIds, input, 1000));
    REQUIRE_EQ(rules.add_rule(1, 60), 1);
    CHECK(
        !rate_limit_exceeded_with_limiters(shard, nullptr, rules, kTestRateLimitIds, input, 1000));
    CHECK(rate_limit_exceeded_with_limiters(shard, nullptr, rules, kTestRateLimitIds, input, 1000));
}

TEST(rate_limit_enforce, shared_budget_is_used_across_shards) {
    RateLimiter first{};
    RateLimiter second{};
    GlobalRateLimiter global{};
    global.reset();
    RateLimitRuleSet rules{};
    REQUIRE_EQ(rules.add_rule(1, 60, 1, RateLimitScope::Global), 0);
    RateLimitKeyInput input{};
    CHECK(
        !rate_limit_exceeded_with_limiters(first, &global, rules, kTestRateLimitIds, input, 1000));
    CHECK(
        rate_limit_exceeded_with_limiters(second, &global, rules, kTestRateLimitIds, input, 1000));
    CHECK(!rate_limit_exceeded_with_limiters(
        second, &global, rules, kTestRateLimitIds, input, 60001000));
}

TEST(rate_limit_enforce, no_rules_does_not_require_shared_limiter) {
    RateLimiter shard{};
    RateLimitRuleSet rules{};
    RateLimitKeyInput input{};
    CHECK(
        !rate_limit_exceeded_with_limiters(shard, nullptr, rules, kTestRateLimitIds, input, 1000));
}

TEST(rate_limit_enforce, rejecting_rule_still_meters_later_rule_in_each_scope) {
    const RateLimitScope scopes[] = {RateLimitScope::Shard, RateLimitScope::Global};
    for (auto first_scope : scopes) {
        for (auto second_scope : scopes) {
            RateLimiter shard{};
            GlobalRateLimiter global{};
            global.reset();
            RateLimitRuleSet rules{};
            REQUIRE_EQ(rules.add_rule(1, 60, 1, first_scope), 0);
            REQUIRE_EQ(rules.add_rule(1, 60, 1, second_scope), 1);
            RateLimitKeyInput input{};
            input.peer_addr = 1;
            // Exhaust only the first rule, leaving the second rule fresh.
            rules.count = 1;
            REQUIRE(!rate_limit_exceeded_with_limiters(
                shard, &global, rules, kTestRateLimitIds, input, 1000));
            rules.count = 2;
            CHECK(rate_limit_exceeded_with_limiters(
                shard, &global, rules, kTestRateLimitIds, input, 1000));
            // The rejected request must still have consumed the second rule.
            rules.rules[0].emit_interval_us = 0;
            CHECK(rate_limit_exceeded_with_limiters(
                shard, &global, rules, kTestRateLimitIds, input, 1000));
            // Rejections do not create debt or extend either GCRA recovery time.
            rules.rules[0].emit_interval_us = 60000000;
            for (u32 i = 0; i < 3; ++i)
                CHECK(rate_limit_exceeded_with_limiters(
                    shard, &global, rules, kTestRateLimitIds, input, 1005));
            CHECK(!rate_limit_exceeded_with_limiters(
                shard, &global, rules, kTestRateLimitIds, input, 60001000));
        }
    }
}

TEST(rate_limit_enforce, later_rejection_does_not_refund_earlier_rule) {
    const RateLimitScope scopes[] = {RateLimitScope::Shard, RateLimitScope::Global};
    for (auto first_scope : scopes) {
        for (auto second_scope : scopes) {
            RateLimiter shard{};
            GlobalRateLimiter global{};
            global.reset();
            RateLimitRuleSet rules{};
            REQUIRE_EQ(rules.add_rule(1, 60, 1, first_scope), 0);
            REQUIRE_EQ(rules.add_rule(1, 60, 1, second_scope), 1);
            RateLimitKeyInput input{};
            input.peer_addr = 1;
            rules.rules[0].emit_interval_us = 0;
            REQUIRE(!rate_limit_exceeded_with_limiters(
                shard, &global, rules, kTestRateLimitIds, input, 1000));
            rules.rules[0].emit_interval_us = 60000000;
            CHECK(rate_limit_exceeded_with_limiters(
                shard, &global, rules, kTestRateLimitIds, input, 1000));
            rules.rules[1].emit_interval_us = 0;
            CHECK(rate_limit_exceeded_with_limiters(
                shard, &global, rules, kTestRateLimitIds, input, 1000));
        }
    }
}

TEST(rate_limit_enforce, first_rejection_still_meters_every_tail_of_four_rule_stack) {
    RateLimiter shard{};
    GlobalRateLimiter global{};
    global.reset();
    RateLimitRuleSet rules{};
    for (u32 i = 0; i < kMaxRateLimitRules; ++i) {
        REQUIRE_EQ(rules.add_rule(1, 60, 1, i % 2 ? RateLimitScope::Global : RateLimitScope::Shard),
                   static_cast<i32>(i));
    }
    RateLimitKeyInput input{};
    input.peer_addr = 1;
    rules.count = 1;
    REQUIRE(
        !rate_limit_exceeded_with_limiters(shard, &global, rules, kTestRateLimitIds, input, 1000));
    rules.count = kMaxRateLimitRules;
    CHECK(rate_limit_exceeded_with_limiters(shard, &global, rules, kTestRateLimitIds, input, 1000));
    for (auto& rule : rules.rules) rule.emit_interval_us = 0;
    for (u32 i = 1; i < kMaxRateLimitRules; ++i) {
        rules.rules[i].emit_interval_us = 60000000;
        CHECK(rate_limit_exceeded_with_limiters(
            shard, &global, rules, kTestRateLimitIds, input, 1000));
        rules.rules[i].emit_interval_us = 0;
    }
}

TEST(rate_limit_enforce, shard_buckets_are_isolated_per_loop_instance) {
    struct Loop {
        RateLimiter rate_limiter{};
    } first, second;
    RateLimitRuleSet rules{};
    REQUIRE_EQ(rules.add_rule(1, 60, 1), 0);
    RateLimitKeyInput input{};
    input.peer_addr = 1;

    // Both loops run on this test thread; their shard buckets must still be
    // independent because state belongs to each loop instance.
    CHECK(!rate_limit_exceeded(&first, rules, kTestRateLimitIds, input, 1000));
    CHECK(rate_limit_exceeded(&first, rules, kTestRateLimitIds, input, 1000));
    CHECK(!rate_limit_exceeded(&second, rules, kTestRateLimitIds, input, 1000));
    CHECK(rate_limit_exceeded(&second, rules, kTestRateLimitIds, input, 1000));
}

TEST(rate_limit_enforce, missing_semantic_id_fails_closed_without_spending) {
    RateLimiter shard{};
    GlobalRateLimiter global{};
    global.reset();
    RateLimitRuleSet rules{};
    REQUIRE_EQ(rules.add_rule(1, 60), 0);
    REQUIRE_EQ(rules.add_rule(1, 60, 1, RateLimitScope::Global), 1);
    const u64 missing_ids[] = {0x12345678, 0, 0, 0};
    RateLimitKeyInput input{};
    CHECK(rate_limit_exceeded_with_limiters(shard, &global, rules, missing_ids, input, 1000));
    // The later missing global ID must not spend the earlier shard rule.
    rules.count = 1;
    CHECK(!rate_limit_exceeded_with_limiters(shard, &global, rules, missing_ids, input, 1000));
    CHECK(rate_limit_exceeded_with_limiters(shard, &global, rules, missing_ids, input, 1000));
}

TEST(rate_limit_arithmetic, rejects_unrepresentable_tau_atomically) {
    RateLimitRuleSet rules{};
    REQUIRE_EQ(rules.add_rule(7, 1, 3), 0);
    const RateLimitRule saved = rules.rules[0];
    CHECK_EQ(rules.add_rule(1, 4293934841u, 4297u), -1);
    CHECK_EQ(rules.count, 1u);
    CHECK_EQ(rules.rules[0].max, saved.max);
    CHECK_EQ(rules.rules[0].emit_interval_us, saved.emit_interval_us);
    CHECK_EQ(rules.rules[0].tau_us, saved.tau_us);
}

TEST(rate_limit_arithmetic, disabled_interval_is_safe) {
    CHECK_EQ(rate_limit_emit_interval_us(0, 60), 0ull);
    CHECK_EQ(rate_limit_emit_interval_us(10, 0), 0ull);
    RateLimitRuleSet disabled{};
    REQUIRE_EQ(disabled.add_rule(0, 60, 4), 0);
    CHECK_EQ(disabled.rules[0].emit_interval_us, 0ull);
    CHECK_EQ(disabled.rules[0].tau_us, 0ull);
}

TEST(rate_limit_arithmetic, emission_interval_uses_ceil) {
    RateLimitRuleSet rules{};
    REQUIRE_EQ(rules.add_rule(3, 1, 1), 0);
    CHECK_EQ(rules.rules[0].emit_interval_us, 333334ull);
    RateLimiter limiter{};
    const u64 key = 0x1234;
    CHECK(limiter.allow_key(key, rules.rules[0].emit_interval_us, rules.rules[0].tau_us, 1000));
    CHECK(!limiter.allow_key(key, rules.rules[0].emit_interval_us, rules.rules[0].tau_us, 333333));
    CHECK(limiter.allow_key(key, rules.rules[0].emit_interval_us, rules.rules[0].tau_us, 334334));
}

TEST(rate_limit_arithmetic, configured_burst_sets_capacity_and_tolerance) {
    RateLimitRuleSet rules{};
    REQUIRE_EQ(rules.add_rule(3, 1, 2), 0);
    const RateLimitRule& rule = rules.rules[0];
    CHECK_EQ(rule.burst, 2u);
    CHECK_EQ(rule.emit_interval_us, 333334ull);
    CHECK_EQ(rule.tau_us, 333334ull);

    RateLimiter limiter{};
    const u64 key = 0x2345;
    CHECK(limiter.allow_key(key, rule.emit_interval_us, rule.tau_us, 1000));
    CHECK(limiter.allow_key(key, rule.emit_interval_us, rule.tau_us, 1000));
    CHECK(!limiter.allow_key(key, rule.emit_interval_us, rule.tau_us, 1000));
    CHECK(limiter.allow_key(key, rule.emit_interval_us, rule.tau_us, 334334));
}

TEST(rate_limit_arithmetic, conformance_and_state_update_are_overflow_safe) {
    constexpr u64 kMax = 0xffffffffffffffffull;
    constexpr u64 kKey = 0x5678;
    RateLimiter shard{};
    GlobalRateLimiter global{};
    global.reset();
    CHECK(shard.allow_key(kKey, 1, 0, kMax - 6));
    CHECK(shard.allow_key(kKey, 1, kMax - 20, kMax - 10));
    CHECK(global.allow_key(kKey, 1, 0, kMax - 6));
    CHECK(global.allow_key(kKey, 1, kMax - 20, kMax - 10));
    CHECK(!shard.allow_key(0x9abc, 10, 0, kMax - 5));
    CHECK(!global.allow_key(0x9abc, 10, 0, kMax - 5));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
