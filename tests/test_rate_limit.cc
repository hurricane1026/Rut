#include "rut/runtime/rate_limit_enforce.h"
#include "test.h"

using namespace rut;

TEST(rate_limit_enforce, missing_global_rejects_before_consuming_shard_budget) {
    RateLimiter shard{};
    RateLimitRuleSet rules{};
    REQUIRE_EQ(rules.add_rule(1, 60), 0);
    REQUIRE_EQ(rules.add_rule(1, 60, 1, RateLimitScope::Global), 1);
    RateLimitKeyInput input{};
    input.peer_addr = 1;
    CHECK(rate_limit_exceeded_with_limiters(shard, nullptr, rules, 0, input, 1000));
    // The failed configuration must not spend an earlier shard rule's budget.
    rules.count = 1;
    CHECK(!rate_limit_exceeded_with_limiters(shard, nullptr, rules, 0, input, 1000));
    CHECK(rate_limit_exceeded_with_limiters(shard, nullptr, rules, 0, input, 1000));
}

TEST(rate_limit_enforce, missing_global_member_fails_closed) {
    struct Loop {
    } loop;
    RateLimitRuleSet rules{};
    REQUIRE_EQ(rules.add_rule(1, 60, 1, RateLimitScope::Global), 0);
    RateLimitKeyInput input{};
    CHECK(rate_limit_exceeded(&loop, rules, 0, input, 1000));
}

TEST(rate_limit_enforce, null_global_pointer_fails_closed) {
    struct Loop {
        GlobalRateLimiter* global_rl = nullptr;
    } loop;
    RateLimitRuleSet rules{};
    REQUIRE_EQ(rules.add_rule(1, 60, 1, RateLimitScope::Global), 0);
    RateLimitKeyInput input{};
    CHECK(rate_limit_exceeded(&loop, rules, 0, input, 1000));
}

TEST(rate_limit_enforce, disabled_global_does_not_require_shared_limiter) {
    RateLimiter shard{};
    RateLimitRuleSet rules{};
    REQUIRE_EQ(rules.add_rule(0, 60, 1, RateLimitScope::Global), 0);
    RateLimitKeyInput input{};
    CHECK(!rate_limit_exceeded_with_limiters(shard, nullptr, rules, 0, input, 1000));
    REQUIRE_EQ(rules.add_rule(1, 60), 1);
    CHECK(!rate_limit_exceeded_with_limiters(shard, nullptr, rules, 0, input, 1000));
    CHECK(rate_limit_exceeded_with_limiters(shard, nullptr, rules, 0, input, 1000));
}

TEST(rate_limit_enforce, shared_budget_is_used_across_shards) {
    RateLimiter first{};
    RateLimiter second{};
    GlobalRateLimiter global{};
    global.reset();
    RateLimitRuleSet rules{};
    REQUIRE_EQ(rules.add_rule(1, 60, 1, RateLimitScope::Global), 0);
    RateLimitKeyInput input{};
    CHECK(!rate_limit_exceeded_with_limiters(first, &global, rules, 0, input, 1000));
    CHECK(rate_limit_exceeded_with_limiters(second, &global, rules, 0, input, 1000));
    CHECK(!rate_limit_exceeded_with_limiters(second, &global, rules, 0, input, 60001000));
}

TEST(rate_limit_enforce, no_rules_does_not_require_shared_limiter) {
    RateLimiter shard{};
    RateLimitRuleSet rules{};
    RateLimitKeyInput input{};
    CHECK(!rate_limit_exceeded_with_limiters(shard, nullptr, rules, 0, input, 1000));
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
            REQUIRE(!rate_limit_exceeded_with_limiters(shard, &global, rules, 0, input, 1000));
            rules.count = 2;
            CHECK(rate_limit_exceeded_with_limiters(shard, &global, rules, 0, input, 1000));
            // The rejected request must still have consumed the second rule.
            rules.rules[0].emit_interval_us = 0;
            CHECK(rate_limit_exceeded_with_limiters(shard, &global, rules, 0, input, 1000));
            // Rejections do not create debt or extend either GCRA recovery time.
            rules.rules[0].emit_interval_us = 60000000;
            for (u32 i = 0; i < 3; ++i)
                CHECK(rate_limit_exceeded_with_limiters(shard, &global, rules, 0, input, 1005));
            CHECK(!rate_limit_exceeded_with_limiters(shard, &global, rules, 0, input, 60001000));
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
            REQUIRE(!rate_limit_exceeded_with_limiters(shard, &global, rules, 0, input, 1000));
            rules.rules[0].emit_interval_us = 60000000;
            CHECK(rate_limit_exceeded_with_limiters(shard, &global, rules, 0, input, 1000));
            rules.rules[1].emit_interval_us = 0;
            CHECK(rate_limit_exceeded_with_limiters(shard, &global, rules, 0, input, 1000));
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
    REQUIRE(!rate_limit_exceeded_with_limiters(shard, &global, rules, 0, input, 1000));
    rules.count = kMaxRateLimitRules;
    CHECK(rate_limit_exceeded_with_limiters(shard, &global, rules, 0, input, 1000));
    for (auto& rule : rules.rules) rule.emit_interval_us = 0;
    for (u32 i = 1; i < kMaxRateLimitRules; ++i) {
        rules.rules[i].emit_interval_us = 60000000;
        CHECK(rate_limit_exceeded_with_limiters(shard, &global, rules, 0, input, 1000));
        rules.rules[i].emit_interval_us = 0;
    }
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
