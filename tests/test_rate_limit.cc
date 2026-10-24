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

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
