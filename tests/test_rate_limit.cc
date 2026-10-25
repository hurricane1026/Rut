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
    const auto decision = rate_limit_decision_with_limiters(
        loop.rate_limiter, nullptr, rules, kTestRateLimitIds, input, 1000);
    CHECK(!decision.allowed);
    CHECK(!decision.retry_known);
    CHECK_EQ(decision.reject_reason, RateLimitRejectReason::MissingGlobal);
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

TEST(rate_limit_enforce, detailed_decision_counts_active_rules_by_scope_and_reason) {
    RateLimiter shard{};
    GlobalRateLimiter global{};
    global.reset();
    RateLimitRuleSet rules{};
    REQUIRE_EQ(rules.add_rule(1, 60, 1, RateLimitScope::Shard), 0);
    REQUIRE_EQ(rules.add_rule(1, 60, 1, RateLimitScope::Global), 1);
    RateLimitKeyInput input{};
    input.peer_addr = 1;
    const u64 ids[] = {1, 2, 0, 0};

    auto accepted = rate_limit_decision_with_limiters(shard, &global, rules, ids, input, 1000);
    CHECK(accepted.allowed);
    CHECK_EQ(accepted.rules_evaluated_by_scope[0], 1u);
    CHECK_EQ(accepted.rules_evaluated_by_scope[1], 1u);
    CHECK_EQ(accepted.rules_rejected_by_scope_reason[0][0], 0u);
    CHECK_EQ(accepted.rules_rejected_by_scope_reason[1][0], 0u);

    auto rejected = rate_limit_decision_with_limiters(shard, &global, rules, ids, input, 1000);
    CHECK(!rejected.allowed);
    CHECK_EQ(rejected.rules_evaluated_by_scope[0], 1u);
    CHECK_EQ(rejected.rules_evaluated_by_scope[1], 1u);
    CHECK_EQ(rejected.rules_rejected_by_scope_reason[0][0], 1u);
    CHECK_EQ(rejected.rules_rejected_by_scope_reason[1][0], 1u);

    const auto preflight =
        rate_limit_decision_with_limiters(shard, nullptr, rules, ids, input, 1000);
    CHECK(!preflight.allowed);
    CHECK_EQ(preflight.rules_evaluated_by_scope[0], 0u);
    CHECK_EQ(preflight.rules_evaluated_by_scope[1], 0u);
    CHECK_EQ(preflight.rules_rejected_by_scope_reason[0][0], 0u);
    CHECK_EQ(preflight.rules_rejected_by_scope_reason[1][0], 0u);

    const auto missing_id = rate_limit_decision_with_limiters(
        shard, &global, rules, static_cast<const u64*>(nullptr), input, 1000);
    CHECK(!missing_id.allowed);
    CHECK_EQ(missing_id.rules_evaluated_by_scope[0], 0u);
    CHECK_EQ(missing_id.rules_evaluated_by_scope[1], 0u);

    RateLimitRuleSet disabled{};
    REQUIRE_EQ(disabled.add_rule(0, 60, 1, RateLimitScope::Global), 0);
    const auto disabled_decision =
        rate_limit_decision_with_limiters(shard, nullptr, disabled, ids, input, 1000);
    CHECK(disabled_decision.allowed);
    CHECK_EQ(disabled_decision.rules_evaluated_by_scope[0], 0u);
    CHECK_EQ(disabled_decision.rules_evaluated_by_scope[1], 0u);
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

TEST(rate_limit_decision, reports_wait_reason_and_unknown_fail_closed) {
    RateLimiter shard{};
    RateLimitRuleSet rules{};
    REQUIRE_EQ(rules.add_rule(1, 60, 1), 0);
    RateLimitKeyInput input{};
    const auto accepted =
        rate_limit_decision_with_limiters(shard, nullptr, rules, kTestRateLimitIds, input, 1000);
    CHECK(accepted.allowed);
    CHECK(accepted.retry_known);
    CHECK_EQ(accepted.next_wait_us, 60'000'000ull);
    const auto rejected =
        rate_limit_decision_with_limiters(shard, nullptr, rules, kTestRateLimitIds, input, 1000);
    CHECK(!rejected.allowed);
    CHECK(rejected.retry_known);
    CHECK_EQ(rejected.reject_reason, RateLimitRejectReason::Budget);
    CHECK_EQ(rejected.next_wait_us, 60'000'000ull);

    const u64 missing[] = {0, 0, 0, 0};
    const auto missing_id =
        rate_limit_decision_with_limiters(shard, nullptr, rules, missing, input, 1000);
    CHECK(!missing_id.allowed);
    CHECK(!missing_id.retry_known);
    CHECK_EQ(missing_id.reject_reason, RateLimitRejectReason::MissingSemanticId);
}

TEST(rate_limit_decision, finite_collision_wait_and_overflow_unknown) {
    RateLimiter shard{};
    REQUIRE(shard.allow_key(1, 10, 20, 1000));
    const auto collision = shard.allow_key_detailed(131, 10, 20, 1000);
    CHECK(!collision.allowed);
    CHECK(collision.retry_known);
    CHECK_EQ(collision.reject_reason, RateLimitRejectReason::ShardCollision);
    CHECK_EQ(collision.next_wait_us, 10ull);

    constexpr u64 kMax = 0xffffffffffffffffull;
    RateLimiter overflow{};
    REQUIRE(overflow.allow_key(kTestRateLimitIds[0], 1, 0, kMax - 1));
    const auto result = overflow.allow_key_detailed(kTestRateLimitIds[0], 10, 0, kMax);
    CHECK(!result.allowed);
    CHECK(!result.retry_known);
    CHECK_EQ(result.reject_reason, RateLimitRejectReason::StateOverflow);
}

TEST(rate_limit_decision, stacked_post_charge_wait_dominates_global_rejection) {
    RateLimiter shard{};
    GlobalRateLimiter global{};
    global.reset();
    RateLimitRuleSet rules{};
    REQUIRE_EQ(rules.add_rule(1, 60, 1, RateLimitScope::Shard), 0);
    REQUIRE_EQ(rules.add_rule(60, 60, 1, RateLimitScope::Global), 1);
    RateLimitKeyInput input{};
    // Consume only the short global budget first. The shard rule remains fresh.
    const u64 global_key = rate_limit_key(
        kTestRateLimitIds[1], rules.rules[1].key.comps, rules.rules[1].key.count, input);
    REQUIRE(global.allow_key(global_key, 1'000'000, 0, 1000));
    const auto decision =
        rate_limit_decision_with_limiters(shard, &global, rules, kTestRateLimitIds, input, 1000);
    CHECK(!decision.allowed);
    CHECK(decision.retry_known);
    CHECK_EQ(decision.reject_reason, RateLimitRejectReason::Budget);
    // The accepted shard rule's 60-second post-charge wait dominates the
    // rejected global rule's one-second recovery wait.
    CHECK_EQ(decision.next_wait_us, 60'000'000ull);
}

TEST(rate_limit_decision, retry_after_uses_integer_second_ceiling) {
    char value[20];
    const u32 n = rate_limit_retry_after_value(1'000'001, value);
    CHECK_EQ(n, 1u);
    CHECK_EQ(value[0], '2');
    CHECK_EQ(rate_limit_retry_after_value(0, value), 1u);
    CHECK_EQ(value[0], '0');
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
