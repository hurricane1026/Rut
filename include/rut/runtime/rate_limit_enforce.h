#pragma once

#include "rut/common/rate_limit_key_spec.h"  // RateLimitRule(Set), RateLimitScope, kMax…
#include "rut/common/types.h"
#include "rut/runtime/rate_limit.h"      // RateLimiter, GlobalRateLimiter
#include "rut/runtime/rate_limit_key.h"  // rate_limit_key, RateLimitKeyInput

// Shared @rateLimit enforcement. Factored out of the HTTP/1 dispatch so the
// HTTP/2 path enforces the same rules against the same per-shard buckets — a
// route protected with @rateLimit must meter and 429 identically over h1 and h2
// (otherwise a client can bypass the limit by negotiating ALPN h2 / h2c).

namespace rut {

inline bool rate_limit_exceeded_with_limiters(RateLimiter& rate_limiter,
                                              GlobalRateLimiter* global_rate_limiter,
                                              const RateLimitRuleSet& rules,
                                              u32 route_idx,
                                              const RateLimitKeyInput& key_in,
                                              u64 now_us) {
    if (rules.count == 0) return false;
    // Validate shared state before spending any earlier shard-rule budget.
    if (global_rate_limiter == nullptr) {
        for (u32 ri = 0; ri < rules.count; ++ri) {
            const auto& rule = rules.rules[ri];
            if (rule.scope == RateLimitScope::Global && rule.emit_interval_us != 0) return true;
        }
    }
    bool exceeded = false;
    for (u32 ri = 0; ri < rules.count; ri++) {
        const RateLimitRule& rule = rules.rules[ri];
        if (rule.emit_interval_us == 0) continue;
        const u32 kScope = route_idx * kMaxRateLimitRules + ri;
        const u64 kKey = rate_limit_key(kScope, rule.key.comps, rule.key.count, key_in);
        const bool kOk =
            (rule.scope == RateLimitScope::Global)
                ? global_rate_limiter->allow_key(kKey, rule.emit_interval_us, rule.tau_us, now_us)
                : rate_limiter.allow_key(kKey, rule.emit_interval_us, rule.tau_us, now_us);
        // Every active rule meters the attempt, even after another rejects it.
        if (!kOk) exceeded = true;
    }
    return exceeded;
}

// Returns true if the request exceeds any of the route's stacked rate-limit
// rules (the caller answers 429). A route may stack several rules; the request
// must pass every one, each metered by its own key tuple. All active rules are
// evaluated: conforming rules consume budget even if another rule rejects the
// request. Rejected GCRA rules do not advance their own timestamp; no rule is
// refunded. Missing required shared state is a preflight failure, not a metered
// request attempt. The limiter is
// per-shard (one thread each), so a thread_local table needs no atomics. Both
// dispatch paths run on the same shard thread with the same Loop type, so they
// resolve to one shared limiter instance. Global-scope rules go to the
// process-shared GlobalRateLimiter. An active global rule without that shared
// instance fails closed (429) before any rule consumes budget. Disabled global
// rules need no instance.
template <typename Loop>
bool rate_limit_exceeded(Loop* loop,
                         const RateLimitRuleSet& rules,
                         u32 route_idx,
                         const RateLimitKeyInput& key_in,
                         u64 now_us) {
    static thread_local RateLimiter rate_limiter{};
    GlobalRateLimiter* grl = nullptr;
    if constexpr (requires { loop->global_rl; }) grl = loop->global_rl;
    return rate_limit_exceeded_with_limiters(rate_limiter, grl, rules, route_idx, key_in, now_us);
}

}  // namespace rut
