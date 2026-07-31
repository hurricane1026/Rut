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
                                              u64 config_generation,
                                              u32 route_idx,
                                              const RateLimitKeyInput& key_in,
                                              u64 now_us) {
    if (rules.count == 0) return false;
    for (u32 ri = 0; ri < rules.count; ri++) {
        const RateLimitRule& rule = rules.rules[ri];
        const u32 kScope = route_idx * kMaxRateLimitRules + ri;
        const u64 kNamespace = rule.identity != 0
                                   ? rule.identity
                                   : (config_generation << 32u) ^
                                         static_cast<u64>(route_idx * kMaxRateLimitRules + ri);
        // A lowered rule identity already names the declaration independently
        // of its current numeric route index. Keep the request-component hash
        // index-free as well so route insertion/reordering cannot reset a
        // compatible bucket. Legacy identity-less rules retain the old scope.
        const u64 kKey =
            rate_limit_key(rule.identity != 0 ? 0 : kScope, rule.key.comps, rule.key.count, key_in);
        const u64 kNamespacedKey =
            kKey ^ (kNamespace + 0x9e3779b97f4a7c15ull + (kKey << 6u) + (kKey >> 2u));
        const bool kOk = (rule.scope == RateLimitScope::Global && global_rate_limiter != nullptr)
                             ? global_rate_limiter->allow_key(kNamespacedKey,
                                                              rule.emit_interval_us,
                                                              rule.tau_us,
                                                              now_us,
                                                              rule.migration_time_us)
                             : rate_limiter.allow_key(kNamespacedKey,
                                                      rule.emit_interval_us,
                                                      rule.tau_us,
                                                      now_us,
                                                      rule.migration_time_us);
        if (!kOk) return true;
    }
    return false;
}

// Returns true if the request exceeds any of the route's stacked rate-limit
// rules (the caller answers 429). A route may stack several rules; the request
// must pass every one, each metered by its own key tuple. The limiter is
// per-shard (one thread each), so a thread_local table needs no atomics. Both
// dispatch paths run on the same shard thread with the same Loop type, so they
// resolve to one shared limiter instance. Global-scope rules go to the
// process-shared GlobalRateLimiter when the loop exposes one; otherwise a global
// rule degrades to per-shard.
template <typename Loop>
bool rate_limit_exceeded(Loop* loop,
                         const RateLimitRuleSet& rules,
                         u64 config_generation,
                         u32 route_idx,
                         const RateLimitKeyInput& key_in,
                         u64 now_us) {
    static thread_local RateLimiter rate_limiter{};
    GlobalRateLimiter* grl = nullptr;
    if constexpr (requires { loop->global_rl; }) grl = loop->global_rl;
    return rate_limit_exceeded_with_limiters(
        rate_limiter, grl, rules, config_generation, route_idx, key_in, now_us);
}

}  // namespace rut
