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
                         u32 route_idx,
                         const RateLimitKeyInput& key_in,
                         u64 now_us) {
    if (rules.count == 0) return false;
    static thread_local RateLimiter rate_limiter{};
    GlobalRateLimiter* grl = nullptr;
    if constexpr (requires { loop->global_rl; }) grl = loop->global_rl;
    for (u32 ri = 0; ri < rules.count; ri++) {
        const RateLimitRule& rule = rules.rules[ri];
        // Fold the rule index into the key scope so stacked rules never share a
        // counter even when their key components overlap.
        const u32 kScope = route_idx * kMaxRateLimitRules + ri;
        const u64 kKey = rate_limit_key(kScope, rule.key.comps, rule.key.count, key_in);
        const bool kOk =
            (rule.scope == RateLimitScope::Global && grl != nullptr)
                ? grl->allow_key(kKey, rule.emit_interval_us, rule.tau_us, now_us)
                : rate_limiter.allow_key(kKey, rule.emit_interval_us, rule.tau_us, now_us);
        if (!kOk) return true;
    }
    return false;
}

}  // namespace rut
