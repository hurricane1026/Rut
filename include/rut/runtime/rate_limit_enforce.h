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

inline u32 rate_limit_retry_after_value(u64 wait_us, char* out) {
    u64 seconds = wait_us / 1'000'000ull;
    if (wait_us % 1'000'000ull != 0) seconds++;
    char reversed[20];
    u32 n = 0;
    do {
        reversed[n++] = static_cast<char>('0' + seconds % 10);
        seconds /= 10;
    } while (seconds != 0);
    for (u32 i = 0; i < n; i++) out[i] = reversed[n - 1 - i];
    return n;
}

inline bool rate_limit_reason_precedes(RateLimitRejectReason a, RateLimitRejectReason b) {
    auto rank = [](RateLimitRejectReason r) -> u8 {
        switch (r) {
            case RateLimitRejectReason::MissingSemanticId:
                return 6;
            case RateLimitRejectReason::MissingGlobal:
                return 5;
            case RateLimitRejectReason::StateOverflow:
                return 4;
            case RateLimitRejectReason::ShardCollision:
                return 3;
            case RateLimitRejectReason::Budget:
                return 2;
            case RateLimitRejectReason::None:
                return 0;
        }
        return 0;
    };
    return rank(a) > rank(b);
}

inline u32 rate_limit_reason_index(RateLimitRejectReason reason) {
    switch (reason) {
        case RateLimitRejectReason::Budget:
            return 0;
        case RateLimitRejectReason::ShardCollision:
            return 1;
        case RateLimitRejectReason::StateOverflow:
            return 2;
        case RateLimitRejectReason::MissingGlobal:
        case RateLimitRejectReason::MissingSemanticId:
        case RateLimitRejectReason::None:
            return 0;
    }
    return 0;
}

inline RateLimitDecision rate_limit_decision_with_limiters(RateLimiter& rate_limiter,
                                                           GlobalRateLimiter* global_rate_limiter,
                                                           const RateLimitRuleSet& rules,
                                                           const u64* rate_limit_ids,
                                                           const RateLimitKeyInput& key_in,
                                                           u64 now_us) {
    RateLimitDecision out{};
    if (rules.count == 0) return out;
    if (rate_limit_ids == nullptr) {
        out.allowed = false;
        out.retry_known = false;
        out.reject_reason = RateLimitRejectReason::MissingSemanticId;
        return out;
    }
    for (u32 ri = 0; ri < rules.count; ++ri) {
        if (rules.rules[ri].emit_interval_us != 0 && rate_limit_ids[ri] == 0) {
            out.allowed = false;
            out.retry_known = false;
            out.reject_reason = RateLimitRejectReason::MissingSemanticId;
            return out;
        }
    }
    if (global_rate_limiter == nullptr) {
        for (u32 ri = 0; ri < rules.count; ++ri) {
            if (rules.rules[ri].scope == RateLimitScope::Global &&
                rules.rules[ri].emit_interval_us != 0) {
                out.allowed = false;
                out.retry_known = false;
                out.reject_reason = RateLimitRejectReason::MissingGlobal;
                return out;
            }
        }
    }
    for (u32 ri = 0; ri < rules.count; ri++) {
        const RateLimitRule& rule = rules.rules[ri];
        if (rule.emit_interval_us == 0) continue;
        const u32 scope = rule.scope == RateLimitScope::Global ? 1u : 0u;
        out.rules_evaluated_by_scope[scope]++;
        const u64 key = rate_limit_key(rate_limit_ids[ri], rule.key.comps, rule.key.count, key_in);
        const RateLimitDecision current =
            rule.scope == RateLimitScope::Global
                ? global_rate_limiter->allow_key_detailed(
                      key, rule.emit_interval_us, rule.tau_us, now_us)
                : rate_limiter.allow_key_detailed(key, rule.emit_interval_us, rule.tau_us, now_us);
        if (current.next_wait_us > out.next_wait_us) out.next_wait_us = current.next_wait_us;
        if (!current.retry_known) out.retry_known = false;
        if (!current.allowed) {
            const u32 reason = rate_limit_reason_index(current.reject_reason);
            out.rules_rejected_by_scope_reason[scope][reason]++;
            out.allowed = false;
            if (out.reject_reason == RateLimitRejectReason::None ||
                rate_limit_reason_precedes(current.reject_reason, out.reject_reason))
                out.reject_reason = current.reject_reason;
        }
    }
    return out;
}

inline bool rate_limit_exceeded_with_limiters(RateLimiter& rate_limiter,
                                              GlobalRateLimiter* global_rate_limiter,
                                              const RateLimitRuleSet& rules,
                                              const u64* rate_limit_ids,
                                              const RateLimitKeyInput& key_in,
                                              u64 now_us) {
    return !rate_limit_decision_with_limiters(
                rate_limiter, global_rate_limiter, rules, rate_limit_ids, key_in, now_us)
                .allowed;
}

// Returns true if the request exceeds any of the route's stacked rate-limit
// rules (the caller answers 429). A route may stack several rules; the request
// must pass every one, each metered by its own key tuple. All active rules are
// evaluated: conforming rules consume budget even if another rule rejects the
// request. Rejected GCRA rules do not advance their own timestamp; no rule is
// refunded. Missing required shared state is a preflight failure, not a metered
// request attempt. The limiter is
// per-shard (one thread each), so the loop-owned table needs no atomics. Both
// dispatch paths run on the same shard thread and use the same Loop-owned
// limiter instance. Global-scope rules go to the
// process-shared GlobalRateLimiter. An active global rule without that shared
// instance fails closed (429) before any rule consumes budget. Disabled global
// rules need no instance.
template <typename Loop>
RateLimitDecision rate_limit_decision(Loop* loop,
                                      const RateLimitRuleSet& rules,
                                      const u64* rate_limit_ids,
                                      const RateLimitKeyInput& key_in,
                                      u64 now_us) {
    GlobalRateLimiter* grl = nullptr;
    if constexpr (requires { loop->global_rl; }) grl = loop->global_rl;
    return rate_limit_decision_with_limiters(
        loop->rate_limiter, grl, rules, rate_limit_ids, key_in, now_us);
}

template <typename Loop>
bool rate_limit_exceeded(Loop* loop,
                         const RateLimitRuleSet& rules,
                         const u64* rate_limit_ids,
                         const RateLimitKeyInput& key_in,
                         u64 now_us) {
    return !rate_limit_decision(loop, rules, rate_limit_ids, key_in, now_us).allowed;
}

}  // namespace rut
