#pragma once

#include "rut/common/types.h"

// Rate-limit metering-key spec — the description of a route's "counting unit".
// Lives in common/ (types.h-only) so both the compiler IR layers (AST → HIR →
// MIR → RIR) and the runtime can carry it. The runtime-side value extraction
// lives in runtime/rate_limit_key.h, which includes this header.

namespace rut {

enum class RateLimitKeyKind : u8 {
    Ip = 0,  // client source address (default when no components are given)
    Header,  // request header value      — name = header name
    Query,   // query-string parameter    — name = param name
    Cookie,  // cookie value              — name = cookie name
    Param,   // route/path parameter      — name = param name
};

// One component of a composite key. `name` is an inline buffer (so the spec is a
// trivially-copyable POD with no external lifetime — safe across RCU config
// swaps and trivial to thread through the IR); unused for Ip.
struct RateLimitKeyComponent {
    static constexpr u32 kMaxName = 32;
    RateLimitKeyKind kind = RateLimitKeyKind::Ip;
    u8 name_len = 0;
    char name[kMaxName] = {};

    bool set_name(const char* s, u32 n) {
        if (n > kMaxName || (n != 0 && s == nullptr)) return false;
        name_len = static_cast<u8>(n);
        for (u32 i = 0; i < n; i++) name[i] = s[i];
        return true;
    }
};

static constexpr u32 kMaxRateLimitKeyComponents = 4;

// A whole metering key: the ordered component list + its length. A POD with an
// inline array, so default copy/move are memberwise (array included) — IR layers
// with hand-written special members copy it in one line.
struct RateLimitKeySpec {
    RateLimitKeyComponent comps[kMaxRateLimitKeyComponents];
    u8 count = 0;

    bool add(RateLimitKeyKind kind, const char* name, u32 name_len) {
        if (count >= kMaxRateLimitKeyComponents) return false;
        RateLimitKeyComponent component{};
        component.kind = kind;
        if (kind != RateLimitKeyKind::Ip && !component.set_name(name, name_len)) return false;
        comps[count++] = component;
        return true;
    }
};

// Where a rule applies. Shard (default): each per-core shard enforces the rule
// independently — fast, no coordination, but a client spread across shards gets
// up to limit × shard_count (SO_REUSEPORT hashes connections by 4-tuple, so a
// client's connections fan out). Global: a process-shared budget via
// GlobalRateLimiter (all shards advance the same slot; colliding keys share it).
enum class RateLimitScope : u8 {
    Shard = 0,
    Global,
};

// One token-bucket (GCRA) rate-limit rule, metered by `key`, applied at `scope`.
// `max` tokens refill per `window_sec`; `burst` is the bucket capacity (max
// instantaneous burst; defaults to `max` so an idle client may spend a whole
// window at once, but never the fixed-window 2× boundary doubling). The runtime
// uses the precomputed GCRA params (`emit_interval_us`, `tau_us`) — derived once
// here, so the hot path needs no division. A route can stack several rules (one
// per @rateLimit) — a request must pass them all (e.g. an anonymous per-IP cap
// and a higher per-API-key cap coexist).
struct RateLimitRule {
    u32 max = 0;         // tokens per window (steady rate = max / window_sec)
    u32 window_sec = 0;  // refill window
    u32 burst = 0;       // bucket capacity; 0 in the spec means "default to max"
    RateLimitScope scope = RateLimitScope::Shard;
    u64 emit_interval_us = 0;  // µs between tokens (0 = rule disabled)
    u64 tau_us = 0;            // burst tolerance, in µs
    RateLimitKeySpec key{};
};

// Rate-limit GCRA arithmetic is precomputed during configuration. Keep the
// interval exact (ceil rather than floor) so a configured window is never
// shortened, and reject a burst whose tolerance cannot be represented in u64.
inline u64 rate_limit_emit_interval_us(u32 max, u32 window_sec) {
    if (max == 0 || window_sec == 0) return 0;
    const u64 numerator = static_cast<u64>(window_sec) * 1000000ull;
    return (numerator + static_cast<u64>(max) - 1ull) / max;
}

inline bool rate_limit_params_representable(u32 max, u32 window_sec, u32 burst) {
    if (max == 0 || window_sec == 0) return true;  // disabled rule
    if (burst == 0) burst = max;
    const u64 emit = rate_limit_emit_interval_us(max, window_sec);
    return static_cast<u64>(burst - 1u) <= 0xffffffffffffffffull / emit;
}

static constexpr u32 kMaxRateLimitRules = 4;

// The ordered rule list for a route + its length. POD (inline arrays) → one-line
// memberwise copy through the IR.
struct RateLimitRuleSet {
    RateLimitRule rules[kMaxRateLimitRules];
    u8 count = 0;

    // Append a rule; returns its index, or -1 if full. `burst == 0` defaults the
    // bucket capacity to `max`. Precomputes the GCRA params so the hot path is
    // division-free: emit = ceil(window/max) (µs per token), tau = (burst-1)·emit.
    i32 add_rule(u32 max,
                 u32 window_sec,
                 u32 burst = 0,
                 RateLimitScope scope = RateLimitScope::Shard) {
        if (count >= kMaxRateLimitRules) return -1;
        if (!rate_limit_params_representable(max, window_sec, burst)) return -1;
        RateLimitRule& r = rules[count];
        r.max = max;
        r.window_sec = window_sec;
        r.burst = (burst == 0) ? max : burst;
        r.scope = scope;
        r.key = RateLimitKeySpec{};
        if (max > 0 && window_sec > 0) {
            const u64 emit = rate_limit_emit_interval_us(max, window_sec);
            r.emit_interval_us = emit;
            r.tau_us = (r.burst > 0 ? static_cast<u64>(r.burst - 1) : 0) * emit;
        } else {
            r.emit_interval_us = 0;  // disabled
            r.tau_us = 0;
        }
        return static_cast<i32>(count++);
    }
};

// True if any rule keys on a component that can ONLY be read from the request
// buffer (header / cookie). A caller that cannot supply a request buffer — e.g.
// an HTTP/2 request whose HTTP/1 synthesis overflowed its scratch buffer — must
// reject rather than meter with an empty buffer, which would extract every such
// component as empty and collapse distinct callers into one shared bucket.
// IP and route-param keys don't read the buffer; query keys may fall back to a
// separately-supplied request path (RateLimitKeyInput::path) only when its
// producer marks that path trusted (for example a validated HTTP/2 :path).
inline bool rate_limit_needs_req_buf(const RateLimitRuleSet& rs) {
    for (u8 i = 0; i < rs.count; i++) {
        const RateLimitKeySpec& k = rs.rules[i].key;
        for (u8 j = 0; j < k.count; j++) {
            switch (k.comps[j].kind) {
                case RateLimitKeyKind::Header:
                case RateLimitKeyKind::Cookie:
                    return true;
                default:
                    break;
            }
        }
    }
    return false;
}

}  // namespace rut
