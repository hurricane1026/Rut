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

    void set_name(const char* s, u32 n) {
        if (n > kMaxName) n = kMaxName;
        name_len = static_cast<u8>(n);
        for (u32 i = 0; i < n; i++) name[i] = s[i];
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
        comps[count].kind = kind;
        comps[count].name_len = 0;
        if (kind != RateLimitKeyKind::Ip && name) comps[count].set_name(name, name_len);
        count++;
        return true;
    }
};

// Where a rule applies. Shard (default): each per-core shard enforces the rule
// independently — fast, no coordination, but a client spread across shards gets
// up to limit × shard_count (SO_REUSEPORT hashes connections by 4-tuple, so a
// client's connections fan out). Global: an exact cluster-wide cap via the shared
// GlobalRateLimiter (all shards advance one bucket).
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
    // Stable semantic identity assigned after route lowering. Compatible reloads
    // reuse the same limiter bucket; changed routes/rules receive a new one.
    u64 identity = 0;
    u32 max = 0;         // tokens per window (steady rate = max / window_sec)
    u32 window_sec = 0;  // refill window
    u32 burst = 0;       // bucket capacity; 0 in the spec means "default to max"
    RateLimitScope scope = RateLimitScope::Shard;
    u64 emit_interval_us = 0;  // µs between tokens (0 = rule disabled)
    u64 tau_us = 0;            // burst tolerance, in µs
    u64 window_us = 0;         // complete accounting horizon, in µs
    // Monotonic activation boundary used to translate predecessor GCRA history
    // when a compatible reload changes emit/tau. Zero means no migration is
    // required (or a hand-built rule that migrates at first observation).
    u64 migration_time_us = 0;
    RateLimitKeySpec key{};
};

static constexpr u32 kMaxRateLimitRules = 4;

// The ordered rule list for a route + its length. POD (inline arrays) → one-line
// memberwise copy through the IR.
struct RateLimitRuleSet {
    RateLimitRule rules[kMaxRateLimitRules];
    u8 count = 0;

    // Append a rule; returns its index, or -1 if full. `burst == 0` defaults the
    // bucket capacity to `max`. Precomputes the GCRA params so the hot path is
    // division-free: emit = window/max (µs per token), tau = (burst-1)·emit.
    i32 add_rule(u32 max,
                 u32 window_sec,
                 u32 burst = 0,
                 RateLimitScope scope = RateLimitScope::Shard) {
        if (count >= kMaxRateLimitRules) return -1;
        RateLimitRule& r = rules[count];
        r.max = max;
        r.window_sec = window_sec;
        r.burst = (burst == 0) ? max : burst;
        r.scope = scope;
        r.key = RateLimitKeySpec{};
        if (max > 0 && window_sec > 0) {
            u64 emit = static_cast<u64>(window_sec) * 1000000ull / max;
            if (emit == 0) emit = 1;  // clamp: extremely high rate → ~1 token/µs
            r.emit_interval_us = emit;
            r.tau_us = (r.burst > 0 ? static_cast<u64>(r.burst - 1) : 0) * emit;
            r.window_us = static_cast<u64>(window_sec) * 1000000ull;
        } else {
            r.emit_interval_us = 0;  // disabled
            r.tau_us = 0;
            r.window_us = 0;
        }
        return static_cast<i32>(count++);
    }
};

// True if any rule keys on a component that can ONLY be read from the request
// buffer (header / cookie). A caller that cannot supply a request buffer — e.g.
// an HTTP/2 request whose HTTP/1 synthesis overflowed its scratch buffer — must
// reject rather than meter with an empty buffer, which would extract every such
// component as empty and collapse distinct callers into one shared bucket.
// IP and route-param keys don't read the buffer; query keys fall back to the
// separately-supplied request path (RateLimitKeyInput::path) — so none of those
// force a reject.
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
