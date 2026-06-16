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

// Where a rule's `max` applies. Shard (default): each per-core shard enforces
// `max` independently — fast, no coordination, but a client spread across shards
// gets up to max × shard_count (SO_REUSEPORT hashes connections by 4-tuple, so a
// client's connections fan out). Global: `max` is an approximate cluster-wide
// budget — each shard enforces ceil(max / shard_count) assuming clients spread
// evenly; tighter for few-connection clients, looser-exact only with even fan-out.
enum class RateLimitScope : u8 {
    Shard = 0,
    Global,
};

// One rate-limit rule: `max` requests per `window_sec`, metered by `key`, applied
// at `scope`. A route can stack several rules (one per @rateLimit) — a request
// must pass them all, so e.g. an anonymous per-IP cap and a higher per-API-key
// cap coexist.
struct RateLimitRule {
    u32 max = 0;
    u32 window_sec = 0;
    RateLimitScope scope = RateLimitScope::Shard;
    RateLimitKeySpec key{};
};

static constexpr u32 kMaxRateLimitRules = 4;

// The ordered rule list for a route + its length. POD (inline arrays) → one-line
// memberwise copy through the IR.
struct RateLimitRuleSet {
    RateLimitRule rules[kMaxRateLimitRules];
    u8 count = 0;

    // Append a rule; returns its index, or -1 if full.
    i32 add_rule(u32 max, u32 window_sec, RateLimitScope scope = RateLimitScope::Shard) {
        if (count >= kMaxRateLimitRules) return -1;
        rules[count].max = max;
        rules[count].window_sec = window_sec;
        rules[count].scope = scope;
        rules[count].key = RateLimitKeySpec{};
        return static_cast<i32>(count++);
    }
};

}  // namespace rut
