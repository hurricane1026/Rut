#pragma once

#include "core/expected.h"
#include "rut/common/failure_policy.h"
#include "rut/common/forward_preflight.h"
#include "rut/common/forward_target_transform.h"
#include "rut/common/http_header_validation.h"
#include "rut/common/redirect_policy.h"
#include "rut/common/response_policy.h"
#include "rut/common/strict_local_response.h"
#include "rut/common/types.h"
#include "rut/jit/art_jit_codegen.h"  // ArtJitMatchFn typedef (LLVM-free)
#include "rut/jit/handler_abi.h"
#include "rut/runtime/error.h"
#include "rut/runtime/rate_limit_key.h"
#include "rut/runtime/route_art.h"
#include "rut/runtime/route_canon.h"   // canonicalize_request
#include "rut/runtime/route_select.h"  // path_has_param_segment
#include "rut/runtime/route_trie.h"
#include "rut/runtime/ws_terminate.h"  // WsMessageHandlerFn (terminate-mode routes)

#include <errno.h>
#include <netinet/in.h>
#include <string.h>

namespace rut {

namespace rir {
struct Module;
}

struct RouteConfig;
bool register_jit_routes(RouteConfig& cfg, const rir::Module& mod, jit::JitEngine& engine);

enum class ExactStrictLocalResponseMatchState : u8 {
    InvalidInput = 0,
    Miss = 1,
    Match = 2,
};

struct ExactStrictLocalResponseMatchResult {
    ExactStrictLocalResponseMatchState state = ExactStrictLocalResponseMatchState::InvalidInput;
    u16 policy_id = 0;
};

// Action for a matched route.
enum class RouteAction : u8 {
    Static,      // respond with fixed status (e.g., 200 OK, 404)
    Proxy,       // forward to upstream target
    JitHandler,  // invoke JIT-compiled handler, may yield for I/O/timer
};

// Upstream target — one named backend that may resolve to several
// address:port endpoints. Multiple endpoints enable per-shard round-robin
// load balancing; a single-endpoint upstream is just addr_count == 1.
struct UpstreamTarget {
    static constexpr u32 kMaxUpstreamNameLen = 32;
    static constexpr u32 kMaxBackends = 8;  // endpoints per upstream (LB pool)

    struct sockaddr_in addrs[kMaxBackends];
    u32 addr_count;
    // Short name for logging/debugging (e.g., "api-v1")
    char name[kMaxUpstreamNameLen];
    u32 name_len;
    // Max concurrent in-flight proxied requests to this backend (0 = unlimited).
    // Enforced cluster-wide via the shared UpstreamConcurrency gauge; over the
    // cap the runtime answers 503 before connecting.
    u32 max_inflight = 0;

    // Active health-check config from `health_check: { ... }` (data only — no
    // probing wired up yet). hc_enabled gates the rest; hc_path is the probe
    // path (NOT NUL-terminated; use hc_path_len), hc_interval_ms the probe
    // period, hc_expected_status the status that marks a backend healthy.
    bool hc_enabled = false;
    char hc_path[64];
    u32 hc_path_len = 0;
    u32 hc_interval_ms = 0;
    u16 hc_expected_status = 200;

    void set_name(const char* n) {
        name_len = 0;
        while (n[name_len] && name_len < sizeof(name) - 1) {
            name[name_len] = n[name_len];
            name_len++;
        }
        name[name_len] = '\0';
    }

    // Append a backend endpoint from IP (host order) + port (host order).
    // Returns false if the backend list is full.
    bool add_addr(u32 ip, u16 port) {
        if (addr_count >= kMaxBackends) return false;
        struct sockaddr_in& a = addrs[addr_count++];
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(ip);
        a.sin_port = htons(port);
        return true;
    }

    // Reset to a single backend endpoint (clears any existing list).
    void set_addr(u32 ip, u16 port) {
        addr_count = 0;
        add_addr(ip, port);
    }
};

// Single route entry: matches method + path prefix → action.
struct RouteEntry {
    static constexpr u32 kMaxPathLen = 128;

    // Match criteria
    char path[kMaxPathLen];  // path prefix (e.g., "/api/v1/")
    u32 path_len;
    u8 method;  // route method key: 0 = any, 1..9 = full HTTP method

    // Action
    RouteAction action;
    u16 upstream_id;              // index into RouteConfig::upstreams (if action == Proxy)
    u16 status_code;              // status code (if action == Static, e.g., 200, 404)
    jit::HandlerFn fn = nullptr;  // JIT-compiled handler (if action == JitHandler)
    bool needs_req_body = false;  // JIT handler reads req.body and needs the full body buffered
    // Per-route rate limit (fixed window). Empty rule set = unlimited. Each rule
    // allows `max` requests per `window_sec` metered by its own key (IP / header
    // / query / cookie / param tuple; empty key = per-client-IP). A request must
    // pass every rule, so stacked rules (one per @rateLimit) give different caps
    // per dimension — e.g. anonymous per-IP plus a higher per-API-key cap.
    RateLimitRuleSet rate_limit{};
    // Per-route client-send byte rate (bytes/sec, 0 = unlimited). The runtime
    // paces the response so it isn't sent faster than this.
    u32 throttle_down_bps = 0;
    // WebSocket TERMINATE mode (Proxy routes only). When `ws_terminate` is set, a 101
    // upgrade enters frame-inspection mode instead of the raw passthrough tunnel: each
    // reassembled message is handed to `ws_frame_handler` (forward/drop/close), bounded by
    // `ws_max_message_size`. Off (default) keeps the passthrough behavior.
    bool ws_terminate = false;
    WsMessageHandlerFn ws_frame_handler = nullptr;
    u32 ws_max_message_size = 0;
    // RFC 6455 status the handler's `frame.close(code)` verdict puts on the wire (1000 default).
    u16 ws_close_code = 1000;
    // Nonzero only for the bounded static direct-forward timeout preflight.
    // Resolves through the same pinned RouteConfig as this RouteEntry.
    ForwardPreflightMode forward_preflight_mode = ForwardPreflightMode::None;
    u16 preflight_forward_policy_bundle_id = 0;
};

// RouteConfig — immutable after construction, atomically swappable.
// Contains route entries + upstream targets. The entire config is replaced
// on hot reload (RCU pattern: new config built, atomic swap, old reclaimed).
//
// Phase 2: simple linear scan (adequate for <100 routes).
// Phase 3: radix trie from Rutlang compiler (O(path_length) lookup).
struct RouteConfig {
    static constexpr u32 kMaxRoutes = 128;
    static constexpr u32 kMaxUpstreams = 64;
    // Response-body table. Populated at compile/config time; referenced
    // by JIT handlers via a 1-based index packed into
    // HandlerResult.upstream_id for ReturnStatus (0 = no custom body,
    // use the default status reason phrase).
    static constexpr u32 kMaxResponseBodies = 128;
    static constexpr u32 kResponseBodyPoolBytes = 8 * 1024;
    // Response-headers tables. Parallel to response_bodies but
    // independently indexed (JIT handlers pack a separate `headers_idx`
    // into HandlerResult.next_state for ReturnStatus, 0 = no custom
    // headers). All (key, value) pairs across every set share one flat
    // pool; each set is an (offset, count) slice into it. Header bytes
    // live in a single char pool so they outlive the RouteConfig's
    // RCU lifetime the same way body_pool does.
    static constexpr u32 kMaxResponseHeaderSets = 128;
    static constexpr u32 kMaxHeaderPoolEntries = 512;
    static constexpr u32 kResponseHeaderBytesPoolBytes = 8 * 1024;
    // Response-policy metadata is copied into this config-owned pool so the
    // compiler/RIR arena can be reclaimed after activation. IDs are 1-based;
    // zero is transparent forwarding.
    static constexpr u32 kMaxResponsePolicies = rut::kMaxResponsePolicies;
    static constexpr u32 kResponsePolicyBytesPoolBytes = 4 * 1024;
    static constexpr u32 kMaxForwardPolicyBundles = kMaxForwardFailurePolicies;
    static constexpr u32 kFailurePolicyBytesPoolBytes = 8 * 1024;
    static constexpr u32 kMaxRedirectPolicies = rut::kMaxRedirectPolicies;
    static constexpr u32 kRedirectPolicyBytesPoolBytes = rut::kRedirectPolicyBytes;
    static constexpr u32 kMaxStrictLocalResponsePolicies = rut::kMaxStrictLocalResponsePolicies;
    static constexpr u32 kStrictLocalResponseBytesPoolBytes =
        rut::kMaxStrictLocalResponsePolicyBytes;
    // Per-response cap for header count. Bigger than what the AST
    // permits (16) so hand-built RouteConfigs — tests, future
    // compile→config helper — have headroom, but small enough that the
    // dispatch code can materialise a stack-local KV array without
    // any risk of silent truncation. Must match the buffer size used
    // by handle_jit_outcome in callbacks_impl.h.
    static constexpr u32 kMaxHeadersPerSet = 32;
    // Firewall IPv4 rule caps. Small fixed arrays keep match checks
    // branch-predictable and allocation-free on the hot path.
    static constexpr u32 kMaxFirewallRules = 64;

    // Non-copyable: the embedded `trie` stores non-owning Str views
    // pointing into routes[].path. A by-value copy would leave the
    // copy's trie referencing the original's path buffers — a use-
    // after-free as soon as the original is modified or destroyed.
    // RouteConfig is published via `const RouteConfig*` for RCU swap;
    // there's no production codepath that needs to copy one.
    RouteConfig() = default;
    RouteConfig(const RouteConfig&) = delete;
    RouteConfig& operator=(const RouteConfig&) = delete;

    RouteEntry routes[kMaxRoutes];
    u32 route_count = 0;

    // Phase 2 dispatch — 2-way tagged union.
    //
    // Pre-add_*: caller picks ArtJit (default) or SegmentTrie via
    // use_art() / use_segment_trie(). Refused once route_count > 0
    // (the chosen state struct's already been populated, swapping
    // would leave the new state empty).
    //
    // Post-add_* for ArtJit configs: caller calls install_art_jit_fn
    // with a JIT-specialized match function (see
    // jit/art_jit_codegen.h). Until installed, ArtJit dispatch falls
    // back to scalar ART::match — slower but correct.
    //
    // For SegmentTrie configs no install step is needed; trie.match
    // runs as soon as add_* finishes populating the trie.
    enum class DispatchKind : u8 {
        ArtJit,       // ART byte-prefix trie, optionally JIT-specialized
        SegmentTrie,  // segment-aware trie (boundary-sensitive overlap;
                      //   the only correct choice when
                      //   needs_segment_aware() returns true).
                      //   `:param` route paths are supported here for
                      //   dynamic segments and request-time capture.
    };

    DispatchKind dispatch_kind() const { return dispatch_kind_; }

    // Caller-side dispatch picker. Must be called BEFORE the first
    // add_*. Returns false if a route has already been added (the
    // existing state would be lost on a swap).
    bool use_art() {
        if (route_count > 0) return false;
        dispatch_kind_ = DispatchKind::ArtJit;
        return true;
    }
    bool use_segment_trie() {
        if (route_count > 0) return false;
        dispatch_kind_ = DispatchKind::SegmentTrie;
        return true;
    }

    // Install a JIT-specialized match function. Caller invokes
    // jit::art_jit_specialize(engine, cfg.art_state, name) after
    // all add_* calls have populated art_state, then passes the
    // returned function pointer here. After install, RouteConfig::
    // match() calls the JIT'd function directly instead of ART's
    // scalar descent. Idempotent: replaces any previously-installed
    // pointer.
    void install_art_jit_fn(jit::ArtJitMatchFn fn) { art_jit_fn_ = fn; }

    // Segment-aware radix trie. Populated by add_* when dispatch_kind_
    // == SegmentTrie. ~1.2 MB inline.
    RouteTrie trie;
    static_assert(kMaxRoutes == TrieNode::kMaxChildren,
                  "RouteConfig::kMaxRoutes must equal TrieNode::kMaxChildren so a config "
                  "whose routes all share a single parent fits the trie's per-node fan-out.");

    // Adaptive Radix Tree — byte-prefix matching with adaptive node
    // sizing (Node4/16/48/256). ~35 KB inline at the current pool
    // caps — see route_art.h's pool-cap comment for the breakdown.
    // Populated by add_*
    // when dispatch_kind_ == ArtJit. After population, caller can
    // JIT-specialize match() via install_art_jit_fn for a ~5x
    // speedup on saas-shaped configs (PR #50 round 2 bench).
    ArtTrie art_state;

    UpstreamTarget upstreams[kMaxUpstreams];
    u32 upstream_count = 0;

    // Background periodic tasks: `timer name, every: D {...}`. Each holds the
    // compiled handler + interval; the shard event loop fires them on schedule
    // (they are NOT matched against requests). Slice 1: bodies are no-ops, so this
    // exercises the scheduling/compile path only.
    static constexpr u32 kMaxTimers = 16;
    struct TimerEntry {
        char name[32];
        u32 name_len = 0;
        jit::HandlerFn fn = nullptr;
        u32 interval_ms = 0;
        // `shard: N` — fire on that shard only; -1 = every shard (default).
        i32 shard = -1;
    };
    TimerEntry timers[kMaxTimers];
    u32 timer_count = 0;

    // A shard-pinned timer whose selector is >= the configured shard count can
    // never fire (fire_due_timers only matches selector == shard_id). Called at
    // startup so a dead singleton fails fast instead of serving silently.
    // Returns the offending timer index, or -1 if all selectors are in range.
    i32 first_out_of_range_timer_shard(u32 shard_count) const {
        const u32 n = timer_count < kMaxTimers ? timer_count : kMaxTimers;
        for (u32 i = 0; i < n; i++) {
            if (timers[i].shard >= 0 && static_cast<u32>(timers[i].shard) >= shard_count)
                return static_cast<i32>(i);
        }
        return -1;
    }

    bool add_timer(
        const char* name, u32 name_len, u32 interval_ms, jit::HandlerFn fn, i32 shard = -1) {
        if (timer_count >= kMaxTimers || fn == nullptr || interval_ms == 0) return false;
        TimerEntry& t = timers[timer_count];
        const u32 kN = name_len < sizeof(t.name) - 1 ? name_len : sizeof(t.name) - 1;
        for (u32 i = 0; i < kN; i++) t.name[i] = name[i];
        t.name[kN] = '\0';
        t.name_len = kN;
        t.fn = fn;
        t.interval_ms = interval_ms;
        t.shard = shard;
        timer_count++;
        return true;
    }

    // Cache<K, i64> instance descriptors from top-level `let x = Cache<IP,
    // i64>(capacity: N)` declarations (docs/language-card.md, Cache section). Declarative
    // only — the per-shard slot tables live in thread_local storage inside
    // the cache helpers; the loader publishes these descriptors to the
    // process CacheRegistry when the config is activated.
    static constexpr u32 kMaxCacheInstances = 8;
    static constexpr u32 kMaxCacheCapacity = 1u << 22;
    struct CacheInstanceEntry {
        char name[32];
        u32 name_len = 0;
        u32 capacity = 0;
    };
    CacheInstanceEntry cache_instances[kMaxCacheInstances];
    u32 cache_instance_count = 0;

    bool add_cache_instance(const char* name, u32 name_len, u32 capacity) {
        if (cache_instance_count >= kMaxCacheInstances || capacity == 0 ||
            capacity > kMaxCacheCapacity)
            return false;
        // The stored name is the hot-reload identity (hashed by
        // cache_registry_publish_config) — reject rather than truncate, or
        // two names sharing the first 31 bytes would silently share state.
        // The frontend enforces the same bound; this guards direct callers.
        if (name_len >= sizeof(CacheInstanceEntry{}.name)) return false;
        for (u32 i = 0; i < cache_instance_count; i++) {
            const CacheInstanceEntry& e = cache_instances[i];
            if (e.name_len == name_len) {
                bool same = true;
                for (u32 c = 0; c < name_len; c++) {
                    if (e.name[c] != name[c]) {
                        same = false;
                        break;
                    }
                }
                if (same) return false;  // duplicate name
            }
        }
        CacheInstanceEntry& e = cache_instances[cache_instance_count];
        const u32 kN = name_len < sizeof(e.name) - 1 ? name_len : sizeof(e.name) - 1;
        for (u32 i = 0; i < kN; i++) e.name[i] = name[i];
        e.name[kN] = '\0';
        e.name_len = kN;
        e.capacity = capacity;
        cache_instance_count++;
        return true;
    }

    // Firewall rules support source IPv4 exact, CIDR, inclusive range, and
    // source-port checks. IP values are packed host-order u32:
    //   ip = (a << 24) | (b << 16) | (c << 8) | d  for a.b.c.d
    // Connection.peer_addr is stored in network byte order; firewall_allows_peer
    // converts it once to the packed host-order representation before evaluation.
    // Evaluation order:
    //   1) deny exact IP / CIDR / range / port (any hit => reject)
    //   2) allow exact IP / CIDR / range / port (if any allow rules exist:
    //      require at least one hit)
    //   3) default allow/deny policy (applies only when allow tables are empty)
    u32 firewall_allow_ips[kMaxFirewallRules]{};
    u32 firewall_deny_ips[kMaxFirewallRules]{};
    u16 firewall_allow_ports[kMaxFirewallRules]{};
    u16 firewall_deny_ports[kMaxFirewallRules]{};
    struct FirewallCidrRule {
        u32 net_addr;
        u32 mask;
    };
    struct FirewallRangeRule {
        u32 start_ip;
        u32 end_ip;
    };
    enum class FirewallDecision : u8 {
        AllowedDefault = 0,
        AllowedByIp = 1,
        AllowedByCidr = 2,
        AllowedByPort = 3,
        AllowedByRange = 4,
        DeniedByIp = 5,
        DeniedByCidr = 6,
        DeniedByPort = 7,
        DeniedByRange = 8,
        DeniedByMissingAllowMatch = 9,
    };
    static bool firewall_decision_is_allow(FirewallDecision d) {
        switch (d) {
            case FirewallDecision::AllowedDefault:
            case FirewallDecision::AllowedByIp:
            case FirewallDecision::AllowedByCidr:
            case FirewallDecision::AllowedByPort:
            case FirewallDecision::AllowedByRange:
                return true;
            case FirewallDecision::DeniedByIp:
            case FirewallDecision::DeniedByCidr:
            case FirewallDecision::DeniedByPort:
            case FirewallDecision::DeniedByRange:
            case FirewallDecision::DeniedByMissingAllowMatch:
                return false;
        }
        return false;
    }
    static bool firewall_decision_is_deny(FirewallDecision d) {
        return !firewall_decision_is_allow(d);
    }
    static const char* firewall_decision_name(FirewallDecision d) {
        switch (d) {
            case FirewallDecision::AllowedDefault:
                return "allowed_default";
            case FirewallDecision::AllowedByIp:
                return "allowed_by_ip";
            case FirewallDecision::AllowedByCidr:
                return "allowed_by_cidr";
            case FirewallDecision::AllowedByPort:
                return "allowed_by_port";
            case FirewallDecision::AllowedByRange:
                return "allowed_by_range";
            case FirewallDecision::DeniedByIp:
                return "denied_by_ip";
            case FirewallDecision::DeniedByCidr:
                return "denied_by_cidr";
            case FirewallDecision::DeniedByPort:
                return "denied_by_port";
            case FirewallDecision::DeniedByRange:
                return "denied_by_range";
            case FirewallDecision::DeniedByMissingAllowMatch:
                return "denied_by_missing_allow_match";
        }
        return "unknown";
    }
    FirewallCidrRule firewall_allow_cidrs[kMaxFirewallRules]{};
    FirewallCidrRule firewall_deny_cidrs[kMaxFirewallRules]{};
    FirewallRangeRule firewall_allow_ranges[kMaxFirewallRules]{};
    FirewallRangeRule firewall_deny_ranges[kMaxFirewallRules]{};
    u32 firewall_allow_count = 0;
    u32 firewall_deny_count = 0;
    u32 firewall_allow_cidr_count = 0;
    u32 firewall_deny_cidr_count = 0;
    u32 firewall_allow_range_count = 0;
    u32 firewall_deny_range_count = 0;
    u32 firewall_allow_port_count = 0;
    u32 firewall_deny_port_count = 0;
    bool firewall_default_allow = true;

    // Reject route paths that aren't in origin-form. Required by the
    // segment trie (which would otherwise silently mismatch malformed
    // configs); the linear-scan default tolerates any string but
    // applying the same gate uniformly keeps add_* semantics
    // consistent across dispatch choices.
    //   - Must be non-null, non-empty, and start with '/'. An empty
    //     string and "api" without a leading slash are rejected
    //     rather than implicitly normalized — the trie's root and
    //     "/api" terminal would otherwise collide silently.
    //   - Must not contain '?' or '#': those mark query/fragment in a
    //     URI and routing doesn't match on them. RouteTrie::match()
    //     strips them from incoming requests.
    //   - Must terminate within kMaxPathLen.
    static bool is_routable_path(const char* path) {
        if (path == nullptr || path[0] != '/') return false;
        for (u32 i = 0; i < RouteEntry::kMaxPathLen; i++) {
            const char ch = path[i];
            if (ch == '\0') return true;
            if (ch == '?' || ch == '#') return false;
        }
        return false;
    }

    // Body entries point into body_pool; pool is a bump-allocated char
    // buffer so body bytes live alongside the config and get reclaimed
    // with it during RCU swap.
    struct ResponseBody {
        const char* data;
        u32 len;
    };
    ResponseBody response_bodies[kMaxResponseBodies];
    u32 response_body_count = 0;
    char body_pool[kResponseBodyPoolBytes];
    u32 body_pool_used = 0;

    // Header entries point into header_bytes_pool; the pool is a
    // bump-allocated char buffer shared by all keys and values. Each
    // pair-entry lives in header_keys[] / header_values[] with pointers
    // into the bytes pool; each response's header set is a slice of
    // those arrays described by HeaderSetRef.
    struct HeaderEntry {
        const char* data;
        u32 len;
    };
    struct HeaderSetRef {
        u16 offset;  // into header_keys / header_values
        u16 count;
    };
    HeaderEntry header_keys[kMaxHeaderPoolEntries];
    HeaderEntry header_values[kMaxHeaderPoolEntries];
    u32 header_pool_used = 0;
    HeaderSetRef response_header_sets[kMaxResponseHeaderSets];
    u32 response_header_set_count = 0;
    char header_bytes_pool[kResponseHeaderBytesPoolBytes];
    u32 header_bytes_pool_used = 0;
    ForwardResponsePolicySpec response_policies[kMaxResponsePolicies]{};
    u32 response_policy_count = 0;
    char response_policy_bytes[kResponsePolicyBytesPoolBytes];
    u32 response_policy_bytes_used = 0;
    ForwardFailurePolicySpec failure_policies[kMaxForwardFailurePolicies]{};
    u32 failure_policy_count = 0;
    char failure_policy_bytes[kFailurePolicyBytesPoolBytes];
    u32 failure_policy_bytes_used = 0;
    ForwardPolicyBundle policy_bundles[kMaxForwardPolicyBundles]{};
    u32 policy_bundle_count = 0;
    ForwardTargetTransformSpec target_transforms[kMaxForwardTargetTransforms]{};
    u32 target_transform_count = 0;
    char target_transform_bytes[kForwardTargetTransformBytes];
    u32 target_transform_bytes_used = 0;
    RedirectPolicySpec redirect_policies[kMaxRedirectPolicies]{};
    u32 redirect_policy_count = 0;
    char redirect_policy_bytes[kRedirectPolicyBytesPoolBytes];
    u32 redirect_policy_bytes_used = 0;
    StrictLocalResponsePolicySpec strict_local_response_policies[kMaxStrictLocalResponsePolicies]{};
    u32 strict_local_response_policy_count = 0;
    // Concrete-method responses selected before exact/prefix/unmatched routing.
    // Slot zero (ANY) is reserved and must remain neutral.
    u16 pre_route_policy_ids[kStrictLocalResponseMethodSlots]{};
    u16 unmatched_policy_ids[kStrictLocalResponseMethodSlots]{};
    ExactStrictLocalResponseBinding
        exact_strict_local_response_bindings[kMaxExactStrictLocalResponseBindings]{};
    u32 exact_strict_local_response_binding_count = 0;
    char strict_local_response_bytes[kStrictLocalResponseBytesPoolBytes];
    u32 strict_local_response_bytes_used = 0;

    bool has_strict_local_response_policy_inventory() const {
        return strict_local_response_policy_count != 0 || strict_local_response_bytes_used != 0;
    }

    bool has_pre_route_metadata() const {
        for (u32 i = 0; i < kStrictLocalResponseMethodSlots; i++)
            if (pre_route_policy_ids[i] != 0) return true;
        return false;
    }

    // This is selector metadata, not the shared policy inventory. A policy
    // pool owned solely by pre-route/exact selectors must not turn a route miss
    // into a configured unmatched response.
    bool has_unmatched_metadata() const {
        for (u32 i = 0; i < kStrictLocalResponseMethodSlots; i++)
            if (unmatched_policy_ids[i] != 0) return true;
        return false;
    }

    bool has_exact_strict_local_response_inventory() const {
        return exact_strict_local_response_inventory_present(
            exact_strict_local_response_bindings, exact_strict_local_response_binding_count);
    }

    bool has_strict_local_response_table_inventory() const {
        return has_strict_local_response_policy_inventory() || has_pre_route_metadata() ||
               has_unmatched_metadata() || has_exact_strict_local_response_inventory();
    }

    bool strict_local_response_bytes_owned(Str value) const {
        const uintptr_t begin = reinterpret_cast<uintptr_t>(strict_local_response_bytes);
        const uintptr_t ptr = reinterpret_cast<uintptr_t>(value.ptr);
        if (value.len == 0)
            return value.ptr != nullptr && ptr >= begin &&
                   ptr - begin <= strict_local_response_bytes_used;
        if (value.ptr == nullptr || value.len > strict_local_response_bytes_used) return false;
        if (ptr < begin || ptr - begin >= strict_local_response_bytes_used) return false;
        return value.len <= strict_local_response_bytes_used - static_cast<u32>(ptr - begin);
    }

    // Complete runtime validation. Source policy IDs may collapse under stable
    // semantic dedup during installation, so runtime ownership requires every
    // owned policy to be referenced at least once (rather than exactly once).
    // Validate counts/mappings before indexing, then require every byte view
    // and exact path to live inside this RouteConfig.
    bool strict_local_response_table_is_valid() const {
        if (strict_local_response_policy_count > kMaxStrictLocalResponsePolicies ||
            strict_local_response_bytes_used > kStrictLocalResponseBytesPoolBytes ||
            exact_strict_local_response_binding_count > kMaxExactStrictLocalResponseBindings)
            return false;
        bool referenced[kMaxStrictLocalResponsePolicies]{};
        for (u32 i = 0; i < strict_local_response_policy_count; i++) {
            const auto& policy = strict_local_response_policies[i];
            if (!strict_local_response_bytes_owned(policy.reason) ||
                !strict_local_response_bytes_owned(policy.content_type) ||
                !strict_local_response_bytes_owned(policy.server) ||
                !strict_local_response_bytes_owned(policy.body))
                return false;
            if (!strict_local_response_policy_spec_valid(policy)) return false;
            for (u32 prior = 0; prior < i; prior++)
                if (strict_local_response_policy_spec_equal(strict_local_response_policies[prior],
                                                            policy))
                    return false;
        }
        if (pre_route_policy_ids[kRouteMethodAny] != 0) return false;
        for (u32 slot = 1; slot < kStrictLocalResponseMethodSlots; slot++) {
            const u16 id = pre_route_policy_ids[slot];
            if (id == 0) continue;
            if (id > strict_local_response_policy_count) return false;
            if (slot == kRouteMethodHead && strict_local_response_policies[id - 1].head_mode !=
                                                StrictLocalResponseHeadMode::SuppressBody)
                return false;
            referenced[id - 1] = true;
        }
        for (u32 slot = 0; slot < kStrictLocalResponseMethodSlots; slot++) {
            const u16 id = unmatched_policy_ids[slot];
            if (id == 0) continue;
            if (id > strict_local_response_policy_count) return false;
            referenced[id - 1] = true;
        }
        const u16 any_id = unmatched_policy_ids[kRouteMethodAny];
        if (any_id != 0 && strict_local_response_policies[any_id - 1].head_mode !=
                               StrictLocalResponseHeadMode::SuppressBody)
            return false;
        const u16 head_id = unmatched_policy_ids[kRouteMethodHead];
        if (head_id != 0 && strict_local_response_policies[head_id - 1].head_mode !=
                                StrictLocalResponseHeadMode::SuppressBody)
            return false;
        for (u32 i = 0; i < kMaxExactStrictLocalResponseBindings; i++) {
            const auto& binding = exact_strict_local_response_bindings[i];
            if (i >= exact_strict_local_response_binding_count) {
                if (!exact_strict_local_response_binding_is_neutral(binding)) return false;
                continue;
            }
            if (!exact_strict_local_response_binding_shape_valid(binding) ||
                binding.policy_id > strict_local_response_policy_count)
                return false;
            const u32 slot = route_method_slot_from_key(binding.method);
            if (slot == kRouteMethodSlotInvalid) return false;
            if ((slot == kRouteMethodAny || slot == kRouteMethodHead) &&
                strict_local_response_policies[binding.policy_id - 1].head_mode !=
                    StrictLocalResponseHeadMode::SuppressBody)
                return false;
            for (u32 prior = 0; prior < i; prior++) {
                const auto& other = exact_strict_local_response_bindings[prior];
                if (binding.method == other.method && binding.path_view == other.path_view &&
                    binding.path_len == other.path_len &&
                    __builtin_memcmp(binding.path, other.path, binding.path_len) == 0)
                    return false;
            }
            referenced[binding.policy_id - 1] = true;
        }
        for (u32 i = 0; i < strict_local_response_policy_count; i++)
            if (!referenced[i]) return false;
        return true;
    }

    bool unmatched_policy_table_is_valid() const {
        return !has_pre_route_metadata() && !has_exact_strict_local_response_inventory() &&
               strict_local_response_table_is_valid();
    }

    u16 pre_route_policy_id(u8 method_key) const {
        const u32 slot = route_method_slot_from_key(method_key);
        if (slot == kRouteMethodSlotInvalid || slot == kRouteMethodAny ||
            !strict_local_response_table_is_valid())
            return 0;
        return pre_route_policy_ids[slot];
    }

    // Raw origin-form exact lookup. Query bytes are outside the selector; no
    // canonicalization is performed. Callers separately enforce the mandatory
    // full-target fragment witness before invoking this helper.
    u16 match_exact_strict_local_response(Str raw_target, u8 method_key) const {
        if (!strict_local_response_table_is_valid() || raw_target.ptr == nullptr ||
            raw_target.len == 0 || raw_target.ptr[0] != '/' || method_key == kRouteMethodInvalid ||
            method_key == kRouteMethodAny ||
            route_method_slot_from_key(method_key) == kRouteMethodSlotInvalid)
            return 0;
        auto match_method = [&](u8 wanted) -> u16 {
            for (u32 i = 0; i < exact_strict_local_response_binding_count; i++) {
                const auto& binding = exact_strict_local_response_bindings[i];
                if (binding.path_view != ExactPathView::Raw || binding.method != wanted ||
                    raw_target.len < binding.path_len)
                    continue;
                bool equal = true;
                for (u32 byte = 0; byte < binding.path_len; byte++)
                    equal &= raw_target.ptr[byte] == binding.path[byte];
                if (!equal) continue;
                if (raw_target.len == binding.path_len || raw_target.ptr[binding.path_len] == '?')
                    return binding.policy_id;
            }
            return 0;
        };
        const u16 exact = match_method(method_key);
        return exact != 0 ? exact : match_method(kRouteMethodAny);
    }

    // Exact strict-local lookup over two independently supplied selection
    // views. The caller owns storage provenance for both ranges and must supply
    // the complete raw target plus an already-computed slash-normalized,
    // path-only fixed point. This helper never allocates, normalizes, or mutates
    // either input. Invalid table/input state is distinct from a valid miss so a
    // caller can fail closed rather than silently continue to prefix routing.
    // Selection order is Raw concrete, SlashNormalized concrete, Raw ANY,
    // SlashNormalized ANY.
    ExactStrictLocalResponseMatchResult match_exact_strict_local_response_views(
        Str raw_target, Str slash_normalized_path, u8 method_key) const {
        const ExactStrictLocalResponseMatchResult invalid{
            ExactStrictLocalResponseMatchState::InvalidInput, 0};
        if (!strict_local_response_table_is_valid() || raw_target.ptr == nullptr ||
            raw_target.len == 0 || slash_normalized_path.ptr == nullptr ||
            slash_normalized_path.len == 0 ||
            slash_normalized_path.len > kMaxExactStrictLocalResponsePathLen ||
            method_key == kRouteMethodInvalid || method_key == kRouteMethodAny ||
            route_method_slot_from_key(method_key) == kRouteMethodSlotInvalid)
            return invalid;
        const uintptr_t raw_address = reinterpret_cast<uintptr_t>(raw_target.ptr);
        const uintptr_t normalized_address = reinterpret_cast<uintptr_t>(slash_normalized_path.ptr);
        if (raw_target.len > UINTPTR_MAX - raw_address ||
            slash_normalized_path.len > UINTPTR_MAX - normalized_address)
            return invalid;
        if (raw_target.ptr[0] != '/' || slash_normalized_path.ptr[0] != '/') return invalid;
        bool previous_slash = false;
        for (u32 i = 0; i < slash_normalized_path.len; i++) {
            const char byte = slash_normalized_path.ptr[i];
            const u8 unsigned_byte = static_cast<u8>(byte);
            if (byte == '?' || byte == '#' || unsigned_byte < 0x20 || unsigned_byte == 0x7f ||
                (byte == '/' && previous_slash))
                return invalid;
            previous_slash = byte == '/';
        }

        auto match = [&](ExactPathView view, u8 wanted) -> u16 {
            const Str target = view == ExactPathView::Raw ? raw_target : slash_normalized_path;
            for (u32 i = 0; i < exact_strict_local_response_binding_count; i++) {
                const auto& binding = exact_strict_local_response_bindings[i];
                if (binding.path_view != view || binding.method != wanted ||
                    target.len < binding.path_len)
                    continue;
                bool equal = true;
                for (u32 byte = 0; byte < binding.path_len; byte++)
                    equal &= target.ptr[byte] == binding.path[byte];
                if (!equal) continue;
                if (view == ExactPathView::SlashNormalized) {
                    if (target.len == binding.path_len) return binding.policy_id;
                } else if (target.len == binding.path_len || target.ptr[binding.path_len] == '?') {
                    return binding.policy_id;
                }
            }
            return 0;
        };
        const ExactPathView views[] = {ExactPathView::Raw,
                                       ExactPathView::SlashNormalized,
                                       ExactPathView::Raw,
                                       ExactPathView::SlashNormalized};
        const u8 methods[] = {method_key, method_key, kRouteMethodAny, kRouteMethodAny};
        for (u32 i = 0; i < 4; i++) {
            const u16 id = match(views[i], methods[i]);
            if (id != 0) return {ExactStrictLocalResponseMatchState::Match, id};
        }
        return {ExactStrictLocalResponseMatchState::Miss, 0};
    }

    bool strict_local_response_policy_id_is_owned(u16 id) const {
        if (id == 0 || id > strict_local_response_policy_count ||
            strict_local_response_policy_count > kMaxStrictLocalResponsePolicies ||
            strict_local_response_bytes_used > kStrictLocalResponseBytesPoolBytes)
            return false;
        const auto& policy = strict_local_response_policies[id - 1];
        return strict_local_response_bytes_owned(policy.reason) &&
               strict_local_response_bytes_owned(policy.content_type) &&
               strict_local_response_bytes_owned(policy.server) &&
               strict_local_response_bytes_owned(policy.body) &&
               strict_local_response_policy_spec_valid(policy);
    }

    // Incremental builder.  Dedup is semantic and stable (first insertion wins).
    // A policy without a mapping is intentionally incomplete activation metadata
    // and therefore fails closed on a miss until the table is completed.
    u16 add_strict_local_response_policy(const StrictLocalResponsePolicySpec& policy) {
        if (!strict_local_response_policy_spec_valid(policy) ||
            strict_local_response_policy_count > kMaxStrictLocalResponsePolicies ||
            strict_local_response_bytes_used > kStrictLocalResponseBytesPoolBytes)
            return 0;
        for (u32 i = 0; i < strict_local_response_policy_count; i++) {
            if (!strict_local_response_policy_id_is_owned(static_cast<u16>(i + 1))) return 0;
            if (strict_local_response_policy_spec_equal(strict_local_response_policies[i], policy))
                return static_cast<u16>(i + 1);
        }
        if (strict_local_response_policy_count == kMaxStrictLocalResponsePolicies) return 0;
        u32 total = 0;
        const Str fields[] = {policy.reason, policy.content_type, policy.server, policy.body};
        for (Str field : fields) {
            if (field.len > kStrictLocalResponseBytesPoolBytes - total) return 0;
            total += field.len;
        }
        if (total > kStrictLocalResponseBytesPoolBytes - strict_local_response_bytes_used) return 0;
        auto copy = [&](Str src, Str& dst) {
            char* out = strict_local_response_bytes + strict_local_response_bytes_used;
            if (src.len != 0) __builtin_memcpy(out, src.ptr, src.len);
            strict_local_response_bytes_used += src.len;
            dst = {out, src.len};
        };
        auto& dst = strict_local_response_policies[strict_local_response_policy_count];
        dst.version = policy.version;
        dst.status_code = policy.status_code;
        dst.date = policy.date;
        dst.connection = policy.connection;
        dst.head_mode = policy.head_mode;
        copy(policy.reason, dst.reason);
        copy(policy.content_type, dst.content_type);
        copy(policy.server, dst.server);
        copy(policy.body, dst.body);
        return static_cast<u16>(++strict_local_response_policy_count);
    }

    bool set_unmatched_policy_id(u8 method_key, u16 policy_id) {
        const u32 slot = route_method_slot_from_key(method_key);
        if (slot == kRouteMethodSlotInvalid || policy_id == 0 ||
            !strict_local_response_policy_id_is_owned(policy_id) || unmatched_policy_ids[slot] != 0)
            return false;
        if ((slot == kRouteMethodAny || slot == kRouteMethodHead) &&
            strict_local_response_policies[policy_id - 1].head_mode !=
                StrictLocalResponseHeadMode::SuppressBody)
            return false;
        unmatched_policy_ids[slot] = policy_id;
        return true;
    }

    bool set_pre_route_policy_id(u8 method_key, u16 policy_id) {
        const u32 slot = route_method_slot_from_key(method_key);
        if (slot == kRouteMethodSlotInvalid || slot == kRouteMethodAny || policy_id == 0 ||
            !strict_local_response_policy_id_is_owned(policy_id) || pre_route_policy_ids[slot] != 0)
            return false;
        if (slot == kRouteMethodHead && strict_local_response_policies[policy_id - 1].head_mode !=
                                            StrictLocalResponseHeadMode::SuppressBody)
            return false;
        pre_route_policy_ids[slot] = policy_id;
        return true;
    }

    bool append_exact_strict_local_response_binding(const ExactStrictLocalResponseBinding& source,
                                                    u16 owned_policy_id) {
        if (exact_strict_local_response_binding_count >= kMaxExactStrictLocalResponseBindings ||
            !exact_strict_local_response_binding_shape_valid(source) || owned_policy_id == 0 ||
            !strict_local_response_policy_id_is_owned(owned_policy_id))
            return false;
        const u32 slot = route_method_slot_from_key(source.method);
        if (slot == kRouteMethodSlotInvalid ||
            ((slot == kRouteMethodAny || slot == kRouteMethodHead) &&
             strict_local_response_policies[owned_policy_id - 1].head_mode !=
                 StrictLocalResponseHeadMode::SuppressBody))
            return false;
        for (u32 i = 0; i < exact_strict_local_response_binding_count; i++) {
            const auto& prior = exact_strict_local_response_bindings[i];
            if (prior.method == source.method && prior.path_view == source.path_view &&
                prior.path_len == source.path_len &&
                __builtin_memcmp(prior.path, source.path, source.path_len) == 0)
                return false;
        }
        auto& destination =
            exact_strict_local_response_bindings[exact_strict_local_response_binding_count];
        for (u32 i = 0; i < sizeof(destination.path); i++) destination.path[i] = source.path[i];
        destination.path_len = source.path_len;
        destination.method = source.method;
        destination.path_view = source.path_view;
        destination.policy_id = owned_policy_id;
        destination.reserved1 = source.reserved1;
        ++exact_strict_local_response_binding_count;
        return true;
    }

    // Copy a complete already-owned table without allocation. Every check and
    // every possible false return precedes the first destination write; once
    // commit starts it only copies bounded arrays and rebases proven pool views.
    bool copy_strict_local_response_table_from_owned(const RouteConfig& source) {
        if (has_strict_local_response_table_inventory()) return false;
        if (!source.strict_local_response_table_is_valid()) return false;

        // Convert every source view to a checked integer offset before the
        // first destination write.  Public/forged views can carry an address
        // numerically inside the source pool without C++ array provenance, so
        // native pointer subtraction would itself be undefined even after the
        // address-range validation above.
        u32 offsets[kMaxStrictLocalResponsePolicies][4]{};
        const uintptr_t source_base =
            reinterpret_cast<uintptr_t>(source.strict_local_response_bytes);
        auto checked_offset = [&](Str value, u32* out) {
            if (out == nullptr || !source.strict_local_response_bytes_owned(value)) return false;
            const uintptr_t address = reinterpret_cast<uintptr_t>(value.ptr);
            if (address < source_base) return false;
            const uintptr_t wide_offset = address - source_base;
            if (wide_offset > source.strict_local_response_bytes_used ||
                wide_offset > kStrictLocalResponseBytesPoolBytes)
                return false;
            const u32 offset = static_cast<u32>(wide_offset);
            if (value.len > source.strict_local_response_bytes_used - offset ||
                value.len > kStrictLocalResponseBytesPoolBytes - offset)
                return false;
            *out = offset;
            return true;
        };
        for (u32 i = 0; i < source.strict_local_response_policy_count; i++) {
            const auto& src = source.strict_local_response_policies[i];
            if (!checked_offset(src.reason, &offsets[i][0]) ||
                !checked_offset(src.content_type, &offsets[i][1]) ||
                !checked_offset(src.server, &offsets[i][2]) ||
                !checked_offset(src.body, &offsets[i][3]))
                return false;
        }

        if (source.strict_local_response_bytes_used != 0)
            __builtin_memcpy(strict_local_response_bytes,
                             source.strict_local_response_bytes,
                             source.strict_local_response_bytes_used);
        for (u32 i = 0; i < source.strict_local_response_policy_count; i++) {
            const auto& src = source.strict_local_response_policies[i];
            auto& dst = strict_local_response_policies[i];
            dst.version = src.version;
            dst.status_code = src.status_code;
            dst.date = src.date;
            dst.connection = src.connection;
            dst.head_mode = src.head_mode;
            dst.reason = {strict_local_response_bytes + offsets[i][0], src.reason.len};
            dst.content_type = {strict_local_response_bytes + offsets[i][1], src.content_type.len};
            dst.server = {strict_local_response_bytes + offsets[i][2], src.server.len};
            dst.body = {strict_local_response_bytes + offsets[i][3], src.body.len};
        }
        strict_local_response_bytes_used = source.strict_local_response_bytes_used;
        strict_local_response_policy_count = source.strict_local_response_policy_count;
        for (u32 i = 0; i < kStrictLocalResponseMethodSlots; i++) {
            pre_route_policy_ids[i] = source.pre_route_policy_ids[i];
            unmatched_policy_ids[i] = source.unmatched_policy_ids[i];
        }
        for (u32 i = 0; i < kMaxExactStrictLocalResponseBindings; i++) {
            const auto& src = source.exact_strict_local_response_bindings[i];
            auto& dst = exact_strict_local_response_bindings[i];
            for (u32 byte = 0; byte < sizeof(dst.path); byte++) dst.path[byte] = src.path[byte];
            dst.path_len = src.path_len;
            dst.method = src.method;
            dst.path_view = src.path_view;
            dst.policy_id = src.policy_id;
            dst.reserved1 = src.reserved1;
        }
        exact_strict_local_response_binding_count =
            source.exact_strict_local_response_binding_count;
        return true;
    }

    bool copy_unmatched_policy_table_from_owned(const RouteConfig& source) {
        if (source.has_pre_route_metadata() || source.has_exact_strict_local_response_inventory())
            return false;
        return copy_strict_local_response_table_from_owned(source);
    }

    // Internal runtime/config transaction. Phase 1 deliberately has no
    // compiler/source representation; callers must provide a complete concrete
    // pre-route table and the existing unmatched/exact inventory together.
    bool install_strict_local_response_table_with_pre_route(
        const StrictLocalResponsePolicySpec* policies,
        u32 policy_count,
        const u16* pre_route_ids,
        const u16* method_policy_ids,
        const ExactStrictLocalResponseBinding* exact_bindings,
        u32 exact_binding_count) {
        if (has_strict_local_response_table_inventory() || policies == nullptr ||
            pre_route_ids == nullptr || method_policy_ids == nullptr || exact_bindings == nullptr ||
            policy_count > kMaxStrictLocalResponsePolicies ||
            exact_binding_count > kMaxExactStrictLocalResponseBindings ||
            pre_route_ids[kRouteMethodAny] != 0)
            return false;

        bool referenced[kMaxStrictLocalResponsePolicies]{};
        u32 reference_count = 0;
        auto add_reference = [&](u16 id) {
            if (id == 0 || id > policy_count || referenced[id - 1]) return false;
            referenced[id - 1] = true;
            ++reference_count;
            return true;
        };
        u32 total_bytes = 0;
        for (u32 i = 0; i < policy_count; i++) {
            if (!strict_local_response_policy_spec_valid(policies[i])) return false;
            const Str fields[] = {
                policies[i].reason, policies[i].content_type, policies[i].server, policies[i].body};
            for (Str field : fields) {
                if (field.len > kStrictLocalResponseBytesPoolBytes - total_bytes) return false;
                total_bytes += field.len;
            }
        }
        for (u32 slot = 1; slot < kStrictLocalResponseMethodSlots; slot++) {
            const u16 id = pre_route_ids[slot];
            if (id == 0) continue;
            if (!add_reference(id) ||
                (slot == kRouteMethodHead &&
                 policies[id - 1].head_mode != StrictLocalResponseHeadMode::SuppressBody))
                return false;
        }
        for (u32 slot = 0; slot < kStrictLocalResponseMethodSlots; slot++) {
            const u16 id = method_policy_ids[slot];
            if (id == 0) continue;
            if (!add_reference(id) ||
                ((slot == kRouteMethodAny || slot == kRouteMethodHead) &&
                 policies[id - 1].head_mode != StrictLocalResponseHeadMode::SuppressBody))
                return false;
        }
        for (u32 i = 0; i < kMaxExactStrictLocalResponseBindings; i++) {
            const auto& binding = exact_bindings[i];
            if (i >= exact_binding_count) {
                if (!exact_strict_local_response_binding_is_neutral(binding)) return false;
                continue;
            }
            if (!exact_strict_local_response_binding_shape_valid(binding) ||
                !add_reference(binding.policy_id))
                return false;
            const u32 slot = route_method_slot_from_key(binding.method);
            if (slot == kRouteMethodSlotInvalid ||
                ((slot == kRouteMethodAny || slot == kRouteMethodHead) &&
                 policies[binding.policy_id - 1].head_mode !=
                     StrictLocalResponseHeadMode::SuppressBody))
                return false;
            for (u32 prior = 0; prior < i; prior++) {
                const auto& earlier = exact_bindings[prior];
                if (earlier.method == binding.method && earlier.path_view == binding.path_view &&
                    earlier.path_len == binding.path_len &&
                    __builtin_memcmp(earlier.path, binding.path, binding.path_len) == 0)
                    return false;
            }
        }
        if (reference_count != policy_count) return false;

        auto replay = [&](RouteConfig& target) {
            u16 remap[kMaxStrictLocalResponsePolicies]{};
            for (u32 i = 0; i < policy_count; i++) {
                remap[i] = target.add_strict_local_response_policy(policies[i]);
                if (remap[i] == 0) return false;
            }
            for (u32 slot = 1; slot < kStrictLocalResponseMethodSlots; slot++) {
                const u16 source_id = pre_route_ids[slot];
                if (source_id != 0 &&
                    !target.set_pre_route_policy_id(static_cast<u8>(slot), remap[source_id - 1]))
                    return false;
            }
            for (u32 slot = 0; slot < kStrictLocalResponseMethodSlots; slot++) {
                const u16 source_id = method_policy_ids[slot];
                if (source_id != 0 &&
                    !target.set_unmatched_policy_id(static_cast<u8>(slot), remap[source_id - 1]))
                    return false;
            }
            for (u32 i = 0; i < exact_binding_count; i++) {
                const u16 source_id = exact_bindings[i].policy_id;
                if (!target.append_exact_strict_local_response_binding(exact_bindings[i],
                                                                       remap[source_id - 1]))
                    return false;
            }
            return target.strict_local_response_table_is_valid();
        };
        RouteConfig* probe = new (std::nothrow) RouteConfig();
        if (probe == nullptr) return false;
        const bool staged = replay(*probe);
        if (!staged) {
            delete probe;
            return false;
        }
        const bool committed = copy_strict_local_response_table_from_owned(*probe);
        delete probe;
        return committed;
    }

    // Install one complete table transactionally. A fresh RouteConfig probes
    // deterministic dedup/remap; no destination byte changes until that probe
    // has accepted the whole input, after which commit is infallible.
    bool install_strict_local_response_table(const StrictLocalResponsePolicySpec* policies,
                                             u32 policy_count,
                                             const u16* method_policy_ids,
                                             const ExactStrictLocalResponseBinding* exact_bindings,
                                             u32 exact_binding_count) {
        if (has_strict_local_response_table_inventory()) return false;
        if (!strict_local_response_source_table_valid(
                policies, policy_count, method_policy_ids, exact_bindings, exact_binding_count))
            return false;
        auto replay = [&](RouteConfig& target) {
            u16 remap[kMaxStrictLocalResponsePolicies]{};
            for (u32 i = 0; i < policy_count; i++) {
                remap[i] = target.add_strict_local_response_policy(policies[i]);
                if (remap[i] == 0) return false;
            }
            for (u32 slot = 0; slot < kStrictLocalResponseMethodSlots; slot++) {
                const u16 source_id = method_policy_ids[slot];
                if (source_id == 0) continue;
                if (!target.set_unmatched_policy_id(static_cast<u8>(slot), remap[source_id - 1]))
                    return false;
            }
            for (u32 i = 0; i < exact_binding_count; i++) {
                const u16 source_id = exact_bindings[i].policy_id;
                if (!target.append_exact_strict_local_response_binding(exact_bindings[i],
                                                                       remap[source_id - 1]))
                    return false;
            }
            return target.strict_local_response_table_is_valid();
        };
        RouteConfig* probe = new (std::nothrow) RouteConfig();
        if (probe == nullptr) return false;
        const bool staged = replay(*probe);
        if (!staged) {
            delete probe;
            return false;
        }

        const bool committed = copy_strict_local_response_table_from_owned(*probe);
        delete probe;
        return committed;
    }

    bool install_unmatched_policy_table(const StrictLocalResponsePolicySpec* policies,
                                        u32 policy_count,
                                        const u16* method_policy_ids) {
        const ExactStrictLocalResponseBinding empty[kMaxExactStrictLocalResponseBindings]{};
        return install_strict_local_response_table(
            policies, policy_count, method_policy_ids, empty, 0);
    }

    // Populate the active dispatch's state with a newly-written
    // routes[route_count] entry. Returns false on:
    //   - a structural capacity hit in that dispatch's data
    //     structure (e.g., trie node-pool exhaustion),
    //   - an unknown / non-canonical dispatch pointer.
    //
    // The fail-closed default is deliberate. Round-4 of #43
    // tightened set_dispatch() to admit only canonical singleton
    // dispatch pointers, so the "unknown dispatch" branch should
    // not occur in normal use. We still reject it here as defense
    // in depth: without explicit per-impl handling the auxiliary
    // state for that dispatch would not be built, and match()
    // would systematically miss. Refusing add_* keeps the failure
    // loud rather than silent.
    //
    // Branches are narrow — body of each is exactly that impl's
    // `insert`. New impls add a branch here; the rest of add_*
    // doesn't change.
    bool populate_dispatch_state(const RouteEntry& r) {
        const Str path_view{r.path, r.path_len};
        const u16 idx = static_cast<u16>(route_count);
        switch (dispatch_kind_) {
            case DispatchKind::ArtJit:
                return art_state.insert(path_view, r.method, idx);
            case DispatchKind::SegmentTrie:
                return trie.insert(path_view, r.method, idx);
        }
        __builtin_unreachable();
    }

    // Add a proxy route: path prefix → upstream target.
    // Returns false if:
    //   - the route table is full,
    //   - upstream_id is out of range,
    //   - the path is malformed (see is_routable_path),
    //   - the path is too long for RouteEntry::path,
    //   - the method key is not recognized (legacy first-char method
    //     bytes are normalized before insertion),
    //   - the active dispatch's state ran out of capacity,
    //   - the active dispatch is not one of the canonical singletons
    //     (see populate_dispatch_state).
    bool add_proxy(const char* path, u8 method, u16 upstream_id) {
        if (route_count >= kMaxRoutes) return false;
        if (upstream_id >= upstream_count) return false;
        if (!is_routable_path(path)) return false;
        if (!dispatch_accepts_path_shape(path)) return false;
        if (!param_count_fits(path)) return false;
        const u8 method_key = route_method_key_from_legacy_char(method);
        if (route_method_slot(method_key) == kMethodSlotInvalid) return false;
        auto& r = routes[route_count];
        r.path_len = 0;
        while (path[r.path_len] && r.path_len < sizeof(r.path) - 1) {
            r.path[r.path_len] = path[r.path_len];
            r.path_len++;
        }
        if (path[r.path_len] != '\0') return false;  // path too long (truncated)
        r.path[r.path_len] = '\0';
        r.method = method_key;
        r.action = RouteAction::Proxy;
        r.upstream_id = upstream_id;
        r.status_code = 0;
        r.fn = nullptr;
        r.needs_req_body = false;
        r.forward_preflight_mode = ForwardPreflightMode::None;
        r.preflight_forward_policy_bundle_id = 0;
        if (!populate_dispatch_state(r)) {
            return false;  // active dispatch at capacity — fail loud
        }
        route_count++;
        return true;
    }

    // Add a Proxy route that TERMINATES WebSocket upgrades: on a 101 the data phase is
    // frame-inspected and each message handed to `handler` (forward/drop/close), bounded
    // by `max_message_size` (clamped to one buffer slice). Same failure modes as
    // add_proxy() plus a null-handler / zero-size check. The C++ surface for terminate
    // routes; the .rut compiler emits this in a later slice.
    bool add_ws_terminate(const char* path,
                          u8 method,
                          u16 upstream_id,
                          WsMessageHandlerFn handler,
                          u32 max_message_size,
                          u16 close_code = 1000) {
#if !RUT_ENABLE_WEBSOCKET
        // The 101/tunnel path is compiled out in this build — a terminate route could
        // never enter terminate mode, so fail loud instead of publishing an unusable route.
        (void)path;
        (void)method;
        (void)upstream_id;
        (void)handler;
        (void)max_message_size;
        (void)close_code;
        return false;
#else
        if (handler == nullptr || max_message_size == 0) return false;
        // Fail closed on a close code the runtime would refuse to put on the wire, using the
        // SAME predicate as the receive-side validator (ws_inspect) and the .rut analyze check
        // — including the reserved 1016–2999 range — so this C++ surface can't publish a route
        // whose handler Close serializes a code the runtime itself considers invalid.
        if (!ws_valid_close_code(close_code)) return false;
        if (!add_proxy(path, method, upstream_id)) return false;
        auto& r = routes[route_count - 1];
        r.ws_terminate = true;
        r.ws_frame_handler = handler;
        r.ws_max_message_size = max_message_size;
        r.ws_close_code = close_code;
        return true;
#endif
    }

    // Set a route's rate limit to a single token-bucket rule (`max` per
    // `window_sec`, burst capacity defaulting to `max`, per-client-IP key),
    // replacing any existing rules. 0/0 leaves the route unlimited. Returns false
    // on a bad index. For stacked rules use add_route_rate_limit_rule; refine the
    // key with add_route_rate_limit_key.
    bool set_route_rate_limit(u32 idx, u32 max, u32 window_sec) {
        if (idx >= route_count) return false;
        routes[idx].rate_limit = RateLimitRuleSet{};
        if (max > 0 && window_sec > 0) routes[idx].rate_limit.add_rule(max, window_sec);
        return true;
    }

    // Append an additional rate-limit rule to a route (stacking): a request must
    // pass every rule. `scope` selects per-shard (default) or exact global; `burst`
    // is the bucket capacity (0 → defaults to `max`). Returns false on a bad index
    // or when the rule set is full.
    bool add_route_rate_limit_rule(u32 idx,
                                   u32 max,
                                   u32 window_sec,
                                   RateLimitScope scope = RateLimitScope::Shard,
                                   u32 burst = 0) {
        if (idx >= route_count) return false;
        return routes[idx].rate_limit.add_rule(max, window_sec, burst, scope) >= 0;
    }

    // Append one metering-key component to a route's *most recently added* rule
    // (IP / header / query / cookie / param). With no components a rule meters
    // per client IP; each appended component adds a dimension, so it counts per
    // unique tuple. `name` is ignored for Ip. Returns false on a bad index, when
    // the route has no rule yet, or when that rule's key is already full.
    bool add_route_rate_limit_key(u32 idx, RateLimitKeyKind kind, const char* name, u32 name_len) {
        if (idx >= route_count) return false;
        RateLimitRuleSet& rs = routes[idx].rate_limit;
        if (rs.count == 0) return false;
        return rs.rules[rs.count - 1].key.add(kind, name, name_len);
    }

    // Attach a per-route client-send byte rate (bytes/sec, 0 disables). Set by
    // the @throttle decorator via register_jit_routes. Returns false on a bad
    // index.
    bool set_route_throttle(u32 idx, u32 down_bps) {
        if (idx >= route_count) return false;
        routes[idx].throttle_down_bps = down_bps;
        return true;
    }

    // Cap concurrent in-flight proxied requests to an upstream (by id). 0 =
    // unlimited. Over the cap the runtime answers 503 before connecting. Returns
    // false on a bad upstream id.
    bool set_upstream_max_inflight(u32 uid, u32 max_inflight) {
        if (uid >= upstream_count) return false;
        upstreams[uid].max_inflight = max_inflight;
        return true;
    }

    // Attach active health-check config to an upstream (by id). Data only — no
    // probing is performed yet. `path` (length `path_len`, not required to be
    // NUL-terminated) is the probe path; `interval_ms` the probe period;
    // `status` the status code that marks a backend healthy. Returns false on a
    // bad upstream id, an over-long path, a non-origin-form path (empty, missing
    // the leading '/', or containing bytes that would break the request line),
    // or an impossible expected HTTP status.
    bool set_upstream_health_check(
        u32 uid, const char* path, u32 path_len, u32 interval_ms, u16 status) {
        if (uid >= upstream_count) return false;
        UpstreamTarget& up = upstreams[uid];
        if (path == nullptr) return false;
        if (path_len >= sizeof(up.hc_path)) return false;
        if (interval_ms == 0) return false;
        if (status < 100 || status > 599) return false;
        // The probe writes this verbatim into `GET <path> HTTP/1.1`, so it must
        // be an origin-form target that cannot inject spaces/control bytes into
        // the request line. The DSL path is also checked at parse time; this is
        // defense-in-depth for the public API.
        if (path_len == 0 || path[0] != '/') return false;
        for (u32 i = 0; i < path_len; i++) {
            const unsigned char ch = static_cast<unsigned char>(path[i]);
            if (ch <= 0x20 || ch == 0x7f) return false;
        }
        for (u32 i = 0; i < path_len; i++) up.hc_path[i] = path[i];
        up.hc_path[path_len] = '\0';
        up.hc_path_len = path_len;
        up.hc_interval_ms = interval_ms;
        up.hc_expected_status = status;
        up.hc_enabled = true;
        return true;
    }

    // Add a static response route. Same failure modes as add_proxy(),
    // minus the upstream-id check that doesn't apply here.
    bool add_static(const char* path, u8 method, u16 status) {
        if (route_count >= kMaxRoutes) return false;
        if (!is_routable_path(path)) return false;
        if (!dispatch_accepts_path_shape(path)) return false;
        if (!param_count_fits(path)) return false;
        const u8 method_key = route_method_key_from_legacy_char(method);
        if (route_method_slot(method_key) == kMethodSlotInvalid) return false;
        auto& r = routes[route_count];
        r.path_len = 0;
        while (path[r.path_len] && r.path_len < sizeof(r.path) - 1) {
            r.path[r.path_len] = path[r.path_len];
            r.path_len++;
        }
        if (path[r.path_len] != '\0') return false;  // path too long
        r.path[r.path_len] = '\0';
        r.method = method_key;
        r.action = RouteAction::Static;
        r.upstream_id = 0;
        r.status_code = status;
        r.fn = nullptr;
        r.needs_req_body = false;
        r.forward_preflight_mode = ForwardPreflightMode::None;
        r.preflight_forward_policy_bundle_id = 0;
        if (!populate_dispatch_state(r)) {
            return false;
        }
        route_count++;
        return true;
    }

private:
    friend bool register_jit_routes(RouteConfig& cfg,
                                    const rir::Module& mod,
                                    jit::JitEngine& engine);

    // Verified-RIR publication entry. Deferred mode is inaccessible to native
    // callers and admitted only after register_jit_routes verifies the module.
    bool add_verified_jit_handler(const char* path,
                                  u8 method,
                                  jit::HandlerFn fn,
                                  bool needs_req_body,
                                  ForwardPreflightMode forward_preflight_mode,
                                  u16 preflight_forward_policy_bundle_id) {
        if (route_count >= kMaxRoutes) return false;
        if (fn == nullptr) return false;
        if (!forward_preflight_mode_valid(forward_preflight_mode) ||
            !forward_preflight_metadata_is_verified_runtime_safe(
                forward_preflight_mode, preflight_forward_policy_bundle_id))
            return false;
        if (forward_preflight_mode_can_own_runtime_deadline(forward_preflight_mode) &&
            (!policy_bundle_id_is_valid(preflight_forward_policy_bundle_id) ||
             !response_read_timeout_seconds_valid(
                 policy_bundles[preflight_forward_policy_bundle_id - 1]
                     .response_read_timeout_seconds)))
            return false;
        if (!is_routable_path(path)) return false;
        if (!dispatch_accepts_path_shape(path)) return false;
        if (!param_count_fits(path)) return false;
        const u8 method_key = route_method_key_from_legacy_char(method);
        if (route_method_slot(method_key) == kMethodSlotInvalid) return false;
        if (forward_preflight_mode == ForwardPreflightMode::AfterCanonicalSelection &&
            (needs_req_body || method_key == kRouteMethodAny ||
             !complete_content_length_route_method_is_admitted(method_key) ||
             policy_bundles[preflight_forward_policy_bundle_id - 1].response_buffering !=
                 ForwardResponseBufferingMode::CompleteContentLength))
            return false;
        auto& r = routes[route_count];
        r.path_len = 0;
        while (path[r.path_len] && r.path_len < sizeof(r.path) - 1) {
            r.path[r.path_len] = path[r.path_len];
            r.path_len++;
        }
        if (path[r.path_len] != '\0') return false;  // path too long
        r.path[r.path_len] = '\0';
        r.method = method_key;
        r.action = RouteAction::JitHandler;
        r.upstream_id = 0;
        r.status_code = 0;
        r.fn = fn;
        r.needs_req_body = needs_req_body;
        r.forward_preflight_mode = forward_preflight_mode;
        r.preflight_forward_policy_bundle_id = preflight_forward_policy_bundle_id;
        if (!populate_dispatch_state(r)) {
            return false;
        }
        route_count++;
        return true;
    }

public:
    // Add a JIT-handler route. Handler is invoked on match; its HandlerResult
    // tells the runtime what to do next (return status, forward, or yield).
    // Same failure modes as add_proxy() plus null-fn check. Native callers are
    // intentionally limited to None/EagerDirect metadata.
    bool add_jit_handler(const char* path,
                         u8 method,
                         jit::HandlerFn fn,
                         bool needs_req_body,
                         ForwardPreflightMode forward_preflight_mode,
                         u16 preflight_forward_policy_bundle_id) {
        if (!forward_preflight_metadata_is_eager_runtime_safe(forward_preflight_mode,
                                                              preflight_forward_policy_bundle_id))
            return false;
        return add_verified_jit_handler(path,
                                        method,
                                        fn,
                                        needs_req_body,
                                        forward_preflight_mode,
                                        preflight_forward_policy_bundle_id);
    }

    // Source-compatible legacy registration. A nonzero historical marker is
    // always the already-supported eager-direct mode; it can never opt into
    // deferred post-selection behavior.
    bool add_jit_handler(const char* path,
                         u8 method,
                         jit::HandlerFn fn,
                         bool needs_req_body = false,
                         u16 preflight_forward_policy_bundle_id = 0) {
        const ForwardPreflightMode mode = preflight_forward_policy_bundle_id == 0
                                              ? ForwardPreflightMode::None
                                              : ForwardPreflightMode::EagerDirect;
        return add_jit_handler(
            path, method, fn, needs_req_body, mode, preflight_forward_policy_bundle_id);
    }

    // Register a response body. Copies the bytes into body_pool so the
    // caller doesn't need to keep the source alive. Returns a 1-based
    // index (0 is reserved as "no body") that JIT handlers can encode
    // in the HandlerResult upstream_id slot for ReturnStatus.
    // Returns 0 if the body table or pool is full, or if the arguments
    // are nonsensical (null data with non-zero len).
    u16 add_response_body(const char* data, u32 len) {
        if (response_body_count >= kMaxResponseBodies) return 0;
        if (len > 0 && data == nullptr) return 0;
        // Subtraction-based capacity check: `body_pool_used + len`
        // would wrap on a large u32 `len` and silently pass, leading
        // to an out-of-bounds write into body_pool.
        if (len > kResponseBodyPoolBytes - body_pool_used) return 0;
        char* dst = body_pool + body_pool_used;
        for (u32 i = 0; i < len; i++) dst[i] = data[i];
        body_pool_used += len;
        const u32 idx = response_body_count++;
        response_bodies[idx] = {dst, len};
        return static_cast<u16>(idx + 1);  // 1-based; 0 reserved
    }

    // Register a response header set. `keys[i]` / `key_lens[i]` and
    // `values[i]` / `value_lens[i]` describe the i-th pair (i in
    // [0, count)). Bytes are copied into header_bytes_pool so callers
    // don't need to keep the source alive. Returns a 1-based index
    // (0 reserved as "no custom headers") that JIT handlers encode in
    // HandlerResult.next_state for ReturnStatus.
    //
    // Returns 0 on any of:
    //   - count == 0 or null pointer tables
    //   - null data + non-zero len for any pair
    //   - capacity failure: sets table, (key, value) arrays (per-set
    //     cap = kMaxHeadersPerSet), or bytes pool
    //   - validation failure: key fails the HTTP tchar grammar, value
    //     contains control chars, or key names a reserved framing
    //     header (Content-Length / Transfer-Encoding / Connection)
    // Duplicate names are allowed so Response.add can represent fields such
    // as Set-Cookie. The map-literal parser still rejects duplicates because
    // that syntax describes singleton entries; ordered Response builders do
    // not.
    u16 add_response_header_set(const char* const* keys,
                                const u32* key_lens,
                                const char* const* values,
                                const u32* value_lens,
                                u32 count) {
        if (count == 0) return 0;
        if (keys == nullptr || values == nullptr || key_lens == nullptr || value_lens == nullptr) {
            return 0;
        }
        if (response_header_set_count >= kMaxResponseHeaderSets) return 0;
        // Per-set cap is enforced here so the dispatch formatter (which
        // uses a fixed stack buffer sized to kMaxHeadersPerSet) can
        // never silently drop trailing pairs.
        if (count > kMaxHeadersPerSet) return 0;
        // Subtraction-based capacity check on the (key, value) arrays.
        if (count > kMaxHeaderPoolEntries - header_pool_used) return 0;
        // Tally total bytes we're about to write; reject if the bytes
        // pool can't fit them. Also validate each (key, value) pair
        // via the shared HTTP header validator — parity with the DSL
        // parser — so manual callers can't accidentally emit malformed
        // or smuggling-prone responses (CR/LF injection, CL/TE
        // conflicts, etc.). Doing the scan up front avoids a partial
        // copy aborting mid-way with half-written state.
        u32 total_bytes = 0;
        for (u32 i = 0; i < count; i++) {
            if ((key_lens[i] > 0 && keys[i] == nullptr) ||
                (value_lens[i] > 0 && values[i] == nullptr)) {
                return 0;
            }
            if (validate_response_header(keys[i], key_lens[i], values[i], value_lens[i]) !=
                HttpHeaderValidation::Ok) {
                return 0;
            }
            // Guard each add individually against u32 overflow.
            if (key_lens[i] > 0xffffffffu - total_bytes) return 0;
            total_bytes += key_lens[i];
            if (value_lens[i] > 0xffffffffu - total_bytes) return 0;
            total_bytes += value_lens[i];
        }
        if (total_bytes > kResponseHeaderBytesPoolBytes - header_bytes_pool_used) return 0;
        const u16 offset = static_cast<u16>(header_pool_used);
        for (u32 i = 0; i < count; i++) {
            char* key_dst = header_bytes_pool + header_bytes_pool_used;
            for (u32 j = 0; j < key_lens[i]; j++) key_dst[j] = keys[i][j];
            header_bytes_pool_used += key_lens[i];
            char* val_dst = header_bytes_pool + header_bytes_pool_used;
            for (u32 j = 0; j < value_lens[i]; j++) val_dst[j] = values[i][j];
            header_bytes_pool_used += value_lens[i];
            header_keys[offset + i] = {key_dst, key_lens[i]};
            header_values[offset + i] = {val_dst, value_lens[i]};
        }
        header_pool_used += count;
        const u32 idx = response_header_set_count++;
        response_header_sets[idx] = {offset, static_cast<u16>(count)};
        return static_cast<u16>(idx + 1);  // 1-based; 0 reserved
    }

    // Register a validated response-policy object. All string fields are
    // copied into RouteConfig-owned storage; no compiler-arena pointer escapes
    // into the active config. Returns a 1-based ID, or zero on rejection.
    u16 add_response_policy(const ForwardResponsePolicySpec& policy) {
        if (!response_policy_spec_valid(policy)) return 0;
        for (u32 i = 0; i < response_policy_count; i++) {
            if (response_policy_spec_equal(response_policies[i], policy))
                return static_cast<u16>(i + 1);
        }
        if (response_policy_count >= kMaxResponsePolicies) return 0;
        u32 total = policy.server.len;
        if (total > kResponsePolicyBytesPoolBytes - response_policy_bytes_used) return 0;
        for (u32 i = 0; i < policy.hide_header_count; i++) {
            if (policy.hide_headers[i].len > 0xffffffffu - total) return 0;
            total += policy.hide_headers[i].len;
        }
        if (total > kResponsePolicyBytesPoolBytes - response_policy_bytes_used) return 0;

        auto copy = [&](Str src, Str& dst) {
            char* out = response_policy_bytes + response_policy_bytes_used;
            for (u32 i = 0; i < src.len; i++) out[i] = src.ptr[i];
            response_policy_bytes_used += src.len;
            dst = {out, src.len};
        };
        auto& dst = response_policies[response_policy_count];
        dst.version = policy.version;
        dst.framing = policy.framing;
        dst.connection = policy.connection;
        dst.date = policy.date;
        dst.head_mode = policy.head_mode;
        copy(policy.server, dst.server);
        dst.hide_header_count = policy.hide_header_count;
        for (u32 i = 0; i < policy.hide_header_count; i++)
            copy(policy.hide_headers[i], dst.hide_headers[i]);
        response_policy_count++;
        return static_cast<u16>(response_policy_count);
    }

    bool response_policy_id_is_valid(u16 id) const {
        return id != 0 && id <= response_policy_count &&
               response_policy_spec_valid(response_policies[id - 1]);
    }

    u16 add_failure_policy(const ForwardFailurePolicySpec& policy) {
        if (!forward_failure_policy_table_spec_valid(policy)) return 0;
        if (failure_policy_count > kMaxForwardFailurePolicies ||
            failure_policy_bytes_used > kFailurePolicyBytesPoolBytes)
            return 0;
        for (u32 i = 0; i < failure_policy_count; i++)
            if (forward_failure_policy_spec_equal(failure_policies[i], policy))
                return static_cast<u16>(i + 1);
        if (failure_policy_count >= kMaxForwardFailurePolicies) return 0;
        u32 total = policy.reason.len;
        if (total > kFailurePolicyBytesPoolBytes - failure_policy_bytes_used) return 0;
        if (policy.content_type.len > 0xffffffffu - total) return 0;
        total += policy.content_type.len;
        if (policy.server.len > 0xffffffffu - total) return 0;
        total += policy.server.len;
        if (policy.body.len > 0xffffffffu - total) return 0;
        total += policy.body.len;
        if (total > kFailurePolicyBytesPoolBytes - failure_policy_bytes_used) return 0;
        auto copy = [&](Str src, Str& dst) {
            char* out = failure_policy_bytes + failure_policy_bytes_used;
            for (u32 i = 0; i < src.len; i++) out[i] = src.ptr[i];
            failure_policy_bytes_used += src.len;
            dst = {out, src.len};
        };
        auto& dst = failure_policies[failure_policy_count];
        dst.version = policy.version;
        dst.status_code = policy.status_code;
        dst.date = policy.date;
        dst.connection = policy.connection;
        dst.head_mode = policy.head_mode;
        copy(policy.reason, dst.reason);
        copy(policy.content_type, dst.content_type);
        copy(policy.server, dst.server);
        copy(policy.body, dst.body);
        failure_policy_count++;
        return static_cast<u16>(failure_policy_count);
    }

    u16 add_policy_bundle(
        u16 response_policy_id,
        u16 failure_policy_id,
        u16 timeout_failure_policy_id = 0,
        u8 response_read_timeout_seconds = 0,
        ForwardResponseBufferingMode response_buffering = ForwardResponseBufferingMode::None) {
        if ((response_policy_id != 0 && !response_policy_id_is_valid(response_policy_id)) ||
            (failure_policy_id != 0 && !failure_policy_id_is_valid(failure_policy_id)) ||
            (response_read_timeout_seconds != 0 &&
             !response_read_timeout_seconds_valid(response_read_timeout_seconds)) ||
            !forward_response_buffering_mode_valid(response_buffering) ||
            (response_read_timeout_seconds == 0 && failure_policy_id == 0))
            return 0;
        if (timeout_failure_policy_id != 0) {
            if (response_policy_id == 0 || failure_policy_id == 0 ||
                !timeout_failure_policy_id_is_valid(timeout_failure_policy_id))
                return 0;
            const bool response_suppress = response_policies[response_policy_id - 1].head_mode ==
                                           ResponsePolicyHeadMode::SuppressBody;
            const bool failure_suppress = failure_policies[failure_policy_id - 1].head_mode ==
                                          FailurePolicyHeadMode::SuppressBody;
            const bool timeout_suppress =
                failure_policies[timeout_failure_policy_id - 1].head_mode ==
                FailurePolicyHeadMode::SuppressBody;
            if (response_suppress != failure_suppress || failure_suppress != timeout_suppress)
                return 0;
        }
        if (response_buffering != ForwardResponseBufferingMode::None &&
            (response_buffering != ForwardResponseBufferingMode::CompleteContentLength ||
             !response_read_timeout_seconds_valid(response_read_timeout_seconds) ||
             response_policy_id == 0 || failure_policy_id == 0 || timeout_failure_policy_id == 0 ||
             !complete_content_length_buffering_policies_valid(
                 response_policies[response_policy_id - 1],
                 failure_policies[failure_policy_id - 1],
                 failure_policies[timeout_failure_policy_id - 1])))
            return 0;
        if (policy_bundle_count > kMaxForwardPolicyBundles) return 0;
        for (u32 i = 0; i < policy_bundle_count; i++) {
            if (policy_bundles[i].response_policy_id == response_policy_id &&
                policy_bundles[i].failure_policy_id == failure_policy_id &&
                policy_bundles[i].timeout_failure_policy_id == timeout_failure_policy_id &&
                policy_bundles[i].response_read_timeout_seconds == response_read_timeout_seconds &&
                policy_bundles[i].response_buffering == response_buffering)
                return static_cast<u16>(i + 1);
        }
        if (policy_bundle_count >= kMaxForwardPolicyBundles) return 0;
        policy_bundles[policy_bundle_count] = {response_policy_id,
                                               failure_policy_id,
                                               timeout_failure_policy_id,
                                               response_read_timeout_seconds,
                                               response_buffering};
        return static_cast<u16>(++policy_bundle_count);
    }

    bool failure_policy_id_is_valid(u16 id) const {
        return failure_policy_count <= kMaxForwardFailurePolicies && id != 0 &&
               id <= failure_policy_count &&
               forward_failure_policy_spec_valid(failure_policies[id - 1]);
    }

    bool timeout_failure_policy_id_is_valid(u16 id) const {
        return failure_policy_count <= kMaxForwardFailurePolicies && id != 0 &&
               id <= failure_policy_count &&
               forward_timeout_failure_policy_spec_valid(failure_policies[id - 1]);
    }

    bool policy_bundle_id_is_valid(u16 id) const {
        if (policy_bundle_count > kMaxForwardPolicyBundles || id == 0 || id > policy_bundle_count)
            return false;
        const auto& b = policy_bundles[id - 1];
        if ((b.response_policy_id != 0 && !response_policy_id_is_valid(b.response_policy_id)) ||
            (b.failure_policy_id != 0 && !failure_policy_id_is_valid(b.failure_policy_id)) ||
            (b.response_read_timeout_seconds != 0 &&
             !response_read_timeout_seconds_valid(b.response_read_timeout_seconds)) ||
            !forward_response_buffering_mode_valid(b.response_buffering) ||
            (b.response_read_timeout_seconds == 0 && b.failure_policy_id == 0))
            return false;
        if (b.response_buffering != ForwardResponseBufferingMode::None &&
            (b.response_buffering != ForwardResponseBufferingMode::CompleteContentLength ||
             !response_read_timeout_seconds_valid(b.response_read_timeout_seconds) ||
             b.response_policy_id == 0 || b.failure_policy_id == 0 ||
             b.timeout_failure_policy_id == 0 ||
             !timeout_failure_policy_id_is_valid(b.timeout_failure_policy_id) ||
             !complete_content_length_buffering_policies_valid(
                 response_policies[b.response_policy_id - 1],
                 failure_policies[b.failure_policy_id - 1],
                 failure_policies[b.timeout_failure_policy_id - 1])))
            return false;
        if (b.timeout_failure_policy_id == 0) return true;
        if (b.response_policy_id == 0 || b.failure_policy_id == 0 ||
            !timeout_failure_policy_id_is_valid(b.timeout_failure_policy_id))
            return false;
        const bool response_suppress = response_policies[b.response_policy_id - 1].head_mode ==
                                       ResponsePolicyHeadMode::SuppressBody;
        const bool failure_suppress = failure_policies[b.failure_policy_id - 1].head_mode ==
                                      FailurePolicyHeadMode::SuppressBody;
        const bool timeout_suppress = failure_policies[b.timeout_failure_policy_id - 1].head_mode ==
                                      FailurePolicyHeadMode::SuppressBody;
        return response_suppress == failure_suppress && failure_suppress == timeout_suppress;
    }

    // Register foundation-only target-transform metadata. Strings are copied
    // into RouteConfig-owned storage; no compiler/RIR pointer escapes here.
    u16 add_target_transform(const ForwardTargetTransformSpec& spec) {
        if (!forward_target_transform_spec_valid(spec)) return 0;
        if (target_transform_count > kMaxForwardTargetTransforms ||
            target_transform_bytes_used > kForwardTargetTransformBytes)
            return 0;
        for (u32 i = 0; i < target_transform_count; i++) {
            if (forward_target_transform_spec_equal(target_transforms[i], spec))
                return static_cast<u16>(i + 1);
        }
        if (target_transform_count >= kMaxForwardTargetTransforms) return 0;
        if (spec.strip_prefix.len > kForwardTargetTransformBytes - target_transform_bytes_used)
            return 0;
        const u32 after_strip = target_transform_bytes_used + spec.strip_prefix.len;
        if (spec.replace_prefix.len > kForwardTargetTransformBytes - after_strip) return 0;
        auto copy = [&](Str src, Str& dst) {
            char* out = target_transform_bytes + target_transform_bytes_used;
            for (u32 i = 0; i < src.len; i++) out[i] = src.ptr[i];
            target_transform_bytes_used += src.len;
            dst = {out, src.len};
        };
        auto& dst = target_transforms[target_transform_count];
        copy(spec.strip_prefix, dst.strip_prefix);
        copy(spec.replace_prefix, dst.replace_prefix);
        target_transform_count++;
        return static_cast<u16>(target_transform_count);
    }

    bool target_transform_id_is_valid(u16 id) const {
        return forward_target_transform_id_is_valid(id, target_transform_count) &&
               forward_target_transform_spec_valid(target_transforms[id - 1]);
    }

    // Register foundation-only redirect metadata. Strings are copied into
    // RouteConfig-owned storage; no compiler/RIR pointer escapes here.
    bool redirect_policy_string_is_owned(Str value) const {
        if (value.len == 0) return true;
        if (value.ptr == nullptr || redirect_policy_bytes_used > kRedirectPolicyBytesPoolBytes ||
            value.len > redirect_policy_bytes_used)
            return false;
        const uintptr_t begin = reinterpret_cast<uintptr_t>(redirect_policy_bytes);
        const uintptr_t end = begin + redirect_policy_bytes_used;
        const uintptr_t ptr = reinterpret_cast<uintptr_t>(value.ptr);
        return ptr >= begin && ptr <= end && value.len <= end - ptr;
    }

    bool redirect_policy_strings_are_owned(const RedirectPolicySpec& policy) const {
        const Str fields[] = {policy.reason,
                              policy.server,
                              policy.content_type,
                              policy.static_authority,
                              policy.target_path,
                              policy.body};
        for (const Str field : fields)
            if (!redirect_policy_string_is_owned(field)) return false;
        return true;
    }

    u16 add_redirect_policy(const RedirectPolicySpec& policy) {
        if (redirect_policy_count > kMaxRedirectPolicies ||
            redirect_policy_bytes_used > kRedirectPolicyBytesPoolBytes)
            return 0;
        if (!redirect_policy_spec_valid(policy)) return 0;
        for (u32 i = 0; i < redirect_policy_count; i++) {
            if (!redirect_policy_strings_are_owned(redirect_policies[i])) return 0;
            if (redirect_policy_spec_equal(redirect_policies[i], policy))
                return static_cast<u16>(i + 1);
        }
        if (redirect_policy_count >= kMaxRedirectPolicies) return 0;
        const Str fields[] = {policy.reason,
                              policy.server,
                              policy.content_type,
                              policy.static_authority,
                              policy.target_path,
                              policy.body};
        u32 total = 0;
        for (const Str field : fields) {
            if (field.len > kRedirectPolicyBytesPoolBytes - redirect_policy_bytes_used - total)
                return 0;
            total += field.len;
        }
        auto copy = [&](Str src, Str& dst) {
            char* out = redirect_policy_bytes + redirect_policy_bytes_used;
            for (u32 i = 0; i < src.len; i++) out[i] = src.ptr[i];
            redirect_policy_bytes_used += src.len;
            dst = {out, src.len};
        };
        auto& dst = redirect_policies[redirect_policy_count];
        dst.scheme = policy.scheme;
        dst.authority = policy.authority;
        dst.port = policy.port;
        dst.path = policy.path;
        dst.query = policy.query;
        dst.date = policy.date;
        dst.connection = policy.connection;
        dst.header_order = policy.header_order;
        dst.status_code = policy.status_code;
        copy(policy.reason, dst.reason);
        copy(policy.server, dst.server);
        copy(policy.content_type, dst.content_type);
        copy(policy.static_authority, dst.static_authority);
        copy(policy.target_path, dst.target_path);
        copy(policy.body, dst.body);
        redirect_policy_count++;
        return static_cast<u16>(redirect_policy_count);
    }

    // Validate and publish a complete borrowed table. The count and byte
    // watermark are committed only after every entry has been prevalidated,
    // so a malformed table cannot become partially visible in cfg.
    bool add_redirect_policy_table(const RedirectPolicySpec* specs, u32 count) {
        if (redirect_policy_count != 0 || redirect_policy_bytes_used != 0 ||
            !redirect_policy_table_valid(specs, count))
            return false;
        u32 total = 0;
        for (u32 i = 0; i < count; i++) {
            const Str fields[] = {specs[i].reason,
                                  specs[i].server,
                                  specs[i].content_type,
                                  specs[i].static_authority,
                                  specs[i].target_path,
                                  specs[i].body};
            for (const Str field : fields) {
                if (field.len > kRedirectPolicyBytesPoolBytes - total) return false;
                total += field.len;
            }
        }
        u32 used = 0;
        for (u32 i = 0; i < count; i++) {
            const auto& src = specs[i];
            auto& dst = redirect_policies[i];
            dst.scheme = src.scheme;
            dst.authority = src.authority;
            dst.port = src.port;
            dst.path = src.path;
            dst.query = src.query;
            dst.date = src.date;
            dst.connection = src.connection;
            dst.header_order = src.header_order;
            dst.status_code = src.status_code;
            const Str fields[] = {src.reason,
                                  src.server,
                                  src.content_type,
                                  src.static_authority,
                                  src.target_path,
                                  src.body};
            Str* destinations[] = {&dst.reason,
                                   &dst.server,
                                   &dst.content_type,
                                   &dst.static_authority,
                                   &dst.target_path,
                                   &dst.body};
            for (u32 field = 0; field < 6; field++) {
                char* out = redirect_policy_bytes + used;
                for (u32 j = 0; j < fields[field].len; j++) out[j] = fields[field].ptr[j];
                *destinations[field] = {out, fields[field].len};
                used += fields[field].len;
            }
        }
        redirect_policy_bytes_used = used;
        redirect_policy_count = count;
        return true;
    }

    bool redirect_policy_id_is_valid(u16 id) const {
        return redirect_policy_count <= kMaxRedirectPolicies &&
               redirect_policy_bytes_used <= kRedirectPolicyBytesPoolBytes && id != 0 &&
               id <= redirect_policy_count &&
               redirect_policy_strings_are_owned(redirect_policies[id - 1]) &&
               redirect_policy_spec_valid(redirect_policies[id - 1]);
    }

    // Add an upstream target. Returns its index, or error if at capacity.
    core::Expected<u32, Error> add_upstream(const char* name, u32 ip, u16 port) {
        if (upstream_count >= kMaxUpstreams)
            return core::make_unexpected(Error::make(ENOSPC, Error::Source::RouteTable));
        u32 idx = upstream_count++;
        upstreams[idx].set_name(name);
        upstreams[idx].set_addr(ip, port);
        return idx;
    }

    // Append an additional backend endpoint to an existing upstream (for
    // load balancing). `idx` must be a previously added upstream. Returns
    // false on a bad index or a full backend list.
    bool add_upstream_backend(u32 idx, u32 ip, u16 port) {
        if (idx >= upstream_count) return false;
        return upstreams[idx].add_addr(ip, port);
    }

    // Firewall helpers.
    // `ip` is host-order IPv4 (for consistency with UpstreamTarget::set_addr).
    bool add_firewall_allow_ip(u32 ip) {
        for (u32 i = 0; i < firewall_allow_count; i++) {
            if (firewall_allow_ips[i] == ip) return true;
        }
        if (firewall_allow_count >= kMaxFirewallRules) return false;
        firewall_allow_ips[firewall_allow_count++] = ip;
        return true;
    }
    bool add_firewall_allow_ip(Str ip_lit) {
        u32 ip = 0;
        if (!parse_ipv4_dotted(ip_lit, ip)) return false;
        return add_firewall_allow_ip(ip);
    }
    bool add_firewall_allow_ip(const char* ip_lit) {
        if (!ip_lit) return false;
        return add_firewall_allow_ip(cstr_as_str(ip_lit));
    }
    // `ip_network_order` uses in_addr.s_addr/getpeername representation.
    bool add_firewall_allow_ip_network_order(u32 ip_network_order) {
        return add_firewall_allow_ip(ntohl(ip_network_order));
    }
    bool remove_firewall_allow_ip(u32 ip) {
        for (u32 i = 0; i < firewall_allow_count; i++) {
            if (firewall_allow_ips[i] != ip) continue;
            for (u32 j = i + 1; j < firewall_allow_count; j++)
                firewall_allow_ips[j - 1] = firewall_allow_ips[j];
            firewall_allow_ips[firewall_allow_count - 1] = 0;
            firewall_allow_count--;
            return true;
        }
        return false;
    }
    bool remove_firewall_allow_ip(Str ip_lit) {
        u32 ip = 0;
        if (!parse_ipv4_dotted(ip_lit, ip)) return false;
        return remove_firewall_allow_ip(ip);
    }
    bool remove_firewall_allow_ip(const char* ip_lit) {
        if (!ip_lit) return false;
        return remove_firewall_allow_ip(cstr_as_str(ip_lit));
    }
    bool remove_firewall_allow_ip_network_order(u32 ip_network_order) {
        return remove_firewall_allow_ip(ntohl(ip_network_order));
    }
    bool add_firewall_deny_ip(u32 ip) {
        for (u32 i = 0; i < firewall_deny_count; i++) {
            if (firewall_deny_ips[i] == ip) return true;
        }
        if (firewall_deny_count >= kMaxFirewallRules) return false;
        firewall_deny_ips[firewall_deny_count++] = ip;
        return true;
    }
    bool add_firewall_deny_ip(Str ip_lit) {
        u32 ip = 0;
        if (!parse_ipv4_dotted(ip_lit, ip)) return false;
        return add_firewall_deny_ip(ip);
    }
    bool add_firewall_deny_ip(const char* ip_lit) {
        if (!ip_lit) return false;
        return add_firewall_deny_ip(cstr_as_str(ip_lit));
    }
    bool add_firewall_deny_ip_network_order(u32 ip_network_order) {
        return add_firewall_deny_ip(ntohl(ip_network_order));
    }
    bool remove_firewall_deny_ip(u32 ip) {
        for (u32 i = 0; i < firewall_deny_count; i++) {
            if (firewall_deny_ips[i] != ip) continue;
            for (u32 j = i + 1; j < firewall_deny_count; j++)
                firewall_deny_ips[j - 1] = firewall_deny_ips[j];
            firewall_deny_ips[firewall_deny_count - 1] = 0;
            firewall_deny_count--;
            return true;
        }
        return false;
    }
    bool remove_firewall_deny_ip(Str ip_lit) {
        u32 ip = 0;
        if (!parse_ipv4_dotted(ip_lit, ip)) return false;
        return remove_firewall_deny_ip(ip);
    }
    bool remove_firewall_deny_ip(const char* ip_lit) {
        if (!ip_lit) return false;
        return remove_firewall_deny_ip(cstr_as_str(ip_lit));
    }
    bool remove_firewall_deny_ip_network_order(u32 ip_network_order) {
        return remove_firewall_deny_ip(ntohl(ip_network_order));
    }
    bool add_firewall_allow_port(u16 port) {
        if (port == 0) return false;
        for (u32 i = 0; i < firewall_allow_port_count; i++) {
            if (firewall_allow_ports[i] == port) return true;
        }
        if (firewall_allow_port_count >= kMaxFirewallRules) return false;
        firewall_allow_ports[firewall_allow_port_count++] = port;
        return true;
    }
    bool remove_firewall_allow_port(u16 port) {
        for (u32 i = 0; i < firewall_allow_port_count; i++) {
            if (firewall_allow_ports[i] != port) continue;
            for (u32 j = i + 1; j < firewall_allow_port_count; j++)
                firewall_allow_ports[j - 1] = firewall_allow_ports[j];
            firewall_allow_ports[firewall_allow_port_count - 1] = 0;
            firewall_allow_port_count--;
            return true;
        }
        return false;
    }
    bool add_firewall_deny_port(u16 port) {
        if (port == 0) return false;
        for (u32 i = 0; i < firewall_deny_port_count; i++) {
            if (firewall_deny_ports[i] == port) return true;
        }
        if (firewall_deny_port_count >= kMaxFirewallRules) return false;
        firewall_deny_ports[firewall_deny_port_count++] = port;
        return true;
    }
    bool remove_firewall_deny_port(u16 port) {
        for (u32 i = 0; i < firewall_deny_port_count; i++) {
            if (firewall_deny_ports[i] != port) continue;
            for (u32 j = i + 1; j < firewall_deny_port_count; j++)
                firewall_deny_ports[j - 1] = firewall_deny_ports[j];
            firewall_deny_ports[firewall_deny_port_count - 1] = 0;
            firewall_deny_port_count--;
            return true;
        }
        return false;
    }
    bool add_firewall_allow_cidr(u32 ip, u8 prefix_len) {
        if (prefix_len > 32) return false;
        const u32 mask = prefix_len == 0 ? 0u : (0xffffffffu << (32u - prefix_len));
        const u32 net_addr = ip & mask;
        for (u32 i = 0; i < firewall_allow_cidr_count; i++) {
            const auto& r = firewall_allow_cidrs[i];
            if (r.net_addr == net_addr && r.mask == mask) return true;
        }
        if (firewall_allow_cidr_count >= kMaxFirewallRules) return false;
        firewall_allow_cidrs[firewall_allow_cidr_count++] = {net_addr, mask};
        return true;
    }
    bool add_firewall_allow_cidr(Str cidr_lit) {
        u32 ip = 0;
        u8 prefix_len = 0;
        if (!parse_ipv4_cidr(cidr_lit, ip, prefix_len)) return false;
        return add_firewall_allow_cidr(ip, prefix_len);
    }
    bool add_firewall_allow_cidr(const char* cidr_lit) {
        if (!cidr_lit) return false;
        return add_firewall_allow_cidr(cstr_as_str(cidr_lit));
    }
    bool add_firewall_allow_cidr_network_order(u32 ip_network_order, u8 prefix_len) {
        return add_firewall_allow_cidr(ntohl(ip_network_order), prefix_len);
    }
    bool add_firewall_allow_range(u32 start_ip, u32 end_ip) {
        if (start_ip > end_ip) return false;
        for (u32 i = 0; i < firewall_allow_range_count; i++) {
            const auto& r = firewall_allow_ranges[i];
            if (r.start_ip == start_ip && r.end_ip == end_ip) return true;
        }
        if (firewall_allow_range_count >= kMaxFirewallRules) return false;
        firewall_allow_ranges[firewall_allow_range_count++] = {start_ip, end_ip};
        return true;
    }
    bool add_firewall_allow_range(Str range_lit) {
        u32 start_ip = 0;
        u32 end_ip = 0;
        if (!parse_ipv4_range(range_lit, start_ip, end_ip)) return false;
        return add_firewall_allow_range(start_ip, end_ip);
    }
    bool add_firewall_allow_range(const char* range_lit) {
        if (!range_lit) return false;
        return add_firewall_allow_range(cstr_as_str(range_lit));
    }
    bool add_firewall_allow_range_network_order(u32 start_ip_network_order,
                                                u32 end_ip_network_order) {
        return add_firewall_allow_range(ntohl(start_ip_network_order), ntohl(end_ip_network_order));
    }
    bool remove_firewall_allow_range(u32 start_ip, u32 end_ip) {
        if (start_ip > end_ip) return false;
        for (u32 i = 0; i < firewall_allow_range_count; i++) {
            const auto& r = firewall_allow_ranges[i];
            if (r.start_ip != start_ip || r.end_ip != end_ip) continue;
            for (u32 j = i + 1; j < firewall_allow_range_count; j++)
                firewall_allow_ranges[j - 1] = firewall_allow_ranges[j];
            firewall_allow_ranges[firewall_allow_range_count - 1] = {0, 0};
            firewall_allow_range_count--;
            return true;
        }
        return false;
    }
    bool remove_firewall_allow_range(Str range_lit) {
        u32 start_ip = 0;
        u32 end_ip = 0;
        if (!parse_ipv4_range(range_lit, start_ip, end_ip)) return false;
        return remove_firewall_allow_range(start_ip, end_ip);
    }
    bool remove_firewall_allow_range(const char* range_lit) {
        if (!range_lit) return false;
        return remove_firewall_allow_range(cstr_as_str(range_lit));
    }
    bool remove_firewall_allow_range_network_order(u32 start_ip_network_order,
                                                   u32 end_ip_network_order) {
        return remove_firewall_allow_range(ntohl(start_ip_network_order),
                                           ntohl(end_ip_network_order));
    }
    bool remove_firewall_allow_cidr(u32 ip, u8 prefix_len) {
        if (prefix_len > 32) return false;
        const u32 mask = prefix_len == 0 ? 0u : (0xffffffffu << (32u - prefix_len));
        const u32 net_addr = ip & mask;
        for (u32 i = 0; i < firewall_allow_cidr_count; i++) {
            const auto& r = firewall_allow_cidrs[i];
            if (r.net_addr != net_addr || r.mask != mask) continue;
            for (u32 j = i + 1; j < firewall_allow_cidr_count; j++)
                firewall_allow_cidrs[j - 1] = firewall_allow_cidrs[j];
            firewall_allow_cidrs[firewall_allow_cidr_count - 1] = {0, 0};
            firewall_allow_cidr_count--;
            return true;
        }
        return false;
    }
    bool remove_firewall_allow_cidr(Str cidr_lit) {
        u32 ip = 0;
        u8 prefix_len = 0;
        if (!parse_ipv4_cidr(cidr_lit, ip, prefix_len)) return false;
        return remove_firewall_allow_cidr(ip, prefix_len);
    }
    bool remove_firewall_allow_cidr(const char* cidr_lit) {
        if (!cidr_lit) return false;
        return remove_firewall_allow_cidr(cstr_as_str(cidr_lit));
    }
    bool remove_firewall_allow_cidr_network_order(u32 ip_network_order, u8 prefix_len) {
        return remove_firewall_allow_cidr(ntohl(ip_network_order), prefix_len);
    }
    bool add_firewall_deny_cidr(u32 ip, u8 prefix_len) {
        if (prefix_len > 32) return false;
        const u32 mask = prefix_len == 0 ? 0u : (0xffffffffu << (32u - prefix_len));
        const u32 net_addr = ip & mask;
        for (u32 i = 0; i < firewall_deny_cidr_count; i++) {
            const auto& r = firewall_deny_cidrs[i];
            if (r.net_addr == net_addr && r.mask == mask) return true;
        }
        if (firewall_deny_cidr_count >= kMaxFirewallRules) return false;
        firewall_deny_cidrs[firewall_deny_cidr_count++] = {net_addr, mask};
        return true;
    }
    bool add_firewall_deny_cidr(Str cidr_lit) {
        u32 ip = 0;
        u8 prefix_len = 0;
        if (!parse_ipv4_cidr(cidr_lit, ip, prefix_len)) return false;
        return add_firewall_deny_cidr(ip, prefix_len);
    }
    bool add_firewall_deny_cidr(const char* cidr_lit) {
        if (!cidr_lit) return false;
        return add_firewall_deny_cidr(cstr_as_str(cidr_lit));
    }
    bool add_firewall_deny_cidr_network_order(u32 ip_network_order, u8 prefix_len) {
        return add_firewall_deny_cidr(ntohl(ip_network_order), prefix_len);
    }
    bool add_firewall_deny_range(u32 start_ip, u32 end_ip) {
        if (start_ip > end_ip) return false;
        for (u32 i = 0; i < firewall_deny_range_count; i++) {
            const auto& r = firewall_deny_ranges[i];
            if (r.start_ip == start_ip && r.end_ip == end_ip) return true;
        }
        if (firewall_deny_range_count >= kMaxFirewallRules) return false;
        firewall_deny_ranges[firewall_deny_range_count++] = {start_ip, end_ip};
        return true;
    }
    bool add_firewall_deny_range(Str range_lit) {
        u32 start_ip = 0;
        u32 end_ip = 0;
        if (!parse_ipv4_range(range_lit, start_ip, end_ip)) return false;
        return add_firewall_deny_range(start_ip, end_ip);
    }
    bool add_firewall_deny_range(const char* range_lit) {
        if (!range_lit) return false;
        return add_firewall_deny_range(cstr_as_str(range_lit));
    }
    bool add_firewall_deny_range_network_order(u32 start_ip_network_order,
                                               u32 end_ip_network_order) {
        return add_firewall_deny_range(ntohl(start_ip_network_order), ntohl(end_ip_network_order));
    }
    bool remove_firewall_deny_range(u32 start_ip, u32 end_ip) {
        if (start_ip > end_ip) return false;
        for (u32 i = 0; i < firewall_deny_range_count; i++) {
            const auto& r = firewall_deny_ranges[i];
            if (r.start_ip != start_ip || r.end_ip != end_ip) continue;
            for (u32 j = i + 1; j < firewall_deny_range_count; j++)
                firewall_deny_ranges[j - 1] = firewall_deny_ranges[j];
            firewall_deny_ranges[firewall_deny_range_count - 1] = {0, 0};
            firewall_deny_range_count--;
            return true;
        }
        return false;
    }
    bool remove_firewall_deny_range(Str range_lit) {
        u32 start_ip = 0;
        u32 end_ip = 0;
        if (!parse_ipv4_range(range_lit, start_ip, end_ip)) return false;
        return remove_firewall_deny_range(start_ip, end_ip);
    }
    bool remove_firewall_deny_range(const char* range_lit) {
        if (!range_lit) return false;
        return remove_firewall_deny_range(cstr_as_str(range_lit));
    }
    bool remove_firewall_deny_range_network_order(u32 start_ip_network_order,
                                                  u32 end_ip_network_order) {
        return remove_firewall_deny_range(ntohl(start_ip_network_order),
                                          ntohl(end_ip_network_order));
    }
    bool remove_firewall_deny_cidr(u32 ip, u8 prefix_len) {
        if (prefix_len > 32) return false;
        const u32 mask = prefix_len == 0 ? 0u : (0xffffffffu << (32u - prefix_len));
        const u32 net_addr = ip & mask;
        for (u32 i = 0; i < firewall_deny_cidr_count; i++) {
            const auto& r = firewall_deny_cidrs[i];
            if (r.net_addr != net_addr || r.mask != mask) continue;
            for (u32 j = i + 1; j < firewall_deny_cidr_count; j++)
                firewall_deny_cidrs[j - 1] = firewall_deny_cidrs[j];
            firewall_deny_cidrs[firewall_deny_cidr_count - 1] = {0, 0};
            firewall_deny_cidr_count--;
            return true;
        }
        return false;
    }
    bool remove_firewall_deny_cidr(Str cidr_lit) {
        u32 ip = 0;
        u8 prefix_len = 0;
        if (!parse_ipv4_cidr(cidr_lit, ip, prefix_len)) return false;
        return remove_firewall_deny_cidr(ip, prefix_len);
    }
    bool remove_firewall_deny_cidr(const char* cidr_lit) {
        if (!cidr_lit) return false;
        return remove_firewall_deny_cidr(cstr_as_str(cidr_lit));
    }
    bool remove_firewall_deny_cidr_network_order(u32 ip_network_order, u8 prefix_len) {
        return remove_firewall_deny_cidr(ntohl(ip_network_order), prefix_len);
    }
    void clear_firewall_allow_rules() {
        for (u32 i = 0; i < firewall_allow_count; i++) firewall_allow_ips[i] = 0;
        for (u32 i = 0; i < firewall_allow_cidr_count; i++) firewall_allow_cidrs[i] = {0, 0};
        for (u32 i = 0; i < firewall_allow_range_count; i++) firewall_allow_ranges[i] = {0, 0};
        for (u32 i = 0; i < firewall_allow_port_count; i++) firewall_allow_ports[i] = 0;
        firewall_allow_count = 0;
        firewall_allow_cidr_count = 0;
        firewall_allow_range_count = 0;
        firewall_allow_port_count = 0;
    }
    void clear_firewall_deny_rules() {
        for (u32 i = 0; i < firewall_deny_count; i++) firewall_deny_ips[i] = 0;
        for (u32 i = 0; i < firewall_deny_cidr_count; i++) firewall_deny_cidrs[i] = {0, 0};
        for (u32 i = 0; i < firewall_deny_range_count; i++) firewall_deny_ranges[i] = {0, 0};
        for (u32 i = 0; i < firewall_deny_port_count; i++) firewall_deny_ports[i] = 0;
        firewall_deny_count = 0;
        firewall_deny_cidr_count = 0;
        firewall_deny_range_count = 0;
        firewall_deny_port_count = 0;
    }
    void clear_firewall_rules() {
        clear_firewall_allow_rules();
        clear_firewall_deny_rules();
    }
    void set_firewall_default_allow(bool allow) { firewall_default_allow = allow; }
    void set_firewall_default_deny() { firewall_default_allow = false; }
    bool firewall_default_is_allow() const { return firewall_default_allow; }

    FirewallDecision firewall_decision(u32 peer_addr, u16 peer_port) const {
        return firewall_decision_impl(ntohl(peer_addr), true, peer_port);
    }
    FirewallDecision firewall_decision(u32 peer_addr) const {
        return firewall_decision_impl(ntohl(peer_addr), false, 0);
    }
    FirewallDecision firewall_decision_host(u32 peer_host_addr) const {
        return firewall_decision(htonl(peer_host_addr));
    }
    FirewallDecision firewall_decision_host(u32 peer_host_addr, u16 peer_port) const {
        return firewall_decision(htonl(peer_host_addr), peer_port);
    }

    // `peer_addr` must be in network byte order (same as getpeername()).
    // It is converted to packed host-order u32 before matching:
    //   (a << 24) | (b << 16) | (c << 8) | d
    // Address-only overloads ignore port rule tables by design (legacy behavior).
    bool firewall_allows_peer(u32 peer_addr) const {
        const FirewallDecision d = firewall_decision(peer_addr);
        return firewall_decision_is_allow(d);
    }
    bool firewall_allows_peer(u32 peer_addr, u16 peer_port) const {
        const FirewallDecision d = firewall_decision(peer_addr, peer_port);
        return firewall_decision_is_allow(d);
    }
    // Convenience overload for host-order IPv4 callers.
    bool firewall_allows_peer_host(u32 peer_host_addr) const {
        return firewall_allows_peer(htonl(peer_host_addr));
    }
    bool firewall_allows_peer_host(u32 peer_host_addr, u16 peer_port) const {
        return firewall_allows_peer(htonl(peer_host_addr), peer_port);
    }

private:
    FirewallDecision firewall_decision_impl(u32 peer_host,
                                            bool use_port_rules,
                                            u16 peer_port) const {
        for (u32 i = 0; i < firewall_deny_count; i++) {
            if (firewall_deny_ips[i] == peer_host) return FirewallDecision::DeniedByIp;
        }
        for (u32 i = 0; i < firewall_deny_cidr_count; i++) {
            const auto& r = firewall_deny_cidrs[i];
            if ((peer_host & r.mask) == r.net_addr) return FirewallDecision::DeniedByCidr;
        }
        for (u32 i = 0; i < firewall_deny_range_count; i++) {
            const auto& r = firewall_deny_ranges[i];
            if (peer_host >= r.start_ip && peer_host <= r.end_ip)
                return FirewallDecision::DeniedByRange;
        }
        if (use_port_rules) {
            for (u32 i = 0; i < firewall_deny_port_count; i++) {
                if (firewall_deny_ports[i] == peer_port) return FirewallDecision::DeniedByPort;
            }
        }
        const bool has_allow_rules = firewall_allow_count > 0 || firewall_allow_cidr_count > 0 ||
                                     firewall_allow_range_count > 0 ||
                                     (use_port_rules && firewall_allow_port_count > 0);
        if (!has_allow_rules) {
            return firewall_default_allow ? FirewallDecision::AllowedDefault
                                          : FirewallDecision::DeniedByMissingAllowMatch;
        }
        for (u32 i = 0; i < firewall_allow_count; i++) {
            if (firewall_allow_ips[i] == peer_host) return FirewallDecision::AllowedByIp;
        }
        for (u32 i = 0; i < firewall_allow_cidr_count; i++) {
            const auto& r = firewall_allow_cidrs[i];
            if ((peer_host & r.mask) == r.net_addr) return FirewallDecision::AllowedByCidr;
        }
        for (u32 i = 0; i < firewall_allow_range_count; i++) {
            const auto& r = firewall_allow_ranges[i];
            if (peer_host >= r.start_ip && peer_host <= r.end_ip)
                return FirewallDecision::AllowedByRange;
        }
        if (use_port_rules) {
            for (u32 i = 0; i < firewall_allow_port_count; i++) {
                if (firewall_allow_ports[i] == peer_port) return FirewallDecision::AllowedByPort;
            }
        }
        return FirewallDecision::DeniedByMissingAllowMatch;
    }

    static Str cstr_as_str(const char* s) {
        u32 len = 0;
        while (s[len]) len++;
        return {s, len};
    }

    static bool parse_ipv4_dotted(Str s, u32& out_ip) {
        u32 octets[4] = {0, 0, 0, 0};
        u32 octet_idx = 0;
        u32 digit_count = 0;
        u32 cur = 0;
        for (u32 i = 0; i < s.len; i++) {
            const char c = s.ptr[i];
            if (c == '.') {
                if (digit_count == 0 || octet_idx >= 3) return false;
                octets[octet_idx++] = cur;
                cur = 0;
                digit_count = 0;
                continue;
            }
            if (c < '0' || c > '9') return false;
            cur = cur * 10 + static_cast<u32>(c - '0');
            if (cur > 255 || ++digit_count > 3) return false;
        }
        if (digit_count == 0 || octet_idx != 3) return false;
        octets[3] = cur;
        out_ip = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
        return true;
    }

    static bool parse_ipv4_cidr(Str s, u32& out_ip, u8& out_prefix_len) {
        u32 slash_idx = 0xffffffffu;
        for (u32 i = 0; i < s.len; i++) {
            if (s.ptr[i] == '/') {
                if (slash_idx != 0xffffffffu) return false;
                slash_idx = i;
            }
        }
        if (slash_idx == 0xffffffffu || slash_idx == 0 || slash_idx + 1 >= s.len) return false;
        if (!parse_ipv4_dotted({s.ptr, slash_idx}, out_ip)) return false;
        u32 prefix = 0;
        for (u32 i = slash_idx + 1; i < s.len; i++) {
            const char c = s.ptr[i];
            if (c < '0' || c > '9') return false;
            prefix = prefix * 10 + static_cast<u32>(c - '0');
            if (prefix > 32) return false;
        }
        out_prefix_len = static_cast<u8>(prefix);
        return true;
    }
    static bool parse_ipv4_range(Str s, u32& out_start_ip, u32& out_end_ip) {
        u32 dash_idx = 0xffffffffu;
        for (u32 i = 0; i < s.len; i++) {
            if (s.ptr[i] == '-') {
                if (dash_idx != 0xffffffffu) return false;
                dash_idx = i;
            }
        }
        if (dash_idx == 0xffffffffu || dash_idx == 0 || dash_idx + 1 >= s.len) return false;
        if (!parse_ipv4_dotted({s.ptr, dash_idx}, out_start_ip)) return false;
        if (!parse_ipv4_dotted({s.ptr + dash_idx + 1, s.len - dash_idx - 1}, out_end_ip))
            return false;
        return out_start_ip <= out_end_ip;
    }

public:
    // Match a request path. Semantics depend on the chosen dispatch
    // (`this->dispatch`), but the default linear-scan dispatch keeps
    // the historical contract: first-match-wins byte-prefix scan,
    // method 0 in a route entry matches any request method, and
    // unmatched requests return nullptr (callers fall back to the
    // default 200 OK handler).
    //
    // `method` is a route method key (0 = any, 1..9 = full HTTP
    // method), or a legacy first-char method byte accepted for
    // hand-built configs. This compatibility wrapper canonicalizes
    // before entering the dispatch hot path.
    const RouteEntry* match(const u8* path_data, u32 path_len, u8 method) const {
        // Reject non-origin-form request targets (asterisk-form `*`,
        // authority-form `host:port`, empty). Origin-form must start
        // with '/'. Done here at dispatch entry so the inner match()
        // functions can assume canonical input shape; the previous
        // per-impl checks (ArtTrie::match, RouteTrie::match) are
        // gone in PR #50 round 6.
        if (path_len == 0 || path_data[0] != '/') return nullptr;

        // Canonicalize once at dispatch entry. The JIT'd function and
        // scalar match() inner functions both consume canonical input,
        // so the canon scan happens exactly once per request
        // regardless of dispatch kind. Convenience wrapper for callers
        // that don't have a parser-produced path_canon (tests,
        // integration helpers); the production hot path goes through
        // match_canonical which skips this scan entirely.
        const Str raw{reinterpret_cast<const char*>(path_data), path_len};
        return match_canonical(canonicalize_request(raw),
                               route_method_key_from_legacy_char(method));
    }

    // Fast path for callers with a pre-canonicalized path. PR #50
    // round 7 (path A): the HTTP parser populates ParsedRequest::path_canon
    // as a free byproduct of the URI SIMD scan, so the production hot
    // path (callbacks_impl.h dispatch) calls this directly and avoids
    // re-scanning the same bytes. Caller MUST guarantee canon shape:
    // no leading '/', no trailing '/', no '?'/'#' bytes.
    //
    // canon.ptr == nullptr is a "no canonical view available" sentinel
    // (parser left path_canon zero-init'd because the URI was not
    // origin-form, or capture_request_metadata couldn't parse). Treat
    // it as a miss so non-origin-form targets cannot fall into a
    // configured "/" catchall. canon.len == 0 with non-null ptr is
    // legitimate (origin-form root "/") and dispatches normally.
    // `method` must be a canonical route method key. Compatibility
    // callers with legacy first-char bytes should use match().
    const RouteEntry* match_canonical(Str canon, u8 method) const {
        return match_canonical(canon, method, nullptr, nullptr, 0);
    }

    const RouteEntry* match_canonical(Str canon,
                                      u8 method,
                                      RouteParam* out_params,
                                      u32* out_param_count,
                                      u32 out_param_cap) const {
        if (out_param_count) *out_param_count = 0;
        if (canon.ptr == nullptr) return nullptr;
        u16 idx;
        switch (dispatch_kind_) {
            case DispatchKind::ArtJit:
                idx = art_jit_fn_ ? art_jit_fn_(canon.ptr, canon.len, method)
                                  : art_state.match_canonical_key(canon, method);
                break;
            case DispatchKind::SegmentTrie:
                idx = trie.match_key(canon, method, out_params, out_param_count, out_param_cap);
                break;
            default:
                __builtin_unreachable();
        }
        if (idx >= route_count) return nullptr;  // covers TrieNode::kInvalidRoute
        return &routes[idx];
    }

private:
    // ART is byte-prefix based and cannot interpret `:param` segments, so
    // reject dynamic routes there. SegmentTrie supports dynamic segments
    // and request-time capture.
    bool dispatch_accepts_path_shape(const char* path) const {
        u32 plen = 0;
        while (path[plen]) plen++;
        if (!path_has_param_segment(Str{path, plen})) return true;
        return dispatch_kind_ == DispatchKind::SegmentTrie;
    }

    bool param_count_fits(const char* path) const {
        u32 count = 0;
        bool at_start = true;
        for (u32 i = 0; path[i]; i++) {
            if (path[i] == '/') {
                at_start = true;
                continue;
            }
            if (at_start && path[i] == ':') {
                count++;
                if (count > kMaxRouteParams) return false;
            }
            at_start = false;
        }
        return true;
    }

    // Tagged-union discriminator. Default is ArtJit since most
    // configs land there post-#41 picker reduction; tests and
    // tooling that call use_segment_trie() before add_* swap
    // explicitly. ArtJit before install_art_jit_fn falls back to
    // scalar ArtTrie::match — slower but always correct.
    DispatchKind dispatch_kind_ = DispatchKind::ArtJit;

    // JIT'd match function pointer (used when dispatch_kind_ ==
    // ArtJit and install_art_jit_fn has been called). nullptr means
    // use scalar fallback.
    jit::ArtJitMatchFn art_jit_fn_ = nullptr;
};

inline bool route_requires_response_read_timeout_preflight_close(const RouteEntry* route,
                                                                 const RouteConfig* config) {
    if (route == nullptr) return false;
    if (route->forward_preflight_mode == ForwardPreflightMode::None &&
        route->preflight_forward_policy_bundle_id == 0)
        return false;
    if (!forward_preflight_mode_valid(route->forward_preflight_mode) ||
        route->forward_preflight_mode != ForwardPreflightMode::EagerDirect ||
        route->preflight_forward_policy_bundle_id == 0)
        return true;
    const u16 id = route->preflight_forward_policy_bundle_id;
    if (config == nullptr || !config->policy_bundle_id_is_valid(id)) return true;
    const auto& bundle = config->policy_bundles[id - 1];
    // A forged route marker that points at a legacy zero-duration bundle is
    // invalid too. Both valid metadata and every invalid shape use the same
    // zero-byte close boundary.
    if (!response_read_timeout_seconds_valid(bundle.response_read_timeout_seconds)) return true;
    return true;
}

}  // namespace rut
