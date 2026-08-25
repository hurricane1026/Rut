#pragma once

// Bridge header: copy the RIR module's declarative content (upstreams
// with addresses, response bodies, response header sets) into a
// RouteConfig so the runtime can serve the compiled handlers.
//
// This helper intentionally does NOT register route entries — those
// require the JitEngine to have compiled and looked up each handler
// function, which is orthogonal to the declarative content here.
// Callers typically:
//   1. jit::codegen(rir.module) → LLVM IR module
//   2. engine.compile(...)
//   3. populate_route_config(cfg, rir.module) for upstreams / bodies /
//      header sets
//   4. register_jit_routes(cfg, rir.module, engine) to select the
//      correct dispatcher and add every route handler
//   5. At the RouteConfig ACTIVATION boundary (not merely after compiling):
//      cache_registry_publish_config(cfg). The cache helpers read the
//      process-global registry, so preparing a replacement config must not
//      publish early and perturb the still-live program. The production
//      loader exposes activate_rut_program() for this step.
//
// Two supported preconditions on `cfg`:
//
//   1. FULLY EMPTY (no routes / upstreams / bodies / header sets).
//      Helper populates every upstream from the module. Requires every
//      DSL upstream to have an address (`upstream X at "..."` or
//      `upstream X { host, port }`). Name-only upstreams cause a
//      fail-fast return because the helper has no address to bind.
//
//   2. PRE-BOUND UPSTREAMS (cfg.upstream_count == mod.upstream_count,
//      bodies / header sets / routes still empty). Helper skips the
//      upstream loop and only populates bodies + header sets. The
//      caller is responsible for having added upstreams in DSL
//      declaration order — the helper verifies each cfg.upstreams[i]
//      name matches mod.upstreams[i] under ASCII case-sensitive
//      compare, so mis-ordered or mis-named entries are caught before
//      the compile-time `upstream_index` resolves to the wrong
//      backend. This is the workflow to use when some or all
//      upstreams are name-only in the DSL and bound at runtime (from
//      a config file, env var, CLI flag, service discovery, etc.).
//
// Any other shape — partial routes / bodies / header sets already in
// cfg, or upstream_count mismatching mod.upstream_count — is rejected.
//
// Returns true on full success. On any partial failure (capacity
// exceeded, validation rejected) the function stops and returns false;
// `cfg` may have been partially populated, so callers should discard
// it rather than try to reuse it.

#include "rut/compiler/hir.h"  // HirModule::kMaxTimers (frontend timer cap)
#include "rut/compiler/rir.h"
#include "rut/compiler/verifier.h"
#include "rut/jit/codegen.h"
#include "rut/jit/jit_engine.h"
#include "rut/runtime/cache_table.h"
#include "rut/runtime/route_table.h"
#include <memory>
#include <new>

namespace rut {

// Redirect IDs are embedded in RIR terminators, so validating only the
// metadata table is insufficient: a forged instruction could otherwise reach
// codegen or route registration with an out-of-range reference.  Keep this
// narrow publication-boundary check shared by the loader and the config
// population helper.
inline bool redirect_references_valid(const rir::Module& mod) {
    if (!redirect_policy_table_valid(mod.redirect_policies, mod.redirect_policy_count))
        return false;
    if (mod.func_count != 0 && mod.functions == nullptr) return false;
    for (u32 fi = 0; fi < mod.func_count; fi++) {
        const auto& fn = mod.functions[fi];
        if (fn.block_count != 0 && fn.blocks == nullptr) return false;
        for (u32 bi = 0; bi < fn.block_count; bi++) {
            const auto& block = fn.blocks[bi];
            if (block.inst_count != 0 && block.insts == nullptr) return false;
            for (u32 ii = 0; ii < block.inst_count; ii++) {
                const auto& inst = block.insts[ii];
                if (inst.op != rir::Opcode::RetRedirect) continue;
                const i64 id = inst.imm.i32_val;
                if (inst.operand_count != 0 || id <= 0 ||
                    static_cast<u64>(id) > mod.redirect_policy_count ||
                    !redirect_policy_spec_valid(mod.redirect_policies[id - 1]))
                    return false;
            }
        }
    }
    return true;
}

// The frontend (analyze.cc) caps declared timers at HirModule::kMaxTimers so a
// surplus is a deterministic DSL error; that cap must fit the runtime table, or
// RouteConfig::add_timer would still reject the overflow at load time.
static_assert(HirModule::kMaxTimers <= RouteConfig::kMaxTimers,
              "frontend timer cap must not exceed the runtime timer table");
// Same containment rule for Cache instance declarations.
static_assert(HirModule::kMaxCaches <= RouteConfig::kMaxCacheInstances,
              "frontend cache cap must not exceed the runtime cache table");

inline bool rir_function_needs_req_body(const rir::Function& fn) {
    if (fn.blocks == nullptr) return false;
    for (u32 bi = 0; bi < fn.block_count; bi++) {
        const auto& block = fn.blocks[bi];
        if (block.insts == nullptr) continue;
        for (u32 ii = 0; ii < block.inst_count; ii++) {
            if (block.insts[ii].op == rir::Opcode::ReqBody) return true;
        }
    }
    return false;
}

inline bool configure_route_dispatch(RouteConfig& cfg, const rir::Module& mod) {
    if (cfg.route_count != 0) return false;
    if (mod.func_count > 0 && mod.functions == nullptr) return false;

    // Count only HTTP routes — timer functions are fired on a schedule, not matched
    // against request paths. Including them would (a) overflow the kMaxRoutes-sized
    // paths[] when func_count exceeds kMaxRoutes (routes + timers can reach
    // kMaxRoutes + kMaxTimers), and (b) let a timer name influence trie selection.
    Str paths[RouteConfig::kMaxRoutes];
    u32 route_count = 0;
    for (u32 i = 0; i < mod.func_count; i++) {
        if (mod.functions[i].is_timer) continue;
        if (route_count >= RouteConfig::kMaxRoutes) return false;
        paths[route_count] = mod.functions[i].route_pattern;
        if (paths[route_count].len > 0 && paths[route_count].ptr == nullptr) return false;
        route_count++;
    }

    if (needs_segment_aware(paths, route_count)) return cfg.use_segment_trie();
    return cfg.use_art();
}

inline bool register_jit_routes(RouteConfig& cfg, const rir::Module& mod, jit::JitEngine& engine) {
    // Guard on BOTH tables: a timer-only module never bumps route_count, so a
    // route_count-only precondition would let a second call re-append the same
    // timers (firing them twice per interval).
    if (cfg.route_count != 0 || cfg.timer_count != 0 || !rir::verify_module(mod).ok ||
        mod.func_count > RouteConfig::kMaxRoutes + RouteConfig::kMaxTimers)
        return false;
    if (cfg.policy_bundle_count != mod.policy_bundle_count) return false;
    for (u32 i = 0; i < mod.policy_bundle_count; i++) {
        const auto& expected = mod.policy_bundles[i];
        const auto& actual = cfg.policy_bundles[i];
        if (!cfg.policy_bundle_id_is_valid(static_cast<u16>(i + 1)) ||
            expected.response_policy_id != actual.response_policy_id ||
            expected.failure_policy_id != actual.failure_policy_id ||
            expected.timeout_failure_policy_id != actual.timeout_failure_policy_id ||
            expected.response_read_timeout_seconds != actual.response_read_timeout_seconds ||
            expected.response_buffering != actual.response_buffering)
            return false;
    }

    jit::HandlerFn handlers[RouteConfig::kMaxRoutes + RouteConfig::kMaxTimers]{};
    for (u32 i = 0; i < mod.func_count; i++) {
        const auto& fn = mod.functions[i];
        if (fn.route_pattern.len >= RouteEntry::kMaxPathLen) return false;
        if (fn.route_pattern.len > 0 && fn.route_pattern.ptr == nullptr) return false;
        if (fn.name.len > 0 && fn.name.ptr == nullptr) return false;

        char symbol[256];
        jit::format_handler_symbol(fn.name, symbol, sizeof(symbol));
        auto* addr = engine.lookup(symbol);
        if (!addr) return false;
        handlers[i] = reinterpret_cast<jit::HandlerFn>(addr);
    }

    auto replay = [&](RouteConfig& target) {
        if (!configure_route_dispatch(target, mod)) return false;
        for (u32 i = 0; i < mod.func_count; i++) {
            const auto& fn = mod.functions[i];
            const auto handler = handlers[i];

            // A timer compiles like a route but is fired on schedule, not matched
            // against requests: register it into the timer table (route_pattern holds
            // the timer name) and skip route registration.
            if (fn.is_timer) {
                if (!target.add_timer(fn.route_pattern.ptr,
                                      fn.route_pattern.len,
                                      fn.timer_interval_ms,
                                      handler,
                                      fn.timer_shard))
                    return false;
                continue;
            }

            char path[RouteEntry::kMaxPathLen];
            for (u32 j = 0; j < fn.route_pattern.len; j++) path[j] = fn.route_pattern.ptr[j];
            path[fn.route_pattern.len] = '\0';

            if (!target.add_jit_handler(path,
                                        fn.http_method,
                                        handler,
                                        rir_function_needs_req_body(fn),
                                        fn.forward_preflight_mode,
                                        fn.preflight_forward_policy_bundle_id))
                return false;
            // @rateLimit decorators → stacked token-bucket rules, each with its own
            // metering key (the route just added is at index route_count - 1).
            if (fn.rate_limit.count > 0) {
                const u32 kRouteIdx = target.route_count - 1;
                for (u32 ri = 0; ri < fn.rate_limit.count; ri++) {
                    const RateLimitRule& rule = fn.rate_limit.rules[ri];
                    if (!target.add_route_rate_limit_rule(
                            kRouteIdx, rule.max, rule.window_sec, rule.scope, rule.burst))
                        return false;
                    for (u32 ki = 0; ki < rule.key.count; ki++) {
                        const RateLimitKeyComponent& kc = rule.key.comps[ki];
                        if (!target.add_route_rate_limit_key(
                                kRouteIdx, kc.kind, kc.name, kc.name_len))
                            return false;
                    }
                }
            }
            if (fn.throttle_down_bps > 0 &&
                !target.set_route_throttle(target.route_count - 1, fn.throttle_down_bps))
                return false;
        }
        return true;
    };

    RouteConfig* probe = new (std::nothrow) RouteConfig();
    if (probe == nullptr) return false;
    // The replay transaction validates typed route metadata against owned
    // policy tables too. Rebuild only those tables through their public owning
    // APIs: RouteConfig is intentionally non-copyable because its dispatch
    // structures contain views into routes[].
    bool probe_policies_valid = true;
    for (u32 i = 0; probe_policies_valid && i < cfg.response_policy_count; i++)
        probe_policies_valid =
            probe->add_response_policy(cfg.response_policies[i]) == static_cast<u16>(i + 1);
    for (u32 i = 0; probe_policies_valid && i < cfg.failure_policy_count; i++)
        probe_policies_valid =
            probe->add_failure_policy(cfg.failure_policies[i]) == static_cast<u16>(i + 1);
    for (u32 i = 0; probe_policies_valid && i < cfg.policy_bundle_count; i++) {
        const auto& bundle = cfg.policy_bundles[i];
        probe_policies_valid =
            probe->add_policy_bundle(bundle.response_policy_id,
                                     bundle.failure_policy_id,
                                     bundle.timeout_failure_policy_id,
                                     bundle.response_read_timeout_seconds,
                                     bundle.response_buffering) == static_cast<u16>(i + 1);
    }
    if (!probe_policies_valid) {
        delete probe;
        return false;
    }
    const bool staged = replay(*probe);
    delete probe;
    if (!staged) return false;
    return replay(cfg);
}

// Step 5 of the documented flow (file docstring): publish the config's Cache
// instance descriptors to the process-global registry the cache helpers
// read. Call at the RouteConfig activation boundary, after every fallible
// registration step succeeded — never while merely preparing a replacement.
inline void cache_registry_publish_config(const RouteConfig& cfg, const void* owner = nullptr) {
    u32 caps[RouteConfig::kMaxCacheInstances] = {};
    u64 idents[RouteConfig::kMaxCacheInstances] = {};
    const u32 n = cfg.cache_instance_count < RouteConfig::kMaxCacheInstances
                      ? cfg.cache_instance_count
                      : RouteConfig::kMaxCacheInstances;
    for (u32 i = 0; i < n; i++) {
        caps[i] = cfg.cache_instances[i].capacity;
        idents[i] =
            cache_instance_identity(cfg.cache_instances[i].name, cfg.cache_instances[i].name_len);
    }
    cache_registry_publish(caps, idents, n, owner);
}

inline bool populate_route_config(RouteConfig& cfg, const rir::Module& mod) {
    // Bodies / header sets / routes must always start empty — there's
    // no "merge" semantics for those tables, and a non-zero count
    // would break the compile-time body_idx / headers_idx invariants.
    if (!rir::verify_module(mod).ok) return false;
    if (cfg.route_count != 0 || cfg.response_body_count != 0 ||
        cfg.response_header_set_count != 0 || cfg.response_policy_count != 0 ||
        cfg.failure_policy_count != 0 || cfg.policy_bundle_count != 0 ||
        cfg.target_transform_count != 0 || cfg.target_transform_bytes_used != 0 ||
        cfg.redirect_policy_count != 0 || cfg.redirect_policy_bytes_used != 0 ||
        cfg.strict_local_response_policy_count != 0 || cfg.strict_local_response_bytes_used != 0 ||
        cfg.has_strict_local_response_table_inventory()) {
        return false;
    }

    if (!redirect_references_valid(mod)) return false;

    // Upstreams admit one of two shapes (see file docstring):
    //   - Fully empty: helper adds every upstream itself.
    //   - Pre-bound: caller already populated exactly mod.upstream_count
    //     upstream slots in DSL declaration order. Helper verifies
    //     names match and skips the add loop.
    const bool upstreams_pre_bound = cfg.upstream_count == mod.upstream_count;
    const bool upstreams_empty = cfg.upstream_count == 0;
    if (!upstreams_empty && !upstreams_pre_bound) return false;

    // Defensive bounds-checks against malformed modules (e.g. a
    // hand-built rir::Module with inconsistent counts). Refuse before
    // we dereference anything out of range.
    if (mod.upstream_count > rir::Module::kMaxUpstreams) return false;
    if (mod.response_body_count > rir::Module::kMaxResponseBodies) return false;
    if (mod.header_set_count > rir::Module::kMaxHeaderSets) return false;
    if (mod.header_pool_used > rir::Module::kMaxHeaderPoolEntries) return false;
    if (mod.response_policy_count > kMaxResponsePolicies) return false;
    for (u32 i = 0; i < mod.response_policy_count; i++) {
        if (!response_policy_spec_valid(mod.response_policies[i])) return false;
    }
    if (mod.failure_policy_count > kMaxForwardFailurePolicies ||
        mod.policy_bundle_count > RouteConfig::kMaxForwardPolicyBundles ||
        mod.target_transform_count > kMaxForwardTargetTransforms ||
        mod.redirect_policy_count > kMaxRedirectPolicies)
        return false;
    for (u32 i = 0; i < mod.failure_policy_count; i++) {
        if (!forward_failure_policy_table_spec_valid(mod.failure_policies[i])) return false;
    }
    // A failure policy can stand alone. A duration also makes a bundle
    // meaningful without either response policy; an all-zero bundle is invalid.
    for (u32 i = 0; i < mod.policy_bundle_count; i++) {
        const auto& bundle = mod.policy_bundles[i];
        if ((bundle.failure_policy_id != 0 &&
             (bundle.failure_policy_id > mod.failure_policy_count ||
              !forward_failure_policy_spec_valid(
                  mod.failure_policies[bundle.failure_policy_id - 1]))) ||
            (bundle.response_policy_id != 0 &&
             (bundle.response_policy_id > mod.response_policy_count ||
              !response_policy_spec_valid(mod.response_policies[bundle.response_policy_id - 1]))) ||
            (bundle.response_read_timeout_seconds != 0 &&
             !response_read_timeout_seconds_valid(bundle.response_read_timeout_seconds)) ||
            !forward_response_buffering_mode_valid(bundle.response_buffering) ||
            (bundle.response_read_timeout_seconds == 0 && bundle.failure_policy_id == 0))
            return false;
        if (bundle.response_buffering != ForwardResponseBufferingMode::None &&
            (bundle.response_buffering != ForwardResponseBufferingMode::CompleteContentLength ||
             !response_read_timeout_seconds_valid(bundle.response_read_timeout_seconds) ||
             bundle.response_policy_id == 0 || bundle.failure_policy_id == 0 ||
             bundle.timeout_failure_policy_id == 0 ||
             bundle.timeout_failure_policy_id > mod.failure_policy_count ||
             !complete_content_length_buffering_policies_valid(
                 mod.response_policies[bundle.response_policy_id - 1],
                 mod.failure_policies[bundle.failure_policy_id - 1],
                 mod.failure_policies[bundle.timeout_failure_policy_id - 1])))
            return false;
        if (bundle.timeout_failure_policy_id != 0) {
            if (bundle.response_policy_id == 0 || bundle.failure_policy_id == 0 ||
                bundle.timeout_failure_policy_id > mod.failure_policy_count ||
                !forward_timeout_failure_policy_spec_valid(
                    mod.failure_policies[bundle.timeout_failure_policy_id - 1]))
                return false;
            const bool response_suppress =
                mod.response_policies[bundle.response_policy_id - 1].head_mode ==
                ResponsePolicyHeadMode::SuppressBody;
            const bool failure_suppress =
                mod.failure_policies[bundle.failure_policy_id - 1].head_mode ==
                FailurePolicyHeadMode::SuppressBody;
            const bool timeout_suppress =
                mod.failure_policies[bundle.timeout_failure_policy_id - 1].head_mode ==
                FailurePolicyHeadMode::SuppressBody;
            if (response_suppress != failure_suppress || failure_suppress != timeout_suppress)
                return false;
        }
    }
    if (!forward_target_transform_table_valid(mod.target_transforms, mod.target_transform_count))
        return false;
    if (!redirect_policy_table_valid(mod.redirect_policies, mod.redirect_policy_count))
        return false;
    for (u32 i = 0; i < mod.header_set_count; i++) {
        const auto& ref = mod.header_sets[i];
        if (static_cast<u32>(ref.offset) + ref.count > mod.header_pool_used) return false;
        if (ref.count > RouteConfig::kMaxHeadersPerSet) return false;
    }

    // Probe, validate, deduplicate, and own the complete strict local-response table before
    // the first destination mutation. This keeps malformed/capacity/OOM
    // rejection transactional even though the legacy population helper permits
    // unrelated later failures to leave a discardable partial config. The
    // metadata-absent legacy path performs no new allocation or commit.
    bool source_has_strict_local_response_metadata =
        mod.strict_local_response_policy_count != 0 ||
        exact_strict_local_response_inventory_present(
            mod.exact_strict_local_response_bindings,
            mod.exact_strict_local_response_binding_count);
    for (u32 slot = 0; slot < kStrictLocalResponseMethodSlots; slot++) {
        source_has_strict_local_response_metadata |= mod.pre_route_policy_ids[slot] != 0;
        source_has_strict_local_response_metadata |= mod.unmatched_policy_ids[slot] != 0;
    }
    std::unique_ptr<RouteConfig> strict_local_response_probe;
    if (source_has_strict_local_response_metadata) {
        strict_local_response_probe.reset(new (std::nothrow) RouteConfig());
        if (!strict_local_response_probe ||
            !strict_local_response_probe->install_strict_local_response_table_with_pre_route(
                mod.strict_local_response_policies,
                mod.strict_local_response_policy_count,
                mod.pre_route_policy_ids,
                mod.unmatched_policy_ids,
                mod.exact_strict_local_response_bindings,
                mod.exact_strict_local_response_binding_count))
            return false;
    }

    // Upstreams: the compiler emits `forward(name)` as a 0-based index
    // into the declaration order (0 = first `upstream` decl, 1 = second,
    // …). `RouteConfig::upstreams` is also declaration-order (add_upstream
    // appends). So for the indices to stay aligned we need one cfg slot
    // per DSL upstream, in the same order.
    if (upstreams_empty) {
        // Name-only upstreams have no address to bind, so fail-fast.
        // Callers who have them should either declare addresses in the
        // DSL (`upstream X at "..."` / `{ host, port }`) or use the
        // pre-bound mode: add_upstream manually in DSL order, then
        // call the helper just for bodies / headers.
        for (u32 i = 0; i < mod.upstream_count; i++) {
            if (!mod.upstreams[i].has_address) return false;
        }
        for (u32 i = 0; i < mod.upstream_count; i++) {
            const auto& up = mod.upstreams[i];
            // add_upstream's name parameter is a NUL-terminated C
            // string; rir::Module stores Str (ptr + len) where the
            // bytes may not be NUL-terminated. Copy into a buffer
            // matching UpstreamTarget::kMaxUpstreamNameLen. Truncate
            // over-long names to match set_name's silent-truncate —
            // a hard limit belongs as a frontend diagnostic, not here.
            char name_buf[UpstreamTarget::kMaxUpstreamNameLen];
            if (up.name.len > 0 && up.name.ptr == nullptr) return false;
            u32 copy_len = up.name.len;
            if (copy_len >= sizeof(name_buf)) copy_len = sizeof(name_buf) - 1;
            for (u32 j = 0; j < copy_len; j++) name_buf[j] = up.name.ptr[j];
            name_buf[copy_len] = '\0';
            auto r = cfg.add_upstream(name_buf, up.ip, up.port);
            if (!r.has_value()) return false;
            if (r.value() != i) return false;
            // Append any extra load-balancing endpoints (primary was the
            // ip/port above). add_upstream_backend fails only on a full
            // backend list, which the frontend already bounds.
            for (u32 b = 0; b < up.extra_count; b++) {
                if (!cfg.add_upstream_backend(i, up.extra_ips[b], up.extra_ports[b])) return false;
            }
            // Attach active health-check config (data only; the frontend already
            // validated path/interval). Fails only on an over-long path.
            if (up.hc_enabled) {
                if (!cfg.set_upstream_health_check(i,
                                                   up.hc_path.ptr,
                                                   up.hc_path.len,
                                                   up.hc_interval_ms,
                                                   up.hc_expected_status))
                    return false;
            }
        }
    } else {
        // Pre-bound mode: verify the caller added upstreams in DSL
        // declaration order. A mismatch here would send forward(a) to
        // the backend at slot a's index but with a different name —
        // silent misconfiguration we'd rather catch up front.
        //
        // The match MUST be exact, so reject any module name that
        // wouldn't round-trip through the 31-byte cfg.upstreams name
        // buffer. If we truncated both sides before comparing, two
        // DSL names with identical first 31 bytes but different
        // suffixes would compare equal, and a caller who pre-bound
        // them in the wrong order could slip past the verification.
        // The empty-cfg branch above can tolerate truncation (it's
        // the one doing the bind, and forward() resolves by index,
        // not by name) but this branch can't.
        for (u32 i = 0; i < mod.upstream_count; i++) {
            const auto& up = mod.upstreams[i];
            if (up.name.len > 0 && up.name.ptr == nullptr) return false;
            if (up.name.len >= UpstreamTarget::kMaxUpstreamNameLen) return false;
            if (cfg.upstreams[i].name_len != up.name.len) return false;
            for (u32 j = 0; j < up.name.len; j++) {
                if (cfg.upstreams[i].name[j] != up.name.ptr[j]) return false;
            }
        }
        // Attach active health-check config onto the pre-bound upstreams too —
        // the caller bound only addresses, so without this the hc fields stay at
        // their defaults (hc_enabled == false) and no probes ever run. Mirrors the
        // empty-upstreams branch above. Fails only on an over-long path.
        for (u32 i = 0; i < mod.upstream_count; i++) {
            const auto& up = mod.upstreams[i];
            if (up.hc_enabled) {
                if (!cfg.set_upstream_health_check(i,
                                                   up.hc_path.ptr,
                                                   up.hc_path.len,
                                                   up.hc_interval_ms,
                                                   up.hc_expected_status))
                    return false;
            }
        }
    }

    // Response bodies (1-based index preserved). Empty bodies don't
    // appear in the module table (lower_rir skips them), so we can
    // feed the bytes straight through.
    for (u32 i = 0; i < mod.response_body_count; i++) {
        const auto& body = mod.response_bodies[i];
        u16 idx = cfg.add_response_body(body.ptr, body.len);
        if (idx == 0) return false;
        // Belt-and-suspenders: the 1-based index must match i+1 so
        // callers that packed body_idx at compile time still resolve
        // correctly. add_response_body assigns sequentially, so this
        // invariant holds iff we start from an empty cfg.
        if (idx != i + 1) return false;
    }

    // Response header sets (1-based index preserved). Materialise the
    // (key, value) pointer tables add_response_header_set expects.
    for (u32 i = 0; i < mod.header_set_count; i++) {
        const auto& ref = mod.header_sets[i];
        const char* keys[RouteConfig::kMaxHeadersPerSet];
        u32 key_lens[RouteConfig::kMaxHeadersPerSet];
        const char* vals[RouteConfig::kMaxHeadersPerSet];
        u32 val_lens[RouteConfig::kMaxHeadersPerSet];
        if (ref.count > RouteConfig::kMaxHeadersPerSet) return false;
        for (u16 j = 0; j < ref.count; j++) {
            const auto& k = mod.header_keys[ref.offset + j];
            const auto& v = mod.header_values[ref.offset + j];
            keys[j] = k.ptr;
            key_lens[j] = k.len;
            vals[j] = v.ptr;
            val_lens[j] = v.len;
        }
        u16 idx = cfg.add_response_header_set(keys, key_lens, vals, val_lens, ref.count);
        if (idx == 0) return false;
        if (idx != i + 1) return false;
    }

    // Response policies (1-based IDs preserved). RouteConfig copies every
    // string into its own pool before the RIR/compiler arena can be released.
    for (u32 i = 0; i < mod.response_policy_count; i++) {
        u16 idx = cfg.add_response_policy(mod.response_policies[i]);
        if (idx == 0 || idx != i + 1) return false;
    }
    for (u32 i = 0; i < mod.failure_policy_count; i++) {
        u16 idx = cfg.add_failure_policy(mod.failure_policies[i]);
        if (idx == 0 || idx != i + 1) return false;
    }
    for (u32 i = 0; i < mod.policy_bundle_count; i++) {
        const auto& bundle = mod.policy_bundles[i];
        u16 idx = cfg.add_policy_bundle(bundle.response_policy_id,
                                        bundle.failure_policy_id,
                                        bundle.timeout_failure_policy_id,
                                        bundle.response_read_timeout_seconds,
                                        bundle.response_buffering);
        if (idx == 0 || idx != i + 1) return false;
    }
    // Cache instance descriptors — declaration order defines the instance
    // index compiled into CacheGet/CacheSet, so the copy must be exact and
    // the target table empty.
    if (cfg.cache_instance_count != 0) return false;
    if (mod.cache_instance_count > RouteConfig::kMaxCacheInstances) return false;
    for (u32 i = 0; i < mod.cache_instance_count; i++) {
        const auto& ci = mod.cache_instances[i];
        if (ci.name.len > 0 && ci.name.ptr == nullptr) return false;
        if (!cfg.add_cache_instance(ci.name.ptr, ci.name.len, ci.capacity)) return false;
    }

    // Target-transform metadata is copied last.  Every operation above can
    // still fail; keeping this final means a failed population never leaves
    // partially published transform metadata in the destination config.
    for (u32 i = 0; i < mod.target_transform_count; i++) {
        u16 idx = cfg.add_target_transform(mod.target_transforms[i]);
        if (idx == 0 || idx != i + 1) return false;
    }
    if (!cfg.add_redirect_policy_table(mod.redirect_policies, mod.redirect_policy_count))
        return false;
    // Every strict-table failure was exhausted before mutation. Commit the
    // already-owned staged table by bounded copy/rebase without allocation.
    if (strict_local_response_probe &&
        !cfg.copy_strict_local_response_table_from_owned(*strict_local_response_probe))
        return false;
    return true;
}

}  // namespace rut
