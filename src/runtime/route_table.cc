#include "rut/runtime/route_table.h"

#include "core/expected.h"
#include "rut/common/byte_span.h"
#include "rut/common/failure_policy.h"
#include "rut/common/forward_policy_head_mode.h"
#include "rut/common/forward_preflight.h"
#include "rut/common/forward_target_transform.h"
#include "rut/common/http_header_validation.h"
#include "rut/common/range_int.h"
#include "rut/common/rate_limit_key_spec.h"
#include "rut/common/redirect_policy.h"
#include "rut/common/response_policy.h"
#include "rut/common/route_host.h"
#include "rut/common/strict_local_response.h"
#include "rut/common/types.h"
#include "rut/common/upstream_health.h"
#include "rut/jit/handler_abi.h"
#include "rut/runtime/error.h"
#include "rut/runtime/es256_policy.h"
#include "rut/runtime/http_cache.h"
#include "rut/runtime/route_method.h"
#include "rut/runtime/route_params.h"
#include "rut/runtime/route_select.h"
#include "rut/runtime/route_trie.h"
#include "rut/runtime/rs256_policy.h"
#include "rut/runtime/slice_pool.h"
#include "rut/runtime/ws_handshake.h"
#include "rut/runtime/ws_terminate.h"

#include <errno.h>
#include <stdint.h>

namespace rut {

bool RouteConfig::add_timer(
    const char* name, u32 name_len, u32 interval_ms, jit::HandlerFn fn, i32 shard) {
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

bool RouteConfig::add_cache_instance(const char* name, u32 name_len, u32 capacity) {
    if (cache_instance_count >= kMaxCacheInstances || capacity == 0 || capacity > kMaxCacheCapacity)
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

bool RouteConfig::is_routable_path(const char* path) {
    if (path == nullptr || path[0] != '/') return false;
    for (u32 i = 0; i < RouteEntry::kMaxPathLen; i++) {
        const char ch = path[i];
        if (ch == '\0') return true;
        if (ch == '?' || ch == '#') return false;
    }
    return false;
}

bool RouteConfig::add_rs256_configuration(Str value) {
    if (rs256_configuration_count > Rs256Policies::kMaxPolicies ||
        rs256_configuration_bytes_used > sizeof(rs256_configuration_bytes))
        return false;
    for (u32 i = 0; i < rs256_configuration_count; ++i)
        if (rs256_configurations[i].eq(value)) return true;
    if (!value.ptr || value.len == 0 || value.len > Rs256Policy::kMaxText ||
        rs256_configuration_count == Rs256Policies::kMaxPolicies ||
        i64{value.len} >
            i64{sizeof(rs256_configuration_bytes)} - i64{rs256_configuration_bytes_used})
        return false;
    char* out = rs256_configuration_bytes + i64{rs256_configuration_bytes_used};
    __builtin_memcpy(out, value.ptr, value.len);
    rs256_configurations[rs256_configuration_count++] = {out, value.len};
    rs256_configuration_bytes_used = static_cast<u32>(
        static_cast<i64>(rs256_configuration_bytes_used) + static_cast<i64>(value.len));
    return true;
}

bool RouteConfig::add_es256_configuration(Str value) {
    if (es256_configuration_count > Es256Policies::kMaxPolicies ||
        es256_configuration_bytes_used > sizeof(es256_configuration_bytes))
        return false;
    for (u32 i = 0; i < es256_configuration_count; ++i)
        if (es256_configurations[i].eq(value)) return true;
    if (!value.ptr || value.len == 0 || value.len > Es256Policy::kMaxText ||
        es256_configuration_count == Es256Policies::kMaxPolicies ||
        i64{value.len} >
            i64{sizeof(es256_configuration_bytes)} - i64{es256_configuration_bytes_used})
        return false;
    char* out = es256_configuration_bytes + i64{es256_configuration_bytes_used};
    __builtin_memcpy(out, value.ptr, value.len);
    es256_configurations[es256_configuration_count++] = {out, value.len};
    es256_configuration_bytes_used = static_cast<u32>(
        static_cast<i64>(es256_configuration_bytes_used) + static_cast<i64>(value.len));
    return true;
}

u16 RouteConfig::add_validated_strict_local_response_policy(
    const StrictLocalResponsePolicySpec& policy) {
    if (strict_local_response_policy_count > kMaxStrictLocalResponsePolicies ||
        strict_local_response_bytes_used > kStrictLocalResponseBytesPoolBytes)
        return 0;
    for (u32 i = 0; i < strict_local_response_policy_count; i++) {
        if (!strict_local_response_policy_id_is_owned(static_cast<u16>(static_cast<i64>(i) + 1)))
            return 0;
        if (strict_local_response_policy_spec_equal(strict_local_response_policies[i], policy))
            return static_cast<u16>(static_cast<i64>(i) + 1);
    }
    if (strict_local_response_policy_count == kMaxStrictLocalResponsePolicies) return 0;
    u32 total = 0;
    const Str fields[] = {policy.reason, policy.content_type, policy.server, policy.body};
    for (Str field : fields) {
        if (i64{field.len} > i64{kStrictLocalResponseBytesPoolBytes} - i64{total}) return 0;
        total = static_cast<u32>(static_cast<i64>(total) + static_cast<i64>(field.len));
    }
    if (i64{total} >
        i64{kStrictLocalResponseBytesPoolBytes} - i64{strict_local_response_bytes_used})
        return 0;
    auto copy = [&](Str src, Str& dst) {
        char* out = strict_local_response_bytes + i64{strict_local_response_bytes_used};
        if (src.len != 0) __builtin_memcpy(out, src.ptr, src.len);
        strict_local_response_bytes_used = static_cast<u32>(
            static_cast<i64>(strict_local_response_bytes_used) + static_cast<i64>(src.len));
        dst = {out, src.len};
    };
    auto& dst = strict_local_response_policies[strict_local_response_policy_count];
    dst.version = policy.version;
    dst.reserved0 = policy.reserved0;
    dst.status_code = policy.status_code;
    dst.date = policy.date;
    dst.connection = policy.connection;
    dst.head_mode = policy.head_mode;
    dst.header_order = policy.header_order;
    copy(policy.reason, dst.reason);
    copy(policy.content_type, dst.content_type);
    copy(policy.server, dst.server);
    copy(policy.body, dst.body);
    return static_cast<u16>(++strict_local_response_policy_count);
}

u16 RouteConfig::add_strict_local_response_policy(const StrictLocalResponsePolicySpec& policy) {
    if (!strict_local_response_policy_spec_valid(policy)) return 0;
    return add_validated_strict_local_response_policy(policy);
}

u16 RouteConfig::add_strict_local_response_policy_for_internal_propagation(
    const StrictLocalResponsePolicySpec& policy) {
    if (!strict_local_response_policy_spec_valid_for_internal_propagation(policy)) return 0;
    return add_validated_strict_local_response_policy(policy);
}

bool RouteConfig::set_unmatched_policy_id(u8 method_key, u16 policy_id) {
    const u32 slot = route_method_slot_from_key(method_key);
    if (slot == kRouteMethodSlotInvalid || policy_id == 0 ||
        !strict_local_response_policy_id_is_owned(policy_id) || unmatched_policy_ids[slot] != 0)
        return false;
    if ((slot == kRouteMethodAny || slot == kRouteMethodHead) &&
        strict_local_response_policies[i64{policy_id} - 1].head_mode !=
            StrictLocalResponseHeadMode::SuppressBody)
        return false;
    unmatched_policy_ids[slot] = policy_id;
    return true;
}

bool RouteConfig::set_pre_route_policy_id(u8 method_key, u16 policy_id) {
    const u32 slot = route_method_slot_from_key(method_key);
    if (slot == kRouteMethodSlotInvalid || slot == kRouteMethodAny || policy_id == 0 ||
        !strict_local_response_policy_id_is_owned(policy_id) || pre_route_policy_ids[slot] != 0)
        return false;
    if (slot == kRouteMethodHead && strict_local_response_policies[i64{policy_id} - 1].head_mode !=
                                        StrictLocalResponseHeadMode::SuppressBody)
        return false;
    pre_route_policy_ids[slot] = policy_id;
    return true;
}

bool RouteConfig::append_exact_strict_local_response_binding(
    const ExactStrictLocalResponseBinding& source, u16 owned_policy_id) {
    if (exact_strict_local_response_binding_count >= kMaxExactStrictLocalResponseBindings ||
        !exact_strict_local_response_binding_shape_valid(source) || owned_policy_id == 0 ||
        !strict_local_response_policy_id_is_owned(owned_policy_id))
        return false;
    const u32 slot = route_method_slot_from_key(source.method);
    if (slot == kRouteMethodSlotInvalid ||
        ((slot == kRouteMethodAny || slot == kRouteMethodHead) &&
         strict_local_response_policies[i64{owned_policy_id} - 1].head_mode !=
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

bool RouteConfig::copy_validated_strict_local_response_table_from_owned(const RouteConfig& source) {
    if (has_strict_local_response_table_inventory()) return false;

    // Convert every source view to a checked integer offset before the
    // first destination write.  Public/forged views can carry an address
    // numerically inside the source pool without C++ array provenance, so
    // native pointer subtraction would itself be undefined even after the
    // address-range validation above.
    u32 offsets[kMaxStrictLocalResponsePolicies][4]{};
    const u32 used = range_int(source.strict_local_response_bytes_used)
                         .min(range_int(kStrictLocalResponseBytesPoolBytes))
                         .to<u32>();
    auto checked_offset = [&] [[nodiscard]] (Str value, u32 * out) {
        return byte_span_offset_within(
            source.strict_local_response_bytes, used, value.ptr, value.len, out);
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
        dst.reserved0 = src.reserved0;
        dst.status_code = src.status_code;
        dst.date = src.date;
        dst.connection = src.connection;
        dst.head_mode = src.head_mode;
        dst.header_order = src.header_order;
        dst.reason = {strict_local_response_bytes + i64{offsets[i][0]}, src.reason.len};
        dst.content_type = {strict_local_response_bytes + i64{offsets[i][1]}, src.content_type.len};
        dst.server = {strict_local_response_bytes + i64{offsets[i][2]}, src.server.len};
        dst.body = {strict_local_response_bytes + i64{offsets[i][3]}, src.body.len};
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
    exact_strict_local_response_binding_count = source.exact_strict_local_response_binding_count;
    return true;
}

bool RouteConfig::copy_strict_local_response_table_from_owned(const RouteConfig& source) {
    if (!source.strict_local_response_table_is_valid()) return false;
    for (u32 i = 0; i < source.strict_local_response_policy_count; i++)
        if (!strict_local_response_policy_spec_valid(source.strict_local_response_policies[i]))
            return false;
    return copy_validated_strict_local_response_table_from_owned(source);
}

bool RouteConfig::copy_strict_local_response_table_from_owned_for_internal_propagation(
    const RouteConfig& source) {
    if (!source.strict_local_response_table_is_valid()) return false;
    return copy_validated_strict_local_response_table_from_owned(source);
}

bool RouteConfig::copy_unmatched_policy_table_from_owned(const RouteConfig& source) {
    if (source.has_pre_route_metadata() || source.has_exact_strict_local_response_inventory())
        return false;
    return copy_strict_local_response_table_from_owned(source);
}

bool RouteConfig::copy_unmatched_policy_table_from_owned_for_internal_propagation(
    const RouteConfig& source) {
    if (source.has_pre_route_metadata() || source.has_exact_strict_local_response_inventory())
        return false;
    return copy_strict_local_response_table_from_owned_for_internal_propagation(source);
}

bool RouteConfig::populate_dispatch_state(const RouteEntry& r) {
    const Str path_view{r.path, r.path_len};
    const u16 idx = static_cast<u16>(route_count);
    if (r.host_len != 0) {
        if (r.host_len > 253 || r.host[r.host_len] != '\0' ||
            !route_host_pattern_valid({r.host, r.host_len}))
            return false;
        u32 scope = 0;
        for (; scope < host_scope_count; scope++)
            if (route_host_equal({host_scopes[scope].name, host_scopes[scope].length},
                                 {r.host, r.host_len}))
                break;
        if (scope == host_scope_count) {
            if (scope == kMaxHostScopes) return false;
            auto& created = host_scopes[scope];
            if (dispatch_kind_ == DispatchKind::ArtJit ? !created.art.init(1)
                                                       : !created.segments.init(1))
                return false;
            __builtin_memcpy(created.name, r.host, r.host_len);
            created.length = r.host_len;
            host_scope_count++;
        }
        auto& state = host_scopes[scope];
        return dispatch_kind_ == DispatchKind::ArtJit
                   ? state.art[0].insert(path_view, r.method, idx)
                   : state.segments[0].insert(path_view, r.method, idx);
    }
    switch (dispatch_kind_) {
        case DispatchKind::ArtJit:
            return art_state.insert(path_view, r.method, idx);
        case DispatchKind::SegmentTrie:
            return trie.insert(path_view, r.method, idx);
    }
    __builtin_unreachable();
}

bool RouteConfig::add_proxy(const char* path, u8 method, u16 upstream_id) {
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

[[nodiscard]] bool RouteConfig::add_ws_terminate(
    [[maybe_unused]] const char* path,
    [[maybe_unused]] u8 method,
    [[maybe_unused]] u16 upstream_id,
    [[maybe_unused]] WsMessageHandlerFn handler,
    [[maybe_unused]] u32 max_message_size,
    [[maybe_unused]] u16 close_code,
    [[maybe_unused]] WsTextRewrite forward_text,
    [[maybe_unused]] Str close_reason,
    [[maybe_unused]] const WsClosePolicy* close_policies,
    [[maybe_unused]] u32 close_policy_count,
    [[maybe_unused]] const WsTextRewrite* forward_texts,
    [[maybe_unused]] u32 forward_text_count,
    [[maybe_unused]] Str subprotocol) {
#if !RUT_ENABLE_WEBSOCKET
    // The 101/tunnel path is compiled out in this build — a terminate route could
    // never enter terminate mode, so fail loud instead of publishing an unusable route.
    return false;
#else
    if (!ws_terminate_metadata_valid(handler,
                                     max_message_size,
                                     close_code,
                                     forward_text,
                                     close_reason,
                                     close_policies,
                                     close_policy_count,
                                     forward_texts,
                                     forward_text_count,
                                     subprotocol))
        return false;
    if (!add_proxy(path, method, upstream_id)) return false;
    auto& r = routes[i64{route_count} - 1];
    set_ws_terminate_metadata(r,
                              handler,
                              max_message_size,
                              close_code,
                              forward_text,
                              close_reason,
                              close_policies,
                              close_policy_count,
                              forward_texts,
                              forward_text_count,
                              subprotocol);
    return true;
#endif
}

[[nodiscard]] bool RouteConfig::attach_ws_terminate_to_jit(
    [[maybe_unused]] u32 route_index,
    [[maybe_unused]] const char* path,
    [[maybe_unused]] u8 method,
    [[maybe_unused]] u16 upstream_id,
    [[maybe_unused]] WsMessageHandlerFn handler,
    [[maybe_unused]] u32 max_message_size,
    [[maybe_unused]] u16 close_code,
    [[maybe_unused]] WsTextRewrite forward_text,
    [[maybe_unused]] Str close_reason,
    [[maybe_unused]] const WsClosePolicy* close_policies,
    [[maybe_unused]] u32 close_policy_count,
    [[maybe_unused]] const WsTextRewrite* forward_texts,
    [[maybe_unused]] u32 forward_text_count,
    [[maybe_unused]] Str subprotocol) {
#if !RUT_ENABLE_WEBSOCKET
    return false;
#else
    if (route_index >= route_count || path == nullptr || upstream_id >= upstream_count ||
        !ws_terminate_metadata_valid(handler,
                                     max_message_size,
                                     close_code,
                                     forward_text,
                                     close_reason,
                                     close_policies,
                                     close_policy_count,
                                     forward_texts,
                                     forward_text_count,
                                     subprotocol))
        return false;
    RouteEntry& route = routes[route_index];
    const u8 method_key = route_method_key_from_legacy_char(method);
    if (route.action != RouteAction::JitHandler || route.fn == nullptr ||
        route.method != method_key || route.ws_terminate || route.ws_frame_handler != nullptr)
        return false;
    u32 path_len = 0;
    while (path_len < RouteEntry::kMaxPathLen && path[path_len]) path_len++;
    if (path_len >= RouteEntry::kMaxPathLen || path_len != route.path_len || path[path_len] != '\0')
        return false;
    for (u32 i = 0; i < path_len; i++)
        if (route.path[i] != path[i]) return false;
    route.upstream_id = upstream_id;
    set_ws_terminate_metadata(route,
                              handler,
                              max_message_size,
                              close_code,
                              forward_text,
                              close_reason,
                              close_policies,
                              close_policy_count,
                              forward_texts,
                              forward_text_count,
                              subprotocol);
    return true;
#endif
}

bool RouteConfig::set_route_rate_limit(u32 idx, u32 max, u32 window_sec, u32 burst) {
    if (idx >= route_count) return false;
    RateLimitRuleSet replacement{};
    if (max > 0 && window_sec > 0 && replacement.add_rule(max, window_sec, burst) < 0) return false;

    RouteEntry& route = routes[idx];
    const RateLimitRuleSet previous_rules = route.rate_limit;
    u64 previous_ids[kMaxRateLimitRules];
    for (u32 i = 0; i < kMaxRateLimitRules; i++) previous_ids[i] = route.rate_limit_ids[i];
    route.rate_limit = replacement;
    if (refresh_route_rate_limit_ids(idx)) return true;

    route.rate_limit = previous_rules;
    for (u32 i = 0; i < kMaxRateLimitRules; i++) route.rate_limit_ids[i] = previous_ids[i];
    return false;
}

bool RouteConfig::add_route_rate_limit_rule(
    u32 idx, u32 max, u32 window_sec, RateLimitScope scope, u32 burst) {
    if (idx >= route_count) return false;
    RouteEntry& route = routes[idx];
    const RateLimitRuleSet previous_rules = route.rate_limit;
    u64 previous_ids[kMaxRateLimitRules];
    for (u32 i = 0; i < kMaxRateLimitRules; i++) previous_ids[i] = route.rate_limit_ids[i];
    if (route.rate_limit.add_rule(max, window_sec, burst, scope) < 0) return false;
    if (refresh_route_rate_limit_ids(idx)) return true;
    route.rate_limit = previous_rules;
    for (u32 i = 0; i < kMaxRateLimitRules; i++) route.rate_limit_ids[i] = previous_ids[i];
    return false;
}

bool RouteConfig::add_route_rate_limit_key(u32 idx,
                                           RateLimitKeyKind kind,
                                           const char* name,
                                           u32 name_len) {
    if (idx >= route_count) return false;
    RateLimitRuleSet& rs = routes[idx].rate_limit;
    if (rs.count == 0 || rs.count > kMaxRateLimitRules) return false;
    const RateLimitRuleSet previous_rules = rs;
    u64 previous_ids[kMaxRateLimitRules];
    for (u32 i = 0; i < kMaxRateLimitRules; i++) previous_ids[i] = routes[idx].rate_limit_ids[i];
    if (!rs.rules[static_cast<i64>(rs.count) - 1].key.add(kind, name, name_len)) return false;
    if (refresh_route_rate_limit_ids(idx)) return true;
    rs = previous_rules;
    for (u32 i = 0; i < kMaxRateLimitRules; i++) routes[idx].rate_limit_ids[i] = previous_ids[i];
    return false;
}

bool RouteConfig::refresh_route_rate_limit_ids(u32 idx) {
    if (idx >= route_count) return false;
    RouteEntry& route = routes[idx];
    if (!rate_limit_route_shape_valid(route)) return false;
    for (u32 i = 0; i < kMaxRateLimitRules; i++) route.rate_limit_ids[i] = 0;
    const u64 route_id = rate_limit_route_id(route);
    for (u32 i = 0; i < route.rate_limit.count; i++) {
        u32 duplicate_rank = 0;
        for (u32 previous = 0; previous < i; previous++)
            if (rate_limit_rule_identity_equal(route.rate_limit.rules[previous],
                                               route.rate_limit.rules[i]))
                duplicate_rank++;
        route.rate_limit_ids[i] =
            rate_limit_rule_id(route_id, route.rate_limit.rules[i], duplicate_rank);
    }
    return true;
}

bool RouteConfig::refresh_all_rate_limit_ids() {
    for (u32 i = 0; i < route_count; i++)
        if (!refresh_route_rate_limit_ids(i)) return false;
    return true;
}

bool RouteConfig::set_route_http_cache(u32 idx, u32 ttl) {
    if (idx >= route_count || ttl > HttpCache::kMaxTtl ||
        (ttl != 0 && routes[idx].method != kRouteMethodGet))
        return false;
    if (routes[idx].http_cache_ttl) --http_cache_route_count;
    routes[idx].http_cache_ttl = ttl;
    if (ttl) ++http_cache_route_count;
    return true;
}

bool RouteConfig::set_route_throttle(u32 idx, u32 down_bps) {
    if (idx >= route_count) return false;
    routes[idx].throttle_down_bps = down_bps;
    return true;
}

bool RouteConfig::set_upstream_max_inflight(u32 uid, u32 max_inflight) {
    if (uid >= upstream_count) return false;
    upstreams[uid].max_inflight = max_inflight;
    return true;
}

bool RouteConfig::set_upstream_health_check(u32 uid,
                                            const char* path,
                                            u32 path_len,
                                            u32 interval_ms,
                                            u16 status,
                                            ActiveHealthThresholds thresholds,
                                            ActiveHealthType type,
                                            u32 timeout_ms,
                                            Str host,
                                            ActiveHealthStatuses statuses,
                                            bool require_initial_success,
                                            u32 unhealthy_interval_ms,
                                            u8 concurrency) {
    if (uid >= upstream_count) return false;
    UpstreamTarget& up = upstreams[uid];
    if (concurrency > UpstreamTarget::kMaxBackends ||
        (host.len && (!active_health_host_valid(host) || type == ActiveHealthType::Tcp)) ||
        path_len >= sizeof(up.hc_path) ||
        !valid_active_health_check(
            type, path, path_len, interval_ms, status, thresholds, timeout_ms, statuses) ||
        (up.http2 && type != ActiveHealthType::Tcp))
        return false;
    for (u32 i = 0; i < host.len; ++i) up.hc_host[i] = host.ptr[i];
    up.hc_host[host.len] = '\0';
    up.hc_host_len = host.len;
    for (u32 i = 0; i < path_len; i++) up.hc_path[i] = path[i];
    up.hc_path[path_len] = '\0';
    up.hc_path_len = path_len;
    up.hc_interval_ms = interval_ms;
    up.hc_unhealthy_interval_ms = unhealthy_interval_ms;
    up.hc_concurrency = concurrency;
    up.hc_expected_status = status;
    up.hc_healthy_statuses = statuses;
    up.hc_thresholds = thresholds;
    up.hc_type = type;
    up.hc_timeout_ms = timeout_ms;
    up.hc_require_initial_success = require_initial_success;
    up.hc_enabled = true;
    return true;
}

bool RouteConfig::add_static(const char* path, u8 method, u16 status) {
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

bool RouteConfig::ws_terminate_metadata_valid(WsMessageHandlerFn handler,
                                              u32 max_message_size,
                                              u16 close_code,
                                              WsTextRewrite forward_text,
                                              Str close_reason,
                                              const WsClosePolicy* close_policies,
                                              u32 close_policy_count,
                                              const WsTextRewrite* forward_texts,
                                              u32 forward_text_count,
                                              Str subprotocol) {
    if (subprotocol.len > SlicePool::kSliceSize ||
        (subprotocol.len != 0 && !ws_valid_subprotocol(subprotocol)))
        return false;
    if (handler == nullptr || !ws_valid_message_capacity(max_message_size) ||
        !ws_valid_text_rewrite(forward_text, max_message_size) ||
        !ws_valid_close_code(close_code) || !ws_valid_close_reason(close_reason) ||
        close_policy_count > kWsMaxClosePolicies ||
        (close_policy_count != 0 && close_policies == nullptr) ||
        forward_text_count > kWsMaxForwardTexts ||
        (forward_text_count != 0 && forward_texts == nullptr))
        return false;
    for (u32 i = 0; i < close_policy_count; i++)
        if (!ws_valid_close_code(close_policies[i].code) ||
            !ws_valid_close_reason(close_policies[i].reason))
            return false;
    for (u32 i = 0; i < forward_text_count; i++)
        if (!ws_valid_text_rewrite(forward_texts[i], max_message_size)) return false;
    return true;
}

void RouteConfig::set_ws_terminate_metadata(RouteEntry& route,
                                            WsMessageHandlerFn handler,
                                            u32 max_message_size,
                                            u16 close_code,
                                            WsTextRewrite forward_text,
                                            Str close_reason,
                                            const WsClosePolicy* close_policies,
                                            u32 close_policy_count,
                                            const WsTextRewrite* forward_texts,
                                            u32 forward_text_count,
                                            Str subprotocol) {
    route.ws_terminate = true;
    route.ws_frame_handler = handler;
    route.ws_max_message_size = max_message_size;
    route.ws_subprotocol = subprotocol;
    route.ws_close_code = close_code;
    route.ws_close_reason = close_reason;
    route.ws_close_policy_count = close_policy_count;
    for (u32 i = 0; i < close_policy_count; i++) route.ws_close_policies[i] = close_policies[i];
    route.ws_forward_text = forward_text;
    route.ws_forward_text_count = forward_text_count;
    for (u32 i = 0; i < forward_text_count; i++) route.ws_forward_texts[i] = forward_texts[i];
}

bool RouteConfig::add_verified_jit_handler(const char* path,
                                           u8 method,
                                           jit::HandlerFn fn,
                                           bool needs_req_body,
                                           ForwardPreflightMode forward_preflight_mode,
                                           u16 preflight_forward_policy_bundle_id,
                                           Str host) {
    if (route_count >= kMaxRoutes) return false;
    if (fn == nullptr) return false;
    if (!forward_preflight_mode_valid(forward_preflight_mode) ||
        !forward_preflight_metadata_is_verified_runtime_safe(forward_preflight_mode,
                                                             preflight_forward_policy_bundle_id))
        return false;
    if (forward_preflight_mode_can_own_runtime_deadline(forward_preflight_mode) &&
        (!policy_bundle_id_is_valid(preflight_forward_policy_bundle_id) ||
         !response_read_timeout_seconds_valid(
             policy_bundles[i64{preflight_forward_policy_bundle_id} - 1]
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
         !forward_response_buffering_uses_content_length_machinery(
             policy_bundles[i64{preflight_forward_policy_bundle_id} - 1].response_buffering)))
        return false;
    if (forward_preflight_mode == ForwardPreflightMode::AfterRequestFramingSelection &&
        (needs_req_body ||
         ((method_key != kRouteMethodHead && method_key != kRouteMethodGet) ||
          (method_key == kRouteMethodHead &&
           policy_bundles[i64{preflight_forward_policy_bundle_id} - 1].response_buffering !=
               ForwardResponseBufferingMode::None) ||
          (method_key == kRouteMethodGet &&
           !forward_response_buffering_uses_content_length_machinery(
               policy_bundles[i64{preflight_forward_policy_bundle_id} - 1].response_buffering)))))
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
    if (host.len != 0 && !route_host_pattern_valid(host)) return false;
    r.host_len = static_cast<u16>(host.len);
    if (host.len != 0 && host.ptr[0] == '[') {
        if (!route_host_from_authority(host, r.host, &r.host_len)) return false;
    } else {
        for (u32 i = 0; i < host.len; i++) r.host[i] = route_host_lower(host.ptr[i]);
        r.host[host.len] = '\0';
    }
    r.needs_req_body = needs_req_body;
    r.needs_password_gateway = 0;
    r.forward_preflight_mode = forward_preflight_mode;
    r.preflight_forward_policy_bundle_id = preflight_forward_policy_bundle_id;
    if (!populate_dispatch_state(r)) {
        return false;
    }
    route_count++;
    return true;
}

bool RouteConfig::add_jit_handler(const char* path,
                                  u8 method,
                                  jit::HandlerFn fn,
                                  bool needs_req_body,
                                  ForwardPreflightMode forward_preflight_mode,
                                  u16 preflight_forward_policy_bundle_id,
                                  Str host) {
    if (!forward_preflight_metadata_is_eager_runtime_safe(forward_preflight_mode,
                                                          preflight_forward_policy_bundle_id))
        return false;
    return add_verified_jit_handler(path,
                                    method,
                                    fn,
                                    needs_req_body,
                                    forward_preflight_mode,
                                    preflight_forward_policy_bundle_id,
                                    host);
}

bool RouteConfig::add_jit_handler(const char* path,
                                  u8 method,
                                  jit::HandlerFn fn,
                                  bool needs_req_body,
                                  u16 preflight_forward_policy_bundle_id) {
    const ForwardPreflightMode mode = preflight_forward_policy_bundle_id == 0
                                          ? ForwardPreflightMode::None
                                          : ForwardPreflightMode::EagerDirect;
    return add_jit_handler(
        path, method, fn, needs_req_body, mode, preflight_forward_policy_bundle_id);
}

u16 RouteConfig::add_response_body(const char* data, u32 len) {
    if (response_body_count >= kMaxResponseBodies) return 0;
    if (len > 0 && data == nullptr) return 0;
    // Subtraction-based capacity check: `body_pool_used + len`
    // would wrap on a large u32 `len` and silently pass, leading
    // to an out-of-bounds write into body_pool.
    if (i64{len} > i64{kResponseBodyPoolBytes} - i64{body_pool_used}) return 0;
    char* dst = body_pool + i64{body_pool_used};
    for (u32 i = 0; i < len; i++) dst[i] = data[i];
    body_pool_used = static_cast<u32>(static_cast<i64>(body_pool_used) + static_cast<i64>(len));
    const u32 idx = response_body_count++;
    response_bodies[idx] = {dst, len};
    return static_cast<u16>(static_cast<i64>(idx) + 1);  // 1-based; 0 reserved
}

u16 RouteConfig::add_response_body_view(const char* data, u32 len) {
    if (response_body_count >= kMaxResponseBodies || len > (1u << 20) ||
        (len != 0 && data == nullptr))
        return 0;
    const u32 idx = response_body_count++;
    response_bodies[idx] = {data, len};
    return static_cast<u16>(static_cast<i64>(idx) + 1);
}

u16 RouteConfig::add_response_header_set(const char* const* keys,
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
    if (i64{count} > i64{kMaxHeaderPoolEntries} - i64{header_pool_used}) return 0;
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
        if (static_cast<i64>(key_lens[i]) >
            static_cast<i64>(UINT32_MAX) - static_cast<i64>(total_bytes))
            return 0;
        total_bytes =
            static_cast<u32>(static_cast<i64>(total_bytes) + static_cast<i64>(key_lens[i]));
        if (static_cast<i64>(value_lens[i]) >
            static_cast<i64>(UINT32_MAX) - static_cast<i64>(total_bytes))
            return 0;
        total_bytes =
            static_cast<u32>(static_cast<i64>(total_bytes) + static_cast<i64>(value_lens[i]));
    }
    if (i64{total_bytes} > i64{kResponseHeaderBytesPoolBytes} - i64{header_bytes_pool_used})
        return 0;
    const u16 offset = static_cast<u16>(header_pool_used);
    for (u32 i = 0; i < count; i++) {
        char* key_dst = header_bytes_pool + i64{header_bytes_pool_used};
        for (u32 j = 0; j < key_lens[i]; j++) key_dst[j] = keys[i][j];
        header_bytes_pool_used = static_cast<u32>(static_cast<i64>(header_bytes_pool_used) +
                                                  static_cast<i64>(key_lens[i]));
        char* val_dst = header_bytes_pool + static_cast<i64>(header_bytes_pool_used);
        for (u32 j = 0; j < value_lens[i]; j++) val_dst[j] = values[i][j];
        header_bytes_pool_used = static_cast<u32>(static_cast<i64>(header_bytes_pool_used) +
                                                  static_cast<i64>(value_lens[i]));
        header_keys[static_cast<i64>(offset) + static_cast<i64>(i)] = {key_dst, key_lens[i]};
        header_values[static_cast<i64>(offset) + static_cast<i64>(i)] = {val_dst, value_lens[i]};
    }
    header_pool_used =
        static_cast<u32>(static_cast<i64>(header_pool_used) + static_cast<i64>(count));
    const u32 idx = response_header_set_count++;
    response_header_sets[idx] = {offset, static_cast<u16>(count)};
    return static_cast<u16>(static_cast<i64>(idx) + 1);  // 1-based; 0 reserved
}

u16 RouteConfig::add_response_policy(const ForwardResponsePolicySpec& policy) {
    if (!response_policy_spec_valid(policy)) return 0;
    for (u32 i = 0; i < response_policy_count; i++) {
        if (response_policy_spec_equal(response_policies[i], policy))
            return static_cast<u16>(static_cast<i64>(i) + 1);
    }
    if (response_policy_count >= kMaxResponsePolicies) return 0;
    u32 total = policy.server.len;
    if (i64{total} > i64{kResponsePolicyBytesPoolBytes} - i64{response_policy_bytes_used}) return 0;
    for (u32 i = 0; i < policy.hide_header_count; i++) {
        if (i64{policy.hide_headers[i].len} >
            static_cast<i64>(UINT32_MAX) - static_cast<i64>(total))
            return 0;
        total = static_cast<u32>(static_cast<i64>(total) +
                                 static_cast<i64>(policy.hide_headers[i].len));
    }
    if (i64{total} > i64{kResponsePolicyBytesPoolBytes} - i64{response_policy_bytes_used}) return 0;

    auto copy = [&](Str src, Str& dst) {
        char* out = response_policy_bytes + i64{response_policy_bytes_used};
        for (u32 i = 0; i < src.len; i++) out[i] = src.ptr[i];
        response_policy_bytes_used = static_cast<u32>(static_cast<i64>(response_policy_bytes_used) +
                                                      static_cast<i64>(src.len));
        dst = {out, src.len};
    };
    auto& dst = response_policies[response_policy_count];
    dst.version = policy.version;
    dst.framing = policy.framing;
    dst.connection = policy.connection;
    dst.date = policy.date;
    dst.head_mode = policy.head_mode;
    dst.header_order = policy.header_order;
    dst.header_names = policy.header_names;
    dst.connection_header = policy.connection_header;
    dst.status_reason = policy.status_reason;
    copy(policy.server, dst.server);
    dst.hide_header_count = policy.hide_header_count;
    for (u32 i = 0; i < policy.hide_header_count; i++)
        copy(policy.hide_headers[i], dst.hide_headers[i]);
    response_policy_count++;
    return static_cast<u16>(response_policy_count);
}

u16 RouteConfig::add_failure_policy(const ForwardFailurePolicySpec& policy) {
    if (!forward_failure_policy_table_spec_valid(policy)) return 0;
    if (failure_policy_count > kMaxForwardFailurePolicies ||
        failure_policy_bytes_used > kFailurePolicyBytesPoolBytes)
        return 0;
    for (u32 i = 0; i < failure_policy_count; i++)
        if (forward_failure_policy_spec_equal(failure_policies[i], policy))
            return static_cast<u16>(static_cast<i64>(i) + 1);
    if (failure_policy_count >= kMaxForwardFailurePolicies) return 0;
    u32 total = policy.reason.len;
    if (static_cast<i64>(total) > static_cast<i64>(kFailurePolicyBytesPoolBytes) -
                                      static_cast<i64>(failure_policy_bytes_used))
        return 0;
    if (static_cast<i64>(policy.content_type.len) >
        static_cast<i64>(UINT32_MAX) - static_cast<i64>(total))
        return 0;
    total = static_cast<u32>(static_cast<i64>(total) + static_cast<i64>(policy.content_type.len));
    if (static_cast<i64>(policy.server.len) >
        static_cast<i64>(UINT32_MAX) - static_cast<i64>(total))
        return 0;
    total = static_cast<u32>(static_cast<i64>(total) + static_cast<i64>(policy.server.len));
    if (static_cast<i64>(policy.body.len) > static_cast<i64>(UINT32_MAX) - static_cast<i64>(total))
        return 0;
    total = static_cast<u32>(static_cast<i64>(total) + static_cast<i64>(policy.body.len));
    if (i64{total} > i64{kFailurePolicyBytesPoolBytes} - i64{failure_policy_bytes_used}) return 0;
    auto copy = [&](Str src, Str& dst) {
        char* out = failure_policy_bytes + i64{failure_policy_bytes_used};
        for (u32 i = 0; i < src.len; i++) out[i] = src.ptr[i];
        failure_policy_bytes_used = static_cast<u32>(static_cast<i64>(failure_policy_bytes_used) +
                                                     static_cast<i64>(src.len));
        dst = {out, src.len};
    };
    auto& dst = failure_policies[failure_policy_count];
    dst.version = policy.version;
    dst.status_code = policy.status_code;
    dst.date = policy.date;
    dst.connection = policy.connection;
    dst.head_mode = policy.head_mode;
    dst.header_order = policy.header_order;
    copy(policy.reason, dst.reason);
    copy(policy.content_type, dst.content_type);
    copy(policy.server, dst.server);
    copy(policy.body, dst.body);
    failure_policy_count++;
    return static_cast<u16>(failure_policy_count);
}

u16 RouteConfig::add_policy_bundle(u16 response_policy_id,
                                   u16 failure_policy_id,
                                   u16 timeout_failure_policy_id,
                                   u8 response_read_timeout_seconds,
                                   ForwardResponseBufferingMode response_buffering) {
    if ((response_policy_id != 0 && !response_policy_id_is_valid(response_policy_id)) ||
        (failure_policy_id != 0 && !failure_policy_id_is_valid(failure_policy_id)) ||
        (response_read_timeout_seconds != 0 &&
         !response_read_timeout_seconds_valid(response_read_timeout_seconds)) ||
        !forward_response_buffering_mode_valid(response_buffering) ||
        (response_read_timeout_seconds == 0 && failure_policy_id == 0) ||
        // `header_order: .upstream` is ordinary-forward-only (see
        // analyze.cc and compile_to_config.h): it never carries response
        // read timing, response buffering, or a timeout failure policy.
        // Repeat that invariant here so a native caller building a
        // RouteConfig directly (bypassing RIR compilation) cannot publish
        // a bundle the deadline/buffering helpers assume never exists.
        (response_policy_id != 0 &&
         response_policies[i64{response_policy_id} - 1].header_order ==
             ResponsePolicyHeaderOrder::Upstream &&
         (response_read_timeout_seconds != 0 ||
          response_buffering != ForwardResponseBufferingMode::None ||
          timeout_failure_policy_id != 0)) ||
        // Envoy H1 status 503 / header_order: .lengthTypeDateServer is
        // ordinary connect-failure-only (see analyze.cc and
        // compile_to_config.h): the runtime's response-read-deadline
        // preflight hard-requires the default failure policy's status to
        // be 502 and closes the downstream connection on mismatch, so
        // repeat that invariant here too.
        (failure_policy_id != 0 &&
         failure_policies[i64{failure_policy_id} - 1].header_order ==
             FailurePolicyHeaderOrder::LengthTypeDateServer &&
         response_read_timeout_seconds != 0))
        return 0;
    if (timeout_failure_policy_id != 0) {
        if (response_policy_id == 0 || failure_policy_id == 0 ||
            !timeout_failure_policy_id_is_valid(timeout_failure_policy_id))
            return 0;
        const bool response_suppress = response_policies[i64{response_policy_id} - 1].head_mode ==
                                       ResponsePolicyHeadMode::SuppressBody;
        const bool failure_suppress = failure_policies[i64{failure_policy_id} - 1].head_mode ==
                                      FailurePolicyHeadMode::SuppressBody;
        const bool timeout_suppress =
            failure_policies[i64{timeout_failure_policy_id} - 1].head_mode ==
            FailurePolicyHeadMode::SuppressBody;
        if (response_suppress != failure_suppress || failure_suppress != timeout_suppress) return 0;
    }
    if (response_buffering != ForwardResponseBufferingMode::None &&
        (!forward_response_buffering_uses_content_length_machinery(response_buffering) ||
         !response_read_timeout_seconds_valid(response_read_timeout_seconds) ||
         response_policy_id == 0 || failure_policy_id == 0 || timeout_failure_policy_id == 0 ||
         !complete_content_length_buffering_policies_valid(
             response_policies[i64{response_policy_id} - 1],
             failure_policies[i64{failure_policy_id} - 1],
             failure_policies[i64{timeout_failure_policy_id} - 1])))
        return 0;
    if (policy_bundle_count > kMaxForwardPolicyBundles) return 0;
    for (u32 i = 0; i < policy_bundle_count; i++) {
        if (policy_bundles[i].response_policy_id == response_policy_id &&
            policy_bundles[i].failure_policy_id == failure_policy_id &&
            policy_bundles[i].timeout_failure_policy_id == timeout_failure_policy_id &&
            policy_bundles[i].response_read_timeout_seconds == response_read_timeout_seconds &&
            policy_bundles[i].response_buffering == response_buffering)
            return static_cast<u16>(static_cast<i64>(i) + 1);
    }
    if (policy_bundle_count >= kMaxForwardPolicyBundles) return 0;
    policy_bundles[policy_bundle_count] = {response_policy_id,
                                           failure_policy_id,
                                           timeout_failure_policy_id,
                                           response_read_timeout_seconds,
                                           response_buffering};
    return static_cast<u16>(++policy_bundle_count);
}

bool RouteConfig::forward_policy_tables_valid() const {
    if (response_policy_count > kMaxResponsePolicies ||
        failure_policy_count > kMaxForwardFailurePolicies ||
        policy_bundle_count > kMaxForwardPolicyBundles ||
        response_policy_bytes_used > kResponsePolicyBytesPoolBytes ||
        failure_policy_bytes_used > kFailurePolicyBytesPoolBytes)
        return false;
    auto response_owned = [&](Str v) {
        return pool_bytes_owned(response_policy_bytes, response_policy_bytes_used, v);
    };
    auto failure_owned = [&](Str v) {
        return pool_bytes_owned(failure_policy_bytes, failure_policy_bytes_used, v);
    };
    // Ownership first: a hand-built config may carry dangling or unmapped
    // views, and the byte-level validators below dereference them.
    for (u32 i = 0; i < response_policy_count; i++) {
        const auto& p = response_policies[i];
        if (p.hide_header_count > kMaxResponsePolicyHideHeaders || !response_owned(p.server))
            return false;
        for (u32 h = 0; h < p.hide_header_count; h++)
            if (!response_owned(p.hide_headers[h])) return false;
        if (!response_policy_spec_valid(p)) return false;
    }
    for (u32 i = 0; i < failure_policy_count; i++) {
        const auto& p = failure_policies[i];
        if (!failure_owned(p.reason) || !failure_owned(p.content_type) ||
            !failure_owned(p.server) || !failure_owned(p.body) ||
            !forward_failure_policy_table_spec_valid(p))
            return false;
    }
    // Every referenced spec is now fully valid, so the admitted checks in
    // policy_bundle_id_is_valid() decide exactly what the full ones would.
    for (u32 i = 0; i < policy_bundle_count; i++)
        if (!policy_bundle_id_is_valid(static_cast<u16>(static_cast<i64>(i) + 1))) return false;
    return true;
}

u16 RouteConfig::add_target_transform(const ForwardTargetTransformSpec& spec) {
    if (!forward_target_transform_spec_valid(spec)) return 0;
    if (target_transform_count > kMaxForwardTargetTransforms ||
        target_transform_bytes_used > kForwardTargetTransformBytes)
        return 0;
    for (u32 i = 0; i < target_transform_count; i++) {
        if (forward_target_transform_spec_equal(target_transforms[i], spec))
            return static_cast<u16>(static_cast<i64>(i) + 1);
    }
    if (target_transform_count >= kMaxForwardTargetTransforms) return 0;
    if (i64{spec.strip_prefix.len} >
        i64{kForwardTargetTransformBytes} - i64{target_transform_bytes_used})
        return 0;
    const u32 after_strip = static_cast<u32>(static_cast<i64>(target_transform_bytes_used) +
                                             static_cast<i64>(spec.strip_prefix.len));
    if (static_cast<i64>(spec.replace_prefix.len) >
        static_cast<i64>(kForwardTargetTransformBytes) - static_cast<i64>(after_strip))
        return 0;
    auto copy = [&](Str src, Str& dst) {
        char* out = target_transform_bytes + i64{target_transform_bytes_used};
        for (u32 i = 0; i < src.len; i++) out[i] = src.ptr[i];
        target_transform_bytes_used = static_cast<u32>(
            static_cast<i64>(target_transform_bytes_used) + static_cast<i64>(src.len));
        dst = {out, src.len};
    };
    auto& dst = target_transforms[target_transform_count];
    copy(spec.strip_prefix, dst.strip_prefix);
    copy(spec.replace_prefix, dst.replace_prefix);
    dst.mode = spec.mode;
    target_transform_count++;
    return static_cast<u16>(target_transform_count);
}

u16 RouteConfig::add_redirect_policy(const RedirectPolicySpec& policy) {
    if (redirect_policy_count > kMaxRedirectPolicies ||
        redirect_policy_bytes_used > kRedirectPolicyBytesPoolBytes)
        return 0;
    if (!redirect_policy_spec_valid(policy)) return 0;
    for (u32 i = 0; i < redirect_policy_count; i++) {
        if (!redirect_policy_strings_are_owned(redirect_policies[i])) return 0;
        if (redirect_policy_spec_equal(redirect_policies[i], policy))
            return static_cast<u16>(static_cast<i64>(i) + 1);
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
        if (i64{field.len} >
            i64{kRedirectPolicyBytesPoolBytes} - i64{redirect_policy_bytes_used} - i64{total})
            return 0;
        total = static_cast<u32>(static_cast<i64>(total) + static_cast<i64>(field.len));
    }
    auto copy = [&](Str src, Str& dst) {
        char* out = redirect_policy_bytes + i64{redirect_policy_bytes_used};
        for (u32 i = 0; i < src.len; i++) out[i] = src.ptr[i];
        redirect_policy_bytes_used = static_cast<u32>(static_cast<i64>(redirect_policy_bytes_used) +
                                                      static_cast<i64>(src.len));
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

bool RouteConfig::add_redirect_policy_table(const RedirectPolicySpec* specs, u32 count) {
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
            if (i64{field.len} > i64{kRedirectPolicyBytesPoolBytes} - i64{total}) return false;
            total = static_cast<u32>(static_cast<i64>(total) + static_cast<i64>(field.len));
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
            char* out = redirect_policy_bytes + i64{used};
            for (u32 j = 0; j < fields[field].len; j++) out[j] = fields[field].ptr[j];
            *destinations[field] = {out, fields[field].len};
            used = static_cast<u32>(static_cast<i64>(used) + static_cast<i64>(fields[field].len));
        }
    }
    redirect_policy_bytes_used = used;
    redirect_policy_count = count;
    return true;
}

core::Expected<u32, Error> RouteConfig::add_upstream(const char* name, u32 ip, u16 port) {
    if (upstream_count >= kMaxUpstreams)
        return core::make_unexpected(Error::make(ENOSPC, Error::Source::RouteTable));
    u32 idx = upstream_count++;
    upstreams[idx].set_name(name);
    upstreams[idx].set_addr(ip, port);
    return idx;
}

bool RouteConfig::dispatch_accepts_path_shape(const char* path) const {
    u32 plen = 0;
    while (path[plen]) plen++;
    if (!path_has_param_segment(Str{path, plen})) return true;
    return dispatch_kind_ == DispatchKind::SegmentTrie;
}

bool RouteConfig::param_count_fits(const char* path) const {
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

}  // namespace rut
