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
#include "rut/jit/codegen.h"
#include "rut/jit/jit_engine.h"
#include "rut/runtime/cache_table.h"
#include "rut/runtime/route_table.h"

namespace rut {

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

inline bool rir_function_can_forward_buffered(const rir::Function& fn) {
    for (u32 yi = 0; yi < fn.yield_count; yi++)
        if (fn.yield_kinds != nullptr &&
            fn.yield_kinds[yi] == static_cast<u8>(jit::YieldKind::Forward))
            return true;
    if (fn.blocks == nullptr) return false;
    for (u32 bi = 0; bi < fn.block_count; bi++) {
        const auto& block = fn.blocks[bi];
        if (block.insts == nullptr) continue;
        for (u32 ii = 0; ii < block.inst_count; ii++)
            if (block.insts[ii].op == rir::Opcode::RetForwardBuffered) return true;
    }
    return false;
}

inline bool rir_function_needs_control_plane_snapshot(const rir::Function& fn) {
    if (fn.blocks == nullptr) return false;
    for (u32 bi = 0; bi < fn.block_count; bi++) {
        const auto& block = fn.blocks[bi];
        if (block.insts == nullptr) continue;
        for (u32 ii = 0; ii < block.inst_count; ii++)
            if (block.insts[ii].op == rir::Opcode::JsonAppendControlPlane) return true;
    }
    return false;
}

inline u64 marking_policy_identity(const rir::Module& mod, const rir::Function& fn);

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
    if (cfg.route_count != 0 || cfg.timer_count != 0) return false;
    if (!configure_route_dispatch(cfg, mod)) return false;

    for (u32 i = 0; i < mod.func_count; i++) {
        const auto& fn = mod.functions[i];
        if (fn.route_pattern.len >= RouteEntry::kMaxPathLen) return false;
        if (fn.route_pattern.len > 0 && fn.route_pattern.ptr == nullptr) return false;
        if (fn.name.len > 0 && fn.name.ptr == nullptr) return false;

        char symbol[256];
        jit::format_handler_symbol(fn.name, symbol, sizeof(symbol));
        auto* addr = engine.lookup(symbol);
        if (!addr) return false;
        auto handler = reinterpret_cast<jit::HandlerFn>(addr);

        // A timer compiles like a route but is fired on schedule, not matched
        // against requests: register it into the timer table (route_pattern holds
        // the timer name) and skip route registration.
        if (fn.is_timer) {
            if (!cfg.add_timer(fn.route_pattern.ptr,
                               fn.route_pattern.len,
                               fn.timer_interval_ms,
                               handler,
                               fn.timer_shard,
                               rir_function_needs_control_plane_snapshot(fn),
                               marking_policy_identity(mod, fn)))
                return false;
            continue;
        }

        char path[RouteEntry::kMaxPathLen];
        for (u32 j = 0; j < fn.route_pattern.len; j++) path[j] = fn.route_pattern.ptr[j];
        path[fn.route_pattern.len] = '\0';

        if (!cfg.add_jit_handler(path,
                                 fn.http_method,
                                 handler,
                                 rir_function_needs_req_body(fn),
                                 rir_function_can_forward_buffered(fn),
                                 rir_function_needs_control_plane_snapshot(fn)))
            return false;
        // @rateLimit decorators → stacked token-bucket rules, each with its own
        // metering key (the route just added is at index route_count - 1).
        if (fn.rate_limit.count > 0) {
            const u32 kRouteIdx = cfg.route_count - 1;
            for (u32 ri = 0; ri < fn.rate_limit.count; ri++) {
                const RateLimitRule& rule = fn.rate_limit.rules[ri];
                cfg.add_route_rate_limit_rule(
                    kRouteIdx, rule.max, rule.window_sec, rule.scope, rule.burst);
                for (u32 ki = 0; ki < rule.key.count; ki++) {
                    const RateLimitKeyComponent& kc = rule.key.comps[ki];
                    cfg.add_route_rate_limit_key(kRouteIdx, kc.kind, kc.name, kc.name_len);
                }
                u64 identity = 1469598103934665603ull;
                auto hash_byte = [&](u8 value) {
                    identity ^= value;
                    identity *= 1099511628211ull;
                };
                auto hash_u32 = [&](u32 value) {
                    for (u32 byte = 0; byte < 4; byte++)
                        hash_byte(static_cast<u8>(value >> (byte * 8u)));
                };
                hash_byte(fn.http_method);
                hash_u32(fn.route_pattern.len);
                for (u32 byte = 0; byte < fn.route_pattern.len; byte++)
                    hash_byte(static_cast<u8>(fn.route_pattern.ptr[byte]));
                u32 duplicate_ordinal = 0;
                for (u32 previous = 0; previous < ri; previous++) {
                    const auto& other = fn.rate_limit.rules[previous];
                    bool same = other.max == rule.max && other.window_sec == rule.window_sec &&
                                other.burst == rule.burst && other.scope == rule.scope &&
                                other.key.count == rule.key.count;
                    for (u32 ki = 0; same && ki < rule.key.count; ki++) {
                        const auto& lhs = other.key.comps[ki];
                        const auto& rhs = rule.key.comps[ki];
                        same = lhs.kind == rhs.kind && lhs.name_len == rhs.name_len;
                        for (u32 byte = 0; same && byte < lhs.name_len; byte++)
                            same = lhs.name[byte] == rhs.name[byte];
                    }
                    if (same) duplicate_ordinal++;
                }
                // Policy participates in the provisional declaration identity,
                // while the duplicate ordinal distinguishes truly identical
                // siblings without depending on unrelated decorator insertion.
                // The reload coordinator remaps a compatible policy edit to the
                // predecessor allocation and supplies its activation timestamp.
                hash_u32(rule.max);
                hash_u32(rule.window_sec);
                hash_u32(rule.burst);
                hash_u32(duplicate_ordinal);
                hash_byte(static_cast<u8>(rule.scope));
                hash_byte(rule.key.count);
                for (u32 ki = 0; ki < rule.key.count; ki++) {
                    const auto& component = rule.key.comps[ki];
                    hash_byte(static_cast<u8>(component.kind));
                    hash_byte(component.name_len);
                    for (u32 byte = 0; byte < component.name_len; byte++)
                        hash_byte(static_cast<u8>(component.name[byte]));
                }
                cfg.routes[kRouteIdx].rate_limit.rules[ri].identity = identity;
            }
        }
        if (fn.throttle_down_bps > 0) {
            cfg.set_route_throttle(cfg.route_count - 1, fn.throttle_down_bps);
        }
    }

    return true;
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

inline void marking_policy_identity_mix(u64* identity, u64 value) {
    *identity ^= value;
    *identity *= 0x100000001B3ull;
}

inline void marking_policy_identity_mix_str(u64* identity, Str value) {
    marking_policy_identity_mix(identity, value.len);
    if (value.ptr == nullptr) return;
    for (u32 i = 0; i < value.len; i++)
        marking_policy_identity_mix(identity, static_cast<u8>(value.ptr[i]));
}

inline bool marking_policy_type_shape_valid_impl(const rir::Type* type,
                                                 const rir::Type** seen,
                                                 u32 depth) {
    if (type == nullptr) return false;
    if (depth >= 64) return false;
    if (type->kind == rir::TypeKind::Void) return false;
    for (u32 i = 0; i < depth; i++)
        if (seen[i] == type) return false;
    seen[depth] = type;
    if (type->kind == rir::TypeKind::Optional || type->kind == rir::TypeKind::Array) {
        if (type->inner == nullptr || type->inner->kind == rir::TypeKind::Void) return false;
        return marking_policy_type_shape_valid_impl(type->inner, seen, depth + 1);
    }
    if (type->kind == rir::TypeKind::Struct) {
        if (type->struct_def == nullptr ||
            (type->struct_def->name.len != 0 && type->struct_def->name.ptr == nullptr) ||
            type->struct_def->field_count > rir::kMaxStructFields ||
            type->struct_def->field_count > type->struct_def->field_capacity)
            return false;
        for (u32 fi = 0; fi < type->struct_def->field_count; fi++) {
            const auto& field = type->struct_def->fields()[fi];
            if ((field.name.len != 0 && field.name.ptr == nullptr) ||
                !marking_policy_type_shape_valid_impl(field.type, seen, depth + 1))
                return false;
            for (u32 previous = 0; previous < fi; previous++)
                if (type->struct_def->fields()[previous].name.eq(field.name)) return false;
        }
    }
    return true;
}

inline bool marking_policy_type_shape_valid(const rir::Type* type) {
    const rir::Type* seen[64]{};
    return marking_policy_type_shape_valid_impl(type, seen, 0);
}

inline bool marking_policy_arena_type_graph_valid_impl(const rir::Module& mod,
                                                       const rir::Type* type,
                                                       const rir::Type** seen,
                                                       u32 depth) {
    if (type == nullptr || depth >= 64 ||
        reinterpret_cast<uintptr_t>(type) % alignof(rir::Type) != 0 ||
        !mod.arena->contains_range(type, sizeof(rir::Type)))
        return false;
    for (u32 i = 0; i < depth; i++)
        if (seen[i] == type) return false;
    seen[depth] = type;
    if (type->kind == rir::TypeKind::Optional || type->kind == rir::TypeKind::Array)
        return marking_policy_arena_type_graph_valid_impl(mod, type->inner, seen, depth + 1);
    if (type->kind != rir::TypeKind::Struct) return true;
    const auto* def = type->struct_def;
    if (def == nullptr || reinterpret_cast<uintptr_t>(def) % alignof(rir::StructDef) != 0 ||
        !mod.arena->contains_range(def, sizeof(rir::StructDef)) ||
        def->field_count > rir::kMaxStructFields || def->field_capacity > rir::kMaxStructFields ||
        def->field_count > def->field_capacity ||
        (def->name.len != 0 && !mod.arena->contains_range(def->name.ptr, def->name.len)))
        return false;
    for (u32 field = 0; field < def->field_count; field++) {
        const auto& field_def = def->fields()[field];
        if (field_def.name.len != 0 &&
            !mod.arena->contains_range(field_def.name.ptr, field_def.name.len))
            return false;
        if (!marking_policy_arena_type_graph_valid_impl(mod, field_def.type, seen, depth + 1))
            return false;
    }
    return true;
}

inline bool marking_policy_arena_type_graph_valid(const rir::Module& mod, const rir::Type* type) {
    if (mod.arena == nullptr) return true;
    const rir::Type* seen[64]{};
    return marking_policy_arena_type_graph_valid_impl(mod, type, seen, 0);
}

inline bool marking_policy_types_equal(const rir::Type* lhs, const rir::Type* rhs, u32 depth = 0) {
    if (lhs == rhs) return lhs != nullptr;
    if (lhs == nullptr || rhs == nullptr || lhs->kind != rhs->kind || depth >= 64) return false;
    if (lhs->kind == rir::TypeKind::Optional || lhs->kind == rir::TypeKind::Array)
        return marking_policy_types_equal(lhs->inner, rhs->inner, depth + 1);
    if (lhs->kind == rir::TypeKind::Struct) return lhs->struct_def == rhs->struct_def;
    return true;
}

inline bool marking_policy_has_string_immediate(rir::Opcode op) {
    return op == rir::Opcode::ConstStr || op == rir::Opcode::ReqHeader ||
           op == rir::Opcode::ReqParam || op == rir::Opcode::ReqQuery ||
           op == rir::Opcode::ReqQueryAll || op == rir::Opcode::ReqHeaderAll ||
           op == rir::Opcode::ReqCookie || op == rir::Opcode::ReqSetHeader ||
           op == rir::Opcode::ReqAddHeader || op == rir::Opcode::RespHeader ||
           op == rir::Opcode::RespSetHeader || op == rir::Opcode::RespAddHeader ||
           op == rir::Opcode::RespRemoveHeader || op == rir::Opcode::StrRegexMatch ||
           op == rir::Opcode::IpInCidr || op == rir::Opcode::JsonAppendRaw ||
           op == rir::Opcode::YieldHttpGet || op == rir::Opcode::YieldHttpPost;
}

inline bool marking_policy_operand_arity_valid(const rir::Instruction& inst) {
    switch (inst.op) {
        case rir::Opcode::ConstStr:
        case rir::Opcode::ConstI32:
        case rir::Opcode::ConstI64:
        case rir::Opcode::ConstBool:
        case rir::Opcode::ConstDuration:
        case rir::Opcode::ConstByteSize:
        case rir::Opcode::ConstMethod:
        case rir::Opcode::ConstStatus:
        case rir::Opcode::ReqHeader:
        case rir::Opcode::ReqParam:
        case rir::Opcode::ReqQuery:
        case rir::Opcode::ReqQueryAll:
        case rir::Opcode::ReqHeaderAll:
        case rir::Opcode::ReqQueryString:
        case rir::Opcode::ReqMethod:
        case rir::Opcode::ReqPath:
        case rir::Opcode::ReqPathOnly:
        case rir::Opcode::ReqBody:
        case rir::Opcode::ReqKeepAlive:
        case rir::Opcode::ReqChunked:
        case rir::Opcode::ReqHasContentLength:
        case rir::Opcode::ReqHttp10:
        case rir::Opcode::ReqHttp11:
        case rir::Opcode::ReqHttpVersion:
        case rir::Opcode::ResumeEventKind:
        case rir::Opcode::ResumeEventResult:
        case rir::Opcode::CtxLoadSlotI32:
        case rir::Opcode::ReqRemoteAddr:
        case rir::Opcode::ReqContentLength:
        case rir::Opcode::ReqCookie:
        case rir::Opcode::RespRemoveHeader:
        case rir::Opcode::RespCommitHeaders:
        case rir::Opcode::TimeNowMicros:
        case rir::Opcode::ReloadRequest:
        case rir::Opcode::JsonReset:
        case rir::Opcode::JsonAppendRaw:
        case rir::Opcode::JsonAppendControlPlane:
        case rir::Opcode::JsonCapture:
        case rir::Opcode::JsonFinish:
        case rir::Opcode::BodyParse:
        case rir::Opcode::OptNil:
        case rir::Opcode::Jmp:
        case rir::Opcode::YieldTimer:
            return inst.operand_count == 0;

        case rir::Opcode::ReqSetHeader:
        case rir::Opcode::ReqAddHeader:
        case rir::Opcode::RespHeader:
        case rir::Opcode::RespStatus:
        case rir::Opcode::RespBody:
        case rir::Opcode::RespSetHeader:
        case rir::Opcode::RespAddHeader:
        case rir::Opcode::RespSetStatus:
        case rir::Opcode::RespSetBody:
        case rir::Opcode::ReqSetPath:
        case rir::Opcode::CtxStoreSlotI32:
        case rir::Opcode::StrRegexMatch:
        case rir::Opcode::SextI64:
        case rir::Opcode::IpInCidr:
        case rir::Opcode::BytesHex:
        case rir::Opcode::CacheGet:
        case rir::Opcode::JsonAppendBool:
        case rir::Opcode::JsonAppendI32:
        case rir::Opcode::JsonAppendI64:
        case rir::Opcode::JsonAppendStr:
        case rir::Opcode::JsonAppendStrList:
        case rir::Opcode::JsonAppendArray:
        case rir::Opcode::StructField:
        case rir::Opcode::ArrayLen:
        case rir::Opcode::StrListLen:
        case rir::Opcode::StrListIsEmpty:
        case rir::Opcode::OptWrap:
        case rir::Opcode::OptIsNil:
        case rir::Opcode::OptUnwrap:
        case rir::Opcode::Br:
        case rir::Opcode::RetForward:
        case rir::Opcode::RetForwardBuffered:
            return inst.operand_count == 1;

        case rir::Opcode::StrHasPrefix:
        case rir::Opcode::StrTrimPrefix:
        case rir::Opcode::CmpEq:
        case rir::Opcode::CmpNe:
        case rir::Opcode::CmpLt:
        case rir::Opcode::CmpGt:
        case rir::Opcode::CmpLe:
        case rir::Opcode::CmpGe:
        case rir::Opcode::BitAnd:
        case rir::Opcode::BitOr:
        case rir::Opcode::BitXor:
        case rir::Opcode::BitShl:
        case rir::Opcode::BitShr:
        case rir::Opcode::Add:
        case rir::Opcode::Sub:
        case rir::Opcode::Mul:
        case rir::Opcode::Div:
        case rir::Opcode::Mod:
        case rir::Opcode::MaxInt:
        case rir::Opcode::MinInt:
        case rir::Opcode::HashHmacSha256:
        case rir::Opcode::CacheSet:
        case rir::Opcode::UpstreamMark:
        case rir::Opcode::ArrayGet:
        case rir::Opcode::StrListGet:
            return inst.operand_count == 2;

        case rir::Opcode::Select:
            return inst.operand_count == 3;

        case rir::Opcode::RespCommitBody:
        case rir::Opcode::RetStatus:
        case rir::Opcode::YieldHttpGet:
        case rir::Opcode::YieldForward:
            return inst.operand_count <= 1;

        case rir::Opcode::YieldHttpPost:
            return inst.operand_count <= 2;

        case rir::Opcode::StrInterpolate:
        case rir::Opcode::StructCreate:
        case rir::Opcode::ArrayCreate:
            return true;

        case rir::Opcode::TraceFuncEnter:
        case rir::Opcode::TraceFuncExit:
        case rir::Opcode::TraceIoStart:
        case rir::Opcode::TraceIoEnd:
        case rir::Opcode::MetricHistRecord:
        case rir::Opcode::MetricCounterIncr:
        case rir::Opcode::AccessLogWrite:
            return false;
    }
    return false;
}

inline bool marking_policy_operand_storage_valid(const rir::Module& mod,
                                                 const rir::Instruction& inst) {
    if (inst.operand_count <= rir::kMaxInlineOperands) return true;
    if (mod.arena == nullptr || inst.extra_operands == nullptr) return false;
    const u64 count = inst.operand_count - rir::kMaxInlineOperands;
    return inst.extra_operand_capacity >= count &&
           count <= static_cast<u64>(-1) / sizeof(rir::ValueId) &&
           mod.arena->contains_range(inst.extra_operands, count * sizeof(rir::ValueId));
}

inline bool marking_policy_find_block(const rir::Function& fn, rir::BlockId id, u32* block_index) {
    for (u32 bi = 0; bi < fn.block_count; bi++) {
        if (fn.blocks[bi].id != id) continue;
        *block_index = bi;
        return true;
    }
    return false;
}

inline bool marking_policy_block_dominates(const rir::Function& fn,
                                           u32 definition_block,
                                           u32 use_block) {
    if (definition_block == use_block || definition_block == 0) return true;
    static constexpr u32 kMaxPolicyBlocks = 4096;
    if (fn.block_count > kMaxPolicyBlocks) return false;
    bool visited[kMaxPolicyBlocks]{};
    u32 worklist[kMaxPolicyBlocks]{};
    u32 work_count = 1;
    worklist[0] = 0;
    visited[0] = true;
    while (work_count != 0) {
        const u32 bi = worklist[--work_count];
        if (bi == definition_block) continue;
        if (bi == use_block) return false;
        const auto& block = fn.blocks[bi];
        if (block.inst_count == 0 || block.insts == nullptr) continue;
        const auto& term = block.insts[block.inst_count - 1];
        const u32 target_count = term.op == rir::Opcode::Br    ? 2
                                 : term.op == rir::Opcode::Jmp ? 1
                                                               : 0;
        for (u32 ti = 0; ti < target_count; ti++) {
            u32 target_index = 0;
            if (!marking_policy_find_block(fn, term.imm.block_targets[ti], &target_index))
                return false;
            if (!visited[target_index] && work_count < kMaxPolicyBlocks) {
                visited[target_index] = true;
                worklist[work_count++] = target_index;
            }
        }
    }
    return true;
}

inline bool marking_policy_is_mark_failure_exit(const rir::Function& fn,
                                                const rir::Instruction& branch,
                                                u32 target_block) {
    if (branch.op != rir::Opcode::Br || branch.operand_count != 1 ||
        branch.operand(0).id >= fn.value_count)
        return false;
    const auto& condition = fn.values[branch.operand(0).id];
    u32 condition_block = 0;
    if (!marking_policy_find_block(fn, condition.def_block, &condition_block) ||
        condition.def_inst >= fn.blocks[condition_block].inst_count ||
        fn.blocks[condition_block].insts[condition.def_inst].op != rir::Opcode::UpstreamMark)
        return false;
    const auto& exit = fn.blocks[target_block];
    if (exit.inst_count == 0 || exit.insts == nullptr) return false;
    for (u32 ii = 0; ii + 1 < exit.inst_count; ii++)
        if (exit.insts[ii].op == rir::Opcode::UpstreamMark) return false;
    const auto& term = exit.insts[exit.inst_count - 1];
    return term.op != rir::Opcode::Br && term.op != rir::Opcode::Jmp;
}

inline bool marking_policy_mark_dominates_exits(const rir::Function& fn, u32 mark_block) {
    if (mark_block == 0) return true;
    static constexpr u32 kMaxPolicyBlocks = 4096;
    if (fn.block_count > kMaxPolicyBlocks) return false;
    bool visited[kMaxPolicyBlocks]{};
    u32 worklist[kMaxPolicyBlocks]{};
    u32 work_count = 1;
    worklist[0] = 0;
    visited[0] = true;
    while (work_count != 0) {
        const u32 bi = worklist[--work_count];
        if (bi == mark_block) continue;
        const auto& block = fn.blocks[bi];
        const auto& term = block.insts[block.inst_count - 1];
        const u32 target_count = term.op == rir::Opcode::Br    ? 2
                                 : term.op == rir::Opcode::Jmp ? 1
                                                               : 0;
        if (target_count == 0) return false;
        for (u32 ti = 0; ti < target_count; ti++) {
            u32 target_index = 0;
            if (!marking_policy_find_block(fn, term.imm.block_targets[ti], &target_index))
                return false;
            if (ti == 1 && marking_policy_is_mark_failure_exit(fn, term, target_index)) continue;
            if (!visited[target_index]) {
                visited[target_index] = true;
                worklist[work_count++] = target_index;
            }
        }
    }
    return true;
}

inline bool marking_policy_operand_has_dominating_definition(const rir::Function& fn,
                                                             rir::ValueId operand,
                                                             u32 use_block,
                                                             u32 use_inst) {
    if (fn.values == nullptr || operand.id >= fn.value_count) return false;
    const auto& value = fn.values[operand.id];
    u32 definition_block = 0;
    if (!marking_policy_find_block(fn, value.def_block, &definition_block)) return false;
    const auto& block = fn.blocks[definition_block];
    if (block.insts == nullptr || value.def_inst >= block.inst_count) return false;
    const auto& definition = block.insts[value.def_inst];
    if (definition.result != operand) return false;
    if (definition_block == use_block) return value.def_inst < use_inst;
    return marking_policy_block_dominates(fn, definition_block, use_block);
}

inline bool marking_policy_value_has_kind(const rir::Function& fn,
                                          rir::ValueId value,
                                          rir::TypeKind kind) {
    return fn.values != nullptr && value.id < fn.value_count &&
           marking_policy_type_shape_valid(fn.values[value.id].type) &&
           fn.values[value.id].type->kind == kind;
}

inline bool marking_policy_json_type_valid(const rir::Type* type, u32 depth = 0) {
    if (!marking_policy_type_shape_valid(type) || depth > 32) return false;
    switch (type->kind) {
        case rir::TypeKind::Bool:
        case rir::TypeKind::I32:
        case rir::TypeKind::I64:
        case rir::TypeKind::Str:
        case rir::TypeKind::StrList:
            return true;
        case rir::TypeKind::Array:
            return marking_policy_json_type_valid(type->inner, depth + 1);
        case rir::TypeKind::Struct:
            if (type->struct_def == nullptr) return false;
            for (u32 fi = 0; fi < type->struct_def->field_count; fi++)
                if (!marking_policy_json_type_valid(type->struct_def->fields()[fi].type, depth + 1))
                    return false;
            return true;
        default:
            return false;
    }
}

inline bool marking_policy_instruction_types_valid(const rir::Function& fn,
                                                   const rir::Instruction& inst) {
    const auto operand_kind = [&](u32 index, rir::TypeKind kind) {
        return marking_policy_value_has_kind(fn, inst.operand(index), kind);
    };
    const rir::Type* result_type = inst.result != rir::kNoValue && inst.result.id < fn.value_count
                                       ? fn.values[inst.result.id].type
                                       : nullptr;
    const auto result_kind = [&](rir::TypeKind kind) {
        return result_type != nullptr && result_type->kind == kind;
    };
    switch (inst.op) {
        case rir::Opcode::ConstI32:
            return result_kind(rir::TypeKind::I32);
        case rir::Opcode::ConstI64:
            return result_kind(rir::TypeKind::I64);
        case rir::Opcode::ConstBool:
            return result_kind(rir::TypeKind::Bool);
        case rir::Opcode::ConstStr:
            return result_kind(rir::TypeKind::Str);
        case rir::Opcode::ConstDuration:
            return result_kind(rir::TypeKind::Duration);
        case rir::Opcode::ConstByteSize:
            return result_kind(rir::TypeKind::ByteSize);
        case rir::Opcode::ConstMethod:
            return result_kind(rir::TypeKind::Method);
        case rir::Opcode::ConstStatus:
            return result_kind(rir::TypeKind::StatusCode);
        case rir::Opcode::TimeNowMicros:
            return result_kind(rir::TypeKind::I64);
        case rir::Opcode::ReloadRequest:
            return result_kind(rir::TypeKind::Bool);
        case rir::Opcode::JsonCapture:
            return result_kind(rir::TypeKind::Str);
        case rir::Opcode::RespHeader:
            return operand_kind(0, rir::TypeKind::Optional) &&
                   fn.values[inst.operand(0).id].type->inner != nullptr &&
                   fn.values[inst.operand(0).id].type->inner->kind == rir::TypeKind::Str &&
                   result_type != nullptr && result_type->kind == rir::TypeKind::Optional &&
                   result_type->inner != nullptr && result_type->inner->kind == rir::TypeKind::Str;
        case rir::Opcode::RespStatus:
            return operand_kind(0, rir::TypeKind::I32) && result_kind(rir::TypeKind::I32);
        case rir::Opcode::RespBody:
            return operand_kind(0, rir::TypeKind::Str) && result_kind(rir::TypeKind::Str);
        case rir::Opcode::RespSetHeader:
        case rir::Opcode::RespAddHeader:
        case rir::Opcode::RespSetBody:
            return inst.result == rir::kNoValue && operand_kind(0, rir::TypeKind::Str);
        case rir::Opcode::RespSetStatus:
            return inst.result == rir::kNoValue && operand_kind(0, rir::TypeKind::I32);
        case rir::Opcode::StrHasPrefix:
            return operand_kind(0, rir::TypeKind::Str) && operand_kind(1, rir::TypeKind::Str) &&
                   result_kind(rir::TypeKind::Bool);
        case rir::Opcode::StrTrimPrefix:
            return operand_kind(0, rir::TypeKind::Str) && operand_kind(1, rir::TypeKind::Str) &&
                   result_kind(rir::TypeKind::Str);
        case rir::Opcode::StrRegexMatch:
            return operand_kind(0, rir::TypeKind::Str) && result_kind(rir::TypeKind::Bool);
        case rir::Opcode::Br:
            return inst.result == rir::kNoValue && operand_kind(0, rir::TypeKind::Bool);
        case rir::Opcode::UpstreamMark:
            return operand_kind(0, rir::TypeKind::I64) && operand_kind(1, rir::TypeKind::Bool) &&
                   result_type != nullptr && result_type->kind == rir::TypeKind::Bool;
        case rir::Opcode::StructCreate: {
            if (!marking_policy_type_shape_valid(inst.imm.struct_ref.type) ||
                inst.imm.struct_ref.type->kind != rir::TypeKind::Struct ||
                !marking_policy_types_equal(result_type, inst.imm.struct_ref.type))
                return false;
            const auto& def = *inst.imm.struct_ref.type->struct_def;
            if (inst.operand_count != def.field_count) return false;
            for (u32 fi = 0; fi < def.field_count; fi++) {
                if (inst.operand(fi).id >= fn.value_count ||
                    !marking_policy_types_equal(fn.values[inst.operand(fi).id].type,
                                                def.fields()[fi].type))
                    return false;
            }
            return true;
        }
        case rir::Opcode::StructField: {
            if (inst.operand_count != 1 || inst.operand(0).id >= fn.value_count ||
                inst.imm.struct_ref.name.len == 0 || inst.imm.struct_ref.name.ptr == nullptr)
                return false;
            const rir::Type* receiver_type = fn.values[inst.operand(0).id].type;
            if (!marking_policy_type_shape_valid(receiver_type) ||
                receiver_type->kind != rir::TypeKind::Struct)
                return false;
            const auto& def = *receiver_type->struct_def;
            const rir::Type* field_type = nullptr;
            for (u32 fi = 0; fi < def.field_count; fi++)
                if (def.fields()[fi].name.eq(inst.imm.struct_ref.name))
                    field_type = def.fields()[fi].type;
            return field_type != nullptr &&
                   marking_policy_types_equal(inst.imm.struct_ref.type, field_type) &&
                   marking_policy_types_equal(result_type, field_type);
        }
        case rir::Opcode::ArrayCreate:
            if (result_type == nullptr || result_type->kind != rir::TypeKind::Array ||
                result_type->inner == nullptr || inst.operand_count > rir::kMaxArrayItems ||
                (inst.operand_count > rir::kMaxInlineOperands && inst.extra_operands == nullptr))
                return false;
            for (u32 oi = 0; oi < inst.operand_count; oi++) {
                if (inst.operand(oi).id >= fn.value_count ||
                    !marking_policy_types_equal(fn.values[inst.operand(oi).id].type,
                                                result_type->inner))
                    return false;
            }
            return true;
        case rir::Opcode::ArrayLen:
            return operand_kind(0, rir::TypeKind::Array) && result_type != nullptr &&
                   result_type->kind == rir::TypeKind::I32;
        case rir::Opcode::ArrayGet: {
            if (!operand_kind(0, rir::TypeKind::Array) || !operand_kind(1, rir::TypeKind::I32) ||
                result_type == nullptr)
                return false;
            const rir::Type* array_type = fn.values[inst.operand(0).id].type;
            return array_type->inner != nullptr &&
                   marking_policy_types_equal(result_type, array_type->inner);
        }
        case rir::Opcode::StrListLen:
            return operand_kind(0, rir::TypeKind::StrList) && result_type != nullptr &&
                   result_type->kind == rir::TypeKind::I32;
        case rir::Opcode::StrListIsEmpty:
            return operand_kind(0, rir::TypeKind::StrList) && result_type != nullptr &&
                   result_type->kind == rir::TypeKind::Bool;
        case rir::Opcode::StrListGet:
            return operand_kind(0, rir::TypeKind::StrList) && operand_kind(1, rir::TypeKind::I32) &&
                   result_type != nullptr && result_type->kind == rir::TypeKind::Optional &&
                   result_type->inner != nullptr && result_type->inner->kind == rir::TypeKind::Str;
        case rir::Opcode::OptNil:
            return marking_policy_type_shape_valid(result_type) &&
                   result_type->kind == rir::TypeKind::Optional;
        case rir::Opcode::Select:
            return operand_kind(0, rir::TypeKind::Bool) && result_type != nullptr &&
                   marking_policy_types_equal(fn.values[inst.operand(1).id].type,
                                              fn.values[inst.operand(2).id].type) &&
                   marking_policy_types_equal(result_type, fn.values[inst.operand(1).id].type);
        case rir::Opcode::OptWrap:
            return result_type != nullptr && result_type->kind == rir::TypeKind::Optional &&
                   marking_policy_types_equal(result_type->inner,
                                              fn.values[inst.operand(0).id].type);
        case rir::Opcode::OptIsNil:
            return operand_kind(0, rir::TypeKind::Optional) && result_type != nullptr &&
                   result_type->kind == rir::TypeKind::Bool;
        case rir::Opcode::OptUnwrap: {
            if (!operand_kind(0, rir::TypeKind::Optional) || result_type == nullptr) return false;
            return marking_policy_types_equal(fn.values[inst.operand(0).id].type->inner,
                                              result_type);
        }
        case rir::Opcode::CmpEq:
        case rir::Opcode::CmpNe: {
            const rir::Type* operand_type = fn.values[inst.operand(0).id].type;
            const auto kind = operand_type->kind;
            const bool equality_comparable =
                kind == rir::TypeKind::Bool || kind == rir::TypeKind::I32 ||
                kind == rir::TypeKind::I64 || kind == rir::TypeKind::U32 ||
                kind == rir::TypeKind::U64 || kind == rir::TypeKind::Str ||
                kind == rir::TypeKind::ByteSize || kind == rir::TypeKind::Duration ||
                kind == rir::TypeKind::Time || kind == rir::TypeKind::IP ||
                kind == rir::TypeKind::StatusCode || kind == rir::TypeKind::Method;
            return equality_comparable &&
                   marking_policy_types_equal(operand_type, fn.values[inst.operand(1).id].type) &&
                   result_kind(rir::TypeKind::Bool);
        }
        case rir::Opcode::CmpLt:
        case rir::Opcode::CmpGt:
        case rir::Opcode::CmpLe:
        case rir::Opcode::CmpGe: {
            const rir::Type* operand_type = fn.values[inst.operand(0).id].type;
            const auto kind = operand_type->kind;
            const bool orderable = kind == rir::TypeKind::I32 || kind == rir::TypeKind::I64 ||
                                   kind == rir::TypeKind::U32 || kind == rir::TypeKind::U64 ||
                                   kind == rir::TypeKind::Str || kind == rir::TypeKind::ByteSize ||
                                   kind == rir::TypeKind::Duration || kind == rir::TypeKind::Time ||
                                   kind == rir::TypeKind::StatusCode;
            return orderable &&
                   marking_policy_types_equal(operand_type, fn.values[inst.operand(1).id].type) &&
                   result_kind(rir::TypeKind::Bool);
        }
        case rir::Opcode::BitAnd:
        case rir::Opcode::BitOr:
        case rir::Opcode::BitXor:
        case rir::Opcode::BitShl:
        case rir::Opcode::BitShr:
        case rir::Opcode::Add:
        case rir::Opcode::Sub:
        case rir::Opcode::Mul:
        case rir::Opcode::Div:
        case rir::Opcode::Mod:
        case rir::Opcode::MaxInt:
        case rir::Opcode::MinInt:
            return (operand_kind(0, rir::TypeKind::I32) || operand_kind(0, rir::TypeKind::I64)) &&
                   marking_policy_types_equal(fn.values[inst.operand(0).id].type,
                                              fn.values[inst.operand(1).id].type) &&
                   marking_policy_types_equal(fn.values[inst.operand(0).id].type, result_type);
        case rir::Opcode::SextI64:
            return operand_kind(0, rir::TypeKind::I32) && result_kind(rir::TypeKind::I64);
        case rir::Opcode::CacheGet:
            return operand_kind(0, rir::TypeKind::IP) && result_type != nullptr &&
                   result_type->kind == rir::TypeKind::Optional && result_type->inner != nullptr &&
                   result_type->inner->kind == rir::TypeKind::I64;
        case rir::Opcode::CacheSet:
            return operand_kind(0, rir::TypeKind::IP) && operand_kind(1, rir::TypeKind::I64) &&
                   result_kind(rir::TypeKind::I64);
        case rir::Opcode::RespRemoveHeader:
        case rir::Opcode::RespCommitHeaders:
        case rir::Opcode::JsonReset:
        case rir::Opcode::JsonAppendRaw:
        case rir::Opcode::JsonAppendControlPlane:
        case rir::Opcode::JsonFinish:
        case rir::Opcode::Jmp:
        case rir::Opcode::YieldTimer:
            return inst.result == rir::kNoValue;
        case rir::Opcode::RespCommitBody:
            return inst.result == rir::kNoValue &&
                   (inst.operand_count == 0 || operand_kind(0, rir::TypeKind::Str));
        case rir::Opcode::RetStatus:
            return inst.result == rir::kNoValue &&
                   (inst.operand_count == 0 || operand_kind(0, rir::TypeKind::I32) ||
                    operand_kind(0, rir::TypeKind::U32) ||
                    operand_kind(0, rir::TypeKind::StatusCode));
        case rir::Opcode::RetForward:
        case rir::Opcode::RetForwardBuffered:
            return inst.result == rir::kNoValue &&
                   (operand_kind(0, rir::TypeKind::I32) || operand_kind(0, rir::TypeKind::U32));
        case rir::Opcode::JsonAppendBool:
            return inst.result == rir::kNoValue && operand_kind(0, rir::TypeKind::Bool);
        case rir::Opcode::JsonAppendI32:
            return inst.result == rir::kNoValue && operand_kind(0, rir::TypeKind::I32);
        case rir::Opcode::JsonAppendI64:
            return inst.result == rir::kNoValue && operand_kind(0, rir::TypeKind::I64);
        case rir::Opcode::JsonAppendStr:
            return inst.result == rir::kNoValue && operand_kind(0, rir::TypeKind::Str);
        case rir::Opcode::JsonAppendStrList:
            return inst.result == rir::kNoValue && operand_kind(0, rir::TypeKind::StrList);
        case rir::Opcode::JsonAppendArray:
            return inst.result == rir::kNoValue && operand_kind(0, rir::TypeKind::Array) &&
                   marking_policy_json_type_valid(fn.values[inst.operand(0).id].type);
        default:
            // Marking-policy RIR can be hand-built or transformed after the
            // typed builder runs. Do not pass an opcode through to codegen until
            // this validator has an explicit operand/result contract for it.
            return false;
    }
}

inline bool marking_policy_ssa_valid(const rir::Module& mod, const rir::Function& fn) {
    for (u32 bi = 0; bi < fn.block_count; bi++) {
        const auto& block = fn.blocks[bi];
        for (u32 ii = 0; ii < block.inst_count; ii++) {
            const auto& inst = block.insts[ii];
            if (!marking_policy_operand_arity_valid(inst)) return false;
            if (!marking_policy_operand_storage_valid(mod, inst)) return false;
            if (inst.result != rir::kNoValue) {
                if (inst.result.id >= fn.value_count ||
                    !marking_policy_type_shape_valid(fn.values[inst.result.id].type) ||
                    fn.values[inst.result.id].def_block != block.id ||
                    fn.values[inst.result.id].def_inst != ii)
                    return false;
            }
            for (u32 oi = 0; oi < inst.operand_count; oi++) {
                const rir::ValueId operand = inst.operand(oi);
                if (operand.id >= fn.value_count ||
                    !marking_policy_type_shape_valid(fn.values[operand.id].type) ||
                    !marking_policy_operand_has_dominating_definition(fn, operand, bi, ii))
                    return false;
            }
            if (!marking_policy_instruction_types_valid(fn, inst)) return false;
        }
    }
    return true;
}

inline bool marking_policy_storage_shape_valid(const rir::Function& fn) {
    if (fn.block_count > fn.block_cap) return false;
    if (fn.value_count > fn.value_cap) return false;
    if (fn.block_count != 0 && fn.blocks == nullptr) return false;
    if (fn.value_count != 0 && fn.values == nullptr) return false;
    for (u32 bi = 0; bi < fn.block_count; bi++) {
        const auto& block = fn.blocks[bi];
        if (block.id.id >= fn.block_cap) return false;
        for (u32 previous = 0; previous < bi; previous++)
            if (fn.blocks[previous].id == block.id) return false;
        if (block.inst_count > block.inst_cap) return false;
        if (block.inst_count != 0 && block.insts == nullptr) return false;
    }
    return true;
}

inline bool marking_policy_arena_storage_shape_valid(const rir::Module& mod,
                                                     const rir::Function& fn) {
    if (mod.arena == nullptr) return true;
    if (fn.block_count > fn.block_cap || fn.value_count > fn.value_cap) return false;
    if (reinterpret_cast<uintptr_t>(fn.blocks) % alignof(rir::Block) != 0 ||
        reinterpret_cast<uintptr_t>(fn.values) % alignof(rir::Value) != 0 ||
        !mod.arena->contains_range(fn.blocks,
                                   static_cast<u64>(fn.block_cap) * sizeof(rir::Block)) ||
        !mod.arena->contains_range(fn.values, static_cast<u64>(fn.value_cap) * sizeof(rir::Value)))
        return false;
    for (u32 value = 0; value < fn.value_count; value++)
        if (!marking_policy_arena_type_graph_valid(mod, fn.values[value].type)) return false;
    for (u32 bi = 0; bi < fn.block_count; bi++) {
        const auto& block = fn.blocks[bi];
        if (block.inst_count > block.inst_cap ||
            reinterpret_cast<uintptr_t>(block.insts) % alignof(rir::Instruction) != 0 ||
            !mod.arena->contains_range(block.insts,
                                       static_cast<u64>(block.inst_cap) * sizeof(rir::Instruction)))
            return false;
        for (u32 ii = 0; ii < block.inst_count; ii++) {
            const auto& inst = block.insts[ii];
            if (marking_policy_has_string_immediate(inst.op) && inst.imm.str_val.len != 0 &&
                !mod.arena->contains_range(inst.imm.str_val.ptr, inst.imm.str_val.len))
                return false;
            if ((inst.op == rir::Opcode::StructCreate || inst.op == rir::Opcode::StructField) &&
                (!marking_policy_arena_type_graph_valid(mod, inst.imm.struct_ref.type) ||
                 (inst.imm.struct_ref.name.len != 0 &&
                  !mod.arena->contains_range(inst.imm.struct_ref.name.ptr,
                                             inst.imm.struct_ref.name.len))))
                return false;
        }
    }
    return true;
}

inline bool marking_policy_shape_valid(const rir::Function& fn, bool inspect_operands = true) {
    if (!marking_policy_storage_shape_valid(fn)) return false;
    for (u32 bi = 0; bi < fn.block_count; bi++) {
        const auto& block = fn.blocks[bi];
        for (u32 ii = 0; ii < block.inst_count; ii++) {
            const auto& inst = block.insts[ii];
            if (inst.is_terminator() && ii + 1 != block.inst_count) return false;
            if (marking_policy_has_string_immediate(inst.op) && inst.imm.str_val.len != 0 &&
                inst.imm.str_val.ptr == nullptr)
                return false;
            if (inst.op == rir::Opcode::Br || inst.op == rir::Opcode::Jmp) {
                const u32 target_count = inst.op == rir::Opcode::Br ? 2 : 1;
                for (u32 ti = 0; ti < target_count; ti++) {
                    u32 target_index = 0;
                    if (inst.imm.block_targets[ti].id >= fn.block_cap ||
                        !marking_policy_find_block(fn, inst.imm.block_targets[ti], &target_index))
                        return false;
                }
            }
            // Functions that do not emit upstream.mark need only storage and
            // control-target validation here. RIR carries no capacity for an
            // arbitrary extra_operands pointer, so opcode-specific traversal
            // is safe only for the fully validated marking-policy path.
            if (!inspect_operands) continue;
            if (inst.operand_count > rir::kMaxInlineOperands) return false;
            if (inst.op == rir::Opcode::StructCreate) {
                if (!marking_policy_type_shape_valid(inst.imm.struct_ref.type) ||
                    inst.imm.struct_ref.type->kind != rir::TypeKind::Struct)
                    return false;
                const auto& def = *inst.imm.struct_ref.type->struct_def;
                if (def.field_count > rir::kMaxStructFields ||
                    inst.operand_count != def.field_count || fn.values == nullptr ||
                    inst.result.id >= fn.value_count ||
                    !marking_policy_types_equal(fn.values[inst.result.id].type,
                                                inst.imm.struct_ref.type))
                    return false;
                for (u32 fi = 0; fi < def.field_count; fi++) {
                    const auto& field = def.fields()[fi];
                    if ((field.name.len != 0 && field.name.ptr == nullptr) ||
                        !marking_policy_type_shape_valid(field.type) ||
                        inst.operand(fi).id >= fn.value_count ||
                        !marking_policy_types_equal(fn.values[inst.operand(fi).id].type,
                                                    field.type))
                        return false;
                }
            } else if (inst.op == rir::Opcode::StructField) {
                if (inst.operand_count != 1 || fn.values == nullptr ||
                    inst.operand(0).id >= fn.value_count || inst.result.id >= fn.value_count ||
                    inst.imm.struct_ref.name.len == 0 || inst.imm.struct_ref.name.ptr == nullptr)
                    return false;
                const rir::Type* receiver_type = fn.values[inst.operand(0).id].type;
                if (!marking_policy_type_shape_valid(receiver_type) ||
                    receiver_type->kind != rir::TypeKind::Struct)
                    return false;
                const auto& def = *receiver_type->struct_def;
                if (def.field_count > rir::kMaxStructFields) return false;
                const rir::Type* field_type = nullptr;
                for (u32 fi = 0; fi < def.field_count; fi++) {
                    const auto& field = def.fields()[fi];
                    if ((field.name.len != 0 && field.name.ptr == nullptr) ||
                        !marking_policy_type_shape_valid(field.type))
                        return false;
                    if (field.name.eq(inst.imm.struct_ref.name)) field_type = field.type;
                }
                if (field_type == nullptr ||
                    !marking_policy_types_equal(inst.imm.struct_ref.type, field_type) ||
                    !marking_policy_types_equal(fn.values[inst.result.id].type, field_type))
                    return false;
            } else if (inst.op == rir::Opcode::ArrayCreate) {
                if (inst.operand_count > rir::kMaxArrayItems || fn.values == nullptr ||
                    inst.result.id >= fn.value_count)
                    return false;
                const rir::Type* result_type = fn.values[inst.result.id].type;
                if (!marking_policy_type_shape_valid(result_type) ||
                    result_type->kind != rir::TypeKind::Array || result_type->inner == nullptr)
                    return false;
                for (u32 oi = 0; oi < inst.operand_count; oi++) {
                    if (inst.operand(oi).id >= fn.value_count ||
                        !marking_policy_types_equal(fn.values[inst.operand(oi).id].type,
                                                    result_type->inner))
                        return false;
                }
            }
        }
    }
    return true;
}

inline bool marking_policy_shape_valid(const rir::Module& mod,
                                       const rir::Function& fn,
                                       bool inspect_operands = true) {
    if (!marking_policy_arena_storage_shape_valid(mod, fn) ||
        !marking_policy_storage_shape_valid(fn))
        return false;
    if (inspect_operands)
        for (u32 bi = 0; bi < fn.block_count; bi++)
            for (u32 ii = 0; ii < fn.blocks[bi].inst_count; ii++)
                if (!marking_policy_operand_storage_valid(mod, fn.blocks[bi].insts[ii]))
                    return false;
    return marking_policy_shape_valid(fn, false) &&
           (!inspect_operands || marking_policy_ssa_valid(mod, fn));
}

inline bool marking_policy_emitted_mask(const rir::Module& mod,
                                        const rir::Function& fn,
                                        u32 upstream_count,
                                        u32* emitted_mask,
                                        bool* request_dependent = nullptr,
                                        bool* suspends = nullptr) {
    if (!marking_policy_arena_storage_shape_valid(mod, fn) ||
        !marking_policy_storage_shape_valid(fn))
        return false;
    u32 mask = 0;
    bool contains_mark = false;
    for (u32 bi = 0; bi < fn.block_count && !contains_mark; bi++) {
        const auto& block = fn.blocks[bi];
        for (u32 ii = 0; ii < block.inst_count; ii++)
            if (block.insts[ii].op == rir::Opcode::UpstreamMark) {
                contains_mark = true;
                break;
            }
    }
    if (!marking_policy_shape_valid(mod, fn, contains_mark)) return false;
    for (u32 bi = 0; bi < fn.block_count; bi++) {
        const auto& block = fn.blocks[bi];
        for (u32 ii = 0; ii < block.inst_count; ii++) {
            const auto& inst = block.insts[ii];
            if (suspends != nullptr && inst.is_yield()) *suspends = true;
            const auto opcode = static_cast<u32>(inst.op);
            if (request_dependent != nullptr &&
                ((opcode >= static_cast<u32>(rir::Opcode::ReqHeader) &&
                  opcode <= static_cast<u32>(rir::Opcode::ReqCookie)) ||
                 inst.op == rir::Opcode::ReqSetHeader || inst.op == rir::Opcode::ReqAddHeader ||
                 inst.op == rir::Opcode::ReqSetPath || inst.op == rir::Opcode::BodyParse))
                *request_dependent = true;
            if (inst.op == rir::Opcode::CacheGet || inst.op == rir::Opcode::CacheSet) {
                if (inst.imm.i32_val < 0 ||
                    static_cast<u32>(inst.imm.i32_val) >= mod.cache_instance_count)
                    return false;
                const auto& cache = mod.cache_instances[inst.imm.i32_val];
                if ((cache.name.len != 0 && cache.name.ptr == nullptr) || cache.capacity == 0 ||
                    cache.capacity > RouteConfig::kMaxCacheCapacity)
                    return false;
                const bool is_get = inst.op == rir::Opcode::CacheGet;
                if (fn.values == nullptr || inst.operand_count != (is_get ? 1u : 2u) ||
                    inst.operand(0).id >= fn.value_count || inst.result.id >= fn.value_count ||
                    fn.values[inst.operand(0).id].type == nullptr ||
                    fn.values[inst.operand(0).id].type->kind != rir::TypeKind::IP ||
                    fn.values[inst.result.id].type == nullptr)
                    return false;
                if (is_get) {
                    const rir::Type* result = fn.values[inst.result.id].type;
                    if (result->kind != rir::TypeKind::Optional || result->inner == nullptr ||
                        result->inner->kind != rir::TypeKind::I64)
                        return false;
                } else if (inst.operand(1).id >= fn.value_count ||
                           fn.values[inst.operand(1).id].type == nullptr ||
                           fn.values[inst.operand(1).id].type->kind != rir::TypeKind::I64 ||
                           fn.values[inst.result.id].type->kind != rir::TypeKind::I64) {
                    return false;
                }
            }
            if (inst.op != rir::Opcode::UpstreamMark) continue;
            if (inst.operand_count != 2 || fn.values == nullptr ||
                inst.operands[0].id >= fn.value_count || inst.operands[1].id >= fn.value_count ||
                inst.result.id >= fn.value_count ||
                fn.values[inst.operands[0].id].type == nullptr ||
                fn.values[inst.operands[1].id].type == nullptr ||
                fn.values[inst.result.id].type == nullptr ||
                fn.values[inst.operands[0].id].type->kind != rir::TypeKind::I64 ||
                fn.values[inst.operands[1].id].type->kind != rir::TypeKind::Bool ||
                fn.values[inst.result.id].type->kind != rir::TypeKind::Bool)
                return false;
            if (!marking_policy_operand_has_dominating_definition(fn, inst.operands[0], bi, ii) ||
                !marking_policy_operand_has_dominating_definition(fn, inst.operands[1], bi, ii))
                return false;
            if (inst.imm.i32_val < 0) return false;
            const u32 receiver = static_cast<u32>(inst.imm.i32_val);
            if (receiver >= upstream_count || receiver >= 32) return false;
            mask |= u32{1} << receiver;
        }
    }
    *emitted_mask = mask;
    return true;
}

inline bool marking_policy_control_flow_valid(const rir::Function& fn) {
    static constexpr u32 kMaxPolicyBlocks = 4096;
    if (fn.block_count == 0 || fn.block_count > kMaxPolicyBlocks || fn.blocks == nullptr)
        return false;
    u8 color[kMaxPolicyBlocks]{};
    u32 stack[kMaxPolicyBlocks]{};
    u32 next_target[kMaxPolicyBlocks]{};
    u32 depth = 1;
    stack[0] = 0;
    color[0] = 1;
    while (depth != 0) {
        const u32 block_index = stack[depth - 1];
        const auto& block = fn.blocks[block_index];
        if (block.inst_count == 0 || block.insts == nullptr || block.terminator() == nullptr)
            return false;
        const auto& term = block.insts[block.inst_count - 1];
        const u32 target_count = term.op == rir::Opcode::Br    ? 2
                                 : term.op == rir::Opcode::Jmp ? 1
                                                               : 0;
        if (next_target[block_index] >= target_count) {
            color[block_index] = 2;
            depth--;
            continue;
        }
        u32 target_index = 0;
        if (!marking_policy_find_block(
                fn, term.imm.block_targets[next_target[block_index]++], &target_index))
            return false;
        if (color[target_index] == 1) return false;
        if (color[target_index] == 0) {
            color[target_index] = 1;
            stack[depth++] = target_index;
        }
    }
    for (u32 bi = 0; bi < fn.block_count; bi++) {
        if (color[bi] != 0) continue;
        const auto& block = fn.blocks[bi];
        for (u32 ii = 0; ii < block.inst_count; ii++)
            if (block.insts[ii].op == rir::Opcode::UpstreamMark) return false;
    }
    for (u32 mark_block = 0; mark_block < fn.block_count; mark_block++)
        for (u32 mark_inst = 0; mark_inst < fn.blocks[mark_block].inst_count; mark_inst++) {
            if (fn.blocks[mark_block].insts[mark_inst].op != rir::Opcode::UpstreamMark) continue;
            if (!marking_policy_mark_dominates_exits(fn, mark_block)) return false;
        }
    return true;
}

// Validate every function that can participate in an upstream-marking policy
// before handing the module to codegen. The same validation also runs while
// populating RouteConfig, but that is too late for malformed SSA: codegen may
// dereference operands while lowering the RIR to LLVM.
inline bool marking_policies_valid_for_codegen(const rir::Module& mod) {
    if (mod.upstream_count > rir::Module::kMaxUpstreams ||
        mod.cache_instance_count > rir::Module::kMaxCacheInstances ||
        mod.cache_instance_count > RouteConfig::kMaxCacheInstances ||
        mod.func_count > mod.func_cap || (mod.func_count != 0 && mod.functions == nullptr))
        return false;
    if (mod.arena != nullptr &&
        (reinterpret_cast<uintptr_t>(mod.functions) % alignof(rir::Function) != 0 ||
         !mod.arena->contains_range(mod.functions,
                                    static_cast<u64>(mod.func_cap) * sizeof(rir::Function))))
        return false;

    u32 claimed_upstreams = 0;
    for (u32 fi = 0; fi < mod.func_count; fi++) {
        const auto& fn = mod.functions[fi];
        u32 emitted_mask = 0;
        bool request_dependent = false;
        bool suspends = false;
        if (!marking_policy_emitted_mask(
                mod, fn, mod.upstream_count, &emitted_mask, &request_dependent, &suspends))
            return false;
        if (!fn.is_timer) {
            if (emitted_mask != 0 || fn.upstream_mark_mask != 0) return false;
            continue;
        }
        if (fn.upstream_mark_mask != emitted_mask) return false;
        if (emitted_mask == 0) continue;
        if (!marking_policy_control_flow_valid(fn) || !mod.upstream_mark_replay_complete ||
            request_dependent || suspends || fn.yield_count != 0 || fn.timer_shard < 0 ||
            (claimed_upstreams & emitted_mask) != 0)
            return false;
        claimed_upstreams |= emitted_mask;
    }
    return true;
}

inline void marking_policy_identity_mix_type_impl(u64* identity,
                                                  const rir::Type& type,
                                                  const rir::Type** seen,
                                                  u32 depth) {
    marking_policy_identity_mix(identity, static_cast<u32>(type.kind));
    if (type.kind == rir::TypeKind::Optional || type.kind == rir::TypeKind::Array) {
        if (type.inner == nullptr) return;
        if (depth >= 64) {
            marking_policy_identity_mix(identity, 0xffffffffffffffffull);
            return;
        }
        for (u32 i = 0; i < depth; i++)
            if (seen[i] == &type) {
                marking_policy_identity_mix(identity, 0xfffffffffffffffeull);
                return;
            }
        seen[depth] = &type;
        marking_policy_identity_mix_type_impl(identity, *type.inner, seen, depth + 1);
    } else if (type.kind == rir::TypeKind::Struct && type.struct_def != nullptr) {
        marking_policy_identity_mix_str(identity, type.struct_def->name);
    }
}

inline void marking_policy_identity_mix_type(u64* identity, const rir::Type& type) {
    const rir::Type* seen[64]{};
    marking_policy_identity_mix_type_impl(identity, type, seen, 0);
}

inline void marking_policy_identity_mix_struct(u64* identity, const rir::StructDef& def) {
    marking_policy_identity_mix_str(identity, def.name);
    marking_policy_identity_mix(identity, def.field_count);
    for (u32 fi = 0; fi < def.field_count; fi++) {
        const auto& field = def.fields()[fi];
        marking_policy_identity_mix_str(identity, field.name);
        marking_policy_identity_mix_type(identity, *field.type);
    }
}

inline u64 marking_policy_upstream_identity(const rir::Module& mod, u32 upstream) {
    u64 identity = 0xCBF29CE484222325ull;
    if (upstream >= mod.upstream_count) {
        marking_policy_identity_mix(&identity, 0xffffffffffffffffull);
        marking_policy_identity_mix(&identity, upstream);
        return identity;
    }
    const auto& declaration = mod.upstreams[upstream];
    marking_policy_identity_mix_str(&identity, declaration.name);
    marking_policy_identity_mix(&identity, declaration.has_address ? 1 : 0);
    if (declaration.has_address) {
        marking_policy_identity_mix(&identity, declaration.extra_count + 1);
        marking_policy_identity_mix(&identity, declaration.ip);
        marking_policy_identity_mix(&identity, declaration.port);
        for (u32 backend = 0; backend < declaration.extra_count; backend++) {
            marking_policy_identity_mix(&identity, declaration.extra_ips[backend]);
            marking_policy_identity_mix(&identity, declaration.extra_ports[backend]);
        }
    }
    return identity;
}

struct MarkingPolicySourceSearch {
    u32 budget;
    u8* select_state;
    u8* select_result;
    u32 select_capacity;
    bool exhausted;
};

inline bool marking_policy_source_search_step(MarkingPolicySourceSearch* search) {
    if (search->budget == 0) {
        search->exhausted = true;
        return false;
    }
    search->budget--;
    return true;
}

inline bool marking_policy_value_flows_to_source_impl(const rir::Function& fn,
                                                      rir::ValueId value,
                                                      rir::ValueId source,
                                                      u32 depth,
                                                      MarkingPolicySourceSearch* search);

inline bool marking_policy_const_i32(const rir::Function& fn, rir::ValueId value, i32* result) {
    if (value.id >= fn.value_count) return false;
    const auto& definition = fn.values[value.id];
    u32 block_index = 0;
    if (!marking_policy_find_block(fn, definition.def_block, &block_index)) return false;
    const auto& block = fn.blocks[block_index];
    if (definition.def_inst >= block.inst_count) return false;
    const auto& inst = block.insts[definition.def_inst];
    if (inst.result != value || inst.op != rir::Opcode::ConstI32) return false;
    *result = inst.imm.i32_val;
    return true;
}

inline bool marking_policy_array_element_path_flows_to_source(const rir::Function& fn,
                                                              rir::ValueId receiver,
                                                              const bool* has_indices,
                                                              const u32* indices,
                                                              i32 index_index,
                                                              rir::ValueId source,
                                                              u32 depth,
                                                              MarkingPolicySourceSearch* search) {
    if (receiver.id >= fn.value_count || depth >= fn.value_count ||
        !marking_policy_source_search_step(search))
        return false;
    const auto& definition = fn.values[receiver.id];
    u32 block_index = 0;
    if (!marking_policy_find_block(fn, definition.def_block, &block_index)) return false;
    const auto& block = fn.blocks[block_index];
    if (definition.def_inst >= block.inst_count) return false;
    const auto& inst = block.insts[definition.def_inst];
    if (inst.result != receiver) return false;
    if (inst.op == rir::Opcode::Select && inst.operand_count == 3)
        return marking_policy_array_element_path_flows_to_source(fn,
                                                                 inst.operand(1),
                                                                 has_indices,
                                                                 indices,
                                                                 index_index,
                                                                 source,
                                                                 depth + 1,
                                                                 search) ||
               marking_policy_array_element_path_flows_to_source(fn,
                                                                 inst.operand(2),
                                                                 has_indices,
                                                                 indices,
                                                                 index_index,
                                                                 source,
                                                                 depth + 1,
                                                                 search);
    if ((inst.op == rir::Opcode::OptWrap || inst.op == rir::Opcode::OptUnwrap) &&
        inst.operand_count == 1)
        return marking_policy_array_element_path_flows_to_source(
            fn, inst.operand(0), has_indices, indices, index_index, source, depth + 1, search);
    if (inst.op == rir::Opcode::StructField && inst.operand_count == 1) {
        const rir::ValueId struct_value = inst.operand(0);
        if (struct_value.id >= fn.value_count) return false;
        const auto& struct_definition = fn.values[struct_value.id];
        u32 struct_block_index = 0;
        if (!marking_policy_find_block(fn, struct_definition.def_block, &struct_block_index))
            return false;
        const auto& struct_block = fn.blocks[struct_block_index];
        if (struct_definition.def_inst >= struct_block.inst_count) return false;
        const auto& create = struct_block.insts[struct_definition.def_inst];
        if (create.result != struct_value || create.op != rir::Opcode::StructCreate ||
            create.imm.struct_ref.type == nullptr ||
            create.imm.struct_ref.type->kind != rir::TypeKind::Struct ||
            create.imm.struct_ref.type->struct_def == nullptr)
            return false;
        const auto& def = *create.imm.struct_ref.type->struct_def;
        for (u32 fi = 0; fi < def.field_count && fi < create.operand_count; fi++)
            if (def.fields()[fi].name.eq(inst.imm.struct_ref.name))
                return marking_policy_array_element_path_flows_to_source(fn,
                                                                         create.operand(fi),
                                                                         has_indices,
                                                                         indices,
                                                                         index_index,
                                                                         source,
                                                                         depth + 1,
                                                                         search);
        return false;
    }
    if (inst.op != rir::Opcode::ArrayCreate) return false;
    const u32 begin = has_indices[index_index] ? indices[index_index] : 0;
    const u32 end = has_indices[index_index] ? begin + 1 : inst.operand_count;
    for (u32 element = begin; element < end && element < inst.operand_count; element++) {
        const bool result =
            index_index == 0
                ? marking_policy_value_flows_to_source_impl(
                      fn, inst.operand(element), source, depth + 1, search)
                : marking_policy_array_element_path_flows_to_source(fn,
                                                                    inst.operand(element),
                                                                    has_indices,
                                                                    indices,
                                                                    index_index - 1,
                                                                    source,
                                                                    depth + 1,
                                                                    search);
        if (result) return true;
    }
    return false;
}

inline bool marking_policy_array_flows_to_source(const rir::Function& fn,
                                                 rir::ValueId receiver,
                                                 rir::ValueId source,
                                                 u32 depth,
                                                 MarkingPolicySourceSearch* search) {
    if (receiver.id >= fn.value_count || depth >= fn.value_count ||
        !marking_policy_source_search_step(search))
        return false;
    const auto& definition = fn.values[receiver.id];
    u32 block_index = 0;
    if (!marking_policy_find_block(fn, definition.def_block, &block_index)) return false;
    const auto& block = fn.blocks[block_index];
    if (definition.def_inst >= block.inst_count) return false;
    const auto& inst = block.insts[definition.def_inst];
    if (inst.result != receiver) return false;
    if (inst.op == rir::Opcode::Select && inst.operand_count == 3)
        return marking_policy_array_flows_to_source(
                   fn, inst.operand(1), source, depth + 1, search) ||
               marking_policy_array_flows_to_source(fn, inst.operand(2), source, depth + 1, search);
    if ((inst.op == rir::Opcode::OptWrap || inst.op == rir::Opcode::OptUnwrap) &&
        inst.operand_count == 1)
        return marking_policy_array_flows_to_source(fn, inst.operand(0), source, depth + 1, search);
    if (inst.op == rir::Opcode::StructField && inst.operand_count == 1) {
        const rir::ValueId struct_value = inst.operand(0);
        if (struct_value.id >= fn.value_count) return false;
        const auto& struct_definition = fn.values[struct_value.id];
        u32 struct_block_index = 0;
        if (!marking_policy_find_block(fn, struct_definition.def_block, &struct_block_index))
            return false;
        const auto& struct_block = fn.blocks[struct_block_index];
        if (struct_definition.def_inst >= struct_block.inst_count) return false;
        const auto& create = struct_block.insts[struct_definition.def_inst];
        if (create.result != struct_value || create.op != rir::Opcode::StructCreate ||
            create.imm.struct_ref.type == nullptr ||
            create.imm.struct_ref.type->kind != rir::TypeKind::Struct ||
            create.imm.struct_ref.type->struct_def == nullptr)
            return false;
        const auto& def = *create.imm.struct_ref.type->struct_def;
        for (u32 fi = 0; fi < def.field_count && fi < create.operand_count; fi++)
            if (def.fields()[fi].name.eq(inst.imm.struct_ref.name))
                return marking_policy_array_flows_to_source(
                    fn, create.operand(fi), source, depth + 1, search);
        return false;
    }
    if (inst.op != rir::Opcode::ArrayCreate) return false;
    for (u32 index = 0; index < inst.operand_count; index++)
        if (marking_policy_value_flows_to_source_impl(
                fn, inst.operand(index), source, depth + 1, search))
            return true;
    return false;
}

inline bool marking_policy_array_flows_to_source(const rir::Function& fn,
                                                 rir::ValueId receiver,
                                                 rir::ValueId source,
                                                 u32 depth) {
    static constexpr u32 kMaxSourceSearchSteps = 65536;
    static constexpr u32 kMaxMemoizedValues = 4096;
    const u64 requested = static_cast<u64>(fn.value_count) * 8 + 1;
    u8 select_state[kMaxMemoizedValues]{};
    u8 select_result[kMaxMemoizedValues]{};
    MarkingPolicySourceSearch search{
        requested < kMaxSourceSearchSteps ? static_cast<u32>(requested) : kMaxSourceSearchSteps,
        select_state,
        select_result,
        fn.value_count < kMaxMemoizedValues ? fn.value_count : kMaxMemoizedValues,
        false};
    const bool result = marking_policy_array_flows_to_source(fn, receiver, source, depth, &search);
    return result || search.exhausted;
}

inline bool marking_policy_struct_field_flows_to_source(const rir::Function& fn,
                                                        rir::ValueId receiver,
                                                        Str field_name,
                                                        rir::ValueId source,
                                                        u32 depth,
                                                        MarkingPolicySourceSearch* search);

inline bool marking_policy_array_struct_field_path_flows_to_source(
    const rir::Function& fn,
    rir::ValueId receiver,
    const bool* has_indices,
    const u32* indices,
    i32 index_index,
    const Str* fields,
    i32 field_index,
    rir::ValueId source,
    u32 depth,
    MarkingPolicySourceSearch* search);

inline bool marking_policy_struct_field_path_flows_to_source(const rir::Function& fn,
                                                             rir::ValueId receiver,
                                                             const Str* fields,
                                                             i32 field_index,
                                                             rir::ValueId source,
                                                             u32 depth,
                                                             MarkingPolicySourceSearch* search) {
    if (field_index < 0)
        return marking_policy_value_flows_to_source_impl(fn, receiver, source, depth + 1, search);
    if (receiver.id >= fn.value_count || depth >= fn.value_count ||
        !marking_policy_source_search_step(search))
        return false;
    const auto& definition = fn.values[receiver.id];
    u32 block_index = 0;
    if (!marking_policy_find_block(fn, definition.def_block, &block_index)) return false;
    const auto& block = fn.blocks[block_index];
    if (definition.def_inst >= block.inst_count) return false;
    const auto& inst = block.insts[definition.def_inst];
    if (inst.result != receiver) return false;
    if (inst.op == rir::Opcode::Select && inst.operand_count == 3)
        return marking_policy_struct_field_path_flows_to_source(
                   fn, inst.operand(1), fields, field_index, source, depth + 1, search) ||
               marking_policy_struct_field_path_flows_to_source(
                   fn, inst.operand(2), fields, field_index, source, depth + 1, search);
    if ((inst.op == rir::Opcode::OptWrap || inst.op == rir::Opcode::OptUnwrap) &&
        inst.operand_count == 1)
        return marking_policy_struct_field_path_flows_to_source(
            fn, inst.operand(0), fields, field_index, source, depth + 1, search);
    if (inst.op == rir::Opcode::ArrayGet && inst.operand_count == 2) {
        static constexpr u32 kMaxArrayPath = 64;
        bool has_indices[kMaxArrayPath];
        u32 indices[kMaxArrayPath];
        u32 index_count = 0;
        rir::ValueId array_receiver = receiver;
        while (index_count < kMaxArrayPath) {
            if (array_receiver.id >= fn.value_count) return false;
            const auto& array_definition = fn.values[array_receiver.id];
            u32 array_block_index = 0;
            if (!marking_policy_find_block(fn, array_definition.def_block, &array_block_index))
                break;
            const auto& array_block = fn.blocks[array_block_index];
            if (array_definition.def_inst >= array_block.inst_count) break;
            const auto& array_inst = array_block.insts[array_definition.def_inst];
            if (array_inst.result != array_receiver || array_inst.op != rir::Opcode::ArrayGet ||
                array_inst.operand_count != 2)
                break;
            i32 index = -1;
            has_indices[index_count] =
                marking_policy_const_i32(fn, array_inst.operand(1), &index) && index >= 0;
            indices[index_count++] = static_cast<u32>(index);
            array_receiver = array_inst.operand(0);
        }
        if (index_count == kMaxArrayPath) {
            search->exhausted = true;
            return false;
        }
        return marking_policy_array_struct_field_path_flows_to_source(
            fn,
            array_receiver,
            has_indices,
            indices,
            static_cast<i32>(index_count) - 1,
            fields,
            field_index,
            source,
            depth + 1,
            search);
    }
    if (inst.op != rir::Opcode::StructCreate || inst.imm.struct_ref.type == nullptr ||
        inst.imm.struct_ref.type->kind != rir::TypeKind::Struct ||
        inst.imm.struct_ref.type->struct_def == nullptr)
        return false;
    const auto& def = *inst.imm.struct_ref.type->struct_def;
    for (u32 field = 0; field < def.field_count && field < inst.operand_count; field++)
        if (def.fields()[field].name.eq(fields[field_index]))
            return marking_policy_struct_field_path_flows_to_source(
                fn, inst.operand(field), fields, field_index - 1, source, depth + 1, search);
    return false;
}

inline bool marking_policy_array_struct_field_path_flows_to_source(
    const rir::Function& fn,
    rir::ValueId receiver,
    const bool* has_indices,
    const u32* indices,
    i32 index_index,
    const Str* fields,
    i32 field_index,
    rir::ValueId source,
    u32 depth,
    MarkingPolicySourceSearch* search) {
    if (receiver.id >= fn.value_count || depth >= fn.value_count ||
        !marking_policy_source_search_step(search))
        return false;
    const auto& definition = fn.values[receiver.id];
    u32 block_index = 0;
    if (!marking_policy_find_block(fn, definition.def_block, &block_index)) return false;
    const auto& block = fn.blocks[block_index];
    if (definition.def_inst >= block.inst_count) return false;
    const auto& inst = block.insts[definition.def_inst];
    if (inst.result != receiver) return false;
    if (inst.op == rir::Opcode::Select && inst.operand_count == 3)
        return marking_policy_array_struct_field_path_flows_to_source(fn,
                                                                      inst.operand(1),
                                                                      has_indices,
                                                                      indices,
                                                                      index_index,
                                                                      fields,
                                                                      field_index,
                                                                      source,
                                                                      depth + 1,
                                                                      search) ||
               marking_policy_array_struct_field_path_flows_to_source(fn,
                                                                      inst.operand(2),
                                                                      has_indices,
                                                                      indices,
                                                                      index_index,
                                                                      fields,
                                                                      field_index,
                                                                      source,
                                                                      depth + 1,
                                                                      search);
    if ((inst.op == rir::Opcode::OptWrap || inst.op == rir::Opcode::OptUnwrap) &&
        inst.operand_count == 1)
        return marking_policy_array_struct_field_path_flows_to_source(fn,
                                                                      inst.operand(0),
                                                                      has_indices,
                                                                      indices,
                                                                      index_index,
                                                                      fields,
                                                                      field_index,
                                                                      source,
                                                                      depth + 1,
                                                                      search);
    if (inst.op != rir::Opcode::ArrayCreate) return false;
    const u32 begin = has_indices[index_index] ? indices[index_index] : 0;
    const u32 end = has_indices[index_index] ? begin + 1 : inst.operand_count;
    for (u32 element = begin; element < end && element < inst.operand_count; element++) {
        const bool result =
            index_index == 0
                ? marking_policy_struct_field_path_flows_to_source(
                      fn, inst.operand(element), fields, field_index, source, depth + 1, search)
                : marking_policy_array_struct_field_path_flows_to_source(fn,
                                                                         inst.operand(element),
                                                                         has_indices,
                                                                         indices,
                                                                         index_index - 1,
                                                                         fields,
                                                                         field_index,
                                                                         source,
                                                                         depth + 1,
                                                                         search);
        if (result) return true;
    }
    return false;
}

inline bool marking_policy_array_struct_field_flows_to_source(const rir::Function& fn,
                                                              rir::ValueId receiver,
                                                              bool has_index,
                                                              u32 index,
                                                              Str field_name,
                                                              rir::ValueId source,
                                                              u32 depth,
                                                              MarkingPolicySourceSearch* search) {
    if (receiver.id >= fn.value_count || depth >= fn.value_count ||
        !marking_policy_source_search_step(search))
        return false;
    const auto& definition = fn.values[receiver.id];
    u32 block_index = 0;
    if (!marking_policy_find_block(fn, definition.def_block, &block_index)) return false;
    const auto& block = fn.blocks[block_index];
    if (definition.def_inst >= block.inst_count) return false;
    const auto& inst = block.insts[definition.def_inst];
    if (inst.result != receiver) return false;
    if (inst.op == rir::Opcode::Select && inst.operand_count == 3)
        return marking_policy_array_struct_field_flows_to_source(
                   fn, inst.operand(1), has_index, index, field_name, source, depth + 1, search) ||
               marking_policy_array_struct_field_flows_to_source(
                   fn, inst.operand(2), has_index, index, field_name, source, depth + 1, search);
    if ((inst.op == rir::Opcode::OptWrap || inst.op == rir::Opcode::OptUnwrap) &&
        inst.operand_count == 1)
        return marking_policy_array_struct_field_flows_to_source(
            fn, inst.operand(0), has_index, index, field_name, source, depth + 1, search);
    if (inst.op != rir::Opcode::ArrayCreate) return false;
    if (has_index)
        return index < inst.operand_count &&
               marking_policy_struct_field_flows_to_source(
                   fn, inst.operand(index), field_name, source, depth + 1, search);
    for (u32 element = 0; element < inst.operand_count; element++)
        if (marking_policy_struct_field_flows_to_source(
                fn, inst.operand(element), field_name, source, depth + 1, search))
            return true;
    return false;
}

inline bool marking_policy_struct_field_flows_to_source(const rir::Function& fn,
                                                        rir::ValueId receiver,
                                                        Str field_name,
                                                        rir::ValueId source,
                                                        u32 depth,
                                                        MarkingPolicySourceSearch* search) {
    if (receiver.id >= fn.value_count || depth >= fn.value_count ||
        !marking_policy_source_search_step(search))
        return false;
    const auto& definition = fn.values[receiver.id];
    u32 block_index = 0;
    if (!marking_policy_find_block(fn, definition.def_block, &block_index)) return false;
    const auto& block = fn.blocks[block_index];
    if (definition.def_inst >= block.inst_count) return false;
    const auto& inst = block.insts[definition.def_inst];
    if (inst.result != receiver) return false;
    if (inst.op == rir::Opcode::Select && inst.operand_count == 3)
        return marking_policy_struct_field_flows_to_source(
                   fn, inst.operand(1), field_name, source, depth + 1, search) ||
               marking_policy_struct_field_flows_to_source(
                   fn, inst.operand(2), field_name, source, depth + 1, search);
    if ((inst.op == rir::Opcode::OptWrap || inst.op == rir::Opcode::OptUnwrap) &&
        inst.operand_count == 1)
        return marking_policy_struct_field_flows_to_source(
            fn, inst.operand(0), field_name, source, depth + 1, search);
    if (inst.op == rir::Opcode::ArrayGet && inst.operand_count == 2) {
        i32 index = -1;
        const bool has_index = marking_policy_const_i32(fn, inst.operand(1), &index) && index >= 0;
        return marking_policy_array_struct_field_flows_to_source(fn,
                                                                 inst.operand(0),
                                                                 has_index,
                                                                 static_cast<u32>(index),
                                                                 field_name,
                                                                 source,
                                                                 depth + 1,
                                                                 search);
    }
    if (inst.op != rir::Opcode::StructCreate || inst.imm.struct_ref.type == nullptr ||
        inst.imm.struct_ref.type->kind != rir::TypeKind::Struct ||
        inst.imm.struct_ref.type->struct_def == nullptr)
        return false;
    const auto& def = *inst.imm.struct_ref.type->struct_def;
    for (u32 fi = 0; fi < def.field_count && fi < inst.operand_count; fi++)
        if (def.fields()[fi].name.eq(field_name))
            return marking_policy_value_flows_to_source_impl(
                fn, inst.operand(fi), source, depth + 1, search);
    return false;
}

inline bool marking_policy_value_flows_to_source_impl(const rir::Function& fn,
                                                      rir::ValueId value,
                                                      rir::ValueId source,
                                                      u32 depth,
                                                      MarkingPolicySourceSearch* search) {
    if (value == source) return true;
    if (value.id >= fn.value_count || depth >= fn.value_count ||
        !marking_policy_source_search_step(search))
        return false;
    const auto& definition = fn.values[value.id];
    u32 block_index = 0;
    if (!marking_policy_find_block(fn, definition.def_block, &block_index)) return false;
    const auto& block = fn.blocks[block_index];
    if (definition.def_inst >= block.inst_count) return false;
    const auto& inst = block.insts[definition.def_inst];
    if (inst.result != value) return false;
    if (inst.op == rir::Opcode::Select && inst.operand_count == 3) {
        if (value.id < search->select_capacity && search->select_state[value.id] == 2)
            return search->select_result[value.id] != 0;
        if (value.id < search->select_capacity && search->select_state[value.id] == 1) return false;
        if (value.id < search->select_capacity) search->select_state[value.id] = 1;
        const bool result = marking_policy_value_flows_to_source_impl(
                                fn, inst.operand(1), source, depth + 1, search) ||
                            marking_policy_value_flows_to_source_impl(
                                fn, inst.operand(2), source, depth + 1, search);
        if (value.id < search->select_capacity) {
            search->select_result[value.id] = result ? 1 : 0;
            search->select_state[value.id] = 2;
        }
        return result;
    }
    if (inst.op == rir::Opcode::StructField && inst.operand_count == 1) {
        static constexpr u32 kMaxFieldPath = 64;
        Str fields[kMaxFieldPath];
        u32 field_count = 0;
        rir::ValueId receiver = value;
        while (field_count < kMaxFieldPath) {
            if (receiver.id >= fn.value_count) return false;
            const auto& field_definition = fn.values[receiver.id];
            u32 field_block_index = 0;
            if (!marking_policy_find_block(fn, field_definition.def_block, &field_block_index))
                break;
            const auto& field_block = fn.blocks[field_block_index];
            if (field_definition.def_inst >= field_block.inst_count) break;
            const auto& field_inst = field_block.insts[field_definition.def_inst];
            if (field_inst.result != receiver || field_inst.op != rir::Opcode::StructField ||
                field_inst.operand_count != 1)
                break;
            fields[field_count++] = field_inst.imm.struct_ref.name;
            receiver = field_inst.operand(0);
        }
        if (field_count == kMaxFieldPath) {
            search->exhausted = true;
            return false;
        }
        if (field_count == 1)
            return marking_policy_struct_field_flows_to_source(
                fn, receiver, fields[0], source, depth + 1, search);
        return marking_policy_struct_field_path_flows_to_source(
            fn, receiver, fields, static_cast<i32>(field_count) - 1, source, depth + 1, search);
    }
    if (inst.op == rir::Opcode::ArrayGet && inst.operand_count == 2) {
        static constexpr u32 kMaxArrayPath = 64;
        bool has_indices[kMaxArrayPath];
        u32 indices[kMaxArrayPath];
        u32 index_count = 0;
        rir::ValueId receiver = value;
        while (index_count < kMaxArrayPath) {
            if (receiver.id >= fn.value_count) return false;
            const auto& array_definition = fn.values[receiver.id];
            u32 array_block_index = 0;
            if (!marking_policy_find_block(fn, array_definition.def_block, &array_block_index))
                break;
            const auto& array_block = fn.blocks[array_block_index];
            if (array_definition.def_inst >= array_block.inst_count) break;
            const auto& array_inst = array_block.insts[array_definition.def_inst];
            if (array_inst.result != receiver || array_inst.op != rir::Opcode::ArrayGet ||
                array_inst.operand_count != 2)
                break;
            i32 index = -1;
            has_indices[index_count] =
                marking_policy_const_i32(fn, array_inst.operand(1), &index) && index >= 0;
            indices[index_count++] = static_cast<u32>(index);
            receiver = array_inst.operand(0);
        }
        if (index_count == kMaxArrayPath) {
            search->exhausted = true;
            return false;
        }
        return marking_policy_array_element_path_flows_to_source(fn,
                                                                 receiver,
                                                                 has_indices,
                                                                 indices,
                                                                 static_cast<i32>(index_count) - 1,
                                                                 source,
                                                                 depth + 1,
                                                                 search);
    }
    if ((inst.op == rir::Opcode::OptWrap || inst.op == rir::Opcode::OptUnwrap) &&
        inst.operand_count == 1)
        return marking_policy_value_flows_to_source_impl(
            fn, inst.operand(0), source, depth + 1, search);
    return false;
}

inline bool marking_policy_value_flows_to_source_with_budget(
    const rir::Function& fn, rir::ValueId value, rir::ValueId source, u32 budget, bool* exhausted) {
    static constexpr u32 kMaxMemoizedValues = 4096;
    u8 select_state[kMaxMemoizedValues]{};
    u8 select_result[kMaxMemoizedValues]{};
    MarkingPolicySourceSearch search{
        budget,
        select_state,
        select_result,
        fn.value_count < kMaxMemoizedValues ? fn.value_count : kMaxMemoizedValues,
        false};
    const bool result = marking_policy_value_flows_to_source_impl(fn, value, source, 0, &search);
    if (exhausted != nullptr) *exhausted = search.exhausted;
    return result;
}

inline u32 marking_policy_source_search_budget(const rir::Function& fn) {
    static constexpr u32 kMaxSourceSearchSteps = 65536;
    const u64 requested = static_cast<u64>(fn.value_count) * 8 + 1;
    return requested < kMaxSourceSearchSteps ? static_cast<u32>(requested) : kMaxSourceSearchSteps;
}

inline bool marking_policy_value_flows_to_source(const rir::Function& fn,
                                                 rir::ValueId value,
                                                 rir::ValueId source) {
    bool exhausted = false;
    const bool result = marking_policy_value_flows_to_source_with_budget(
        fn, value, source, marking_policy_source_search_budget(fn), &exhausted);
    return result || exhausted;
}

inline bool marking_policy_value_proven_to_flow_to_source(const rir::Function& fn,
                                                          rir::ValueId value,
                                                          rir::ValueId source) {
    return marking_policy_value_flows_to_source_with_budget(
        fn, value, source, marking_policy_source_search_budget(fn), nullptr);
}

inline bool marking_policy_value_is_mark_server(const rir::Function& fn, rir::ValueId value) {
    for (u32 bi = 0; bi < fn.block_count; bi++) {
        const auto& block = fn.blocks[bi];
        for (u32 ii = 0; ii < block.inst_count; ii++) {
            const auto& inst = block.insts[ii];
            if (inst.op == rir::Opcode::UpstreamMark && inst.operand_count == 2 &&
                marking_policy_value_proven_to_flow_to_source(fn, inst.operand(0), value))
                return true;
        }
    }
    return false;
}

// Fingerprint the compiled timer rather than only its name/period. This keeps
// unchanged marking policy stable across reloads while clearing manual
// overrides if the timer body or its scheduling policy changes.
inline u64 marking_policy_identity(const rir::Module& mod, const rir::Function& fn) {
    u64 identity = 0xCBF29CE484222325ull;
    marking_policy_identity_mix_str(&identity, fn.route_pattern);
    marking_policy_identity_mix(&identity, fn.timer_interval_ms);
    marking_policy_identity_mix(&identity, static_cast<u32>(fn.timer_shard));
    u64 marked_upstreams[32]{};
    u32 marked_count = 0;
    for (u32 upstream = 0; upstream < mod.upstream_count && upstream < 32; upstream++) {
        if ((fn.upstream_mark_mask & (u32{1} << upstream)) == 0) continue;
        const u64 upstream_identity = marking_policy_upstream_identity(mod, upstream);
        u32 insertion = marked_count;
        while (insertion != 0 && marked_upstreams[insertion - 1] > upstream_identity) {
            marked_upstreams[insertion] = marked_upstreams[insertion - 1];
            insertion--;
        }
        marked_upstreams[insertion] = upstream_identity;
        marked_count++;
    }
    marking_policy_identity_mix(&identity, marked_count);
    for (u32 upstream = 0; upstream < marked_count; upstream++)
        marking_policy_identity_mix(&identity, marked_upstreams[upstream]);
    for (u32 bi = 0; bi < fn.block_count; bi++) {
        const auto& block = fn.blocks[bi];
        marking_policy_identity_mix(&identity, block.id.id);
        for (u32 ii = 0; ii < block.inst_count; ii++) {
            const auto& inst = block.insts[ii];
            marking_policy_identity_mix(&identity, static_cast<u32>(inst.op));
            marking_policy_identity_mix(&identity, inst.result.id);
            marking_policy_identity_mix(&identity, inst.operand_count);
            for (u32 oi = 0; oi < inst.operand_count; oi++)
                marking_policy_identity_mix(&identity, inst.operand(oi).id);

            const auto op = inst.op;
            if (op == rir::Opcode::ConstStr || op == rir::Opcode::ReqHeader ||
                op == rir::Opcode::ReqParam || op == rir::Opcode::ReqQuery ||
                op == rir::Opcode::ReqQueryAll || op == rir::Opcode::ReqHeaderAll ||
                op == rir::Opcode::ReqCookie || op == rir::Opcode::ReqSetHeader ||
                op == rir::Opcode::ReqAddHeader || op == rir::Opcode::RespHeader ||
                op == rir::Opcode::RespSetHeader || op == rir::Opcode::RespAddHeader ||
                op == rir::Opcode::RespRemoveHeader || op == rir::Opcode::StrRegexMatch ||
                op == rir::Opcode::IpInCidr || op == rir::Opcode::JsonAppendRaw ||
                op == rir::Opcode::YieldHttpGet || op == rir::Opcode::YieldHttpPost) {
                marking_policy_identity_mix_str(&identity, inst.imm.str_val);
            } else if (op == rir::Opcode::ConstI32 || op == rir::Opcode::ConstStatus ||
                       op == rir::Opcode::CtxLoadSlotI32 || op == rir::Opcode::CtxStoreSlotI32 ||
                       op == rir::Opcode::JsonAppendControlPlane) {
                marking_policy_identity_mix(&identity, static_cast<u32>(inst.imm.i32_val));
            } else if (op == rir::Opcode::CacheGet || op == rir::Opcode::CacheSet) {
                const u32 cache_index = static_cast<u32>(inst.imm.i32_val);
                if (cache_index < mod.cache_instance_count) {
                    const auto& cache = mod.cache_instances[cache_index];
                    marking_policy_identity_mix_str(&identity, cache.name);
                    marking_policy_identity_mix(&identity, cache.capacity);
                } else {
                    marking_policy_identity_mix(&identity, 0xffffffffffffffffull);
                    marking_policy_identity_mix(&identity, cache_index);
                }
            } else if (op == rir::Opcode::UpstreamMark) {
                const u32 upstream = static_cast<u32>(inst.imm.i32_val);
                marking_policy_identity_mix(&identity,
                                            marking_policy_upstream_identity(mod, upstream));
            } else if (op == rir::Opcode::RetStatus && inst.operand_count == 0) {
                const u64 immediate = static_cast<u64>(inst.imm.i64_val);
                const u32 status = static_cast<u32>(immediate & 0xffffu);
                const u32 body_index = static_cast<u32>((immediate >> 16) & 0xffffu);
                const u32 header_set_index = static_cast<u32>((immediate >> 32) & 0xffffu);
                marking_policy_identity_mix(&identity, status);
                marking_policy_identity_mix(&identity, body_index == 0 ? 0 : 1);
                if (body_index != 0) {
                    if (body_index <= mod.response_body_count) {
                        marking_policy_identity_mix_str(&identity,
                                                        mod.response_bodies[body_index - 1]);
                    } else {
                        marking_policy_identity_mix(&identity, 0xffffffffffffffffull);
                        marking_policy_identity_mix(&identity, body_index);
                    }
                }
                marking_policy_identity_mix(&identity, header_set_index == 0 ? 0 : 1);
                if (header_set_index != 0) {
                    if (header_set_index <= mod.header_set_count) {
                        const auto& header_set = mod.header_sets[header_set_index - 1];
                        marking_policy_identity_mix(&identity, header_set.count);
                        for (u32 header = 0; header < header_set.count; header++) {
                            const u32 pool_index = header_set.offset + header;
                            if (pool_index >= mod.header_pool_used) {
                                marking_policy_identity_mix(&identity, 0xfffffffffffffffeull);
                                marking_policy_identity_mix(&identity, pool_index);
                                continue;
                            }
                            marking_policy_identity_mix_str(&identity, mod.header_keys[pool_index]);
                            marking_policy_identity_mix_str(&identity,
                                                            mod.header_values[pool_index]);
                        }
                    } else {
                        marking_policy_identity_mix(&identity, 0xffffffffffffffffull);
                        marking_policy_identity_mix(&identity, header_set_index);
                    }
                }
            } else if (op == rir::Opcode::ConstI64 || op == rir::Opcode::ConstDuration ||
                       op == rir::Opcode::ConstByteSize || op == rir::Opcode::YieldTimer) {
                const u64 immediate = static_cast<u64>(inst.imm.i64_val);
                if (op == rir::Opcode::ConstI64 && inst.result != rir::kNoValue &&
                    marking_policy_value_is_mark_server(fn, inst.result)) {
                    if (immediate == 0) {
                        marking_policy_identity_mix(&identity, 0xffffffffffffffffull);
                    } else {
                        const u64 decoded = immediate - 1;
                        if (decoded > 0xffffffffu) {
                            marking_policy_identity_mix(&identity, 0xfffffffffffffffeull);
                            marking_policy_identity_mix(&identity, immediate);
                            continue;
                        }
                        const u32 upstream = static_cast<u32>((decoded >> 16) & 0xffffu);
                        const u32 backend = static_cast<u32>(decoded & 0xffffu);
                        marking_policy_identity_mix(
                            &identity, marking_policy_upstream_identity(mod, upstream));
                        marking_policy_identity_mix(&identity, backend);
                    }
                } else {
                    marking_policy_identity_mix(&identity, immediate);
                }
            } else if (op == rir::Opcode::ConstBool) {
                marking_policy_identity_mix(&identity, inst.imm.bool_val ? 1 : 0);
            } else if (op == rir::Opcode::ConstMethod) {
                marking_policy_identity_mix(&identity, inst.imm.method_val);
            } else if (op == rir::Opcode::Br) {
                marking_policy_identity_mix(&identity, inst.imm.block_targets[0].id);
                marking_policy_identity_mix(&identity, inst.imm.block_targets[1].id);
            } else if (op == rir::Opcode::Jmp) {
                marking_policy_identity_mix(&identity, inst.imm.block_targets[0].id);
            } else if (op == rir::Opcode::StructCreate) {
                marking_policy_identity_mix_struct(&identity,
                                                   *inst.imm.struct_ref.type->struct_def);
            } else if (op == rir::Opcode::StructField) {
                marking_policy_identity_mix_str(&identity, inst.imm.struct_ref.name);
            }
        }
    }
    return identity == 0 ? 1 : identity;
}

inline bool populate_route_config(RouteConfig& cfg, const rir::Module& mod) {
    // Bodies / header sets / routes must always start empty — there's
    // no "merge" semantics for those tables, and a non-zero count
    // would break the compile-time body_idx / headers_idx invariants.
    if (cfg.route_count != 0 || cfg.response_body_count != 0 ||
        cfg.response_header_set_count != 0) {
        return false;
    }

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
    for (u32 i = 0; i < mod.upstream_count; i++)
        if (mod.upstreams[i].extra_count > rir::Module::Upstream::kMaxExtraBackends) return false;
    if (mod.cache_instance_count > rir::Module::kMaxCacheInstances ||
        mod.cache_instance_count > RouteConfig::kMaxCacheInstances)
        return false;
    if (mod.func_count > mod.func_cap) return false;
    if (mod.func_count != 0 && mod.functions == nullptr) return false;
    if (mod.response_body_count > rir::Module::kMaxResponseBodies) return false;
    if (mod.header_set_count > rir::Module::kMaxHeaderSets) return false;
    if (mod.header_pool_used > rir::Module::kMaxHeaderPoolEntries) return false;
    for (u32 i = 0; i < mod.header_set_count; i++) {
        const auto& ref = mod.header_sets[i];
        if (static_cast<u32>(ref.offset) + ref.count > mod.header_pool_used) return false;
        if (ref.count > RouteConfig::kMaxHeadersPerSet) return false;
    }
    if (!marking_policies_valid_for_codegen(mod)) return false;
    u32 marked_upstream_mask = 0;
    for (u32 fi = 0; fi < mod.func_count; fi++)
        marked_upstream_mask |= mod.functions[fi].upstream_mark_mask;

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
            cfg.upstreams[i].name_identity = upstream_name_identity(up.name.ptr, up.name.len);
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
            // A declaration with concrete endpoints defines the Server token
            // order. A pre-bound runtime view must match it exactly or the
            // numeric backend identity could name another endpoint.
            if (up.has_address && (marked_upstream_mask & (u32{1} << i)) != 0) {
                const auto& target = cfg.upstreams[i];
                if (target.addr_count != up.extra_count + 1) return false;
                if (target.addrs[0].sin_addr.s_addr != htonl(up.ip) ||
                    target.addrs[0].sin_port != htons(up.port))
                    return false;
                for (u32 b = 0; b < up.extra_count; b++) {
                    if (target.addrs[b + 1].sin_addr.s_addr != htonl(up.extra_ips[b]) ||
                        target.addrs[b + 1].sin_port != htons(up.extra_ports[b]))
                        return false;
                }
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

    for (u32 fi = 0; fi < mod.func_count; fi++) {
        const auto& fn = mod.functions[fi];
        u32 emitted_mask = 0;
        bool request_dependent = false;
        bool suspends = false;
        if (!marking_policy_emitted_mask(
                mod, fn, mod.upstream_count, &emitted_mask, &request_dependent, &suspends))
            return false;
        if (!fn.is_timer) {
            if (emitted_mask != 0 || fn.upstream_mark_mask != 0) return false;
            continue;
        }
        if (fn.upstream_mark_mask != emitted_mask) return false;
        if (emitted_mask == 0) continue;
        // A mark changes replay-visible control-plane state. Keep compiler
        // output unavailable at activation until lowering also emits the
        // ordered attempt/result/version events required by the replay
        // contract. Focused hand-built IR tests opt in explicitly below.
        if (!mod.upstream_mark_replay_complete) return false;
        if (request_dependent || suspends || fn.yield_count != 0) return false;
        if (fn.timer_shard < 0) return false;
        const u64 policy_identity = marking_policy_identity(mod, fn);
        for (u32 upstream = 0; upstream < mod.upstream_count && upstream < 32; upstream++) {
            if ((fn.upstream_mark_mask & (u32{1} << upstream)) == 0) continue;
            if (cfg.upstreams[upstream].marking_policy_identity != 0) return false;
            cfg.upstreams[upstream].marking_policy_identity = policy_identity;
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
    return true;
}

}  // namespace rut
