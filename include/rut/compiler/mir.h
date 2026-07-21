#pragma once

#include "rut/common/rate_limit_key_spec.h"
#include "rut/common/types.h"
#include "rut/common/wait_limits.h"
#include "rut/compiler/ast.h"
#include "rut/compiler/diagnostic.h"

namespace rut {

inline constexpr u32 kMaxMirTupleSlots = 10;

enum class MirTerminatorKind : u8 {
    Branch,
    ReturnStatus,
    ForwardUpstream,
    YieldTimer,
};

enum class MirValueKind : u8 {
    BoolConst,
    IntConst,
    StrConst,
    ArrayLit,
    RegexMatch,
    Tuple,
    TupleSlot,
    VariantCase,
    IfElse,
    StructInit,
    Field,
    ReqHeader,
    ReqSetHeader,
    ReqAddHeader,
    RespHeader,
    RespStatus,
    RespBody,
    RespSetHeader,
    RespAddHeader,
    RespRemoveHeader,
    RespSetStatus,
    RespSetBody,
    ReqParam,
    ReqCookie,
    ReqQuery,
    ReqQueryAll,
    ReqHeaderAll,
    ReqQueryString,
    StrListLen,
    StrListIsEmpty,
    StrListGet,
    ReqPath,
    ReqPathOnly,
    ReqBody,
    ReqKeepAlive,
    ReqChunked,
    ReqHasContentLength,
    ReqHttp10,
    ReqHttp11,
    ReqHttpVersion,
    ReqContentLength,
    ReqRemoteAddr,
    // HTTP method literal — int_value holds the HttpMethod enum value.
    ConstMethod,
    // Read of the parsed request method from the current connection.
    ReqMethod,
    Nil,
    Error,
    LocalRef,
    Eq,
    Lt,
    Gt,
    BitAnd,
    BitOr,
    BitXor,
    BitShl,
    BitShr,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    WidenI64,
    TimeNowMicros,
    MaxInt,
    MinInt,
    Or,
    NoError,
    HasValue,
    ValueOf,
    MissingOf,
    MatchPayload,
    VariantTag,
    WaitResult,
    WaitField,
    CacheGet,
    CacheSet,
    JsonBuild,
};

enum class MirTypeKind : u8 {
    Unknown,
    Bool,
    I32,
    I64,
    Str,
    Variant,
    Tuple,
    Struct,
    Method,
    ByteSize,
    IP,
    StrList,
    Array,
    Json,
};

struct MirTypeShape {
    MirTypeKind type = MirTypeKind::Unknown;
    bool is_concrete = false;
    bool carrier_ready = false;
    u32 generic_index = 0xffffffffu;
    u32 variant_index = 0xffffffffu;
    u32 struct_index = 0xffffffffu;
    u32 tuple_len = 0;
    u32 tuple_elem_shape_indices[kMaxMirTupleSlots]{};
    u32 array_elem_shape_index = 0xffffffffu;
};

struct MirVariant {
    static constexpr u32 kMaxTypeParams = 4;
    struct CaseDecl {
        Str name{};
        MirTypeKind payload_type = MirTypeKind::Unknown;
        bool has_payload = false;
        u32 payload_shape_index = 0xffffffffu;
        u32 payload_variant_index = 0xffffffffu;
        u32 payload_struct_index = 0xffffffffu;
        u32 payload_tuple_len = 0;
        MirTypeKind payload_tuple_types[kMaxMirTupleSlots]{};
        u32 payload_tuple_variant_indices[kMaxMirTupleSlots]{};
        u32 payload_tuple_struct_indices[kMaxMirTupleSlots]{};
    };

    Span span{};
    Str name{};
    FixedVec<Str, kMaxTypeParams> type_params;
    u32 template_variant_index = 0xffffffffu;
    u32 instance_type_arg_count = 0;
    MirTypeKind instance_type_args[kMaxTypeParams]{};
    u32 instance_generic_indices[kMaxTypeParams]{};
    u32 instance_shape_indices[kMaxTypeParams]{};
    static constexpr u32 kMaxCases = 16;
    FixedVec<CaseDecl, kMaxCases> cases;
};

struct MirStruct {
    static constexpr u32 kMaxTypeParams = 4;
    struct FieldDecl {
        Str name{};
        Str type_name{};
        MirTypeKind type = MirTypeKind::Unknown;
        u32 shape_index = 0xffffffffu;
        bool is_error_type = false;
        u32 variant_index = 0xffffffffu;
        u32 struct_index = 0xffffffffu;
        u32 tuple_len = 0;
        MirTypeKind tuple_types[kMaxMirTupleSlots]{};
        u32 tuple_variant_indices[kMaxMirTupleSlots]{};
        u32 tuple_struct_indices[kMaxMirTupleSlots]{};
    };

    Span span{};
    Str name{};
    bool conforms_error = false;
    FixedVec<Str, kMaxTypeParams> type_params;
    u32 template_struct_index = 0xffffffffu;
    u32 instance_type_arg_count = 0;
    MirTypeKind instance_type_args[kMaxTypeParams]{};
    u32 instance_generic_indices[kMaxTypeParams]{};
    u32 instance_shape_indices[kMaxTypeParams]{};
    static constexpr u32 kMaxFields = 8;
    FixedVec<FieldDecl, kMaxFields> fields;
};

struct MirValue {
    struct FieldInit {
        Str name{};
        MirValue* value = nullptr;
    };

    MirValueKind kind = MirValueKind::BoolConst;
    MirTypeKind type = MirTypeKind::Unknown;
    u32 shape_index = 0xffffffffu;
    bool may_nil = false;
    bool may_error = false;
    bool bool_value = false;
    i64 int_value = 0;
    Str str_value{};
    Str msg{};
    u32 local_index = 0;
    u32 variant_index = 0;
    u32 struct_index = 0xffffffffu;
    u32 case_index = 0;
    u32 tuple_len = 0;
    MirTypeKind tuple_types[kMaxMirTupleSlots]{};
    u32 tuple_variant_indices[kMaxMirTupleSlots]{};
    u32 tuple_struct_indices[kMaxMirTupleSlots]{};
    u32 error_struct_index = 0xffffffffu;
    u32 error_variant_index = 0xffffffffu;
    u32 error_case_index = 0xffffffffu;
    // CacheGet/CacheSet: index into MirModule::caches.
    u32 cache_index = 0xffffffffu;
    MirValue* lhs = nullptr;
    MirValue* rhs = nullptr;
    bool is_pipe_conditional = false;
    bool is_eager_fallback = false;
    bool is_wait_result = false;
    WaitEventKind wait_event_kind = WaitEventKind::Timer;
    u32 wait_payload = 0;
    u8 wait_arm_mask = kWaitEventArmTimer;
    u32 wait_index = 0xffffffffu;
    static constexpr u32 kMaxFieldInits = 8;
    static constexpr u32 kMaxArgs = 8;
    FixedVec<FieldInit, kMaxFieldInits> field_inits;
    FixedVec<MirValue*, kMaxArgs> args;
};

struct MirLocal {
    Span span{};
    Str name{};
    u32 ref_index = 0;
    MirTypeKind type = MirTypeKind::Bool;
    u32 shape_index = 0xffffffffu;
    bool may_nil = false;
    bool may_error = false;
    u32 variant_index = 0;
    u32 struct_index = 0xffffffffu;
    u32 tuple_len = 0;
    MirTypeKind tuple_types[kMaxMirTupleSlots]{};
    u32 tuple_variant_indices[kMaxMirTupleSlots]{};
    u32 tuple_struct_indices[kMaxMirTupleSlots]{};
    u32 error_struct_index = 0xffffffffu;
    u32 error_variant_index = 0xffffffffu;
    bool is_wait_result = false;
    WaitEventKind wait_event_kind = WaitEventKind::Timer;
    u32 wait_payload = 0;
    u8 wait_arm_mask = kWaitEventArmTimer;
    u32 wait_index = 0xffffffffu;
    MirValue init{};
};

enum class MirTerminatorSourceKind : u8 {
    Literal,
    LocalRef,
};

struct MirHeaderKV {
    Str key{};
    Str value{};
};

struct MirTerminator {
    static constexpr u32 kMaxJsonDynamicValues = 8;
    static constexpr u32 kMaxJsonMaterializedValues = kMaxJsonDynamicValues + 1;
    MirTerminatorKind kind = MirTerminatorKind::ReturnStatus;
    Span span{};
    MirTerminatorSourceKind source_kind = MirTerminatorSourceKind::Literal;
    i32 status_code = 0;
    bool commit_response_mutations = false;
    u32 local_ref_index = 0xffffffffu;
    u32 upstream_index = 0;
    bool forward_buffered = false;
    bool use_cmp = false;
    MirValue cond{};
    MirValue lhs{};
    MirValue rhs{};
    u32 then_block = 0;
    u32 else_block = 0;
    WaitEventKind yield_event_kind = WaitEventKind::Timer;
    u32 yield_ms = 0;
    u8 yield_arm_mask = kWaitEventArmTimer;
    u16 yield_next_state = 0;
    // Optional response body literal — carried verbatim from HIR for
    // ReturnStatus terminators. lower_rir maps identical literals to a
    // shared body_idx that codegen packs into HandlerResult.upstream_id.
    Str response_body{};
    bool has_dynamic_response_body = false;
    FixedVec<Str, kMaxJsonDynamicValues + 1> json_segments;
    FixedVec<u32, kMaxJsonDynamicValues> json_value_ref_indices;
    FixedVec<MirLocal, kMaxJsonMaterializedValues> json_locals;
    // Optional response headers carried from HIR. Inline-stored.
    // len == 0 means "no kwarg". lower_rir interns these into the
    // RIR module's shared header pool.
    static constexpr u32 kMaxHeaders = 16;
    FixedVec<MirHeaderKV, kMaxHeaders> response_headers;
    // Request-path rewrite for forward(set_path:) — carried verbatim from HIR.
    // ptr != nullptr → lower_rir emits ReqSetPath before RetForward.
    Str forward_set_path{};
    // Request-header overrides for forward(set_header:) — carried verbatim from
    // HIR. len > 0 → lower_rir emits one ReqSetHeader per entry before RetForward.
    FixedVec<MirHeaderKV, kMaxHeaders> forward_set_headers;
};

struct MirBlock {
    struct Effect {
        u32 value_index = 0xffffffffu;
        Span span{};
    };
    Str label{};
    // Side effects materialized in this block immediately before `term`.
    // Each entry indexes the owning MirFunction::values pool.
    // A resumed Response may apply the full bounded header mutation log plus
    // one status and one body replacement before its terminal return.
    static constexpr u32 kMaxEffects = 18;
    FixedVec<Effect, kMaxEffects> effects;
    MirTerminator term{};
};

struct MirFunction {
    struct Wait {
        Span span{};
        WaitEventKind event_kind = WaitEventKind::Timer;
        u32 ms = 0;
        u8 arm_mask = kWaitEventArmTimer;
    };

    Span span{};
    u8 method = 0;
    Str path{};
    Str name{};
    static constexpr u32 kMaxLocals = 16;
    static constexpr u32 kMaxBlocks = 16;
    static constexpr u32 kMaxValues = 64;
    static constexpr u32 kMaxWaits = kMaxRouteWaits;
    FixedVec<MirValue, kMaxValues> values;
    FixedVec<MirLocal, kMaxLocals> locals;
    FixedVec<MirBlock, kMaxBlocks> blocks;
    FixedVec<Wait, kMaxWaits> waits;
    bool state_zero_enters_entry = false;
    u32 resume_terminal_block = 0;
    bool has_explicit_resume_blocks = false;
    u32 resume_blocks[kMaxWaits + 1]{};
    u32 error_variant_index = 0xffffffffu;
    // @rateLimit per-route limit, copied from HirRoute → carried to RIR Function.
    // @rateLimit decorators -> stacked fixed-window rules (empty = no limit).
    RateLimitRuleSet rate_limit{};
    // @throttle client-send byte rate (bytes/sec, 0 = none).
    u32 throttle_down_bps = 0;
    // Timer function: a `timer name, every: D {...}` periodic task (path holds the
    // name). Carried to the RIR Function so config registers it into the timer
    // table instead of the route table.
    bool is_timer = false;
    u32 timer_interval_ms = 0;
    i32 timer_shard = -1;

    MirFunction() = default;
    MirFunction(const MirFunction& other)
        : span(other.span),
          method(other.method),
          path(other.path),
          name(other.name),
          values(other.values),
          locals(other.locals),
          blocks(other.blocks),
          waits(other.waits),
          state_zero_enters_entry(other.state_zero_enters_entry),
          resume_terminal_block(other.resume_terminal_block),
          has_explicit_resume_blocks(other.has_explicit_resume_blocks),
          error_variant_index(other.error_variant_index),
          rate_limit(other.rate_limit),
          throttle_down_bps(other.throttle_down_bps),
          is_timer(other.is_timer),
          timer_interval_ms(other.timer_interval_ms),
          timer_shard(other.timer_shard) {
        for (u32 i = 0; i < kMaxWaits + 1; i++) resume_blocks[i] = other.resume_blocks[i];
        rebase_from(other);
    }
    MirFunction& operator=(const MirFunction& other) {
        if (this == &other) return *this;
        span = other.span;
        method = other.method;
        path = other.path;
        name = other.name;
        values = other.values;
        locals = other.locals;
        blocks = other.blocks;
        waits = other.waits;
        state_zero_enters_entry = other.state_zero_enters_entry;
        resume_terminal_block = other.resume_terminal_block;
        has_explicit_resume_blocks = other.has_explicit_resume_blocks;
        for (u32 i = 0; i < kMaxWaits + 1; i++) resume_blocks[i] = other.resume_blocks[i];
        error_variant_index = other.error_variant_index;
        rate_limit = other.rate_limit;
        throttle_down_bps = other.throttle_down_bps;
        is_timer = other.is_timer;
        timer_interval_ms = other.timer_interval_ms;
        timer_shard = other.timer_shard;
        rebase_from(other);
        return *this;
    }
    MirFunction(MirFunction&& other) noexcept
        : span(other.span),
          method(other.method),
          path(other.path),
          name(other.name),
          values(other.values),
          locals(other.locals),
          blocks(other.blocks),
          waits(other.waits),
          state_zero_enters_entry(other.state_zero_enters_entry),
          resume_terminal_block(other.resume_terminal_block),
          has_explicit_resume_blocks(other.has_explicit_resume_blocks),
          error_variant_index(other.error_variant_index),
          rate_limit(other.rate_limit),
          throttle_down_bps(other.throttle_down_bps),
          is_timer(other.is_timer),
          timer_interval_ms(other.timer_interval_ms),
          timer_shard(other.timer_shard) {
        for (u32 i = 0; i < kMaxWaits + 1; i++) resume_blocks[i] = other.resume_blocks[i];
        rebase_from(other);
    }
    MirFunction& operator=(MirFunction&& other) noexcept {
        if (this == &other) return *this;
        span = other.span;
        method = other.method;
        path = other.path;
        name = other.name;
        values = other.values;
        locals = other.locals;
        blocks = other.blocks;
        waits = other.waits;
        state_zero_enters_entry = other.state_zero_enters_entry;
        resume_terminal_block = other.resume_terminal_block;
        has_explicit_resume_blocks = other.has_explicit_resume_blocks;
        for (u32 i = 0; i < kMaxWaits + 1; i++) resume_blocks[i] = other.resume_blocks[i];
        error_variant_index = other.error_variant_index;
        rate_limit = other.rate_limit;
        throttle_down_bps = other.throttle_down_bps;
        is_timer = other.is_timer;
        timer_interval_ms = other.timer_interval_ms;
        timer_shard = other.timer_shard;
        rebase_from(other);
        return *this;
    }

private:
    void rebase_value_ptr(const MirFunction& other, MirValue*& ptr) {
        if (ptr == nullptr) return;
        const auto begin = &other.values.data[0];
        const auto end = begin + other.values.len;
        if (ptr < begin || ptr >= end) return;
        const u32 index = static_cast<u32>(ptr - begin);
        ptr = &values.data[index];
    }

    void rebase_value(MirValue& value, const MirFunction& other) {
        rebase_value_ptr(other, value.lhs);
        rebase_value_ptr(other, value.rhs);
        for (u32 i = 0; i < value.field_inits.len; i++) {
            rebase_value_ptr(other, value.field_inits[i].value);
        }
        for (u32 i = 0; i < value.args.len; i++) {
            rebase_value_ptr(other, value.args[i]);
        }
    }

    void rebase_from(const MirFunction& other) {
        for (u32 i = 0; i < values.len; i++) rebase_value(values[i], other);
        for (u32 i = 0; i < locals.len; i++) rebase_value(locals[i].init, other);
        for (u32 i = 0; i < blocks.len; i++) {
            rebase_value(blocks[i].term.cond, other);
            rebase_value(blocks[i].term.lhs, other);
            rebase_value(blocks[i].term.rhs, other);
            for (u32 li = 0; li < blocks[i].term.json_locals.len; li++)
                rebase_value(blocks[i].term.json_locals[li].init, other);
        }
    }
};

struct MirUpstream {
    Span span{};
    Str name{};
    u16 id = 0;
    // Address copied from HIR. has_address == false → the runtime
    // must bind this upstream via add_upstream(); addresses declared
    // in the DSL live here in host byte order (matching
    // RouteConfig::add_upstream's expected layout).
    bool has_address = false;
    u32 ip = 0;
    u16 port = 0;
    // Extra load-balancing endpoints copied from HIR (primary = ip/port).
    static constexpr u32 kMaxExtraBackends = 7;
    u32 extra_count = 0;
    u32 extra_ips[kMaxExtraBackends] = {};
    u16 extra_ports[kMaxExtraBackends] = {};
    // Active health-check config copied from HIR (data only; no probing yet).
    bool hc_enabled = false;
    Str hc_path{};
    u32 hc_interval_ms = 0;
    u16 hc_expected_status = 200;
};

struct MirCacheInstance {
    Span span{};
    Str name{};
    u32 capacity = 0;
};

struct MirModule {
    static constexpr u32 kMaxUpstreams = 32;
    static constexpr u32 kMaxCaches = 8;
    static constexpr u32 kMaxStructs = 64;
    static constexpr u32 kMaxVariants = 32;
    // One MirFunction per HIR route, INCLUDING synthesized timer routes, so this
    // must cover HirModule::kMaxRoutes + kMaxTimers (kept in sync by a static_assert
    // in mir_build.cc). Otherwise a config near the route cap plus timers analyzes
    // but fails MIR lowering with TooManyItems.
    static constexpr u32 kMaxFunctions = 112;  // 96 routes + 16 timers
    static constexpr u32 kMaxTypeShapes = 256;

    FixedVec<MirUpstream, kMaxUpstreams> upstreams;
    FixedVec<MirCacheInstance, kMaxCaches> caches;
    FixedVec<MirStruct, kMaxStructs> structs;
    FixedVec<MirVariant, kMaxVariants> variants;
    FixedVec<MirFunction, kMaxFunctions> functions;
    FixedVec<MirTypeShape, kMaxTypeShapes> type_shapes;

    MirModule() = default;
    MirModule(const MirModule& other)
        : upstreams(other.upstreams),
          caches(other.caches),
          structs(other.structs),
          variants(other.variants),
          functions(other.functions),
          type_shapes(other.type_shapes) {}
    MirModule& operator=(const MirModule& other) {
        if (this == &other) return *this;
        upstreams = other.upstreams;
        caches = other.caches;
        structs = other.structs;
        variants = other.variants;
        functions = other.functions;
        type_shapes = other.type_shapes;
        return *this;
    }
    MirModule(MirModule&& other) noexcept
        : upstreams(other.upstreams),
          caches(other.caches),
          structs(other.structs),
          variants(other.variants),
          functions(other.functions),
          type_shapes(other.type_shapes) {}
    MirModule& operator=(MirModule&& other) noexcept {
        if (this == &other) return *this;
        upstreams = other.upstreams;
        caches = other.caches;
        structs = other.structs;
        variants = other.variants;
        functions = other.functions;
        type_shapes = other.type_shapes;
        return *this;
    }
};

}  // namespace rut
