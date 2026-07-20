#pragma once

#include "rut/common/types.h"
#include "rut/common/wait_limits.h"
#include "rut/compiler/ast.h"
#include "rut/compiler/diagnostic.h"
#include <deque>
#include <memory>
#include <string>

namespace rut {

enum class HirProtocolKind : u8 {
    Custom,
    Error,
    Eq,
    Ord,
};

struct HirUpstream {
    Span span{};
    Str name{};
    u16 id = 0;
    // Address declared in the DSL via `upstream X at "..."` or
    // `upstream X { host: "...", port: N }`. `has_address == false`
    // means the runtime must bind this upstream via add_upstream();
    // analyze doesn't force an address on every upstream, to stay
    // compatible with test configs that register upstreams manually.
    // ip is in host byte order (RouteConfig::add_upstream expects
    // the same).
    bool has_address = false;
    u32 ip = 0;
    u16 port = 0;
    // Extra load-balancing endpoints beyond the primary (ip, port), from
    // `{ backends: [...] }`. Primary + extras are round-robined at runtime.
    // ips in host byte order, matching RouteConfig::add_upstream_backend.
    static constexpr u32 kMaxExtraBackends = 7;  // AstUpstreamDecl::kMaxBackends - 1
    u32 extra_count = 0;
    u32 extra_ips[kMaxExtraBackends] = {};
    u16 extra_ports[kMaxExtraBackends] = {};
    // Active health-check config copied from the DSL (data only; no probing in
    // this slice). hc_enabled gates the rest. path/interval required when set;
    // status defaults to 200. hc_path is a Str (like name) copied into a char
    // buffer at populate_route_config via set_upstream_health_check.
    bool hc_enabled = false;
    Str hc_path{};
    u32 hc_interval_ms = 0;
    u16 hc_expected_status = 200;
};
struct HirImport {
    Span span{};
    Str path{};
    bool selective = false;
    bool has_namespace_alias = false;
    Str namespace_alias{};
    bool has_package_decl = false;
    bool same_package = false;
    Str package_name{};
};

struct HirAlias {
    static constexpr u32 kMaxTargetParts = 8;
    Span span{};
    Str name{};
    FixedVec<Str, kMaxTargetParts> target_parts;
};

struct HirTypeAlias {
    static constexpr u32 kMaxTypeParams = AstTypeAliasDecl::kMaxTypeParams;
    static constexpr u32 kMaxArms = AstTypeAliasDecl::kMaxArms;
    struct ArmDecl {
        bool is_wildcard = false;
        bool is_type_equality = false;
        Str type_param{};
        Str associated_name{};
        Str rhs_type_param{};
        Str rhs_associated_name{};
        Str constraint_namespace{};
        Str constraint{};
        AstTypeRef type{};
    };
    Span span{};
    Str name{};
    FixedVec<Str, kMaxTypeParams> type_params;
    bool is_match = false;
    AstTypeRef target{};
    FixedVec<ArmDecl, kMaxArms> arms;
};

enum class HirExprKind : u8 {
    BoolLit,
    IntLit,
    StrLit,
    RegexMatch,
    Tuple,
    // Array literal: elements stored in `args`. analyze rejects heterogeneous
    // arrays and bare empty `[]`; typed empty route locals are currently
    // accepted only when their `let xs: [T] = []` binding is used solely as a
    // static for-loop iterator.
    // Element count is a value property on `HirExpr.array_len`, not a type
    // property; the result's HirTypeShape carries only `array_elem_shape_index`.
    ArrayLit,
    TupleSlot,
    VariantCase,
    IfElse,
    Call,
    StructInit,
    Field,
    ReqHeader,
    // `req.set("Name", value)` statement effect. `str_value` is the validated
    // literal header name; `lhs` is the plain string value. The expression
    // echoes the value internally so it can use the existing effect/value
    // materialization pipeline, but analyze forbids value-position use.
    ReqSetHeader,
    // `req.add("Name", "value")`: preserves existing same-named fields and
    // appends one new field line.
    ReqAddHeader,
    // Compile-time Response builder. int_value is the validated status code;
    // field_inits stores ordered literal response headers.
    ResponseInit,
    RespHeader,
    RespSetHeader,
    RespAddHeader,
    RespRemoveHeader,
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
    // HTTP method literal — int_value holds the HttpMethod enum
    // value (0=GET, 1=POST, …, matching rut/runtime/http_parser.h).
    ConstMethod,
    // Read of the parsed request method from the current connection.
    ReqMethod,
    Nil,
    Error,
    LocalRef,
    Eq,
    Lt,
    Gt,
    // Bitwise builtins (`bitwise.and(a, b)` etc.) — binary i32 ops on
    // lhs/rhs. `bitwise.flip(a)` desugars to BitXor(a, -1) at analyze time.
    BitAnd,
    BitOr,
    BitXor,
    BitShl,
    BitShr,
    // Arithmetic operators — binary i32 ops on lhs/rhs. Overflow wraps
    // two's-complement; x / 0 and x % 0 are 0; INT_MIN / -1 is INT_MIN and
    // INT_MIN % -1 is 0 (analyze fold and codegen agree by construction).
    // Unary minus is Sub(IntLit 0, x) from the parser.
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    // Sign-extend a runtime i32 to i64 — produced only by the `i64(x)`
    // builtin (literals fold at analyze time). Operand in lhs; result I64.
    WidenI64,
    // `time.nowMicros()` — monotonic microseconds, type I64, nullary.
    TimeNowMicros,
    // `max(a, b)` / `min(a, b)` builtins — same-width {I32,I64} binary,
    // signed; single evaluation (real opcodes, not an IfElse desugar).
    MaxInt,
    MinInt,
    Or,
    NoError,
    HasValue,
    ValueOf,
    MissingOf,
    MatchPayload,
    VariantTag,
    ProtocolCall,
    WaitResult,
    WaitField,
    // Cache<K, i64> state ops (DESIGN.md §3.3.6). cache_index selects
    // the declared instance; key operand in lhs. CacheGet → I64 with
    // may_nil=true (miss covers never-seen AND evicted); CacheSet carries
    // the value in rhs and echoes it (type I64).
    CacheGet,
    CacheSet,
};

enum class HirTypeKind : u8 {
    Unknown,
    Bool,
    I32,
    // 64-bit signed integer. Produced by the `i64(x)` conversion builtin and
    // by int literals that don't fit i32; arithmetic/comparisons are
    // same-type ({I32,I64}) — no implicit mixing.
    I64,
    Str,
    Generic,
    Associated,
    Variant,
    Tuple,
    Struct,
    Method,
    ByteSize,
    IP,
    // Homogeneous fixed-size sequence. Carrier for `for x in <arr>` iteration.
    // Type-shape info lives in HirTypeShape via `array_elem_shape_index`
    // alone; length is a *value* property on `HirExpr.array_len` so two
    // arrays with the same element type but different lengths share one
    // shape. Composite-type host structures (HirLocal, HirExpr, etc.)
    // reference the shape through their existing `shape_index` rather than
    // mirroring inline fields.
    Array,
    // Runtime view over ordered string slices. Unlike Array, this has a
    // MIR/RIR carrier and may be stored in route locals.
    StrList,
    // A bounded response builder local. It is consumed by `return <local>` and
    // does not have a runtime MIR carrier in the initial literal-only slice.
    Response,
};

inline constexpr u32 kMaxTupleSlots = 10;

struct HirTypeShape {
    HirTypeKind type = HirTypeKind::Unknown;
    bool is_concrete = false;
    u32 generic_index = 0xffffffffu;
    u32 variant_index = 0xffffffffu;
    u32 struct_index = 0xffffffffu;
    u32 tuple_len = 0;
    u32 tuple_elem_shape_indices[kMaxTupleSlots]{};
    // Array-typed shape: array_elem_shape_index points at another
    // HirTypeShape in HirModule::type_shapes describing the element type.
    // Length is a *value* property (lives on HirExpr.array_len, carried
    // forward to MIR for unroll) — not a type property, so two arrays of
    // the same element type with different lengths still share one shape.
    // Sentinel: type != Array → array_elem_shape_index = 0xffffffffu.
    u32 array_elem_shape_index = 0xffffffffu;
};

struct HirProtocol {
    static constexpr u32 kMaxMethods = 8;
    static constexpr u32 kMaxAssociatedTypes = 8;
    struct AssociatedTypeDecl {
        Str name{};
    };
    struct MethodDecl {
        struct ParamDecl {
            Str type_name{};
            HirTypeKind type = HirTypeKind::Unknown;
            u32 generic_index = 0xffffffffu;
            Str associated_name{};
            u32 variant_index = 0xffffffffu;
            u32 struct_index = 0xffffffffu;
            u32 tuple_len = 0;
            HirTypeKind tuple_types[kMaxTupleSlots]{};
            u32 tuple_variant_indices[kMaxTupleSlots]{};
            u32 tuple_struct_indices[kMaxTupleSlots]{};
            u32 shape_index = 0xffffffffu;
        };
        Str name{};
        FixedVec<ParamDecl, 8> params;
        bool has_return_type = false;
        Str return_type_name{};
        HirTypeKind return_type = HirTypeKind::Unknown;
        u32 return_generic_index = 0xffffffffu;
        Str return_associated_name{};
        u32 return_variant_index = 0xffffffffu;
        u32 return_struct_index = 0xffffffffu;
        u32 return_tuple_len = 0;
        HirTypeKind return_tuple_types[kMaxTupleSlots]{};
        u32 return_tuple_variant_indices[kMaxTupleSlots]{};
        u32 return_tuple_struct_indices[kMaxTupleSlots]{};
        u32 return_shape_index = 0xffffffffu;
        bool return_may_nil = false;
        bool return_may_error = false;
        u32 return_error_struct_index = 0xffffffffu;
        u32 return_error_variant_index = 0xffffffffu;
        u32 function_index = 0xffffffffu;
    };
    Span span{};
    Str name{};
    HirProtocolKind kind = HirProtocolKind::Custom;
    FixedVec<AssociatedTypeDecl, kMaxAssociatedTypes> associated_types;
    FixedVec<MethodDecl, kMaxMethods> methods;
};

struct HirConformance {
    Span span{};
    u32 protocol_index = 0xffffffffu;
    HirTypeKind type = HirTypeKind::Unknown;
    u32 variant_index = 0xffffffffu;
    u32 struct_index = 0xffffffffu;
    u32 tuple_len = 0;
    HirTypeKind tuple_types[kMaxTupleSlots]{};
    u32 tuple_variant_indices[kMaxTupleSlots]{};
    u32 tuple_struct_indices[kMaxTupleSlots]{};
    bool is_generic_template = false;
};

struct HirVariant {
    static constexpr u32 kMaxTypeParams = 4;
    static constexpr u32 kMaxGenericProtocols = 4;
    struct TypeArgRef {
        HirTypeKind type = HirTypeKind::Unknown;
        u32 generic_index = 0xffffffffu;
        u32 variant_index = 0xffffffffu;
        u32 struct_index = 0xffffffffu;
        u32 tuple_len = 0;
        HirTypeKind tuple_types[kMaxTupleSlots]{};
        u32 tuple_variant_indices[kMaxTupleSlots]{};
        u32 tuple_struct_indices[kMaxTupleSlots]{};
        u32 shape_index = 0xffffffffu;
    };
    struct CaseDecl {
        Str name{};
        HirTypeKind payload_type = HirTypeKind::Unknown;
        bool has_payload = false;
        u32 payload_generic_index = 0xffffffffu;
        bool payload_generic_has_error_constraint = false;
        bool payload_generic_has_eq_constraint = false;
        bool payload_generic_has_ord_constraint = false;
        u32 payload_generic_protocol_index = 0xffffffffu;
        u32 payload_generic_protocol_count = 0;
        u32 payload_generic_protocol_indices[kMaxGenericProtocols]{};
        u32 payload_variant_index = 0xffffffffu;
        u32 payload_struct_index = 0xffffffffu;
        u32 payload_tuple_len = 0;
        HirTypeKind payload_tuple_types[kMaxTupleSlots]{};
        u32 payload_tuple_variant_indices[kMaxTupleSlots]{};
        u32 payload_tuple_struct_indices[kMaxTupleSlots]{};
        u32 payload_template_variant_index = 0xffffffffu;
        u32 payload_template_struct_index = 0xffffffffu;
        u32 payload_type_arg_count = 0;
        TypeArgRef payload_type_args[kMaxTypeParams]{};
        u32 payload_shape_index = 0xffffffffu;
    };

    Span span{};
    Str name{};
    FixedVec<Str, kMaxTypeParams> type_params;
    u32 template_variant_index = 0xffffffffu;
    u32 instance_type_arg_count = 0;
    HirTypeKind instance_type_args[kMaxTypeParams]{};
    u32 instance_generic_indices[kMaxTypeParams]{};
    u32 instance_variant_indices[kMaxTypeParams]{};
    u32 instance_struct_indices[kMaxTypeParams]{};
    u32 instance_tuple_lens[kMaxTypeParams]{};
    HirTypeKind instance_tuple_types[kMaxTypeParams][kMaxTupleSlots]{};
    u32 instance_tuple_variant_indices[kMaxTypeParams][kMaxTupleSlots]{};
    u32 instance_tuple_struct_indices[kMaxTypeParams][kMaxTupleSlots]{};
    u32 instance_shape_indices[kMaxTypeParams]{};
    static constexpr u32 kMaxCases = 16;
    FixedVec<CaseDecl, kMaxCases> cases;
};

struct HirStruct {
    static constexpr u32 kMaxTypeParams = 4;
    static constexpr u32 kMaxGenericProtocols = 4;
    using TypeArgRef = HirVariant::TypeArgRef;
    struct FieldDecl {
        Str name{};
        Str type_name{};
        HirTypeKind type = HirTypeKind::Unknown;
        bool is_error_type = false;
        u32 generic_index = 0xffffffffu;
        bool generic_has_error_constraint = false;
        bool generic_has_eq_constraint = false;
        bool generic_has_ord_constraint = false;
        u32 generic_protocol_index = 0xffffffffu;
        u32 generic_protocol_count = 0;
        u32 generic_protocol_indices[kMaxGenericProtocols]{};
        u32 variant_index = 0xffffffffu;
        u32 struct_index = 0xffffffffu;
        u32 tuple_len = 0;
        HirTypeKind tuple_types[kMaxTupleSlots]{};
        u32 tuple_variant_indices[kMaxTupleSlots]{};
        u32 tuple_struct_indices[kMaxTupleSlots]{};
        u32 template_variant_index = 0xffffffffu;
        u32 template_struct_index = 0xffffffffu;
        u32 type_arg_count = 0;
        TypeArgRef type_args[kMaxTypeParams]{};
        u32 shape_index = 0xffffffffu;
    };

    Span span{};
    Str name{};
    bool conforms_error = false;
    FixedVec<Str, kMaxTypeParams> type_params;
    u32 template_struct_index = 0xffffffffu;
    u32 instance_type_arg_count = 0;
    HirTypeKind instance_type_args[kMaxTypeParams]{};
    u32 instance_generic_indices[kMaxTypeParams]{};
    u32 instance_variant_indices[kMaxTypeParams]{};
    u32 instance_struct_indices[kMaxTypeParams]{};
    u32 instance_tuple_lens[kMaxTypeParams]{};
    HirTypeKind instance_tuple_types[kMaxTypeParams][kMaxTupleSlots]{};
    u32 instance_tuple_variant_indices[kMaxTypeParams][kMaxTupleSlots]{};
    u32 instance_tuple_struct_indices[kMaxTypeParams][kMaxTupleSlots]{};
    u32 instance_shape_indices[kMaxTypeParams]{};
    static constexpr u32 kMaxFields = 8;
    FixedVec<FieldDecl, kMaxFields> fields;
};

struct HirExpr {
    struct FieldInit {
        Str name{};
        HirExpr* value = nullptr;
    };

    HirExprKind kind = HirExprKind::BoolLit;
    HirTypeKind type = HirTypeKind::Unknown;
    Span span{};
    bool may_nil = false;
    bool may_error = false;
    bool bool_value = false;
    i64 int_value = 0;
    Str str_value{};
    Str msg{};
    u32 local_index = 0;
    u32 generic_index = 0xffffffffu;
    Str associated_name{};
    bool generic_has_error_constraint = false;
    bool generic_has_eq_constraint = false;
    bool generic_has_ord_constraint = false;
    static constexpr u32 kMaxGenericProtocols = 4;
    u32 generic_protocol_index = 0xffffffffu;
    u32 generic_protocol_count = 0;
    u32 generic_protocol_indices[kMaxGenericProtocols]{};
    u32 protocol_index = 0xffffffffu;
    u32 variant_index = 0;
    u32 struct_index = 0xffffffffu;
    u32 case_index = 0;
    u32 tuple_len = 0;
    HirTypeKind tuple_types[kMaxTupleSlots]{};
    u32 tuple_variant_indices[kMaxTupleSlots]{};
    u32 tuple_struct_indices[kMaxTupleSlots]{};
    u32 shape_index = 0xffffffffu;
    u32 error_struct_index = 0xffffffffu;
    u32 error_variant_index = 0xffffffffu;
    u32 error_case_index = 0xffffffffu;
    // For HirExprKind::ArrayLit: compile-time-known element count. Elements
    // themselves live in `args`. For non-Array exprs: 0.
    u32 array_len = 0;
    // CacheGet/CacheSet: index into HirModule::caches.
    u32 cache_index = 0xffffffffu;
    HirExpr* lhs = nullptr;
    HirExpr* rhs = nullptr;
    bool is_pipe_conditional = false;
    bool is_eager_fallback = false;
    bool is_wait_result = false;
    WaitEventKind wait_event_kind = WaitEventKind::Timer;
    u32 wait_payload = 0;
    u8 wait_arm_mask = kWaitEventArmTimer;
    u32 wait_index = 0xffffffffu;
    // Struct/object construction is still capped by the AST at 8 fields, but
    // ResponseInit also uses this storage for its ordered literal header prefix.
    // Match the language's existing 16-header terminator limit so builder syntax
    // does not impose a smaller, surprising cap.
    static constexpr u32 kMaxFieldInits = 16;
    // HIR-level cap stays at 8 even though AstExpr::kMaxArgs = 32: HirRoute
    // sits at ~300 KB on stack and is copied on each recursive
    // analyze_file_internal call (via `HirRoute scratch{}`). A 32-wide cap
    // here inflates the exprs / locals / for_loops pools enough to blow the
    // 8 MB thread stack during cyclic-import tests. Phase 3a's ArrayLit
    // analyze catches > kMaxArgs element arrays cleanly; a larger HIR cap
    // can land when we introduce an out-of-line array-element pool.
    static constexpr u32 kMaxArgs = 8;
    FixedVec<FieldInit, kMaxFieldInits> field_inits;
    FixedVec<HirExpr*, kMaxArgs> args;
};

struct HirFunction {
    static constexpr u32 kMaxTypeParams = 4;
    struct TypeParamDecl {
        static constexpr u32 kMaxConstraints = 4;
        Str name{};
        bool has_constraint = false;
        Str constraint{};
        HirProtocolKind constraint_kind = HirProtocolKind::Custom;
        bool has_error_constraint = false;
        bool has_eq_constraint = false;
        bool has_ord_constraint = false;
        u32 custom_protocol_count = 0;
        Str constraints[kMaxConstraints]{};
        HirProtocolKind constraint_kinds[kMaxConstraints]{};
        u32 custom_protocol_indices[kMaxConstraints]{};
    };
    struct ParamDecl {
        Str name{};
        HirTypeKind type = HirTypeKind::Unknown;
        u32 generic_index = 0xffffffffu;
        Str associated_name{};
        bool generic_has_error_constraint = false;
        bool generic_has_eq_constraint = false;
        bool generic_has_ord_constraint = false;
        u32 generic_protocol_index = 0xffffffffu;
        u32 generic_protocol_count = 0;
        u32 generic_protocol_indices[HirExpr::kMaxGenericProtocols]{};
        u32 template_variant_index = 0xffffffffu;
        u32 template_struct_index = 0xffffffffu;
        u32 type_arg_count = 0;
        HirVariant::TypeArgRef type_args[kMaxTypeParams]{};
        u32 variant_index = 0xffffffffu;
        u32 struct_index = 0xffffffffu;
        u32 tuple_len = 0;
        HirTypeKind tuple_types[kMaxTupleSlots]{};
        u32 tuple_variant_indices[kMaxTupleSlots]{};
        u32 tuple_struct_indices[kMaxTupleSlots]{};
        u32 shape_index = 0xffffffffu;
        u32 array_elem_shape_index = 0xffffffffu;
        bool has_underscore_label = false;
    };

    Span span{};
    Str name{};
    HirTypeKind return_type = HirTypeKind::Unknown;
    u32 return_generic_index = 0xffffffffu;
    Str return_associated_name{};
    u32 return_template_variant_index = 0xffffffffu;
    u32 return_template_struct_index = 0xffffffffu;
    u32 return_type_arg_count = 0;
    HirVariant::TypeArgRef return_type_args[kMaxTypeParams]{};
    u32 return_variant_index = 0xffffffffu;
    u32 return_struct_index = 0xffffffffu;
    u32 return_tuple_len = 0;
    HirTypeKind return_tuple_types[kMaxTupleSlots]{};
    u32 return_tuple_variant_indices[kMaxTupleSlots]{};
    u32 return_tuple_struct_indices[kMaxTupleSlots]{};
    u32 return_shape_index = 0xffffffffu;
    u32 return_array_elem_shape_index = 0xffffffffu;
    static constexpr u32 kMaxParams = 8;
    static constexpr u32 kMaxExprs = 64;
    FixedVec<TypeParamDecl, kMaxTypeParams> type_params;
    FixedVec<ParamDecl, kMaxParams> params;
    FixedVec<HirExpr, kMaxExprs> exprs;
    // Chain-after currently replays only Response header mutations. Remember
    // whether the source helper also contained another statement effect so a
    // call site cannot silently drop it during expansion.
    bool has_non_response_statement_effect = false;
    struct RespondHeader {
        Str key{};
        Str value{};
    };
    struct RespondGuard {
        Span span{};
        HirExpr cond{};
        i32 status_code = 0;
        Str response_body{};
        static constexpr u32 kMaxHeaders = 16;
        FixedVec<RespondHeader, kMaxHeaders> response_headers;
    };
    static constexpr u32 kMaxRespondGuards = 4;
    FixedVec<RespondGuard, kMaxRespondGuards> respond_guards;
    HirExpr body{};

    HirFunction() = default;
    HirFunction(const HirFunction& other)
        : span(other.span),
          name(other.name),
          return_type(other.return_type),
          return_generic_index(other.return_generic_index),
          return_associated_name(other.return_associated_name),
          return_template_variant_index(other.return_template_variant_index),
          return_template_struct_index(other.return_template_struct_index),
          return_type_arg_count(other.return_type_arg_count),
          return_variant_index(other.return_variant_index),
          return_struct_index(other.return_struct_index),
          return_tuple_len(other.return_tuple_len),
          return_shape_index(other.return_shape_index),
          return_array_elem_shape_index(other.return_array_elem_shape_index),
          type_params(other.type_params),
          params(other.params),
          exprs(other.exprs),
          has_non_response_statement_effect(other.has_non_response_statement_effect),
          respond_guards(other.respond_guards),
          body(other.body) {
        for (u32 i = 0; i < other.return_tuple_len; i++) {
            return_tuple_types[i] = other.return_tuple_types[i];
            return_tuple_variant_indices[i] = other.return_tuple_variant_indices[i];
            return_tuple_struct_indices[i] = other.return_tuple_struct_indices[i];
        }
        for (u32 i = 0; i < other.return_type_arg_count; i++) {
            return_type_args[i] = other.return_type_args[i];
        }
        rebase_from(other);
    }
    HirFunction& operator=(const HirFunction& other) {
        if (this == &other) return *this;
        span = other.span;
        name = other.name;
        return_type = other.return_type;
        return_generic_index = other.return_generic_index;
        return_associated_name = other.return_associated_name;
        return_template_variant_index = other.return_template_variant_index;
        return_template_struct_index = other.return_template_struct_index;
        return_type_arg_count = other.return_type_arg_count;
        return_variant_index = other.return_variant_index;
        return_struct_index = other.return_struct_index;
        return_tuple_len = other.return_tuple_len;
        return_shape_index = other.return_shape_index;
        return_array_elem_shape_index = other.return_array_elem_shape_index;
        for (u32 i = 0; i < other.return_tuple_len; i++) {
            return_tuple_types[i] = other.return_tuple_types[i];
            return_tuple_variant_indices[i] = other.return_tuple_variant_indices[i];
            return_tuple_struct_indices[i] = other.return_tuple_struct_indices[i];
        }
        for (u32 i = 0; i < other.return_type_arg_count; i++) {
            return_type_args[i] = other.return_type_args[i];
        }
        type_params = other.type_params;
        params = other.params;
        exprs = other.exprs;
        has_non_response_statement_effect = other.has_non_response_statement_effect;
        respond_guards = other.respond_guards;
        body = other.body;
        rebase_from(other);
        return *this;
    }
    HirFunction(HirFunction&& other) noexcept
        : span(other.span),
          name(other.name),
          return_type(other.return_type),
          return_generic_index(other.return_generic_index),
          return_associated_name(other.return_associated_name),
          return_template_variant_index(other.return_template_variant_index),
          return_template_struct_index(other.return_template_struct_index),
          return_type_arg_count(other.return_type_arg_count),
          return_variant_index(other.return_variant_index),
          return_struct_index(other.return_struct_index),
          return_tuple_len(other.return_tuple_len),
          return_shape_index(other.return_shape_index),
          return_array_elem_shape_index(other.return_array_elem_shape_index),
          type_params(other.type_params),
          params(other.params),
          exprs(other.exprs),
          has_non_response_statement_effect(other.has_non_response_statement_effect),
          respond_guards(other.respond_guards),
          body(other.body) {
        for (u32 i = 0; i < other.return_tuple_len; i++) {
            return_tuple_types[i] = other.return_tuple_types[i];
            return_tuple_variant_indices[i] = other.return_tuple_variant_indices[i];
            return_tuple_struct_indices[i] = other.return_tuple_struct_indices[i];
        }
        for (u32 i = 0; i < other.return_type_arg_count; i++) {
            return_type_args[i] = other.return_type_args[i];
        }
        rebase_from(other);
    }
    HirFunction& operator=(HirFunction&& other) noexcept {
        if (this == &other) return *this;
        span = other.span;
        name = other.name;
        return_type = other.return_type;
        return_generic_index = other.return_generic_index;
        return_associated_name = other.return_associated_name;
        return_template_variant_index = other.return_template_variant_index;
        return_template_struct_index = other.return_template_struct_index;
        return_type_arg_count = other.return_type_arg_count;
        return_variant_index = other.return_variant_index;
        return_struct_index = other.return_struct_index;
        return_tuple_len = other.return_tuple_len;
        return_shape_index = other.return_shape_index;
        return_array_elem_shape_index = other.return_array_elem_shape_index;
        for (u32 i = 0; i < other.return_tuple_len; i++) {
            return_tuple_types[i] = other.return_tuple_types[i];
            return_tuple_variant_indices[i] = other.return_tuple_variant_indices[i];
            return_tuple_struct_indices[i] = other.return_tuple_struct_indices[i];
        }
        for (u32 i = 0; i < other.return_type_arg_count; i++) {
            return_type_args[i] = other.return_type_args[i];
        }
        type_params = other.type_params;
        params = other.params;
        exprs = other.exprs;
        has_non_response_statement_effect = other.has_non_response_statement_effect;
        respond_guards = other.respond_guards;
        body = other.body;
        rebase_from(other);
        return *this;
    }

private:
    void rebase_expr_ptr(const HirFunction& other, HirExpr*& ptr) {
        if (ptr == nullptr) return;
        const auto begin = &other.exprs.data[0];
        const auto end = begin + other.exprs.len;
        if (ptr < begin || ptr >= end) return;
        const u32 index = static_cast<u32>(ptr - begin);
        ptr = &exprs.data[index];
    }

    void rebase_expr(HirExpr& expr, const HirFunction& other) {
        rebase_expr_ptr(other, expr.lhs);
        rebase_expr_ptr(other, expr.rhs);
        for (u32 i = 0; i < expr.field_inits.len; i++) {
            rebase_expr_ptr(other, expr.field_inits[i].value);
        }
        for (u32 i = 0; i < expr.args.len; i++) {
            rebase_expr_ptr(other, expr.args[i]);
        }
    }

    void rebase_respond_guard(RespondGuard& guard, const HirFunction& other) {
        rebase_expr(guard.cond, other);
    }

    void rebase_from(const HirFunction& other) {
        for (u32 i = 0; i < exprs.len; i++) rebase_expr(exprs[i], other);
        for (u32 i = 0; i < respond_guards.len; i++) rebase_respond_guard(respond_guards[i], other);
        rebase_expr(body, other);
    }
};

struct HirLocal {
    Span span{};
    Str name{};
    u32 ref_index = 0;
    HirTypeKind type = HirTypeKind::Unknown;
    u32 generic_index = 0xffffffffu;
    Str associated_name{};
    bool generic_has_error_constraint = false;
    bool generic_has_eq_constraint = false;
    bool generic_has_ord_constraint = false;
    u32 generic_protocol_index = 0xffffffffu;
    u32 generic_protocol_count = 0;
    u32 generic_protocol_indices[HirExpr::kMaxGenericProtocols]{};
    bool may_nil = false;
    bool may_error = false;
    u32 variant_index = 0;
    u32 struct_index = 0xffffffffu;
    u32 tuple_len = 0;
    HirTypeKind tuple_types[kMaxTupleSlots]{};
    u32 tuple_variant_indices[kMaxTupleSlots]{};
    u32 tuple_struct_indices[kMaxTupleSlots]{};
    u32 shape_index = 0xffffffffu;
    u32 error_struct_index = 0xffffffffu;
    u32 error_variant_index = 0xffffffffu;
    bool is_wait_result = false;
    bool is_magic_request_proxy = false;
    WaitEventKind wait_event_kind = WaitEventKind::Timer;
    u32 wait_payload = 0;
    u8 wait_arm_mask = kWaitEventArmTimer;
    u32 wait_index = 0xffffffffu;
    HirExpr init{};
};

enum class HirTerminatorKind : u8 {
    ReturnStatus,
    ForwardUpstream,
};

// Where the runtime status value comes from, when kind == ReturnStatus.
// Literal: status_code is the i32 to return (compile-time constant).
// LocalRef: read the value of route.locals[local_ref_index] at runtime.
enum class HirTerminatorSourceKind : u8 {
    Literal,
    LocalRef,
};

struct HirHeaderKV {
    Str key{};
    Str value{};
};

struct HirTerminator {
    HirTerminatorKind kind = HirTerminatorKind::ReturnStatus;
    Span span{};
    HirTerminatorSourceKind source_kind = HirTerminatorSourceKind::Literal;
    i32 status_code = 0;
    // A dynamically mutated Response builder keeps its mutations pending until
    // this exact return path commits them to the outgoing response.
    bool commit_response_mutations = false;
    u32 local_ref_index = 0xffffffffu;
    u32 upstream_index = 0;
    // Optional response body literal (populated when the source was
    // `return response(N, body: "...")`). Sentinel by ptr, not len:
    //   ptr == nullptr   → no body kwarg, use default status-reason.
    //   ptr != nullptr   → explicit body (including `body: ""` which
    //                      keeps ptr non-null with len == 0).
    // analyze.cc::analyze_term only copies this when the Ast source
    // had `has_response_body == true`, so the sentinel is preserved
    // end-to-end.
    Str response_body{};
    // Optional response headers from `response(N, headers: {...})`.
    // Inline-stored so analyze doesn't need the AstFile handle, and
    // downstream passes don't need a module-level pool. len == 0
    // means "no kwarg" (parser rejects explicit empty dicts).
    static constexpr u32 kMaxHeaders = 16;
    FixedVec<HirHeaderKV, kMaxHeaders> response_headers;
    // Request-path rewrite for `forward(name, set_path: "...")` (literal). ptr
    // != nullptr means a path override is present; lowering emits ReqSetPath
    // before the RetForward terminator.
    Str forward_set_path{};
    // Request-header overrides for `forward(name, set_header: {...})`. len == 0
    // means none; lowering emits one ReqSetHeader per entry before RetForward.
    FixedVec<HirHeaderKV, kMaxHeaders> forward_set_headers;
};

struct HirGuardBody {
    enum class BodyKind : u8 {
        Direct,
        If,
    };

    static constexpr u32 kMaxLocals = 4;
    BodyKind body_kind = BodyKind::Direct;
    FixedVec<HirLocal, kMaxLocals> locals;
    HirExpr cond{};
    HirTerminator then_term{};
    HirTerminator else_term{};
    HirTerminator direct_term{};
};

struct HirGuardMatchArm {
    Span span{};
    bool is_wildcard = false;
    HirExpr pattern{};
    HirTerminator direct_term{};
};

struct HirGuard {
    enum class FailKind : u8 {
        Term,
        Match,
        Body,
    };

    static constexpr u32 kMaxFailMatchArms = 8;
    Span span{};
    HirExpr cond{};
    FailKind fail_kind = FailKind::Term;
    HirTerminator fail_term{};
    HirExpr fail_match_expr{};
    u32 fail_match_start = 0;
    u32 fail_match_count = 0;
    HirGuardBody fail_body{};
};

struct HirMatchArm {
    enum class BodyKind : u8 {
        Direct,
        If,
    };

    Span span{};
    bool is_wildcard = false;
    HirExpr pattern{};
    bool bind_payload = false;
    Str bind_name{};
    HirTypeKind bind_type = HirTypeKind::Unknown;
    u32 bind_variant_index = 0xffffffffu;
    u32 bind_struct_index = 0xffffffffu;
    u32 bind_tuple_len = 0;
    HirTypeKind bind_tuple_types[kMaxTupleSlots]{};
    u32 bind_tuple_variant_indices[kMaxTupleSlots]{};
    u32 bind_tuple_struct_indices[kMaxTupleSlots]{};
    bool has_arm_guard = false;
    HirExpr arm_guard{};
    BodyKind body_kind = BodyKind::Direct;
    // Source-ordered side effects that execute after this arm's prelude
    // guards and immediately before its terminal body. Entries index the
    // owning HirRoute::exprs pool. CacheSet and request-header mutations are supported.
    static constexpr u32 kMaxEffects = 2;
    FixedVec<u32, kMaxEffects> effect_expr_indices;
    static constexpr u32 kMaxPreludeGuards = 4;
    FixedVec<HirGuard, kMaxPreludeGuards> guards;
    HirExpr cond{};
    HirTerminator then_term{};
    HirTerminator else_term{};
    HirTerminator direct_term{};
};

enum class HirControlKind : u8 {
    Direct,
    If,
    Match,
};

struct HirControl {
    HirControlKind kind = HirControlKind::Direct;
    static constexpr u32 kMaxMatchArms = 8;
    HirExpr cond{};
    HirExpr match_expr{};
    FixedVec<HirMatchArm, kMaxMatchArms> match_arms;
    HirTerminator then_term{};
    HirTerminator else_term{};
    HirTerminator direct_term{};
};

struct HirForLoopIf {
    Span span{};
    HirExpr cond{};
    HirTerminator then_term{};
    HirTerminator else_term{};
};

struct HirForLoopMatchArm {
    enum class BodyKind : u8 {
        Direct,
        If,
    };

    Span span{};
    bool is_wildcard = false;
    HirExpr pattern{};
    bool bind_payload = false;
    Str bind_name{};
    HirTypeKind bind_type = HirTypeKind::Unknown;
    u32 bind_variant_index = 0xffffffffu;
    u32 bind_struct_index = 0xffffffffu;
    u32 bind_tuple_len = 0;
    HirTypeKind bind_tuple_types[kMaxTupleSlots]{};
    u32 bind_tuple_variant_indices[kMaxTupleSlots]{};
    u32 bind_tuple_struct_indices[kMaxTupleSlots]{};
    bool has_arm_guard = false;
    HirExpr arm_guard{};
    BodyKind body_kind = BodyKind::Direct;
    static constexpr u32 kMaxLocals = 4;
    static constexpr u32 kMaxPreludeGuards = 2;
    FixedVec<HirLocal, kMaxLocals> locals;
    FixedVec<HirGuard, kMaxPreludeGuards> guards;
    HirExpr cond{};
    HirTerminator then_term{};
    HirTerminator else_term{};
    HirTerminator direct_term{};
};

struct HirForLoopMatch {
    Span span{};
    static constexpr u32 kMaxMatchArms = 8;
    HirExpr match_expr{};
    FixedVec<HirForLoopMatchArm, kMaxMatchArms> arms;
};

// Body of a `for ... in` loop. The current compile-time unroll path supports
// body-local lets, body guards, and an optional terminating control (return /
// forward / if with terminal branches / simple match with terminal arms).
// Nested for-loops and richer match forms are represented in the HIR body.
// The body's guards, local inits, if conds, and match exprs/patterns carry
// inline HirExpr subtrees whose lhs/rhs/args* point into the parent
// HirRoute::exprs pool; HirRoute::rebase_from must walk them. HirTerminator
// has no HirExpr pointers (only status_code / upstream_index / response
// strings), so it doesn't participate in rebase.
struct HirForLoopBody {
    struct Step {
        enum class Kind : u8 {
            Let,
            Guard,
            If,
            Match,
            For,
            Term,
        };
        Kind kind = Kind::Let;
        u32 index = 0;
        Span span{};
    };
    // Body-local lets are compile-time-expanded with each iteration. Keep
    // this small: each HirLocal carries an inline HirExpr init.
    static constexpr u32 kMaxLocals = 4;
    // 2 guards cover the canonical DESIGN.md examples (1 guard short-circuits
    // the request, rarely 2 for compound checks). Each HirGuard is ~4.5 KB
    // inline, so raising this directly grows HirRoute on the stack — see
    // HirExpr::kMaxArgs comment for the recursive-analyze stack budget.
    static constexpr u32 kMaxGuards = 2;
    static constexpr u32 kMaxIfs = 1;
    static constexpr u32 kMaxMatches = 1;
    static constexpr u32 kMaxSteps = kMaxLocals + kMaxGuards + kMaxIfs + kMaxMatches + 2;
    FixedVec<Step, kMaxSteps> steps;
    FixedVec<HirLocal, kMaxLocals> locals;
    FixedVec<HirGuard, kMaxGuards> guards;
    FixedVec<HirForLoopIf, kMaxIfs> ifs;
    FixedVec<HirForLoopMatch, kMaxMatches> matches;
    HirTerminator term{};
    bool has_term = false;
};

struct HirForLoop {
    Span span{};
    // Iteration source. Must type-check as Array<T>; the element type T
    // binds the loop variable's HirTypeKind below. iter_expr's HirExpr*
    // subfields point into HirRoute::exprs, so they need rebase too.
    HirExpr iter_expr{};
    // Loop variable (e.g., `item` in `for item in xs`). Scope is the body
    // only. analyze pushes it into route.locals so body HirExpr LocalRefs
    // bind to a stable ref_index (required once MIR unroll substitutes per
    // iteration), then *clears the name* after body analysis — Ident
    // resolution scans locals by name so post-loop code can't reach the
    // loop variable, and next_local_ref_index still won't reuse the slot.
    Str loop_var_name{};
    HirTypeKind loop_var_type = HirTypeKind::Unknown;
    u32 loop_var_variant_index = 0xffffffffu;
    u32 loop_var_struct_index = 0xffffffffu;
    u32 loop_var_shape_index = 0xffffffffu;
    // Value that body LocalRefs carry in `local_index` when they refer to
    // the loop variable. Set at analyze time from loop_var.ref_index; MIR
    // unroll matches against this to substitute the per-iteration element.
    u32 loop_var_ref_index = 0xffffffffu;
    HirForLoopBody body{};
};

// WebSocket terminate-mode frame-handler verdict. Mirrors the runtime
// `WsFrameAction` (ws_terminate.h): the per-message disposition the JIT'd
// handler returns. Slice B only produces `Forward` (forward-only / empty
// body); Drop/Close are follow-up slices.
enum class WsVerdict : u8 {
    Forward,
    Drop,
    Close,
};

// HIR of a `websocket(<upstream>) { <frame-handler> }` terminate route. A frame
// handler is a pure verdict function `(opcode, payload, len) -> WsVerdict`, not
// an HTTP terminator, so it lives beside HirRoute.control rather than in it.
// Slice B: forward-only, so just the default verdict + the resolved upstream.
// One guard in a terminate handler — a condition on a frame accessor that, when FALSE for a
// message, yields `verdict` (the else branch). Two accessors so far:
//   Len        — `guard frame.len <cmp> N`            : the reassembled message length (len param)
//   Opcode     — `guard frame.isText`/`isBinary`      : the message opcode (== Text / == Binary)
//   FromClient — `guard frame.fromClient`             : the direction (== 1 on the client leg)
//   TextMatch  — `guard [not] frame.text.matches(re)` : a regex scan over the message payload
struct WsLenGuard {
    enum class Accessor : u8 { Len, Opcode, FromClient, TextMatch };
    // Rut's comparison operators are only `<` `>` `==` (no `<=`/`>=`/`!=`), so these three
    // cover every guard condition analyze can produce. Opcode guards always use Eq.
    enum class Cmp : u8 { Lt, Gt, Eq };
    Accessor accessor = Accessor::Len;
    Cmp cmp = Cmp::Lt;
    u32 bound = 0;  // Len: the byte literal frame.len is compared to. Opcode: the WsOpcode value.
    // TextMatch only: the regex pattern (points into source/intern memory; valid through
    // codegen) and whether a leading `not` inverts the match.
    Str pattern{};
    bool negate = false;
    WsVerdict verdict = WsVerdict::Drop;  // yielded when the guard fails
};

struct HirWsHandler {
    WsVerdict default_verdict = WsVerdict::Forward;
    // `guard frame.len <cmp> N else { <verdict> }` checks, in source order, evaluated before the
    // default verdict; the first failing guard's verdict wins. (frame.len maps to the message
    // length the engine passes; richer accessors — text/payload/opcode — are a follow-up.)
    static constexpr u32 kMaxLenGuards = 4;
    FixedVec<WsLenGuard, kMaxLenGuards> len_guards;
    // `frame.forward(payload)` modify form: forward a rewritten message instead of the
    // original. The payload expression (Str-typed) is stored in HirRoute.exprs;
    // forward_payload_expr is its index there (0xffffffffu when has_forward_payload is false).
    // Lowering the modify path (the bounded output buffer) is Phase 4b; build_mir still rejects.
    bool has_forward_payload = false;
    u32 forward_payload_expr = 0xffffffffu;
    // `frame.close(code)` status code (default 1000 = normal closure). Only meaningful when
    // default_verdict == Close. Validated to RFC 6455 application close codes in analyze.
    u16 close_code = 1000;
    // `maxMessageSize:` kwarg in bytes (0 = omitted → the loader uses the engine default). The
    // runtime arm-time clamps this to one slice (~16 KB); a larger value is silently capped.
    u32 max_message_size = 0;
    u32 upstream_index = 0;
    Span span{};
};

struct HirRoute {
    // True for the scratch route used to analyze helper bodies (magic `req`
    // functions) — capture validation and other per-route checks defer to the
    // concrete attached route. NOT the same as a concrete route whose path
    // happens to be empty (PR #164 round 7).
    bool is_helper_scratch = false;
    // Analysis-only flags (never serialized). cache_ops_blocked: the route
    // body contains a wait, so CacheGet/CacheSet are rejected (locals
    // re-materialize on resume — the op would run after the wait).
    // cache_set_stmt_ok: one-shot permission set by a supported bare-statement
    // path and consumed by the cache.set receiver. A set remains illegal in
    // value position, where eager lowering could run it on non-taken paths.
    bool cache_ops_blocked = false;
    bool cache_set_stmt_ok = false;
    // One-shot permission for a bare `req.set(...)` statement. Like Cache.set,
    // request mutation cannot escape into an eager/lazy value expression.
    bool req_header_mutation_stmt_ok = false;
    // Analysis-only (never serialized): the route body contains a wait, so
    // time.nowMicros() is rejected — locals re-materialize on resume, and a
    // pre-wait timestamp binding would sample after the wait.
    bool time_ops_blocked = false;
    struct DecoratorRef {
        Span span{};
        Str name{};
        u32 function_index = 0xffffffffu;  // resolved in analyze; 0xffffffffu = unresolved
    };
    struct Wait {
        Span span{};
        WaitEventKind event_kind = WaitEventKind::Timer;
        u32 ms = 0;  // duration in milliseconds; packed into the u32 yield
                     // payload (status_code + upstream_id) at codegen time.
                     // Parser caps at UINT32_MAX (~49 days).
        u8 arm_mask = kWaitEventArmTimer;
    };

    Span span{};
    u8 method = 0;
    Str path{};
    static constexpr u32 kMaxLocals = 16;
    static constexpr u32 kMaxGuards = 8;
    static constexpr u32 kMaxExprs = 64;
    static constexpr u32 kMaxDecorators = 8;
    static constexpr u32 kMaxWaits = kMaxRouteWaits;
    // 2 for-loops per route covers realistic DSL patterns (one allowlist
    // check + one server-pool iteration) while keeping HirRoute under the
    // stack budget. Each HirForLoop is ~10 KB even at kMaxGuards=2; a
    // larger cap would push HirRoute past the recursive-analyze budget.
    static constexpr u32 kMaxForLoops = 2;
    FixedVec<HirExpr, kMaxExprs> exprs;
    FixedVec<HirLocal, kMaxLocals> locals;
    FixedVec<HirGuard, kMaxGuards> guards;
    FixedVec<DecoratorRef, kMaxDecorators> decorators;
    u32 decorator_guard_count = 0;
    FixedVec<Wait, kMaxWaits> waits;
    FixedVec<HirForLoop, kMaxForLoops> for_loops;
    HirControl control{};
    bool allow_respond_effects = false;
    u32 error_variant_index = 0xffffffffu;
    // @rateLimit decorators → stacked fixed-window rules (empty = no limit).
    // Flows to the RIR Function and on to RouteConfig rate-limit setup.
    RateLimitRuleSet rate_limit{};
    // @throttle decorator → client-send byte rate (bytes/sec, 0 = none).
    u32 throttle_down_bps = 0;
    // WebSocket terminate mode: when the route body is `websocket(x){...}`, this
    // route has no HTTP terminator — `ws_handler` carries the frame-handler
    // verdict instead and `control` is unused. (Slice B; lowering rejects it
    // until the JIT path lands.)
    bool is_ws_terminate = false;
    HirWsHandler ws_handler{};
    // Timer route: the body is a `timer name, every: D {...}` background periodic
    // task, not an HTTP route. `path` holds the timer name; `timer_interval_ms`
    // the period. Registered into RouteConfig.timers[] (not routes[]) and fired by
    // the shard event loop instead of matched against requests.
    bool is_timer = false;
    u32 timer_interval_ms = 0;
    // `shard: N` — fire on that shard only; -1 = every shard (default).
    i32 timer_shard = -1;

    HirRoute() = default;
    HirRoute(const HirRoute& other)
        : span(other.span),
          method(other.method),
          path(other.path),
          exprs(other.exprs),
          locals(other.locals),
          guards(other.guards),
          decorators(other.decorators),
          decorator_guard_count(other.decorator_guard_count),
          waits(other.waits),
          for_loops(other.for_loops),
          control(other.control),
          allow_respond_effects(other.allow_respond_effects),
          error_variant_index(other.error_variant_index),
          rate_limit(other.rate_limit),
          throttle_down_bps(other.throttle_down_bps),
          is_ws_terminate(other.is_ws_terminate),
          ws_handler(other.ws_handler),
          is_timer(other.is_timer),
          timer_interval_ms(other.timer_interval_ms),
          timer_shard(other.timer_shard) {
        rebase_from(other);
    }
    HirRoute& operator=(const HirRoute& other) {
        if (this == &other) return *this;
        span = other.span;
        method = other.method;
        path = other.path;
        exprs = other.exprs;
        locals = other.locals;
        guards = other.guards;
        decorators = other.decorators;
        decorator_guard_count = other.decorator_guard_count;
        waits = other.waits;
        for_loops = other.for_loops;
        control = other.control;
        allow_respond_effects = other.allow_respond_effects;
        error_variant_index = other.error_variant_index;
        rate_limit = other.rate_limit;
        throttle_down_bps = other.throttle_down_bps;
        is_ws_terminate = other.is_ws_terminate;
        ws_handler = other.ws_handler;
        is_timer = other.is_timer;
        timer_interval_ms = other.timer_interval_ms;
        timer_shard = other.timer_shard;
        rebase_from(other);
        return *this;
    }
    HirRoute(HirRoute&& other) noexcept
        : span(other.span),
          method(other.method),
          path(other.path),
          exprs(other.exprs),
          locals(other.locals),
          guards(other.guards),
          decorators(other.decorators),
          decorator_guard_count(other.decorator_guard_count),
          waits(other.waits),
          for_loops(other.for_loops),
          control(other.control),
          allow_respond_effects(other.allow_respond_effects),
          error_variant_index(other.error_variant_index),
          rate_limit(other.rate_limit),
          throttle_down_bps(other.throttle_down_bps),
          is_ws_terminate(other.is_ws_terminate),
          ws_handler(other.ws_handler),
          is_timer(other.is_timer),
          timer_interval_ms(other.timer_interval_ms),
          timer_shard(other.timer_shard) {
        rebase_from(other);
    }
    HirRoute& operator=(HirRoute&& other) noexcept {
        if (this == &other) return *this;
        span = other.span;
        method = other.method;
        path = other.path;
        exprs = other.exprs;
        locals = other.locals;
        guards = other.guards;
        decorators = other.decorators;
        decorator_guard_count = other.decorator_guard_count;
        waits = other.waits;
        for_loops = other.for_loops;
        control = other.control;
        allow_respond_effects = other.allow_respond_effects;
        error_variant_index = other.error_variant_index;
        rate_limit = other.rate_limit;
        throttle_down_bps = other.throttle_down_bps;
        is_ws_terminate = other.is_ws_terminate;
        ws_handler = other.ws_handler;
        is_timer = other.is_timer;
        timer_interval_ms = other.timer_interval_ms;
        timer_shard = other.timer_shard;
        rebase_from(other);
        return *this;
    }

private:
    void rebase_expr_ptr(const HirRoute& other, HirExpr*& ptr) {
        if (ptr == nullptr) return;
        const auto begin = &other.exprs.data[0];
        const auto end = begin + other.exprs.len;
        if (ptr < begin || ptr >= end) return;
        const u32 index = static_cast<u32>(ptr - begin);
        ptr = &exprs.data[index];
    }

    void rebase_expr(HirExpr& expr, const HirRoute& other) {
        rebase_expr_ptr(other, expr.lhs);
        rebase_expr_ptr(other, expr.rhs);
        for (u32 i = 0; i < expr.field_inits.len; i++) {
            rebase_expr_ptr(other, expr.field_inits[i].value);
        }
        for (u32 i = 0; i < expr.args.len; i++) {
            rebase_expr_ptr(other, expr.args[i]);
        }
    }

    void rebase_guard(HirGuard& guard, const HirRoute& other) {
        rebase_expr(guard.cond, other);
        rebase_expr(guard.fail_match_expr, other);
        for (u32 li = 0; li < guard.fail_body.locals.len; li++) {
            rebase_expr(guard.fail_body.locals[li].init, other);
        }
        rebase_expr(guard.fail_body.cond, other);
    }

    void rebase_from(const HirRoute& other) {
        for (u32 i = 0; i < exprs.len; i++) rebase_expr(exprs[i], other);
        for (u32 i = 0; i < locals.len; i++) rebase_expr(locals[i].init, other);
        for (u32 i = 0; i < guards.len; i++) {
            rebase_guard(guards[i], other);
        }
        // For-loops: iter_expr and the body's guard conds all point into
        // `exprs`, so rebase them the same way as top-level guards.
        for (u32 i = 0; i < for_loops.len; i++) {
            rebase_expr(for_loops[i].iter_expr, other);
            for (u32 li = 0; li < for_loops[i].body.locals.len; li++) {
                rebase_expr(for_loops[i].body.locals[li].init, other);
            }
            for (u32 gi = 0; gi < for_loops[i].body.guards.len; gi++) {
                rebase_guard(for_loops[i].body.guards[gi], other);
            }
            for (u32 ii = 0; ii < for_loops[i].body.ifs.len; ii++) {
                rebase_expr(for_loops[i].body.ifs[ii].cond, other);
            }
            for (u32 mi = 0; mi < for_loops[i].body.matches.len; mi++) {
                rebase_expr(for_loops[i].body.matches[mi].match_expr, other);
                for (u32 ai = 0; ai < for_loops[i].body.matches[mi].arms.len; ai++) {
                    rebase_expr(for_loops[i].body.matches[mi].arms[ai].pattern, other);
                    rebase_expr(for_loops[i].body.matches[mi].arms[ai].arm_guard, other);
                    for (u32 li = 0; li < for_loops[i].body.matches[mi].arms[ai].locals.len; li++) {
                        rebase_expr(for_loops[i].body.matches[mi].arms[ai].locals[li].init, other);
                    }
                    for (u32 gi = 0; gi < for_loops[i].body.matches[mi].arms[ai].guards.len; gi++) {
                        rebase_guard(for_loops[i].body.matches[mi].arms[ai].guards[gi], other);
                    }
                    rebase_expr(for_loops[i].body.matches[mi].arms[ai].cond, other);
                }
            }
        }
        rebase_expr(control.cond, other);
        rebase_expr(control.match_expr, other);
        for (u32 i = 0; i < control.match_arms.len; i++) {
            rebase_expr(control.match_arms[i].pattern, other);
            rebase_expr(control.match_arms[i].arm_guard, other);
            for (u32 gi = 0; gi < control.match_arms[i].guards.len; gi++) {
                rebase_guard(control.match_arms[i].guards[gi], other);
            }
            rebase_expr(control.match_arms[i].cond, other);
        }
    }
};

struct HirImplMethod {
    Str name{};
    u32 function_index = 0xffffffffu;
};

struct HirAssociatedTypeBinding {
    Str name{};
    HirTypeKind type = HirTypeKind::Unknown;
    u32 generic_index = 0xffffffffu;
    u32 variant_index = 0xffffffffu;
    u32 struct_index = 0xffffffffu;
    u32 tuple_len = 0;
    HirTypeKind tuple_types[kMaxTupleSlots]{};
    u32 tuple_variant_indices[kMaxTupleSlots]{};
    u32 tuple_struct_indices[kMaxTupleSlots]{};
    u32 shape_index = 0xffffffffu;
};

struct HirImpl {
    static constexpr u32 kMaxMethods = 8;
    static constexpr u32 kMaxAssociatedTypes = 8;
    Span span{};
    u32 protocol_index = 0xffffffffu;
    HirTypeKind type = HirTypeKind::Unknown;
    u32 struct_index = 0xffffffffu;
    bool is_generic_template = false;
    FixedVec<HirAssociatedTypeBinding, kMaxAssociatedTypes> associated_types;
    FixedVec<HirImplMethod, kMaxMethods> methods;
};

struct HirCacheDecl {
    Span span{};
    Str name{};
    u32 capacity = 0;
};

struct HirModule {
    static constexpr u32 kMaxUpstreams = 32;
    static constexpr u32 kMaxImports = 64;
    static constexpr u32 kMaxAliases = 64;
    static constexpr u32 kMaxTypeAliases = 64;
    static constexpr u32 kMaxFunctions = 64;
    static constexpr u32 kMaxStructs = 64;
    static constexpr u32 kMaxVariants = 64;
    static constexpr u32 kMaxProtocols = 32;
    static constexpr u32 kMaxConformances = 64;
    static constexpr u32 kMaxImpls = 64;
    static constexpr u32 kMaxRoutes = 96;
    // Timers compile to routes (is_timer flag) to reuse route→MIR→codegen, but are
    // registered into RouteConfig.timers[] (a separate kMaxTimers table) at load,
    // so they must NOT consume HTTP-route capacity. The routes vector is sized to
    // hold both; analyze.cc caps HTTP routes at kMaxRoutes and timers at kMaxTimers
    // independently. kMaxTimers must match RouteConfig::kMaxTimers (static_assert in
    // compile_to_config.h).
    static constexpr u32 kMaxTimers = 16;
    static constexpr u32 kMaxGuardMatchArms = 64;
    static constexpr u32 kMaxTypeShapes = 512;
    // Must not exceed RouteConfig::kMaxCacheInstances (static_assert in
    // compile_to_config.h).
    static constexpr u32 kMaxCaches = 8;

    FixedVec<HirUpstream, kMaxUpstreams> upstreams;
    FixedVec<HirCacheDecl, kMaxCaches> caches;
    FixedVec<HirImport, kMaxImports> imports;
    FixedVec<HirAlias, kMaxAliases> aliases;
    std::deque<AstTypeRef> type_ref_storage;
    FixedVec<HirTypeAlias, kMaxTypeAliases> type_aliases;
    FixedVec<HirFunction, kMaxFunctions> functions;
    FixedVec<HirStruct, kMaxStructs> structs;
    FixedVec<HirVariant, kMaxVariants> variants;
    FixedVec<HirProtocol, kMaxProtocols> protocols;
    FixedVec<HirConformance, kMaxConformances> conformances;
    FixedVec<HirImpl, kMaxImpls> impls;
    FixedVec<HirGuardMatchArm, kMaxGuardMatchArms> guard_match_arms;
    // Holds HTTP routes (≤kMaxRoutes) plus synthesized timer routes (≤kMaxTimers).
    FixedVec<HirRoute, kMaxRoutes + kMaxTimers> routes;
    FixedVec<HirTypeShape, kMaxTypeShapes> type_shapes;
    // Shared across HirModule copies so every copied Str view continues to
    // reference stable bytes after the source module is destroyed.
    mutable std::shared_ptr<std::deque<std::string>> owned_strings =
        std::make_shared<std::deque<std::string>>();
    // Recursive import analysis points this at the root module's storage so
    // generated Str views copied out of an imported HIR remain valid. It is an
    // analysis-only target; copied modules use their shared owned_strings.
    mutable std::deque<std::string>* analysis_owned_strings = nullptr;
    bool has_package_decl = false;
    Span package_span{};
    Str package_name{};

    HirModule() = default;
    HirModule(const HirModule& other)
        : upstreams(other.upstreams),
          caches(other.caches),
          imports(other.imports),
          aliases(other.aliases),
          type_ref_storage(other.type_ref_storage),
          type_aliases(other.type_aliases),
          functions(other.functions),
          structs(other.structs),
          variants(other.variants),
          protocols(other.protocols),
          conformances(other.conformances),
          impls(other.impls),
          guard_match_arms(other.guard_match_arms),
          routes(other.routes),
          type_shapes(other.type_shapes),
          owned_strings(other.owned_strings),
          has_package_decl(other.has_package_decl),
          package_span(other.package_span),
          package_name(other.package_name) {
        rebase_type_alias_storage_ptrs(other);
    }
    HirModule& operator=(const HirModule& other) {
        if (this == &other) return *this;
        upstreams = other.upstreams;
        caches = other.caches;
        imports = other.imports;
        aliases = other.aliases;
        type_ref_storage = other.type_ref_storage;
        type_aliases = other.type_aliases;
        functions = other.functions;
        structs = other.structs;
        variants = other.variants;
        protocols = other.protocols;
        conformances = other.conformances;
        impls = other.impls;
        guard_match_arms = other.guard_match_arms;
        routes = other.routes;
        type_shapes = other.type_shapes;
        owned_strings = other.owned_strings;
        analysis_owned_strings = nullptr;
        has_package_decl = other.has_package_decl;
        package_span = other.package_span;
        package_name = other.package_name;
        rebase_type_alias_storage_ptrs(other);
        return *this;
    }
    HirModule(HirModule&& other) noexcept = delete;
    HirModule& operator=(HirModule&& other) noexcept = delete;

    void rebase_type_alias_storage_ptrs(const HirModule& other) {
        for (u32 i = 0; i < type_aliases.len; i++) {
            rebase_type_ref_tree_ptrs(other, type_aliases[i].target);
            for (u32 arm_i = 0; arm_i < type_aliases[i].arms.len; arm_i++)
                rebase_type_ref_tree_ptrs(other, type_aliases[i].arms[arm_i].type);
        }
    }

    void rebase_type_ref_storage_ptr(const HirModule& other, AstTypeRef*& ptr) {
        if (ptr == nullptr) return;
        for (std::size_t i = 0; i < other.type_ref_storage.size(); i++) {
            if (ptr == &other.type_ref_storage[i]) {
                ptr = &type_ref_storage[i];
                return;
            }
        }
    }

    void rebase_type_ref_tree_ptrs(const HirModule& other, AstTypeRef& ref) {
        for (u32 i = 0; i < ref.type_args.len; i++) {
            rebase_type_ref_storage_ptr(other, ref.type_args[i]);
            if (ref.type_args[i] != nullptr) rebase_type_ref_tree_ptrs(other, *ref.type_args[i]);
        }
        for (u32 i = 0; i < ref.tuple_elem_types.len; i++) {
            rebase_type_ref_storage_ptr(other, ref.tuple_elem_types[i]);
            if (ref.tuple_elem_types[i] != nullptr)
                rebase_type_ref_tree_ptrs(other, *ref.tuple_elem_types[i]);
        }
    }
};

}  // namespace rut
