#pragma once

#include "rut/common/rate_limit_key_spec.h"
#include "rut/common/types.h"
#include "rut/compiler/diagnostic.h"

namespace rut {

enum class AstItemKind : u8 {
    Upstream,
    Import,
    Func,
    Struct,
    Variant,
    Protocol,
    Using,
    TypeAlias,
    Impl,
    Chain,
    Route,
    Timer,
};

enum class AstStmtKind : u8 {
    Expr,
    Let,
    Guard,
    ReturnStatus,
    ForwardUpstream,
    // `websocket(<upstream>) { <frame-handler> }` — terminate mode (vs the bare
    // `websocket(x)` passthrough, which stays ForwardUpstream). `name` = upstream
    // identifier; `then_stmt` = the parsed frame-handler body block (reused like For).
    // The body's per-message verdicts (forward/drop/close) are a follow-up slice.
    WsTerminate,
    If,
    Match,
    Block,
    Wait,  // `wait(N)` / `wait(2s)` — suspend handler for a timer duration.
    WaitAny,
    // `for <name> in <expr> { <body> }`. Fields reused from AstStatement:
    //   - name        = loop variable identifier (e.g., "item" in `for item in xs`)
    //   - expr        = iteration source expression (must type-check as Array<T>)
    //   - then_stmt   = body block (via parse_braced_stmt_body; may be a single
    //                   stmt if the block contained exactly one stmt)
    // No break / continue / else / labels (spec §3.3.9: every iteration runs
    // to completion). Analyze (Phase 3b) enforces the iteration source is
    // array-typed and compile-time-sized and builds a HirForLoop. `inline for`
    // is not accepted as a compatibility spelling; static `for` is the single
    // canonical loop surface. MIR build unrolls supported static for-loops into
    // a source-ordered route step chain for Direct, if, and match route control
    // — see mir_build.cc.
    // Runtime iterables remain later work.
    For,
};

enum class WaitEventKind : u8 {
    Timer,
    Any,
    Recv,
    Send,
    UpstreamConnect,
    UpstreamRecv,
    UpstreamSend,
};

enum WaitEventArmMask : u8 {
    kWaitEventArmNone = 0,
    kWaitEventArmTimer = 1u << 0,
    kWaitEventArmRecv = 1u << 1,
    kWaitEventArmSend = 1u << 2,
    kWaitEventArmUpstreamConnect = 1u << 3,
    kWaitEventArmUpstreamRecv = 1u << 4,
    kWaitEventArmUpstreamSend = 1u << 5,
};

inline u8 wait_event_kind_default_arm_mask(WaitEventKind kind, u32 payload = 0) {
    switch (kind) {
        case WaitEventKind::Timer:
            return kWaitEventArmTimer;
        case WaitEventKind::Any:
            return static_cast<u8>(kWaitEventArmRecv |
                                   (payload != 0 ? kWaitEventArmTimer : kWaitEventArmNone));
        case WaitEventKind::Recv:
            return kWaitEventArmRecv;
        case WaitEventKind::Send:
            return kWaitEventArmSend;
        case WaitEventKind::UpstreamConnect:
            return kWaitEventArmUpstreamConnect;
        case WaitEventKind::UpstreamRecv:
            return kWaitEventArmUpstreamRecv;
        case WaitEventKind::UpstreamSend:
            return kWaitEventArmUpstreamSend;
    }
    return kWaitEventArmNone;
}

// Single response header key/value pair, used by `response(N, headers: {...})`.
// Both fields are non-owning views into the lexer's source buffer.
struct AstHeaderKV {
    Str key{};
    Str value{};
};

enum class AstExprKind : u8 {
    BoolLit,
    IntLit,
    StrLit,
    RegexLit,
    Tuple,
    // Array literal `[e1, e2, ...]` — elements stored in `args`.
    // Parser accepts empty `[]`; analyze currently rejects empty array
    // literals unconditionally (Rutlang has no push/append so the element
    // type can't be inferred later). Contextual inference from a surrounding
    // type annotation is deferred; until then `let xs: [i32] = []` also
    // errors.  Surface `[T]` type syntax desugars to
    // `AstTypeRef{name="Array", type_args=[T]}` in parse_func_type_ref.
    ArrayLit,
    StructInit,
    Placeholder,
    VariantCase,
    Call,
    MethodCall,
    Field,
    ReqHeader,
    ReqParam,
    ReqCookie,
    ReqQuery,
    ReqQueryString,
    // HTTP method literal as expression. The concrete method (GET,
    // POST, …) is encoded in int_value using the HttpMethod enum
    // values from rut/runtime/http_parser.h. Lets `POST` etc. appear
    // in contexts like `guard req.method == POST else { ... }`.
    LitMethod,
    Nil,
    Error,
    Ident,
    Eq,
    Lt,
    Gt,
    And,
    Or,
    Pipe,
    Wait,
};

struct AstTypeRef {
    static constexpr u32 kMaxTypeArgs = 4;
    Str namespace_name{};
    Str name{};
    bool is_tuple = false;
    static constexpr u32 kMaxTupleElems = 10;
    FixedVec<Str, kMaxTupleElems> tuple_elem_names;
    FixedVec<AstTypeRef*, kMaxTupleElems> tuple_elem_types;
    FixedVec<Str, kMaxTypeArgs> type_arg_names;
    FixedVec<Str, kMaxTypeArgs> type_arg_namespaces;
    FixedVec<AstTypeRef*, kMaxTypeArgs> type_args;
};

struct AstExpr {
    static constexpr u32 kMaxTypeArgs = 4;
    struct FieldInit {
        Str name{};
        AstExpr* value = nullptr;
    };

    AstExprKind kind = AstExprKind::BoolLit;
    Span span{};
    bool bool_value = false;
    i32 int_value = 0;
    Str str_value{};
    Str msg{};
    Str name{};
    AstExpr* lhs = nullptr;
    AstExpr* rhs = nullptr;
    static constexpr u32 kMaxFieldInits = 8;
    // Shared capacity for tuple elements, call arguments, field inits, and
    // array literals. HirExpr::kMaxArgs must stay at 8 (HirRoute stack
    // budget — see the comment there), so keeping AstExpr at 8 too means
    // ArrayLit with > 8 elements fails at parse with TooManyItems at the
    // 9th element's span, instead of parsing successfully and then failing
    // ambiguously in analyze. Once HIR gets an out-of-line element pool
    // for arrays, both caps can rise together.
    static constexpr u32 kMaxArgs = 8;
    FixedVec<FieldInit, kMaxFieldInits> field_inits;
    FixedVec<AstTypeRef, kMaxTypeArgs> type_args;
    FixedVec<AstExpr*, kMaxArgs> args;
    WaitEventKind wait_event_kind = WaitEventKind::Timer;
    u32 wait_ms = 0;
};

struct AstStatement {
    AstStmtKind kind = AstStmtKind::ReturnStatus;
    Span span{};
    Str name{};
    bool bind_value = false;
    // WebSocket frame guard only: a leading `not`/`!` negated the condition
    // (`guard not frame.text.matches(re"…") else { … }`). Set by parse_ws_frame_guard,
    // read by the WsTerminate analyze path; unused by every other statement kind.
    bool cond_negated = false;
    // WsTerminate only: the `maxMessageSize:` kwarg in bytes (`websocket(x, maxMessageSize: 8kb)`),
    // 0 when omitted (the loader then uses the engine default). Carried to HirWsHandler.
    u32 ws_max_message_size = 0;
    bool is_const = false;
    bool has_type = false;
    AstTypeRef type{};
    AstExpr expr{};
    // Dual use: HTTP status code for `return <N>`, or milliseconds for
    // `wait(N)`. u32 fits both the HTTP range and the full u32 yield
    // payload range (~49 days); semantic validation is in analyze.
    u32 status_code = 0;
    WaitEventKind wait_event_kind = WaitEventKind::Timer;
    bool has_wait_expr = false;
    // Response body literal, populated when `return` uses the
    // `response(N, body: "...")` form. `has_response_body` distinguishes
    // an omitted kwarg from an explicit empty string — the latter must
    // still be rejected while body plumbing is not wired end-to-end.
    Str response_body{};
    bool has_response_body = false;
    // Response headers from `response(N, headers: { "K": "V", ... })`.
    // Inline-stored (no external pool) so analyze/lowering don't need
    // the AstFile handle. `response_headers.len == 0` means "no kwarg";
    // the parser rejects the explicit-empty `headers: {}` form so the
    // length uniquely distinguishes "absent" from "present".
    static constexpr u32 kMaxResponseHeaders = 16;
    FixedVec<AstHeaderKV, kMaxResponseHeaders> response_headers;
    // Request-path rewrite from `forward(name, set_path: "...")`. Literal only
    // for now; lowered to a ReqSetPath op before the forward terminator so the
    // proxy rewrites the outbound request line.
    Str forward_set_path{};
    bool has_forward_set_path = false;
    // Request-header overrides from `forward(name, set_header: { "K": "V", ... })`.
    // Inline-stored like response_headers; lowered to ReqSetHeader ops before the
    // forward terminator so the proxy injects/replaces the lines outbound.
    // `forward_set_headers.len == 0` means "no kwarg" (empty dict is rejected).
    static constexpr u32 kMaxForwardSetHeaders = 16;
    FixedVec<AstHeaderKV, kMaxForwardSetHeaders> forward_set_headers;
    AstStatement* then_stmt = nullptr;
    AstStatement* else_stmt = nullptr;
    static constexpr u32 kMaxBlockStatements = 8;
    FixedVec<AstStatement*, kMaxBlockStatements> block_stmts;
    static constexpr u32 kMaxMatchArms = 8;
    struct MatchArm {
        Span span{};
        bool is_wildcard = false;
        bool bind_value = false;
        Str bind_name{};
        AstExpr pattern{};
        bool has_guard = false;
        AstExpr* guard = nullptr;
        AstStatement* stmt = nullptr;
    };
    FixedVec<MatchArm, kMaxMatchArms> match_arms;
};

struct AstUpstreamDecl {
    Span span{};
    Str name{};
    // Optional backend address. Two syntactic forms produce the same
    // fields, distinguished only by what the parser saw after the name:
    //   A. `upstream backend at "127.0.0.1:8080"`
    //      → host_lit = "127.0.0.1:8080", port_is_set = false.
    //   B. `upstream backend { host: "127.0.0.1", port: 8080 }`
    //      → host_lit = "127.0.0.1", port_lit = 8080, port_is_set = true.
    // Analyze parses host_lit + port_lit into (ip u32, port u16) and
    // stores the result on HirUpstream. has_address == false means no
    // address was declared in the DSL (runtime must supply one via
    // add_upstream()). Both forms require an IPv4 literal today;
    // DNS/IPv6 are future work.
    bool has_address = false;
    Str host_lit{};    // raw string from `at "..."` or `host: "..."`
    Span addr_span{};  // points at the address site for diagnostics
    bool port_is_set = false;
    u32 port_lit = 0;  // u32 to fit any parsed IntLit before range check

    //   C. `upstream backend { backends: ["10.0.0.1:8080", "10.0.0.2:8080"] }`
    //      → backend_count > 0, each backend_lits[i] = "host:port".
    //      Analyze parses backend_lits[0] into the primary (ip,port) and
    //      backend_lits[1..] into the extra-backend arrays on HirUpstream,
    //      so existing single-address readers are unchanged. Mutually
    //      exclusive with host_lit/port_lit (the parser rejects mixing).
    static constexpr u32 kMaxBackends = 8;
    u32 backend_count = 0;  // 0 → single-address form via host_lit/port_lit
    Str backend_lits[kMaxBackends]{};

    //   D. `{ ..., health_check: { path: "/healthz", interval: 5s, status: 200 } }`
    //      → hc_enabled = true. path/interval are required when the block is
    //      present; status defaults to 200. Config-only data threaded verbatim
    //      through HIR→MIR→RIR into RouteConfig::set_upstream_health_check; no
    //      runtime probing in this slice.
    bool hc_enabled = false;
    Str hc_path_lit{};             // raw `path:` string literal
    u32 hc_interval_ms = 0;        // `interval:` DurLit converted to ms
    u16 hc_expected_status = 200;  // `status:` IntLit (optional, default 200)
};

struct AstFunctionDecl {
    static constexpr u32 kMaxTypeParams = 4;
    struct TypeParamDecl {
        static constexpr u32 kMaxConstraints = 4;
        Str name{};
        bool has_constraint = false;
        Str constraint_namespace{};
        Str constraint{};
        FixedVec<Str, kMaxConstraints> constraint_namespaces;
        FixedVec<Str, kMaxConstraints> constraints;
    };
    struct ParamDecl {
        Str name{};
        AstTypeRef type{};
        bool has_underscore_label = false;  // `_ name: Type` (Swift-style omitted-label)
    };

    Span span{};
    Str name{};
    bool has_return_type = false;
    AstTypeRef return_type{};
    AstStatement* body = nullptr;
    static constexpr u32 kMaxParams = 8;
    FixedVec<TypeParamDecl, kMaxTypeParams> type_params;
    FixedVec<ParamDecl, kMaxParams> params;
};

struct AstStructDecl {
    static constexpr u32 kMaxTypeParams = 4;
    struct FieldDecl {
        Str name{};
        AstTypeRef type{};
    };

    Span span{};
    Str name{};
    FixedVec<Str, kMaxTypeParams> type_params;
    static constexpr u32 kMaxFields = 8;
    FixedVec<FieldDecl, kMaxFields> fields;
};

struct AstVariantDecl {
    static constexpr u32 kMaxTypeParams = 4;
    struct CaseDecl {
        Str name{};
        bool has_payload = false;
        AstTypeRef payload_type{};
    };

    Span span{};
    Str name{};
    FixedVec<Str, kMaxTypeParams> type_params;
    static constexpr u32 kMaxCases = 16;
    FixedVec<CaseDecl, kMaxCases> cases;
};

struct AstProtocolDecl {
    static constexpr u32 kMaxMethods = 8;
    static constexpr u32 kMaxParams = 8;
    static constexpr u32 kMaxAssociatedTypes = 8;
    struct AssociatedTypeDecl {
        Str name{};
    };
    struct MethodDecl {
        struct ParamDecl {
            Str name{};
            AstTypeRef type{};
            bool has_underscore_label = false;
        };
        Str name{};
        bool has_return_type = false;
        AstTypeRef return_type{};
        AstStatement* default_body = nullptr;
        FixedVec<ParamDecl, kMaxParams> params;
    };
    Span span{};
    Str name{};
    FixedVec<AssociatedTypeDecl, kMaxAssociatedTypes> associated_types;
    FixedVec<MethodDecl, kMaxMethods> methods;
};

struct AstImportDecl {
    static constexpr u32 kMaxSelectedNames = 16;
    struct SelectedName {
        Str name{};
        bool has_alias = false;
        Str alias{};
    };
    Span span{};
    Str path{};
    bool selective = false;
    bool has_namespace_alias = false;
    Str namespace_alias{};
    FixedVec<SelectedName, kMaxSelectedNames> selected_names;
};

struct AstUsingDecl {
    static constexpr u32 kMaxTargetParts = 8;
    Span span{};
    Str name{};
    FixedVec<Str, kMaxTargetParts> target_parts;
};

struct AstTypeAliasDecl {
    static constexpr u32 kMaxTypeParams = 4;
    static constexpr u32 kMaxArms = 8;
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

struct AstImplDecl {
    static constexpr u32 kMaxProtocols = 4;
    static constexpr u32 kMaxMethods = 8;
    static constexpr u32 kMaxAssociatedTypes = 8;
    struct AssociatedTypeBinding {
        Str name{};
        AstTypeRef type{};
    };
    Span span{};
    AstTypeRef target{};
    FixedVec<Str, kMaxProtocols> protocol_namespaces;
    FixedVec<Str, kMaxProtocols> protocols;
    FixedVec<AssociatedTypeBinding, kMaxAssociatedTypes> associated_types;
    FixedVec<AstFunctionDecl, kMaxMethods> methods;
};

struct AstDecorator {
    Span span{};
    Str namespace_name{};  // empty unless @ns.name form
    Str name{};
    // Official built-in decorators carry typed args, interpreted by analyze per
    // name (the parser only accepts a fixed whitelist — no user decorators).
    // @rateLimit(limit: N, window: <duration>, by: <key>): requests per window.
    // The metering key (default per-client-IP) is built from `rate_limit_key`'s
    // components (IP / header / query / cookie / param).
    u32 rate_limit_max = 0;
    u32 rate_limit_window_sec = 0;
    u32 rate_limit_burst = 0;  // token-bucket capacity; 0 → defaults to limit
    RateLimitKeySpec rate_limit_key{};
    RateLimitScope rate_limit_scope = RateLimitScope::Shard;
    // @throttle(downstream: <ByteSize> per <duration>): client-send byte rate,
    // stored as bytes/second (0 = none).
    u32 throttle_down_bps = 0;
};

enum class AstChainStepKind : u8 {
    Before,
    After,
};

struct AstChainDecl {
    struct Step {
        AstChainStepKind kind = AstChainStepKind::Before;
        Span span{};
        AstExpr call{};
        u32 else_status = 0;
    };

    Span span{};
    Str name{};
    static constexpr u32 kMaxSteps = 8;
    FixedVec<Step, kMaxSteps> steps;
};

struct AstChainUse {
    Span span{};
    Str name{};
};

struct AstRouteDecl {
    Span span{};
    Span body_span{};
    u8 method = 0;
    Str path{};
    static constexpr u32 kMaxStatements = 16;
    // Statements live in AstFile::stmt_pool (alloc_stmt) — storing them
    // inline made sizeof(AstItem) ~485KB (AstStatement is ~23KB) and the
    // recursive-descent parser's by-value AstItem frames overflowed the 8MB
    // stack under gcc 16 Debug. Same treatment the AstTimerDecl comment
    // already prescribed for large inline statement storage.
    FixedVec<AstStatement*, kMaxStatements> statements;
    static constexpr u32 kMaxDecorators = 8;
    FixedVec<AstDecorator, kMaxDecorators> decorators;
    static constexpr u32 kMaxChains = 4;
    FixedVec<AstChainUse, kMaxChains> chains;
};

// Background periodic task: `timer name, every: <duration> { <body> }`. The body
// compiles to a no-request/no-response state-machine handler the shard event loop
// fires every interval. (slice 1: `shard:` selector deferred — runs every shard.)
struct AstTimerDecl {
    Span span{};
    Span body_span{};
    Str name{};
    u32 interval_ms = 0;
    // Slice 1 rejects any non-empty timer body (no execution yet), so the parser
    // only needs to know whether the body had statements — it does NOT store them.
    // Storing a FixedVec<AstStatement, N> here (AstStatement is large, and AstItem
    // inlines every decl kind) bloated the parser's per-item stack frame enough to
    // overflow on the recursive-import path under clang Debug / ASan. When body
    // execution lands, lift the statements into an out-of-line pool, not inline.
    u32 statement_count = 0;
};

struct AstItem {
    AstItemKind kind = AstItemKind::Upstream;
    Span span{};
    AstUpstreamDecl upstream{};
    AstImportDecl import_decl{};
    AstFunctionDecl func{};
    AstStructDecl struct_decl{};
    AstVariantDecl variant{};
    AstProtocolDecl protocol{};
    AstUsingDecl using_decl{};
    AstTypeAliasDecl type_alias{};
    AstImplDecl impl_decl{};
    AstChainDecl chain{};
    AstRouteDecl route{};
    AstTimerDecl timer{};
};

struct AstFile {
    static constexpr u32 kMaxItems = 128;
    static constexpr u32 kMaxExprPool = 128;
    // Route statements moved out of AstRouteDecl into this pool; sized for
    // kMaxItems routes with several statements each plus nested block bodies.
    static constexpr u32 kMaxStmtPool = 512;
    static constexpr u32 kMaxTypePool = 256;
    FixedVec<AstItem, kMaxItems> items;
    FixedVec<AstExpr, kMaxExprPool> expr_pool;
    FixedVec<AstStatement, kMaxStmtPool> stmt_pool;
    FixedVec<AstTypeRef, kMaxTypePool> type_pool;
    bool has_package_decl = false;
    Span package_span{};
    Str package_name{};

    AstFile() = default;
    AstFile(const AstFile& other)
        : items(other.items),
          expr_pool(other.expr_pool),
          stmt_pool(other.stmt_pool),
          type_pool(other.type_pool) {
        rebase_from(other);
    }
    AstFile& operator=(const AstFile& other) {
        if (this == &other) return *this;
        items = other.items;
        expr_pool = other.expr_pool;
        stmt_pool = other.stmt_pool;
        type_pool = other.type_pool;
        rebase_from(other);
        return *this;
    }
    AstFile(AstFile&& other) noexcept
        : items(other.items),
          expr_pool(other.expr_pool),
          stmt_pool(other.stmt_pool),
          type_pool(other.type_pool) {
        rebase_from(other);
    }
    AstFile& operator=(AstFile&& other) noexcept {
        if (this == &other) return *this;
        items = other.items;
        expr_pool = other.expr_pool;
        stmt_pool = other.stmt_pool;
        type_pool = other.type_pool;
        rebase_from(other);
        return *this;
    }

private:
    void rebase_type_ptr(const AstFile& other, AstTypeRef*& ptr) {
        if (ptr == nullptr) return;
        const auto begin = &other.type_pool.data[0];
        const auto end = begin + other.type_pool.len;
        if (ptr < begin || ptr >= end) return;
        const u32 index = static_cast<u32>(ptr - begin);
        ptr = &type_pool.data[index];
    }

    void rebase_expr_ptr(const AstFile& other, AstExpr*& ptr) {
        if (ptr == nullptr) return;
        const auto begin = &other.expr_pool.data[0];
        const auto end = begin + other.expr_pool.len;
        if (ptr < begin || ptr >= end) return;
        const u32 index = static_cast<u32>(ptr - begin);
        ptr = &expr_pool.data[index];
    }

    void rebase_stmt_ptr(const AstFile& other, AstStatement*& ptr) {
        if (ptr == nullptr) return;
        const auto begin = &other.stmt_pool.data[0];
        const auto end = begin + other.stmt_pool.len;
        if (ptr < begin || ptr >= end) return;
        const u32 index = static_cast<u32>(ptr - begin);
        ptr = &stmt_pool.data[index];
    }

    void rebase_type_ref(const AstFile& other, AstTypeRef& type) {
        for (u32 i = 0; i < type.tuple_elem_types.len; i++) {
            rebase_type_ptr(other, type.tuple_elem_types[i]);
        }
        for (u32 i = 0; i < type.type_args.len; i++) {
            rebase_type_ptr(other, type.type_args[i]);
        }
    }

    void rebase_expr(const AstFile& other, AstExpr& expr) {
        rebase_expr_ptr(other, expr.lhs);
        rebase_expr_ptr(other, expr.rhs);
        for (u32 i = 0; i < expr.type_args.len; i++) {
            rebase_type_ref(other, expr.type_args[i]);
        }
        for (u32 i = 0; i < expr.field_inits.len; i++) {
            rebase_expr_ptr(other, expr.field_inits[i].value);
        }
        for (u32 i = 0; i < expr.args.len; i++) {
            rebase_expr_ptr(other, expr.args[i]);
        }
    }

    void rebase_stmt(const AstFile& other, AstStatement& stmt) {
        if (stmt.has_type) rebase_type_ref(other, stmt.type);
        rebase_expr(other, stmt.expr);
        rebase_stmt_ptr(other, stmt.then_stmt);
        rebase_stmt_ptr(other, stmt.else_stmt);
        for (u32 i = 0; i < stmt.block_stmts.len; i++) {
            rebase_stmt_ptr(other, stmt.block_stmts[i]);
        }
        for (u32 i = 0; i < stmt.match_arms.len; i++) {
            rebase_expr(other, stmt.match_arms[i].pattern);
            rebase_expr_ptr(other, stmt.match_arms[i].guard);
            rebase_stmt_ptr(other, stmt.match_arms[i].stmt);
        }
    }

    void rebase_func(const AstFile& other, AstFunctionDecl& func) {
        if (func.has_return_type) rebase_type_ref(other, func.return_type);
        for (u32 i = 0; i < func.params.len; i++) {
            rebase_type_ref(other, func.params[i].type);
        }
        rebase_stmt_ptr(other, func.body);
    }

    void rebase_struct(const AstFile& other, AstStructDecl& decl) {
        for (u32 i = 0; i < decl.fields.len; i++) {
            rebase_type_ref(other, decl.fields[i].type);
        }
    }

    void rebase_variant(const AstFile& other, AstVariantDecl& decl) {
        for (u32 i = 0; i < decl.cases.len; i++) {
            if (decl.cases[i].has_payload) rebase_type_ref(other, decl.cases[i].payload_type);
        }
    }

    void rebase_protocol(const AstFile& other, AstProtocolDecl& decl) {
        for (u32 i = 0; i < decl.methods.len; i++) {
            auto& method = decl.methods[i];
            if (method.has_return_type) rebase_type_ref(other, method.return_type);
            for (u32 pi = 0; pi < method.params.len; pi++) {
                rebase_type_ref(other, method.params[pi].type);
            }
            rebase_stmt_ptr(other, method.default_body);
        }
    }

    void rebase_impl(const AstFile& other, AstImplDecl& decl) {
        rebase_type_ref(other, decl.target);
        for (u32 i = 0; i < decl.associated_types.len; i++) {
            rebase_type_ref(other, decl.associated_types[i].type);
        }
        for (u32 i = 0; i < decl.methods.len; i++) {
            rebase_func(other, decl.methods[i]);
        }
    }

    void rebase_type_alias(const AstFile& other, AstTypeAliasDecl& decl) {
        rebase_type_ref(other, decl.target);
        for (u32 i = 0; i < decl.arms.len; i++) {
            rebase_type_ref(other, decl.arms[i].type);
        }
    }

    void rebase_chain(const AstFile& other, AstChainDecl& decl) {
        for (u32 i = 0; i < decl.steps.len; i++) {
            rebase_expr(other, decl.steps[i].call);
        }
    }

    void rebase_from(const AstFile& other) {
        for (u32 i = 0; i < type_pool.len; i++) rebase_type_ref(other, type_pool[i]);
        for (u32 i = 0; i < expr_pool.len; i++) rebase_expr(other, expr_pool[i]);
        for (u32 i = 0; i < stmt_pool.len; i++) rebase_stmt(other, stmt_pool[i]);
        for (u32 i = 0; i < items.len; i++) {
            switch (items[i].kind) {
                case AstItemKind::Func:
                    rebase_func(other, items[i].func);
                    break;
                case AstItemKind::Struct:
                    rebase_struct(other, items[i].struct_decl);
                    break;
                case AstItemKind::Variant:
                    rebase_variant(other, items[i].variant);
                    break;
                case AstItemKind::Protocol:
                    rebase_protocol(other, items[i].protocol);
                    break;
                case AstItemKind::TypeAlias:
                    rebase_type_alias(other, items[i].type_alias);
                    break;
                case AstItemKind::Impl:
                    rebase_impl(other, items[i].impl_decl);
                    break;
                case AstItemKind::Chain:
                    rebase_chain(other, items[i].chain);
                    break;
                case AstItemKind::Route:
                    // Route statements live in stmt_pool (bulk-rebased above);
                    // only the pointers themselves need relocation here.
                    for (u32 j = 0; j < items[i].route.statements.len; j++) {
                        rebase_stmt_ptr(other, items[i].route.statements[j]);
                    }
                    break;
                default:
                    break;
            }
        }
    }
};

}  // namespace rut
