#include "rut/compiler/mir_build.h"

#include <vector>

namespace rut {

// build_mir lowers one MirFunction per HIR route, including synthesized timer
// routes (analyze.cc reserves kMaxRoutes + kMaxTimers HIR route slots). The MIR
// function table must hold all of them, or a config near the route cap plus timers
// would lower into TooManyItems after passing analysis.
static_assert(MirModule::kMaxFunctions >= HirModule::kMaxRoutes + HirModule::kMaxTimers,
              "MIR function capacity must cover all HIR routes plus timers");

namespace {

static Str entry_label() {
    return {"entry", 5};
}

static Str then_label() {
    return {"then", 4};
}

static Str else_label() {
    return {"else", 4};
}

static Str cont_label() {
    return {"cont", 4};
}

static Str fail_label() {
    return {"fail", 4};
}

static Str match_test_label() {
    return {"match_test", 10};
}

static Str match_case_label() {
    return {"match_case", 10};
}

static Str match_default_label() {
    return {"match_default", 13};
}

static MirTypeKind mir_type_kind(HirTypeKind kind) {
    return kind == HirTypeKind::Bool       ? MirTypeKind::Bool
           : kind == HirTypeKind::I32      ? MirTypeKind::I32
           : kind == HirTypeKind::I64      ? MirTypeKind::I64
           : kind == HirTypeKind::Str      ? MirTypeKind::Str
           : kind == HirTypeKind::Method   ? MirTypeKind::Method
           : kind == HirTypeKind::ByteSize ? MirTypeKind::ByteSize
           : kind == HirTypeKind::IP       ? MirTypeKind::IP
           : kind == HirTypeKind::Variant  ? MirTypeKind::Variant
           : kind == HirTypeKind::Tuple    ? MirTypeKind::Tuple
           : kind == HirTypeKind::Struct   ? MirTypeKind::Struct
                                           : MirTypeKind::Unknown;
}

static bool expand_hir_flat_shape(const HirModule& module,
                                  u32 shape_index,
                                  MirTypeKind* type,
                                  u32* variant_index,
                                  u32* struct_index,
                                  u32* tuple_len,
                                  MirTypeKind* tuple_types,
                                  u32* tuple_variant_indices,
                                  u32* tuple_struct_indices) {
    if (shape_index == 0xffffffffu || shape_index >= module.type_shapes.len) return false;
    const auto& shape = module.type_shapes[shape_index];
    *type = mir_type_kind(shape.type);
    *variant_index = shape.variant_index;
    *struct_index = shape.struct_index;
    *tuple_len = shape.tuple_len;
    if (shape.type != HirTypeKind::Tuple) return true;
    for (u32 i = 0; i < shape.tuple_len; i++) {
        const u32 elem_index = shape.tuple_elem_shape_indices[i];
        if (elem_index >= module.type_shapes.len) return false;
        const auto& elem = module.type_shapes[elem_index];
        if (elem.type == HirTypeKind::Tuple) return false;
        tuple_types[i] = mir_type_kind(elem.type);
        tuple_variant_indices[i] = elem.variant_index;
        tuple_struct_indices[i] = elem.struct_index;
    }
    return true;
}

static void apply_expr_shape_if_available(const HirModule& module,
                                          const HirExpr& expr,
                                          MirValue* out) {
    expand_hir_flat_shape(module,
                          expr.shape_index,
                          &out->type,
                          &out->variant_index,
                          &out->struct_index,
                          &out->tuple_len,
                          out->tuple_types,
                          out->tuple_variant_indices,
                          out->tuple_struct_indices);
}

static bool shape_carrier_ready(const MirModule& mir,
                                u32 shape_index,
                                const bool* struct_ready,
                                const bool* variant_ready) {
    if (shape_index >= mir.type_shapes.len) return false;
    const auto& shape = mir.type_shapes[shape_index];
    if (!shape.is_concrete) return false;
    if (shape.type == MirTypeKind::Bool || shape.type == MirTypeKind::I32 ||
        shape.type == MirTypeKind::Str || shape.type == MirTypeKind::Method)
        return true;
    if (shape.type == MirTypeKind::Struct)
        return shape.struct_index < mir.structs.len && struct_ready[shape.struct_index];
    if (shape.type == MirTypeKind::Variant)
        return shape.variant_index < mir.variants.len && variant_ready[shape.variant_index];
    if (shape.type != MirTypeKind::Tuple) return false;
    for (u32 i = 0; i < shape.tuple_len; i++) {
        if (!shape_carrier_ready(
                mir, shape.tuple_elem_shape_indices[i], struct_ready, variant_ready))
            return false;
    }
    return true;
}

static bool shape_slot_carrier_ready(const MirModule& mir,
                                     u32 shape_index,
                                     const bool* struct_ready,
                                     const bool* variant_ready) {
    if (shape_index >= mir.type_shapes.len) return false;
    const auto& shape = mir.type_shapes[shape_index];
    if (!shape.is_concrete) return false;
    if (shape.type == MirTypeKind::Method) return false;
    if (shape.type == MirTypeKind::Bool || shape.type == MirTypeKind::I32 ||
        shape.type == MirTypeKind::Str)
        return true;
    if (shape.type == MirTypeKind::Struct)
        return shape.struct_index < mir.structs.len && struct_ready[shape.struct_index];
    if (shape.type == MirTypeKind::Variant)
        return shape.variant_index < mir.variants.len && variant_ready[shape.variant_index];
    if (shape.type != MirTypeKind::Tuple) return false;
    for (u32 i = 0; i < shape.tuple_len; i++) {
        if (!shape_carrier_ready(
                mir, shape.tuple_elem_shape_indices[i], struct_ready, variant_ready))
            return false;
    }
    return true;
}

static bool instance_arg_concrete(const MirModule& mir, MirTypeKind type, u32 shape_index) {
    if (shape_index != 0xffffffffu) {
        if (shape_index >= mir.type_shapes.len) return false;
        return mir.type_shapes[shape_index].is_concrete;
    }
    return type != MirTypeKind::Unknown;
}

static bool instance_fully_concrete(const MirModule& mir,
                                    u32 arg_count,
                                    const MirTypeKind* arg_types,
                                    const u32* shape_indices) {
    for (u32 ai = 0; ai < arg_count; ai++) {
        if (!instance_arg_concrete(mir, arg_types[ai], shape_indices[ai])) return false;
    }
    return true;
}

static bool is_open_generic_struct_decl(const MirStruct& st) {
    return st.type_params.len != 0 && st.template_struct_index == 0xffffffffu;
}

static bool is_open_generic_variant_decl(const MirVariant& variant) {
    return variant.type_params.len != 0 && variant.template_variant_index == 0xffffffffu;
}

static bool field_carrier_ready(const MirModule& mir,
                                const MirStruct::FieldDecl& field,
                                const bool* struct_ready,
                                const bool* variant_ready) {
    if (field.is_error_type) return true;
    if (field.shape_index != 0xffffffffu)
        return shape_slot_carrier_ready(mir, field.shape_index, struct_ready, variant_ready);
    // Note: Method is intentionally omitted here (and in the variant
    // payload analog below). lower_rir's struct-field and variant-
    // payload builders don't yet have a Method carrier — a
    // Method-typed struct field / payload would lower to an Optional
    // <I32> slot and fail in emit_struct_create. Method as a plain
    // value is fine (shape_carrier_ready accepts it) because it's
    // lowered as a bare i8; these per-field helpers only run when
    // there's no shape index to delegate to, so until someone wires
    // Method into the carrier builders, reporting it as "ready"
    // here would mislead the lowering pass. Today's surface DSL
    // can't declare Method-typed struct fields anyway.
    if (field.type == MirTypeKind::Bool || field.type == MirTypeKind::I32 ||
        field.type == MirTypeKind::Str)
        return true;
    if (field.type == MirTypeKind::Struct)
        return field.struct_index < mir.structs.len && struct_ready[field.struct_index];
    if (field.type == MirTypeKind::Variant)
        return field.variant_index < mir.variants.len && variant_ready[field.variant_index];
    return false;
}

static bool variant_payload_carrier_ready(const MirModule& mir,
                                          const MirVariant::CaseDecl& c,
                                          const bool* struct_ready,
                                          const bool* variant_ready) {
    if (!c.has_payload) return true;
    if (c.payload_shape_index != 0xffffffffu)
        return shape_slot_carrier_ready(mir, c.payload_shape_index, struct_ready, variant_ready);
    // See field_carrier_ready: Method payloads have no lower_rir
    // carrier yet, so don't claim they're ready.
    if (c.payload_type == MirTypeKind::Bool || c.payload_type == MirTypeKind::I32 ||
        c.payload_type == MirTypeKind::Str)
        return true;
    if (c.payload_type == MirTypeKind::Struct)
        return c.payload_struct_index < mir.structs.len && struct_ready[c.payload_struct_index];
    if (c.payload_type == MirTypeKind::Variant)
        return c.payload_variant_index < mir.variants.len && variant_ready[c.payload_variant_index];
    return false;
}

// Context for MIR for-loop unrolling. When lowering the body of a HirForLoop
// iteration, the caller passes a non-null ctx so LocalRefs to the loop variable
// or body-local bindings are replaced with the current iteration's MirValues.
// External callers pass nullptr: route-level code cannot reference those
// bindings because analyze clears their names after the body.
struct ForLoopCtx {
    struct LocalBinding {
        u32 ref_index = 0xffffffffu;
        const MirValue* value = nullptr;
    };
    FixedVec<LocalBinding, HirRoute::kMaxLocals> locals;
};

static FrontendResult<MirValue> mir_value(const HirExpr& expr,
                                          const HirModule& module,
                                          MirFunction* fn,
                                          const ForLoopCtx* ctx = nullptr) {
    MirValue v{};
    v.shape_index = expr.shape_index;
    v.may_nil = expr.may_nil;
    v.may_error = expr.may_error;
    if (expr.kind == HirExprKind::BoolLit) {
        v.kind = MirValueKind::BoolConst;
        v.type = MirTypeKind::Bool;
        v.bool_value = expr.bool_value;
        return v;
    }
    if (expr.kind == HirExprKind::IntLit) {
        v.kind = MirValueKind::IntConst;
        v.type = mir_type_kind(expr.type);  // I32 or I64
        v.int_value = expr.int_value;
        return v;
    }
    if (expr.kind == HirExprKind::StrLit) {
        v.kind = MirValueKind::StrConst;
        v.type = MirTypeKind::Str;
        v.str_value = expr.str_value;
        return v;
    }
    if (expr.kind == HirExprKind::RegexMatch) {
        auto lhs = mir_value(*expr.lhs, module, fn, ctx);
        if (!lhs) return core::make_unexpected(lhs.error());
        if (!fn->values.push(lhs.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = MirValueKind::RegexMatch;
        v.type = MirTypeKind::Bool;
        v.str_value = expr.str_value;
        v.lhs = &fn->values[fn->values.len - 1];
        return v;
    }
    if (expr.kind == HirExprKind::Tuple) {
        v.kind = MirValueKind::Tuple;
        v.type = MirTypeKind::Tuple;
        v.tuple_len = expr.tuple_len;
        for (u32 i = 0; i < expr.tuple_len; i++) {
            v.tuple_types[i] = mir_type_kind(expr.tuple_types[i]);
            v.tuple_variant_indices[i] = expr.tuple_variant_indices[i];
            v.tuple_struct_indices[i] = expr.tuple_struct_indices[i];
        }
        expand_hir_flat_shape(module,
                              expr.shape_index,
                              &v.type,
                              &v.variant_index,
                              &v.struct_index,
                              &v.tuple_len,
                              v.tuple_types,
                              v.tuple_variant_indices,
                              v.tuple_struct_indices);
        for (u32 i = 0; i < expr.args.len; i++) {
            auto elem = mir_value(*expr.args[i], module, fn, ctx);
            if (!elem) return core::make_unexpected(elem.error());
            if (!fn->values.push(elem.value()))
                return frontend_error(FrontendError::TooManyItems, expr.span);
            if (!v.args.push(&fn->values[fn->values.len - 1]))
                return frontend_error(FrontendError::TooManyItems, expr.span);
        }
        return v;
    }
    if (expr.kind == HirExprKind::StructInit) {
        v.kind = MirValueKind::StructInit;
        v.type = MirTypeKind::Struct;
        v.struct_index = expr.struct_index;
        v.str_value = expr.str_value;
        apply_expr_shape_if_available(module, expr, &v);
        for (u32 i = 0; i < expr.field_inits.len; i++) {
            auto field_value = mir_value(*expr.field_inits[i].value, module, fn, ctx);
            if (!field_value) return core::make_unexpected(field_value.error());
            if (!fn->values.push(field_value.value()))
                return frontend_error(FrontendError::TooManyItems, expr.span);
            MirValue::FieldInit field_init{};
            field_init.name = expr.field_inits[i].name;
            field_init.value = &fn->values[fn->values.len - 1];
            if (!v.field_inits.push(field_init))
                return frontend_error(FrontendError::TooManyItems, expr.span);
        }
        return v;
    }
    if (expr.kind == HirExprKind::TupleSlot) {
        auto lhs = mir_value(*expr.lhs, module, fn, ctx);
        if (!lhs) return core::make_unexpected(lhs.error());
        if (!fn->values.push(lhs.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = MirValueKind::TupleSlot;
        v.type = mir_type_kind(expr.type);
        v.variant_index = expr.variant_index;
        v.struct_index = expr.struct_index;
        v.int_value = expr.int_value;
        v.lhs = &fn->values[fn->values.len - 1];
        apply_expr_shape_if_available(module, expr, &v);
        return v;
    }
    if (expr.kind == HirExprKind::VariantCase) {
        v.kind = MirValueKind::VariantCase;
        v.type = MirTypeKind::Variant;
        v.variant_index = expr.variant_index;
        v.case_index = expr.case_index;
        v.error_variant_index = expr.error_variant_index;
        v.error_case_index = expr.error_case_index;
        v.int_value = expr.int_value;
        apply_expr_shape_if_available(module, expr, &v);
        if (expr.lhs != nullptr) {
            auto payload = mir_value(*expr.lhs, module, fn, ctx);
            if (!payload) return core::make_unexpected(payload.error());
            if (!fn->values.push(payload.value()))
                return frontend_error(FrontendError::TooManyItems, expr.span);
            v.lhs = &fn->values[fn->values.len - 1];
        }
        return v;
    }
    if (expr.kind == HirExprKind::Field) {
        auto lhs = mir_value(*expr.lhs, module, fn, ctx);
        if (!lhs) return core::make_unexpected(lhs.error());
        if (!fn->values.push(lhs.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = MirValueKind::Field;
        v.type = mir_type_kind(expr.type);
        v.str_value = expr.str_value;
        v.lhs = &fn->values[fn->values.len - 1];
        v.variant_index = expr.variant_index;
        v.struct_index = expr.struct_index;
        v.tuple_len = expr.tuple_len;
        for (u32 i = 0; i < expr.tuple_len; i++) {
            v.tuple_types[i] = mir_type_kind(expr.tuple_types[i]);
            v.tuple_variant_indices[i] = expr.tuple_variant_indices[i];
            v.tuple_struct_indices[i] = expr.tuple_struct_indices[i];
        }
        v.error_struct_index = expr.error_struct_index;
        v.error_variant_index = expr.error_variant_index;
        return v;
    }
    if (expr.kind == HirExprKind::ReqHeader) {
        v.kind = MirValueKind::ReqHeader;
        v.type = MirTypeKind::Str;
        v.may_nil = true;
        v.str_value = expr.str_value;
        return v;
    }
    if (expr.kind == HirExprKind::ReqSetHeader || expr.kind == HirExprKind::ReqAddHeader) {
        if (expr.lhs == nullptr) return frontend_error(FrontendError::UnsupportedSyntax, expr.span);
        auto value = mir_value(*expr.lhs, module, fn, ctx);
        if (!value) return core::make_unexpected(value.error());
        if (!fn->values.push(value.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = expr.kind == HirExprKind::ReqAddHeader ? MirValueKind::ReqAddHeader
                                                        : MirValueKind::ReqSetHeader;
        v.type = MirTypeKind::Str;
        v.str_value = expr.str_value;
        v.lhs = &fn->values[fn->values.len - 1];
        return v;
    }
    if (expr.kind == HirExprKind::RespHeader) {
        if (expr.lhs == nullptr) return frontend_error(FrontendError::UnsupportedSyntax, expr.span);
        auto fallback = mir_value(*expr.lhs, module, fn, ctx);
        if (!fallback) return core::make_unexpected(fallback.error());
        if (!fn->values.push(fallback.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = MirValueKind::RespHeader;
        v.type = MirTypeKind::Str;
        v.may_nil = true;
        v.str_value = expr.str_value;
        v.lhs = &fn->values[fn->values.len - 1];
        return v;
    }
    if (expr.kind == HirExprKind::RespSetHeader || expr.kind == HirExprKind::RespAddHeader ||
        expr.kind == HirExprKind::RespRemoveHeader) {
        v.kind = expr.kind == HirExprKind::RespSetHeader   ? MirValueKind::RespSetHeader
                 : expr.kind == HirExprKind::RespAddHeader ? MirValueKind::RespAddHeader
                                                           : MirValueKind::RespRemoveHeader;
        v.type = MirTypeKind::Str;
        v.str_value = expr.str_value;
        if (expr.kind != HirExprKind::RespRemoveHeader) {
            if (expr.lhs == nullptr)
                return frontend_error(FrontendError::UnsupportedSyntax, expr.span);
            auto value = mir_value(*expr.lhs, module, fn, ctx);
            if (!value) return core::make_unexpected(value.error());
            if (!fn->values.push(value.value()))
                return frontend_error(FrontendError::TooManyItems, expr.span);
            v.lhs = &fn->values[fn->values.len - 1];
        }
        return v;
    }
    if (expr.kind == HirExprKind::ReqParam) {
        v.kind = MirValueKind::ReqParam;
        v.type = MirTypeKind::Str;
        v.str_value = expr.str_value;
        return v;
    }
    if (expr.kind == HirExprKind::ReqCookie) {
        v.kind = MirValueKind::ReqCookie;
        v.type = MirTypeKind::Str;
        v.may_nil = true;
        v.str_value = expr.str_value;
        return v;
    }
    if (expr.kind == HirExprKind::ReqQuery) {
        v.kind = MirValueKind::ReqQuery;
        v.type = MirTypeKind::Str;
        v.may_nil = true;
        v.str_value = expr.str_value;
        return v;
    }
    if (expr.kind == HirExprKind::ReqQueryString) {
        v.kind = MirValueKind::ReqQueryString;
        v.type = MirTypeKind::Str;
        v.may_nil = true;
        return v;
    }
    if (expr.kind == HirExprKind::ReqPath) {
        v.kind = MirValueKind::ReqPath;
        v.type = MirTypeKind::Str;
        return v;
    }
    if (expr.kind == HirExprKind::ReqPathOnly) {
        v.kind = MirValueKind::ReqPathOnly;
        v.type = MirTypeKind::Str;
        return v;
    }
    if (expr.kind == HirExprKind::ReqBody) {
        v.kind = MirValueKind::ReqBody;
        v.type = MirTypeKind::Str;
        return v;
    }
    if (expr.kind == HirExprKind::ReqKeepAlive) {
        v.kind = MirValueKind::ReqKeepAlive;
        v.type = MirTypeKind::Bool;
        return v;
    }
    if (expr.kind == HirExprKind::ReqChunked) {
        v.kind = MirValueKind::ReqChunked;
        v.type = MirTypeKind::Bool;
        return v;
    }
    if (expr.kind == HirExprKind::ReqHasContentLength) {
        v.kind = MirValueKind::ReqHasContentLength;
        v.type = MirTypeKind::Bool;
        return v;
    }
    if (expr.kind == HirExprKind::ReqHttp10) {
        v.kind = MirValueKind::ReqHttp10;
        v.type = MirTypeKind::Bool;
        return v;
    }
    if (expr.kind == HirExprKind::ReqHttp11) {
        v.kind = MirValueKind::ReqHttp11;
        v.type = MirTypeKind::Bool;
        return v;
    }
    if (expr.kind == HirExprKind::ReqHttpVersion) {
        v.kind = MirValueKind::ReqHttpVersion;
        v.type = MirTypeKind::Str;
        return v;
    }
    if (expr.kind == HirExprKind::ReqContentLength) {
        v.kind = MirValueKind::ReqContentLength;
        v.type = MirTypeKind::ByteSize;
        return v;
    }
    if (expr.kind == HirExprKind::TimeNowMicros) {
        v.kind = MirValueKind::TimeNowMicros;
        v.type = MirTypeKind::I64;
        return v;
    }
    if (expr.kind == HirExprKind::ReqRemoteAddr) {
        v.kind = MirValueKind::ReqRemoteAddr;
        v.type = MirTypeKind::IP;
        return v;
    }
    if (expr.kind == HirExprKind::ConstMethod) {
        v.kind = MirValueKind::ConstMethod;
        v.type = MirTypeKind::Method;
        v.int_value = expr.int_value;
        return v;
    }
    if (expr.kind == HirExprKind::ReqMethod) {
        v.kind = MirValueKind::ReqMethod;
        v.type = MirTypeKind::Method;
        return v;
    }
    if (expr.kind == HirExprKind::Nil) {
        v.kind = MirValueKind::Nil;
        v.type = MirTypeKind::Unknown;
        return v;
    }
    if (expr.kind == HirExprKind::Error) {
        v.kind = MirValueKind::Error;
        v.type = MirTypeKind::Unknown;
        v.int_value = expr.int_value;
        v.msg = expr.msg;
        v.error_struct_index = expr.error_struct_index;
        v.error_variant_index = expr.error_variant_index;
        v.error_case_index = expr.error_case_index;
        v.str_value = expr.str_value;
        for (u32 i = 0; i < expr.field_inits.len; i++) {
            auto field_value = mir_value(*expr.field_inits[i].value, module, fn, ctx);
            if (!field_value) return core::make_unexpected(field_value.error());
            if (!fn->values.push(field_value.value()))
                return frontend_error(FrontendError::TooManyItems, expr.span);
            MirValue::FieldInit field_init{};
            field_init.name = expr.field_inits[i].name;
            field_init.value = &fn->values[fn->values.len - 1];
            if (!v.field_inits.push(field_init))
                return frontend_error(FrontendError::TooManyItems, expr.span);
        }
        return v;
    }
    if (expr.kind == HirExprKind::Eq || expr.kind == HirExprKind::Lt ||
        expr.kind == HirExprKind::Gt || expr.kind == HirExprKind::BitAnd ||
        expr.kind == HirExprKind::BitOr || expr.kind == HirExprKind::BitXor ||
        expr.kind == HirExprKind::BitShl || expr.kind == HirExprKind::BitShr ||
        expr.kind == HirExprKind::Add || expr.kind == HirExprKind::Sub ||
        expr.kind == HirExprKind::Mul || expr.kind == HirExprKind::Div ||
        expr.kind == HirExprKind::Mod || expr.kind == HirExprKind::MaxInt ||
        expr.kind == HirExprKind::MinInt) {
        auto lhs = mir_value(*expr.lhs, module, fn, ctx);
        if (!lhs) return core::make_unexpected(lhs.error());
        auto rhs = mir_value(*expr.rhs, module, fn, ctx);
        if (!rhs) return core::make_unexpected(rhs.error());
        if (!fn->values.push(lhs.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        MirValue* lhs_ptr = &fn->values[fn->values.len - 1];
        if (!fn->values.push(rhs.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        MirValue* rhs_ptr = &fn->values[fn->values.len - 1];
        switch (expr.kind) {
            case HirExprKind::Eq:
                v.kind = MirValueKind::Eq;
                break;
            case HirExprKind::Lt:
                v.kind = MirValueKind::Lt;
                break;
            case HirExprKind::Gt:
                v.kind = MirValueKind::Gt;
                break;
            case HirExprKind::BitAnd:
                v.kind = MirValueKind::BitAnd;
                break;
            case HirExprKind::BitOr:
                v.kind = MirValueKind::BitOr;
                break;
            case HirExprKind::BitXor:
                v.kind = MirValueKind::BitXor;
                break;
            case HirExprKind::BitShl:
                v.kind = MirValueKind::BitShl;
                break;
            case HirExprKind::BitShr:
                v.kind = MirValueKind::BitShr;
                break;
            case HirExprKind::Add:
                v.kind = MirValueKind::Add;
                break;
            case HirExprKind::Sub:
                v.kind = MirValueKind::Sub;
                break;
            case HirExprKind::Mul:
                v.kind = MirValueKind::Mul;
                break;
            case HirExprKind::Div:
                v.kind = MirValueKind::Div;
                break;
            case HirExprKind::MaxInt:
                v.kind = MirValueKind::MaxInt;
                break;
            case HirExprKind::MinInt:
                v.kind = MirValueKind::MinInt;
                break;
            default:
                v.kind = MirValueKind::Mod;
                break;
        }
        const bool is_cmp = expr.kind == HirExprKind::Eq || expr.kind == HirExprKind::Lt ||
                            expr.kind == HirExprKind::Gt;
        // Bit ops stay I32; arith carries the operand width (I32 or I64).
        v.type = is_cmp ? MirTypeKind::Bool : mir_type_kind(expr.type);
        v.lhs = lhs_ptr;
        v.rhs = rhs_ptr;
        v.error_variant_index = expr.error_variant_index;
        return v;
    }
    if (expr.kind == HirExprKind::WidenI64) {
        auto operand = mir_value(*expr.lhs, module, fn, ctx);
        if (!operand) return core::make_unexpected(operand.error());
        if (!fn->values.push(operand.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = MirValueKind::WidenI64;
        v.type = MirTypeKind::I64;
        v.lhs = &fn->values[fn->values.len - 1];
        return v;
    }
    if (expr.kind == HirExprKind::CacheGet) {
        auto key = mir_value(*expr.lhs, module, fn, ctx);
        if (!key) return core::make_unexpected(key.error());
        if (!fn->values.push(key.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = MirValueKind::CacheGet;
        v.type = MirTypeKind::I64;
        v.may_nil = true;
        v.cache_index = expr.cache_index;
        v.lhs = &fn->values[fn->values.len - 1];
        return v;
    }
    if (expr.kind == HirExprKind::CacheSet) {
        auto key = mir_value(*expr.lhs, module, fn, ctx);
        if (!key) return core::make_unexpected(key.error());
        auto value = mir_value(*expr.rhs, module, fn, ctx);
        if (!value) return core::make_unexpected(value.error());
        if (!fn->values.push(key.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        MirValue* key_ptr = &fn->values[fn->values.len - 1];
        if (!fn->values.push(value.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = MirValueKind::CacheSet;
        v.type = MirTypeKind::I64;
        v.cache_index = expr.cache_index;
        v.lhs = key_ptr;
        v.rhs = &fn->values[fn->values.len - 1];
        return v;
    }
    if (expr.kind == HirExprKind::IfElse) {
        auto cond = mir_value(*expr.lhs, module, fn, ctx);
        if (!cond) return core::make_unexpected(cond.error());
        auto then_v = mir_value(*expr.rhs, module, fn, ctx);
        if (!then_v) return core::make_unexpected(then_v.error());
        auto else_v = mir_value(*expr.args[0], module, fn, ctx);
        if (!else_v) return core::make_unexpected(else_v.error());
        if (!fn->values.push(cond.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        MirValue* cond_ptr = &fn->values[fn->values.len - 1];
        if (!fn->values.push(then_v.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        MirValue* then_ptr = &fn->values[fn->values.len - 1];
        if (!fn->values.push(else_v.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        MirValue* else_ptr = &fn->values[fn->values.len - 1];
        v.kind = MirValueKind::IfElse;
        v.type = mir_type_kind(expr.type);
        v.lhs = cond_ptr;
        v.rhs = then_ptr;
        if (!v.args.push(else_ptr)) return frontend_error(FrontendError::TooManyItems, expr.span);
        v.variant_index = expr.variant_index;
        v.struct_index = expr.struct_index;
        v.error_struct_index = expr.error_struct_index;
        v.error_variant_index = expr.error_variant_index;
        v.is_pipe_conditional = expr.is_pipe_conditional;
        v.is_eager_fallback = expr.is_eager_fallback;
        apply_expr_shape_if_available(module, expr, &v);
        return v;
    }
    if (expr.kind == HirExprKind::Or) {
        auto lhs = mir_value(*expr.lhs, module, fn, ctx);
        if (!lhs) return core::make_unexpected(lhs.error());
        auto rhs = mir_value(*expr.rhs, module, fn, ctx);
        if (!rhs) return core::make_unexpected(rhs.error());
        if (!fn->values.push(lhs.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        MirValue* lhs_ptr = &fn->values[fn->values.len - 1];
        if (!fn->values.push(rhs.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        MirValue* rhs_ptr = &fn->values[fn->values.len - 1];
        v.kind = MirValueKind::Or;
        v.type = mir_type_kind(expr.type);
        v.lhs = lhs_ptr;
        v.rhs = rhs_ptr;
        v.variant_index = expr.variant_index;
        v.struct_index = expr.struct_index;
        v.error_struct_index = expr.error_struct_index;
        v.error_variant_index = expr.error_variant_index;
        apply_expr_shape_if_available(module, expr, &v);
        return v;
    }
    if (expr.kind == HirExprKind::NoError) {
        auto lhs = mir_value(*expr.lhs, module, fn, ctx);
        if (!lhs) return core::make_unexpected(lhs.error());
        if (!fn->values.push(lhs.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = MirValueKind::NoError;
        v.type = MirTypeKind::Bool;
        v.lhs = &fn->values[fn->values.len - 1];
        v.error_variant_index = expr.error_variant_index;
        return v;
    }
    if (expr.kind == HirExprKind::HasValue) {
        auto lhs = mir_value(*expr.lhs, module, fn, ctx);
        if (!lhs) return core::make_unexpected(lhs.error());
        if (!fn->values.push(lhs.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = MirValueKind::HasValue;
        v.type = MirTypeKind::Bool;
        v.lhs = &fn->values[fn->values.len - 1];
        v.variant_index = expr.variant_index;
        v.struct_index = expr.struct_index;
        v.error_struct_index = expr.error_struct_index;
        v.error_variant_index = expr.error_variant_index;
        return v;
    }
    if (expr.kind == HirExprKind::ValueOf) {
        auto lhs = mir_value(*expr.lhs, module, fn, ctx);
        if (!lhs) return core::make_unexpected(lhs.error());
        if (!fn->values.push(lhs.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = MirValueKind::ValueOf;
        v.type = mir_type_kind(expr.type);
        v.variant_index = expr.variant_index;
        v.struct_index = expr.struct_index;
        v.error_struct_index = expr.error_struct_index;
        v.error_variant_index = expr.error_variant_index;
        v.lhs = &fn->values[fn->values.len - 1];
        apply_expr_shape_if_available(module, expr, &v);
        return v;
    }
    if (expr.kind == HirExprKind::MissingOf) {
        auto lhs = mir_value(*expr.lhs, module, fn, ctx);
        if (!lhs) return core::make_unexpected(lhs.error());
        if (!fn->values.push(lhs.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = MirValueKind::MissingOf;
        v.type = mir_type_kind(expr.type);
        v.may_nil = expr.may_nil;
        v.may_error = expr.may_error;
        v.variant_index = expr.variant_index;
        v.struct_index = expr.struct_index;
        v.error_struct_index = expr.error_struct_index;
        v.error_variant_index = expr.error_variant_index;
        v.lhs = &fn->values[fn->values.len - 1];
        apply_expr_shape_if_available(module, expr, &v);
        return v;
    }
    if (expr.kind == HirExprKind::MatchPayload) {
        auto lhs = mir_value(*expr.lhs, module, fn, ctx);
        if (!lhs) return core::make_unexpected(lhs.error());
        if (!fn->values.push(lhs.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = MirValueKind::MatchPayload;
        v.type = mir_type_kind(expr.type);
        v.variant_index = expr.variant_index;
        v.struct_index = expr.struct_index;
        v.case_index = expr.case_index;
        v.lhs = &fn->values[fn->values.len - 1];
        v.error_variant_index = expr.error_variant_index;
        apply_expr_shape_if_available(module, expr, &v);
        return v;
    }
    if (expr.kind == HirExprKind::VariantTag) {
        auto lhs = mir_value(*expr.lhs, module, fn, ctx);
        if (!lhs) return core::make_unexpected(lhs.error());
        if (!fn->values.push(lhs.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = MirValueKind::VariantTag;
        v.type = MirTypeKind::I32;
        v.variant_index = expr.variant_index;
        v.lhs = &fn->values[fn->values.len - 1];
        return v;
    }
    if (expr.kind == HirExprKind::LocalRef) {
        if (ctx != nullptr) {
            for (u32 li = 0; li < ctx->locals.len; li++) {
                if (expr.local_index == ctx->locals[li].ref_index &&
                    ctx->locals[li].value != nullptr)
                    return *ctx->locals[li].value;
            }
        }
        v.kind = MirValueKind::LocalRef;
        v.type = mir_type_kind(expr.type);
        v.is_wait_result = expr.is_wait_result;
        v.wait_event_kind = expr.wait_event_kind;
        v.wait_payload = expr.wait_payload;
        v.wait_arm_mask = expr.wait_arm_mask;
        v.wait_index = expr.wait_index;
        v.variant_index = expr.variant_index;
        v.struct_index = expr.struct_index;
        v.local_index = expr.local_index;
        v.error_struct_index = expr.error_struct_index;
        v.error_variant_index = expr.error_variant_index;
        apply_expr_shape_if_available(module, expr, &v);
        return v;
    }
    if (expr.kind == HirExprKind::WaitResult) {
        v.kind = MirValueKind::WaitResult;
        v.type = MirTypeKind::Unknown;
        v.is_wait_result = true;
        v.wait_event_kind = expr.wait_event_kind;
        v.wait_payload = expr.wait_payload;
        v.wait_arm_mask = expr.wait_arm_mask;
        v.wait_index = expr.wait_index;
        return v;
    }
    if (expr.kind == HirExprKind::WaitField) {
        auto lhs = mir_value(*expr.lhs, module, fn, ctx);
        if (!lhs) return core::make_unexpected(lhs.error());
        if (!fn->values.push(lhs.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = MirValueKind::WaitField;
        v.type = mir_type_kind(expr.type);
        v.str_value = expr.str_value;
        v.lhs = &fn->values[fn->values.len - 1];
        v.wait_index = lhs->wait_index;
        return v;
    }
    return frontend_error(FrontendError::UnsupportedSyntax, expr.span);
}

}  // namespace

FrontendResult<MirModule*> build_mir(const HirModule& module) {
    auto* mir = new MirModule{};

    for (u32 i = 0; i < module.type_shapes.len; i++) {
        MirTypeShape shape{};
        shape.type = mir_type_kind(module.type_shapes[i].type);
        shape.is_concrete = module.type_shapes[i].is_concrete;
        shape.generic_index = module.type_shapes[i].generic_index;
        shape.variant_index = module.type_shapes[i].variant_index;
        shape.struct_index = module.type_shapes[i].struct_index;
        shape.tuple_len = module.type_shapes[i].tuple_len;
        for (u32 ti = 0; ti < shape.tuple_len; ti++) {
            shape.tuple_elem_shape_indices[ti] = module.type_shapes[i].tuple_elem_shape_indices[ti];
        }
        if (!mir->type_shapes.push(shape)) return frontend_error(FrontendError::TooManyItems, {});
    }
    for (u32 i = 0; i < module.caches.len; i++) {
        MirCacheInstance ci{};
        ci.span = module.caches[i].span;
        ci.name = module.caches[i].name;
        ci.capacity = module.caches[i].capacity;
        if (!mir->caches.push(ci)) return frontend_error(FrontendError::TooManyItems, {});
    }
    for (u32 i = 0; i < module.upstreams.len; i++) {
        MirUpstream up{};
        up.span = module.upstreams[i].span;
        up.name = module.upstreams[i].name;
        up.id = module.upstreams[i].id;
        up.has_address = module.upstreams[i].has_address;
        up.ip = module.upstreams[i].ip;
        up.port = module.upstreams[i].port;
        up.extra_count = module.upstreams[i].extra_count;
        for (u32 b = 0; b < up.extra_count; b++) {
            up.extra_ips[b] = module.upstreams[i].extra_ips[b];
            up.extra_ports[b] = module.upstreams[i].extra_ports[b];
        }
        up.hc_enabled = module.upstreams[i].hc_enabled;
        up.hc_path = module.upstreams[i].hc_path;
        up.hc_interval_ms = module.upstreams[i].hc_interval_ms;
        up.hc_expected_status = module.upstreams[i].hc_expected_status;
        if (!mir->upstreams.push(up)) return frontend_error(FrontendError::TooManyItems, up.span);
    }

    for (u32 i = 0; i < module.structs.len; i++) {
        MirStruct st{};
        st.span = module.structs[i].span;
        st.name = module.structs[i].name;
        st.conforms_error = module.structs[i].conforms_error;
        st.type_params = module.structs[i].type_params;
        st.template_struct_index = module.structs[i].template_struct_index;
        st.instance_type_arg_count = module.structs[i].instance_type_arg_count;
        for (u32 ai = 0; ai < st.instance_type_arg_count; ai++) {
            st.instance_type_args[ai] = mir_type_kind(module.structs[i].instance_type_args[ai]);
            st.instance_generic_indices[ai] = module.structs[i].instance_generic_indices[ai];
            st.instance_shape_indices[ai] = module.structs[i].instance_shape_indices[ai];
        }
        for (u32 fi = 0; fi < module.structs[i].fields.len; fi++) {
            MirStruct::FieldDecl field{};
            field.name = module.structs[i].fields[fi].name;
            field.type_name = module.structs[i].fields[fi].type_name;
            field.type = mir_type_kind(module.structs[i].fields[fi].type);
            field.shape_index = module.structs[i].fields[fi].shape_index;
            field.is_error_type = module.structs[i].fields[fi].is_error_type;
            field.variant_index = module.structs[i].fields[fi].variant_index;
            field.struct_index = module.structs[i].fields[fi].struct_index;
            field.tuple_len = module.structs[i].fields[fi].tuple_len;
            for (u32 ti = 0; ti < field.tuple_len; ti++) {
                field.tuple_types[ti] = mir_type_kind(module.structs[i].fields[fi].tuple_types[ti]);
                field.tuple_variant_indices[ti] =
                    module.structs[i].fields[fi].tuple_variant_indices[ti];
                field.tuple_struct_indices[ti] =
                    module.structs[i].fields[fi].tuple_struct_indices[ti];
            }
            if (!st.fields.push(field)) return frontend_error(FrontendError::TooManyItems, st.span);
        }
        if (!mir->structs.push(st)) return frontend_error(FrontendError::TooManyItems, st.span);
    }

    for (u32 i = 0; i < module.variants.len; i++) {
        MirVariant variant{};
        variant.span = module.variants[i].span;
        variant.name = module.variants[i].name;
        variant.type_params = module.variants[i].type_params;
        variant.template_variant_index = module.variants[i].template_variant_index;
        variant.instance_type_arg_count = module.variants[i].instance_type_arg_count;
        for (u32 ai = 0; ai < variant.instance_type_arg_count; ai++) {
            variant.instance_type_args[ai] =
                mir_type_kind(module.variants[i].instance_type_args[ai]);
            variant.instance_generic_indices[ai] = module.variants[i].instance_generic_indices[ai];
            variant.instance_shape_indices[ai] = module.variants[i].instance_shape_indices[ai];
        }
        for (u32 ci = 0; ci < module.variants[i].cases.len; ci++) {
            MirVariant::CaseDecl case_decl{};
            case_decl.name = module.variants[i].cases[ci].name;
            case_decl.has_payload = module.variants[i].cases[ci].has_payload;
            case_decl.payload_type = mir_type_kind(module.variants[i].cases[ci].payload_type);
            case_decl.payload_shape_index = module.variants[i].cases[ci].payload_shape_index;
            case_decl.payload_variant_index = module.variants[i].cases[ci].payload_variant_index;
            case_decl.payload_struct_index = module.variants[i].cases[ci].payload_struct_index;
            case_decl.payload_tuple_len = module.variants[i].cases[ci].payload_tuple_len;
            for (u32 ti = 0; ti < case_decl.payload_tuple_len; ti++) {
                case_decl.payload_tuple_types[ti] =
                    mir_type_kind(module.variants[i].cases[ci].payload_tuple_types[ti]);
                case_decl.payload_tuple_variant_indices[ti] =
                    module.variants[i].cases[ci].payload_tuple_variant_indices[ti];
                case_decl.payload_tuple_struct_indices[ti] =
                    module.variants[i].cases[ci].payload_tuple_struct_indices[ti];
            }
            if (!variant.cases.push(case_decl))
                return frontend_error(FrontendError::TooManyItems, variant.span);
        }
        if (!mir->variants.push(variant))
            return frontend_error(FrontendError::TooManyItems, variant.span);
    }

    bool struct_ready[MirModule::kMaxStructs]{};
    bool variant_ready[MirModule::kMaxVariants]{};
    bool changed = true;
    while (changed) {
        changed = false;
        for (u32 i = 0; i < mir->structs.len; i++) {
            if (struct_ready[i]) continue;
            const auto& st = mir->structs[i];
            bool ready = true;
            if (is_open_generic_struct_decl(st)) ready = false;
            if (ready && !instance_fully_concrete(*mir,
                                                  st.instance_type_arg_count,
                                                  st.instance_type_args,
                                                  st.instance_shape_indices))
                ready = false;
            for (u32 fi = 0; ready && fi < st.fields.len; fi++) {
                if (!field_carrier_ready(*mir, st.fields[fi], struct_ready, variant_ready))
                    ready = false;
            }
            if (ready) {
                struct_ready[i] = true;
                changed = true;
            }
        }
        for (u32 i = 0; i < mir->variants.len; i++) {
            if (variant_ready[i]) continue;
            const auto& variant = mir->variants[i];
            bool ready = true;
            if (is_open_generic_variant_decl(variant)) ready = false;
            if (ready && !instance_fully_concrete(*mir,
                                                  variant.instance_type_arg_count,
                                                  variant.instance_type_args,
                                                  variant.instance_shape_indices))
                ready = false;
            for (u32 ci = 0; ready && ci < variant.cases.len; ci++) {
                if (!variant_payload_carrier_ready(
                        *mir, variant.cases[ci], struct_ready, variant_ready))
                    ready = false;
            }
            if (ready) {
                variant_ready[i] = true;
                changed = true;
            }
        }
    }
    for (u32 i = 0; i < mir->type_shapes.len; i++) {
        mir->type_shapes[i].carrier_ready =
            shape_carrier_ready(*mir, i, struct_ready, variant_ready);
    }

    for (u32 i = 0; i < module.routes.len; i++) {
#if RUT_ENABLE_WEBSOCKET
        // WebSocket terminate-mode frame handlers don't go through the HTTP MIR/RIR pipeline —
        // a constant verdict needs no request parsing / response building / state machine. The
        // serve loader emits them directly (jit::emit_ws_handler) and registers them via
        // RouteConfig::add_ws_terminate. Skip them here so the HTTP routes still build.
        if (module.routes[i].is_ws_terminate) continue;
#endif
        MirFunction fn{};
        fn.span = module.routes[i].span;
        fn.method = module.routes[i].method;
        fn.path = module.routes[i].path;
        fn.name = {"route", 5};
        fn.error_variant_index = module.routes[i].error_variant_index;
        fn.rate_limit = module.routes[i].rate_limit;
        fn.throttle_down_bps = module.routes[i].throttle_down_bps;
        fn.is_timer = module.routes[i].is_timer;
        fn.timer_interval_ms = module.routes[i].timer_interval_ms;
        fn.timer_shard = module.routes[i].timer_shard;

        // Propagate wait(ms) list 1:1. Codegen will turn each into a yield
        // boundary in the generated state machine.
        for (u32 wi = 0; wi < module.routes[i].waits.len; wi++) {
            MirFunction::Wait w{};
            w.span = module.routes[i].waits[wi].span;
            w.event_kind = module.routes[i].waits[wi].event_kind;
            w.ms = module.routes[i].waits[wi].ms;
            w.arm_mask = module.routes[i].waits[wi].arm_mask;
            if (!fn.waits.push(w)) return frontend_error(FrontendError::TooManyItems, w.span);
        }

        for (u32 li = 0; li < module.routes[i].locals.len; li++) {
            if (module.routes[i].locals[li].type == HirTypeKind::Tuple) continue;
            // Array locals are compile-time constants for for-loop unroll
            // only. They have no runtime MirValue carrier yet, so do not
            // emit a MIR local for them.
            if (module.routes[i].locals[li].type == HirTypeKind::Array ||
                module.routes[i].locals[li].type == HirTypeKind::Response)
                continue;
            // Skip synthetic name-cleared locals. Analyze keeps for-loop
            // loop variables in HirRoute::locals so body LocalRefs bind to
            // a stable ref_index, then blanks the name for scope-hiding
            // (see analyze.cc:10137). MIR unroll substitutes every
            // reference to the loop var with the per-iteration element
            // (see ForLoopCtx in mir_value), so its MIR slot is never
            // read. Emitting it anyway would push a MirLocal whose init
            // is a self-referential LocalRef — lower_rir's
            // materialize_local_init would resolve it to ValueId{0} since
            // the slot is still being initialized, turning any future
            // substitution regression into a silent miscompile.
            //
            // EXCEPT bare statement-effect carriers: they are also name-cleared
            // (unnameable by design) but their init is the side effect itself —
            // dropping one would silently delete the write.
            if (module.routes[i].locals[li].name.len == 0 &&
                module.routes[i].locals[li].init.kind != HirExprKind::CacheSet &&
                module.routes[i].locals[li].init.kind != HirExprKind::ReqSetHeader &&
                module.routes[i].locals[li].init.kind != HirExprKind::ReqAddHeader &&
                module.routes[i].locals[li].init.kind != HirExprKind::RespSetHeader &&
                module.routes[i].locals[li].init.kind != HirExprKind::RespAddHeader &&
                module.routes[i].locals[li].init.kind != HirExprKind::RespRemoveHeader)
                continue;
            if (module.routes[i].locals[li].is_wait_result) continue;
            MirLocal local{};
            local.span = module.routes[i].locals[li].span;
            local.name = module.routes[i].locals[li].name;
            local.ref_index = module.routes[i].locals[li].ref_index;
            local.type = mir_type_kind(module.routes[i].locals[li].type);
            local.shape_index = module.routes[i].locals[li].shape_index;
            local.may_nil = module.routes[i].locals[li].may_nil;
            local.may_error = module.routes[i].locals[li].may_error;
            local.variant_index = module.routes[i].locals[li].variant_index;
            local.struct_index = module.routes[i].locals[li].struct_index;
            local.tuple_len = module.routes[i].locals[li].tuple_len;
            for (u32 ti = 0; ti < local.tuple_len; ti++) {
                local.tuple_types[ti] = mir_type_kind(module.routes[i].locals[li].tuple_types[ti]);
                local.tuple_variant_indices[ti] =
                    module.routes[i].locals[li].tuple_variant_indices[ti];
                local.tuple_struct_indices[ti] =
                    module.routes[i].locals[li].tuple_struct_indices[ti];
            }
            local.error_struct_index = module.routes[i].locals[li].error_struct_index;
            local.error_variant_index = module.routes[i].locals[li].error_variant_index;
            local.is_wait_result = module.routes[i].locals[li].is_wait_result;
            local.wait_event_kind = module.routes[i].locals[li].wait_event_kind;
            local.wait_payload = module.routes[i].locals[li].wait_payload;
            local.wait_arm_mask = module.routes[i].locals[li].wait_arm_mask;
            local.wait_index = module.routes[i].locals[li].wait_index;
            auto init = mir_value(module.routes[i].locals[li].init, module, &fn);
            if (!init) return core::make_unexpected(init.error());
            local.init = init.value();
            if (!fn.locals.push(local))
                return frontend_error(FrontendError::TooManyItems, local.span);
        }

        auto set_term_from_hir = [](MirTerminator* out, const HirTerminator& term) {
            out->span = term.span;
            out->status_code = term.status_code;
            out->commit_response_mutations = term.commit_response_mutations;
            out->upstream_index = term.upstream_index;
            out->kind = term.kind == HirTerminatorKind::ReturnStatus
                            ? MirTerminatorKind::ReturnStatus
                            : MirTerminatorKind::ForwardUpstream;
            out->source_kind = term.source_kind == HirTerminatorSourceKind::LocalRef
                                   ? MirTerminatorSourceKind::LocalRef
                                   : MirTerminatorSourceKind::Literal;
            out->local_ref_index = term.local_ref_index;
            out->response_body = term.response_body;
            out->forward_set_path = term.forward_set_path;
            out->response_headers.len = 0;
            // Both HIR and MIR cap at 16 headers per terminator, so a
            // straight copy cannot truncate. Static-assert the cap
            // equality here so a future tweak on either side trips
            // the build instead of silently dropping headers.
            static_assert(HirTerminator::kMaxHeaders == MirTerminator::kMaxHeaders,
                          "HIR/MIR header cap must stay in lockstep or a different "
                          "copy strategy (returning an error) is required.");
            for (u32 i = 0; i < term.response_headers.len; i++) {
                const auto& p = term.response_headers[i];
                const bool ok = out->response_headers.push({p.key, p.value});
                // Unreachable given the static_assert above; use a
                // builtin trap in debug/release rather than `(void)ok`
                // so a regression surfaces immediately instead of
                // silently shipping a truncated header set.
                if (!ok) __builtin_trap();
            }
            // forward(set_header:) overrides — same cap on both sides (the
            // static_assert above covers kMaxHeaders), straight copy.
            out->forward_set_headers.len = 0;
            for (u32 i = 0; i < term.forward_set_headers.len; i++) {
                const auto& p = term.forward_set_headers[i];
                if (!out->forward_set_headers.push({p.key, p.value})) __builtin_trap();
            }
        };
        auto set_arm_effects = [&](MirBlock* out, const HirMatchArm& arm) -> FrontendResult<void> {
            for (u32 ei = 0; ei < arm.effect_expr_indices.len; ei++) {
                const u32 expr_index = arm.effect_expr_indices[ei];
                if (expr_index >= module.routes[i].exprs.len)
                    return frontend_error(FrontendError::UnsupportedSyntax, arm.span);
                auto effect = mir_value(module.routes[i].exprs[expr_index], module, &fn);
                if (!effect) return core::make_unexpected(effect.error());
                if (!fn.values.push(effect.value()))
                    return frontend_error(FrontendError::TooManyItems, arm.span);
                if (!out->effects.push(
                        {fn.values.len - 1, module.routes[i].exprs[expr_index].span}))
                    return frontend_error(FrontendError::TooManyItems, arm.span);
            }
            return {};
        };
        auto guard_fail_block_count = [&](const HirGuard& guard) -> u32 {
            if (guard.fail_kind == HirGuard::FailKind::Term) return 1;
            if (guard.fail_kind == HirGuard::FailKind::Body)
                return guard.fail_body.body_kind == HirGuardBody::BodyKind::If ? 3u : 1u;
            u32 non_wildcard = 0;
            for (u32 ai = 0; ai < guard.fail_match_count; ai++) {
                // one test block per non-wildcard arm, one case/default block per arm
                // fail_match arms live in route storage to keep HirGuard compact
                const auto& arm = module.guard_match_arms[guard.fail_match_start + ai];
                if (!arm.is_wildcard) non_wildcard++;
            }
            return non_wildcard + guard.fail_match_count;
        };
        auto emit_guard_fail = [&](const HirGuard& guard,
                                   const ForLoopCtx* ctx = nullptr) -> FrontendResult<void> {
            if (guard.fail_kind == HirGuard::FailKind::Term) {
                MirBlock fail_block{};
                fail_block.label = fail_label();
                set_term_from_hir(&fail_block.term, guard.fail_term);
                if (!fn.blocks.push(fail_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);
                return {};
            }

            if (guard.fail_kind == HirGuard::FailKind::Body) {
                ForLoopCtx scoped_ctx{};
                const ForLoopCtx* body_ctx = ctx;
                if (guard.fail_body.locals.len != 0) {
                    if (ctx != nullptr) scoped_ctx = *ctx;
                    body_ctx = &scoped_ctx;
                    for (u32 li = 0; li < guard.fail_body.locals.len; li++) {
                        const auto& local = guard.fail_body.locals[li];
                        auto local_value = mir_value(local.init, module, &fn, body_ctx);
                        if (!local_value) return core::make_unexpected(local_value.error());
                        if (!fn.values.push(local_value.value()))
                            return frontend_error(FrontendError::TooManyItems, local.span);
                        ForLoopCtx::LocalBinding binding{};
                        binding.ref_index = local.ref_index;
                        binding.value = &fn.values[fn.values.len - 1];
                        if (!scoped_ctx.locals.push(binding))
                            return frontend_error(FrontendError::TooManyItems, local.span);
                    }
                }
                MirBlock fail_block{};
                fail_block.label = fail_label();
                if (guard.fail_body.body_kind == HirGuardBody::BodyKind::If) {
                    fail_block.term.kind = MirTerminatorKind::Branch;
                    fail_block.term.span = guard.fail_body.cond.span;
                    auto cond = mir_value(guard.fail_body.cond, module, &fn, body_ctx);
                    if (!cond) return core::make_unexpected(cond.error());
                    fail_block.term.cond = cond.value();
                    const u32 then_index = fn.blocks.len + 1;
                    const u32 else_index = fn.blocks.len + 2;
                    fail_block.term.then_block = then_index;
                    fail_block.term.else_block = else_index;
                    if (!fn.blocks.push(fail_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);

                    MirBlock then_block{};
                    then_block.label = then_label();
                    set_term_from_hir(&then_block.term, guard.fail_body.then_term);
                    if (!fn.blocks.push(then_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);

                    MirBlock else_block{};
                    else_block.label = else_label();
                    set_term_from_hir(&else_block.term, guard.fail_body.else_term);
                    if (!fn.blocks.push(else_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                } else {
                    set_term_from_hir(&fail_block.term, guard.fail_body.direct_term);
                    if (!fn.blocks.push(fail_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                }
                return {};
            }

            u32 test_index[HirGuard::kMaxFailMatchArms]{};
            u32 case_index[HirGuard::kMaxFailMatchArms]{};
            u32 cursor = fn.blocks.len;
            u32 default_index = 0xffffffffu;
            for (u32 ai = 0; ai < guard.fail_match_count; ai++) {
                const auto& arm = module.guard_match_arms[guard.fail_match_start + ai];
                if (!arm.is_wildcard) test_index[ai] = cursor++;
            }
            for (u32 ai = 0; ai < guard.fail_match_count; ai++) {
                const auto& arm = module.guard_match_arms[guard.fail_match_start + ai];
                case_index[ai] = cursor++;
                if (arm.is_wildcard) default_index = case_index[ai];
            }

            auto subject = mir_value(guard.fail_match_expr, module, &fn, ctx);
            if (!subject) return core::make_unexpected(subject.error());
            for (u32 ai = 0; ai < guard.fail_match_count; ai++) {
                const auto& arm = module.guard_match_arms[guard.fail_match_start + ai];
                if (arm.is_wildcard) continue;
                MirBlock test_block{};
                test_block.label = match_test_label();
                auto arm_pattern = mir_value(arm.pattern, module, &fn, ctx);
                if (!arm_pattern) return core::make_unexpected(arm_pattern.error());
                test_block.term.kind = MirTerminatorKind::Branch;
                test_block.term.use_cmp = true;
                test_block.term.span = arm.span;
                test_block.term.lhs = subject.value();
                test_block.term.rhs = arm_pattern.value();
                test_block.term.then_block = case_index[ai];
                u32 next_test = default_index;
                for (u32 next = ai + 1; next < guard.fail_match_count; next++) {
                    if (!module.guard_match_arms[guard.fail_match_start + next].is_wildcard) {
                        next_test = test_index[next];
                        break;
                    }
                }
                test_block.term.else_block = next_test;
                if (!fn.blocks.push(test_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);
            }

            for (u32 ai = 0; ai < guard.fail_match_count; ai++) {
                const auto& arm = module.guard_match_arms[guard.fail_match_start + ai];
                MirBlock case_block{};
                case_block.label = arm.is_wildcard ? match_default_label() : match_case_label();
                set_term_from_hir(&case_block.term, arm.direct_term);
                if (!fn.blocks.push(case_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);
            }
            return {};
        };
        auto set_match_arm_guard_branch = [&](MirBlock& block,
                                              const HirMatchArm& arm,
                                              u32 first_guard_index,
                                              u32 body_index,
                                              auto&& fallthrough) -> FrontendResult<void> {
            auto cond = mir_value(arm.arm_guard, module, &fn);
            if (!cond) return core::make_unexpected(cond.error());
            block.term.kind = MirTerminatorKind::Branch;
            block.term.span = arm.arm_guard.span;
            block.term.cond = cond.value();
            block.term.then_block = arm.guards.len != 0 ? first_guard_index : body_index;
            auto fallback = fallthrough();
            if (!fallback) return core::make_unexpected(fallback.error());
            block.term.else_block = fallback.value();
            return {};
        };
        auto emit_match_prelude_guard_blocks = [&](const HirMatchArm& arm,
                                                   u32 ai,
                                                   auto guard_index,
                                                   auto guard_fail_index,
                                                   const u32* body_index) -> FrontendResult<void> {
            const u32 first_guard_index = arm.has_arm_guard ? 0 : 1;
            for (u32 gi = first_guard_index; gi < arm.guards.len; gi++) {
                MirBlock guard_block{};
                guard_block.label = cont_label();
                auto cond = mir_value(arm.guards[gi].cond, module, &fn);
                if (!cond) return core::make_unexpected(cond.error());
                guard_block.term.kind = MirTerminatorKind::Branch;
                guard_block.term.span = arm.guards[gi].span;
                guard_block.term.cond = cond.value();
                guard_block.term.then_block =
                    gi + 1 < arm.guards.len ? guard_index[ai][gi + 1] : body_index[ai];
                guard_block.term.else_block = guard_fail_index[ai][gi];
                if (!fn.blocks.push(guard_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);
            }
            return {};
        };

        if (fn.waits.len != 0 && module.routes[i].for_loops.len == 0) {
            if (module.routes[i].control.kind != HirControlKind::Direct &&
                module.routes[i].control.kind != HirControlKind::If &&
                module.routes[i].control.kind != HirControlKind::Match) {
                return frontend_error(FrontendError::UnsupportedSyntax, fn.span);
            }

            struct RouteStep {
                enum class Kind : u8 { Guard, Wait };
                Kind kind;
                u32 index;
                Span span;
            };
            RouteStep steps[HirRoute::kMaxGuards + HirRoute::kMaxWaits]{};
            u32 step_count = 0;
            for (u32 gi = 0; gi < module.routes[i].guards.len; gi++) {
                steps[step_count++] = {
                    RouteStep::Kind::Guard, gi, module.routes[i].guards[gi].span};
            }
            for (u32 wi = 0; wi < fn.waits.len; wi++) {
                steps[step_count++] = {RouteStep::Kind::Wait, wi, fn.waits[wi].span};
            }
            for (u32 si = 1; si < step_count; si++) {
                RouteStep cur = steps[si];
                u32 pos = si;
                while (pos > 0 && cur.span.start < steps[pos - 1].span.start) {
                    steps[pos] = steps[pos - 1];
                    pos--;
                }
                steps[pos] = cur;
            }

            const u32 terminal_index = step_count;
            const u32 then_index =
                module.routes[i].control.kind == HirControlKind::If ? terminal_index + 1 : 0;
            const u32 else_index =
                module.routes[i].control.kind == HirControlKind::If ? terminal_index + 2 : 0;
            u32 match_arm_block_index[HirControl::kMaxMatchArms]{};
            u32 match_arm_body_index[HirControl::kMaxMatchArms]{};
            u32 match_arm_then_index[HirControl::kMaxMatchArms]{};
            u32 match_arm_else_index[HirControl::kMaxMatchArms]{};
            u32 match_arm_guard_index[HirControl::kMaxMatchArms][HirMatchArm::kMaxPreludeGuards]{};
            u32 match_arm_guard_fail_index[HirControl::kMaxMatchArms]
                                          [HirMatchArm::kMaxPreludeGuards]{};
            u32 match_arm_count = 0;
            u32 match_test_count = 0;
            u32 match_end_index = 0;
            if (module.routes[i].control.kind == HirControlKind::Match) {
                match_arm_count = module.routes[i].control.match_arms.len;
                match_test_count = match_arm_count - 1;
                u32 next_index = terminal_index + match_test_count;
                for (u32 ai = 0; ai < match_arm_count; ai++) {
                    const auto& arm = module.routes[i].control.match_arms[ai];
                    match_arm_block_index[ai] = next_index++;
                    if (arm.guards.len != 0) {
                        if (arm.has_arm_guard) match_arm_guard_index[ai][0] = next_index++;
                        for (u32 gi = 1; gi < arm.guards.len; gi++)
                            match_arm_guard_index[ai][gi] = next_index++;
                        match_arm_body_index[ai] = next_index++;
                        for (u32 gi = 0; gi < arm.guards.len; gi++) {
                            match_arm_guard_fail_index[ai][gi] = next_index;
                            next_index += guard_fail_block_count(arm.guards[gi]);
                        }
                    } else if (arm.has_arm_guard) {
                        match_arm_body_index[ai] = next_index++;
                    } else {
                        match_arm_body_index[ai] = match_arm_block_index[ai];
                    }
                    if (arm.body_kind == HirMatchArm::BodyKind::If) {
                        match_arm_then_index[ai] = next_index++;
                        match_arm_else_index[ai] = next_index++;
                    }
                }
                match_end_index = next_index;
            }
            u32 fail_cursor = terminal_index + 1;
            if (module.routes[i].control.kind == HirControlKind::If)
                fail_cursor = terminal_index + 3;
            if (module.routes[i].control.kind == HirControlKind::Match)
                fail_cursor = match_end_index;
            u32 guard_fail_index[HirRoute::kMaxGuards]{};
            for (u32 si = 0; si < step_count; si++) {
                if (steps[si].kind != RouteStep::Kind::Guard) continue;
                const u32 gi = steps[si].index;
                guard_fail_index[gi] = fail_cursor;
                fail_cursor += guard_fail_block_count(module.routes[i].guards[gi]);
            }
            if (fail_cursor > MirFunction::kMaxBlocks)
                return frontend_error(FrontendError::TooManyItems, fn.span);

            u32 wait_ordinal = 0;
            fn.has_explicit_resume_blocks = true;
            fn.state_zero_enters_entry = true;
            fn.resume_blocks[0] = 0;
            for (u32 si = 0; si < step_count; si++) {
                MirBlock step_block{};
                step_block.label = si == 0 ? entry_label() : cont_label();
                const u32 next_index = si + 1 < step_count ? si + 1 : terminal_index;
                if (steps[si].kind == RouteStep::Kind::Guard) {
                    const auto& guard = module.routes[i].guards[steps[si].index];
                    step_block.term.kind = MirTerminatorKind::Branch;
                    step_block.term.span = guard.span;
                    auto cond = mir_value(guard.cond, module, &fn);
                    if (!cond) return core::make_unexpected(cond.error());
                    step_block.term.cond = cond.value();
                    step_block.term.then_block = next_index;
                    step_block.term.else_block = guard_fail_index[steps[si].index];
                } else {
                    const auto& wait = fn.waits[steps[si].index];
                    wait_ordinal++;
                    step_block.term.kind = MirTerminatorKind::YieldTimer;
                    step_block.term.span = wait.span;
                    step_block.term.yield_event_kind = wait.event_kind;
                    step_block.term.yield_ms = wait.ms;
                    step_block.term.yield_arm_mask = wait.arm_mask;
                    step_block.term.yield_next_state = static_cast<u16>(wait_ordinal);
                    fn.resume_blocks[wait_ordinal] = next_index;
                }
                if (!fn.blocks.push(step_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);
            }
            if (wait_ordinal != fn.waits.len)
                return frontend_error(FrontendError::UnsupportedSyntax, fn.span);

            MirBlock terminal_block{};
            terminal_block.label = cont_label();
            if (module.routes[i].control.kind == HirControlKind::Direct) {
                set_term_from_hir(&terminal_block.term, module.routes[i].control.direct_term);
                if (!fn.blocks.push(terminal_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);
            } else if (module.routes[i].control.kind == HirControlKind::If) {
                terminal_block.term.kind = MirTerminatorKind::Branch;
                terminal_block.term.span = module.routes[i].control.cond.span;
                auto cond = mir_value(module.routes[i].control.cond, module, &fn);
                if (!cond) return core::make_unexpected(cond.error());
                terminal_block.term.cond = cond.value();
                terminal_block.term.then_block = then_index;
                terminal_block.term.else_block = else_index;
                if (!fn.blocks.push(terminal_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);

                MirBlock then_block{};
                then_block.label = then_label();
                set_term_from_hir(&then_block.term, module.routes[i].control.then_term);
                if (!fn.blocks.push(then_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);

                MirBlock else_block{};
                else_block.label = else_label();
                set_term_from_hir(&else_block.term, module.routes[i].control.else_term);
                if (!fn.blocks.push(else_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);
            } else if (module.routes[i].control.kind == HirControlKind::Match) {
                auto subject = mir_value(module.routes[i].control.match_expr, module, &fn);
                if (!subject) return core::make_unexpected(subject.error());
                auto arm_fallthrough_target = [&](u32 ai) -> FrontendResult<u32> {
                    if (ai + 1 < match_test_count) return terminal_index + ai + 1;
                    if (ai + 1 < match_arm_count) return match_arm_block_index[ai + 1];
                    return frontend_error(FrontendError::UnsupportedSyntax,
                                          module.routes[i].control.match_arms[ai].span);
                };
                if (match_test_count == 0) {
                    MirBlock case_block{};
                    const auto& arm = module.routes[i].control.match_arms[0];
                    case_block.label = arm.is_wildcard ? match_default_label() : match_case_label();
                    if (arm.has_arm_guard) {
                        auto guarded =
                            set_match_arm_guard_branch(case_block,
                                                       arm,
                                                       match_arm_guard_index[0][0],
                                                       match_arm_body_index[0],
                                                       [&] { return arm_fallthrough_target(0); });
                        if (!guarded) return core::make_unexpected(guarded.error());
                    } else if (arm.guards.len != 0) {
                        auto cond = mir_value(arm.guards[0].cond, module, &fn);
                        if (!cond) return core::make_unexpected(cond.error());
                        case_block.term.kind = MirTerminatorKind::Branch;
                        case_block.term.span = arm.guards[0].span;
                        case_block.term.cond = cond.value();
                        case_block.term.then_block = arm.guards.len > 1
                                                         ? match_arm_guard_index[0][1]
                                                         : match_arm_body_index[0];
                        case_block.term.else_block = match_arm_guard_fail_index[0][0];
                    } else if (arm.body_kind == HirMatchArm::BodyKind::If) {
                        case_block.term.kind = MirTerminatorKind::Branch;
                        case_block.term.span = arm.cond.span;
                        auto cond = mir_value(arm.cond, module, &fn);
                        if (!cond) return core::make_unexpected(cond.error());
                        case_block.term.cond = cond.value();
                        case_block.term.then_block = match_arm_then_index[0];
                        case_block.term.else_block = match_arm_else_index[0];
                    } else {
                        set_term_from_hir(&case_block.term, arm.direct_term);
                    }
                    if (!arm.has_arm_guard && arm.guards.len == 0) {
                        auto effects = set_arm_effects(&case_block, arm);
                        if (!effects) return core::make_unexpected(effects.error());
                    }
                    if (!fn.blocks.push(case_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                    auto guard_blocks = emit_match_prelude_guard_blocks(arm,
                                                                        0,
                                                                        match_arm_guard_index,
                                                                        match_arm_guard_fail_index,
                                                                        match_arm_body_index);
                    if (!guard_blocks) return core::make_unexpected(guard_blocks.error());
                    if (arm.guards.len != 0 || arm.has_arm_guard) {
                        MirBlock body_block{};
                        body_block.label = cont_label();
                        if (arm.body_kind == HirMatchArm::BodyKind::If) {
                            body_block.term.kind = MirTerminatorKind::Branch;
                            body_block.term.span = arm.cond.span;
                            auto cond = mir_value(arm.cond, module, &fn);
                            if (!cond) return core::make_unexpected(cond.error());
                            body_block.term.cond = cond.value();
                            body_block.term.then_block = match_arm_then_index[0];
                            body_block.term.else_block = match_arm_else_index[0];
                        } else {
                            set_term_from_hir(&body_block.term, arm.direct_term);
                        }
                        auto effects = set_arm_effects(&body_block, arm);
                        if (!effects) return core::make_unexpected(effects.error());
                        if (!fn.blocks.push(body_block))
                            return frontend_error(FrontendError::TooManyItems, fn.span);
                        for (u32 gi = 0; gi < arm.guards.len; gi++) {
                            auto emitted = emit_guard_fail(arm.guards[gi]);
                            if (!emitted) return core::make_unexpected(emitted.error());
                        }
                    }
                    if (arm.body_kind == HirMatchArm::BodyKind::If) {
                        MirBlock then_block{};
                        then_block.label = then_label();
                        set_term_from_hir(&then_block.term, arm.then_term);
                        if (!fn.blocks.push(then_block))
                            return frontend_error(FrontendError::TooManyItems, fn.span);
                        MirBlock else_block{};
                        else_block.label = else_label();
                        set_term_from_hir(&else_block.term, arm.else_term);
                        if (!fn.blocks.push(else_block))
                            return frontend_error(FrontendError::TooManyItems, fn.span);
                    }
                } else {
                    for (u32 ai = 0; ai < match_test_count; ai++) {
                        MirBlock test_block{};
                        test_block.label = ai == 0 ? cont_label() : match_test_label();
                        const auto& arm = module.routes[i].control.match_arms[ai];
                        auto arm_pattern = mir_value(arm.pattern, module, &fn);
                        if (!arm_pattern) return core::make_unexpected(arm_pattern.error());
                        test_block.term.kind = MirTerminatorKind::Branch;
                        test_block.term.use_cmp = true;
                        test_block.term.span = arm.span;
                        test_block.term.lhs = subject.value();
                        test_block.term.rhs = arm_pattern.value();
                        test_block.term.then_block = match_arm_block_index[ai];
                        test_block.term.else_block = ai + 1 < match_test_count
                                                         ? terminal_index + ai + 1
                                                         : match_arm_block_index[match_test_count];
                        if (!fn.blocks.push(test_block))
                            return frontend_error(FrontendError::TooManyItems, fn.span);
                    }

                    for (u32 ai = 0; ai < match_arm_count; ai++) {
                        MirBlock case_block{};
                        const auto& arm = module.routes[i].control.match_arms[ai];
                        case_block.label =
                            arm.is_wildcard ? match_default_label() : match_case_label();
                        if (arm.has_arm_guard) {
                            auto guarded = set_match_arm_guard_branch(
                                case_block,
                                arm,
                                match_arm_guard_index[ai][0],
                                match_arm_body_index[ai],
                                [&] { return arm_fallthrough_target(ai); });
                            if (!guarded) return core::make_unexpected(guarded.error());
                        } else if (arm.guards.len != 0) {
                            auto cond = mir_value(arm.guards[0].cond, module, &fn);
                            if (!cond) return core::make_unexpected(cond.error());
                            case_block.term.kind = MirTerminatorKind::Branch;
                            case_block.term.span = arm.guards[0].span;
                            case_block.term.cond = cond.value();
                            case_block.term.then_block = arm.guards.len > 1
                                                             ? match_arm_guard_index[ai][1]
                                                             : match_arm_body_index[ai];
                            case_block.term.else_block = match_arm_guard_fail_index[ai][0];
                        } else if (arm.body_kind == HirMatchArm::BodyKind::If) {
                            case_block.term.kind = MirTerminatorKind::Branch;
                            case_block.term.span = arm.cond.span;
                            auto cond = mir_value(arm.cond, module, &fn);
                            if (!cond) return core::make_unexpected(cond.error());
                            case_block.term.cond = cond.value();
                            case_block.term.then_block = match_arm_then_index[ai];
                            case_block.term.else_block = match_arm_else_index[ai];
                        } else {
                            set_term_from_hir(&case_block.term, arm.direct_term);
                        }
                        if (!fn.blocks.push(case_block))
                            return frontend_error(FrontendError::TooManyItems, fn.span);
                        auto guard_blocks =
                            emit_match_prelude_guard_blocks(arm,
                                                            ai,
                                                            match_arm_guard_index,
                                                            match_arm_guard_fail_index,
                                                            match_arm_body_index);
                        if (!guard_blocks) return core::make_unexpected(guard_blocks.error());
                        if (arm.guards.len != 0 || arm.has_arm_guard) {
                            MirBlock body_block{};
                            body_block.label = cont_label();
                            if (arm.body_kind == HirMatchArm::BodyKind::If) {
                                body_block.term.kind = MirTerminatorKind::Branch;
                                body_block.term.span = arm.cond.span;
                                auto cond = mir_value(arm.cond, module, &fn);
                                if (!cond) return core::make_unexpected(cond.error());
                                body_block.term.cond = cond.value();
                                body_block.term.then_block = match_arm_then_index[ai];
                                body_block.term.else_block = match_arm_else_index[ai];
                            } else {
                                set_term_from_hir(&body_block.term, arm.direct_term);
                            }
                            if (!fn.blocks.push(body_block))
                                return frontend_error(FrontendError::TooManyItems, fn.span);
                            for (u32 gi = 0; gi < arm.guards.len; gi++) {
                                auto emitted = emit_guard_fail(arm.guards[gi]);
                                if (!emitted) return core::make_unexpected(emitted.error());
                            }
                        }
                        if (arm.body_kind == HirMatchArm::BodyKind::If) {
                            MirBlock then_block{};
                            then_block.label = then_label();
                            set_term_from_hir(&then_block.term, arm.then_term);
                            if (!fn.blocks.push(then_block))
                                return frontend_error(FrontendError::TooManyItems, fn.span);
                            MirBlock else_block{};
                            else_block.label = else_label();
                            set_term_from_hir(&else_block.term, arm.else_term);
                            if (!fn.blocks.push(else_block))
                                return frontend_error(FrontendError::TooManyItems, fn.span);
                        }
                    }
                }
            }

            for (u32 si = 0; si < step_count; si++) {
                if (steps[si].kind != RouteStep::Kind::Guard) continue;
                auto emitted = emit_guard_fail(module.routes[i].guards[steps[si].index]);
                if (!emitted) return core::make_unexpected(emitted.error());
            }

            if (!mir->functions.push(fn))
                return frontend_error(FrontendError::TooManyItems, fn.span);
            continue;
        }

        // Phase 4b/4c for-loop unroll. A guard-only for-loop compiles to a
        // flat chain of per-iteration virtual body steps. A loop body with a
        // terminator lowers only the first iteration, since the terminator
        // exits the route before any later iteration can run. Virtual loop
        // steps sort at the source position of the containing for statement;
        // within that expansion they keep loop iteration and body order.
        //
        // Preconditions (checked below): route control is Direct, If, or
        // Match and every for-loop body has at least one body step. Rejected
        // shapes (runtime iterables, empty bodies) get
        // FrontendError::UnsupportedSyntax pointing at the relevant span.
        if (module.routes[i].for_loops.len != 0) {
            auto iter_array_for = [&](const HirForLoop& fl) -> const HirExpr* {
                auto resolve_array =
                    [&](auto&& self, const HirExpr& expr, u32 depth) -> const HirExpr* {
                    if (depth > module.routes[i].locals.len + HirRoute::kMaxLocals) return nullptr;
                    if (expr.kind == HirExprKind::ArrayLit) return &expr;
                    if (expr.kind != HirExprKind::LocalRef) return nullptr;
                    for (u32 li = 0; li < module.routes[i].locals.len; li++) {
                        const auto& local = module.routes[i].locals[li];
                        if (local.ref_index == expr.local_index)
                            return self(self, local.init, depth + 1);
                    }
                    return nullptr;
                };
                return resolve_array(resolve_array, fl.iter_expr, 0);
            };
            struct RouteStep {
                enum class Kind : u8 {
                    Guard,
                    If,
                    Match,
                    Term,
                };
                Kind kind = Kind::Guard;
                const HirGuard* guard = nullptr;
                const HirForLoopIf* body_if = nullptr;
                const HirForLoopMatch* body_match = nullptr;
                const HirTerminator* term = nullptr;
                Span span{};
                u32 order_start = 0;
                u32 order_seq = 0;
                bool has_ctx = false;
                u32 ctx_index = 0xffffffffu;
            };
            constexpr u32 kMaxUnrolled = HirExpr::kMaxArgs * HirForLoopBody::kMaxSteps;
            constexpr u32 kMaxForRouteSteps =
                HirRoute::kMaxGuards + HirRoute::kMaxForLoops * kMaxUnrolled;
            FixedVec<RouteStep, kMaxForRouteSteps> steps{};
            std::vector<ForLoopCtx> step_contexts;
            step_contexts.reserve(kMaxForRouteSteps);
            u32 route_step_seq = 0;
            auto set_step_ctx = [&](RouteStep* step,
                                    const ForLoopCtx& ctx) -> FrontendResult<void> {
                if (step_contexts.size() >= kMaxForRouteSteps)
                    return frontend_error(FrontendError::TooManyItems, step->span);
                step->has_ctx = true;
                step->ctx_index = static_cast<u32>(step_contexts.size());
                step_contexts.push_back(ctx);
                return {};
            };
            auto route_step_ctx = [&](const RouteStep& step) -> const ForLoopCtx* {
                if (!step.has_ctx) return nullptr;
                if (step.ctx_index >= step_contexts.size()) return nullptr;
                return &step_contexts[step.ctx_index];
            };
            auto push_ctx_binding = [&](ForLoopCtx* ctx,
                                        u32 ref_index,
                                        MirValue value,
                                        Span span) -> FrontendResult<void> {
                if (!fn.values.push(value))
                    return frontend_error(FrontendError::TooManyItems, span);
                ForLoopCtx::LocalBinding binding{};
                binding.ref_index = ref_index;
                binding.value = &fn.values[fn.values.len - 1];
                if (!ctx->locals.push(binding))
                    return frontend_error(FrontendError::TooManyItems, span);
                return {};
            };
            bool for_loop_is_child[kMaxForRouteSteps]{};
            for (u32 fi = 0; fi < module.routes[i].for_loops.len; fi++) {
                const auto& fl = module.routes[i].for_loops[fi];
                for (u32 si = 0; si < fl.body.steps.len; si++) {
                    const auto& body_step = fl.body.steps[si];
                    if (body_step.kind == HirForLoopBody::Step::Kind::For) {
                        if (body_step.index >= module.routes[i].for_loops.len)
                            return frontend_error(FrontendError::UnsupportedSyntax, body_step.span);
                        for_loop_is_child[body_step.index] = true;
                    }
                }
            }
            auto emit_for_loop = [&](auto&& self,
                                     u32 fi,
                                     const ForLoopCtx* parent_ctx,
                                     u32 order_start) -> FrontendResult<void> {
                const auto& fl = module.routes[i].for_loops[fi];
                const HirExpr* iter_array = iter_array_for(fl);
                // This unroll requires a compile-time-known array literal,
                // either inline in the for expression or through a
                // route-local array constant. Other array-producing
                // expressions need a runtime array carrier before they can
                // be lowered.
                const bool supported = fl.body.steps.len != 0 && iter_array != nullptr;
                if (!supported || fl.loop_var_ref_index == 0xffffffffu) {
                    return frontend_error(
                        FrontendError::UnsupportedSyntax,
                        fl.span,
                        lit_str("static for-loop body must contain at least one supported step"));
                }
                const u32 iter_count =
                    fl.body.has_term && iter_array->args.len != 0 ? 1u : iter_array->args.len;
                for (u32 ai = 0; ai < iter_count; ai++) {
                    auto elem = mir_value(*iter_array->args[ai], module, &fn, parent_ctx);
                    if (!elem) return core::make_unexpected(elem.error());
                    ForLoopCtx ctx = parent_ctx ? *parent_ctx : ForLoopCtx{};
                    auto loop_binding =
                        push_ctx_binding(&ctx, fl.loop_var_ref_index, elem.value(), fl.span);
                    if (!loop_binding) return core::make_unexpected(loop_binding.error());
                    for (u32 bi = 0; bi < fl.body.steps.len; bi++) {
                        const auto& body_step = fl.body.steps[bi];
                        if (body_step.kind == HirForLoopBody::Step::Kind::Let) {
                            if (body_step.index >= fl.body.locals.len)
                                return frontend_error(FrontendError::UnsupportedSyntax,
                                                      body_step.span);
                            const auto& local = fl.body.locals[body_step.index];
                            auto local_value = mir_value(local.init, module, &fn, &ctx);
                            if (!local_value) return core::make_unexpected(local_value.error());
                            auto local_binding = push_ctx_binding(
                                &ctx, local.ref_index, local_value.value(), local.span);
                            if (!local_binding) return core::make_unexpected(local_binding.error());
                            continue;
                        }
                        if (body_step.kind == HirForLoopBody::Step::Kind::Guard) {
                            if (body_step.index >= fl.body.guards.len)
                                return frontend_error(FrontendError::UnsupportedSyntax,
                                                      body_step.span);
                            RouteStep step{};
                            step.kind = RouteStep::Kind::Guard;
                            step.guard = &fl.body.guards[body_step.index];
                            step.span = fl.body.guards[body_step.index].span;
                            step.order_start = order_start;
                            step.order_seq = route_step_seq++;
                            auto ctx_set = set_step_ctx(&step, ctx);
                            if (!ctx_set) return core::make_unexpected(ctx_set.error());
                            if (!steps.push(step))
                                return frontend_error(FrontendError::TooManyItems, fl.span);
                            continue;
                        }
                        if (body_step.kind == HirForLoopBody::Step::Kind::If) {
                            if (body_step.index >= fl.body.ifs.len)
                                return frontend_error(FrontendError::UnsupportedSyntax,
                                                      body_step.span);
                            RouteStep step{};
                            step.kind = RouteStep::Kind::If;
                            step.body_if = &fl.body.ifs[body_step.index];
                            step.span = fl.body.ifs[body_step.index].span;
                            step.order_start = order_start;
                            step.order_seq = route_step_seq++;
                            auto ctx_set = set_step_ctx(&step, ctx);
                            if (!ctx_set) return core::make_unexpected(ctx_set.error());
                            if (!steps.push(step))
                                return frontend_error(FrontendError::TooManyItems, fl.span);
                            continue;
                        }
                        if (body_step.kind == HirForLoopBody::Step::Kind::Match) {
                            if (body_step.index >= fl.body.matches.len)
                                return frontend_error(FrontendError::UnsupportedSyntax,
                                                      body_step.span);
                            RouteStep step{};
                            step.kind = RouteStep::Kind::Match;
                            step.body_match = &fl.body.matches[body_step.index];
                            step.span = fl.body.matches[body_step.index].span;
                            step.order_start = order_start;
                            step.order_seq = route_step_seq++;
                            auto ctx_set = set_step_ctx(&step, ctx);
                            if (!ctx_set) return core::make_unexpected(ctx_set.error());
                            if (!steps.push(step))
                                return frontend_error(FrontendError::TooManyItems, fl.span);
                            continue;
                        }
                        if (body_step.kind == HirForLoopBody::Step::Kind::For) {
                            if (body_step.index >= module.routes[i].for_loops.len)
                                return frontend_error(FrontendError::UnsupportedSyntax,
                                                      body_step.span);
                            auto child = self(self, body_step.index, &ctx, order_start);
                            if (!child) return core::make_unexpected(child.error());
                            continue;
                        }
                        RouteStep step{};
                        step.kind = RouteStep::Kind::Term;
                        step.term = &fl.body.term;
                        step.span = fl.body.term.span;
                        step.order_start = order_start;
                        step.order_seq = route_step_seq++;
                        auto ctx_set = set_step_ctx(&step, ctx);
                        if (!ctx_set) return core::make_unexpected(ctx_set.error());
                        if (!steps.push(step))
                            return frontend_error(FrontendError::TooManyItems, fl.span);
                    }
                }
                return {};
            };
            for (u32 gi = 0; gi < module.routes[i].guards.len; gi++) {
                RouteStep step{};
                step.kind = RouteStep::Kind::Guard;
                step.guard = &module.routes[i].guards[gi];
                step.span = module.routes[i].guards[gi].span;
                step.order_start = step.span.start;
                step.order_seq = route_step_seq++;
                if (!steps.push(step))
                    return frontend_error(FrontendError::TooManyItems,
                                          module.routes[i].guards[gi].span);
            }
            if (module.routes[i].control.kind != HirControlKind::Direct &&
                module.routes[i].control.kind != HirControlKind::If &&
                module.routes[i].control.kind != HirControlKind::Match) {
                return frontend_error(FrontendError::UnsupportedSyntax,
                                      module.routes[i].for_loops[0].span);
            }
            for (u32 fi = 0; fi < module.routes[i].for_loops.len; fi++) {
                if (for_loop_is_child[fi]) continue;
                auto emitted = emit_for_loop(
                    emit_for_loop, fi, nullptr, module.routes[i].for_loops[fi].span.start);
                if (!emitted) return core::make_unexpected(emitted.error());
            }
            for (u32 si = 1; si < steps.len; si++) {
                RouteStep cur = steps[si];
                u32 pos = si;
                while (pos > 0 && (cur.order_start < steps[pos - 1].order_start ||
                                   (cur.order_start == steps[pos - 1].order_start &&
                                    cur.order_seq < steps[pos - 1].order_seq))) {
                    steps[pos] = steps[pos - 1];
                    pos--;
                }
                steps[pos] = cur;
            }

            u32 step_count = steps.len;
            bool has_terminating_step = false;
            u32 terminating_step_index = 0xffffffffu;
            for (u32 si = 0; si < steps.len; si++) {
                if (steps[si].kind == RouteStep::Kind::Term ||
                    steps[si].kind == RouteStep::Kind::If ||
                    steps[si].kind == RouteStep::Kind::Match) {
                    step_count = si + 1;
                    has_terminating_step = true;
                    terminating_step_index = si;
                    break;
                }
            }

            const u32 terminal_index = step_count;
            const bool route_control_is_if =
                module.routes[i].control.kind == HirControlKind::If && !has_terminating_step;
            const u32 then_index = route_control_is_if ? terminal_index + 1 : 0;
            const u32 else_index = route_control_is_if ? terminal_index + 2 : 0;
            u32 match_arm_block_index[HirControl::kMaxMatchArms]{};
            u32 match_arm_body_index[HirControl::kMaxMatchArms]{};
            u32 match_arm_then_index[HirControl::kMaxMatchArms]{};
            u32 match_arm_else_index[HirControl::kMaxMatchArms]{};
            u32 match_arm_guard_index[HirControl::kMaxMatchArms][HirMatchArm::kMaxPreludeGuards]{};
            u32 match_arm_guard_fail_index[HirControl::kMaxMatchArms]
                                          [HirMatchArm::kMaxPreludeGuards]{};
            u32 match_arm_count = 0;
            u32 match_test_count = 0;
            u32 match_end_index = 0;
            u32 body_match_extra_test_index[HirForLoopMatch::kMaxMatchArms]{};
            u32 body_match_test_ordinal[HirForLoopMatch::kMaxMatchArms]{};
            u32 body_match_guard_index[HirForLoopMatch::kMaxMatchArms]{};
            u32 body_match_prelude_guard_index[HirForLoopMatch::kMaxMatchArms]
                                              [HirForLoopMatchArm::kMaxPreludeGuards]{};
            u32 body_match_prelude_guard_fail_index[HirForLoopMatch::kMaxMatchArms]
                                                   [HirForLoopMatchArm::kMaxPreludeGuards]{};
            u32 body_match_case_index[HirForLoopMatch::kMaxMatchArms]{};
            u32 body_match_then_index[HirForLoopMatch::kMaxMatchArms]{};
            u32 body_match_else_index[HirForLoopMatch::kMaxMatchArms]{};
            u32 body_match_non_wildcard_count = 0;
            u32 body_match_end_index = 0;
            bool block_budget_overflow = false;
            Span block_budget_span = module.routes[i].span;
            auto note_block_budget = [&](u32 next_index, Span span) {
                if (!block_budget_overflow && next_index > MirFunction::kMaxBlocks) {
                    block_budget_overflow = true;
                    block_budget_span = span;
                }
            };
            auto reserve_blocks = [&](u32* cursor, u32 count, Span span) -> u32 {
                const u32 first = *cursor;
                *cursor += count;
                note_block_budget(*cursor, span);
                return first;
            };
            if (module.routes[i].control.kind == HirControlKind::Match && !has_terminating_step) {
                match_arm_count = module.routes[i].control.match_arms.len;
                match_test_count = match_arm_count - 1;
                u32 next_index = terminal_index + match_test_count;
                note_block_budget(next_index, module.routes[i].span);
                for (u32 ai = 0; ai < match_arm_count; ai++) {
                    const auto& arm = module.routes[i].control.match_arms[ai];
                    match_arm_block_index[ai] = reserve_blocks(&next_index, 1, arm.span);
                    if (arm.guards.len != 0) {
                        if (arm.has_arm_guard)
                            match_arm_guard_index[ai][0] = reserve_blocks(&next_index, 1, arm.span);
                        for (u32 gi = 1; gi < arm.guards.len; gi++)
                            match_arm_guard_index[ai][gi] =
                                reserve_blocks(&next_index, 1, arm.guards[gi].span);
                        match_arm_body_index[ai] = reserve_blocks(&next_index, 1, arm.span);
                        for (u32 gi = 0; gi < arm.guards.len; gi++) {
                            match_arm_guard_fail_index[ai][gi] = next_index;
                            reserve_blocks(&next_index,
                                           guard_fail_block_count(arm.guards[gi]),
                                           arm.guards[gi].span);
                        }
                    } else if (arm.has_arm_guard) {
                        match_arm_body_index[ai] = reserve_blocks(&next_index, 1, arm.span);
                    } else {
                        match_arm_body_index[ai] = match_arm_block_index[ai];
                    }
                    if (arm.body_kind == HirMatchArm::BodyKind::If) {
                        match_arm_then_index[ai] = reserve_blocks(&next_index, 1, arm.span);
                        match_arm_else_index[ai] = reserve_blocks(&next_index, 1, arm.span);
                    }
                }
                match_end_index = next_index;
            }
            u32 guard_fail_index[kMaxForRouteSteps]{};
            u32 fail_cursor = terminal_index;
            if (has_terminating_step && steps[terminating_step_index].kind == RouteStep::Kind::If) {
                fail_cursor = terminal_index + 2;
            } else if (has_terminating_step &&
                       steps[terminating_step_index].kind == RouteStep::Kind::Match) {
                const auto& body_match = *steps[terminating_step_index].body_match;
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    if (!body_match.arms[ai].is_wildcard) {
                        body_match_test_ordinal[ai] = body_match_non_wildcard_count++;
                    }
                }
                u32 cursor = terminal_index;
                note_block_budget(cursor, steps[terminating_step_index].span);
                for (u32 ai = 1; ai < body_match_non_wildcard_count; ai++) {
                    body_match_extra_test_index[ai] =
                        reserve_blocks(&cursor, 1, steps[terminating_step_index].span);
                }
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    if (body_match.arms[ai].has_arm_guard)
                        body_match_guard_index[ai] =
                            reserve_blocks(&cursor, 1, body_match.arms[ai].span);
                }
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    for (u32 gi = 0; gi < body_match.arms[ai].guards.len; gi++) {
                        body_match_prelude_guard_index[ai][gi] =
                            reserve_blocks(&cursor, 1, body_match.arms[ai].guards[gi].span);
                    }
                }
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    body_match_case_index[ai] =
                        reserve_blocks(&cursor, 1, body_match.arms[ai].span);
                    if (body_match.arms[ai].body_kind == HirForLoopMatchArm::BodyKind::If) {
                        body_match_then_index[ai] =
                            reserve_blocks(&cursor, 1, body_match.arms[ai].span);
                        body_match_else_index[ai] =
                            reserve_blocks(&cursor, 1, body_match.arms[ai].span);
                    }
                }
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    for (u32 gi = 0; gi < body_match.arms[ai].guards.len; gi++) {
                        body_match_prelude_guard_fail_index[ai][gi] = cursor;
                        reserve_blocks(&cursor,
                                       guard_fail_block_count(body_match.arms[ai].guards[gi]),
                                       body_match.arms[ai].guards[gi].span);
                    }
                }
                body_match_end_index = cursor;
                fail_cursor = body_match_end_index;
            }
            if (!has_terminating_step) {
                if (module.routes[i].control.kind == HirControlKind::Direct) {
                    fail_cursor = terminal_index + 1;
                    note_block_budget(fail_cursor, module.routes[i].span);
                } else if (module.routes[i].control.kind == HirControlKind::If) {
                    fail_cursor = terminal_index + 3;
                    note_block_budget(fail_cursor, module.routes[i].span);
                } else {
                    fail_cursor = match_end_index;
                }
            }
            for (u32 si = 0; si < step_count; si++) {
                if (steps[si].kind != RouteStep::Kind::Guard) continue;
                guard_fail_index[si] = fail_cursor;
                reserve_blocks(
                    &fail_cursor, guard_fail_block_count(*steps[si].guard), steps[si].span);
            }
            if (fail_cursor > MirFunction::kMaxBlocks)
                return frontend_error(FrontendError::TooManyItems,
                                      block_budget_span,
                                      lit_str("static for-loop block budget exceeded"));

            auto extend_for_loop_match_arm_ctx =
                [&](const HirForLoopMatchArm& arm,
                    const ForLoopCtx* base_ctx,
                    ForLoopCtx* scoped_ctx) -> FrontendResult<const ForLoopCtx*> {
                if (arm.locals.len == 0) return base_ctx;
                if (base_ctx != nullptr) *scoped_ctx = *base_ctx;
                const ForLoopCtx* body_ctx = scoped_ctx;
                for (u32 li = 0; li < arm.locals.len; li++) {
                    const auto& local = arm.locals[li];
                    auto local_value = mir_value(local.init, module, &fn, body_ctx);
                    if (!local_value) return core::make_unexpected(local_value.error());
                    auto local_binding = push_ctx_binding(
                        scoped_ctx, local.ref_index, local_value.value(), local.span);
                    if (!local_binding) return core::make_unexpected(local_binding.error());
                }
                return body_ctx;
            };
            auto body_match_arm_entry_index = [&](const HirForLoopMatchArm& arm,
                                                  u32 arm_index) -> u32 {
                if (arm.has_arm_guard) return body_match_guard_index[arm_index];
                if (arm.guards.len != 0) return body_match_prelude_guard_index[arm_index][0];
                return body_match_case_index[arm_index];
            };
            auto body_match_arm_body_index = [&](const HirForLoopMatchArm& arm,
                                                 u32 arm_index) -> u32 {
                if (arm.guards.len != 0) return body_match_prelude_guard_index[arm_index][0];
                return body_match_case_index[arm_index];
            };
            auto emit_body_match_prelude_guards =
                [&](const HirForLoopMatch& body_match,
                    const ForLoopCtx* ctx) -> FrontendResult<void> {
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    const auto& arm = body_match.arms[ai];
                    ForLoopCtx scoped_ctx{};
                    auto body_ctx = extend_for_loop_match_arm_ctx(arm, ctx, &scoped_ctx);
                    if (!body_ctx) return core::make_unexpected(body_ctx.error());
                    for (u32 gi = 0; gi < arm.guards.len; gi++) {
                        MirBlock guard_block{};
                        guard_block.label = cont_label();
                        guard_block.term.kind = MirTerminatorKind::Branch;
                        guard_block.term.span = arm.guards[gi].span;
                        auto cond = mir_value(arm.guards[gi].cond, module, &fn, body_ctx.value());
                        if (!cond) return core::make_unexpected(cond.error());
                        guard_block.term.cond = cond.value();
                        guard_block.term.then_block =
                            gi + 1 < arm.guards.len ? body_match_prelude_guard_index[ai][gi + 1]
                                                    : body_match_case_index[ai];
                        guard_block.term.else_block = body_match_prelude_guard_fail_index[ai][gi];
                        if (!fn.blocks.push(guard_block))
                            return frontend_error(FrontendError::TooManyItems, fn.span);
                    }
                }
                return {};
            };
            auto emit_body_match_prelude_guard_fails =
                [&](const HirForLoopMatch& body_match,
                    const ForLoopCtx* ctx) -> FrontendResult<void> {
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    const auto& arm = body_match.arms[ai];
                    ForLoopCtx scoped_ctx{};
                    auto body_ctx = extend_for_loop_match_arm_ctx(arm, ctx, &scoped_ctx);
                    if (!body_ctx) return core::make_unexpected(body_ctx.error());
                    for (u32 gi = 0; gi < arm.guards.len; gi++) {
                        auto emitted = emit_guard_fail(arm.guards[gi], body_ctx.value());
                        if (!emitted) return core::make_unexpected(emitted.error());
                    }
                }
                return {};
            };

            for (u32 si = 0; si < step_count; si++) {
                const ForLoopCtx* step_ctx = route_step_ctx(steps[si]);
                MirBlock block{};
                block.label = si == 0 ? entry_label() : cont_label();
                if (steps[si].kind == RouteStep::Kind::Term) {
                    set_term_from_hir(&block.term, *steps[si].term);
                    if (!fn.blocks.push(block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                    continue;
                }
                if (steps[si].kind == RouteStep::Kind::If) {
                    block.term.kind = MirTerminatorKind::Branch;
                    block.term.span = steps[si].body_if->span;
                    auto cond = mir_value(steps[si].body_if->cond, module, &fn, step_ctx);
                    if (!cond) return core::make_unexpected(cond.error());
                    block.term.cond = cond.value();
                    block.term.then_block = terminal_index;
                    block.term.else_block = terminal_index + 1;
                    if (!fn.blocks.push(block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                    continue;
                }
                if (steps[si].kind == RouteStep::Kind::Match) {
                    const auto& body_match = *steps[si].body_match;
                    if (body_match.arms.len == 0)
                        return frontend_error(FrontendError::UnsupportedSyntax, body_match.span);
                    auto subject = mir_value(body_match.match_expr, module, &fn, step_ctx);
                    if (!subject) return core::make_unexpected(subject.error());
                    auto body_match_fallthrough_target = [&](u32 arm_index) -> u32 {
                        for (u32 next = arm_index + 1; next < body_match.arms.len; next++) {
                            if (body_match.arms[next].is_wildcard)
                                return body_match_arm_entry_index(body_match.arms[next], next);
                            const u32 ordinal = body_match_test_ordinal[next];
                            return ordinal == 0 ? si : body_match_extra_test_index[ordinal];
                        }
                        return body_match_arm_entry_index(body_match.arms[body_match.arms.len - 1],
                                                          body_match.arms.len - 1);
                    };
                    if (body_match_non_wildcard_count == 0) {
                        block.term.kind = MirTerminatorKind::Branch;
                        block.term.cond.kind = MirValueKind::BoolConst;
                        block.term.cond.type = MirTypeKind::Bool;
                        block.term.cond.bool_value = true;
                        block.term.then_block = body_match_arm_entry_index(body_match.arms[0], 0);
                        block.term.else_block = block.term.then_block;
                    } else {
                        auto arm_pattern =
                            mir_value(body_match.arms[0].pattern, module, &fn, step_ctx);
                        if (!arm_pattern) return core::make_unexpected(arm_pattern.error());
                        block.term.kind = MirTerminatorKind::Branch;
                        block.term.use_cmp = true;
                        block.term.span = body_match.arms[0].span;
                        block.term.lhs = subject.value();
                        block.term.rhs = arm_pattern.value();
                        block.term.then_block = body_match_arm_entry_index(body_match.arms[0], 0);
                        block.term.else_block = body_match_non_wildcard_count > 1
                                                    ? body_match_extra_test_index[1]
                                                    : body_match_fallthrough_target(0);
                    }
                    if (!fn.blocks.push(block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                    continue;
                }
                block.term.kind = MirTerminatorKind::Branch;
                block.term.span = steps[si].guard->span;
                auto cond = mir_value(steps[si].guard->cond, module, &fn, step_ctx);
                if (!cond) return core::make_unexpected(cond.error());
                block.term.cond = cond.value();
                block.term.then_block = si + 1 < step_count ? si + 1 : terminal_index;
                block.term.else_block = guard_fail_index[si];
                if (!fn.blocks.push(block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);
            }

            if (has_terminating_step && steps[terminating_step_index].kind == RouteStep::Kind::If) {
                const auto& body_if = *steps[terminating_step_index].body_if;
                MirBlock then_block{};
                then_block.label = then_label();
                set_term_from_hir(&then_block.term, body_if.then_term);
                if (!fn.blocks.push(then_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);

                MirBlock else_block{};
                else_block.label = else_label();
                set_term_from_hir(&else_block.term, body_if.else_term);
                if (!fn.blocks.push(else_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);
            } else if (has_terminating_step &&
                       steps[terminating_step_index].kind == RouteStep::Kind::Match) {
                const auto& body_match = *steps[terminating_step_index].body_match;
                const ForLoopCtx* terminating_ctx = route_step_ctx(steps[terminating_step_index]);
                auto subject = mir_value(body_match.match_expr, module, &fn, terminating_ctx);
                if (!subject) return core::make_unexpected(subject.error());
                auto body_match_fallthrough_target = [&](u32 arm_index) -> u32 {
                    for (u32 next = arm_index + 1; next < body_match.arms.len; next++) {
                        if (body_match.arms[next].is_wildcard)
                            return body_match_arm_entry_index(body_match.arms[next], next);
                        return body_match_extra_test_index[body_match_test_ordinal[next]];
                    }
                    return body_match_arm_entry_index(body_match.arms[body_match.arms.len - 1],
                                                      body_match.arms.len - 1);
                };
                auto set_body_match_arm_term = [&](MirBlock* out,
                                                   const HirForLoopMatchArm& arm,
                                                   u32 arm_index) -> FrontendResult<void> {
                    ForLoopCtx scoped_ctx{};
                    auto body_ctx =
                        extend_for_loop_match_arm_ctx(arm, terminating_ctx, &scoped_ctx);
                    if (!body_ctx) return core::make_unexpected(body_ctx.error());
                    if (arm.body_kind == HirForLoopMatchArm::BodyKind::If) {
                        out->term.kind = MirTerminatorKind::Branch;
                        out->term.span = arm.cond.span;
                        auto cond = mir_value(arm.cond, module, &fn, body_ctx.value());
                        if (!cond) return core::make_unexpected(cond.error());
                        out->term.cond = cond.value();
                        out->term.then_block = body_match_then_index[arm_index];
                        out->term.else_block = body_match_else_index[arm_index];
                    } else {
                        set_term_from_hir(&out->term, arm.direct_term);
                    }
                    return {};
                };
                for (u32 ai = 1; ai < body_match_non_wildcard_count; ai++) {
                    MirBlock test_block{};
                    test_block.label = match_test_label();
                    auto arm_pattern =
                        mir_value(body_match.arms[ai].pattern, module, &fn, terminating_ctx);
                    if (!arm_pattern) return core::make_unexpected(arm_pattern.error());
                    test_block.term.kind = MirTerminatorKind::Branch;
                    test_block.term.use_cmp = true;
                    test_block.term.span = body_match.arms[ai].span;
                    test_block.term.lhs = subject.value();
                    test_block.term.rhs = arm_pattern.value();
                    test_block.term.then_block =
                        body_match_arm_entry_index(body_match.arms[ai], ai);
                    test_block.term.else_block = ai + 1 < body_match_non_wildcard_count
                                                     ? body_match_extra_test_index[ai + 1]
                                                     : body_match_fallthrough_target(ai);
                    if (!fn.blocks.push(test_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                }
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    const auto& arm = body_match.arms[ai];
                    if (!arm.has_arm_guard) continue;
                    ForLoopCtx scoped_ctx{};
                    auto body_ctx =
                        extend_for_loop_match_arm_ctx(arm, terminating_ctx, &scoped_ctx);
                    if (!body_ctx) return core::make_unexpected(body_ctx.error());
                    MirBlock guard_block{};
                    guard_block.label = cont_label();
                    guard_block.term.kind = MirTerminatorKind::Branch;
                    guard_block.term.span = arm.arm_guard.span;
                    auto guard = mir_value(arm.arm_guard, module, &fn, body_ctx.value());
                    if (!guard) return core::make_unexpected(guard.error());
                    guard_block.term.cond = guard.value();
                    guard_block.term.then_block =
                        body_match_arm_body_index(body_match.arms[ai], ai);
                    guard_block.term.else_block = body_match_fallthrough_target(ai);
                    if (!fn.blocks.push(guard_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                }
                auto prelude_guards = emit_body_match_prelude_guards(body_match, terminating_ctx);
                if (!prelude_guards) return core::make_unexpected(prelude_guards.error());
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    MirBlock case_block{};
                    case_block.label = body_match.arms[ai].is_wildcard ? match_default_label()
                                                                       : match_case_label();
                    auto armed = set_body_match_arm_term(&case_block, body_match.arms[ai], ai);
                    if (!armed) return core::make_unexpected(armed.error());
                    if (!fn.blocks.push(case_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                    if (body_match.arms[ai].body_kind == HirForLoopMatchArm::BodyKind::If) {
                        MirBlock then_block{};
                        then_block.label = then_label();
                        set_term_from_hir(&then_block.term, body_match.arms[ai].then_term);
                        if (!fn.blocks.push(then_block))
                            return frontend_error(FrontendError::TooManyItems, fn.span);

                        MirBlock else_block{};
                        else_block.label = else_label();
                        set_term_from_hir(&else_block.term, body_match.arms[ai].else_term);
                        if (!fn.blocks.push(else_block))
                            return frontend_error(FrontendError::TooManyItems, fn.span);
                    }
                }
                auto prelude_fails =
                    emit_body_match_prelude_guard_fails(body_match, terminating_ctx);
                if (!prelude_fails) return core::make_unexpected(prelude_fails.error());
            }

            if (!has_terminating_step) {
                // Body block: the route's terminal control after every
                // guard-only loop iteration has passed.
                MirBlock body_block{};
                body_block.label = cont_label();
                if (module.routes[i].control.kind == HirControlKind::Direct) {
                    set_term_from_hir(&body_block.term, module.routes[i].control.direct_term);
                    if (!fn.blocks.push(body_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                } else if (module.routes[i].control.kind == HirControlKind::If) {
                    body_block.term.kind = MirTerminatorKind::Branch;
                    body_block.term.span = module.routes[i].control.cond.span;
                    auto if_cond = mir_value(module.routes[i].control.cond, module, &fn);
                    if (!if_cond) return core::make_unexpected(if_cond.error());
                    body_block.term.cond = if_cond.value();
                    body_block.term.then_block = then_index;
                    body_block.term.else_block = else_index;
                    if (!fn.blocks.push(body_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);

                    MirBlock then_block{};
                    then_block.label = then_label();
                    set_term_from_hir(&then_block.term, module.routes[i].control.then_term);
                    if (!fn.blocks.push(then_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);

                    MirBlock else_block{};
                    else_block.label = else_label();
                    set_term_from_hir(&else_block.term, module.routes[i].control.else_term);
                    if (!fn.blocks.push(else_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                } else {
                    auto subject = mir_value(module.routes[i].control.match_expr, module, &fn);
                    if (!subject) return core::make_unexpected(subject.error());
                    auto arm_fallthrough_target = [&](u32 ai) -> FrontendResult<u32> {
                        if (ai + 1 < match_test_count) return terminal_index + ai + 1;
                        if (ai + 1 < match_arm_count) return match_arm_block_index[ai + 1];
                        return frontend_error(FrontendError::UnsupportedSyntax,
                                              module.routes[i].control.match_arms[ai].span);
                    };
                    if (match_test_count == 0) {
                        const auto& arm = module.routes[i].control.match_arms[0];
                        body_block.label =
                            arm.is_wildcard ? match_default_label() : match_case_label();
                        if (arm.has_arm_guard) {
                            auto guarded = set_match_arm_guard_branch(
                                body_block,
                                arm,
                                match_arm_guard_index[0][0],
                                match_arm_body_index[0],
                                [&] { return arm_fallthrough_target(0); });
                            if (!guarded) return core::make_unexpected(guarded.error());
                        } else if (arm.guards.len != 0) {
                            auto cond = mir_value(arm.guards[0].cond, module, &fn);
                            if (!cond) return core::make_unexpected(cond.error());
                            body_block.term.kind = MirTerminatorKind::Branch;
                            body_block.term.span = arm.guards[0].span;
                            body_block.term.cond = cond.value();
                            body_block.term.then_block = arm.guards.len > 1
                                                             ? match_arm_guard_index[0][1]
                                                             : match_arm_body_index[0];
                            body_block.term.else_block = match_arm_guard_fail_index[0][0];
                        } else if (arm.body_kind == HirMatchArm::BodyKind::If) {
                            body_block.term.kind = MirTerminatorKind::Branch;
                            body_block.term.span = arm.cond.span;
                            auto cond = mir_value(arm.cond, module, &fn);
                            if (!cond) return core::make_unexpected(cond.error());
                            body_block.term.cond = cond.value();
                            body_block.term.then_block = match_arm_then_index[0];
                            body_block.term.else_block = match_arm_else_index[0];
                        } else {
                            set_term_from_hir(&body_block.term, arm.direct_term);
                        }
                        if (!fn.blocks.push(body_block))
                            return frontend_error(FrontendError::TooManyItems, fn.span);
                        auto guard_blocks =
                            emit_match_prelude_guard_blocks(arm,
                                                            0,
                                                            match_arm_guard_index,
                                                            match_arm_guard_fail_index,
                                                            match_arm_body_index);
                        if (!guard_blocks) return core::make_unexpected(guard_blocks.error());
                        if (arm.guards.len != 0 || arm.has_arm_guard) {
                            MirBlock match_body_block{};
                            match_body_block.label = cont_label();
                            if (arm.body_kind == HirMatchArm::BodyKind::If) {
                                match_body_block.term.kind = MirTerminatorKind::Branch;
                                match_body_block.term.span = arm.cond.span;
                                auto cond = mir_value(arm.cond, module, &fn);
                                if (!cond) return core::make_unexpected(cond.error());
                                match_body_block.term.cond = cond.value();
                                match_body_block.term.then_block = match_arm_then_index[0];
                                match_body_block.term.else_block = match_arm_else_index[0];
                            } else {
                                set_term_from_hir(&match_body_block.term, arm.direct_term);
                            }
                            if (!fn.blocks.push(match_body_block))
                                return frontend_error(FrontendError::TooManyItems, fn.span);
                            for (u32 gi = 0; gi < arm.guards.len; gi++) {
                                auto emitted = emit_guard_fail(arm.guards[gi]);
                                if (!emitted) return core::make_unexpected(emitted.error());
                            }
                        }
                        if (arm.body_kind == HirMatchArm::BodyKind::If) {
                            MirBlock then_block{};
                            then_block.label = then_label();
                            set_term_from_hir(&then_block.term, arm.then_term);
                            if (!fn.blocks.push(then_block))
                                return frontend_error(FrontendError::TooManyItems, fn.span);
                            MirBlock else_block{};
                            else_block.label = else_label();
                            set_term_from_hir(&else_block.term, arm.else_term);
                            if (!fn.blocks.push(else_block))
                                return frontend_error(FrontendError::TooManyItems, fn.span);
                        }
                    } else {
                        for (u32 ai = 0; ai < match_test_count; ai++) {
                            MirBlock test_block{};
                            test_block.label = ai == 0 ? cont_label() : match_test_label();
                            const auto& arm = module.routes[i].control.match_arms[ai];
                            auto arm_pattern = mir_value(arm.pattern, module, &fn);
                            if (!arm_pattern) return core::make_unexpected(arm_pattern.error());
                            test_block.term.kind = MirTerminatorKind::Branch;
                            test_block.term.use_cmp = true;
                            test_block.term.span = arm.span;
                            test_block.term.lhs = subject.value();
                            test_block.term.rhs = arm_pattern.value();
                            test_block.term.then_block = match_arm_block_index[ai];
                            test_block.term.else_block =
                                ai + 1 < match_test_count ? terminal_index + ai + 1
                                                          : match_arm_block_index[match_test_count];
                            if (!fn.blocks.push(test_block))
                                return frontend_error(FrontendError::TooManyItems, fn.span);
                        }
                        for (u32 ai = 0; ai < match_arm_count; ai++) {
                            MirBlock case_block{};
                            const auto& arm = module.routes[i].control.match_arms[ai];
                            case_block.label =
                                arm.is_wildcard ? match_default_label() : match_case_label();
                            if (arm.has_arm_guard) {
                                auto guarded = set_match_arm_guard_branch(
                                    case_block,
                                    arm,
                                    match_arm_guard_index[ai][0],
                                    match_arm_body_index[ai],
                                    [&] { return arm_fallthrough_target(ai); });
                                if (!guarded) return core::make_unexpected(guarded.error());
                            } else if (arm.guards.len != 0) {
                                auto cond = mir_value(arm.guards[0].cond, module, &fn);
                                if (!cond) return core::make_unexpected(cond.error());
                                case_block.term.kind = MirTerminatorKind::Branch;
                                case_block.term.span = arm.guards[0].span;
                                case_block.term.cond = cond.value();
                                case_block.term.then_block = arm.guards.len > 1
                                                                 ? match_arm_guard_index[ai][1]
                                                                 : match_arm_body_index[ai];
                                case_block.term.else_block = match_arm_guard_fail_index[ai][0];
                            } else if (arm.body_kind == HirMatchArm::BodyKind::If) {
                                case_block.term.kind = MirTerminatorKind::Branch;
                                case_block.term.span = arm.cond.span;
                                auto cond = mir_value(arm.cond, module, &fn);
                                if (!cond) return core::make_unexpected(cond.error());
                                case_block.term.cond = cond.value();
                                case_block.term.then_block = match_arm_then_index[ai];
                                case_block.term.else_block = match_arm_else_index[ai];
                            } else {
                                set_term_from_hir(&case_block.term, arm.direct_term);
                            }
                            if (!fn.blocks.push(case_block))
                                return frontend_error(FrontendError::TooManyItems, fn.span);
                            auto guard_blocks =
                                emit_match_prelude_guard_blocks(arm,
                                                                ai,
                                                                match_arm_guard_index,
                                                                match_arm_guard_fail_index,
                                                                match_arm_body_index);
                            if (!guard_blocks) return core::make_unexpected(guard_blocks.error());
                            if (arm.guards.len != 0 || arm.has_arm_guard) {
                                MirBlock match_body_block{};
                                match_body_block.label = cont_label();
                                if (arm.body_kind == HirMatchArm::BodyKind::If) {
                                    match_body_block.term.kind = MirTerminatorKind::Branch;
                                    match_body_block.term.span = arm.cond.span;
                                    auto cond = mir_value(arm.cond, module, &fn);
                                    if (!cond) return core::make_unexpected(cond.error());
                                    match_body_block.term.cond = cond.value();
                                    match_body_block.term.then_block = match_arm_then_index[ai];
                                    match_body_block.term.else_block = match_arm_else_index[ai];
                                } else {
                                    set_term_from_hir(&match_body_block.term, arm.direct_term);
                                }
                                if (!fn.blocks.push(match_body_block))
                                    return frontend_error(FrontendError::TooManyItems, fn.span);
                                for (u32 gi = 0; gi < arm.guards.len; gi++) {
                                    auto emitted = emit_guard_fail(arm.guards[gi]);
                                    if (!emitted) return core::make_unexpected(emitted.error());
                                }
                            }
                            if (arm.body_kind == HirMatchArm::BodyKind::If) {
                                MirBlock then_block{};
                                then_block.label = then_label();
                                set_term_from_hir(&then_block.term, arm.then_term);
                                if (!fn.blocks.push(then_block))
                                    return frontend_error(FrontendError::TooManyItems, fn.span);
                                MirBlock else_block{};
                                else_block.label = else_label();
                                set_term_from_hir(&else_block.term, arm.else_term);
                                if (!fn.blocks.push(else_block))
                                    return frontend_error(FrontendError::TooManyItems, fn.span);
                            }
                        }
                    }
                }
            }

            // Fail blocks, one per route/virtual guard step.
            for (u32 si = 0; si < step_count; si++) {
                if (steps[si].kind != RouteStep::Kind::Guard) continue;
                auto emitted = emit_guard_fail(*steps[si].guard, route_step_ctx(steps[si]));
                if (!emitted) return core::make_unexpected(emitted.error());
            }

            if (!mir->functions.push(fn))
                return frontend_error(FrontendError::TooManyItems, fn.span);
            continue;
        }

        if (fn.waits.len != 0 && module.routes[i].decorator_guard_count != 0) {
            const u32 guard_count = module.routes[i].guards.len;
            const bool scope = module.routes[i].control.kind == HirControlKind::Direct &&
                               fn.waits.len <= MirFunction::kMaxWaits;
            if (!scope) return frontend_error(FrontendError::UnsupportedSyntax, fn.span);

            const u32 yield_index = guard_count;
            const u32 terminal_index = yield_index + 1;
            u32 guard_fail_index[HirRoute::kMaxGuards]{};
            u32 fail_cursor = terminal_index + 1;
            for (u32 gi = 0; gi < guard_count; gi++) {
                guard_fail_index[gi] = fail_cursor;
                fail_cursor += guard_fail_block_count(module.routes[i].guards[gi]);
            }
            if (fail_cursor > MirFunction::kMaxBlocks)
                return frontend_error(FrontendError::TooManyItems, fn.span);

            for (u32 gi = 0; gi < guard_count; gi++) {
                const auto& guard = module.routes[i].guards[gi];
                MirBlock guard_block{};
                guard_block.label = gi == 0 ? entry_label() : cont_label();
                guard_block.term.kind = MirTerminatorKind::Branch;
                guard_block.term.span = guard.span;
                auto cond = mir_value(guard.cond, module, &fn);
                if (!cond) return core::make_unexpected(cond.error());
                guard_block.term.cond = cond.value();
                guard_block.term.then_block = gi + 1 < guard_count ? gi + 1 : yield_index;
                guard_block.term.else_block = guard_fail_index[gi];
                if (!fn.blocks.push(guard_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);
            }

            MirBlock yield_block{};
            yield_block.label = cont_label();
            yield_block.term.kind = MirTerminatorKind::YieldTimer;
            yield_block.term.span = fn.waits[0].span;
            yield_block.term.yield_event_kind = fn.waits[0].event_kind;
            yield_block.term.yield_ms = fn.waits[0].ms;
            yield_block.term.yield_arm_mask = fn.waits[0].arm_mask;
            yield_block.term.yield_next_state = 1;
            if (!fn.blocks.push(yield_block))
                return frontend_error(FrontendError::TooManyItems, fn.span);

            MirBlock terminal_block{};
            terminal_block.label = cont_label();
            set_term_from_hir(&terminal_block.term, module.routes[i].control.direct_term);
            if (!fn.blocks.push(terminal_block))
                return frontend_error(FrontendError::TooManyItems, fn.span);

            for (u32 gi = 0; gi < guard_count; gi++) {
                auto emitted = emit_guard_fail(module.routes[i].guards[gi]);
                if (!emitted) return core::make_unexpected(emitted.error());
            }

            fn.state_zero_enters_entry = true;
            fn.resume_terminal_block = terminal_index;
            if (!mir->functions.push(fn))
                return frontend_error(FrontendError::TooManyItems, fn.span);
            continue;
        }

        MirBlock block{};
        block.label = entry_label();
        if (module.routes[i].guards.len != 0) {
            const u32 guard_count = module.routes[i].guards.len;

            if (module.routes[i].control.kind == HirControlKind::Direct) {
                const u32 body_index = guard_count;
                u32 guard_fail_index[HirRoute::kMaxGuards]{};
                u32 fail_cursor = body_index + 1;
                for (u32 gi = 0; gi < guard_count; gi++) {
                    guard_fail_index[gi] = fail_cursor;
                    fail_cursor += guard_fail_block_count(module.routes[i].guards[gi]);
                }
                const auto& guard0 = module.routes[i].guards[0];
                block.term.kind = MirTerminatorKind::Branch;
                block.term.span = guard0.span;
                auto cond0 = mir_value(guard0.cond, module, &fn);
                if (!cond0) return core::make_unexpected(cond0.error());
                block.term.cond = cond0.value();
                block.term.then_block = guard_count > 1 ? 1 : body_index;
                block.term.else_block = guard_fail_index[0];
                if (!fn.blocks.push(block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);

                for (u32 gi = 1; gi < guard_count; gi++) {
                    MirBlock guard_block{};
                    guard_block.label = cont_label();
                    const auto& guard = module.routes[i].guards[gi];
                    guard_block.term.kind = MirTerminatorKind::Branch;
                    guard_block.term.span = guard.span;
                    auto cond = mir_value(guard.cond, module, &fn);
                    if (!cond) return core::make_unexpected(cond.error());
                    guard_block.term.cond = cond.value();
                    guard_block.term.then_block = gi + 1 < guard_count ? gi + 1 : body_index;
                    guard_block.term.else_block = guard_fail_index[gi];
                    if (!fn.blocks.push(guard_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                }

                MirBlock cont_block{};
                cont_block.label = cont_label();
                set_term_from_hir(&cont_block.term, module.routes[i].control.direct_term);
                if (!fn.blocks.push(cont_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);

                for (u32 gi = 0; gi < guard_count; gi++) {
                    auto emitted = emit_guard_fail(module.routes[i].guards[gi]);
                    if (!emitted) return core::make_unexpected(emitted.error());
                }
            } else if (module.routes[i].control.kind == HirControlKind::If) {
                const u32 body_index = guard_count;
                const u32 then_index = body_index + 1;
                const u32 else_index = body_index + 2;
                u32 guard_fail_index[HirRoute::kMaxGuards]{};
                u32 fail_cursor = body_index + 3;
                for (u32 gi = 0; gi < guard_count; gi++) {
                    guard_fail_index[gi] = fail_cursor;
                    fail_cursor += guard_fail_block_count(module.routes[i].guards[gi]);
                }
                const auto& guard0 = module.routes[i].guards[0];
                block.term.kind = MirTerminatorKind::Branch;
                block.term.span = guard0.span;
                auto cond0 = mir_value(guard0.cond, module, &fn);
                if (!cond0) return core::make_unexpected(cond0.error());
                block.term.cond = cond0.value();
                block.term.then_block = guard_count > 1 ? 1 : body_index;
                block.term.else_block = guard_fail_index[0];
                if (!fn.blocks.push(block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);

                for (u32 gi = 1; gi < guard_count; gi++) {
                    MirBlock guard_block{};
                    guard_block.label = cont_label();
                    const auto& guard = module.routes[i].guards[gi];
                    guard_block.term.kind = MirTerminatorKind::Branch;
                    guard_block.term.span = guard.span;
                    auto cond = mir_value(guard.cond, module, &fn);
                    if (!cond) return core::make_unexpected(cond.error());
                    guard_block.term.cond = cond.value();
                    guard_block.term.then_block = gi + 1 < guard_count ? gi + 1 : body_index;
                    guard_block.term.else_block = guard_fail_index[gi];
                    if (!fn.blocks.push(guard_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                }

                MirBlock cont_block{};
                cont_block.label = cont_label();
                cont_block.term.kind = MirTerminatorKind::Branch;
                cont_block.term.span = module.routes[i].control.cond.span;
                auto if_cond = mir_value(module.routes[i].control.cond, module, &fn);
                if (!if_cond) return core::make_unexpected(if_cond.error());
                cont_block.term.cond = if_cond.value();
                cont_block.term.then_block = then_index;
                cont_block.term.else_block = else_index;
                if (!fn.blocks.push(cont_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);

                MirBlock then_block{};
                then_block.label = then_label();
                set_term_from_hir(&then_block.term, module.routes[i].control.then_term);
                if (!fn.blocks.push(then_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);

                MirBlock else_block{};
                else_block.label = else_label();
                set_term_from_hir(&else_block.term, module.routes[i].control.else_term);
                if (!fn.blocks.push(else_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);

                for (u32 gi = 0; gi < guard_count; gi++) {
                    auto emitted = emit_guard_fail(module.routes[i].guards[gi]);
                    if (!emitted) return core::make_unexpected(emitted.error());
                }
            } else if (module.routes[i].control.kind == HirControlKind::Match) {
                const u32 arm_count = module.routes[i].control.match_arms.len;
                const u32 test_count = arm_count - 1;
                u32 arm_block_index[HirControl::kMaxMatchArms]{};
                u32 arm_body_index[HirControl::kMaxMatchArms]{};
                u32 arm_then_index[HirControl::kMaxMatchArms]{};
                u32 arm_else_index[HirControl::kMaxMatchArms]{};
                u32 arm_guard_index[HirControl::kMaxMatchArms][HirMatchArm::kMaxPreludeGuards]{};
                u32 arm_guard_fail_index[HirControl::kMaxMatchArms]
                                        [HirMatchArm::kMaxPreludeGuards]{};
                u32 next_index = guard_count + test_count;
                for (u32 ai = 0; ai < arm_count; ai++) {
                    const auto& arm = module.routes[i].control.match_arms[ai];
                    arm_block_index[ai] = next_index++;
                    if (arm.guards.len != 0) {
                        if (arm.has_arm_guard) arm_guard_index[ai][0] = next_index++;
                        for (u32 gi = 1; gi < arm.guards.len; gi++)
                            arm_guard_index[ai][gi] = next_index++;
                        arm_body_index[ai] = next_index++;
                        for (u32 gi = 0; gi < arm.guards.len; gi++) {
                            arm_guard_fail_index[ai][gi] = next_index;
                            next_index += guard_fail_block_count(arm.guards[gi]);
                        }
                    } else if (arm.has_arm_guard) {
                        arm_body_index[ai] = next_index++;
                    } else {
                        arm_body_index[ai] = arm_block_index[ai];
                    }
                    if (arm.body_kind == HirMatchArm::BodyKind::If) {
                        arm_then_index[ai] = next_index++;
                        arm_else_index[ai] = next_index++;
                    }
                }
                u32 guard_fail_index[HirRoute::kMaxGuards]{};
                u32 fail_cursor = next_index;
                for (u32 gi = 0; gi < guard_count; gi++) {
                    guard_fail_index[gi] = fail_cursor;
                    fail_cursor += guard_fail_block_count(module.routes[i].guards[gi]);
                }
                const auto& guard0 = module.routes[i].guards[0];
                block.term.kind = MirTerminatorKind::Branch;
                block.term.span = guard0.span;
                auto cond0 = mir_value(guard0.cond, module, &fn);
                if (!cond0) return core::make_unexpected(cond0.error());
                block.term.cond = cond0.value();
                block.term.then_block =
                    guard_count > 1 ? 1 : (test_count > 0 ? guard_count : arm_block_index[0]);
                block.term.else_block = guard_fail_index[0];
                if (!fn.blocks.push(block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);

                for (u32 gi = 1; gi < guard_count; gi++) {
                    MirBlock guard_block{};
                    guard_block.label = cont_label();
                    const auto& guard = module.routes[i].guards[gi];
                    guard_block.term.kind = MirTerminatorKind::Branch;
                    guard_block.term.span = guard.span;
                    auto cond = mir_value(guard.cond, module, &fn);
                    if (!cond) return core::make_unexpected(cond.error());
                    guard_block.term.cond = cond.value();
                    guard_block.term.then_block =
                        gi + 1 < guard_count ? gi + 1
                                             : (test_count > 0 ? guard_count : arm_block_index[0]);
                    guard_block.term.else_block = guard_fail_index[gi];
                    if (!fn.blocks.push(guard_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                }

                auto subject = mir_value(module.routes[i].control.match_expr, module, &fn);
                if (!subject) return core::make_unexpected(subject.error());
                auto arm_fallthrough_target = [&](u32 ai) -> FrontendResult<u32> {
                    if (ai + 1 < test_count) return guard_count + ai + 1;
                    if (ai + 1 < arm_count) return arm_block_index[ai + 1];
                    return frontend_error(FrontendError::UnsupportedSyntax,
                                          module.routes[i].control.match_arms[ai].span);
                };
                for (u32 ai = 0; ai < test_count; ai++) {
                    MirBlock test_block{};
                    test_block.label = ai == 0 ? cont_label() : match_test_label();
                    const auto& arm = module.routes[i].control.match_arms[ai];
                    auto arm_pattern = mir_value(arm.pattern, module, &fn);
                    if (!arm_pattern) return core::make_unexpected(arm_pattern.error());
                    test_block.term.kind = MirTerminatorKind::Branch;
                    test_block.term.use_cmp = true;
                    test_block.term.span = arm.span;
                    test_block.term.lhs = subject.value();
                    test_block.term.rhs = arm_pattern.value();
                    test_block.term.then_block = arm_block_index[ai];
                    test_block.term.else_block =
                        ai + 1 < test_count ? guard_count + ai + 1 : arm_block_index[test_count];
                    if (!fn.blocks.push(test_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                }

                for (u32 ai = 0; ai < arm_count; ai++) {
                    MirBlock case_block{};
                    const auto& arm = module.routes[i].control.match_arms[ai];
                    case_block.label = arm.is_wildcard ? match_default_label() : match_case_label();
                    if (arm.has_arm_guard) {
                        auto guarded = set_match_arm_guard_branch(
                            case_block, arm, arm_guard_index[ai][0], arm_body_index[ai], [&] {
                                return arm_fallthrough_target(ai);
                            });
                        if (!guarded) return core::make_unexpected(guarded.error());
                    } else if (arm.guards.len != 0) {
                        auto cond = mir_value(arm.guards[0].cond, module, &fn);
                        if (!cond) return core::make_unexpected(cond.error());
                        case_block.term.kind = MirTerminatorKind::Branch;
                        case_block.term.span = arm.guards[0].span;
                        case_block.term.cond = cond.value();
                        case_block.term.then_block =
                            arm.guards.len > 1 ? arm_guard_index[ai][1] : arm_body_index[ai];
                        case_block.term.else_block = arm_guard_fail_index[ai][0];
                    } else if (arm.body_kind == HirMatchArm::BodyKind::If) {
                        case_block.term.kind = MirTerminatorKind::Branch;
                        case_block.term.span = arm.cond.span;
                        auto cond = mir_value(arm.cond, module, &fn);
                        if (!cond) return core::make_unexpected(cond.error());
                        case_block.term.cond = cond.value();
                        case_block.term.then_block = arm_then_index[ai];
                        case_block.term.else_block = arm_else_index[ai];
                    } else {
                        set_term_from_hir(&case_block.term, arm.direct_term);
                    }
                    if (!arm.has_arm_guard && arm.guards.len == 0) {
                        auto effects = set_arm_effects(&case_block, arm);
                        if (!effects) return core::make_unexpected(effects.error());
                    }
                    if (!fn.blocks.push(case_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                    auto guard_blocks = emit_match_prelude_guard_blocks(
                        arm, ai, arm_guard_index, arm_guard_fail_index, arm_body_index);
                    if (!guard_blocks) return core::make_unexpected(guard_blocks.error());
                    if (arm.guards.len != 0 || arm.has_arm_guard) {
                        MirBlock body_block{};
                        body_block.label = cont_label();
                        if (arm.body_kind == HirMatchArm::BodyKind::If) {
                            body_block.term.kind = MirTerminatorKind::Branch;
                            body_block.term.span = arm.cond.span;
                            auto cond = mir_value(arm.cond, module, &fn);
                            if (!cond) return core::make_unexpected(cond.error());
                            body_block.term.cond = cond.value();
                            body_block.term.then_block = arm_then_index[ai];
                            body_block.term.else_block = arm_else_index[ai];
                        } else {
                            set_term_from_hir(&body_block.term, arm.direct_term);
                        }
                        auto effects = set_arm_effects(&body_block, arm);
                        if (!effects) return core::make_unexpected(effects.error());
                        if (!fn.blocks.push(body_block))
                            return frontend_error(FrontendError::TooManyItems, fn.span);
                        for (u32 gi = 0; gi < arm.guards.len; gi++) {
                            auto emitted = emit_guard_fail(arm.guards[gi]);
                            if (!emitted) return core::make_unexpected(emitted.error());
                        }
                    }
                    if (arm.body_kind == HirMatchArm::BodyKind::If) {
                        MirBlock then_block{};
                        then_block.label = then_label();
                        set_term_from_hir(&then_block.term, arm.then_term);
                        if (!fn.blocks.push(then_block))
                            return frontend_error(FrontendError::TooManyItems, fn.span);
                        MirBlock else_block{};
                        else_block.label = else_label();
                        set_term_from_hir(&else_block.term, arm.else_term);
                        if (!fn.blocks.push(else_block))
                            return frontend_error(FrontendError::TooManyItems, fn.span);
                    }
                }

                for (u32 gi = 0; gi < guard_count; gi++) {
                    auto emitted = emit_guard_fail(module.routes[i].guards[gi]);
                    if (!emitted) return core::make_unexpected(emitted.error());
                }
            } else {
                return frontend_error(FrontendError::UnsupportedSyntax, fn.span);
            }
        } else if (module.routes[i].control.kind == HirControlKind::If) {
            block.term.kind = MirTerminatorKind::Branch;
            block.term.span = module.routes[i].control.cond.span;
            auto cond = mir_value(module.routes[i].control.cond, module, &fn);
            if (!cond) return core::make_unexpected(cond.error());
            block.term.cond = cond.value();
            block.term.then_block = 1;
            block.term.else_block = 2;
            if (!fn.blocks.push(block)) return frontend_error(FrontendError::TooManyItems, fn.span);

            MirBlock then_block{};
            then_block.label = then_label();
            set_term_from_hir(&then_block.term, module.routes[i].control.then_term);
            if (!fn.blocks.push(then_block))
                return frontend_error(FrontendError::TooManyItems, fn.span);

            MirBlock else_block{};
            else_block.label = else_label();
            set_term_from_hir(&else_block.term, module.routes[i].control.else_term);
            if (!fn.blocks.push(else_block))
                return frontend_error(FrontendError::TooManyItems, fn.span);
        } else if (module.routes[i].control.kind == HirControlKind::Match) {
            const u32 arm_count = module.routes[i].control.match_arms.len;
            const u32 test_count = arm_count - 1;
            u32 arm_block_index[HirControl::kMaxMatchArms]{};
            u32 arm_body_index[HirControl::kMaxMatchArms]{};
            u32 arm_then_index[HirControl::kMaxMatchArms]{};
            u32 arm_else_index[HirControl::kMaxMatchArms]{};
            u32 arm_guard_index[HirControl::kMaxMatchArms][HirMatchArm::kMaxPreludeGuards]{};
            u32 arm_guard_fail_index[HirControl::kMaxMatchArms][HirMatchArm::kMaxPreludeGuards]{};
            u32 next_index = test_count;
            for (u32 ai = 0; ai < arm_count; ai++) {
                const auto& arm = module.routes[i].control.match_arms[ai];
                arm_block_index[ai] = next_index++;
                if (arm.guards.len != 0) {
                    if (arm.has_arm_guard) arm_guard_index[ai][0] = next_index++;
                    for (u32 gi = 1; gi < arm.guards.len; gi++)
                        arm_guard_index[ai][gi] = next_index++;
                    arm_body_index[ai] = next_index++;
                    for (u32 gi = 0; gi < arm.guards.len; gi++) {
                        arm_guard_fail_index[ai][gi] = next_index;
                        next_index += guard_fail_block_count(arm.guards[gi]);
                    }
                } else if (arm.has_arm_guard) {
                    arm_body_index[ai] = next_index++;
                } else {
                    arm_body_index[ai] = arm_block_index[ai];
                }
                if (arm.body_kind == HirMatchArm::BodyKind::If) {
                    arm_then_index[ai] = next_index++;
                    arm_else_index[ai] = next_index++;
                }
            }
            auto subject = mir_value(module.routes[i].control.match_expr, module, &fn);
            if (!subject) return core::make_unexpected(subject.error());
            auto arm_fallthrough_target = [&](u32 ai) -> FrontendResult<u32> {
                if (ai + 1 < test_count) return ai + 1;
                if (ai + 1 < arm_count) return arm_block_index[ai + 1];
                return frontend_error(FrontendError::UnsupportedSyntax,
                                      module.routes[i].control.match_arms[ai].span);
            };
            if (test_count == 0) {
                MirBlock case_block{};
                const auto& arm = module.routes[i].control.match_arms[0];
                case_block.label = arm.is_wildcard ? match_default_label() : match_case_label();
                if (arm.has_arm_guard) {
                    auto guarded = set_match_arm_guard_branch(
                        case_block, arm, arm_guard_index[0][0], arm_body_index[0], [&] {
                            return arm_fallthrough_target(0);
                        });
                    if (!guarded) return core::make_unexpected(guarded.error());
                } else if (arm.guards.len != 0) {
                    auto cond = mir_value(arm.guards[0].cond, module, &fn);
                    if (!cond) return core::make_unexpected(cond.error());
                    case_block.term.kind = MirTerminatorKind::Branch;
                    case_block.term.span = arm.guards[0].span;
                    case_block.term.cond = cond.value();
                    case_block.term.then_block =
                        arm.guards.len > 1 ? arm_guard_index[0][1] : arm_body_index[0];
                    case_block.term.else_block = arm_guard_fail_index[0][0];
                } else if (arm.body_kind == HirMatchArm::BodyKind::If) {
                    case_block.term.kind = MirTerminatorKind::Branch;
                    case_block.term.span = arm.cond.span;
                    auto cond = mir_value(arm.cond, module, &fn);
                    if (!cond) return core::make_unexpected(cond.error());
                    case_block.term.cond = cond.value();
                    case_block.term.then_block = arm_then_index[0];
                    case_block.term.else_block = arm_else_index[0];
                } else {
                    set_term_from_hir(&case_block.term, arm.direct_term);
                }
                if (!arm.has_arm_guard && arm.guards.len == 0) {
                    auto effects = set_arm_effects(&case_block, arm);
                    if (!effects) return core::make_unexpected(effects.error());
                }
                if (!fn.blocks.push(case_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);
                auto guard_blocks = emit_match_prelude_guard_blocks(
                    arm, 0, arm_guard_index, arm_guard_fail_index, arm_body_index);
                if (!guard_blocks) return core::make_unexpected(guard_blocks.error());
                if (arm.guards.len != 0 || arm.has_arm_guard) {
                    MirBlock body_block{};
                    body_block.label = cont_label();
                    if (arm.body_kind == HirMatchArm::BodyKind::If) {
                        body_block.term.kind = MirTerminatorKind::Branch;
                        body_block.term.span = arm.cond.span;
                        auto cond = mir_value(arm.cond, module, &fn);
                        if (!cond) return core::make_unexpected(cond.error());
                        body_block.term.cond = cond.value();
                        body_block.term.then_block = arm_then_index[0];
                        body_block.term.else_block = arm_else_index[0];
                    } else {
                        set_term_from_hir(&body_block.term, arm.direct_term);
                    }
                    auto effects = set_arm_effects(&body_block, arm);
                    if (!effects) return core::make_unexpected(effects.error());
                    if (!fn.blocks.push(body_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                    for (u32 gi = 0; gi < arm.guards.len; gi++) {
                        auto emitted = emit_guard_fail(arm.guards[gi]);
                        if (!emitted) return core::make_unexpected(emitted.error());
                    }
                }
                if (arm.body_kind == HirMatchArm::BodyKind::If) {
                    MirBlock then_block{};
                    then_block.label = then_label();
                    set_term_from_hir(&then_block.term, arm.then_term);
                    if (!fn.blocks.push(then_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                    MirBlock else_block{};
                    else_block.label = else_label();
                    set_term_from_hir(&else_block.term, arm.else_term);
                    if (!fn.blocks.push(else_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                }
            } else {
                for (u32 ai = 0; ai < test_count; ai++) {
                    MirBlock test_block{};
                    test_block.label = match_test_label();
                    const auto& arm = module.routes[i].control.match_arms[ai];
                    auto arm_pattern = mir_value(arm.pattern, module, &fn);
                    if (!arm_pattern) return core::make_unexpected(arm_pattern.error());
                    test_block.term.kind = MirTerminatorKind::Branch;
                    test_block.term.use_cmp = true;
                    test_block.term.span = arm.span;
                    test_block.term.lhs = subject.value();
                    test_block.term.rhs = arm_pattern.value();
                    test_block.term.then_block = arm_block_index[ai];
                    test_block.term.else_block =
                        ai + 1 < test_count ? ai + 1 : arm_block_index[test_count];
                    if (!fn.blocks.push(test_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                }

                for (u32 ai = 0; ai < arm_count; ai++) {
                    MirBlock case_block{};
                    const auto& arm = module.routes[i].control.match_arms[ai];
                    case_block.label = arm.is_wildcard ? match_default_label() : match_case_label();
                    if (arm.has_arm_guard) {
                        auto guarded = set_match_arm_guard_branch(
                            case_block, arm, arm_guard_index[ai][0], arm_body_index[ai], [&] {
                                return arm_fallthrough_target(ai);
                            });
                        if (!guarded) return core::make_unexpected(guarded.error());
                    } else if (arm.guards.len != 0) {
                        auto cond = mir_value(arm.guards[0].cond, module, &fn);
                        if (!cond) return core::make_unexpected(cond.error());
                        case_block.term.kind = MirTerminatorKind::Branch;
                        case_block.term.span = arm.guards[0].span;
                        case_block.term.cond = cond.value();
                        case_block.term.then_block =
                            arm.guards.len > 1 ? arm_guard_index[ai][1] : arm_body_index[ai];
                        case_block.term.else_block = arm_guard_fail_index[ai][0];
                    } else if (arm.body_kind == HirMatchArm::BodyKind::If) {
                        case_block.term.kind = MirTerminatorKind::Branch;
                        case_block.term.span = arm.cond.span;
                        auto cond = mir_value(arm.cond, module, &fn);
                        if (!cond) return core::make_unexpected(cond.error());
                        case_block.term.cond = cond.value();
                        case_block.term.then_block = arm_then_index[ai];
                        case_block.term.else_block = arm_else_index[ai];
                    } else {
                        set_term_from_hir(&case_block.term, arm.direct_term);
                    }
                    if (!arm.has_arm_guard && arm.guards.len == 0) {
                        auto effects = set_arm_effects(&case_block, arm);
                        if (!effects) return core::make_unexpected(effects.error());
                    }
                    if (!fn.blocks.push(case_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                    auto guard_blocks = emit_match_prelude_guard_blocks(
                        arm, ai, arm_guard_index, arm_guard_fail_index, arm_body_index);
                    if (!guard_blocks) return core::make_unexpected(guard_blocks.error());
                    if (arm.guards.len != 0 || arm.has_arm_guard) {
                        MirBlock body_block{};
                        body_block.label = cont_label();
                        if (arm.body_kind == HirMatchArm::BodyKind::If) {
                            body_block.term.kind = MirTerminatorKind::Branch;
                            body_block.term.span = arm.cond.span;
                            auto cond = mir_value(arm.cond, module, &fn);
                            if (!cond) return core::make_unexpected(cond.error());
                            body_block.term.cond = cond.value();
                            body_block.term.then_block = arm_then_index[ai];
                            body_block.term.else_block = arm_else_index[ai];
                        } else {
                            set_term_from_hir(&body_block.term, arm.direct_term);
                        }
                        auto effects = set_arm_effects(&body_block, arm);
                        if (!effects) return core::make_unexpected(effects.error());
                        if (!fn.blocks.push(body_block))
                            return frontend_error(FrontendError::TooManyItems, fn.span);
                        for (u32 gi = 0; gi < arm.guards.len; gi++) {
                            auto emitted = emit_guard_fail(arm.guards[gi]);
                            if (!emitted) return core::make_unexpected(emitted.error());
                        }
                    }
                    if (arm.body_kind == HirMatchArm::BodyKind::If) {
                        MirBlock then_block{};
                        then_block.label = then_label();
                        set_term_from_hir(&then_block.term, arm.then_term);
                        if (!fn.blocks.push(then_block))
                            return frontend_error(FrontendError::TooManyItems, fn.span);
                        MirBlock else_block{};
                        else_block.label = else_label();
                        set_term_from_hir(&else_block.term, arm.else_term);
                        if (!fn.blocks.push(else_block))
                            return frontend_error(FrontendError::TooManyItems, fn.span);
                    }
                }
            }
        } else {
            set_term_from_hir(&block.term, module.routes[i].control.direct_term);
            if (!fn.blocks.push(block)) return frontend_error(FrontendError::TooManyItems, fn.span);
        }
        if (!mir->functions.push(fn)) return frontend_error(FrontendError::TooManyItems, fn.span);
    }

    return mir;
}

}  // namespace rut
