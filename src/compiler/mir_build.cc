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
           : kind == HirTypeKind::Server   ? MirTypeKind::I64
           : kind == HirTypeKind::Str      ? MirTypeKind::Str
           : kind == HirTypeKind::Method   ? MirTypeKind::Method
           : kind == HirTypeKind::ByteSize ? MirTypeKind::ByteSize
           : kind == HirTypeKind::IP       ? MirTypeKind::IP
           : kind == HirTypeKind::StrList  ? MirTypeKind::StrList
           : kind == HirTypeKind::Array    ? MirTypeKind::Array
           : kind == HirTypeKind::Json     ? MirTypeKind::Json
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
        shape.type == MirTypeKind::I64 || shape.type == MirTypeKind::Str ||
        shape.type == MirTypeKind::Method || shape.type == MirTypeKind::ByteSize ||
        shape.type == MirTypeKind::IP || shape.type == MirTypeKind::StrList)
        return true;
    if (shape.type == MirTypeKind::Array)
        return shape.array_elem_shape_index < mir.type_shapes.len &&
               shape_carrier_ready(mir, shape.array_elem_shape_index, struct_ready, variant_ready);
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
        shape.type == MirTypeKind::I64 || shape.type == MirTypeKind::Str ||
        shape.type == MirTypeKind::ByteSize || shape.type == MirTypeKind::IP ||
        shape.type == MirTypeKind::StrList)
        return true;
    if (shape.type == MirTypeKind::Array)
        return shape.array_elem_shape_index < mir.type_shapes.len &&
               shape_slot_carrier_ready(
                   mir, shape.array_elem_shape_index, struct_ready, variant_ready);
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
    if (expr.kind == HirExprKind::StatsSnapshot || expr.kind == HirExprKind::MetricsSnapshot) {
        return frontend_error(
            FrontendError::UnsupportedSyntax,
            expr.span,
            lit_str("control-plane builtin is declared and type-checked, but runtime lowering "
                    "is not connected yet"));
    }
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
    if (expr.kind == HirExprKind::IntLit || expr.kind == HirExprKind::ServerLit) {
        v.kind = MirValueKind::IntConst;
        v.type = mir_type_kind(expr.type);  // I32, I64, or opaque Server as I64
        v.int_value = expr.int_value;
        return v;
    }
    if (expr.kind == HirExprKind::StrLit) {
        v.kind = MirValueKind::StrConst;
        v.type = MirTypeKind::Str;
        v.str_value = expr.str_value;
        return v;
    }
    if (expr.kind == HirExprKind::ArrayLit) {
        v.kind = MirValueKind::ArrayLit;
        v.type = MirTypeKind::Array;
        apply_expr_shape_if_available(module, expr, &v);
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
    if (expr.kind == HirExprKind::JsonBuild) {
        v.kind = MirValueKind::JsonBuild;
        v.type = MirTypeKind::Json;
        v.str_value = expr.str_value;
        for (u32 i = 0; i < expr.field_inits.len; i++) {
            if (expr.field_inits[i].value == nullptr)
                return frontend_error(FrontendError::UnsupportedSyntax, expr.span);
            auto leaf = mir_value(*expr.field_inits[i].value, module, fn, ctx);
            if (!leaf) return core::make_unexpected(leaf.error());
            if (!fn->values.push(leaf.value()))
                return frontend_error(FrontendError::TooManyItems, expr.span);
            MirValue::FieldInit part{};
            part.name = expr.field_inits[i].name;
            part.value = &fn->values[fn->values.len - 1];
            if (!v.field_inits.push(part))
                return frontend_error(FrontendError::TooManyItems, expr.span);
        }
        return v;
    }
    if (expr.kind == HirExprKind::AdminJson) {
        v.kind = MirValueKind::AdminJson;
        v.type = MirTypeKind::Json;
        v.int_value = expr.int_value;
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
    if (expr.kind == HirExprKind::RespStatus || expr.kind == HirExprKind::RespBody) {
        if (expr.lhs == nullptr) return frontend_error(FrontendError::UnsupportedSyntax, expr.span);
        auto fallback = mir_value(*expr.lhs, module, fn, ctx);
        if (!fallback) return core::make_unexpected(fallback.error());
        if (!fn->values.push(fallback.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = expr.kind == HirExprKind::RespStatus ? MirValueKind::RespStatus
                                                      : MirValueKind::RespBody;
        v.type = expr.kind == HirExprKind::RespStatus ? MirTypeKind::I32 : MirTypeKind::Str;
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
    if (expr.kind == HirExprKind::RespSetStatus || expr.kind == HirExprKind::RespSetBody) {
        if (expr.lhs == nullptr) return frontend_error(FrontendError::UnsupportedSyntax, expr.span);
        auto value = mir_value(*expr.lhs, module, fn, ctx);
        if (!value) return core::make_unexpected(value.error());
        if (!fn->values.push(value.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = expr.kind == HirExprKind::RespSetStatus ? MirValueKind::RespSetStatus
                                                         : MirValueKind::RespSetBody;
        v.type = value->type;
        v.lhs = &fn->values[fn->values.len - 1];
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
    if (expr.kind == HirExprKind::ReqQueryAll || expr.kind == HirExprKind::ReqHeaderAll) {
        v.kind = expr.kind == HirExprKind::ReqQueryAll ? MirValueKind::ReqQueryAll
                                                       : MirValueKind::ReqHeaderAll;
        v.type = mir_type_kind(expr.type);
        v.str_value = expr.str_value;
        apply_expr_shape_if_available(module, expr, &v);
        return v;
    }
    if (expr.kind == HirExprKind::StrListLen || expr.kind == HirExprKind::StrListIsEmpty) {
        auto list = mir_value(*expr.lhs, module, fn, ctx);
        if (!list) return core::make_unexpected(list.error());
        if (!fn->values.push(list.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = expr.kind == HirExprKind::StrListLen ? MirValueKind::StrListLen
                                                      : MirValueKind::StrListIsEmpty;
        v.type = expr.kind == HirExprKind::StrListLen ? MirTypeKind::I32 : MirTypeKind::Bool;
        v.lhs = &fn->values[fn->values.len - 1];
        return v;
    }
    if (expr.kind == HirExprKind::StrListGet) {
        auto list = mir_value(*expr.lhs, module, fn, ctx);
        if (!list) return core::make_unexpected(list.error());
        if (!fn->values.push(list.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.lhs = &fn->values[fn->values.len - 1];
        auto index = mir_value(*expr.rhs, module, fn, ctx);
        if (!index) return core::make_unexpected(index.error());
        if (!fn->values.push(index.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.rhs = &fn->values[fn->values.len - 1];
        v.kind = MirValueKind::StrListGet;
        v.type = MirTypeKind::Str;
        v.may_nil = true;
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
    if (expr.kind == HirExprKind::UpstreamMark) {
        auto server = mir_value(*expr.lhs, module, fn, ctx);
        if (!server) return core::make_unexpected(server.error());
        auto healthy = mir_value(*expr.rhs, module, fn, ctx);
        if (!healthy) return core::make_unexpected(healthy.error());
        if (!fn->values.push(server.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        MirValue* server_ptr = &fn->values[fn->values.len - 1];
        if (!fn->values.push(healthy.value()))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        v.kind = MirValueKind::UpstreamMark;
        v.type = MirTypeKind::Bool;
        v.int_value = expr.int_value;
        v.lhs = server_ptr;
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
        shape.array_elem_shape_index = module.type_shapes[i].array_elem_shape_index;
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
        fn.upstream_mark_mask = module.routes[i].upstream_mark_mask;

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

        bool static_iter_ref[HirRoute::kMaxLocals]{};
        for (u32 fi = 0; fi < module.routes[i].for_loops.len; fi++) {
            const HirExpr* iter = &module.routes[i].for_loops[fi].iter_expr;
            for (u32 depth = 0; depth < module.routes[i].locals.len; depth++) {
                if (iter->kind != HirExprKind::LocalRef ||
                    iter->local_index >= HirRoute::kMaxLocals)
                    break;
                static_iter_ref[iter->local_index] = true;
                const HirLocal* source = nullptr;
                for (u32 li = 0; li < module.routes[i].locals.len; li++) {
                    if (module.routes[i].locals[li].ref_index == iter->local_index) {
                        source = &module.routes[i].locals[li];
                        break;
                    }
                }
                if (source == nullptr) break;
                iter = &source->init;
            }
        }
        auto static_iter_ref_needed_at_runtime =
            [&](auto&& /*self*/, u32 ref_index, u32 /*depth*/) -> bool {
            return ref_index < HirRoute::kMaxLocals && static_iter_ref[ref_index];
        };
        auto is_response_effect = [](HirExprKind kind) {
            return kind == HirExprKind::RespSetHeader || kind == HirExprKind::RespAddHeader ||
                   kind == HirExprKind::RespRemoveHeader || kind == HirExprKind::RespSetStatus ||
                   kind == HirExprKind::RespSetBody;
        };

        for (u32 li = 0; li < module.routes[i].locals.len; li++) {
            if (module.routes[i].locals[li].type == HirTypeKind::Tuple) continue;
            if (module.routes[i].locals[li].type == HirTypeKind::Response) continue;
            if (module.routes[i].locals[li].type == HirTypeKind::Stats ||
                module.routes[i].locals[li].type == HirTypeKind::Metrics)
                continue;
            // Named Json values are encoded runtime carriers. Materializing
            // them once preserves initialization/call-site semantics and lets
            // the state splitter persist the document across waits.
            if (module.routes[i].locals[li].type == HirTypeKind::Array &&
                module.routes[i].locals[li].ref_index < HirRoute::kMaxLocals &&
                static_iter_ref[module.routes[i].locals[li].ref_index] &&
                !static_iter_ref_needed_at_runtime(
                    static_iter_ref_needed_at_runtime, module.routes[i].locals[li].ref_index, 0))
                continue;
            // Wait routes execute response mutations in their source-ordered
            // resume block below. Materializing them in the function prelude
            // would run post-forward reads before the captured response exists.
            if (fn.waits.len != 0 && is_response_effect(module.routes[i].locals[li].init.kind))
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
            // EXCEPT retained wait-arm dependencies and bare statement-effect
            // carriers: both are name-cleared (unnameable by design), but the
            // former must be rebuilt after resume and the latter carries the
            // side effect itself.
            if (module.routes[i].locals[li].name.len == 0 &&
                !module.routes[i].locals[li].materialize_on_resume &&
                module.routes[i].locals[li].init.kind != HirExprKind::CacheSet &&
                module.routes[i].locals[li].init.kind != HirExprKind::ReqSetHeader &&
                module.routes[i].locals[li].init.kind != HirExprKind::ReqAddHeader &&
                module.routes[i].locals[li].init.kind != HirExprKind::RespSetHeader &&
                module.routes[i].locals[li].init.kind != HirExprKind::RespAddHeader &&
                module.routes[i].locals[li].init.kind != HirExprKind::RespRemoveHeader &&
                module.routes[i].locals[li].init.kind != HirExprKind::RespSetStatus &&
                module.routes[i].locals[li].init.kind != HirExprKind::RespSetBody)
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
            local.defer_to_terminator = module.routes[i].locals[li].defer_to_terminator;
            local.materialize_on_resume = module.routes[i].locals[li].materialize_on_resume;
            local.rematerialize_after_wait = module.routes[i].locals[li].rematerialize_after_wait;
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

        bool term_json_copy_failed = false;
        Diagnostic term_json_copy_error{};
        auto set_term_from_hir = [&](MirTerminator* out,
                                     const HirTerminator& term,
                                     const ForLoopCtx* ctx = nullptr) {
            out->span = term.span;
            out->status_code = term.status_code;
            out->commit_response_mutations = term.commit_response_mutations;
            out->upstream_index = term.upstream_index;
            out->forward_buffered = term.forward_buffered;
            out->kind = term.kind == HirTerminatorKind::ReturnStatus
                            ? MirTerminatorKind::ReturnStatus
                            : MirTerminatorKind::ForwardUpstream;
            out->source_kind = term.source_kind == HirTerminatorSourceKind::LocalRef
                                   ? MirTerminatorSourceKind::LocalRef
                                   : MirTerminatorSourceKind::Literal;
            out->local_ref_index = term.local_ref_index;
            if (term.source_kind == HirTerminatorSourceKind::LocalRef && ctx != nullptr) {
                for (u32 li = ctx->locals.len; li > 0; li--) {
                    const auto& binding = ctx->locals[li - 1];
                    if (binding.ref_index != term.local_ref_index || binding.value == nullptr)
                        continue;
                    auto resolve_static_value =
                        [&](auto&& self, const MirValue* value, u32 depth) -> const MirValue* {
                        if (value == nullptr || depth >= HirRoute::kMaxLocals) return nullptr;
                        if (value->kind == MirValueKind::LocalRef) {
                            for (u32 ci = ctx->locals.len; ci > 0; ci--)
                                if (ctx->locals[ci - 1].ref_index == value->local_index &&
                                    ctx->locals[ci - 1].value != value)
                                    return self(self, ctx->locals[ci - 1].value, depth + 1);
                            for (u32 fi = fn.locals.len; fi > 0; fi--)
                                if (fn.locals[fi - 1].ref_index == value->local_index)
                                    return self(self, &fn.locals[fi - 1].init, depth + 1);
                            return nullptr;
                        }
                        if (value->kind == MirValueKind::ArrayGet && value->lhs != nullptr) {
                            const MirValue* array = self(self, value->lhs, depth + 1);
                            if (array == nullptr || array->kind != MirValueKind::ArrayLit ||
                                value->int_value < 0 ||
                                static_cast<u64>(value->int_value) >= array->args.len)
                                return nullptr;
                            return self(
                                self, array->args[static_cast<u32>(value->int_value)], depth + 1);
                        }
                        return value;
                    };
                    const MirValue* proven =
                        resolve_static_value(resolve_static_value, binding.value, 0);
                    if (proven != nullptr && proven->kind == MirValueKind::IntConst) {
                        if (proven->int_value < 100 || proven->int_value > 599) {
                            term_json_copy_failed = true;
                            term_json_copy_error =
                                Diagnostic{FrontendError::InvalidStatusCode, term.span, {}};
                            return;
                        }
                        out->source_kind = MirTerminatorSourceKind::Literal;
                        out->status_code = static_cast<u16>(proven->int_value);
                        out->local_ref_index = 0xffffffffu;
                    } else {
                        // A loop-derived runtime i32 has no HTTP-range proof.
                        // Reject it instead of letting codegen truncate it to
                        // an invalid wire status.
                        term_json_copy_failed = true;
                        term_json_copy_error =
                            Diagnostic{FrontendError::InvalidStatusCode, term.span, {}};
                    }
                    break;
                }
            }
            out->response_body = term.response_body;
            out->has_dynamic_response_body = term.has_dynamic_response_body;
            out->control_plane_json_kind = term.control_plane_json_kind;
            out->json_segments.len = 0;
            out->json_value_ref_indices.len = 0;
            out->json_locals.len = 0;
            static_assert(
                HirTerminator::kMaxJsonDynamicValues == MirTerminator::kMaxJsonDynamicValues,
                "HIR/MIR dynamic JSON caps must match");
            static_assert(HirTerminator::kMaxJsonMaterializedValues ==
                              MirTerminator::kMaxJsonMaterializedValues,
                          "HIR/MIR dynamic JSON materialization caps must match");
            static_assert(HirRoute::kMaxLocals == MirFunction::kMaxLocals,
                          "HIR/MIR local ref ranges must match");
            for (u32 ji = 0; ji < term.json_segments.len; ji++) {
                if (!out->json_segments.push(term.json_segments[ji])) __builtin_trap();
            }
            for (u32 ji = 0; ji < term.json_value_ref_indices.len; ji++) {
                if (!out->json_value_ref_indices.push(term.json_value_ref_indices[ji]))
                    __builtin_trap();
            }
            for (u32 ji = 0; ji < term.json_value_expr_indices.len; ji++) {
                const u32 expr_index = term.json_value_expr_indices[ji];
                if (expr_index >= module.routes[i].exprs.len) {
                    term_json_copy_failed = true;
                    term_json_copy_error =
                        Diagnostic{FrontendError::UnsupportedSyntax, term.span, {}};
                    return;
                }
                const auto& value = module.routes[i].exprs[expr_index];
                MirLocal local{};
                local.span = value.span;
                local.ref_index = MirFunction::kMaxLocals + ji;
                local.type = mir_type_kind(value.type);
                local.shape_index = value.shape_index;
                local.may_nil = value.may_nil;
                local.may_error = value.may_error;
                local.variant_index = value.variant_index;
                local.struct_index = value.struct_index;
                local.tuple_len = value.tuple_len;
                for (u32 ti = 0; ti < local.tuple_len; ti++) {
                    local.tuple_types[ti] = mir_type_kind(value.tuple_types[ti]);
                    local.tuple_variant_indices[ti] = value.tuple_variant_indices[ti];
                    local.tuple_struct_indices[ti] = value.tuple_struct_indices[ti];
                }
                local.error_struct_index = value.error_struct_index;
                local.error_variant_index = value.error_variant_index;
                auto init = mir_value(value, module, &fn, ctx);
                if (!init) {
                    term_json_copy_failed = true;
                    term_json_copy_error = init.error();
                    return;
                }
                local.init = init.value();
                if (!out->json_locals.push(local)) {
                    term_json_copy_failed = true;
                    term_json_copy_error = Diagnostic{FrontendError::TooManyItems, term.span, {}};
                    return;
                }
            }
            if (term.json_body_expr_index != 0xffffffffu) {
                if (term.json_body_expr_index >= module.routes[i].exprs.len) {
                    term_json_copy_failed = true;
                    term_json_copy_error =
                        Diagnostic{FrontendError::UnsupportedSyntax, term.span, {}};
                    return;
                }
                const auto& value = module.routes[i].exprs[term.json_body_expr_index];
                out->json_body_local.span = value.span;
                out->json_body_local.type = mir_type_kind(value.type);
                auto init = mir_value(value, module, &fn, ctx);
                if (!init) {
                    term_json_copy_failed = true;
                    term_json_copy_error = init.error();
                    return;
                }
                out->json_body_local.init = init.value();
                out->has_json_body_plan = true;
            }
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
        auto set_branch_local = [&](MirBlock* out,
                                    const HirLocal& local,
                                    const ForLoopCtx* ctx = nullptr) -> FrontendResult<void> {
            auto value = mir_value(local.init, module, &fn, ctx);
            if (!value) return core::make_unexpected(value.error());
            if (!fn.values.push(value.value()))
                return frontend_error(FrontendError::TooManyItems, local.span);
            if (!out->effects.push({fn.values.len - 1, local.span, local.ref_index}))
                return frontend_error(FrontendError::TooManyItems, local.span);
            return {};
        };
        auto set_for_branch_term = [&](MirBlock* out,
                                       const HirForLoopBranch& branch,
                                       const ForLoopCtx* ctx = nullptr) -> FrontendResult<void> {
            for (u32 li = 0; li < branch.locals.len; li++) {
                auto local = set_branch_local(out, branch.locals[li], ctx);
                if (!local) return core::make_unexpected(local.error());
            }
            set_term_from_hir(&out->term, branch.term, ctx);
            return {};
        };
        auto guard_fail_block_count = [&](const HirGuard& guard) -> u32 {
            if (guard.fail_kind == HirGuard::FailKind::Term) return 1;
            if (guard.fail_kind == HirGuard::FailKind::LoopControl) return 1;
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
                                   const ForLoopCtx* ctx = nullptr,
                                   u32 loop_control_target = 0xffffffffu) -> FrontendResult<void> {
            if (guard.fail_kind == HirGuard::FailKind::Term) {
                MirBlock fail_block{};
                fail_block.label = fail_label();
                for (u32 li = 0; li < guard.fail_body.locals.len; li++) {
                    auto local = set_branch_local(&fail_block, guard.fail_body.locals[li], ctx);
                    if (!local) return core::make_unexpected(local.error());
                }
                set_term_from_hir(&fail_block.term, guard.fail_term, ctx);
                if (!fn.blocks.push(fail_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);
                return {};
            }

            if (guard.fail_kind == HirGuard::FailKind::LoopControl) {
                if (loop_control_target == 0xffffffffu)
                    return frontend_error(FrontendError::UnsupportedSyntax, guard.span);
                MirBlock fail_block{};
                fail_block.label = fail_label();
                fail_block.term.kind = MirTerminatorKind::Branch;
                fail_block.term.span = guard.span;
                fail_block.term.cond.kind = MirValueKind::BoolConst;
                fail_block.term.cond.type = MirTypeKind::Bool;
                fail_block.term.cond.bool_value = true;
                fail_block.term.then_block = loop_control_target;
                fail_block.term.else_block = loop_control_target;
                if (!fn.blocks.push(fail_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);
                return {};
            }

            if (guard.fail_kind == HirGuard::FailKind::Body) {
                MirBlock fail_block{};
                fail_block.label = fail_label();
                ForLoopCtx scoped_ctx{};
                const ForLoopCtx* body_ctx = ctx;
                if (guard.fail_body.locals.len != 0) {
                    if (ctx != nullptr) scoped_ctx = *ctx;
                    body_ctx = &scoped_ctx;
                    for (u32 li = 0; li < guard.fail_body.shared_local_count; li++) {
                        const auto& local = guard.fail_body.locals[li];
                        auto local_value = mir_value(local.init, module, &fn, body_ctx);
                        if (!local_value) return core::make_unexpected(local_value.error());
                        if (!fn.values.push(local_value.value()))
                            return frontend_error(FrontendError::TooManyItems, local.span);
                        const u32 value_index = fn.values.len - 1;
                        MirValue local_ref{};
                        local_ref.kind = MirValueKind::LocalRef;
                        local_ref.type = local_value->type;
                        local_ref.shape_index = local_value->shape_index;
                        local_ref.may_nil = local_value->may_nil;
                        local_ref.may_error = local_value->may_error;
                        local_ref.local_index = local.ref_index;
                        local_ref.variant_index = local_value->variant_index;
                        local_ref.struct_index = local_value->struct_index;
                        local_ref.tuple_len = local_value->tuple_len;
                        for (u32 ti = 0; ti < local_value->tuple_len; ti++) {
                            local_ref.tuple_types[ti] = local_value->tuple_types[ti];
                            local_ref.tuple_variant_indices[ti] =
                                local_value->tuple_variant_indices[ti];
                            local_ref.tuple_struct_indices[ti] =
                                local_value->tuple_struct_indices[ti];
                        }
                        local_ref.error_struct_index = local_value->error_struct_index;
                        local_ref.error_variant_index = local_value->error_variant_index;
                        if (!fn.values.push(local_ref))
                            return frontend_error(FrontendError::TooManyItems, local.span);
                        if (!fail_block.effects.push({value_index, local.span, local.ref_index}))
                            return frontend_error(FrontendError::TooManyItems, local.span);
                        ForLoopCtx::LocalBinding binding{};
                        binding.ref_index = local.ref_index;
                        binding.value = &fn.values[fn.values.len - 1];
                        if (!scoped_ctx.locals.push(binding))
                            return frontend_error(FrontendError::TooManyItems, local.span);
                    }
                }
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
                    if (guard.fail_body.has_then_local) {
                        auto local =
                            set_branch_local(&then_block, guard.fail_body.then_local, body_ctx);
                        if (!local) return core::make_unexpected(local.error());
                    }
                    for (u32 li = 0; li < guard.fail_body.then_term_local_count; li++) {
                        const auto& local =
                            guard.fail_body.locals[guard.fail_body.then_term_local_start + li];
                        auto added = set_branch_local(&then_block, local, body_ctx);
                        if (!added) return core::make_unexpected(added.error());
                    }
                    set_term_from_hir(&then_block.term, guard.fail_body.then_term, body_ctx);
                    if (!fn.blocks.push(then_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);

                    MirBlock else_block{};
                    else_block.label = else_label();
                    for (u32 li = 0; li < guard.fail_body.else_term_local_count; li++) {
                        const auto& local =
                            guard.fail_body.locals[guard.fail_body.else_term_local_start + li];
                        auto added = set_branch_local(&else_block, local, body_ctx);
                        if (!added) return core::make_unexpected(added.error());
                    }
                    set_term_from_hir(&else_block.term, guard.fail_body.else_term, body_ctx);
                    if (!fn.blocks.push(else_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                } else {
                    for (u32 li = 0; li < guard.fail_body.direct_term_local_count; li++) {
                        const auto& local =
                            guard.fail_body.locals[guard.fail_body.direct_term_local_start + li];
                        auto added = set_branch_local(&fail_block, local, body_ctx);
                        if (!added) return core::make_unexpected(added.error());
                    }
                    set_term_from_hir(&fail_block.term, guard.fail_body.direct_term, body_ctx);
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
                for (u32 li = 0; li < arm.locals.len; li++) {
                    auto local = set_branch_local(&case_block, arm.locals[li], ctx);
                    if (!local) return core::make_unexpected(local.error());
                }
                set_term_from_hir(&case_block.term, arm.direct_term, ctx);
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
                        if (arm.has_then_local) {
                            auto local = set_branch_local(&then_block, arm.then_local);
                            if (!local) return core::make_unexpected(local.error());
                        }
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
                            if (arm.has_then_local) {
                                auto local = set_branch_local(&then_block, arm.then_local);
                                if (!local) return core::make_unexpected(local.error());
                            }
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

            // Attach each response mutation to the first control/wait block
            // after its source position, or to the terminal block. This keeps
            // effects behind preceding guards and after the buffered-forward
            // resume that made their captured field reads valid.
            for (u32 li = 0; li < module.routes[i].locals.len; li++) {
                const auto& local = module.routes[i].locals[li];
                if (!is_response_effect(local.init.kind)) continue;
                u32 target = terminal_index;
                for (u32 si = 0; si < step_count; si++) {
                    if (local.span.start < steps[si].span.start) {
                        target = si;
                        break;
                    }
                }
                // Chain-after effects inherit the helper declaration span, which
                // may precede the route's expression-form buffered forward even
                // though they semantically run after its response is captured.
                // Clamp response effects to the capture's resume block.
                for (u32 si = 0; si < step_count; si++) {
                    if (steps[si].kind == RouteStep::Kind::Wait &&
                        fn.waits[steps[si].index].event_kind == WaitEventKind::ForwardBuffered &&
                        target <= si) {
                        target = si + 1;
                        break;
                    }
                }
                if (target >= fn.blocks.len)
                    return frontend_error(FrontendError::UnsupportedSyntax, local.span);
                auto effect = mir_value(local.init, module, &fn);
                if (!effect) return core::make_unexpected(effect.error());
                if (!fn.values.push(effect.value()))
                    return frontend_error(FrontendError::TooManyItems, local.span);
                if (!fn.blocks[target].effects.push({fn.values.len - 1, local.span}))
                    return frontend_error(FrontendError::TooManyItems, local.span);
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
            auto materialized_iter_ref_for = [&](const HirForLoop& fl) -> const HirExpr* {
                const HirExpr* iter = &fl.iter_expr;
                for (u32 depth = 0; depth <= module.routes[i].locals.len; depth++) {
                    if (iter->kind != HirExprKind::LocalRef) return nullptr;
                    if (static_iter_ref_needed_at_runtime(
                            static_iter_ref_needed_at_runtime, iter->local_index, 0))
                        return iter;
                    const HirLocal* source = nullptr;
                    for (u32 li = 0; li < module.routes[i].locals.len; li++) {
                        if (module.routes[i].locals[li].ref_index == iter->local_index) {
                            source = &module.routes[i].locals[li];
                            break;
                        }
                    }
                    if (source == nullptr) return nullptr;
                    iter = &source->init;
                }
                return nullptr;
            };
            struct RouteStep {
                enum class Kind : u8 {
                    Let,
                    Effect,
                    Guard,
                    If,
                    IfControl,
                    Match,
                    MatchControl,
                    Jump,
                    Term,
                };
                Kind kind = Kind::Guard;
                const HirGuard* guard = nullptr;
                const HirForLoopIf* body_if = nullptr;
                const HirForLoopMatch* body_match = nullptr;
                const HirTerminator* term = nullptr;
                const FixedVec<HirLocal, HirForLoopBranch::kMaxLocals>* term_locals = nullptr;
                Span span{};
                u32 order_start = 0;
                u32 order_seq = 0;
                u32 jump_target_seq = 0xffffffffu;
                u32 jump_after_source = 0;
                u32 jump_target_index = 0xffffffffu;
                u32 then_target_seq = 0xffffffffu;
                u32 then_after_source = 0;
                u32 then_target_index = 0xffffffffu;
                u32 else_target_seq = 0xffffffffu;
                u32 else_after_source = 0;
                u32 else_target_index = 0xffffffffu;
                u32 then_term_index = 0xffffffffu;
                u32 else_term_index = 0xffffffffu;
                u32 match_direct_target_seq[HirForLoopMatch::kMaxMatchArms]{};
                u32 match_direct_after_source[HirForLoopMatch::kMaxMatchArms]{};
                u32 match_direct_target_index[HirForLoopMatch::kMaxMatchArms]{};
                u32 match_then_target_seq[HirForLoopMatch::kMaxMatchArms]{};
                u32 match_then_after_source[HirForLoopMatch::kMaxMatchArms]{};
                u32 match_then_target_index[HirForLoopMatch::kMaxMatchArms]{};
                u32 match_else_target_seq[HirForLoopMatch::kMaxMatchArms]{};
                u32 match_else_after_source[HirForLoopMatch::kMaxMatchArms]{};
                u32 match_else_target_index[HirForLoopMatch::kMaxMatchArms]{};
                u32 match_guard_target_seq[HirForLoopMatch::kMaxMatchArms]
                                          [HirForLoopMatchArm::kMaxPreludeGuards]{};
                u32 match_guard_after_source[HirForLoopMatch::kMaxMatchArms]
                                            [HirForLoopMatchArm::kMaxPreludeGuards]{};
                u32 match_guard_target_index[HirForLoopMatch::kMaxMatchArms]
                                            [HirForLoopMatchArm::kMaxPreludeGuards]{};
                u32 match_test_index[HirForLoopMatch::kMaxMatchArms]{};
                u32 match_test_ordinal[HirForLoopMatch::kMaxMatchArms]{};
                u32 match_case_index[HirForLoopMatch::kMaxMatchArms]{};
                u32 match_source_guard_index[HirForLoopMatch::kMaxMatchArms]{};
                u32 match_arm_guard_index[HirForLoopMatch::kMaxMatchArms]{};
                u32 match_post_guard_index[HirForLoopMatch::kMaxMatchArms]{};
                u32 match_prelude_guard_index[HirForLoopMatch::kMaxMatchArms]
                                             [HirForLoopMatchArm::kMaxPreludeGuards]{};
                u32 match_prelude_fail_index[HirForLoopMatch::kMaxMatchArms]
                                            [HirForLoopMatchArm::kMaxPreludeGuards]{};
                u32 match_then_term_index[HirForLoopMatch::kMaxMatchArms]{};
                u32 match_else_term_index[HirForLoopMatch::kMaxMatchArms]{};
                u32 match_direct_term_index[HirForLoopMatch::kMaxMatchArms]{};
                u32 match_non_wildcard_count = 0;
                bool has_ctx = false;
                bool ends_all_paths = false;
                u32 ctx_index = 0xffffffffu;
                u32 effect_value_index = 0xffffffffu;
                u32 effect_local_ref_index = 0xffffffffu;
                MirValue match_subject{};
                bool has_match_subject = false;
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
            u32 next_unrolled_local_ref = 0;
            const auto reserve_local_ref = [&](const HirLocal& local) {
                if (local.ref_index < MirFunction::kMaxLocals &&
                    next_unrolled_local_ref <= local.ref_index)
                    next_unrolled_local_ref = local.ref_index + 1;
            };
            const auto reserve_branch_refs = [&](const HirForLoopBranch& branch) {
                for (u32 li = 0; li < branch.locals.len; li++) reserve_local_ref(branch.locals[li]);
            };
            const auto reserve_guard_refs = [&](const HirGuard& guard) {
                if (guard.fail_kind == HirGuard::FailKind::Body ||
                    guard.fail_kind == HirGuard::FailKind::Term) {
                    for (u32 li = 0; li < guard.fail_body.locals.len; li++)
                        reserve_local_ref(guard.fail_body.locals[li]);
                    if (guard.fail_body.has_then_local)
                        reserve_local_ref(guard.fail_body.then_local);
                    return;
                }
                if (guard.fail_kind != HirGuard::FailKind::Match ||
                    guard.fail_match_start > module.guard_match_arms.len ||
                    guard.fail_match_count > module.guard_match_arms.len - guard.fail_match_start)
                    return;
                for (u32 ai = 0; ai < guard.fail_match_count; ai++) {
                    const auto& arm = module.guard_match_arms[guard.fail_match_start + ai];
                    for (u32 li = 0; li < arm.locals.len; li++) reserve_local_ref(arm.locals[li]);
                }
            };
            const auto& hir_route = module.routes[i];
            for (u32 li = 0; li < hir_route.locals.len; li++)
                reserve_local_ref(hir_route.locals[li]);
            for (u32 gi = 0; gi < hir_route.guards.len; gi++)
                reserve_guard_refs(hir_route.guards[gi]);
            if (hir_route.control.kind == HirControlKind::Match) {
                for (u32 ai = 0; ai < hir_route.control.match_arms.len; ai++) {
                    const auto& arm = hir_route.control.match_arms[ai];
                    if (arm.has_then_local) reserve_local_ref(arm.then_local);
                    for (u32 gi = 0; gi < arm.guards.len; gi++) reserve_guard_refs(arm.guards[gi]);
                }
            }
            for (u32 fi = 0; fi < hir_route.for_loops.len; fi++) {
                const auto& body = hir_route.for_loops[fi].body;
                for (u32 li = 0; li < body.locals.len; li++) reserve_local_ref(body.locals[li]);
                for (u32 li = 0; li < body.term_locals.len; li++)
                    reserve_local_ref(body.term_locals[li]);
                for (u32 gi = 0; gi < body.guards.len; gi++) reserve_guard_refs(body.guards[gi]);
                for (u32 ii = 0; ii < body.ifs.len; ii++) {
                    reserve_branch_refs(body.ifs[ii].then_branch);
                    reserve_branch_refs(body.ifs[ii].else_branch);
                }
                for (u32 mi = 0; mi < body.matches.len; mi++) {
                    const auto& match = body.matches[mi];
                    for (u32 ai = 0; ai < match.arms.len; ai++) {
                        const auto& arm = match.arms[ai];
                        for (u32 li = 0; li < arm.locals.len; li++)
                            reserve_local_ref(arm.locals[li]);
                        for (u32 gi = 0; gi < arm.guards.len; gi++)
                            reserve_guard_refs(arm.guards[gi]);
                        reserve_branch_refs(arm.then_branch);
                        reserve_branch_refs(arm.else_branch);
                        reserve_branch_refs(arm.direct_branch);
                    }
                }
            }
            auto push_materialized_binding = [&](ForLoopCtx* ctx,
                                                 u32 source_ref_index,
                                                 MirValue value,
                                                 Span span,
                                                 u32 order_start) -> FrontendResult<void> {
                if (next_unrolled_local_ref >= MirFunction::kMaxLocals)
                    return frontend_error(FrontendError::TooManyItems, span);
                const u32 materialized_ref = next_unrolled_local_ref++;
                if (!fn.values.push(value))
                    return frontend_error(FrontendError::TooManyItems, span);
                const u32 effect_value_index = fn.values.len - 1;

                MirValue local_ref{};
                local_ref.kind = MirValueKind::LocalRef;
                local_ref.type = value.type;
                local_ref.shape_index = value.shape_index;
                local_ref.may_nil = value.may_nil;
                local_ref.may_error = value.may_error;
                local_ref.local_index = materialized_ref;
                local_ref.variant_index = value.variant_index;
                local_ref.struct_index = value.struct_index;
                local_ref.tuple_len = value.tuple_len;
                for (u32 ti = 0; ti < value.tuple_len; ti++) {
                    local_ref.tuple_types[ti] = value.tuple_types[ti];
                    local_ref.tuple_variant_indices[ti] = value.tuple_variant_indices[ti];
                    local_ref.tuple_struct_indices[ti] = value.tuple_struct_indices[ti];
                }
                local_ref.error_struct_index = value.error_struct_index;
                local_ref.error_variant_index = value.error_variant_index;
                if (!fn.values.push(local_ref))
                    return frontend_error(FrontendError::TooManyItems, span);
                ForLoopCtx::LocalBinding binding{};
                binding.ref_index = source_ref_index;
                binding.value = &fn.values[fn.values.len - 1];
                if (!ctx->locals.push(binding))
                    return frontend_error(FrontendError::TooManyItems, span);

                RouteStep step{};
                step.kind = RouteStep::Kind::Let;
                step.span = span;
                step.order_start = order_start;
                step.order_seq = route_step_seq++;
                step.effect_value_index = effect_value_index;
                step.effect_local_ref_index = materialized_ref;
                if (!steps.push(step)) return frontend_error(FrontendError::TooManyItems, span);
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
            auto loop_has_local_control = [&](u32 loop_index) -> bool {
                if (loop_index >= module.routes[i].for_loops.len) return false;
                const auto& loop = module.routes[i].for_loops[loop_index];
                const auto literal_matches = [](const HirExpr& subject, const HirExpr& pattern) {
                    if (subject.kind != pattern.kind) return false;
                    if (subject.kind == HirExprKind::BoolLit)
                        return subject.bool_value == pattern.bool_value;
                    if (subject.kind == HirExprKind::IntLit)
                        return subject.int_value == pattern.int_value;
                    if (subject.kind == HirExprKind::StrLit)
                        return subject.str_value.eq(pattern.str_value);
                    return false;
                };
                const auto match_has_local_control = [&](u32 mi) {
                    if (mi >= loop.body.matches.len) return false;
                    const auto& body_match = loop.body.matches[mi];
                    const bool literal_subject =
                        body_match.match_expr.kind == HirExprKind::BoolLit ||
                        body_match.match_expr.kind == HirExprKind::IntLit ||
                        body_match.match_expr.kind == HirExprKind::StrLit;
                    for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                        const auto& arm = body_match.arms[ai];
                        if (literal_subject && !arm.is_wildcard &&
                            !literal_matches(body_match.match_expr, arm.pattern))
                            continue;
                        const bool arm_guard_can_fall_through =
                            (arm.has_source_arm_guard &&
                             (arm.source_arm_guard.kind != HirExprKind::BoolLit ||
                              !arm.source_arm_guard.bool_value)) ||
                            (arm.has_arm_guard && (arm.arm_guard.kind != HirExprKind::BoolLit ||
                                                   !arm.arm_guard.bool_value));
                        for (u32 gi = 0; gi < arm.guards.len; gi++)
                            if (arm.guards[gi].fail_kind == HirGuard::FailKind::LoopControl &&
                                (arm.guards[gi].cond.kind != HirExprKind::BoolLit ||
                                 !arm.guards[gi].cond.bool_value))
                                return true;
                        if (literal_subject && !arm_guard_can_fall_through) break;
                    }
                    return false;
                };
                for (u32 si = 0; si < loop.body.steps.len; si++) {
                    const auto& step = loop.body.steps[si];
                    if (step.kind == HirForLoopBody::Step::Kind::Guard &&
                        step.index < loop.body.guards.len) {
                        const auto& guard = loop.body.guards[step.index];
                        if (guard.fail_kind == HirGuard::FailKind::LoopControl &&
                            (guard.cond.kind != HirExprKind::BoolLit || !guard.cond.bool_value))
                            return true;
                        if (guard.cond.kind == HirExprKind::BoolLit && !guard.cond.bool_value &&
                            guard.fail_kind == HirGuard::FailKind::Term)
                            return false;
                    }
                    if (step.kind == HirForLoopBody::Step::Kind::Break ||
                        step.kind == HirForLoopBody::Step::Kind::Continue)
                        return true;
                    if (step.kind == HirForLoopBody::Step::Kind::Match &&
                        match_has_local_control(step.index))
                        return true;
                    if (step.kind != HirForLoopBody::Step::Kind::If ||
                        step.index >= loop.body.ifs.len)
                        continue;
                    const auto& body_if = loop.body.ifs[step.index];
                    const bool then_reachable =
                        body_if.cond.kind != HirExprKind::BoolLit || body_if.cond.bool_value;
                    const bool else_reachable =
                        body_if.cond.kind != HirExprKind::BoolLit || !body_if.cond.bool_value;
                    const auto is_control = [](const HirForLoopBranch& branch) {
                        return branch.kind == HirForLoopBranch::Kind::Break ||
                               branch.kind == HirForLoopBranch::Kind::Continue;
                    };
                    if ((then_reachable && is_control(body_if.then_branch)) ||
                        (else_reachable && is_control(body_if.else_branch)))
                        return true;
                }
                return false;
            };
            auto loop_has_reachable_terminator = [&](u32 loop_index) -> bool {
                if (loop_index >= module.routes[i].for_loops.len) return false;
                const auto& loop = module.routes[i].for_loops[loop_index];
                if (loop.body.has_term) return true;
                const auto literal_matches = [](const HirExpr& subject, const HirExpr& pattern) {
                    if (subject.kind != pattern.kind) return false;
                    if (subject.kind == HirExprKind::BoolLit)
                        return subject.bool_value == pattern.bool_value;
                    if (subject.kind == HirExprKind::IntLit)
                        return subject.int_value == pattern.int_value;
                    if (subject.kind == HirExprKind::StrLit)
                        return subject.str_value.eq(pattern.str_value);
                    return false;
                };
                const auto branch_terminates = [](const HirForLoopBranch& branch) {
                    return branch.kind == HirForLoopBranch::Kind::Term;
                };
                for (u32 si = 0; si < loop.body.steps.len; si++) {
                    const auto& step = loop.body.steps[si];
                    if (step.kind == HirForLoopBody::Step::Kind::Term) return true;
                    if (step.kind == HirForLoopBody::Step::Kind::If &&
                        step.index < loop.body.ifs.len) {
                        const auto& body_if = loop.body.ifs[step.index];
                        if (body_if.cond.kind == HirExprKind::BoolLit) {
                            if (branch_terminates(body_if.cond.bool_value ? body_if.then_branch
                                                                          : body_if.else_branch))
                                return true;
                        } else if (branch_terminates(body_if.then_branch) &&
                                   branch_terminates(body_if.else_branch)) {
                            return true;
                        }
                    }
                    if (step.kind != HirForLoopBody::Step::Kind::Match ||
                        step.index >= loop.body.matches.len)
                        continue;
                    const auto& body_match = loop.body.matches[step.index];
                    const bool literal_subject =
                        body_match.match_expr.kind == HirExprKind::BoolLit ||
                        body_match.match_expr.kind == HirExprKind::IntLit ||
                        body_match.match_expr.kind == HirExprKind::StrLit;
                    if (!literal_subject) continue;
                    for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                        const auto& arm = body_match.arms[ai];
                        if (!arm.is_wildcard &&
                            !literal_matches(body_match.match_expr, arm.pattern))
                            continue;
                        const bool source_guard_is_false =
                            arm.has_source_arm_guard &&
                            arm.source_arm_guard.kind == HirExprKind::BoolLit &&
                            !arm.source_arm_guard.bool_value;
                        const bool arm_guard_is_false =
                            arm.has_arm_guard && arm.arm_guard.kind == HirExprKind::BoolLit &&
                            !arm.arm_guard.bool_value;
                        const bool arm_guard_can_fall_through =
                            (arm.has_source_arm_guard &&
                             (arm.source_arm_guard.kind != HirExprKind::BoolLit ||
                              !arm.source_arm_guard.bool_value)) ||
                            (arm.has_arm_guard && (arm.arm_guard.kind != HirExprKind::BoolLit ||
                                                   !arm.arm_guard.bool_value));
                        if (source_guard_is_false || arm_guard_is_false) continue;
                        bool reaches_body = true;
                        for (u32 gi = 0; gi < arm.guards.len; gi++) {
                            const auto& guard = arm.guards[gi];
                            if (guard.cond.kind == HirExprKind::BoolLit && guard.cond.bool_value)
                                continue;
                            if (guard.cond.kind == HirExprKind::BoolLit &&
                                guard.fail_kind == HirGuard::FailKind::Term)
                                return true;
                            reaches_body = false;
                            break;
                        }
                        if (!reaches_body) return false;
                        if (arm.body_kind == HirForLoopMatchArm::BodyKind::Direct) {
                            if (branch_terminates(arm.direct_branch) && !arm_guard_can_fall_through)
                                return true;
                        } else if (arm.cond.kind == HirExprKind::BoolLit) {
                            if (branch_terminates(arm.cond.bool_value ? arm.then_branch
                                                                      : arm.else_branch) &&
                                !arm_guard_can_fall_through)
                                return true;
                        } else if (branch_terminates(arm.then_branch) &&
                                   branch_terminates(arm.else_branch) &&
                                   !arm_guard_can_fall_through) {
                            return true;
                        }
                        if (!arm_guard_can_fall_through) break;
                    }
                }
                return false;
            };
            auto loop_can_advance_to_later_iteration =
                [&](auto&& self, u32 loop_index, u32 depth) -> bool {
                if (loop_index >= module.routes[i].for_loops.len ||
                    depth > module.routes[i].for_loops.len)
                    return false;
                const auto& loop = module.routes[i].for_loops[loop_index];
                const auto literal_pattern_matches = [](const HirExpr& subject,
                                                        const HirExpr& pattern) {
                    if (subject.kind != pattern.kind) return false;
                    if (subject.kind == HirExprKind::BoolLit)
                        return subject.bool_value == pattern.bool_value;
                    if (subject.kind == HirExprKind::IntLit)
                        return subject.int_value == pattern.int_value;
                    if (subject.kind == HirExprKind::StrLit)
                        return subject.str_value.eq(pattern.str_value);
                    return false;
                };
                const auto has_literal_subject = [](const HirExpr& expr) {
                    return expr.kind == HirExprKind::BoolLit || expr.kind == HirExprKind::IntLit ||
                           expr.kind == HirExprKind::StrLit;
                };
                const auto match_can_advance = [&](u32 mi) {
                    if (mi >= loop.body.matches.len) return false;
                    const auto& body_match = loop.body.matches[mi];
                    const auto capture_group_has_source_guard = [&](u32 arm_index) {
                        const auto& selected = body_match.arms[arm_index];
                        const auto can_fall_through = [](const HirForLoopMatchArm& candidate) {
                            return candidate.has_source_arm_guard &&
                                   (candidate.source_arm_guard.kind != HirExprKind::BoolLit ||
                                    !candidate.source_arm_guard.bool_value);
                        };
                        if (can_fall_through(selected)) return true;
                        if (selected.capture_group == 0) return false;
                        for (u32 grouped = 0; grouped < body_match.arms.len; grouped++)
                            if (body_match.arms[grouped].capture_group == selected.capture_group &&
                                can_fall_through(body_match.arms[grouped]))
                                return true;
                        return false;
                    };
                    const auto source_guard_is_statically_false = [&](u32 arm_index) {
                        const auto& selected = body_match.arms[arm_index];
                        if (selected.has_source_arm_guard)
                            return selected.source_arm_guard.kind == HirExprKind::BoolLit &&
                                   !selected.source_arm_guard.bool_value;
                        if (selected.capture_group == 0) return false;
                        for (u32 grouped = 0; grouped < body_match.arms.len; grouped++) {
                            const auto& candidate = body_match.arms[grouped];
                            if (candidate.capture_group != selected.capture_group ||
                                !candidate.has_source_arm_guard)
                                continue;
                            return candidate.source_arm_guard.kind == HirExprKind::BoolLit &&
                                   !candidate.source_arm_guard.bool_value;
                        }
                        return false;
                    };
                    for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                        const auto& arm = body_match.arms[ai];
                        if (has_literal_subject(body_match.match_expr) && !arm.is_wildcard &&
                            !literal_pattern_matches(body_match.match_expr, arm.pattern))
                            continue;
                        if (source_guard_is_statically_false(ai) ||
                            (arm.has_arm_guard && arm.arm_guard.kind == HirExprKind::BoolLit &&
                             !arm.arm_guard.bool_value))
                            continue;
                        bool body_reachable = true;
                        for (u32 gi = 0; gi < arm.guards.len; gi++) {
                            const auto& guard = arm.guards[gi];
                            if (guard.cond.kind == HirExprKind::BoolLit && guard.cond.bool_value)
                                continue;
                            if (guard.fail_kind == HirGuard::FailKind::LoopControl &&
                                guard.fail_loop_control == HirLoopControl::Continue)
                                return true;
                            if (guard.cond.kind == HirExprKind::BoolLit) {
                                body_reachable = false;
                                break;
                            }
                        }
                        if (body_reachable &&
                            arm.body_kind == HirForLoopMatchArm::BodyKind::Direct) {
                            if (arm.direct_branch.kind == HirForLoopBranch::Kind::Continue)
                                return true;
                        } else if (body_reachable) {
                            const bool then_reachable =
                                arm.cond.kind != HirExprKind::BoolLit || arm.cond.bool_value;
                            const bool else_reachable =
                                arm.cond.kind != HirExprKind::BoolLit || !arm.cond.bool_value;
                            if ((then_reachable &&
                                 arm.then_branch.kind == HirForLoopBranch::Kind::Continue) ||
                                (else_reachable &&
                                 arm.else_branch.kind == HirForLoopBranch::Kind::Continue))
                                return true;
                        }
                        const bool arm_guard_can_fall_through =
                            arm.has_arm_guard && (arm.arm_guard.kind != HirExprKind::BoolLit ||
                                                  !arm.arm_guard.bool_value);
                        if (has_literal_subject(body_match.match_expr) &&
                            !arm_guard_can_fall_through && !capture_group_has_source_guard(ai))
                            break;
                    }
                    return false;
                };
                for (u32 si = 0; si < loop.body.steps.len; si++) {
                    const auto& step = loop.body.steps[si];
                    if (step.kind == HirForLoopBody::Step::Kind::Guard &&
                        step.index < loop.body.guards.len) {
                        const auto& guard = loop.body.guards[step.index];
                        if (guard.fail_kind == HirGuard::FailKind::LoopControl &&
                            guard.fail_loop_control == HirLoopControl::Continue &&
                            (guard.cond.kind != HirExprKind::BoolLit || !guard.cond.bool_value))
                            return true;
                        if (guard.cond.kind == HirExprKind::BoolLit && !guard.cond.bool_value) {
                            if (guard.fail_kind == HirGuard::FailKind::Term ||
                                (guard.fail_kind == HirGuard::FailKind::LoopControl &&
                                 guard.fail_loop_control == HirLoopControl::Break))
                                return false;
                        }
                    }
                    if (step.kind == HirForLoopBody::Step::Kind::Term ||
                        step.kind == HirForLoopBody::Step::Kind::Break)
                        return false;
                    if (step.kind == HirForLoopBody::Step::Kind::Continue) return true;
                    if (step.kind == HirForLoopBody::Step::Kind::Match &&
                        match_can_advance(step.index))
                        return true;
                    if (step.kind == HirForLoopBody::Step::Kind::If &&
                        step.index < loop.body.ifs.len) {
                        const auto& body_if = loop.body.ifs[step.index];
                        const bool then_reachable =
                            body_if.cond.kind != HirExprKind::BoolLit || body_if.cond.bool_value;
                        const bool else_reachable =
                            body_if.cond.kind != HirExprKind::BoolLit || !body_if.cond.bool_value;
                        if ((then_reachable &&
                             body_if.then_branch.kind == HirForLoopBranch::Kind::Continue) ||
                            (else_reachable &&
                             body_if.else_branch.kind == HirForLoopBranch::Kind::Continue))
                            return true;
                    }
                    if (step.kind != HirForLoopBody::Step::Kind::For ||
                        !self(self, step.index, depth + 1))
                        continue;
                    // Child control resumes at the next parent step. It can
                    // expose a later parent iteration only when the remaining
                    // suffix does not terminate every path through this trip.
                    bool suffix_terminates_route = false;
                    const auto ends_parent_trip = [](const HirForLoopBranch& branch) {
                        return branch.kind == HirForLoopBranch::Kind::Term ||
                               branch.kind == HirForLoopBranch::Kind::Break;
                    };
                    for (u32 next = si + 1; next < loop.body.steps.len; next++) {
                        const auto& suffix = loop.body.steps[next];
                        if (suffix.kind == HirForLoopBody::Step::Kind::For &&
                            suffix.index < module.routes[i].for_loops.len) {
                            const auto& suffix_loop = module.routes[i].for_loops[suffix.index];
                            const HirExpr* suffix_iter = iter_array_for(suffix_loop);
                            if (loop_has_reachable_terminator(suffix.index) &&
                                !loop_has_local_control(suffix.index) && suffix_iter != nullptr &&
                                suffix_iter->args.len != 0 &&
                                !self(self, suffix.index, depth + 1)) {
                                suffix_terminates_route = true;
                                break;
                            }
                        }
                        if (suffix.kind == HirForLoopBody::Step::Kind::Term ||
                            suffix.kind == HirForLoopBody::Step::Kind::Break) {
                            suffix_terminates_route = true;
                            break;
                        }
                        if (suffix.kind == HirForLoopBody::Step::Kind::Guard &&
                            suffix.index < loop.body.guards.len) {
                            const auto& guard = loop.body.guards[suffix.index];
                            if (guard.cond.kind == HirExprKind::BoolLit && !guard.cond.bool_value &&
                                (guard.fail_kind == HirGuard::FailKind::Term ||
                                 (guard.fail_kind == HirGuard::FailKind::LoopControl &&
                                  guard.fail_loop_control == HirLoopControl::Break))) {
                                suffix_terminates_route = true;
                                break;
                            }
                        }
                        if (suffix.kind == HirForLoopBody::Step::Kind::If &&
                            suffix.index < loop.body.ifs.len) {
                            const auto& body_if = loop.body.ifs[suffix.index];
                            const bool selected_terminates =
                                body_if.cond.kind == HirExprKind::BoolLit
                                    ? ends_parent_trip(body_if.cond.bool_value
                                                           ? body_if.then_branch
                                                           : body_if.else_branch)
                                    : ends_parent_trip(body_if.then_branch) &&
                                          ends_parent_trip(body_if.else_branch);
                            if (selected_terminates) {
                                suffix_terminates_route = true;
                                break;
                            }
                        }
                        if (suffix.kind == HirForLoopBody::Step::Kind::Match &&
                            suffix.index < loop.body.matches.len) {
                            const auto& body_match = loop.body.matches[suffix.index];
                            const auto capture_group_has_source_guard = [&](u32 arm_index) {
                                const auto& selected = body_match.arms[arm_index];
                                const auto can_fall_through =
                                    [](const HirForLoopMatchArm& candidate) {
                                        return candidate.has_source_arm_guard &&
                                               (candidate.source_arm_guard.kind !=
                                                    HirExprKind::BoolLit ||
                                                !candidate.source_arm_guard.bool_value);
                                    };
                                if (can_fall_through(selected)) return true;
                                if (selected.capture_group == 0) return false;
                                for (u32 grouped = 0; grouped < body_match.arms.len; grouped++)
                                    if (body_match.arms[grouped].capture_group ==
                                            selected.capture_group &&
                                        can_fall_through(body_match.arms[grouped]))
                                        return true;
                                return false;
                            };
                            const auto source_guard_is_statically_false = [&](u32 arm_index) {
                                const auto& selected = body_match.arms[arm_index];
                                if (selected.has_source_arm_guard)
                                    return selected.source_arm_guard.kind == HirExprKind::BoolLit &&
                                           !selected.source_arm_guard.bool_value;
                                if (selected.capture_group == 0) return false;
                                for (u32 grouped = 0; grouped < body_match.arms.len; grouped++) {
                                    const auto& candidate = body_match.arms[grouped];
                                    if (candidate.capture_group != selected.capture_group ||
                                        !candidate.has_source_arm_guard)
                                        continue;
                                    return candidate.source_arm_guard.kind ==
                                               HirExprKind::BoolLit &&
                                           !candidate.source_arm_guard.bool_value;
                                }
                                return false;
                            };
                            bool any_reachable = false;
                            bool all_terminate = true;
                            for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                                const auto& arm = body_match.arms[ai];
                                if (has_literal_subject(body_match.match_expr) &&
                                    !arm.is_wildcard &&
                                    !literal_pattern_matches(body_match.match_expr, arm.pattern))
                                    continue;
                                if (source_guard_is_statically_false(ai) ||
                                    (arm.has_arm_guard &&
                                     arm.arm_guard.kind == HirExprKind::BoolLit &&
                                     !arm.arm_guard.bool_value))
                                    continue;
                                any_reachable = true;
                                bool arm_terminates = true;
                                bool body_reachable = true;
                                for (u32 gi = 0; gi < arm.guards.len && body_reachable; gi++) {
                                    const auto& guard = arm.guards[gi];
                                    if (guard.cond.kind == HirExprKind::BoolLit &&
                                        guard.cond.bool_value)
                                        continue;
                                    const bool failure_terminates =
                                        guard.fail_kind != HirGuard::FailKind::LoopControl ||
                                        guard.fail_loop_control == HirLoopControl::Break;
                                    arm_terminates = arm_terminates && failure_terminates;
                                    if (guard.cond.kind == HirExprKind::BoolLit)
                                        body_reachable = false;
                                }
                                if (body_reachable)
                                    arm_terminates =
                                        arm_terminates &&
                                        (arm.body_kind == HirForLoopMatchArm::BodyKind::Direct
                                             ? ends_parent_trip(arm.direct_branch)
                                         : arm.cond.kind == HirExprKind::BoolLit
                                             ? ends_parent_trip(arm.cond.bool_value
                                                                    ? arm.then_branch
                                                                    : arm.else_branch)
                                             : ends_parent_trip(arm.then_branch) &&
                                                   ends_parent_trip(arm.else_branch));
                                all_terminate &= arm_terminates;
                                const bool arm_guard_can_fall_through =
                                    arm.has_arm_guard &&
                                    (arm.arm_guard.kind != HirExprKind::BoolLit ||
                                     !arm.arm_guard.bool_value);
                                if (has_literal_subject(body_match.match_expr) &&
                                    !arm_guard_can_fall_through &&
                                    !capture_group_has_source_guard(ai))
                                    break;
                            }
                            if (any_reachable && all_terminate) {
                                suffix_terminates_route = true;
                                break;
                            }
                        }
                    }
                    if (!suffix_terminates_route) return true;
                }
                return false;
            };
            auto emit_for_loop = [&](auto&& self,
                                     u32 fi,
                                     const ForLoopCtx* parent_ctx,
                                     u32 order_start,
                                     bool enclosing_can_advance) -> FrontendResult<void> {
                const auto& fl = module.routes[i].for_loops[fi];
                const HirExpr* iter_array = iter_array_for(fl);
                const HirExpr* materialized_iter = materialized_iter_ref_for(fl);
                // This unroll requires a compile-time-known array literal,
                // either inline in the for expression or through a
                // route-local array constant. Runtime array values are
                // carried normally, but are not statically unrolled here.
                const bool supported = fl.body.steps.len != 0 && iter_array != nullptr;
                if (!supported || fl.loop_var_ref_index == 0xffffffffu) {
                    return frontend_error(
                        FrontendError::UnsupportedSyntax,
                        fl.span,
                        lit_str("static for-loop body must contain at least one supported step"));
                }
                const bool can_advance_to_later_iteration =
                    loop_can_advance_to_later_iteration(loop_can_advance_to_later_iteration, fi, 0);
                const auto nested_loop_guarantees_route_termination = [&](u32 loop_index) {
                    if (loop_index >= module.routes[i].for_loops.len) return false;
                    const auto& candidate = module.routes[i].for_loops[loop_index];
                    for (u32 step_index = 0; step_index < candidate.body.steps.len; step_index++) {
                        const auto& candidate_step = candidate.body.steps[step_index];
                        if (candidate_step.kind != HirForLoopBody::Step::Kind::For ||
                            candidate_step.index >= module.routes[i].for_loops.len)
                            continue;
                        const auto& child = module.routes[i].for_loops[candidate_step.index];
                        const HirExpr* child_iter = iter_array_for(child);
                        if (loop_has_reachable_terminator(candidate_step.index) &&
                            !loop_has_local_control(candidate_step.index) &&
                            child_iter != nullptr && child_iter->args.len != 0 &&
                            !loop_can_advance_to_later_iteration(
                                loop_can_advance_to_later_iteration, candidate_step.index, 0))
                            return true;
                    }
                    return false;
                };
                const bool has_control_or_terminator = fl.body.has_term ||
                                                       fl.body.has_loop_control ||
                                                       nested_loop_guarantees_route_termination(fi);
                FixedVec<MirValue, HirExpr::kMaxArgs> eager_inline_elements;
                if (materialized_iter == nullptr) {
                    for (u32 ai = 0; ai < iter_array->args.len; ai++) {
                        auto elem = mir_value(*iter_array->args[ai], module, &fn, parent_ctx);
                        if (!elem) return core::make_unexpected(elem.error());
                        const bool capture = elem->kind != MirValueKind::BoolConst &&
                                             elem->kind != MirValueKind::IntConst &&
                                             elem->kind != MirValueKind::StrConst &&
                                             elem->kind != MirValueKind::LocalRef;
                        if (capture) {
                            const u32 eager_ref = 0xffffff00u + ai;
                            ForLoopCtx capture_ctx = parent_ctx ? *parent_ctx : ForLoopCtx{};
                            auto captured = push_materialized_binding(
                                &capture_ctx, eager_ref, elem.value(), fl.span, order_start);
                            if (!captured) return core::make_unexpected(captured.error());
                            elem = *capture_ctx.locals[capture_ctx.locals.len - 1].value;
                        }
                        if (!eager_inline_elements.push(elem.value()))
                            return frontend_error(FrontendError::TooManyItems, fl.span);
                    }
                }
                const u32 iter_count = has_control_or_terminator &&
                                               !can_advance_to_later_iteration &&
                                               iter_array->args.len != 0
                                           ? 1u
                                           : iter_array->args.len;
                struct PendingTarget {
                    enum class Slot : u8 {
                        Jump,
                        IfThen,
                        IfElse,
                        MatchDirect,
                        MatchThen,
                        MatchElse,
                        MatchGuard,
                    };
                    u32 step_index = 0;
                    Slot slot = Slot::Jump;
                    u32 arm_index = 0;
                    u32 guard_index = 0;
                };
                static constexpr u32 kMaxPendingTargets =
                    HirForLoopBody::kMaxSteps * HirForLoopMatch::kMaxMatchArms;
                FixedVec<PendingTarget, kMaxPendingTargets> pending_continues{};
                FixedVec<PendingTarget, kMaxPendingTargets> after_loop_targets{};
                const auto set_target_seq = [&](const PendingTarget& target, u32 seq) {
                    auto& step = steps[target.step_index];
                    switch (target.slot) {
                        case PendingTarget::Slot::Jump:
                            step.jump_target_seq = seq;
                            break;
                        case PendingTarget::Slot::IfThen:
                            step.then_target_seq = seq;
                            break;
                        case PendingTarget::Slot::IfElse:
                            step.else_target_seq = seq;
                            break;
                        case PendingTarget::Slot::MatchDirect:
                            step.match_direct_target_seq[target.arm_index] = seq;
                            break;
                        case PendingTarget::Slot::MatchThen:
                            step.match_then_target_seq[target.arm_index] = seq;
                            break;
                        case PendingTarget::Slot::MatchElse:
                            step.match_else_target_seq[target.arm_index] = seq;
                            break;
                        case PendingTarget::Slot::MatchGuard:
                            step.match_guard_target_seq[target.arm_index][target.guard_index] = seq;
                            break;
                    }
                };
                const auto set_target_after_source = [&](const PendingTarget& target, u32 source) {
                    auto& step = steps[target.step_index];
                    switch (target.slot) {
                        case PendingTarget::Slot::Jump:
                            step.jump_after_source = source;
                            break;
                        case PendingTarget::Slot::IfThen:
                            step.then_after_source = source;
                            break;
                        case PendingTarget::Slot::IfElse:
                            step.else_after_source = source;
                            break;
                        case PendingTarget::Slot::MatchDirect:
                            step.match_direct_after_source[target.arm_index] = source;
                            break;
                        case PendingTarget::Slot::MatchThen:
                            step.match_then_after_source[target.arm_index] = source;
                            break;
                        case PendingTarget::Slot::MatchElse:
                            step.match_else_after_source[target.arm_index] = source;
                            break;
                        case PendingTarget::Slot::MatchGuard:
                            step.match_guard_after_source[target.arm_index][target.guard_index] =
                                source;
                            break;
                    }
                };
                bool stop_after_iteration = false;
                for (u32 ai = 0; ai < iter_count; ai++) {
                    bool can_continue_before_direct_break = false;
                    for (u32 pi = 0; pi < pending_continues.len; pi++) {
                        const auto& pending = pending_continues[pi];
                        set_target_seq(pending, route_step_seq);
                    }
                    pending_continues.len = 0;
                    FrontendResult<MirValue> elem =
                        frontend_error(FrontendError::UnsupportedSyntax, fl.span);
                    if (materialized_iter != nullptr) {
                        if (iter_array->args[ai]->kind == HirExprKind::IntLit) {
                            elem = mir_value(*iter_array->args[ai], module, &fn, parent_ctx);
                        } else {
                            auto array = mir_value(*materialized_iter, module, &fn, parent_ctx);
                            if (!array) return core::make_unexpected(array.error());
                            if (!fn.values.push(array.value()))
                                return frontend_error(FrontendError::TooManyItems, fl.span);
                            MirValue indexed{};
                            indexed.kind = MirValueKind::ArrayGet;
                            indexed.type = mir_type_kind(iter_array->args[ai]->type);
                            indexed.shape_index = iter_array->args[ai]->shape_index;
                            indexed.variant_index = iter_array->args[ai]->variant_index;
                            indexed.struct_index = iter_array->args[ai]->struct_index;
                            indexed.tuple_len = iter_array->args[ai]->tuple_len;
                            for (u32 ti = 0; ti < indexed.tuple_len; ti++) {
                                indexed.tuple_types[ti] =
                                    mir_type_kind(iter_array->args[ai]->tuple_types[ti]);
                                indexed.tuple_variant_indices[ti] =
                                    iter_array->args[ai]->tuple_variant_indices[ti];
                                indexed.tuple_struct_indices[ti] =
                                    iter_array->args[ai]->tuple_struct_indices[ti];
                            }
                            indexed.int_value = ai;
                            indexed.lhs = &fn.values[fn.values.len - 1];
                            elem = indexed;
                        }
                    } else {
                        elem = eager_inline_elements[ai];
                    }
                    if (!elem) return core::make_unexpected(elem.error());
                    ForLoopCtx ctx = parent_ctx ? *parent_ctx : ForLoopCtx{};
                    const bool capture_inline_runtime_element =
                        materialized_iter == nullptr && elem->kind != MirValueKind::BoolConst &&
                        elem->kind != MirValueKind::IntConst &&
                        elem->kind != MirValueKind::StrConst &&
                        elem->kind != MirValueKind::LocalRef;
                    auto loop_binding =
                        capture_inline_runtime_element
                            ? push_materialized_binding(
                                  &ctx, fl.loop_var_ref_index, elem.value(), fl.span, order_start)
                            : push_ctx_binding(&ctx, fl.loop_var_ref_index, elem.value(), fl.span);
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
                            const bool capture_local =
                                local_value->kind != MirValueKind::BoolConst &&
                                local_value->kind != MirValueKind::IntConst &&
                                local_value->kind != MirValueKind::StrConst &&
                                local_value->kind != MirValueKind::LocalRef;
                            auto local_binding =
                                capture_local
                                    ? push_materialized_binding(&ctx,
                                                                local.ref_index,
                                                                local_value.value(),
                                                                local.span,
                                                                order_start)
                                    : push_ctx_binding(
                                          &ctx, local.ref_index, local_value.value(), local.span);
                            if (!local_binding) return core::make_unexpected(local_binding.error());
                            continue;
                        }
                        if (body_step.kind == HirForLoopBody::Step::Kind::Effect) {
                            if (body_step.index >= fl.body.effects.len)
                                return frontend_error(FrontendError::UnsupportedSyntax,
                                                      body_step.span);
                            auto effect =
                                mir_value(fl.body.effects[body_step.index], module, &fn, &ctx);
                            if (!effect) return core::make_unexpected(effect.error());
                            if (!fn.values.push(effect.value()))
                                return frontend_error(FrontendError::TooManyItems, body_step.span);
                            RouteStep step{};
                            step.kind = RouteStep::Kind::Effect;
                            step.span = body_step.span;
                            step.order_start = order_start;
                            step.order_seq = route_step_seq++;
                            step.effect_value_index = fn.values.len - 1;
                            auto ctx_set = set_step_ctx(&step, ctx);
                            if (!ctx_set) return core::make_unexpected(ctx_set.error());
                            if (!steps.push(step))
                                return frontend_error(FrontendError::TooManyItems, fl.span);
                            continue;
                        }
                        if (body_step.kind == HirForLoopBody::Step::Kind::Guard) {
                            if (body_step.index >= fl.body.guards.len)
                                return frontend_error(FrontendError::UnsupportedSyntax,
                                                      body_step.span);
                            const auto& body_guard = fl.body.guards[body_step.index];
                            if (body_guard.fail_kind == HirGuard::FailKind::LoopControl &&
                                body_guard.cond.kind == HirExprKind::BoolLit &&
                                body_guard.cond.bool_value)
                                continue;
                            RouteStep step{};
                            step.kind = RouteStep::Kind::Guard;
                            step.guard = &body_guard;
                            step.span = body_guard.span;
                            step.order_start = order_start;
                            step.order_seq = route_step_seq++;
                            if (step.guard->fail_kind == HirGuard::FailKind::LoopControl) {
                                // Either break or continue can bypass a later
                                // terminating child loop in the parent body.
                                can_continue_before_direct_break = true;
                                const PendingTarget target{steps.len, PendingTarget::Slot::Jump, 0};
                                const bool exits_loop =
                                    step.guard->fail_loop_control == HirLoopControl::Break ||
                                    ai + 1 == iter_count;
                                if (!(exits_loop ? after_loop_targets.push(target)
                                                 : pending_continues.push(target)))
                                    return frontend_error(FrontendError::TooManyItems, fl.span);
                            }
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
                            const auto& body_if = fl.body.ifs[body_step.index];
                            step.kind =
                                body_if.then_branch.kind == HirForLoopBranch::Kind::Term &&
                                        body_if.else_branch.kind == HirForLoopBranch::Kind::Term &&
                                        !can_advance_to_later_iteration &&
                                        !can_continue_before_direct_break && !enclosing_can_advance
                                    ? RouteStep::Kind::If
                                    : RouteStep::Kind::IfControl;
                            step.body_if = &body_if;
                            step.span = fl.body.ifs[body_step.index].span;
                            step.order_start = order_start;
                            step.order_seq = route_step_seq++;
                            const auto set_branch_target = [&](const HirForLoopBranch& branch,
                                                               bool then_branch) -> bool {
                                if (branch.kind == HirForLoopBranch::Kind::Term) return true;
                                can_continue_before_direct_break = true;
                                if (branch.kind == HirForLoopBranch::Kind::Break ||
                                    ai + 1 == iter_count) {
                                    return after_loop_targets.push(
                                        {steps.len,
                                         then_branch ? PendingTarget::Slot::IfThen
                                                     : PendingTarget::Slot::IfElse,
                                         0});
                                }
                                return pending_continues.push({steps.len,
                                                               then_branch
                                                                   ? PendingTarget::Slot::IfThen
                                                                   : PendingTarget::Slot::IfElse,
                                                               0});
                            };
                            if (!set_branch_target(step.body_if->then_branch, true) ||
                                !set_branch_target(step.body_if->else_branch, false))
                                return frontend_error(FrontendError::TooManyItems, fl.span);
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
                            step.body_match = &fl.body.matches[body_step.index];
                            bool all_terms = true;
                            for (u32 mi = 0; mi < step.body_match->arms.len; mi++) {
                                const auto& arm = step.body_match->arms[mi];
                                step.match_direct_target_seq[mi] = 0xffffffffu;
                                step.match_direct_target_index[mi] = 0xffffffffu;
                                step.match_then_target_seq[mi] = 0xffffffffu;
                                step.match_then_target_index[mi] = 0xffffffffu;
                                step.match_else_target_seq[mi] = 0xffffffffu;
                                step.match_else_target_index[mi] = 0xffffffffu;
                                step.match_then_term_index[mi] = 0xffffffffu;
                                step.match_else_term_index[mi] = 0xffffffffu;
                                step.match_direct_term_index[mi] = 0xffffffffu;
                                for (u32 gi = 0; gi < arm.guards.len; gi++) {
                                    step.match_guard_target_seq[mi][gi] = 0xffffffffu;
                                    step.match_guard_target_index[mi][gi] = 0xffffffffu;
                                    all_terms &=
                                        arm.guards[gi].fail_kind != HirGuard::FailKind::LoopControl;
                                }
                                if (arm.body_kind == HirForLoopMatchArm::BodyKind::Direct)
                                    all_terms &=
                                        arm.direct_branch.kind == HirForLoopBranch::Kind::Term;
                                else
                                    all_terms &=
                                        arm.then_branch.kind == HirForLoopBranch::Kind::Term &&
                                        arm.else_branch.kind == HirForLoopBranch::Kind::Term;
                            }
                            step.kind = all_terms && !can_advance_to_later_iteration &&
                                                !can_continue_before_direct_break &&
                                                !enclosing_can_advance
                                            ? RouteStep::Kind::Match
                                            : RouteStep::Kind::MatchControl;
                            step.span = fl.body.matches[body_step.index].span;
                            step.order_start = order_start;
                            step.order_seq = route_step_seq++;
                            const auto set_match_target = [&](const HirForLoopBranch& branch,
                                                              PendingTarget::Slot slot,
                                                              u32 arm_index) -> bool {
                                if (branch.kind == HirForLoopBranch::Kind::Term) return true;
                                can_continue_before_direct_break = true;
                                const PendingTarget target{steps.len, slot, arm_index};
                                if (branch.kind == HirForLoopBranch::Kind::Break ||
                                    ai + 1 == iter_count)
                                    return after_loop_targets.push(target);
                                return pending_continues.push(target);
                            };
                            if (step.kind == RouteStep::Kind::MatchControl) {
                                for (u32 mi = 0; mi < step.body_match->arms.len; mi++) {
                                    const auto& arm = step.body_match->arms[mi];
                                    if (arm.body_kind == HirForLoopMatchArm::BodyKind::Direct) {
                                        if (!set_match_target(arm.direct_branch,
                                                              PendingTarget::Slot::MatchDirect,
                                                              mi))
                                            return frontend_error(FrontendError::TooManyItems,
                                                                  fl.span);
                                    } else if (!set_match_target(arm.then_branch,
                                                                 PendingTarget::Slot::MatchThen,
                                                                 mi) ||
                                               !set_match_target(arm.else_branch,
                                                                 PendingTarget::Slot::MatchElse,
                                                                 mi)) {
                                        return frontend_error(FrontendError::TooManyItems, fl.span);
                                    }
                                    for (u32 gi = 0; gi < arm.guards.len; gi++) {
                                        const auto& guard = arm.guards[gi];
                                        if (guard.fail_kind != HirGuard::FailKind::LoopControl)
                                            continue;
                                        can_continue_before_direct_break = true;
                                        const PendingTarget target{
                                            steps.len, PendingTarget::Slot::MatchGuard, mi, gi};
                                        const bool exits_loop =
                                            guard.fail_loop_control == HirLoopControl::Break ||
                                            ai + 1 == iter_count;
                                        if (!(exits_loop ? after_loop_targets.push(target)
                                                         : pending_continues.push(target)))
                                            return frontend_error(FrontendError::TooManyItems,
                                                                  fl.span);
                                    }
                                }
                            }
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
                            auto child =
                                self(self,
                                     body_step.index,
                                     &ctx,
                                     order_start,
                                     enclosing_can_advance || can_continue_before_direct_break);
                            if (!child) return core::make_unexpected(child.error());
                            continue;
                        }
                        if (body_step.kind == HirForLoopBody::Step::Kind::Break ||
                            body_step.kind == HirForLoopBody::Step::Kind::Continue) {
                            RouteStep step{};
                            step.kind = RouteStep::Kind::Jump;
                            step.span = body_step.span;
                            step.order_start = order_start;
                            step.order_seq = route_step_seq++;
                            const u32 jump_index = steps.len;
                            if (!steps.push(step))
                                return frontend_error(FrontendError::TooManyItems, fl.span);
                            if (body_step.kind == HirForLoopBody::Step::Kind::Break) {
                                if (!after_loop_targets.push(
                                        {jump_index, PendingTarget::Slot::Jump, 0}))
                                    return frontend_error(FrontendError::TooManyItems, fl.span);
                                stop_after_iteration = !can_continue_before_direct_break;
                            } else if (ai + 1 < iter_count) {
                                if (!pending_continues.push(
                                        {jump_index, PendingTarget::Slot::Jump, 0}))
                                    return frontend_error(FrontendError::TooManyItems, fl.span);
                            } else if (!after_loop_targets.push(
                                           {jump_index, PendingTarget::Slot::Jump, 0})) {
                                return frontend_error(FrontendError::TooManyItems, fl.span);
                            }
                            continue;
                        }
                        RouteStep step{};
                        step.kind = RouteStep::Kind::Term;
                        step.term = &fl.body.term;
                        step.term_locals = &fl.body.term_locals;
                        step.span = fl.body.term.span;
                        step.order_start = order_start;
                        step.order_seq = route_step_seq++;
                        step.ends_all_paths = !loop_has_local_control(fi) && !enclosing_can_advance;
                        auto ctx_set = set_step_ctx(&step, ctx);
                        if (!ctx_set) return core::make_unexpected(ctx_set.error());
                        if (!steps.push(step))
                            return frontend_error(FrontendError::TooManyItems, fl.span);
                    }
                    if (stop_after_iteration) break;
                }
                for (u32 ji = 0; ji < after_loop_targets.len; ji++) {
                    if (for_loop_is_child[fi]) {
                        set_target_seq(after_loop_targets[ji], route_step_seq);
                        set_target_after_source(after_loop_targets[ji], fl.span.end);
                    } else {
                        set_target_after_source(after_loop_targets[ji], fl.span.end);
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
                    emit_for_loop, fi, nullptr, module.routes[i].for_loops[fi].span.start, false);
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

            for (u32 si = 0; si < steps.len; si++) {
                const bool guard_loop_control =
                    steps[si].kind == RouteStep::Kind::Guard && steps[si].guard != nullptr &&
                    steps[si].guard->fail_kind == HirGuard::FailKind::LoopControl;
                if (steps[si].kind != RouteStep::Kind::Jump && !guard_loop_control) continue;
                if (steps[si].jump_target_seq != 0xffffffffu) {
                    for (u32 ti = 0; ti < steps.len; ti++) {
                        if (steps[ti].order_seq == steps[si].jump_target_seq) {
                            steps[si].jump_target_index = ti;
                            break;
                        }
                    }
                }
                if (steps[si].jump_target_index == 0xffffffffu &&
                    steps[si].jump_after_source != 0) {
                    for (u32 ti = 0; ti < steps.len; ti++) {
                        if (steps[ti].order_start >= steps[si].jump_after_source) {
                            steps[si].jump_target_index = ti;
                            break;
                        }
                    }
                }
            }
            auto resolve_loop_target = [&](u32 target_seq, u32 after_source) -> u32 {
                if (target_seq != 0xffffffffu) {
                    for (u32 ti = 0; ti < steps.len; ti++)
                        if (steps[ti].order_seq == target_seq) return ti;
                }
                if (after_source != 0) {
                    for (u32 ti = 0; ti < steps.len; ti++)
                        if (steps[ti].order_start >= after_source) return ti;
                }
                return 0xffffffffu;
            };
            for (u32 si = 0; si < steps.len; si++) {
                if (steps[si].kind != RouteStep::Kind::IfControl) continue;
                steps[si].then_target_index =
                    resolve_loop_target(steps[si].then_target_seq, steps[si].then_after_source);
                steps[si].else_target_index =
                    resolve_loop_target(steps[si].else_target_seq, steps[si].else_after_source);
            }
            for (u32 si = 0; si < steps.len; si++) {
                if (steps[si].kind != RouteStep::Kind::MatchControl) continue;
                for (u32 ai = 0; ai < steps[si].body_match->arms.len; ai++) {
                    steps[si].match_direct_target_index[ai] =
                        resolve_loop_target(steps[si].match_direct_target_seq[ai],
                                            steps[si].match_direct_after_source[ai]);
                    steps[si].match_then_target_index[ai] = resolve_loop_target(
                        steps[si].match_then_target_seq[ai], steps[si].match_then_after_source[ai]);
                    steps[si].match_else_target_index[ai] = resolve_loop_target(
                        steps[si].match_else_target_seq[ai], steps[si].match_else_after_source[ai]);
                    for (u32 gi = 0; gi < steps[si].body_match->arms[ai].guards.len; gi++) {
                        steps[si].match_guard_target_index[ai][gi] =
                            resolve_loop_target(steps[si].match_guard_target_seq[ai][gi],
                                                steps[si].match_guard_after_source[ai][gi]);
                    }
                }
            }

            u32 step_count = steps.len;
            bool has_terminating_step = false;
            u32 terminating_step_index = 0xffffffffu;
            for (u32 si = 0; si < steps.len; si++) {
                if ((steps[si].kind == RouteStep::Kind::Term && steps[si].ends_all_paths) ||
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
            u32 body_match_source_guard_index[HirForLoopMatch::kMaxMatchArms]{};
            u32 body_match_post_guard_index[HirForLoopMatch::kMaxMatchArms]{};
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
            auto is_capture_group_owner = [](const HirForLoopMatch& match, u32 arm_index) {
                const u8 group = match.arms[arm_index].capture_group;
                if (group == 0) return true;
                for (u32 prior = 0; prior < arm_index; prior++)
                    if (match.arms[prior].capture_group == group) return false;
                return true;
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
                    if (!is_capture_group_owner(body_match, ai)) continue;
                    for (u32 gi = 0; gi < body_match.arms[ai].guards.len; gi++) {
                        body_match_prelude_guard_index[ai][gi] =
                            reserve_blocks(&cursor, 1, body_match.arms[ai].guards[gi].span);
                    }
                }
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    if (body_match.arms[ai].has_source_arm_guard)
                        body_match_source_guard_index[ai] =
                            reserve_blocks(&cursor, 1, body_match.arms[ai].span);
                    if (body_match.arms[ai].has_arm_guard)
                        body_match_guard_index[ai] =
                            reserve_blocks(&cursor, 1, body_match.arms[ai].span);
                }
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    if (body_match.arms[ai].post_arm_guard_expr_index != 0xffffffffu)
                        body_match_post_guard_index[ai] =
                            reserve_blocks(&cursor, 1, body_match.arms[ai].span);
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
                    if (!is_capture_group_owner(body_match, ai)) continue;
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
                if (steps[si].kind != RouteStep::Kind::IfControl) continue;
                if (steps[si].body_if->then_branch.kind == HirForLoopBranch::Kind::Term)
                    steps[si].then_term_index = reserve_blocks(&fail_cursor, 1, steps[si].span);
                if (steps[si].body_if->else_branch.kind == HirForLoopBranch::Kind::Term)
                    steps[si].else_term_index = reserve_blocks(&fail_cursor, 1, steps[si].span);
            }
            for (u32 si = 0; si < step_count; si++) {
                if (steps[si].kind != RouteStep::Kind::MatchControl) continue;
                auto& step = steps[si];
                const auto& body_match = *step.body_match;
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    if (!body_match.arms[ai].is_wildcard)
                        step.match_test_ordinal[ai] = step.match_non_wildcard_count++;
                }
                for (u32 ordinal = 1; ordinal < step.match_non_wildcard_count; ordinal++)
                    step.match_test_index[ordinal] = reserve_blocks(&fail_cursor, 1, step.span);
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    const auto& arm = body_match.arms[ai];
                    if (arm.has_source_arm_guard)
                        step.match_source_guard_index[ai] =
                            reserve_blocks(&fail_cursor, 1, arm.span);
                    if (arm.has_arm_guard)
                        step.match_arm_guard_index[ai] = reserve_blocks(&fail_cursor, 1, arm.span);
                    if (is_capture_group_owner(body_match, ai)) {
                        for (u32 gi = 0; gi < arm.guards.len; gi++)
                            step.match_prelude_guard_index[ai][gi] =
                                reserve_blocks(&fail_cursor, 1, arm.guards[gi].span);
                    }
                    if (arm.post_arm_guard_expr_index != 0xffffffffu)
                        step.match_post_guard_index[ai] = reserve_blocks(&fail_cursor, 1, arm.span);
                    step.match_case_index[ai] = reserve_blocks(&fail_cursor, 1, arm.span);
                    if (arm.body_kind == HirForLoopMatchArm::BodyKind::Direct) {
                        if (arm.direct_branch.kind == HirForLoopBranch::Kind::Term)
                            step.match_direct_term_index[ai] =
                                reserve_blocks(&fail_cursor, 1, arm.span);
                    } else {
                        if (arm.then_branch.kind == HirForLoopBranch::Kind::Term)
                            step.match_then_term_index[ai] =
                                reserve_blocks(&fail_cursor, 1, arm.span);
                        if (arm.else_branch.kind == HirForLoopBranch::Kind::Term)
                            step.match_else_term_index[ai] =
                                reserve_blocks(&fail_cursor, 1, arm.span);
                    }
                    if (is_capture_group_owner(body_match, ai)) {
                        for (u32 gi = 0; gi < arm.guards.len; gi++) {
                            step.match_prelude_fail_index[ai][gi] = fail_cursor;
                            reserve_blocks(&fail_cursor,
                                           guard_fail_block_count(arm.guards[gi]),
                                           arm.guards[gi].span);
                        }
                    }
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

            ForLoopCtx body_match_arm_contexts[HirForLoopMatch::kMaxMatchArms]{};
            ForLoopCtx body_match_shared_contexts[HirForLoopMatch::kMaxMatchArms]{};
            FixedVec<MirBlock::Effect, HirForLoopMatchArm::kMaxLocals>
                body_match_arm_effects[HirForLoopMatch::kMaxMatchArms]{};
            FixedVec<u8, HirForLoopMatchArm::kMaxLocals>
                body_match_arm_effect_depths[HirForLoopMatch::kMaxMatchArms]{};
            u8 body_match_capture_owner[HirForLoopMatch::kMaxMatchArms]{};
            const HirForLoopMatch* terminating_body_match = nullptr;
            const ForLoopCtx* terminating_body_match_ctx = nullptr;
            if (has_terminating_step &&
                steps[terminating_step_index].kind == RouteStep::Kind::Match) {
                terminating_body_match = steps[terminating_step_index].body_match;
                terminating_body_match_ctx = route_step_ctx(steps[terminating_step_index]);
                for (u32 ai = 0; ai < terminating_body_match->arms.len; ai++) {
                    const auto& arm = terminating_body_match->arms[ai];
                    if (arm.capture_local_count > arm.locals.len)
                        return frontend_error(FrontendError::UnsupportedSyntax, arm.span);
                    body_match_capture_owner[ai] = static_cast<u8>(ai);
                    u32 local_start = 0;
                    if (arm.capture_group != 0) {
                        for (u32 prior = 0; prior < ai; prior++) {
                            if (terminating_body_match->arms[prior].capture_group !=
                                arm.capture_group)
                                continue;
                            body_match_capture_owner[ai] = static_cast<u8>(prior);
                            body_match_arm_contexts[ai] = body_match_shared_contexts[prior];
                            local_start = arm.capture_local_count;
                            break;
                        }
                    }
                    if (body_match_capture_owner[ai] == ai && terminating_body_match_ctx != nullptr)
                        body_match_arm_contexts[ai] = *terminating_body_match_ctx;
                    ForLoopCtx* body_ctx = &body_match_arm_contexts[ai];
                    if (body_match_capture_owner[ai] == ai && arm.capture_local_count == 0)
                        body_match_shared_contexts[ai] = *body_ctx;
                    for (u32 li = local_start; li < arm.locals.len; li++) {
                        const auto& local = arm.locals[li];
                        auto local_value = mir_value(local.init, module, &fn, body_ctx);
                        if (!local_value) return core::make_unexpected(local_value.error());
                        const bool capture_local = local_value->kind != MirValueKind::BoolConst &&
                                                   local_value->kind != MirValueKind::IntConst &&
                                                   local_value->kind != MirValueKind::StrConst &&
                                                   local_value->kind != MirValueKind::LocalRef;
                        if (!capture_local) {
                            auto local_binding = push_ctx_binding(
                                body_ctx, local.ref_index, local_value.value(), local.span);
                            if (!local_binding) return core::make_unexpected(local_binding.error());
                            if (body_match_capture_owner[ai] == ai &&
                                li + 1 == arm.capture_local_count)
                                body_match_shared_contexts[ai] = *body_ctx;
                            continue;
                        }
                        if (next_unrolled_local_ref >= MirFunction::kMaxLocals)
                            return frontend_error(FrontendError::TooManyItems, local.span);
                        const u32 materialized_ref = next_unrolled_local_ref++;
                        if (!fn.values.push(local_value.value()))
                            return frontend_error(FrontendError::TooManyItems, local.span);
                        const u32 value_index = fn.values.len - 1;
                        MirValue local_ref{};
                        local_ref.kind = MirValueKind::LocalRef;
                        local_ref.type = local_value->type;
                        local_ref.shape_index = local_value->shape_index;
                        local_ref.may_nil = local_value->may_nil;
                        local_ref.may_error = local_value->may_error;
                        local_ref.local_index = materialized_ref;
                        local_ref.variant_index = local_value->variant_index;
                        local_ref.struct_index = local_value->struct_index;
                        local_ref.tuple_len = local_value->tuple_len;
                        for (u32 ti = 0; ti < local_value->tuple_len; ti++) {
                            local_ref.tuple_types[ti] = local_value->tuple_types[ti];
                            local_ref.tuple_variant_indices[ti] =
                                local_value->tuple_variant_indices[ti];
                            local_ref.tuple_struct_indices[ti] =
                                local_value->tuple_struct_indices[ti];
                        }
                        local_ref.error_struct_index = local_value->error_struct_index;
                        local_ref.error_variant_index = local_value->error_variant_index;
                        if (!fn.values.push(local_ref))
                            return frontend_error(FrontendError::TooManyItems, local.span);
                        ForLoopCtx::LocalBinding binding{};
                        binding.ref_index = local.ref_index;
                        binding.value = &fn.values[fn.values.len - 1];
                        if (!body_ctx->locals.push(binding) ||
                            !body_match_arm_effects[ai].push(
                                {value_index, local.span, materialized_ref}) ||
                            !body_match_arm_effect_depths[ai].push(arm.local_guard_depth[li])) {
                            return frontend_error(FrontendError::TooManyItems, local.span);
                        }
                        if (body_match_capture_owner[ai] == ai && li + 1 == arm.capture_local_count)
                            body_match_shared_contexts[ai] = *body_ctx;
                    }
                }
            }
            auto for_loop_match_arm_ctx = [&](const HirForLoopMatchArm& arm,
                                              u32 arm_index,
                                              const ForLoopCtx* base_ctx) -> const ForLoopCtx* {
                if (arm.locals.len == 0 || terminating_body_match == nullptr) return base_ctx;
                return &body_match_arm_contexts[arm_index];
            };
            auto append_body_match_arm_effects = [&](MirBlock* block,
                                                     u32 arm_index,
                                                     u32 guard_depth,
                                                     Span span) -> FrontendResult<void> {
                for (u32 ei = 0; ei < body_match_arm_effects[arm_index].len; ei++) {
                    if (body_match_arm_effect_depths[arm_index][ei] != guard_depth) continue;
                    if (!block->effects.push(body_match_arm_effects[arm_index][ei]))
                        return frontend_error(FrontendError::TooManyItems, span);
                }
                return {};
            };
            auto extend_for_loop_match_arm_ctx =
                [&](const HirForLoopMatchArm& arm,
                    const ForLoopCtx* base_ctx,
                    ForLoopCtx* scoped_ctx,
                    u32 local_start,
                    u32 local_end,
                    FixedVec<MirBlock::Effect, HirForLoopMatchArm::kMaxLocals>* effects,
                    FixedVec<u32, HirForLoopMatchArm::kMaxLocals>* effect_depths)
                -> FrontendResult<const ForLoopCtx*> {
                if (local_start >= local_end) return base_ctx;
                if (base_ctx != nullptr) *scoped_ctx = *base_ctx;
                const ForLoopCtx* body_ctx = scoped_ctx;
                for (u32 li = local_start; li < local_end; li++) {
                    const auto& local = arm.locals[li];
                    auto local_value = mir_value(local.init, module, &fn, body_ctx);
                    if (!local_value) return core::make_unexpected(local_value.error());
                    const bool capture_local = local_value->kind != MirValueKind::BoolConst &&
                                               local_value->kind != MirValueKind::IntConst &&
                                               local_value->kind != MirValueKind::StrConst &&
                                               local_value->kind != MirValueKind::LocalRef;
                    if (capture_local) {
                        if (next_unrolled_local_ref >= MirFunction::kMaxLocals)
                            return frontend_error(FrontendError::TooManyItems, local.span);
                        const u32 materialized_ref = next_unrolled_local_ref++;
                        if (!fn.values.push(local_value.value()))
                            return frontend_error(FrontendError::TooManyItems, local.span);
                        const u32 value_index = fn.values.len - 1;
                        MirValue local_ref = local_value.value();
                        local_ref.kind = MirValueKind::LocalRef;
                        local_ref.local_index = materialized_ref;
                        local_ref.args.len = 0;
                        local_ref.lhs = nullptr;
                        local_ref.rhs = nullptr;
                        auto local_binding =
                            push_ctx_binding(scoped_ctx, local.ref_index, local_ref, local.span);
                        if (!local_binding) return core::make_unexpected(local_binding.error());
                        if (effects == nullptr || effect_depths == nullptr ||
                            !effects->push({value_index, local.span, materialized_ref}) ||
                            !effect_depths->push(arm.local_guard_depth[li]))
                            return frontend_error(FrontendError::TooManyItems, local.span);
                        continue;
                    }
                    auto local_binding = push_ctx_binding(
                        scoped_ctx, local.ref_index, local_value.value(), local.span);
                    if (!local_binding) return core::make_unexpected(local_binding.error());
                }
                return body_ctx;
            };
            auto body_match_arm_entry_index = [&](const HirForLoopMatchArm& arm,
                                                  u32 arm_index) -> u32 {
                if (arm.has_source_arm_guard) return body_match_source_guard_index[arm_index];
                if (arm.has_arm_guard && arm.arm_guard_precedes_prelude)
                    return body_match_guard_index[arm_index];
                if (is_capture_group_owner(*terminating_body_match, arm_index) &&
                    arm.capture_group != 0 && arm.guards.len != 0)
                    return body_match_prelude_guard_index[arm_index][0];
                if (arm.has_arm_guard) return body_match_guard_index[arm_index];
                if (arm.post_arm_guard_expr_index != 0xffffffffu)
                    return body_match_post_guard_index[arm_index];
                if (arm.guards.len != 0 &&
                    (arm.capture_group == 0 ||
                     is_capture_group_owner(*terminating_body_match, arm_index)))
                    return body_match_prelude_guard_index[arm_index][0];
                return body_match_case_index[arm_index];
            };
            auto body_match_arm_post_prelude_index = [&](const HirForLoopMatchArm& arm,
                                                         u32 arm_index) -> u32 {
                if (arm.post_arm_guard_expr_index != 0xffffffffu)
                    return body_match_post_guard_index[arm_index];
                if (arm.has_arm_guard) return body_match_guard_index[arm_index];
                return body_match_case_index[arm_index];
            };
            auto body_match_arm_body_index = [&](const HirForLoopMatchArm&, u32 arm_index) -> u32 {
                return body_match_case_index[arm_index];
            };
            auto emit_body_match_prelude_guards =
                [&](const HirForLoopMatch& body_match,
                    const ForLoopCtx* ctx) -> FrontendResult<void> {
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    if (!is_capture_group_owner(body_match, ai)) continue;
                    const auto& arm = body_match.arms[ai];
                    const ForLoopCtx* body_ctx = for_loop_match_arm_ctx(arm, ai, ctx);
                    for (u32 gi = 0; gi < arm.guards.len; gi++) {
                        MirBlock guard_block{};
                        guard_block.label = cont_label();
                        auto effects =
                            append_body_match_arm_effects(&guard_block, ai, gi, arm.span);
                        if (!effects) return core::make_unexpected(effects.error());
                        guard_block.term.kind = MirTerminatorKind::Branch;
                        guard_block.term.span = arm.guards[gi].span;
                        auto cond = mir_value(arm.guards[gi].cond, module, &fn, body_ctx);
                        if (!cond) return core::make_unexpected(cond.error());
                        guard_block.term.cond = cond.value();
                        guard_block.term.then_block =
                            gi + 1 < arm.guards.len ? body_match_prelude_guard_index[ai][gi + 1]
                            : arm.capture_group != 0 && arm.has_arm_guard
                                ? body_match_guard_index[ai]
                            : arm.post_arm_guard_expr_index != 0xffffffffu
                                ? body_match_post_guard_index[ai]
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
                    if (!is_capture_group_owner(body_match, ai)) continue;
                    const auto& arm = body_match.arms[ai];
                    const ForLoopCtx* body_ctx = for_loop_match_arm_ctx(arm, ai, ctx);
                    for (u32 gi = 0; gi < arm.guards.len; gi++) {
                        auto emitted = emit_guard_fail(arm.guards[gi], body_ctx);
                        if (!emitted) return core::make_unexpected(emitted.error());
                    }
                }
                return {};
            };

            for (u32 si = 0; si < step_count; si++) {
                const ForLoopCtx* step_ctx = route_step_ctx(steps[si]);
                MirBlock block{};
                block.label = si == 0 ? entry_label() : cont_label();
                if (steps[si].kind == RouteStep::Kind::Let ||
                    steps[si].kind == RouteStep::Kind::Effect) {
                    if (!block.effects.push({steps[si].effect_value_index,
                                             steps[si].span,
                                             steps[si].effect_local_ref_index}))
                        return frontend_error(FrontendError::TooManyItems, steps[si].span);
                    block.term.kind = MirTerminatorKind::Branch;
                    block.term.span = steps[si].span;
                    block.term.cond.kind = MirValueKind::BoolConst;
                    block.term.cond.type = MirTypeKind::Bool;
                    block.term.cond.bool_value = true;
                    block.term.then_block = si + 1 < step_count ? si + 1 : terminal_index;
                    block.term.else_block = block.term.then_block;
                    if (!fn.blocks.push(block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                    continue;
                }
                if (steps[si].kind == RouteStep::Kind::Term) {
                    if (steps[si].term_locals != nullptr) {
                        for (u32 li = 0; li < steps[si].term_locals->len; li++) {
                            auto local =
                                set_branch_local(&block, (*steps[si].term_locals)[li], step_ctx);
                            if (!local) return core::make_unexpected(local.error());
                        }
                    }
                    set_term_from_hir(&block.term, *steps[si].term, step_ctx);
                    if (!fn.blocks.push(block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                    continue;
                }
                if (steps[si].kind == RouteStep::Kind::IfControl) {
                    const auto& body_if = *steps[si].body_if;
                    block.term.kind = MirTerminatorKind::Branch;
                    block.term.span = body_if.span;
                    auto cond = mir_value(body_if.cond, module, &fn, step_ctx);
                    if (!cond) return core::make_unexpected(cond.error());
                    block.term.cond = cond.value();
                    block.term.then_block = body_if.then_branch.kind == HirForLoopBranch::Kind::Term
                                                ? steps[si].then_term_index
                                                : (steps[si].then_target_index == 0xffffffffu
                                                       ? terminal_index
                                                       : steps[si].then_target_index);
                    block.term.else_block = body_if.else_branch.kind == HirForLoopBranch::Kind::Term
                                                ? steps[si].else_term_index
                                                : (steps[si].else_target_index == 0xffffffffu
                                                       ? terminal_index
                                                       : steps[si].else_target_index);
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
                if (steps[si].kind == RouteStep::Kind::MatchControl) {
                    const auto& body_match = *steps[si].body_match;
                    if (body_match.arms.len == 0)
                        return frontend_error(FrontendError::UnsupportedSyntax, body_match.span);
                    auto subject = mir_value(body_match.match_expr, module, &fn, step_ctx);
                    if (!subject) return core::make_unexpected(subject.error());
                    const bool capture_subject = subject->kind != MirValueKind::BoolConst &&
                                                 subject->kind != MirValueKind::IntConst &&
                                                 subject->kind != MirValueKind::StrConst &&
                                                 subject->kind != MirValueKind::LocalRef;
                    if (capture_subject) {
                        if (next_unrolled_local_ref >= MirFunction::kMaxLocals)
                            return frontend_error(FrontendError::TooManyItems, body_match.span);
                        const u32 materialized_ref = next_unrolled_local_ref++;
                        if (!fn.values.push(subject.value()))
                            return frontend_error(FrontendError::TooManyItems, body_match.span);
                        if (!block.effects.push(
                                {fn.values.len - 1, body_match.span, materialized_ref}))
                            return frontend_error(FrontendError::TooManyItems, body_match.span);
                        MirValue local_ref = subject.value();
                        local_ref.kind = MirValueKind::LocalRef;
                        local_ref.local_index = materialized_ref;
                        local_ref.args.len = 0;
                        local_ref.lhs = nullptr;
                        local_ref.rhs = nullptr;
                        steps[si].match_subject = local_ref;
                    } else {
                        steps[si].match_subject = subject.value();
                    }
                    steps[si].has_match_subject = true;
                    auto arm_entry = [&](u32 arm_index) -> u32 {
                        const auto& arm = body_match.arms[arm_index];
                        if (arm.has_source_arm_guard)
                            return steps[si].match_source_guard_index[arm_index];
                        if (is_capture_group_owner(body_match, arm_index) &&
                            arm.capture_group != 0 && arm.guards.len != 0)
                            return steps[si].match_prelude_guard_index[arm_index][0];
                        if (arm.has_arm_guard) return steps[si].match_arm_guard_index[arm_index];
                        if (arm.post_arm_guard_expr_index != 0xffffffffu)
                            return steps[si].match_post_guard_index[arm_index];
                        if (arm.guards.len != 0 && (arm.capture_group == 0 ||
                                                    is_capture_group_owner(body_match, arm_index)))
                            return steps[si].match_prelude_guard_index[arm_index][0];
                        return steps[si].match_case_index[arm_index];
                    };
                    auto fallthrough_target = [&](u32 arm_index) -> u32 {
                        for (u32 next = arm_index + 1; next < body_match.arms.len; next++) {
                            if (body_match.arms[arm_index].capture_group != 0 &&
                                body_match.arms[next].capture_group ==
                                    body_match.arms[arm_index].capture_group)
                                continue;
                            if (body_match.arms[next].is_wildcard) return arm_entry(next);
                            return steps[si].match_test_index[steps[si].match_test_ordinal[next]];
                        }
                        return arm_entry(body_match.arms.len - 1);
                    };
                    if (steps[si].match_non_wildcard_count == 0) {
                        block.term.kind = MirTerminatorKind::Branch;
                        block.term.cond.kind = MirValueKind::BoolConst;
                        block.term.cond.type = MirTypeKind::Bool;
                        block.term.cond.bool_value = true;
                        block.term.then_block = arm_entry(0);
                        block.term.else_block = block.term.then_block;
                    } else {
                        auto pattern = mir_value(body_match.arms[0].pattern, module, &fn, step_ctx);
                        if (!pattern) return core::make_unexpected(pattern.error());
                        block.term.kind = MirTerminatorKind::Branch;
                        block.term.use_cmp = true;
                        block.term.span = body_match.arms[0].span;
                        block.term.lhs = steps[si].match_subject;
                        block.term.rhs = pattern.value();
                        block.term.then_block = arm_entry(0);
                        block.term.else_block = fallthrough_target(0);
                    }
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
                            if (body_match.arms[arm_index].capture_group != 0 &&
                                body_match.arms[next].capture_group ==
                                    body_match.arms[arm_index].capture_group)
                                continue;
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
                if (steps[si].kind == RouteStep::Kind::Jump) {
                    block.term.kind = MirTerminatorKind::Branch;
                    block.term.span = steps[si].span;
                    block.term.cond.kind = MirValueKind::BoolConst;
                    block.term.cond.type = MirTypeKind::Bool;
                    block.term.cond.bool_value = true;
                    const u32 target = steps[si].jump_target_index == 0xffffffffu
                                           ? terminal_index
                                           : steps[si].jump_target_index;
                    block.term.then_block = target;
                    block.term.else_block = target;
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
                const ForLoopCtx* terminating_ctx = route_step_ctx(steps[terminating_step_index]);
                MirBlock then_block{};
                then_block.label = then_label();
                auto then_term =
                    set_for_branch_term(&then_block, body_if.then_branch, terminating_ctx);
                if (!then_term) return core::make_unexpected(then_term.error());
                if (!fn.blocks.push(then_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);

                MirBlock else_block{};
                else_block.label = else_label();
                auto else_term =
                    set_for_branch_term(&else_block, body_if.else_branch, terminating_ctx);
                if (!else_term) return core::make_unexpected(else_term.error());
                if (!fn.blocks.push(else_block))
                    return frontend_error(FrontendError::TooManyItems, fn.span);
            } else if (has_terminating_step &&
                       steps[terminating_step_index].kind == RouteStep::Kind::Match) {
                const auto& body_match = *steps[terminating_step_index].body_match;
                const ForLoopCtx* terminating_ctx = route_step_ctx(steps[terminating_step_index]);
                auto subject = mir_value(body_match.match_expr, module, &fn, terminating_ctx);
                if (!subject) return core::make_unexpected(subject.error());
                auto body_match_pattern_fallthrough_target = [&](u32 arm_index) -> u32 {
                    for (u32 next = arm_index + 1; next < body_match.arms.len; next++) {
                        if (body_match.arms[arm_index].capture_group != 0 &&
                            body_match.arms[next].capture_group ==
                                body_match.arms[arm_index].capture_group)
                            continue;
                        if (body_match.arms[next].is_wildcard)
                            return body_match_arm_entry_index(body_match.arms[next], next);
                        return body_match_extra_test_index[body_match_test_ordinal[next]];
                    }
                    return body_match_arm_entry_index(body_match.arms[body_match.arms.len - 1],
                                                      body_match.arms.len - 1);
                };
                auto body_match_guard_fallthrough_target = [&](u32 arm_index) -> u32 {
                    for (u32 next = arm_index + 1; next < body_match.arms.len; next++) {
                        if (body_match.arms[arm_index].capture_group != 0 &&
                            body_match.arms[next].capture_group ==
                                body_match.arms[arm_index].capture_group) {
                            if (body_match.arms[next].is_wildcard)
                                return body_match_arm_post_prelude_index(body_match.arms[next],
                                                                         next);
                            return body_match_extra_test_index[body_match_test_ordinal[next]];
                        }
                        if (body_match.arms[next].is_wildcard)
                            return body_match_arm_entry_index(body_match.arms[next], next);
                        return body_match_extra_test_index[body_match_test_ordinal[next]];
                    }
                    return body_match_arm_entry_index(body_match.arms[body_match.arms.len - 1],
                                                      body_match.arms.len - 1);
                };
                auto body_match_source_fallthrough_target = [&](u32 arm_index) -> u32 {
                    for (u32 next = arm_index + 1; next < body_match.arms.len; next++) {
                        if (body_match.arms[arm_index].capture_group != 0 &&
                            body_match.arms[next].capture_group ==
                                body_match.arms[arm_index].capture_group)
                            continue;
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
                    const ForLoopCtx* body_ctx =
                        for_loop_match_arm_ctx(arm, arm_index, terminating_ctx);
                    if (arm.body_kind == HirForLoopMatchArm::BodyKind::If) {
                        out->term.kind = MirTerminatorKind::Branch;
                        out->term.span = arm.cond.span;
                        auto cond = mir_value(arm.cond, module, &fn, body_ctx);
                        if (!cond) return core::make_unexpected(cond.error());
                        out->term.cond = cond.value();
                        out->term.then_block = body_match_then_index[arm_index];
                        out->term.else_block = body_match_else_index[arm_index];
                    } else {
                        auto term = set_for_branch_term(out, arm.direct_branch, body_ctx);
                        if (!term) return core::make_unexpected(term.error());
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
                        body_match.arms[ai].capture_group != 0 &&
                                body_match.arms[ai - 1].capture_group ==
                                    body_match.arms[ai].capture_group
                            ? body_match_arm_post_prelude_index(body_match.arms[ai], ai)
                            : body_match_arm_entry_index(body_match.arms[ai], ai);
                    test_block.term.else_block = ai + 1 < body_match_non_wildcard_count
                                                     ? body_match_extra_test_index[ai + 1]
                                                     : body_match_pattern_fallthrough_target(ai);
                    if (!fn.blocks.push(test_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                }
                auto prelude_guards = emit_body_match_prelude_guards(body_match, terminating_ctx);
                if (!prelude_guards) return core::make_unexpected(prelude_guards.error());
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    const auto& arm = body_match.arms[ai];
                    if (!arm.has_source_arm_guard) continue;
                    const ForLoopCtx* body_ctx = for_loop_match_arm_ctx(arm, ai, terminating_ctx);
                    MirBlock source_guard{};
                    source_guard.label = cont_label();
                    auto effects = append_body_match_arm_effects(
                        &source_guard,
                        ai,
                        HirForLoopMatchArm::kSourceGuardDependencyDepth,
                        arm.span);
                    if (!effects) return core::make_unexpected(effects.error());
                    effects = append_body_match_arm_effects(
                        &source_guard, ai, HirForLoopMatchArm::kSourceGuardLatchDepth, arm.span);
                    if (!effects) return core::make_unexpected(effects.error());
                    source_guard.term.kind = MirTerminatorKind::Branch;
                    source_guard.term.span = arm.source_arm_guard.span;
                    auto guard = mir_value(arm.source_arm_guard, module, &fn, body_ctx);
                    if (!guard) return core::make_unexpected(guard.error());
                    source_guard.term.cond = guard.value();
                    source_guard.term.then_block = arm.guards.len != 0
                                                       ? body_match_prelude_guard_index[ai][0]
                                                   : arm.has_arm_guard ? body_match_guard_index[ai]
                                                                       : body_match_case_index[ai];
                    source_guard.term.else_block = body_match_source_fallthrough_target(ai);
                    if (!fn.blocks.push(source_guard))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                }
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    const auto& arm = body_match.arms[ai];
                    if (!arm.has_arm_guard) continue;
                    const ForLoopCtx* body_ctx = for_loop_match_arm_ctx(arm, ai, terminating_ctx);
                    MirBlock guard_block{};
                    guard_block.label = cont_label();
                    const u32 effect_depth = arm.arm_guard_precedes_prelude
                                                 ? HirForLoopMatchArm::kSourceGuardDependencyDepth
                                                 : arm.guards.len;
                    auto effects =
                        append_body_match_arm_effects(&guard_block, ai, effect_depth, arm.span);
                    if (!effects) return core::make_unexpected(effects.error());
                    guard_block.term.kind = MirTerminatorKind::Branch;
                    guard_block.term.span = arm.arm_guard.span;
                    auto guard = mir_value(arm.arm_guard, module, &fn, body_ctx);
                    if (!guard) return core::make_unexpected(guard.error());
                    guard_block.term.cond = guard.value();
                    guard_block.term.then_block =
                        arm.arm_guard_precedes_prelude && arm.guards.len != 0
                            ? body_match_prelude_guard_index[ai][0]
                        : arm.post_arm_guard_expr_index != 0xffffffffu
                            ? body_match_post_guard_index[ai]
                        : arm.capture_group != 0
                            ? body_match_arm_body_index(body_match.arms[ai], ai)
                        : arm.guards.len != 0 ? body_match_prelude_guard_index[ai][0]
                                              : body_match_arm_body_index(body_match.arms[ai], ai);
                    guard_block.term.else_block = body_match_guard_fallthrough_target(ai);
                    if (!fn.blocks.push(guard_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                }
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    const auto& arm = body_match.arms[ai];
                    if (arm.post_arm_guard_expr_index == 0xffffffffu) continue;
                    if (arm.post_arm_guard_expr_index >= module.routes[i].exprs.len)
                        return frontend_error(FrontendError::UnsupportedSyntax, arm.span);
                    const ForLoopCtx* body_ctx = for_loop_match_arm_ctx(arm, ai, terminating_ctx);
                    MirBlock guard_block{};
                    guard_block.label = cont_label();
                    auto effects =
                        append_body_match_arm_effects(&guard_block, ai, arm.guards.len, arm.span);
                    if (!effects) return core::make_unexpected(effects.error());
                    const auto& post_guard = module.routes[i].exprs[arm.post_arm_guard_expr_index];
                    guard_block.term.kind = MirTerminatorKind::Branch;
                    guard_block.term.span = post_guard.span;
                    auto guard = mir_value(post_guard, module, &fn, body_ctx);
                    if (!guard) return core::make_unexpected(guard.error());
                    guard_block.term.cond = guard.value();
                    guard_block.term.then_block = body_match_case_index[ai];
                    guard_block.term.else_block = body_match_guard_fallthrough_target(ai);
                    if (!fn.blocks.push(guard_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                }
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    MirBlock case_block{};
                    case_block.label = body_match.arms[ai].is_wildcard ? match_default_label()
                                                                       : match_case_label();
                    if (body_match.arms[ai].post_arm_guard_expr_index == 0xffffffffu &&
                        (!body_match.arms[ai].has_arm_guard ||
                         body_match.arms[ai].arm_guard_precedes_prelude)) {
                        auto effects = append_body_match_arm_effects(&case_block,
                                                                     ai,
                                                                     body_match.arms[ai].guards.len,
                                                                     body_match.arms[ai].span);
                        if (!effects) return core::make_unexpected(effects.error());
                    }
                    auto armed = set_body_match_arm_term(&case_block, body_match.arms[ai], ai);
                    if (!armed) return core::make_unexpected(armed.error());
                    if (!fn.blocks.push(case_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                    if (body_match.arms[ai].body_kind == HirForLoopMatchArm::BodyKind::If) {
                        const ForLoopCtx* body_ctx =
                            for_loop_match_arm_ctx(body_match.arms[ai], ai, terminating_ctx);
                        MirBlock then_block{};
                        then_block.label = then_label();
                        auto then_term = set_for_branch_term(
                            &then_block, body_match.arms[ai].then_branch, body_ctx);
                        if (!then_term) return core::make_unexpected(then_term.error());
                        if (!fn.blocks.push(then_block))
                            return frontend_error(FrontendError::TooManyItems, fn.span);

                        MirBlock else_block{};
                        else_block.label = else_label();
                        auto else_term = set_for_branch_term(
                            &else_block, body_match.arms[ai].else_branch, body_ctx);
                        if (!else_term) return core::make_unexpected(else_term.error());
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
                            if (arm.has_then_local) {
                                auto local = set_branch_local(&then_block, arm.then_local);
                                if (!local) return core::make_unexpected(local.error());
                            }
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
                                if (arm.has_then_local) {
                                    auto local = set_branch_local(&then_block, arm.then_local);
                                    if (!local) return core::make_unexpected(local.error());
                                }
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

            for (u32 si = 0; si < step_count; si++) {
                if (steps[si].kind != RouteStep::Kind::IfControl) continue;
                const auto& body_if = *steps[si].body_if;
                const ForLoopCtx* step_ctx = route_step_ctx(steps[si]);
                if (body_if.then_branch.kind == HirForLoopBranch::Kind::Term) {
                    MirBlock then_term{};
                    then_term.label = then_label();
                    auto lowered = set_for_branch_term(&then_term, body_if.then_branch, step_ctx);
                    if (!lowered) return core::make_unexpected(lowered.error());
                    if (!fn.blocks.push(then_term))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                }
                if (body_if.else_branch.kind == HirForLoopBranch::Kind::Term) {
                    MirBlock else_term{};
                    else_term.label = else_label();
                    auto lowered = set_for_branch_term(&else_term, body_if.else_branch, step_ctx);
                    if (!lowered) return core::make_unexpected(lowered.error());
                    if (!fn.blocks.push(else_term))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                }
            }
            for (u32 si = 0; si < step_count; si++) {
                if (steps[si].kind != RouteStep::Kind::MatchControl) continue;
                auto& step = steps[si];
                const auto& body_match = *step.body_match;
                const ForLoopCtx* step_ctx = route_step_ctx(step);
                if (!step.has_match_subject)
                    return frontend_error(FrontendError::UnsupportedSyntax, step.span);
                auto arm_target =
                    [&](const HirForLoopBranch& branch, u32 term_index, u32 loop_index) -> u32 {
                    if (branch.kind == HirForLoopBranch::Kind::Term) return term_index;
                    return loop_index == 0xffffffffu ? terminal_index : loop_index;
                };
                auto arm_entry = [&](u32 arm_index) -> u32 {
                    const auto& arm = body_match.arms[arm_index];
                    if (arm.has_source_arm_guard) return step.match_source_guard_index[arm_index];
                    if (arm.has_arm_guard && arm.arm_guard_precedes_prelude)
                        return step.match_arm_guard_index[arm_index];
                    if (is_capture_group_owner(body_match, arm_index) && arm.capture_group != 0 &&
                        arm.guards.len != 0)
                        return step.match_prelude_guard_index[arm_index][0];
                    if (arm.has_arm_guard) return step.match_arm_guard_index[arm_index];
                    if (arm.post_arm_guard_expr_index != 0xffffffffu)
                        return step.match_post_guard_index[arm_index];
                    if (arm.guards.len != 0 &&
                        (arm.capture_group == 0 || is_capture_group_owner(body_match, arm_index)))
                        return step.match_prelude_guard_index[arm_index][0];
                    return step.match_case_index[arm_index];
                };
                auto arm_post_prelude = [&](u32 arm_index) -> u32 {
                    const auto& arm = body_match.arms[arm_index];
                    if (arm.post_arm_guard_expr_index != 0xffffffffu)
                        return step.match_post_guard_index[arm_index];
                    if (arm.has_arm_guard) return step.match_arm_guard_index[arm_index];
                    return step.match_case_index[arm_index];
                };
                auto pattern_fallthrough_target = [&](u32 arm_index) -> u32 {
                    for (u32 next = arm_index + 1; next < body_match.arms.len; next++) {
                        if (body_match.arms[arm_index].capture_group != 0 &&
                            body_match.arms[next].capture_group ==
                                body_match.arms[arm_index].capture_group)
                            continue;
                        if (body_match.arms[next].is_wildcard) return arm_entry(next);
                        return step.match_test_index[step.match_test_ordinal[next]];
                    }
                    return arm_entry(body_match.arms.len - 1);
                };
                auto guard_fallthrough_target = [&](u32 arm_index) -> u32 {
                    for (u32 next = arm_index + 1; next < body_match.arms.len; next++) {
                        if (body_match.arms[arm_index].capture_group != 0 &&
                            body_match.arms[next].capture_group ==
                                body_match.arms[arm_index].capture_group) {
                            if (body_match.arms[next].is_wildcard) return arm_post_prelude(next);
                            return step.match_test_index[step.match_test_ordinal[next]];
                        }
                        if (body_match.arms[next].is_wildcard) return arm_entry(next);
                        return step.match_test_index[step.match_test_ordinal[next]];
                    }
                    return arm_entry(body_match.arms.len - 1);
                };
                auto source_fallthrough_target = [&](u32 arm_index) -> u32 {
                    for (u32 next = arm_index + 1; next < body_match.arms.len; next++) {
                        if (body_match.arms[arm_index].capture_group != 0 &&
                            body_match.arms[next].capture_group ==
                                body_match.arms[arm_index].capture_group)
                            continue;
                        if (body_match.arms[next].is_wildcard) return arm_entry(next);
                        return step.match_test_index[step.match_test_ordinal[next]];
                    }
                    return arm_entry(body_match.arms.len - 1);
                };
                for (u32 ordinal = 1; ordinal < step.match_non_wildcard_count; ordinal++) {
                    u32 arm_index = 0;
                    while (arm_index < body_match.arms.len &&
                           (body_match.arms[arm_index].is_wildcard ||
                            step.match_test_ordinal[arm_index] != ordinal))
                        arm_index++;
                    if (arm_index >= body_match.arms.len)
                        return frontend_error(FrontendError::UnsupportedSyntax, step.span);
                    auto pattern =
                        mir_value(body_match.arms[arm_index].pattern, module, &fn, step_ctx);
                    if (!pattern) return core::make_unexpected(pattern.error());
                    MirBlock test{};
                    test.label = match_test_label();
                    test.term.kind = MirTerminatorKind::Branch;
                    test.term.use_cmp = true;
                    test.term.span = body_match.arms[arm_index].span;
                    test.term.lhs = step.match_subject;
                    test.term.rhs = pattern.value();
                    test.term.then_block = arm_index != 0 &&
                                                   body_match.arms[arm_index].capture_group != 0 &&
                                                   body_match.arms[arm_index - 1].capture_group ==
                                                       body_match.arms[arm_index].capture_group
                                               ? arm_post_prelude(arm_index)
                                               : arm_entry(arm_index);
                    test.term.else_block = pattern_fallthrough_target(arm_index);
                    if (!fn.blocks.push(test))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                }
                ForLoopCtx arm_contexts[HirForLoopMatch::kMaxMatchArms]{};
                ForLoopCtx shared_arm_contexts[HirForLoopMatch::kMaxMatchArms]{};
                FixedVec<MirBlock::Effect, HirForLoopMatchArm::kMaxLocals>
                    arm_effects[HirForLoopMatch::kMaxMatchArms]{};
                FixedVec<u32, HirForLoopMatchArm::kMaxLocals>
                    arm_effect_depths[HirForLoopMatch::kMaxMatchArms]{};
                u8 capture_owner[HirForLoopMatch::kMaxMatchArms]{};
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    const auto& arm = body_match.arms[ai];
                    if (arm.capture_local_count > arm.locals.len)
                        return frontend_error(FrontendError::UnsupportedSyntax, arm.span);
                    capture_owner[ai] = static_cast<u8>(ai);
                    if (arm.capture_group != 0) {
                        for (u32 prior = 0; prior < ai; prior++) {
                            if (body_match.arms[prior].capture_group != arm.capture_group) continue;
                            capture_owner[ai] = static_cast<u8>(prior);
                            arm_contexts[ai] = shared_arm_contexts[prior];
                            break;
                        }
                    }
                    const u32 owner = capture_owner[ai];
                    if (owner == ai) {
                        arm_contexts[ai] = *step_ctx;
                        auto prefix = extend_for_loop_match_arm_ctx(arm,
                                                                    step_ctx,
                                                                    &arm_contexts[ai],
                                                                    0,
                                                                    arm.capture_local_count,
                                                                    &arm_effects[ai],
                                                                    &arm_effect_depths[ai]);
                        if (!prefix) return core::make_unexpected(prefix.error());
                        shared_arm_contexts[ai] = arm_contexts[ai];
                    }
                    auto extended = extend_for_loop_match_arm_ctx(arm,
                                                                  &arm_contexts[ai],
                                                                  &arm_contexts[ai],
                                                                  arm.capture_local_count,
                                                                  arm.locals.len,
                                                                  &arm_effects[ai],
                                                                  &arm_effect_depths[ai]);
                    if (!extended) return core::make_unexpected(extended.error());
                }
                for (u32 ai = 0; ai < body_match.arms.len; ai++) {
                    const auto& arm = body_match.arms[ai];
                    const ForLoopCtx* body_ctx = arm.locals.len == 0 ? step_ctx : &arm_contexts[ai];
                    auto append_effects_at_depth = [&](MirBlock* block,
                                                       u32 depth) -> FrontendResult<void> {
                        for (u32 ei = 0; ei < arm_effects[ai].len; ei++) {
                            if (arm_effect_depths[ai][ei] != depth) continue;
                            if (!block->effects.push(arm_effects[ai][ei]))
                                return frontend_error(FrontendError::TooManyItems, arm.span);
                        }
                        return {};
                    };
                    if (arm.has_source_arm_guard) {
                        MirBlock source_guard{};
                        source_guard.label = cont_label();
                        auto effects = append_effects_at_depth(
                            &source_guard, HirForLoopMatchArm::kSourceGuardDependencyDepth);
                        if (!effects) return core::make_unexpected(effects.error());
                        effects = append_effects_at_depth(
                            &source_guard, HirForLoopMatchArm::kSourceGuardLatchDepth);
                        if (!effects) return core::make_unexpected(effects.error());
                        source_guard.term.kind = MirTerminatorKind::Branch;
                        source_guard.term.span = arm.source_arm_guard.span;
                        auto cond = mir_value(arm.source_arm_guard, module, &fn, body_ctx);
                        if (!cond) return core::make_unexpected(cond.error());
                        source_guard.term.cond = cond.value();
                        source_guard.term.then_block =
                            arm.guards.len != 0 ? step.match_prelude_guard_index[ai][0]
                            : arm.has_arm_guard ? step.match_arm_guard_index[ai]
                                                : step.match_case_index[ai];
                        source_guard.term.else_block = source_fallthrough_target(ai);
                        if (!fn.blocks.push(source_guard))
                            return frontend_error(FrontendError::TooManyItems, fn.span);
                    }
                    if (arm.has_arm_guard) {
                        MirBlock guard{};
                        guard.label = cont_label();
                        const u32 effect_depth =
                            arm.arm_guard_precedes_prelude
                                ? HirForLoopMatchArm::kSourceGuardDependencyDepth
                                : arm.guards.len;
                        auto effects = append_effects_at_depth(&guard, effect_depth);
                        if (!effects) return core::make_unexpected(effects.error());
                        guard.term.kind = MirTerminatorKind::Branch;
                        guard.term.span = arm.arm_guard.span;
                        auto cond = mir_value(arm.arm_guard, module, &fn, body_ctx);
                        if (!cond) return core::make_unexpected(cond.error());
                        guard.term.cond = cond.value();
                        guard.term.then_block =
                            arm.arm_guard_precedes_prelude && arm.guards.len != 0
                                ? step.match_prelude_guard_index[ai][0]
                            : arm.post_arm_guard_expr_index != 0xffffffffu
                                ? step.match_post_guard_index[ai]
                            : arm.capture_group != 0 ? step.match_case_index[ai]
                            : arm.guards.len != 0    ? step.match_prelude_guard_index[ai][0]
                                                     : step.match_case_index[ai];
                        guard.term.else_block = guard_fallthrough_target(ai);
                        if (!fn.blocks.push(guard))
                            return frontend_error(FrontendError::TooManyItems, fn.span);
                    }
                    if (is_capture_group_owner(body_match, ai))
                        for (u32 gi = 0; gi < arm.guards.len; gi++) {
                            MirBlock guard{};
                            guard.label = cont_label();
                            auto effects = append_effects_at_depth(&guard, gi);
                            if (!effects) return core::make_unexpected(effects.error());
                            guard.term.kind = MirTerminatorKind::Branch;
                            guard.term.span = arm.guards[gi].span;
                            auto cond = mir_value(arm.guards[gi].cond, module, &fn, body_ctx);
                            if (!cond) return core::make_unexpected(cond.error());
                            guard.term.cond = cond.value();
                            guard.term.then_block = gi + 1 < arm.guards.len
                                                        ? step.match_prelude_guard_index[ai][gi + 1]
                                                    : arm.capture_group != 0 && arm.has_arm_guard
                                                        ? step.match_arm_guard_index[ai]
                                                        : step.match_case_index[ai];
                            guard.term.else_block = step.match_prelude_fail_index[ai][gi];
                            if (!fn.blocks.push(guard))
                                return frontend_error(FrontendError::TooManyItems, fn.span);
                        }
                    if (arm.post_arm_guard_expr_index != 0xffffffffu) {
                        if (arm.post_arm_guard_expr_index >= module.routes[i].exprs.len)
                            return frontend_error(FrontendError::UnsupportedSyntax, arm.span);
                        MirBlock guard{};
                        guard.label = cont_label();
                        auto effects = append_effects_at_depth(&guard, arm.guards.len);
                        if (!effects) return core::make_unexpected(effects.error());
                        const auto& post_guard =
                            module.routes[i].exprs[arm.post_arm_guard_expr_index];
                        guard.term.kind = MirTerminatorKind::Branch;
                        guard.term.span = post_guard.span;
                        auto cond = mir_value(post_guard, module, &fn, body_ctx);
                        if (!cond) return core::make_unexpected(cond.error());
                        guard.term.cond = cond.value();
                        guard.term.then_block = step.match_case_index[ai];
                        guard.term.else_block = guard_fallthrough_target(ai);
                        if (!fn.blocks.push(guard))
                            return frontend_error(FrontendError::TooManyItems, fn.span);
                    }
                    MirBlock case_block{};
                    case_block.label = arm.is_wildcard ? match_default_label() : match_case_label();
                    if (arm.post_arm_guard_expr_index == 0xffffffffu &&
                        (!arm.has_arm_guard || arm.arm_guard_precedes_prelude)) {
                        auto effects = append_effects_at_depth(&case_block, arm.guards.len);
                        if (!effects) return core::make_unexpected(effects.error());
                    }
                    if (arm.body_kind == HirForLoopMatchArm::BodyKind::If) {
                        case_block.term.kind = MirTerminatorKind::Branch;
                        case_block.term.span = arm.cond.span;
                        auto cond = mir_value(arm.cond, module, &fn, body_ctx);
                        if (!cond) return core::make_unexpected(cond.error());
                        case_block.term.cond = cond.value();
                        case_block.term.then_block = arm_target(arm.then_branch,
                                                                step.match_then_term_index[ai],
                                                                step.match_then_target_index[ai]);
                        case_block.term.else_block = arm_target(arm.else_branch,
                                                                step.match_else_term_index[ai],
                                                                step.match_else_target_index[ai]);
                    } else {
                        const u32 target = arm_target(arm.direct_branch,
                                                      step.match_direct_term_index[ai],
                                                      step.match_direct_target_index[ai]);
                        case_block.term.kind = MirTerminatorKind::Branch;
                        case_block.term.cond.kind = MirValueKind::BoolConst;
                        case_block.term.cond.type = MirTypeKind::Bool;
                        case_block.term.cond.bool_value = true;
                        case_block.term.then_block = target;
                        case_block.term.else_block = target;
                    }
                    if (!fn.blocks.push(case_block))
                        return frontend_error(FrontendError::TooManyItems, fn.span);
                    if (arm.body_kind == HirForLoopMatchArm::BodyKind::Direct &&
                        arm.direct_branch.kind == HirForLoopBranch::Kind::Term) {
                        MirBlock term{};
                        term.label = cont_label();
                        auto lowered = set_for_branch_term(&term, arm.direct_branch, body_ctx);
                        if (!lowered) return core::make_unexpected(lowered.error());
                        if (!fn.blocks.push(term))
                            return frontend_error(FrontendError::TooManyItems, fn.span);
                    } else if (arm.body_kind == HirForLoopMatchArm::BodyKind::If) {
                        if (arm.then_branch.kind == HirForLoopBranch::Kind::Term) {
                            MirBlock term{};
                            term.label = then_label();
                            auto lowered = set_for_branch_term(&term, arm.then_branch, body_ctx);
                            if (!lowered) return core::make_unexpected(lowered.error());
                            if (!fn.blocks.push(term))
                                return frontend_error(FrontendError::TooManyItems, fn.span);
                        }
                        if (arm.else_branch.kind == HirForLoopBranch::Kind::Term) {
                            MirBlock term{};
                            term.label = else_label();
                            auto lowered = set_for_branch_term(&term, arm.else_branch, body_ctx);
                            if (!lowered) return core::make_unexpected(lowered.error());
                            if (!fn.blocks.push(term))
                                return frontend_error(FrontendError::TooManyItems, fn.span);
                        }
                    }
                    if (is_capture_group_owner(body_match, ai))
                        for (u32 gi = 0; gi < arm.guards.len; gi++) {
                            const u32 loop_target =
                                step.match_guard_target_index[ai][gi] == 0xffffffffu
                                    ? terminal_index
                                    : step.match_guard_target_index[ai][gi];
                            auto emitted = emit_guard_fail(arm.guards[gi], body_ctx, loop_target);
                            if (!emitted) return core::make_unexpected(emitted.error());
                        }
                }
            }

            // Fail blocks, one per route/virtual guard step.
            for (u32 si = 0; si < step_count; si++) {
                if (steps[si].kind != RouteStep::Kind::Guard) continue;
                const u32 loop_target = steps[si].jump_target_index == 0xffffffffu
                                            ? terminal_index
                                            : steps[si].jump_target_index;
                auto emitted =
                    emit_guard_fail(*steps[si].guard, route_step_ctx(steps[si]), loop_target);
                if (!emitted) return core::make_unexpected(emitted.error());
            }

            if (term_json_copy_failed) return core::make_unexpected(term_json_copy_error);
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
                        if (arm.has_then_local) {
                            auto local = set_branch_local(&then_block, arm.then_local);
                            if (!local) return core::make_unexpected(local.error());
                        }
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
                    if (arm.has_then_local) {
                        auto local = set_branch_local(&then_block, arm.then_local);
                        if (!local) return core::make_unexpected(local.error());
                    }
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
                        if (arm.has_then_local) {
                            auto local = set_branch_local(&then_block, arm.then_local);
                            if (!local) return core::make_unexpected(local.error());
                        }
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
        if (term_json_copy_failed) return core::make_unexpected(term_json_copy_error);
        if (!mir->functions.push(fn)) return frontend_error(FrontendError::TooManyItems, fn.span);
    }

    return mir;
}

}  // namespace rut
