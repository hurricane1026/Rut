#include "rut/compiler/lower_rir.h"

#include "rut/compiler/rir_builder.h"
#include "rut/jit/handler_abi.h"

namespace rut {

namespace {

static u8 yield_kind_abi(WaitEventKind kind) {
    switch (kind) {
        case WaitEventKind::Timer:
            return static_cast<u8>(jit::YieldKind::Timer);
        case WaitEventKind::Any:
            return static_cast<u8>(jit::YieldKind::Any);
        case WaitEventKind::Recv:
            return static_cast<u8>(jit::YieldKind::Recv);
        case WaitEventKind::Send:
            return static_cast<u8>(jit::YieldKind::Send);
        case WaitEventKind::UpstreamConnect:
            return static_cast<u8>(jit::YieldKind::UpstreamConnect);
        case WaitEventKind::UpstreamRecv:
            return static_cast<u8>(jit::YieldKind::UpstreamRecv);
        case WaitEventKind::UpstreamSend:
            return static_cast<u8>(jit::YieldKind::UpstreamSend);
    }
    return static_cast<u8>(jit::YieldKind::Timer);
}

static constexpr u32 wait_kind_slot(u32 wait_index) {
    return wait_index * 2;
}

static constexpr u32 wait_result_slot(u32 wait_index) {
    return wait_index * 2 + 1;
}

struct VariantLoweringInfo {
    const rir::Type* struct_type = nullptr;
    const rir::Type* payload_bool_type = nullptr;
    const rir::Type* payload_i32_type = nullptr;
    const rir::Type* payload_str_type = nullptr;
    const rir::Type* payload_tuple_type = nullptr;
    const rir::Type* payload_variant_type = nullptr;
    const rir::Type* payload_struct_type = nullptr;
    const rir::Type* payload_bool_opt_type = nullptr;
    const rir::Type* payload_i32_opt_type = nullptr;
    const rir::Type* payload_str_opt_type = nullptr;
    const rir::Type* payload_tuple_opt_type = nullptr;
    const rir::Type* payload_variant_opt_type = nullptr;
    const rir::Type* payload_struct_opt_type = nullptr;
    rir::StructDef* payload_tuple_struct_def = nullptr;
    u32 payload_tuple_len = 0;
    MirTypeKind payload_tuple_types[kMaxMirTupleSlots]{};
    u32 payload_tuple_variant_indices[kMaxMirTupleSlots]{};
    u32 payload_tuple_struct_indices[kMaxMirTupleSlots]{};
    u32 payload_variant_index = 0xffffffffu;
    u32 payload_struct_index = 0xffffffffu;
    u32 payload_shape_index = 0xffffffffu;
    rir::StructDef* struct_def = nullptr;
};

struct ErrorLoweringInfo {
    const rir::Type* struct_type = nullptr;
    const rir::Type* error_type = nullptr;
    const rir::Type* error_opt_type = nullptr;
    const rir::Type* payload_inner_type = nullptr;
    const rir::Type* payload_opt_type = nullptr;
    rir::StructDef* struct_def = nullptr;
};

struct TupleLoweringInfo {
    const rir::Type* struct_type = nullptr;
    rir::StructDef* struct_def = nullptr;
    u32 tuple_len = 0;
    MirTypeKind tuple_types[kMaxMirTupleSlots]{};
    u32 tuple_variant_indices[kMaxMirTupleSlots]{};
    u32 tuple_struct_indices[kMaxMirTupleSlots]{};
};

struct FlatMirShape {
    MirTypeKind type = MirTypeKind::Unknown;
    u32 variant_index = 0xffffffffu;
    u32 struct_index = 0xffffffffu;
    u32 tuple_len = 0;
    MirTypeKind tuple_types[kMaxMirTupleSlots]{};
    u32 tuple_variant_indices[kMaxMirTupleSlots]{};
    u32 tuple_struct_indices[kMaxMirTupleSlots]{};
};

static FrontendResult<const rir::Type*> rir_type_for_flat_shape(
    const FlatMirShape& shape,
    const VariantLoweringInfo* variant_infos,
    TupleLoweringInfo* tuple_infos,
    u32* tuple_info_count,
    const rir::StructDef* const* user_struct_defs,
    rir::Builder& b,
    Span span);

static Str lit(const char* s) {
    u32 n = 0;
    while (s[n]) n++;
    return {s, n};
}

// Intern a compiler-only target transform into the RIR-owned arena.  The table
// entry is published only after both literal copies succeed; an arena
// allocation that fails may consume unreclaimable arena space, but cannot
// leave a partially visible transform or advance the stable ID sequence.
static FrontendResult<u16> intern_target_transform(rir::Module& mod,
                                                   const ForwardTargetTransformSpec& spec,
                                                   Span span) {
    if (!forward_target_transform_spec_valid(spec))
        return frontend_error(FrontendError::UnsupportedSyntax, span);

    for (u32 i = 0; i < mod.target_transform_count; i++) {
        if (forward_target_transform_spec_equal(mod.target_transforms[i], spec))
            return static_cast<u16>(i + 1);
    }
    if (mod.target_transform_count >= kMaxForwardTargetTransforms)
        return frontend_error(FrontendError::TooManyItems, span);

    u32 used = 0;
    for (u32 i = 0; i < mod.target_transform_count; i++) {
        const auto& existing = mod.target_transforms[i];
        if (used > kForwardTargetTransformBytes ||
            existing.strip_prefix.len > kForwardTargetTransformBytes - used)
            return frontend_error(FrontendError::TooManyItems, span);
        used += existing.strip_prefix.len;
        if (existing.replace_prefix.len > kForwardTargetTransformBytes - used)
            return frontend_error(FrontendError::TooManyItems, span);
        used += existing.replace_prefix.len;
    }
    if (spec.strip_prefix.len > kForwardTargetTransformBytes - used)
        return frontend_error(FrontendError::TooManyItems, span);
    used += spec.strip_prefix.len;
    if (spec.replace_prefix.len > kForwardTargetTransformBytes - used)
        return frontend_error(FrontendError::TooManyItems, span);

    auto copy = [&](Str src) -> Str {
        char* dst = mod.arena->alloc_array<char>(src.len);
        if (!dst) return {nullptr, 0xffffffffu};
        for (u32 i = 0; i < src.len; i++) dst[i] = src.ptr[i];
        return {dst, src.len};
    };
    const Str strip = copy(spec.strip_prefix);
    if (strip.len == 0xffffffffu) return frontend_error(FrontendError::OutOfMemory, span);
    const Str replace = copy(spec.replace_prefix);
    if (replace.len == 0xffffffffu) return frontend_error(FrontendError::OutOfMemory, span);

    const u32 index = mod.target_transform_count;
    mod.target_transforms[index] = {strip, replace};
    mod.target_transform_count++;
    return static_cast<u16>(index + 1);
}

static Str payload_field_name(MirTypeKind kind) {
    if (kind == MirTypeKind::Bool) return lit("payload_bool");
    if (kind == MirTypeKind::Str) return lit("payload_str");
    if (kind == MirTypeKind::Tuple) return lit("payload_tuple");
    if (kind == MirTypeKind::Variant) return lit("payload_variant");
    if (kind == MirTypeKind::Struct) return lit("payload_struct");
    return lit("payload_i32");
}

static const rir::Type* payload_inner_type(const VariantLoweringInfo& info, MirTypeKind kind) {
    if (kind == MirTypeKind::Bool) return info.payload_bool_type;
    if (kind == MirTypeKind::Str) return info.payload_str_type;
    if (kind == MirTypeKind::Tuple) return info.payload_tuple_type;
    if (kind == MirTypeKind::Variant) return info.payload_variant_type;
    if (kind == MirTypeKind::Struct) return info.payload_struct_type;
    return info.payload_i32_type;
}

static const rir::Type* payload_opt_type(const VariantLoweringInfo& info, MirTypeKind kind) {
    if (kind == MirTypeKind::Bool) return info.payload_bool_opt_type;
    if (kind == MirTypeKind::Str) return info.payload_str_opt_type;
    if (kind == MirTypeKind::Tuple) return info.payload_tuple_opt_type;
    if (kind == MirTypeKind::Variant) return info.payload_variant_opt_type;
    if (kind == MirTypeKind::Struct) return info.payload_struct_opt_type;
    return info.payload_i32_opt_type;
}

static ErrorLoweringInfo& error_info_for(MirTypeKind kind,
                                         u32 variant_index,
                                         u32 error_struct_index,
                                         ErrorLoweringInfo* scalar_infos,
                                         ErrorLoweringInfo* variant_infos,
                                         ErrorLoweringInfo* struct_infos) {
    if (error_struct_index != 0xffffffffu) return struct_infos[error_struct_index];
    if (kind == MirTypeKind::Bool) return scalar_infos[0];
    if (kind == MirTypeKind::I32) return scalar_infos[1];
    if (kind == MirTypeKind::Str) return scalar_infos[2];
    if (kind == MirTypeKind::Variant) return variant_infos[variant_index];
    return scalar_infos[3];
}

static ErrorLoweringInfo& error_info_for(const FlatMirShape& shape,
                                         u32 error_struct_index,
                                         ErrorLoweringInfo* scalar_infos,
                                         ErrorLoweringInfo* variant_infos,
                                         ErrorLoweringInfo* struct_infos) {
    return error_info_for(shape.type,
                          shape.variant_index,
                          error_struct_index,
                          scalar_infos,
                          variant_infos,
                          struct_infos);
}

static Str error_payload_field_name() {
    return lit("payload");
}

static Str error_field_name() {
    return lit("err");
}

static Str error_code_field_name() {
    return lit("code");
}

static Str error_msg_field_name() {
    return lit("msg");
}

static Str error_file_field_name() {
    return lit("file");
}

static Str error_func_field_name() {
    return lit("func");
}

static Str error_line_field_name() {
    return lit("line");
}

static Str error_check_label() {
    return lit("error_check");
}

static Str error_return_label() {
    return lit("error_return");
}

static Str branch_cond_payload_label() {
    return lit("branch_cond_payload");
}

static Str prelude_label() {
    return lit("prelude");
}

static bool copy_str(MmapArena& arena, Str src, Str* out) {
    char* mem = arena.alloc_array<char>(src.len + 1);
    if (!mem) return false;
    for (u32 i = 0; i < src.len; i++) mem[i] = src.ptr[i];
    mem[src.len] = '\0';
    out->ptr = mem;
    out->len = src.len;
    return true;
}

static bool build_route_name(MmapArena& arena, u32 index, Str* out) {
    char buf[32];
    buf[0] = 'r';
    buf[1] = 'o';
    buf[2] = 'u';
    buf[3] = 't';
    buf[4] = 'e';
    buf[5] = '_';
    u32 pos = 6;
    char tmp[10];
    u32 n = 0;
    u32 v = index;
    if (v == 0) {
        tmp[n++] = '0';
    } else {
        while (v > 0) {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
    }
    while (n > 0) buf[pos++] = tmp[--n];
    return copy_str(arena, {buf, pos}, out);
}

static bool same_tuple_shape(const VariantLoweringInfo& info,
                             u32 tuple_len,
                             const MirTypeKind* tuple_types,
                             const u32* tuple_variant_indices,
                             const u32* tuple_struct_indices) {
    if (info.payload_tuple_len != tuple_len) return false;
    for (u32 i = 0; i < tuple_len; i++) {
        if (info.payload_tuple_types[i] != tuple_types[i]) return false;
        if (info.payload_tuple_types[i] == MirTypeKind::Variant &&
            info.payload_tuple_variant_indices[i] != tuple_variant_indices[i])
            return false;
        if (info.payload_tuple_types[i] == MirTypeKind::Struct &&
            info.payload_tuple_struct_indices[i] != tuple_struct_indices[i])
            return false;
    }
    return true;
}

static bool build_tuple_field_name(MmapArena& arena, u32 index, Str* out) {
    char buf[8];
    u32 pos = 0;
    buf[pos++] = '_';
    u32 n = index + 1;
    char tmp[4];
    u32 tn = 0;
    do {
        tmp[tn++] = static_cast<char>('0' + (n % 10));
        n /= 10;
    } while (n != 0);
    while (tn > 0) buf[pos++] = tmp[--tn];
    return copy_str(arena, {buf, pos}, out);
}

static bool same_tuple_shape(const TupleLoweringInfo& info,
                             u32 tuple_len,
                             const MirTypeKind* tuple_types,
                             const u32* tuple_variant_indices,
                             const u32* tuple_struct_indices) {
    if (info.tuple_len != tuple_len) return false;
    for (u32 i = 0; i < tuple_len; i++) {
        if (info.tuple_types[i] != tuple_types[i]) return false;
        if (info.tuple_types[i] == MirTypeKind::Variant &&
            info.tuple_variant_indices[i] != tuple_variant_indices[i])
            return false;
        if (info.tuple_types[i] == MirTypeKind::Struct &&
            info.tuple_struct_indices[i] != tuple_struct_indices[i])
            return false;
    }
    return true;
}

static FlatMirShape fallback_shape(const MirValue& value) {
    FlatMirShape out{};
    out.type = value.type;
    out.variant_index = value.variant_index;
    out.struct_index = value.struct_index;
    out.tuple_len = value.tuple_len;
    for (u32 i = 0; i < value.tuple_len; i++) {
        out.tuple_types[i] = value.tuple_types[i];
        out.tuple_variant_indices[i] = value.tuple_variant_indices[i];
        out.tuple_struct_indices[i] = value.tuple_struct_indices[i];
    }
    return out;
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

static FlatMirShape fallback_shape(const MirStruct::FieldDecl& field) {
    FlatMirShape out{};
    out.type = field.type;
    out.variant_index = field.variant_index;
    out.struct_index = field.struct_index;
    out.tuple_len = field.tuple_len;
    for (u32 i = 0; i < field.tuple_len; i++) {
        out.tuple_types[i] = field.tuple_types[i];
        out.tuple_variant_indices[i] = field.tuple_variant_indices[i];
        out.tuple_struct_indices[i] = field.tuple_struct_indices[i];
    }
    return out;
}

static FlatMirShape fallback_shape(const MirLocal& local) {
    FlatMirShape out{};
    out.type = local.type;
    out.variant_index = local.variant_index;
    out.struct_index = local.struct_index;
    out.tuple_len = local.tuple_len;
    for (u32 i = 0; i < local.tuple_len; i++) {
        out.tuple_types[i] = local.tuple_types[i];
        out.tuple_variant_indices[i] = local.tuple_variant_indices[i];
        out.tuple_struct_indices[i] = local.tuple_struct_indices[i];
    }
    return out;
}

static FlatMirShape fallback_shape(const MirVariant::CaseDecl& c) {
    FlatMirShape out{};
    out.type = c.payload_type;
    out.variant_index = c.payload_variant_index;
    out.struct_index = c.payload_struct_index;
    out.tuple_len = c.payload_tuple_len;
    for (u32 i = 0; i < c.payload_tuple_len; i++) {
        out.tuple_types[i] = c.payload_tuple_types[i];
        out.tuple_variant_indices[i] = c.payload_tuple_variant_indices[i];
        out.tuple_struct_indices[i] = c.payload_tuple_struct_indices[i];
    }
    return out;
}

static FlatMirShape fallback_payload_shape(const VariantLoweringInfo& info) {
    FlatMirShape out{};
    if (info.payload_tuple_len != 0) {
        out.type = MirTypeKind::Tuple;
        out.tuple_len = info.payload_tuple_len;
        for (u32 i = 0; i < info.payload_tuple_len; i++) {
            out.tuple_types[i] = info.payload_tuple_types[i];
            out.tuple_variant_indices[i] = info.payload_tuple_variant_indices[i];
            out.tuple_struct_indices[i] = info.payload_tuple_struct_indices[i];
        }
        return out;
    }
    if (info.payload_variant_index != 0xffffffffu) {
        out.type = MirTypeKind::Variant;
        out.variant_index = info.payload_variant_index;
        return out;
    }
    if (info.payload_struct_index != 0xffffffffu) {
        out.type = MirTypeKind::Struct;
        out.struct_index = info.payload_struct_index;
    }
    return out;
}

static FlatMirShape tuple_elem_shape(u32 index,
                                     const MirTypeKind* tuple_types,
                                     const u32* tuple_variant_indices,
                                     const u32* tuple_struct_indices) {
    FlatMirShape out{};
    out.type = tuple_types[index];
    if (out.type == MirTypeKind::Variant) out.variant_index = tuple_variant_indices[index];
    if (out.type == MirTypeKind::Struct) out.struct_index = tuple_struct_indices[index];
    return out;
}

static bool expand_flat_shape(const MirModule& mir, u32 shape_index, FlatMirShape* out) {
    if (shape_index == 0xffffffffu || shape_index >= mir.type_shapes.len) return false;
    const auto& shape = mir.type_shapes[shape_index];
    if (!shape.carrier_ready) return false;
    out->type = shape.type;
    out->variant_index = shape.variant_index;
    out->struct_index = shape.struct_index;
    out->tuple_len = shape.tuple_len;
    if (shape.type != MirTypeKind::Tuple) return true;
    for (u32 i = 0; i < shape.tuple_len; i++) {
        const u32 elem_index = shape.tuple_elem_shape_indices[i];
        if (elem_index >= mir.type_shapes.len) return false;
        const auto& elem = mir.type_shapes[elem_index];
        if (!elem.carrier_ready) return false;
        if (elem.type == MirTypeKind::Tuple) return false;
        out->tuple_types[i] = elem.type;
        out->tuple_variant_indices[i] = elem.variant_index;
        out->tuple_struct_indices[i] = elem.struct_index;
    }
    return true;
}

static FlatMirShape resolved_shape(const MirModule& mir, const MirValue& value) {
    auto out = fallback_shape(value);
    expand_flat_shape(mir, value.shape_index, &out);
    return out;
}

static FlatMirShape resolved_shape(const MirModule& mir, const MirStruct::FieldDecl& field) {
    auto out = fallback_shape(field);
    expand_flat_shape(mir, field.shape_index, &out);
    return out;
}

static FlatMirShape resolved_shape(const MirModule& mir, const MirLocal& local) {
    auto out = fallback_shape(local);
    expand_flat_shape(mir, local.shape_index, &out);
    return out;
}

static FlatMirShape resolved_shape(const MirModule& mir, const MirVariant::CaseDecl& c) {
    auto out = fallback_shape(c);
    expand_flat_shape(mir, c.payload_shape_index, &out);
    return out;
}

static FlatMirShape resolved_payload_shape(const MirModule& mir, const VariantLoweringInfo& info) {
    auto out = fallback_payload_shape(info);
    expand_flat_shape(mir, info.payload_shape_index, &out);
    return out;
}

static bool build_indexed_name(MmapArena& arena, Str prefix, u32 index, Str* out) {
    char buf[64];
    u32 pos = 0;
    for (u32 i = 0; i < prefix.len; i++) buf[pos++] = prefix.ptr[i];
    char tmp[16];
    u32 tn = 0;
    u32 n = index;
    do {
        tmp[tn++] = static_cast<char>('0' + (n % 10));
        n /= 10;
    } while (n != 0);
    while (tn > 0) buf[pos++] = tmp[--tn];
    return copy_str(arena, {buf, pos}, out);
}

static FrontendResult<const TupleLoweringInfo*> get_or_create_tuple_lowering(
    u32 tuple_len,
    const MirTypeKind* tuple_types,
    const u32* tuple_variant_indices,
    const u32* tuple_struct_indices,
    const VariantLoweringInfo* variant_infos,
    const rir::StructDef* const* user_struct_defs,
    TupleLoweringInfo* tuple_infos,
    u32* tuple_info_count,
    rir::Builder& b,
    Span span) {
    for (u32 i = 0; i < *tuple_info_count; i++) {
        if (same_tuple_shape(tuple_infos[i],
                             tuple_len,
                             tuple_types,
                             tuple_variant_indices,
                             tuple_struct_indices))
            return &tuple_infos[i];
    }
    if (*tuple_info_count >= 64) return frontend_error(FrontendError::TooManyItems, span);
    auto& info = tuple_infos[*tuple_info_count];
    info.tuple_len = tuple_len;
    for (u32 i = 0; i < tuple_len; i++) {
        info.tuple_types[i] = tuple_types[i];
        info.tuple_variant_indices[i] = tuple_variant_indices[i];
        info.tuple_struct_indices[i] = tuple_struct_indices[i];
    }
    rir::FieldDef fields[kMaxMirTupleSlots]{};
    for (u32 i = 0; i < tuple_len; i++) {
        if (!build_tuple_field_name(*b.mod->arena, i, &fields[i].name))
            return frontend_error(FrontendError::OutOfMemory, span);
        const auto elem_shape =
            tuple_elem_shape(i, tuple_types, tuple_variant_indices, tuple_struct_indices);
        auto field_ty = rir_type_for_flat_shape(
            elem_shape, variant_infos, tuple_infos, tuple_info_count, user_struct_defs, b, span);
        if (!field_ty) return core::make_unexpected(field_ty.error());
        fields[i].type = field_ty.value();
    }
    Str name{};
    if (!build_indexed_name(*b.mod->arena, lit("__tuple_"), *tuple_info_count, &name))
        return frontend_error(FrontendError::OutOfMemory, span);
    auto sd = b.create_struct(name, fields, tuple_len);
    if (!sd) return frontend_error(FrontendError::OutOfMemory, span);
    auto struct_ty = b.make_type(rir::TypeKind::Struct, nullptr, sd.value());
    if (!struct_ty) return frontend_error(FrontendError::OutOfMemory, span);
    info.struct_def = sd.value();
    info.struct_type = struct_ty.value();
    (*tuple_info_count)++;
    return &info;
}

static FrontendResult<const rir::Type*> rir_type_for_shape(
    MirTypeKind type,
    u32 variant_index,
    u32 struct_index,
    u32 tuple_len,
    const MirTypeKind* tuple_types,
    const u32* tuple_variant_indices,
    const u32* tuple_struct_indices,
    const VariantLoweringInfo* variant_infos,
    TupleLoweringInfo* tuple_infos,
    u32* tuple_info_count,
    const rir::StructDef* const* user_struct_defs,
    rir::Builder& b,
    Span span) {
    if (type == MirTypeKind::Bool) {
        auto ty = b.make_type(rir::TypeKind::Bool);
        if (!ty) return frontend_error(FrontendError::OutOfMemory, span);
        return ty.value();
    }
    if (type == MirTypeKind::I32) {
        auto ty = b.make_type(rir::TypeKind::I32);
        if (!ty) return frontend_error(FrontendError::OutOfMemory, span);
        return ty.value();
    }
    if (type == MirTypeKind::I64) {
        auto ty = b.make_type(rir::TypeKind::I64);
        if (!ty) return frontend_error(FrontendError::OutOfMemory, span);
        return ty.value();
    }
    if (type == MirTypeKind::Str) {
        auto ty = b.make_type(rir::TypeKind::Str);
        if (!ty) return frontend_error(FrontendError::OutOfMemory, span);
        return ty.value();
    }
    if (type == MirTypeKind::Method) {
        auto ty = b.make_type(rir::TypeKind::Method);
        if (!ty) return frontend_error(FrontendError::OutOfMemory, span);
        return ty.value();
    }
    if (type == MirTypeKind::ByteSize) {
        auto ty = b.make_type(rir::TypeKind::ByteSize);
        if (!ty) return frontend_error(FrontendError::OutOfMemory, span);
        return ty.value();
    }
    if (type == MirTypeKind::IP) {
        auto ty = b.make_type(rir::TypeKind::IP);
        if (!ty) return frontend_error(FrontendError::OutOfMemory, span);
        return ty.value();
    }
    if (type == MirTypeKind::Variant && variant_index != 0xffffffffu &&
        variant_infos[variant_index].struct_type != nullptr)
        return variant_infos[variant_index].struct_type;
    if (type == MirTypeKind::Variant) {
        auto ty = b.make_type(rir::TypeKind::I32);
        if (!ty) return frontend_error(FrontendError::OutOfMemory, span);
        return ty.value();
    }
    if (type == MirTypeKind::Tuple) {
        auto tuple_info = get_or_create_tuple_lowering(tuple_len,
                                                       tuple_types,
                                                       tuple_variant_indices,
                                                       tuple_struct_indices,
                                                       variant_infos,
                                                       user_struct_defs,
                                                       tuple_infos,
                                                       tuple_info_count,
                                                       b,
                                                       span);
        if (!tuple_info) return core::make_unexpected(tuple_info.error());
        return tuple_info.value()->struct_type;
    }
    if (type == MirTypeKind::Struct && struct_index != 0xffffffffu &&
        user_struct_defs[struct_index] != nullptr) {
        auto ty = b.make_type(rir::TypeKind::Struct,
                              nullptr,
                              const_cast<rir::StructDef*>(user_struct_defs[struct_index]));
        if (!ty) return frontend_error(FrontendError::OutOfMemory, span);
        return ty.value();
    }
    return frontend_error(FrontendError::UnsupportedSyntax, span);
}

static FrontendResult<const rir::Type*> rir_type_for_flat_shape(
    const FlatMirShape& shape,
    const VariantLoweringInfo* variant_infos,
    TupleLoweringInfo* tuple_infos,
    u32* tuple_info_count,
    const rir::StructDef* const* user_struct_defs,
    rir::Builder& b,
    Span span) {
    return rir_type_for_shape(shape.type,
                              shape.variant_index,
                              shape.struct_index,
                              shape.tuple_len,
                              shape.tuple_types,
                              shape.tuple_variant_indices,
                              shape.tuple_struct_indices,
                              variant_infos,
                              tuple_infos,
                              tuple_info_count,
                              user_struct_defs,
                              b,
                              span);
}

static FrontendResult<rir::ValueId> emit_eq_for_flat_shape(
    const FlatMirShape& shape,
    rir::ValueId lhs,
    rir::ValueId rhs,
    const MirModule& mir,
    const VariantLoweringInfo* variant_infos,
    TupleLoweringInfo* tuple_infos,
    u32* tuple_info_count,
    ErrorLoweringInfo* error_scalar_infos,
    ErrorLoweringInfo* error_variant_infos,
    ErrorLoweringInfo* error_struct_infos,
    const rir::StructDef* const* user_struct_defs,
    rir::Builder& b,
    Span span);

static FrontendResult<rir::ValueId> emit_ord_for_flat_shape(
    const FlatMirShape& shape,
    rir::ValueId lhs,
    rir::ValueId rhs,
    const MirModule& mir,
    const VariantLoweringInfo* variant_infos,
    TupleLoweringInfo* tuple_infos,
    u32* tuple_info_count,
    ErrorLoweringInfo* error_scalar_infos,
    ErrorLoweringInfo* error_variant_infos,
    ErrorLoweringInfo* error_struct_infos,
    const rir::StructDef* const* user_struct_defs,
    rir::Builder& b,
    Span span,
    bool less_than);

static FrontendResult<rir::ValueId> emit_eq_for_standard_error(rir::ValueId lhs,
                                                               rir::ValueId rhs,
                                                               rir::Builder& b,
                                                               Span span) {
    auto i32_ty = b.make_type(rir::TypeKind::I32);
    if (!i32_ty) return frontend_error(FrontendError::OutOfMemory, span);
    auto str_ty = b.make_type(rir::TypeKind::Str);
    if (!str_ty) return frontend_error(FrontendError::OutOfMemory, span);
    struct FieldSpec {
        Str name;
        const rir::Type* type;
    };
    const FieldSpec fields[] = {
        {error_code_field_name(), i32_ty.value()},
        {error_msg_field_name(), str_ty.value()},
        {error_file_field_name(), str_ty.value()},
        {error_func_field_name(), str_ty.value()},
        {error_line_field_name(), i32_ty.value()},
    };
    auto result = b.emit_const_bool(true, {span.line, span.col});
    if (!result) return frontend_error(FrontendError::OutOfMemory, span);
    for (const auto& field : fields) {
        auto lhs_field = b.emit_struct_field(lhs, field.name, field.type, {span.line, span.col});
        if (!lhs_field) return frontend_error(FrontendError::OutOfMemory, span);
        auto rhs_field = b.emit_struct_field(rhs, field.name, field.type, {span.line, span.col});
        if (!rhs_field) return frontend_error(FrontendError::OutOfMemory, span);
        auto eq = b.emit_cmp(
            rir::Opcode::CmpEq, lhs_field.value(), rhs_field.value(), {span.line, span.col});
        if (!eq) return frontend_error(FrontendError::OutOfMemory, span);
        auto next =
            b.emit_select(result.value(), eq.value(), result.value(), {span.line, span.col});
        if (!next) return frontend_error(FrontendError::OutOfMemory, span);
        result = next;
    }
    return result.value();
}

static FrontendResult<rir::ValueId> emit_eq_for_shape(MirTypeKind type,
                                                      u32 variant_index,
                                                      u32 struct_index,
                                                      u32 tuple_len,
                                                      const MirTypeKind* tuple_types,
                                                      const u32* tuple_variant_indices,
                                                      const u32* tuple_struct_indices,
                                                      rir::ValueId lhs,
                                                      rir::ValueId rhs,
                                                      const MirModule& mir,
                                                      const VariantLoweringInfo* variant_infos,
                                                      TupleLoweringInfo* tuple_infos,
                                                      u32* tuple_info_count,
                                                      ErrorLoweringInfo* error_scalar_infos,
                                                      ErrorLoweringInfo* error_variant_infos,
                                                      ErrorLoweringInfo* error_struct_infos,
                                                      const rir::StructDef* const* user_struct_defs,
                                                      rir::Builder& b,
                                                      Span span) {
    if (type == MirTypeKind::Bool || type == MirTypeKind::I32 || type == MirTypeKind::I64 ||
        type == MirTypeKind::Str || type == MirTypeKind::Method || type == MirTypeKind::ByteSize ||
        type == MirTypeKind::IP) {
        auto cmp = b.emit_cmp(rir::Opcode::CmpEq, lhs, rhs, {span.line, span.col});
        if (!cmp) return frontend_error(FrontendError::OutOfMemory, span);
        return cmp.value();
    }
    if (type == MirTypeKind::Tuple) {
        auto result = b.emit_const_bool(true, {span.line, span.col});
        if (!result) return frontend_error(FrontendError::OutOfMemory, span);
        for (u32 i = 0; i < tuple_len; i++) {
            Str field_name{};
            if (!build_tuple_field_name(*b.mod->arena, i, &field_name))
                return frontend_error(FrontendError::OutOfMemory, span);
            const auto elem_shape =
                tuple_elem_shape(i, tuple_types, tuple_variant_indices, tuple_struct_indices);
            auto field_ty = rir_type_for_flat_shape(elem_shape,
                                                    variant_infos,
                                                    tuple_infos,
                                                    tuple_info_count,
                                                    user_struct_defs,
                                                    b,
                                                    span);
            if (!field_ty) return core::make_unexpected(field_ty.error());
            auto lhs_field =
                b.emit_struct_field(lhs, field_name, field_ty.value(), {span.line, span.col});
            if (!lhs_field) return frontend_error(FrontendError::OutOfMemory, span);
            auto rhs_field =
                b.emit_struct_field(rhs, field_name, field_ty.value(), {span.line, span.col});
            if (!rhs_field) return frontend_error(FrontendError::OutOfMemory, span);
            auto eq = emit_eq_for_flat_shape(elem_shape,
                                             lhs_field.value(),
                                             rhs_field.value(),
                                             mir,
                                             variant_infos,
                                             tuple_infos,
                                             tuple_info_count,
                                             error_scalar_infos,
                                             error_variant_infos,
                                             error_struct_infos,
                                             user_struct_defs,
                                             b,
                                             span);
            if (!eq) return core::make_unexpected(eq.error());
            auto next =
                b.emit_select(result.value(), eq.value(), result.value(), {span.line, span.col});
            if (!next) return frontend_error(FrontendError::OutOfMemory, span);
            result = next;
        }
        return result.value();
    }
    if (type == MirTypeKind::Struct) {
        if (struct_index >= mir.structs.len)
            return frontend_error(FrontendError::UnsupportedSyntax, span);
        auto result = b.emit_const_bool(true, {span.line, span.col});
        if (!result) return frontend_error(FrontendError::OutOfMemory, span);
        const auto& st = mir.structs[struct_index];
        for (u32 i = 0; i < st.fields.len; i++) {
            const auto& field = st.fields[i];
            const auto field_shape = resolved_shape(mir, field);
            if (field.is_error_type) {
                const rir::Type* error_ty = error_scalar_infos[0].error_type;
                if (error_ty == nullptr)
                    return frontend_error(FrontendError::UnsupportedSyntax, span);
                auto lhs_field =
                    b.emit_struct_field(lhs, field.name, error_ty, {span.line, span.col});
                if (!lhs_field) return frontend_error(FrontendError::OutOfMemory, span);
                auto rhs_field =
                    b.emit_struct_field(rhs, field.name, error_ty, {span.line, span.col});
                if (!rhs_field) return frontend_error(FrontendError::OutOfMemory, span);
                auto eq = emit_eq_for_standard_error(lhs_field.value(), rhs_field.value(), b, span);
                if (!eq) return core::make_unexpected(eq.error());
                auto next = b.emit_select(
                    result.value(), eq.value(), result.value(), {span.line, span.col});
                if (!next) return frontend_error(FrontendError::OutOfMemory, span);
                result = next;
                continue;
            }
            auto field_ty = rir_type_for_flat_shape(field_shape,
                                                    variant_infos,
                                                    tuple_infos,
                                                    tuple_info_count,
                                                    user_struct_defs,
                                                    b,
                                                    span);
            if (!field_ty) return core::make_unexpected(field_ty.error());
            auto lhs_field =
                b.emit_struct_field(lhs, field.name, field_ty.value(), {span.line, span.col});
            if (!lhs_field) return frontend_error(FrontendError::OutOfMemory, span);
            auto rhs_field =
                b.emit_struct_field(rhs, field.name, field_ty.value(), {span.line, span.col});
            if (!rhs_field) return frontend_error(FrontendError::OutOfMemory, span);
            auto eq = emit_eq_for_flat_shape(field_shape,
                                             lhs_field.value(),
                                             rhs_field.value(),
                                             mir,
                                             variant_infos,
                                             tuple_infos,
                                             tuple_info_count,
                                             error_scalar_infos,
                                             error_variant_infos,
                                             error_struct_infos,
                                             user_struct_defs,
                                             b,
                                             span);
            if (!eq) return core::make_unexpected(eq.error());
            auto next =
                b.emit_select(result.value(), eq.value(), result.value(), {span.line, span.col});
            if (!next) return frontend_error(FrontendError::OutOfMemory, span);
            result = next;
        }
        return result.value();
    }
    if (type == MirTypeKind::Variant) {
        if (variant_index >= mir.variants.len)
            return frontend_error(FrontendError::UnsupportedSyntax, span);
        if (variant_infos[variant_index].struct_type == nullptr) {
            auto cmp = b.emit_cmp(rir::Opcode::CmpEq, lhs, rhs, {span.line, span.col});
            if (!cmp) return frontend_error(FrontendError::OutOfMemory, span);
            return cmp.value();
        }
        auto i32_ty = b.make_type(rir::TypeKind::I32);
        if (!i32_ty) return frontend_error(FrontendError::OutOfMemory, span);
        auto lhs_tag = b.emit_struct_field(lhs, lit("tag"), i32_ty.value(), {span.line, span.col});
        if (!lhs_tag) return frontend_error(FrontendError::OutOfMemory, span);
        auto rhs_tag = b.emit_struct_field(rhs, lit("tag"), i32_ty.value(), {span.line, span.col});
        if (!rhs_tag) return frontend_error(FrontendError::OutOfMemory, span);
        auto result =
            b.emit_cmp(rir::Opcode::CmpEq, lhs_tag.value(), rhs_tag.value(), {span.line, span.col});
        if (!result) return frontend_error(FrontendError::OutOfMemory, span);
        const auto& variant = mir.variants[variant_index];
        for (u32 i = 0; i < variant.cases.len; i++) {
            const auto& c = variant.cases[i];
            if (!c.has_payload) continue;
            const auto payload_shape = resolved_shape(mir, c);
            const auto payload_kind = payload_shape.type;
            auto case_tag = b.emit_const_i32(static_cast<i32>(i), {span.line, span.col});
            if (!case_tag) return frontend_error(FrontendError::OutOfMemory, span);
            auto case_match = b.emit_cmp(
                rir::Opcode::CmpEq, lhs_tag.value(), case_tag.value(), {span.line, span.col});
            if (!case_match) return frontend_error(FrontendError::OutOfMemory, span);
            auto payload_opt_ty = payload_opt_type(variant_infos[variant_index], payload_kind);
            auto payload_inner_ty = payload_inner_type(variant_infos[variant_index], payload_kind);
            auto lhs_payload_opt = b.emit_struct_field(
                lhs, payload_field_name(payload_kind), payload_opt_ty, {span.line, span.col});
            if (!lhs_payload_opt) return frontend_error(FrontendError::OutOfMemory, span);
            auto rhs_payload_opt = b.emit_struct_field(
                rhs, payload_field_name(payload_kind), payload_opt_ty, {span.line, span.col});
            if (!rhs_payload_opt) return frontend_error(FrontendError::OutOfMemory, span);
            auto lhs_payload =
                b.emit_opt_unwrap(lhs_payload_opt.value(), payload_inner_ty, {span.line, span.col});
            if (!lhs_payload) return frontend_error(FrontendError::OutOfMemory, span);
            auto rhs_payload =
                b.emit_opt_unwrap(rhs_payload_opt.value(), payload_inner_ty, {span.line, span.col});
            if (!rhs_payload) return frontend_error(FrontendError::OutOfMemory, span);
            auto payload_eq = emit_eq_for_flat_shape(payload_shape,
                                                     lhs_payload.value(),
                                                     rhs_payload.value(),
                                                     mir,
                                                     variant_infos,
                                                     tuple_infos,
                                                     tuple_info_count,
                                                     error_scalar_infos,
                                                     error_variant_infos,
                                                     error_struct_infos,
                                                     user_struct_defs,
                                                     b,
                                                     span);
            if (!payload_eq) return core::make_unexpected(payload_eq.error());
            auto next = b.emit_select(
                case_match.value(), payload_eq.value(), result.value(), {span.line, span.col});
            if (!next) return frontend_error(FrontendError::OutOfMemory, span);
            result = next;
        }
        return result.value();
    }
    return frontend_error(FrontendError::UnsupportedSyntax, span);
}

static FrontendResult<rir::ValueId> emit_eq_for_flat_shape(
    const FlatMirShape& shape,
    rir::ValueId lhs,
    rir::ValueId rhs,
    const MirModule& mir,
    const VariantLoweringInfo* variant_infos,
    TupleLoweringInfo* tuple_infos,
    u32* tuple_info_count,
    ErrorLoweringInfo* error_scalar_infos,
    ErrorLoweringInfo* error_variant_infos,
    ErrorLoweringInfo* error_struct_infos,
    const rir::StructDef* const* user_struct_defs,
    rir::Builder& b,
    Span span) {
    return emit_eq_for_shape(shape.type,
                             shape.variant_index,
                             shape.struct_index,
                             shape.tuple_len,
                             shape.tuple_types,
                             shape.tuple_variant_indices,
                             shape.tuple_struct_indices,
                             lhs,
                             rhs,
                             mir,
                             variant_infos,
                             tuple_infos,
                             tuple_info_count,
                             error_scalar_infos,
                             error_variant_infos,
                             error_struct_infos,
                             user_struct_defs,
                             b,
                             span);
}

static FrontendResult<rir::ValueId> emit_ord_for_shape(
    MirTypeKind type,
    u32 variant_index,
    u32 struct_index,
    u32 tuple_len,
    const MirTypeKind* tuple_types,
    const u32* tuple_variant_indices,
    const u32* tuple_struct_indices,
    rir::ValueId lhs,
    rir::ValueId rhs,
    const MirModule& mir,
    const VariantLoweringInfo* variant_infos,
    TupleLoweringInfo* tuple_infos,
    u32* tuple_info_count,
    ErrorLoweringInfo* error_scalar_infos,
    ErrorLoweringInfo* error_variant_infos,
    ErrorLoweringInfo* error_struct_infos,
    const rir::StructDef* const* user_struct_defs,
    rir::Builder& b,
    Span span,
    bool less_than) {
    if (type == MirTypeKind::I32 || type == MirTypeKind::I64 || type == MirTypeKind::Str) {
        auto op = less_than ? rir::Opcode::CmpLt : rir::Opcode::CmpGt;
        auto cmp = b.emit_cmp(op, lhs, rhs, {span.line, span.col});
        if (!cmp) return frontend_error(FrontendError::OutOfMemory, span);
        return cmp.value();
    }
    if (type == MirTypeKind::Tuple) {
        auto result = b.emit_const_bool(false, {span.line, span.col});
        if (!result) return frontend_error(FrontendError::OutOfMemory, span);
        for (i32 i = static_cast<i32>(tuple_len) - 1; i >= 0; i--) {
            Str field_name{};
            if (!build_tuple_field_name(*b.mod->arena, static_cast<u32>(i), &field_name))
                return frontend_error(FrontendError::OutOfMemory, span);
            const auto elem_shape = tuple_elem_shape(
                static_cast<u32>(i), tuple_types, tuple_variant_indices, tuple_struct_indices);
            auto field_ty = rir_type_for_flat_shape(elem_shape,
                                                    variant_infos,
                                                    tuple_infos,
                                                    tuple_info_count,
                                                    user_struct_defs,
                                                    b,
                                                    span);
            if (!field_ty) return core::make_unexpected(field_ty.error());
            auto lhs_field =
                b.emit_struct_field(lhs, field_name, field_ty.value(), {span.line, span.col});
            if (!lhs_field) return frontend_error(FrontendError::OutOfMemory, span);
            auto rhs_field =
                b.emit_struct_field(rhs, field_name, field_ty.value(), {span.line, span.col});
            if (!rhs_field) return frontend_error(FrontendError::OutOfMemory, span);
            auto eq = emit_eq_for_flat_shape(elem_shape,
                                             lhs_field.value(),
                                             rhs_field.value(),
                                             mir,
                                             variant_infos,
                                             tuple_infos,
                                             tuple_info_count,
                                             error_scalar_infos,
                                             error_variant_infos,
                                             error_struct_infos,
                                             user_struct_defs,
                                             b,
                                             span);
            if (!eq) return core::make_unexpected(eq.error());
            auto ord = emit_ord_for_flat_shape(elem_shape,
                                               lhs_field.value(),
                                               rhs_field.value(),
                                               mir,
                                               variant_infos,
                                               tuple_infos,
                                               tuple_info_count,
                                               error_scalar_infos,
                                               error_variant_infos,
                                               error_struct_infos,
                                               user_struct_defs,
                                               b,
                                               span,
                                               less_than);
            if (!ord) return core::make_unexpected(ord.error());
            auto next =
                b.emit_select(eq.value(), result.value(), ord.value(), {span.line, span.col});
            if (!next) return frontend_error(FrontendError::OutOfMemory, span);
            result = next;
        }
        return result.value();
    }
    if (type == MirTypeKind::Struct) {
        if (struct_index >= mir.structs.len)
            return frontend_error(FrontendError::UnsupportedSyntax, span);
        auto result = b.emit_const_bool(false, {span.line, span.col});
        if (!result) return frontend_error(FrontendError::OutOfMemory, span);
        const auto& st = mir.structs[struct_index];
        for (i32 i = static_cast<i32>(st.fields.len) - 1; i >= 0; i--) {
            const auto& field = st.fields[static_cast<u32>(i)];
            const auto field_shape = resolved_shape(mir, field);
            if (field.is_error_type) return frontend_error(FrontendError::UnsupportedSyntax, span);
            auto field_ty = rir_type_for_flat_shape(field_shape,
                                                    variant_infos,
                                                    tuple_infos,
                                                    tuple_info_count,
                                                    user_struct_defs,
                                                    b,
                                                    span);
            if (!field_ty) return core::make_unexpected(field_ty.error());
            auto lhs_field =
                b.emit_struct_field(lhs, field.name, field_ty.value(), {span.line, span.col});
            if (!lhs_field) return frontend_error(FrontendError::OutOfMemory, span);
            auto rhs_field =
                b.emit_struct_field(rhs, field.name, field_ty.value(), {span.line, span.col});
            if (!rhs_field) return frontend_error(FrontendError::OutOfMemory, span);
            auto eq = emit_eq_for_flat_shape(field_shape,
                                             lhs_field.value(),
                                             rhs_field.value(),
                                             mir,
                                             variant_infos,
                                             tuple_infos,
                                             tuple_info_count,
                                             error_scalar_infos,
                                             error_variant_infos,
                                             error_struct_infos,
                                             user_struct_defs,
                                             b,
                                             span);
            if (!eq) return core::make_unexpected(eq.error());
            auto ord = emit_ord_for_flat_shape(field_shape,
                                               lhs_field.value(),
                                               rhs_field.value(),
                                               mir,
                                               variant_infos,
                                               tuple_infos,
                                               tuple_info_count,
                                               error_scalar_infos,
                                               error_variant_infos,
                                               error_struct_infos,
                                               user_struct_defs,
                                               b,
                                               span,
                                               less_than);
            if (!ord) return core::make_unexpected(ord.error());
            auto next =
                b.emit_select(eq.value(), result.value(), ord.value(), {span.line, span.col});
            if (!next) return frontend_error(FrontendError::OutOfMemory, span);
            result = next;
        }
        return result.value();
    }
    if (type == MirTypeKind::Variant) {
        if (variant_index >= mir.variants.len)
            return frontend_error(FrontendError::UnsupportedSyntax, span);
        const auto& info = variant_infos[variant_index];
        auto i32_ty = b.make_type(rir::TypeKind::I32);
        if (!i32_ty) return frontend_error(FrontendError::OutOfMemory, span);
        if (info.struct_type == nullptr) {
            auto op = less_than ? rir::Opcode::CmpLt : rir::Opcode::CmpGt;
            auto cmp = b.emit_cmp(op, lhs, rhs, {span.line, span.col});
            if (!cmp) return frontend_error(FrontendError::OutOfMemory, span);
            return cmp.value();
        }
        auto lhs_tag = b.emit_struct_field(lhs, lit("tag"), i32_ty.value(), {span.line, span.col});
        if (!lhs_tag) return frontend_error(FrontendError::OutOfMemory, span);
        auto rhs_tag = b.emit_struct_field(rhs, lit("tag"), i32_ty.value(), {span.line, span.col});
        if (!rhs_tag) return frontend_error(FrontendError::OutOfMemory, span);
        auto initial = b.emit_cmp(less_than ? rir::Opcode::CmpLt : rir::Opcode::CmpGt,
                                  lhs_tag.value(),
                                  rhs_tag.value(),
                                  {span.line, span.col});
        if (!initial) return frontend_error(FrontendError::OutOfMemory, span);
        auto result = initial.value();
        const auto& variant = mir.variants[variant_index];
        for (i32 i = static_cast<i32>(variant.cases.len) - 1; i >= 0; i--) {
            const auto& c = variant.cases[static_cast<u32>(i)];
            if (!c.has_payload) continue;
            const auto payload_shape = resolved_shape(mir, c);
            const auto payload_kind = payload_shape.type;
            auto case_tag = b.emit_const_i32(i, {span.line, span.col});
            if (!case_tag) return frontend_error(FrontendError::OutOfMemory, span);
            auto case_match = b.emit_cmp(
                rir::Opcode::CmpEq, lhs_tag.value(), case_tag.value(), {span.line, span.col});
            if (!case_match) return frontend_error(FrontendError::OutOfMemory, span);
            auto payload_opt_ty = payload_opt_type(info, payload_kind);
            auto payload_inner_ty = payload_inner_type(info, payload_kind);
            auto lhs_payload_opt = b.emit_struct_field(
                lhs, payload_field_name(payload_kind), payload_opt_ty, {span.line, span.col});
            if (!lhs_payload_opt) return frontend_error(FrontendError::OutOfMemory, span);
            auto rhs_payload_opt = b.emit_struct_field(
                rhs, payload_field_name(payload_kind), payload_opt_ty, {span.line, span.col});
            if (!rhs_payload_opt) return frontend_error(FrontendError::OutOfMemory, span);
            auto lhs_payload =
                b.emit_opt_unwrap(lhs_payload_opt.value(), payload_inner_ty, {span.line, span.col});
            if (!lhs_payload) return frontend_error(FrontendError::OutOfMemory, span);
            auto rhs_payload =
                b.emit_opt_unwrap(rhs_payload_opt.value(), payload_inner_ty, {span.line, span.col});
            if (!rhs_payload) return frontend_error(FrontendError::OutOfMemory, span);
            auto payload_ord = emit_ord_for_flat_shape(payload_shape,
                                                       lhs_payload.value(),
                                                       rhs_payload.value(),
                                                       mir,
                                                       variant_infos,
                                                       tuple_infos,
                                                       tuple_info_count,
                                                       error_scalar_infos,
                                                       error_variant_infos,
                                                       error_struct_infos,
                                                       user_struct_defs,
                                                       b,
                                                       span,
                                                       less_than);
            if (!payload_ord) return core::make_unexpected(payload_ord.error());
            auto next = b.emit_select(
                case_match.value(), payload_ord.value(), result, {span.line, span.col});
            if (!next) return frontend_error(FrontendError::OutOfMemory, span);
            result = next.value();
        }
        return result;
    }
    return frontend_error(FrontendError::UnsupportedSyntax, span);
}

static FrontendResult<rir::ValueId> emit_ord_for_flat_shape(
    const FlatMirShape& shape,
    rir::ValueId lhs,
    rir::ValueId rhs,
    const MirModule& mir,
    const VariantLoweringInfo* variant_infos,
    TupleLoweringInfo* tuple_infos,
    u32* tuple_info_count,
    ErrorLoweringInfo* error_scalar_infos,
    ErrorLoweringInfo* error_variant_infos,
    ErrorLoweringInfo* error_struct_infos,
    const rir::StructDef* const* user_struct_defs,
    rir::Builder& b,
    Span span,
    bool less_than) {
    return emit_ord_for_shape(shape.type,
                              shape.variant_index,
                              shape.struct_index,
                              shape.tuple_len,
                              shape.tuple_types,
                              shape.tuple_variant_indices,
                              shape.tuple_struct_indices,
                              lhs,
                              rhs,
                              mir,
                              variant_infos,
                              tuple_infos,
                              tuple_info_count,
                              error_scalar_infos,
                              error_variant_infos,
                              error_struct_infos,
                              user_struct_defs,
                              b,
                              span,
                              less_than);
}

static FrontendResult<rir::ValueId> materialize_value(const MirValue& value,
                                                      const MirModule& mir,
                                                      const VariantLoweringInfo* variant_infos,
                                                      TupleLoweringInfo* tuple_infos,
                                                      u32* tuple_info_count,
                                                      ErrorLoweringInfo* error_scalar_infos,
                                                      ErrorLoweringInfo* error_variant_infos,
                                                      ErrorLoweringInfo* error_struct_infos,
                                                      const rir::StructDef* const* user_struct_defs,
                                                      rir::Builder& b,
                                                      const rir::ValueId* locals,
                                                      u32 local_count,
                                                      Span span) {
    auto make_inner_type = [&](const FlatMirShape& shape) -> FrontendResult<const rir::Type*> {
        return rir_type_for_flat_shape(
            shape, variant_infos, tuple_infos, tuple_info_count, user_struct_defs, b, span);
    };

    if (value.kind == MirValueKind::BoolConst) {
        auto v = b.emit_const_bool(value.bool_value, {span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::IntConst) {
        auto v = value.type == MirTypeKind::I64
                     ? b.emit_const_i64(value.int_value, {span.line, span.col})
                     : b.emit_const_i32(static_cast<i32>(value.int_value), {span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::StrConst) {
        auto v = b.emit_const_str(value.str_value, {span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::RegexMatch) {
        auto lhs = materialize_value(*value.lhs,
                                     mir,
                                     variant_infos,
                                     tuple_infos,
                                     tuple_info_count,
                                     error_scalar_infos,
                                     error_variant_infos,
                                     error_struct_infos,
                                     user_struct_defs,
                                     b,
                                     locals,
                                     local_count,
                                     span);
        if (!lhs) return core::make_unexpected(lhs.error());
        auto v = b.emit_str_regex_match(lhs.value(), value.str_value, {span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::Tuple) {
        const auto tuple_shape = resolved_shape(mir, value);
        auto tuple_info = get_or_create_tuple_lowering(tuple_shape.tuple_len,
                                                       tuple_shape.tuple_types,
                                                       tuple_shape.tuple_variant_indices,
                                                       tuple_shape.tuple_struct_indices,
                                                       variant_infos,
                                                       user_struct_defs,
                                                       tuple_infos,
                                                       tuple_info_count,
                                                       b,
                                                       span);
        if (!tuple_info) return core::make_unexpected(tuple_info.error());
        rir::ValueId field_vals[kMaxMirTupleSlots]{};
        for (u32 i = 0; i < value.args.len; i++) {
            auto elem = materialize_value(*value.args[i],
                                          mir,
                                          variant_infos,
                                          tuple_infos,
                                          tuple_info_count,
                                          error_scalar_infos,
                                          error_variant_infos,
                                          error_struct_infos,
                                          user_struct_defs,
                                          b,
                                          locals,
                                          local_count,
                                          span);
            if (!elem) return core::make_unexpected(elem.error());
            field_vals[i] = elem.value();
        }
        auto created = b.emit_struct_create(
            (*tuple_info)->struct_def, field_vals, value.tuple_len, {span.line, span.col});
        if (!created) return frontend_error(FrontendError::OutOfMemory, span);
        return created.value();
    }
    if (value.kind == MirValueKind::StructInit) {
        const auto struct_shape = resolved_shape(mir, value);
        const u32 struct_index = struct_shape.struct_index;
        if (struct_index >= mir.structs.len || user_struct_defs[struct_index] == nullptr)
            return frontend_error(FrontendError::UnsupportedSyntax, span, value.str_value);
        rir::ValueId field_vals[MirStruct::kMaxFields]{};
        for (u32 fi = 0; fi < mir.structs[struct_index].fields.len; fi++) {
            const auto& field = mir.structs[struct_index].fields[fi];
            u32 init_index = value.field_inits.len;
            for (u32 ii = 0; ii < value.field_inits.len; ii++) {
                if (value.field_inits[ii].name.eq(field.name)) {
                    init_index = ii;
                    break;
                }
            }
            if (init_index == value.field_inits.len)
                return frontend_error(FrontendError::UnsupportedSyntax, span, field.name);
            auto field_value = materialize_value(*value.field_inits[init_index].value,
                                                 mir,
                                                 variant_infos,
                                                 tuple_infos,
                                                 tuple_info_count,
                                                 error_scalar_infos,
                                                 error_variant_infos,
                                                 error_struct_infos,
                                                 user_struct_defs,
                                                 b,
                                                 locals,
                                                 local_count,
                                                 span);
            if (!field_value) return core::make_unexpected(field_value.error());
            field_vals[fi] = field_value.value();
        }
        auto created =
            b.emit_struct_create(const_cast<rir::StructDef*>(user_struct_defs[struct_index]),
                                 field_vals,
                                 mir.structs[struct_index].fields.len,
                                 {span.line, span.col});
        if (!created) return frontend_error(FrontendError::OutOfMemory, span);
        return created.value();
    }
    if (value.kind == MirValueKind::VariantCase) {
        const auto variant_shape = resolved_shape(mir, value);
        const u32 variant_index = variant_shape.variant_index;
        const auto& variant = mir.variants[variant_index];
        bool has_any_payload = false;
        for (u32 i = 0; i < variant.cases.len; i++) {
            if (variant.cases[i].has_payload) {
                has_any_payload = true;
                break;
            }
        }
        if (!has_any_payload && variant_infos[variant_index].struct_type == nullptr) {
            auto v = b.emit_const_i32(static_cast<i32>(value.int_value), {span.line, span.col});
            if (!v) return frontend_error(FrontendError::OutOfMemory, span);
            return v.value();
        }
        auto tag = b.emit_const_i32(static_cast<i32>(value.int_value), {span.line, span.col});
        if (!tag) return frontend_error(FrontendError::OutOfMemory, span);
        rir::ValueId payload_bool{};
        rir::ValueId payload_i32{};
        rir::ValueId payload_str{};
        rir::ValueId payload_tuple{};
        auto nil_bool =
            b.emit_opt_nil(variant_infos[variant_index].payload_bool_type, {span.line, span.col});
        if (!nil_bool) return frontend_error(FrontendError::OutOfMemory, span);
        payload_bool = nil_bool.value();
        auto nil_i32 =
            b.emit_opt_nil(variant_infos[variant_index].payload_i32_type, {span.line, span.col});
        if (!nil_i32) return frontend_error(FrontendError::OutOfMemory, span);
        payload_i32 = nil_i32.value();
        payload_tuple = nil_i32.value();
        rir::ValueId payload_variant = nil_i32.value();
        rir::ValueId payload_struct = nil_i32.value();
        auto nil_str =
            b.emit_opt_nil(variant_infos[variant_index].payload_str_type, {span.line, span.col});
        if (!nil_str) return frontend_error(FrontendError::OutOfMemory, span);
        payload_str = nil_str.value();
        if (variant_infos[variant_index].payload_tuple_type != nullptr) {
            auto nil_tuple = b.emit_opt_nil(variant_infos[variant_index].payload_tuple_type,
                                            {span.line, span.col});
            if (!nil_tuple) return frontend_error(FrontendError::OutOfMemory, span);
            payload_tuple = nil_tuple.value();
        }
        if (variant_infos[variant_index].payload_variant_type != nullptr) {
            auto nil_variant = b.emit_opt_nil(variant_infos[variant_index].payload_variant_type,
                                              {span.line, span.col});
            if (!nil_variant) return frontend_error(FrontendError::OutOfMemory, span);
            payload_variant = nil_variant.value();
        }
        if (variant_infos[variant_index].payload_struct_type != nullptr) {
            auto nil_struct = b.emit_opt_nil(variant_infos[variant_index].payload_struct_type,
                                             {span.line, span.col});
            if (!nil_struct) return frontend_error(FrontendError::OutOfMemory, span);
            payload_struct = nil_struct.value();
        }

        if (variant.cases[value.case_index].has_payload && value.lhs != nullptr) {
            const auto payload_shape = resolved_shape(mir, variant.cases[value.case_index]);
            const auto payload_kind = payload_shape.type;
            auto payload_val = materialize_value(*value.lhs,
                                                 mir,
                                                 variant_infos,
                                                 tuple_infos,
                                                 tuple_info_count,
                                                 error_scalar_infos,
                                                 error_variant_infos,
                                                 error_struct_infos,
                                                 user_struct_defs,
                                                 b,
                                                 locals,
                                                 local_count,
                                                 span);
            if (!payload_val) return core::make_unexpected(payload_val.error());
            auto wrapped = b.emit_opt_wrap(payload_val.value(), {span.line, span.col});
            if (!wrapped) return frontend_error(FrontendError::OutOfMemory, span);
            if (payload_kind == MirTypeKind::Bool)
                payload_bool = wrapped.value();
            else if (payload_kind == MirTypeKind::Str)
                payload_str = wrapped.value();
            else if (payload_kind == MirTypeKind::Tuple)
                payload_tuple = wrapped.value();
            else if (payload_kind == MirTypeKind::Variant)
                payload_variant = wrapped.value();
            else if (payload_kind == MirTypeKind::Struct)
                payload_struct = wrapped.value();
            else
                payload_i32 = wrapped.value();
        }
        rir::ValueId fields[] = {tag.value(),
                                 payload_bool,
                                 payload_i32,
                                 payload_str,
                                 payload_tuple,
                                 payload_variant,
                                 payload_struct};
        auto created = b.emit_struct_create(
            variant_infos[variant_index].struct_def, fields, 7, {span.line, span.col});
        if (!created) return frontend_error(FrontendError::OutOfMemory, span);
        return created.value();
    }
    if (value.kind == MirValueKind::TupleSlot) {
        auto subject = materialize_value(*value.lhs,
                                         mir,
                                         variant_infos,
                                         tuple_infos,
                                         tuple_info_count,
                                         error_scalar_infos,
                                         error_variant_infos,
                                         error_struct_infos,
                                         user_struct_defs,
                                         b,
                                         locals,
                                         local_count,
                                         span);
        if (!subject) return core::make_unexpected(subject.error());
        Str field_name{};
        if (!build_tuple_field_name(*b.mod->arena, static_cast<u32>(value.int_value), &field_name))
            return frontend_error(FrontendError::OutOfMemory, span);
        const auto slot_shape = resolved_shape(mir, value);
        auto field_type = rir_type_for_flat_shape(
            slot_shape, variant_infos, tuple_infos, tuple_info_count, user_struct_defs, b, span);
        if (!field_type) return core::make_unexpected(field_type.error());
        auto field = b.emit_struct_field(
            subject.value(), field_name, field_type.value(), {span.line, span.col});
        if (!field) return frontend_error(FrontendError::OutOfMemory, span);
        return field.value();
    }
    if (value.kind == MirValueKind::ReqHeader) {
        auto v = b.emit_req_header(value.str_value, {span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::ReqParam) {
        auto v = b.emit_req_param(value.str_value, {span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::ReqCookie) {
        auto v = b.emit_req_cookie(value.str_value, {span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::ReqQuery) {
        auto v = b.emit_req_query(value.str_value, {span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::ReqQueryString) {
        auto v = b.emit_req_query_string({span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::ReqPath) {
        auto v = b.emit_req_path({span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::ReqPathOnly) {
        auto v = b.emit_req_path_only({span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::ReqBody) {
        auto v = b.emit_req_body({span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::ReqKeepAlive) {
        auto v = b.emit_req_keep_alive({span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::ReqChunked) {
        auto v = b.emit_req_chunked({span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::ReqHasContentLength) {
        auto v = b.emit_req_has_content_length({span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::ReqHttp10) {
        auto v = b.emit_req_http10({span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::ReqHttp11) {
        auto v = b.emit_req_http11({span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::ReqHttpVersion) {
        auto v = b.emit_req_http_version({span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::ReqContentLength) {
        auto v = b.emit_req_content_length({span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::TimeNowMicros) {
        auto out = b.emit_time_now_micros({span.line, span.col});
        if (!out) return frontend_error(FrontendError::OutOfMemory, span);
        return out.value();
    }
    if (value.kind == MirValueKind::ReqRemoteAddr) {
        auto v = b.emit_req_remote_addr({span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::ConstMethod) {
        auto v = b.emit_const_method(static_cast<u8>(value.int_value), {span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::ReqMethod) {
        auto v = b.emit_req_method({span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::WaitResult) {
        return frontend_error(FrontendError::UnsupportedSyntax, span);
    }
    if (value.kind == MirValueKind::WaitField) {
        const u32 wait_index = value.wait_index;
        if (wait_index == 0xffffffffu)
            return frontend_error(FrontendError::UnsupportedSyntax, span, value.str_value);
        if (value.str_value.eq({"kind", 4})) {
            auto v = b.emit_ctx_load_slot_i32(wait_kind_slot(wait_index), {span.line, span.col});
            if (!v) return frontend_error(FrontendError::OutOfMemory, span);
            return v.value();
        }
        auto result = b.emit_ctx_load_slot_i32(wait_result_slot(wait_index), {span.line, span.col});
        if (!result) return frontend_error(FrontendError::OutOfMemory, span);
        if (value.str_value.eq({"result", 6})) return result.value();
        auto zero = b.emit_const_i32(0, {span.line, span.col});
        if (!zero) return frontend_error(FrontendError::OutOfMemory, span);
        if (value.str_value.eq({"ok", 2})) {
            auto cmp =
                b.emit_cmp(rir::Opcode::CmpGe, result.value(), zero.value(), {span.line, span.col});
            if (!cmp) return frontend_error(FrontendError::OutOfMemory, span);
            return cmp.value();
        }
        if (value.str_value.eq({"eof", 3})) {
            auto event_kind =
                b.emit_ctx_load_slot_i32(wait_kind_slot(wait_index), {span.line, span.col});
            if (!event_kind) return frontend_error(FrontendError::OutOfMemory, span);
            auto recv_kind =
                b.emit_const_i32(static_cast<i32>(jit::YieldKind::Recv), {span.line, span.col});
            if (!recv_kind) return frontend_error(FrontendError::OutOfMemory, span);
            auto upstream_recv_kind = b.emit_const_i32(
                static_cast<i32>(jit::YieldKind::UpstreamRecv), {span.line, span.col});
            if (!upstream_recv_kind) return frontend_error(FrontendError::OutOfMemory, span);
            auto recv_like = b.emit_cmp(
                rir::Opcode::CmpEq, event_kind.value(), recv_kind.value(), {span.line, span.col});
            if (!recv_like) return frontend_error(FrontendError::OutOfMemory, span);
            auto upstream_recv_like = b.emit_cmp(rir::Opcode::CmpEq,
                                                 event_kind.value(),
                                                 upstream_recv_kind.value(),
                                                 {span.line, span.col});
            if (!upstream_recv_like) return frontend_error(FrontendError::OutOfMemory, span);
            auto result_is_zero =
                b.emit_cmp(rir::Opcode::CmpEq, result.value(), zero.value(), {span.line, span.col});
            if (!result_is_zero) return frontend_error(FrontendError::OutOfMemory, span);
            auto false_v = b.emit_const_bool(false, {span.line, span.col});
            if (!false_v) return frontend_error(FrontendError::OutOfMemory, span);
            auto upstream_eof = b.emit_select(upstream_recv_like.value(),
                                              result_is_zero.value(),
                                              false_v.value(),
                                              {span.line, span.col});
            if (!upstream_eof) return frontend_error(FrontendError::OutOfMemory, span);
            auto eof = b.emit_select(recv_like.value(),
                                     result_is_zero.value(),
                                     upstream_eof.value(),
                                     {span.line, span.col});
            if (!eof) return frontend_error(FrontendError::OutOfMemory, span);
            return eof.value();
        }
        u32 wanted = 0xffffffffu;
        if (value.str_value.eq({"timer", 5}))
            wanted = static_cast<u32>(jit::YieldKind::Timer);
        else if (value.str_value.eq({"recv", 4}))
            wanted = static_cast<u32>(jit::YieldKind::Recv);
        else if (value.str_value.eq({"send", 4}))
            wanted = static_cast<u32>(jit::YieldKind::Send);
        else if (value.str_value.eq({"upstream_connect", 16}))
            wanted = static_cast<u32>(jit::YieldKind::UpstreamConnect);
        else if (value.str_value.eq({"upstream_recv", 13}))
            wanted = static_cast<u32>(jit::YieldKind::UpstreamRecv);
        else if (value.str_value.eq({"upstream_send", 13}))
            wanted = static_cast<u32>(jit::YieldKind::UpstreamSend);
        if (wanted != 0xffffffffu) {
            auto event_kind =
                b.emit_ctx_load_slot_i32(wait_kind_slot(wait_index), {span.line, span.col});
            if (!event_kind) return frontend_error(FrontendError::OutOfMemory, span);
            auto kind_const = b.emit_const_i32(static_cast<i32>(wanted), {span.line, span.col});
            if (!kind_const) return frontend_error(FrontendError::OutOfMemory, span);
            auto cmp = b.emit_cmp(
                rir::Opcode::CmpEq, event_kind.value(), kind_const.value(), {span.line, span.col});
            if (!cmp) return frontend_error(FrontendError::OutOfMemory, span);
            return cmp.value();
        }
        return frontend_error(FrontendError::UnsupportedSyntax, span, value.str_value);
    }
    if (value.kind == MirValueKind::Nil) {
        auto v = b.emit_const_i32(0, {span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::Error) {
        auto v = b.emit_const_i32(static_cast<i32>(value.int_value), {span.line, span.col});
        if (!v) return frontend_error(FrontendError::OutOfMemory, span);
        return v.value();
    }
    if (value.kind == MirValueKind::Field) {
        auto lhs = materialize_value(*value.lhs,
                                     mir,
                                     variant_infos,
                                     tuple_infos,
                                     tuple_info_count,
                                     error_scalar_infos,
                                     error_variant_infos,
                                     error_struct_infos,
                                     user_struct_defs,
                                     b,
                                     locals,
                                     local_count,
                                     span);
        if (!lhs) return core::make_unexpected(lhs.error());
        const auto lhs_shape = resolved_shape(mir, *value.lhs);
        auto& err_info = error_info_for(lhs_shape,
                                        value.lhs->error_struct_index,
                                        error_scalar_infos,
                                        error_variant_infos,
                                        error_struct_infos);
        if (value.lhs->may_error && (value.str_value.eq(error_code_field_name()) ||
                                     value.str_value.eq(error_msg_field_name()) ||
                                     value.str_value.eq(error_file_field_name()) ||
                                     value.str_value.eq(error_func_field_name()) ||
                                     value.str_value.eq(error_line_field_name()))) {
            auto err = b.emit_struct_field(
                lhs.value(), error_field_name(), err_info.error_opt_type, {span.line, span.col});
            if (!err) return frontend_error(FrontendError::OutOfMemory, span);
            auto err_value =
                b.emit_opt_unwrap(err.value(), err_info.error_type, {span.line, span.col});
            if (!err_value) return frontend_error(FrontendError::OutOfMemory, span);
            const auto field_shape = resolved_shape(mir, value);
            auto field_type = rir_type_for_flat_shape(field_shape,
                                                      variant_infos,
                                                      tuple_infos,
                                                      tuple_info_count,
                                                      user_struct_defs,
                                                      b,
                                                      span);
            if (!field_type) return core::make_unexpected(field_type.error());
            auto field = b.emit_struct_field(
                err_value.value(), value.str_value, field_type.value(), {span.line, span.col});
            if (!field) return frontend_error(FrontendError::OutOfMemory, span);
            return field.value();
        }
        if (lhs_shape.type == MirTypeKind::Struct && lhs_shape.struct_index < mir.structs.len) {
            const auto& st = mir.structs[lhs_shape.struct_index];
            u32 field_index = st.fields.len;
            for (u32 i = 0; i < st.fields.len; i++) {
                if (st.fields[i].name.eq(value.str_value)) {
                    field_index = i;
                    break;
                }
            }
            if (field_index == st.fields.len)
                return frontend_error(FrontendError::UnsupportedSyntax, span, value.str_value);
            const auto& field = st.fields[field_index];
            const auto field_shape = resolved_shape(mir, field);
            const rir::Type* field_type = nullptr;
            if (field.is_error_type)
                field_type = err_info.error_type;
            else {
                auto ty = rir_type_for_flat_shape(field_shape,
                                                  variant_infos,
                                                  tuple_infos,
                                                  tuple_info_count,
                                                  user_struct_defs,
                                                  b,
                                                  span);
                if (!ty) return core::make_unexpected(ty.error());
                field_type = ty.value();
            }
            auto field_v = b.emit_struct_field(
                lhs.value(), value.str_value, field_type, {span.line, span.col});
            if (!field_v) return frontend_error(FrontendError::OutOfMemory, span);
            return field_v.value();
        }
        return frontend_error(FrontendError::UnsupportedSyntax, span, value.str_value);
    }
    if (value.kind == MirValueKind::Or) {
        auto lhs = materialize_value(*value.lhs,
                                     mir,
                                     variant_infos,
                                     tuple_infos,
                                     tuple_info_count,
                                     error_scalar_infos,
                                     error_variant_infos,
                                     error_struct_infos,
                                     user_struct_defs,
                                     b,
                                     locals,
                                     local_count,
                                     span);
        if (!lhs) return core::make_unexpected(lhs.error());
        auto rhs = materialize_value(*value.rhs,
                                     mir,
                                     variant_infos,
                                     tuple_infos,
                                     tuple_info_count,
                                     error_scalar_infos,
                                     error_variant_infos,
                                     error_struct_infos,
                                     user_struct_defs,
                                     b,
                                     locals,
                                     local_count,
                                     span);
        if (!rhs) return core::make_unexpected(rhs.error());
        if (value.lhs->kind == MirValueKind::Nil || value.lhs->kind == MirValueKind::Error)
            return rhs.value();
        if (!value.lhs->may_error && !value.lhs->may_nil) {
            // Never-missing lhs: the select is decided at compile time. The
            // analyze fold keeps this shape only when the fallback contains
            // a presence test that must still evaluate (it consumes its
            // carrier's runtime error) — rhs is already materialized above,
            // so just yield the lhs.
            return lhs.value();
        }
        const auto value_shape = resolved_shape(mir, value);
        auto inner = make_inner_type(value_shape);
        if (!inner) return core::make_unexpected(inner.error());
        if (value.lhs->may_error) {
            auto& err_info = error_info_for(value_shape,
                                            value.error_struct_index,
                                            error_scalar_infos,
                                            error_variant_infos,
                                            error_struct_infos);
            auto err = b.emit_struct_field(
                lhs.value(), error_field_name(), err_info.error_opt_type, {span.line, span.col});
            if (!err) return frontend_error(FrontendError::OutOfMemory, span);
            auto err_is_nil = b.emit_opt_is_nil(err.value(), {span.line, span.col});
            if (!err_is_nil) return frontend_error(FrontendError::OutOfMemory, span);
            auto false_v = b.emit_const_bool(false, {span.line, span.col});
            if (!false_v) return frontend_error(FrontendError::OutOfMemory, span);
            auto error_missing = b.emit_cmp(
                rir::Opcode::CmpEq, err_is_nil.value(), false_v.value(), {span.line, span.col});
            if (!error_missing) return frontend_error(FrontendError::OutOfMemory, span);
            auto payload = b.emit_struct_field(lhs.value(),
                                               error_payload_field_name(),
                                               err_info.payload_opt_type,
                                               {span.line, span.col});
            if (!payload) return frontend_error(FrontendError::OutOfMemory, span);
            auto payload_nil = b.emit_opt_is_nil(payload.value(), {span.line, span.col});
            if (!payload_nil) return frontend_error(FrontendError::OutOfMemory, span);
            auto missing = b.emit_select(error_missing.value(),
                                         error_missing.value(),
                                         payload_nil.value(),
                                         {span.line, span.col});
            if (!missing) return frontend_error(FrontendError::OutOfMemory, span);
            auto unwrapped =
                b.emit_opt_unwrap(payload.value(), inner.value(), {span.line, span.col});
            if (!unwrapped) return frontend_error(FrontendError::OutOfMemory, span);
            auto selected = b.emit_select(
                missing.value(), rhs.value(), unwrapped.value(), {span.line, span.col});
            if (!selected) return frontend_error(FrontendError::OutOfMemory, span);
            return selected.value();
        }
        auto is_nil = b.emit_opt_is_nil(lhs.value(), {span.line, span.col});
        if (!is_nil) return frontend_error(FrontendError::OutOfMemory, span);
        auto unwrapped = b.emit_opt_unwrap(lhs.value(), inner.value(), {span.line, span.col});
        if (!unwrapped) return frontend_error(FrontendError::OutOfMemory, span);
        auto selected =
            b.emit_select(is_nil.value(), rhs.value(), unwrapped.value(), {span.line, span.col});
        if (!selected) return frontend_error(FrontendError::OutOfMemory, span);
        return selected.value();
    }
    if (value.kind == MirValueKind::IfElse) {
        auto cond = materialize_value(*value.lhs,
                                      mir,
                                      variant_infos,
                                      tuple_infos,
                                      tuple_info_count,
                                      error_scalar_infos,
                                      error_variant_infos,
                                      error_struct_infos,
                                      user_struct_defs,
                                      b,
                                      locals,
                                      local_count,
                                      span);
        if (!cond) return core::make_unexpected(cond.error());
        auto then_v = materialize_value(*value.rhs,
                                        mir,
                                        variant_infos,
                                        tuple_infos,
                                        tuple_info_count,
                                        error_scalar_infos,
                                        error_variant_infos,
                                        error_struct_infos,
                                        user_struct_defs,
                                        b,
                                        locals,
                                        local_count,
                                        span);
        if (!then_v) return core::make_unexpected(then_v.error());
        auto else_v = materialize_value(*value.args[0],
                                        mir,
                                        variant_infos,
                                        tuple_infos,
                                        tuple_info_count,
                                        error_scalar_infos,
                                        error_variant_infos,
                                        error_struct_infos,
                                        user_struct_defs,
                                        b,
                                        locals,
                                        local_count,
                                        span);
        if (!else_v) return core::make_unexpected(else_v.error());
        const auto value_shape = resolved_shape(mir, value);
        if (value.may_error) {
            auto& err_info = error_info_for(value_shape,
                                            value.error_struct_index,
                                            error_scalar_infos,
                                            error_variant_infos,
                                            error_struct_infos);
            const bool eager_missing_fallback =
                value.lhs != nullptr && !value.is_pipe_conditional &&
                (value.lhs->kind == MirValueKind::HasValue ||
                 (value.is_eager_fallback && value.lhs->kind == MirValueKind::BoolConst &&
                  value.lhs->bool_value));
            auto wrap_error_branch = [&](const MirValue& branch,
                                         rir::ValueId branch_id) -> FrontendResult<rir::ValueId> {
                if (branch.may_error) {
                    if (branch.kind != MirValueKind::Error) return branch_id;
                    const i32 tag_value = branch.error_variant_index != 0xffffffffu
                                              ? static_cast<i32>(branch.error_case_index)
                                              : static_cast<i32>(branch.int_value);
                    auto code = b.emit_const_i32(tag_value, {span.line, span.col});
                    if (!code) return frontend_error(FrontendError::OutOfMemory, span);
                    auto msg = b.emit_const_str(branch.msg, {span.line, span.col});
                    if (!msg) return frontend_error(FrontendError::OutOfMemory, span);
                    auto file = b.emit_const_str(Str{}, {span.line, span.col});
                    if (!file) return frontend_error(FrontendError::OutOfMemory, span);
                    auto func = b.emit_const_str(Str{}, {span.line, span.col});
                    if (!func) return frontend_error(FrontendError::OutOfMemory, span);
                    auto line =
                        b.emit_const_i32(static_cast<i32>(span.line), {span.line, span.col});
                    if (!line) return frontend_error(FrontendError::OutOfMemory, span);
                    rir::ValueId error_fields[] = {
                        code.value(), msg.value(), file.value(), func.value(), line.value()};
                    auto error_val = b.emit_struct_create(
                        const_cast<rir::StructDef*>(err_info.error_type->struct_def),
                        error_fields,
                        5,
                        {span.line, span.col});
                    if (!error_val) return frontend_error(FrontendError::OutOfMemory, span);
                    auto wrapped_err = b.emit_opt_wrap(error_val.value(), {span.line, span.col});
                    if (!wrapped_err) return frontend_error(FrontendError::OutOfMemory, span);
                    auto nil_payload =
                        b.emit_opt_nil(err_info.payload_inner_type, {span.line, span.col});
                    if (!nil_payload) return frontend_error(FrontendError::OutOfMemory, span);
                    rir::ValueId fields[] = {wrapped_err.value(), nil_payload.value()};
                    auto created =
                        b.emit_struct_create(err_info.struct_def, fields, 2, {span.line, span.col});
                    if (!created) return frontend_error(FrontendError::OutOfMemory, span);
                    return created.value();
                }
                rir::ValueId err{};
                auto nil_err = b.emit_opt_nil(err_info.error_type, {span.line, span.col});
                if (!nil_err) return frontend_error(FrontendError::OutOfMemory, span);
                err = nil_err.value();
                rir::ValueId payload{};
                if (branch.may_nil) {
                    if (branch.kind == MirValueKind::Nil) {
                        auto nil_payload =
                            b.emit_opt_nil(err_info.payload_inner_type, {span.line, span.col});
                        if (!nil_payload) return frontend_error(FrontendError::OutOfMemory, span);
                        payload = nil_payload.value();
                    } else {
                        payload = branch_id;
                    }
                } else {
                    auto wrapped = b.emit_opt_wrap(branch_id, {span.line, span.col});
                    if (!wrapped) return frontend_error(FrontendError::OutOfMemory, span);
                    payload = wrapped.value();
                }
                rir::ValueId fields[] = {err, payload};
                auto created =
                    b.emit_struct_create(err_info.struct_def, fields, 2, {span.line, span.col});
                if (!created) return frontend_error(FrontendError::OutOfMemory, span);
                return created.value();
            };
            auto then_wrapped = wrap_error_branch(*value.rhs, then_v.value());
            if (!then_wrapped) return core::make_unexpected(then_wrapped.error());
            auto else_wrapped = wrap_error_branch(*value.args[0], else_v.value());
            if (!else_wrapped) return core::make_unexpected(else_wrapped.error());
            auto selected = b.emit_select(
                cond.value(), then_wrapped.value(), else_wrapped.value(), {span.line, span.col});
            if (!selected) return frontend_error(FrontendError::OutOfMemory, span);
            if (!eager_missing_fallback) return selected.value();
            auto branch_has_error = [&](rir::ValueId branch_id) -> FrontendResult<rir::ValueId> {
                auto err = b.emit_struct_field(
                    branch_id, error_field_name(), err_info.error_opt_type, {span.line, span.col});
                if (!err) return frontend_error(FrontendError::OutOfMemory, span);
                auto err_is_nil = b.emit_opt_is_nil(err.value(), {span.line, span.col});
                if (!err_is_nil) return frontend_error(FrontendError::OutOfMemory, span);
                auto false_v = b.emit_const_bool(false, {span.line, span.col});
                if (!false_v) return frontend_error(FrontendError::OutOfMemory, span);
                auto has_error = b.emit_cmp(
                    rir::Opcode::CmpEq, err_is_nil.value(), false_v.value(), {span.line, span.col});
                if (!has_error) return frontend_error(FrontendError::OutOfMemory, span);
                return has_error.value();
            };
            auto then_has_error = branch_has_error(then_wrapped.value());
            if (!then_has_error) return core::make_unexpected(then_has_error.error());
            auto else_has_error = branch_has_error(else_wrapped.value());
            if (!else_has_error) return core::make_unexpected(else_has_error.error());
            auto selected_or_else_error = b.emit_select(else_has_error.value(),
                                                        else_wrapped.value(),
                                                        selected.value(),
                                                        {span.line, span.col});
            if (!selected_or_else_error) return frontend_error(FrontendError::OutOfMemory, span);
            auto selected_or_error = b.emit_select(then_has_error.value(),
                                                   then_wrapped.value(),
                                                   selected_or_else_error.value(),
                                                   {span.line, span.col});
            if (!selected_or_error) return frontend_error(FrontendError::OutOfMemory, span);
            return selected_or_error.value();
        }
        if (value.may_nil) {
            auto inner = make_inner_type(value_shape);
            if (!inner) return core::make_unexpected(inner.error());
            auto wrap_optional_branch =
                [&](const MirValue& branch,
                    rir::ValueId branch_id) -> FrontendResult<rir::ValueId> {
                if (branch.may_nil) {
                    if (branch.kind == MirValueKind::Nil) {
                        auto nil = b.emit_opt_nil(inner.value(), {span.line, span.col});
                        if (!nil) return frontend_error(FrontendError::OutOfMemory, span);
                        return nil.value();
                    }
                    return branch_id;
                }
                auto wrapped = b.emit_opt_wrap(branch_id, {span.line, span.col});
                if (!wrapped) return frontend_error(FrontendError::OutOfMemory, span);
                return wrapped.value();
            };
            auto then_wrapped = wrap_optional_branch(*value.rhs, then_v.value());
            if (!then_wrapped) return core::make_unexpected(then_wrapped.error());
            auto else_wrapped = wrap_optional_branch(*value.args[0], else_v.value());
            if (!else_wrapped) return core::make_unexpected(else_wrapped.error());
            auto selected = b.emit_select(
                cond.value(), then_wrapped.value(), else_wrapped.value(), {span.line, span.col});
            if (!selected) return frontend_error(FrontendError::OutOfMemory, span);
            return selected.value();
        }
        auto selected =
            b.emit_select(cond.value(), then_v.value(), else_v.value(), {span.line, span.col});
        if (!selected) return frontend_error(FrontendError::OutOfMemory, span);
        return selected.value();
    }
    if (value.kind == MirValueKind::NoError) {
        auto lhs = materialize_value(*value.lhs,
                                     mir,
                                     variant_infos,
                                     tuple_infos,
                                     tuple_info_count,
                                     error_scalar_infos,
                                     error_variant_infos,
                                     error_struct_infos,
                                     user_struct_defs,
                                     b,
                                     locals,
                                     local_count,
                                     span);
        if (!lhs) return core::make_unexpected(lhs.error());
        const auto lhs_shape = resolved_shape(mir, *value.lhs);
        auto& err_info = error_info_for(lhs_shape,
                                        value.lhs->error_struct_index,
                                        error_scalar_infos,
                                        error_variant_infos,
                                        error_struct_infos);
        auto err = b.emit_struct_field(
            lhs.value(), error_field_name(), err_info.error_opt_type, {span.line, span.col});
        if (!err) return frontend_error(FrontendError::OutOfMemory, span);
        auto is_nil = b.emit_opt_is_nil(err.value(), {span.line, span.col});
        if (!is_nil) return frontend_error(FrontendError::OutOfMemory, span);
        return is_nil.value();
    }
    if (value.kind == MirValueKind::HasValue) {
        auto lhs = materialize_value(*value.lhs,
                                     mir,
                                     variant_infos,
                                     tuple_infos,
                                     tuple_info_count,
                                     error_scalar_infos,
                                     error_variant_infos,
                                     error_struct_infos,
                                     user_struct_defs,
                                     b,
                                     locals,
                                     local_count,
                                     span);
        if (!lhs) return core::make_unexpected(lhs.error());
        if (value.lhs->may_error) {
            const auto lhs_shape = resolved_shape(mir, *value.lhs);
            auto& err_info = error_info_for(lhs_shape,
                                            value.lhs->error_struct_index,
                                            error_scalar_infos,
                                            error_variant_infos,
                                            error_struct_infos);
            auto err = b.emit_struct_field(
                lhs.value(), error_field_name(), err_info.error_opt_type, {span.line, span.col});
            if (!err) return frontend_error(FrontendError::OutOfMemory, span);
            auto err_is_nil = b.emit_opt_is_nil(err.value(), {span.line, span.col});
            if (!err_is_nil) return frontend_error(FrontendError::OutOfMemory, span);
            if (!value.lhs->may_nil) return err_is_nil.value();
            auto payload = b.emit_struct_field(lhs.value(),
                                               error_payload_field_name(),
                                               err_info.payload_opt_type,
                                               {span.line, span.col});
            if (!payload) return frontend_error(FrontendError::OutOfMemory, span);
            auto payload_is_nil = b.emit_opt_is_nil(payload.value(), {span.line, span.col});
            if (!payload_is_nil) return frontend_error(FrontendError::OutOfMemory, span);
            auto false_v = b.emit_const_bool(false, {span.line, span.col});
            if (!false_v) return frontend_error(FrontendError::OutOfMemory, span);
            auto has_payload = b.emit_cmp(
                rir::Opcode::CmpEq, payload_is_nil.value(), false_v.value(), {span.line, span.col});
            if (!has_payload) return frontend_error(FrontendError::OutOfMemory, span);
            auto has_value = b.emit_select(
                err_is_nil.value(), has_payload.value(), false_v.value(), {span.line, span.col});
            if (!has_value) return frontend_error(FrontendError::OutOfMemory, span);
            return has_value.value();
        }
        auto is_nil = b.emit_opt_is_nil(lhs.value(), {span.line, span.col});
        if (!is_nil) return frontend_error(FrontendError::OutOfMemory, span);
        auto false_v = b.emit_const_bool(false, {span.line, span.col});
        if (!false_v) return frontend_error(FrontendError::OutOfMemory, span);
        auto has_value =
            b.emit_cmp(rir::Opcode::CmpEq, is_nil.value(), false_v.value(), {span.line, span.col});
        if (!has_value) return frontend_error(FrontendError::OutOfMemory, span);
        return has_value.value();
    }
    if (value.kind == MirValueKind::ValueOf) {
        auto lhs = materialize_value(*value.lhs,
                                     mir,
                                     variant_infos,
                                     tuple_infos,
                                     tuple_info_count,
                                     error_scalar_infos,
                                     error_variant_infos,
                                     error_struct_infos,
                                     user_struct_defs,
                                     b,
                                     locals,
                                     local_count,
                                     span);
        if (!lhs) return core::make_unexpected(lhs.error());
        if (value.lhs->may_error) {
            const auto value_shape = resolved_shape(mir, value);
            auto& err_info = error_info_for(value_shape,
                                            value.error_struct_index,
                                            error_scalar_infos,
                                            error_variant_infos,
                                            error_struct_infos);
            auto payload = b.emit_struct_field(lhs.value(),
                                               error_payload_field_name(),
                                               err_info.payload_opt_type,
                                               {span.line, span.col});
            if (!payload) return frontend_error(FrontendError::OutOfMemory, span);
            auto inner = make_inner_type(resolved_shape(mir, value));
            if (!inner) return core::make_unexpected(inner.error());
            auto unwrapped =
                b.emit_opt_unwrap(payload.value(), inner.value(), {span.line, span.col});
            if (!unwrapped) return frontend_error(FrontendError::OutOfMemory, span);
            return unwrapped.value();
        }
        auto inner = make_inner_type(resolved_shape(mir, value));
        if (!inner) return core::make_unexpected(inner.error());
        auto unwrapped = b.emit_opt_unwrap(lhs.value(), inner.value(), {span.line, span.col});
        if (!unwrapped) return frontend_error(FrontendError::OutOfMemory, span);
        return unwrapped.value();
    }
    if (value.kind == MirValueKind::MissingOf) {
        auto lhs = materialize_value(*value.lhs,
                                     mir,
                                     variant_infos,
                                     tuple_infos,
                                     tuple_info_count,
                                     error_scalar_infos,
                                     error_variant_infos,
                                     error_struct_infos,
                                     user_struct_defs,
                                     b,
                                     locals,
                                     local_count,
                                     span);
        if (!lhs) return core::make_unexpected(lhs.error());
        auto inner = make_inner_type(resolved_shape(mir, value));
        if (!inner) return core::make_unexpected(inner.error());
        if (value.may_error) {
            const auto value_shape = resolved_shape(mir, value);
            auto& err_info = error_info_for(value_shape,
                                            value.error_struct_index,
                                            error_scalar_infos,
                                            error_variant_infos,
                                            error_struct_infos);
            rir::ValueId err{};
            if (value.lhs->may_error) {
                auto lhs_err = b.emit_struct_field(lhs.value(),
                                                   error_field_name(),
                                                   err_info.error_opt_type,
                                                   {span.line, span.col});
                if (!lhs_err) return frontend_error(FrontendError::OutOfMemory, span);
                err = lhs_err.value();
            } else {
                auto nil_err = b.emit_opt_nil(err_info.error_type, {span.line, span.col});
                if (!nil_err) return frontend_error(FrontendError::OutOfMemory, span);
                err = nil_err.value();
            }
            auto nil_payload = b.emit_opt_nil(inner.value(), {span.line, span.col});
            if (!nil_payload) return frontend_error(FrontendError::OutOfMemory, span);
            rir::ValueId fields[] = {err, nil_payload.value()};
            auto created =
                b.emit_struct_create(err_info.struct_def, fields, 2, {span.line, span.col});
            if (!created) return frontend_error(FrontendError::OutOfMemory, span);
            return created.value();
        }
        auto nil = b.emit_opt_nil(inner.value(), {span.line, span.col});
        if (!nil) return frontend_error(FrontendError::OutOfMemory, span);
        return nil.value();
    }
    if (value.kind == MirValueKind::MatchPayload) {
        auto subject = materialize_value(*value.lhs,
                                         mir,
                                         variant_infos,
                                         tuple_infos,
                                         tuple_info_count,
                                         error_scalar_infos,
                                         error_variant_infos,
                                         error_struct_infos,
                                         user_struct_defs,
                                         b,
                                         locals,
                                         local_count,
                                         span);
        if (!subject) return core::make_unexpected(subject.error());
        const auto subject_shape = resolved_shape(mir, *value.lhs);
        const u32 subject_variant_index = subject_shape.variant_index;
        if (subject_shape.type != MirTypeKind::Variant || subject_variant_index >= mir.variants.len)
            return frontend_error(FrontendError::UnsupportedSyntax, span);
        const auto& payload_case = mir.variants[subject_variant_index].cases[value.case_index];
        const auto payload_shape = resolved_shape(mir, payload_case);
        const auto payload_kind = payload_shape.type;
        const rir::Type* payload_opt_ty =
            payload_opt_type(variant_infos[subject_variant_index], payload_kind);
        const rir::Type* payload_inner_ty =
            payload_inner_type(variant_infos[subject_variant_index], payload_kind);
        if (payload_opt_ty == nullptr || payload_inner_ty == nullptr) {
            auto ty = rir_type_for_flat_shape(payload_shape,
                                              variant_infos,
                                              tuple_infos,
                                              tuple_info_count,
                                              user_struct_defs,
                                              b,
                                              span);
            if (!ty) return core::make_unexpected(ty.error());
            payload_inner_ty = ty.value();
            auto opt_ty = b.make_type(rir::TypeKind::Optional, payload_inner_ty);
            if (!opt_ty) return frontend_error(FrontendError::OutOfMemory, span);
            payload_opt_ty = opt_ty.value();
        }
        auto payload_opt = b.emit_struct_field(subject.value(),
                                               payload_field_name(payload_kind),
                                               payload_opt_ty,
                                               {span.line, span.col});
        if (!payload_opt) return frontend_error(FrontendError::OutOfMemory, span);
        auto unwrapped =
            b.emit_opt_unwrap(payload_opt.value(), payload_inner_ty, {span.line, span.col});
        if (!unwrapped) return frontend_error(FrontendError::OutOfMemory, span);
        return unwrapped.value();
    }
    if (value.kind == MirValueKind::VariantTag) {
        auto subject = materialize_value(*value.lhs,
                                         mir,
                                         variant_infos,
                                         tuple_infos,
                                         tuple_info_count,
                                         error_scalar_infos,
                                         error_variant_infos,
                                         error_struct_infos,
                                         user_struct_defs,
                                         b,
                                         locals,
                                         local_count,
                                         span);
        if (!subject) return core::make_unexpected(subject.error());
        const auto subject_shape = resolved_shape(mir, *value.lhs);
        if (subject_shape.type != MirTypeKind::Variant ||
            subject_shape.variant_index >= mir.variants.len)
            return frontend_error(FrontendError::UnsupportedSyntax, span);
        if (variant_infos[subject_shape.variant_index].struct_type == nullptr)
            return subject.value();
        auto i32_ty = b.make_type(rir::TypeKind::I32);
        if (!i32_ty) return frontend_error(FrontendError::OutOfMemory, span);
        auto tag =
            b.emit_struct_field(subject.value(), lit("tag"), i32_ty.value(), {span.line, span.col});
        if (!tag) return frontend_error(FrontendError::OutOfMemory, span);
        return tag.value();
    }
    if (value.kind == MirValueKind::BitAnd || value.kind == MirValueKind::BitOr ||
        value.kind == MirValueKind::BitXor || value.kind == MirValueKind::BitShl ||
        value.kind == MirValueKind::BitShr || value.kind == MirValueKind::Add ||
        value.kind == MirValueKind::Sub || value.kind == MirValueKind::Mul ||
        value.kind == MirValueKind::Div || value.kind == MirValueKind::Mod ||
        value.kind == MirValueKind::MaxInt || value.kind == MirValueKind::MinInt) {
        auto lhs = materialize_value(*value.lhs,
                                     mir,
                                     variant_infos,
                                     tuple_infos,
                                     tuple_info_count,
                                     error_scalar_infos,
                                     error_variant_infos,
                                     error_struct_infos,
                                     user_struct_defs,
                                     b,
                                     locals,
                                     local_count,
                                     span);
        if (!lhs) return core::make_unexpected(lhs.error());
        auto rhs = materialize_value(*value.rhs,
                                     mir,
                                     variant_infos,
                                     tuple_infos,
                                     tuple_info_count,
                                     error_scalar_infos,
                                     error_variant_infos,
                                     error_struct_infos,
                                     user_struct_defs,
                                     b,
                                     locals,
                                     local_count,
                                     span);
        if (!rhs) return core::make_unexpected(rhs.error());
        rir::Opcode op = rir::Opcode::BitAnd;
        if (value.kind == MirValueKind::BitOr)
            op = rir::Opcode::BitOr;
        else if (value.kind == MirValueKind::BitXor)
            op = rir::Opcode::BitXor;
        else if (value.kind == MirValueKind::BitShl)
            op = rir::Opcode::BitShl;
        else if (value.kind == MirValueKind::BitShr)
            op = rir::Opcode::BitShr;
        else if (value.kind == MirValueKind::Add)
            op = rir::Opcode::Add;
        else if (value.kind == MirValueKind::Sub)
            op = rir::Opcode::Sub;
        else if (value.kind == MirValueKind::Mul)
            op = rir::Opcode::Mul;
        else if (value.kind == MirValueKind::Div)
            op = rir::Opcode::Div;
        else if (value.kind == MirValueKind::Mod)
            op = rir::Opcode::Mod;
        else if (value.kind == MirValueKind::MaxInt)
            op = rir::Opcode::MaxInt;
        else if (value.kind == MirValueKind::MinInt)
            op = rir::Opcode::MinInt;
        auto out = rir::Builder::is_arith_opcode(op)
                       ? b.emit_arith(op, lhs.value(), rhs.value(), {span.line, span.col})
                       : b.emit_bit(op, lhs.value(), rhs.value(), {span.line, span.col});
        if (!out) return frontend_error(FrontendError::OutOfMemory, span);
        return out.value();
    }
    if (value.kind == MirValueKind::CacheGet || value.kind == MirValueKind::CacheSet) {
        auto key = materialize_value(*value.lhs,
                                     mir,
                                     variant_infos,
                                     tuple_infos,
                                     tuple_info_count,
                                     error_scalar_infos,
                                     error_variant_infos,
                                     error_struct_infos,
                                     user_struct_defs,
                                     b,
                                     locals,
                                     local_count,
                                     span);
        if (!key) return core::make_unexpected(key.error());
        if (value.kind == MirValueKind::CacheGet) {
            auto out = b.emit_cache_get(value.cache_index, key.value(), {span.line, span.col});
            if (!out) return frontend_error(FrontendError::OutOfMemory, span);
            return out.value();
        }
        auto val = materialize_value(*value.rhs,
                                     mir,
                                     variant_infos,
                                     tuple_infos,
                                     tuple_info_count,
                                     error_scalar_infos,
                                     error_variant_infos,
                                     error_struct_infos,
                                     user_struct_defs,
                                     b,
                                     locals,
                                     local_count,
                                     span);
        if (!val) return core::make_unexpected(val.error());
        auto out =
            b.emit_cache_set(value.cache_index, key.value(), val.value(), {span.line, span.col});
        if (!out) return frontend_error(FrontendError::OutOfMemory, span);
        return out.value();
    }
    if (value.kind == MirValueKind::ReqSetHeader || value.kind == MirValueKind::ReqAddHeader) {
        if (value.lhs == nullptr) return frontend_error(FrontendError::UnsupportedSyntax, span);
        auto val = materialize_value(*value.lhs,
                                     mir,
                                     variant_infos,
                                     tuple_infos,
                                     tuple_info_count,
                                     error_scalar_infos,
                                     error_variant_infos,
                                     error_struct_infos,
                                     user_struct_defs,
                                     b,
                                     locals,
                                     local_count,
                                     span);
        if (!val) return core::make_unexpected(val.error());
        const bool emitted = value.kind == MirValueKind::ReqAddHeader
                                 ? static_cast<bool>(b.emit_req_add_header(
                                       value.str_value, val.value(), {span.line, span.col}))
                                 : static_cast<bool>(b.emit_req_set_header(
                                       value.str_value, val.value(), {span.line, span.col}));
        if (!emitted) return frontend_error(FrontendError::OutOfMemory, span);
        return val.value();
    }
    if (value.kind == MirValueKind::RespHeader) {
        if (value.lhs == nullptr) return frontend_error(FrontendError::UnsupportedSyntax, span);
        auto str_ty_result = b.make_type(rir::TypeKind::Str);
        if (!str_ty_result) return frontend_error(FrontendError::OutOfMemory, span);
        auto* str_ty = str_ty_result.value();
        rir::ValueId fallback{};
        if (value.lhs->kind == MirValueKind::Nil) {
            auto nil = b.emit_opt_nil(str_ty, {span.line, span.col});
            if (!nil) return frontend_error(FrontendError::OutOfMemory, span);
            fallback = nil.value();
        } else {
            auto raw = materialize_value(*value.lhs,
                                         mir,
                                         variant_infos,
                                         tuple_infos,
                                         tuple_info_count,
                                         error_scalar_infos,
                                         error_variant_infos,
                                         error_struct_infos,
                                         user_struct_defs,
                                         b,
                                         locals,
                                         local_count,
                                         span);
            if (!raw) return core::make_unexpected(raw.error());
            auto wrapped = b.emit_opt_wrap(raw.value(), {span.line, span.col});
            if (!wrapped) return frontend_error(FrontendError::OutOfMemory, span);
            fallback = wrapped.value();
        }
        auto out = b.emit_resp_header(value.str_value, fallback, {span.line, span.col});
        if (!out) return frontend_error(FrontendError::OutOfMemory, span);
        return out.value();
    }
    if (value.kind == MirValueKind::RespSetHeader || value.kind == MirValueKind::RespAddHeader) {
        if (value.lhs == nullptr) return frontend_error(FrontendError::UnsupportedSyntax, span);
        auto val = materialize_value(*value.lhs,
                                     mir,
                                     variant_infos,
                                     tuple_infos,
                                     tuple_info_count,
                                     error_scalar_infos,
                                     error_variant_infos,
                                     error_struct_infos,
                                     user_struct_defs,
                                     b,
                                     locals,
                                     local_count,
                                     span);
        if (!val) return core::make_unexpected(val.error());
        const bool emitted = value.kind == MirValueKind::RespAddHeader
                                 ? static_cast<bool>(b.emit_resp_add_header(
                                       value.str_value, val.value(), {span.line, span.col}))
                                 : static_cast<bool>(b.emit_resp_set_header(
                                       value.str_value, val.value(), {span.line, span.col}));
        if (!emitted) return frontend_error(FrontendError::OutOfMemory, span);
        return val.value();
    }
    if (value.kind == MirValueKind::RespRemoveHeader) {
        if (!b.emit_resp_remove_header(value.str_value, {span.line, span.col}))
            return frontend_error(FrontendError::OutOfMemory, span);
        auto zero = b.emit_const_str({"", 0}, {span.line, span.col});
        if (!zero) return frontend_error(FrontendError::OutOfMemory, span);
        return zero.value();
    }
    if (value.kind == MirValueKind::WidenI64) {
        auto operand = materialize_value(*value.lhs,
                                         mir,
                                         variant_infos,
                                         tuple_infos,
                                         tuple_info_count,
                                         error_scalar_infos,
                                         error_variant_infos,
                                         error_struct_infos,
                                         user_struct_defs,
                                         b,
                                         locals,
                                         local_count,
                                         span);
        if (!operand) return core::make_unexpected(operand.error());
        auto out = b.emit_sext_i64(operand.value(), {span.line, span.col});
        if (!out) return frontend_error(FrontendError::OutOfMemory, span);
        return out.value();
    }
    if (value.kind == MirValueKind::Eq || value.kind == MirValueKind::Lt ||
        value.kind == MirValueKind::Gt) {
        const MirValue& lhs_expr = *value.lhs;
        const auto lhs_shape = resolved_shape(mir, lhs_expr);
        auto lhs = materialize_value(*value.lhs,
                                     mir,
                                     variant_infos,
                                     tuple_infos,
                                     tuple_info_count,
                                     error_scalar_infos,
                                     error_variant_infos,
                                     error_struct_infos,
                                     user_struct_defs,
                                     b,
                                     locals,
                                     local_count,
                                     span);
        if (!lhs) return core::make_unexpected(lhs.error());
        auto rhs = materialize_value(*value.rhs,
                                     mir,
                                     variant_infos,
                                     tuple_infos,
                                     tuple_info_count,
                                     error_scalar_infos,
                                     error_variant_infos,
                                     error_struct_infos,
                                     user_struct_defs,
                                     b,
                                     locals,
                                     local_count,
                                     span);
        if (!rhs) return core::make_unexpected(rhs.error());
        if (value.kind == MirValueKind::Eq)
            return emit_eq_for_flat_shape(lhs_shape,
                                          lhs.value(),
                                          rhs.value(),
                                          mir,
                                          variant_infos,
                                          tuple_infos,
                                          tuple_info_count,
                                          error_scalar_infos,
                                          error_variant_infos,
                                          error_struct_infos,
                                          user_struct_defs,
                                          b,
                                          span);
        return emit_ord_for_flat_shape(lhs_shape,
                                       lhs.value(),
                                       rhs.value(),
                                       mir,
                                       variant_infos,
                                       tuple_infos,
                                       tuple_info_count,
                                       error_scalar_infos,
                                       error_variant_infos,
                                       error_struct_infos,
                                       user_struct_defs,
                                       b,
                                       span,
                                       value.kind == MirValueKind::Lt);
    }
    if (value.local_index >= local_count)
        return frontend_error(FrontendError::UnsupportedSyntax, span);
    return locals[value.local_index];
}

static FrontendResult<rir::ValueId> materialize_local_init(
    const MirLocal& local,
    const MirModule& mir,
    const VariantLoweringInfo* variant_infos,
    TupleLoweringInfo* tuple_infos,
    u32* tuple_info_count,
    ErrorLoweringInfo* error_scalar_infos,
    ErrorLoweringInfo* error_variant_infos,
    ErrorLoweringInfo* error_struct_infos,
    const rir::StructDef* error_struct_def,
    const rir::StructDef* const* user_struct_defs,
    rir::Builder& b,
    const rir::ValueId* locals,
    u32 local_count,
    Str func_name,
    Str source_name) {
    const auto local_shape = resolved_shape(mir, local);
    auto make_inner_type = [&](const FlatMirShape& shape,
                               Span span) -> FrontendResult<const rir::Type*> {
        if (shape.type == MirTypeKind::Variant) {
            if (shape.variant_index < mir.variants.len &&
                variant_infos[shape.variant_index].struct_type)
                return variant_infos[shape.variant_index].struct_type;
            auto inner = b.make_type(rir::TypeKind::I32);
            if (!inner) return frontend_error(FrontendError::OutOfMemory, span);
            return inner.value();
        }
        if (shape.type == MirTypeKind::Struct) {
            if (shape.struct_index >= mir.structs.len ||
                user_struct_defs[shape.struct_index] == nullptr)
                return frontend_error(FrontendError::UnsupportedSyntax, span);
            auto inner =
                b.make_type(rir::TypeKind::Struct,
                            nullptr,
                            const_cast<rir::StructDef*>(user_struct_defs[shape.struct_index]));
            if (!inner) return frontend_error(FrontendError::OutOfMemory, span);
            return inner.value();
        }
        const rir::TypeKind inner_kind = shape.type == MirTypeKind::Bool  ? rir::TypeKind::Bool
                                         : shape.type == MirTypeKind::Str ? rir::TypeKind::Str
                                         : shape.type == MirTypeKind::I64 ? rir::TypeKind::I64
                                                                          : rir::TypeKind::I32;
        auto inner = b.make_type(inner_kind);
        if (!inner) return frontend_error(FrontendError::OutOfMemory, span);
        return inner.value();
    };

    if (local.may_error) {
        // I64 is deliberately NOT admitted here: the __error_unknown scalar
        // carrier's payload field is Optional<i32>, so a fallible i64 local
        // would fail deep in emit_struct_create. Analysis rejects every
        // fallible-i64 producer (kI64FallibleDetail); this is the
        // defense-in-depth backstop — when an i64 error carrier exists, add
        // I64 back alongside it. (may_nil I64 IS supported — the Optional
        // carrier is width-generic.)
        if (local_shape.type != MirTypeKind::Bool && local_shape.type != MirTypeKind::I32 &&
            local_shape.type != MirTypeKind::Str && local_shape.type != MirTypeKind::Variant &&
            local_shape.type != MirTypeKind::Struct && local_shape.type != MirTypeKind::Unknown)
            return frontend_error(FrontendError::UnsupportedSyntax, local.span);
        auto inner = make_inner_type(local_shape, local.span);
        if (!inner) return core::make_unexpected(inner.error());
        auto payload_opt = b.make_type(rir::TypeKind::Optional, inner.value());
        if (!payload_opt) return frontend_error(FrontendError::OutOfMemory, local.span);
        auto& err_info = error_info_for(local_shape,
                                        local.error_struct_index,
                                        error_scalar_infos,
                                        error_variant_infos,
                                        error_struct_infos);

        if (local.init.may_error && local.init.kind != MirValueKind::Error) {
            auto init = materialize_value(local.init,
                                          mir,
                                          variant_infos,
                                          tuple_infos,
                                          tuple_info_count,
                                          error_scalar_infos,
                                          error_variant_infos,
                                          error_struct_infos,
                                          user_struct_defs,
                                          b,
                                          locals,
                                          local_count,
                                          local.span);
            if (!init) return core::make_unexpected(init.error());
            return init.value();
        }

        rir::ValueId err{};
        rir::ValueId payload{};
        if (local.init.kind == MirValueKind::Error) {
            const i32 tag_value = local.init.error_variant_index != 0xffffffffu
                                      ? static_cast<i32>(local.init.error_case_index)
                                      : static_cast<i32>(local.init.int_value);
            auto code = b.emit_const_i32(tag_value, {local.span.line, local.span.col});
            if (!code) return frontend_error(FrontendError::OutOfMemory, local.span);
            auto msg = b.emit_const_str(local.init.msg, {local.span.line, local.span.col});
            if (!msg) return frontend_error(FrontendError::OutOfMemory, local.span);
            auto file = b.emit_const_str(source_name, {local.span.line, local.span.col});
            if (!file) return frontend_error(FrontendError::OutOfMemory, local.span);
            auto func = b.emit_const_str(func_name, {local.span.line, local.span.col});
            if (!func) return frontend_error(FrontendError::OutOfMemory, local.span);
            auto line = b.emit_const_i32(static_cast<i32>(local.span.line),
                                         {local.span.line, local.span.col});
            if (!line) return frontend_error(FrontendError::OutOfMemory, local.span);
            rir::ValueId error_fields[] = {
                code.value(), msg.value(), file.value(), func.value(), line.value()};
            auto error_val = b.emit_struct_create(const_cast<rir::StructDef*>(error_struct_def),
                                                  error_fields,
                                                  5,
                                                  {local.span.line, local.span.col});
            if (!error_val) return frontend_error(FrontendError::OutOfMemory, local.span);
            rir::ValueId err_value = error_val.value();
            if (local.init.error_struct_index != 0xffffffffu) {
                if (local.init.error_struct_index >= mir.structs.len)
                    return frontend_error(FrontendError::UnsupportedSyntax, local.span);
                auto* custom_struct_def =
                    const_cast<rir::StructDef*>(user_struct_defs[local.init.error_struct_index]);
                if (!custom_struct_def)
                    return frontend_error(FrontendError::UnsupportedSyntax, local.span);
                rir::ValueId custom_fields[MirStruct::kMaxFields]{};
                for (u32 fi = 0; fi < mir.structs[local.init.error_struct_index].fields.len; fi++) {
                    const auto& field = mir.structs[local.init.error_struct_index].fields[fi];
                    if (field.name.eq({"err", 3}) && field.is_error_type) {
                        custom_fields[fi] = error_val.value();
                        continue;
                    }
                    u32 init_index = local.init.field_inits.len;
                    for (u32 ii = 0; ii < local.init.field_inits.len; ii++) {
                        if (local.init.field_inits[ii].name.eq(field.name)) {
                            init_index = ii;
                            break;
                        }
                    }
                    if (init_index == local.init.field_inits.len)
                        return frontend_error(
                            FrontendError::UnsupportedSyntax, local.span, field.name);
                    auto field_value = materialize_value(*local.init.field_inits[init_index].value,
                                                         mir,
                                                         variant_infos,
                                                         tuple_infos,
                                                         tuple_info_count,
                                                         error_scalar_infos,
                                                         error_variant_infos,
                                                         error_struct_infos,
                                                         user_struct_defs,
                                                         b,
                                                         locals,
                                                         local_count,
                                                         local.span);
                    if (!field_value) return core::make_unexpected(field_value.error());
                    custom_fields[fi] = field_value.value();
                }
                auto custom_error =
                    b.emit_struct_create(custom_struct_def,
                                         custom_fields,
                                         mir.structs[local.init.error_struct_index].fields.len,
                                         {local.span.line, local.span.col});
                if (!custom_error) return frontend_error(FrontendError::OutOfMemory, local.span);
                auto extracted_err = b.emit_struct_field(custom_error.value(),
                                                         error_field_name(),
                                                         err_info.error_type,
                                                         {local.span.line, local.span.col});
                if (!extracted_err) return frontend_error(FrontendError::OutOfMemory, local.span);
                err_value = extracted_err.value();
            }
            auto wrapped_err = b.emit_opt_wrap(err_value, {local.span.line, local.span.col});
            if (!wrapped_err) return frontend_error(FrontendError::OutOfMemory, local.span);
            err = wrapped_err.value();
            if (payload.id == 0) {
                auto nil_payload =
                    b.emit_opt_nil(err_info.payload_inner_type, {local.span.line, local.span.col});
                if (!nil_payload) return frontend_error(FrontendError::OutOfMemory, local.span);
                payload = nil_payload.value();
            }
        } else {
            auto nil_err = b.emit_opt_nil(err_info.error_type, {local.span.line, local.span.col});
            if (!nil_err) return frontend_error(FrontendError::OutOfMemory, local.span);
            err = nil_err.value();
            if (local.init.kind == MirValueKind::Nil) {
                auto nil_payload = b.emit_opt_nil(inner.value(), {local.span.line, local.span.col});
                if (!nil_payload) return frontend_error(FrontendError::OutOfMemory, local.span);
                payload = nil_payload.value();
            } else {
                auto init = materialize_value(local.init,
                                              mir,
                                              variant_infos,
                                              tuple_infos,
                                              tuple_info_count,
                                              error_scalar_infos,
                                              error_variant_infos,
                                              error_struct_infos,
                                              user_struct_defs,
                                              b,
                                              locals,
                                              local_count,
                                              local.span);
                if (!init) return core::make_unexpected(init.error());
                if (local.init.may_nil) {
                    payload = init.value();
                } else {
                    auto wrapped = b.emit_opt_wrap(init.value(), {local.span.line, local.span.col});
                    if (!wrapped) return frontend_error(FrontendError::OutOfMemory, local.span);
                    payload = wrapped.value();
                }
            }
        }

        rir::ValueId fields[] = {err, payload};
        auto created =
            b.emit_struct_create(err_info.struct_def, fields, 2, {local.span.line, local.span.col});
        if (!created) return frontend_error(FrontendError::OutOfMemory, local.span);
        return created.value();
    }
    if (!local.may_nil)
        return materialize_value(local.init,
                                 mir,
                                 variant_infos,
                                 tuple_infos,
                                 tuple_info_count,
                                 error_scalar_infos,
                                 error_variant_infos,
                                 error_struct_infos,
                                 user_struct_defs,
                                 b,
                                 locals,
                                 local_count,
                                 local.span);

    if (local_shape.type != MirTypeKind::Bool && local_shape.type != MirTypeKind::I32 &&
        local_shape.type != MirTypeKind::I64 && local_shape.type != MirTypeKind::Str &&
        local_shape.type != MirTypeKind::Variant && local_shape.type != MirTypeKind::Struct)
        return frontend_error(FrontendError::UnsupportedSyntax, local.span);

    auto inner = make_inner_type(local_shape, local.span);
    if (!inner) return core::make_unexpected(inner.error());
    if (local.init.kind == MirValueKind::Nil) {
        auto nil = b.emit_opt_nil(inner.value(), {local.span.line, local.span.col});
        if (!nil) return frontend_error(FrontendError::OutOfMemory, local.span);
        return nil.value();
    }

    auto init = materialize_value(local.init,
                                  mir,
                                  variant_infos,
                                  tuple_infos,
                                  tuple_info_count,
                                  error_scalar_infos,
                                  error_variant_infos,
                                  error_struct_infos,
                                  user_struct_defs,
                                  b,
                                  locals,
                                  local_count,
                                  local.span);
    if (!init) return core::make_unexpected(init.error());
    if (local.init.may_nil) return init.value();

    auto wrapped = b.emit_opt_wrap(init.value(), {local.span.line, local.span.col});
    if (!wrapped) return frontend_error(FrontendError::OutOfMemory, local.span);
    return wrapped.value();
}

static FrontendResult<void> emit_term(const MirTerminator& term,
                                      const MirModule& mir,
                                      const VariantLoweringInfo* variant_infos,
                                      TupleLoweringInfo* tuple_infos,
                                      u32* tuple_info_count,
                                      ErrorLoweringInfo* error_scalar_infos,
                                      ErrorLoweringInfo* error_variant_infos,
                                      ErrorLoweringInfo* error_struct_infos,
                                      const rir::StructDef* const* user_struct_defs,
                                      rir::Builder& b,
                                      rir::Function* fn,
                                      const rir::BlockId* block_ids,
                                      const rir::ValueId* locals,
                                      u32 local_count) {
    if (term.kind == MirTerminatorKind::Branch) {
        rir::ValueId cond_id{};
        if (term.use_cmp) {
            const auto lhs_shape = resolved_shape(mir, term.lhs);
            const auto rhs_shape = resolved_shape(mir, term.rhs);
            auto lhs = materialize_value(term.lhs,
                                         mir,
                                         variant_infos,
                                         tuple_infos,
                                         tuple_info_count,
                                         error_scalar_infos,
                                         error_variant_infos,
                                         error_struct_infos,
                                         user_struct_defs,
                                         b,
                                         locals,
                                         local_count,
                                         term.span);
            if (!lhs) return core::make_unexpected(lhs.error());
            auto rhs = materialize_value(term.rhs,
                                         mir,
                                         variant_infos,
                                         tuple_infos,
                                         tuple_info_count,
                                         error_scalar_infos,
                                         error_variant_infos,
                                         error_struct_infos,
                                         user_struct_defs,
                                         b,
                                         locals,
                                         local_count,
                                         term.span);
            if (!rhs) return core::make_unexpected(rhs.error());
            if (term.lhs.kind == MirValueKind::Error &&
                term.lhs.error_variant_index != 0xffffffffu) {
                auto i32_ty_result = b.make_type(rir::TypeKind::I32);
                if (!i32_ty_result) return frontend_error(FrontendError::OutOfMemory, term.span);
                auto* i32_ty = i32_ty_result.value();
                rir::ValueId rhs_tag = rhs.value();
                if (rhs_shape.type == MirTypeKind::Variant &&
                    rhs_shape.variant_index < mir.variants.len &&
                    variant_infos[rhs_shape.variant_index].struct_type != nullptr) {
                    auto rhs_tag_field = b.emit_struct_field(
                        rhs.value(), lit("tag"), i32_ty, {term.span.line, term.span.col});
                    if (!rhs_tag_field)
                        return frontend_error(FrontendError::OutOfMemory, term.span);
                    rhs_tag = rhs_tag_field.value();
                }
                auto cmp = b.emit_cmp(
                    rir::Opcode::CmpEq, lhs.value(), rhs_tag, {term.span.line, term.span.col});
                if (!cmp) return frontend_error(FrontendError::OutOfMemory, term.span);
                cond_id = cmp.value();
            } else if (term.lhs.may_error && term.lhs.error_variant_index != 0xffffffffu) {
                auto& err_info = error_info_for(lhs_shape,
                                                term.lhs.error_struct_index,
                                                error_scalar_infos,
                                                error_variant_infos,
                                                error_struct_infos);
                auto err = b.emit_struct_field(lhs.value(),
                                               error_field_name(),
                                               err_info.error_opt_type,
                                               {term.span.line, term.span.col});
                if (!err) return frontend_error(FrontendError::OutOfMemory, term.span);
                auto err_is_nil = b.emit_opt_is_nil(err.value(), {term.span.line, term.span.col});
                if (!err_is_nil) return frontend_error(FrontendError::OutOfMemory, term.span);
                auto false_v = b.emit_const_bool(false, {term.span.line, term.span.col});
                if (!false_v) return frontend_error(FrontendError::OutOfMemory, term.span);
                auto has_error = b.emit_cmp(rir::Opcode::CmpEq,
                                            err_is_nil.value(),
                                            false_v.value(),
                                            {term.span.line, term.span.col});
                if (!has_error) return frontend_error(FrontendError::OutOfMemory, term.span);
                auto err_value = b.emit_opt_unwrap(
                    err.value(), err_info.error_type, {term.span.line, term.span.col});
                if (!err_value) return frontend_error(FrontendError::OutOfMemory, term.span);
                auto i32_ty = b.make_type(rir::TypeKind::I32);
                if (!i32_ty) return frontend_error(FrontendError::OutOfMemory, term.span);
                auto tag_value = b.emit_struct_field(err_value.value(),
                                                     error_code_field_name(),
                                                     i32_ty.value(),
                                                     {term.span.line, term.span.col});
                if (!tag_value) return frontend_error(FrontendError::OutOfMemory, term.span);
                rir::ValueId rhs_tag = rhs.value();
                if (rhs_shape.type == MirTypeKind::Variant &&
                    rhs_shape.variant_index < mir.variants.len &&
                    variant_infos[rhs_shape.variant_index].struct_type != nullptr) {
                    auto rhs_tag_field = b.emit_struct_field(
                        rhs.value(), lit("tag"), i32_ty.value(), {term.span.line, term.span.col});
                    if (!rhs_tag_field)
                        return frontend_error(FrontendError::OutOfMemory, term.span);
                    rhs_tag = rhs_tag_field.value();
                }
                auto cmp = b.emit_cmp(rir::Opcode::CmpEq,
                                      tag_value.value(),
                                      rhs_tag,
                                      {term.span.line, term.span.col});
                if (!cmp) return frontend_error(FrontendError::OutOfMemory, term.span);
                auto cond = b.emit_select(has_error.value(),
                                          cmp.value(),
                                          false_v.value(),
                                          {term.span.line, term.span.col});
                if (!cond) return frontend_error(FrontendError::OutOfMemory, term.span);
                cond_id = cond.value();
            } else if (lhs_shape.type == MirTypeKind::Variant &&
                       lhs_shape.variant_index < mir.variants.len &&
                       variant_infos[lhs_shape.variant_index].struct_type != nullptr) {
                auto* i32_ty = b.make_type(rir::TypeKind::I32).value();
                auto lhs_tag = b.emit_struct_field(
                    lhs.value(), lit("tag"), i32_ty, {term.span.line, term.span.col});
                if (!lhs_tag) return frontend_error(FrontendError::OutOfMemory, term.span);
                auto rhs_tag = b.emit_struct_field(
                    rhs.value(), lit("tag"), i32_ty, {term.span.line, term.span.col});
                if (!rhs_tag) return frontend_error(FrontendError::OutOfMemory, term.span);
                lhs = lhs_tag.value();
                rhs = rhs_tag.value();
                auto cmp = b.emit_cmp(
                    rir::Opcode::CmpEq, lhs.value(), rhs.value(), {term.span.line, term.span.col});
                if (!cmp) return frontend_error(FrontendError::OutOfMemory, term.span);
                cond_id = cmp.value();
            } else {
                auto cmp = b.emit_cmp(
                    rir::Opcode::CmpEq, lhs.value(), rhs.value(), {term.span.line, term.span.col});
                if (!cmp) return frontend_error(FrontendError::OutOfMemory, term.span);
                cond_id = cmp.value();
            }
        } else {
            auto cond = materialize_value(term.cond,
                                          mir,
                                          variant_infos,
                                          tuple_infos,
                                          tuple_info_count,
                                          error_scalar_infos,
                                          error_variant_infos,
                                          error_struct_infos,
                                          user_struct_defs,
                                          b,
                                          locals,
                                          local_count,
                                          term.span);
            if (!cond) return core::make_unexpected(cond.error());
            if (term.cond.may_error) {
                const auto cond_shape = resolved_shape(mir, term.cond);
                auto& err_info = error_info_for(cond_shape,
                                                term.cond.error_struct_index,
                                                error_scalar_infos,
                                                error_variant_infos,
                                                error_struct_infos);
                auto err = b.emit_struct_field(cond.value(),
                                               error_field_name(),
                                               err_info.error_opt_type,
                                               {term.span.line, term.span.col});
                if (!err) return frontend_error(FrontendError::OutOfMemory, term.span);
                auto err_is_nil = b.emit_opt_is_nil(err.value(), {term.span.line, term.span.col});
                if (!err_is_nil) return frontend_error(FrontendError::OutOfMemory, term.span);
                auto payload = b.emit_struct_field(cond.value(),
                                                   error_payload_field_name(),
                                                   err_info.payload_opt_type,
                                                   {term.span.line, term.span.col});
                if (!payload) return frontend_error(FrontendError::OutOfMemory, term.span);
                auto payload_block = b.create_block(fn, branch_cond_payload_label());
                if (!payload_block) return frontend_error(FrontendError::OutOfMemory, term.span);
                auto error_block = b.create_block(fn, error_return_label());
                if (!error_block) return frontend_error(FrontendError::OutOfMemory, term.span);
                if (!b.emit_br(err_is_nil.value(),
                               payload_block.value(),
                               error_block.value(),
                               {term.span.line, term.span.col}))
                    return frontend_error(FrontendError::OutOfMemory, term.span);

                b.set_insert_point(fn, error_block.value());
                if (!b.emit_ret_status(500, {term.span.line, term.span.col}))
                    return frontend_error(FrontendError::OutOfMemory, term.span);

                b.set_insert_point(fn, payload_block.value());
                auto bool_ty = b.make_type(rir::TypeKind::Bool);
                if (!bool_ty) return frontend_error(FrontendError::OutOfMemory, term.span);
                auto unwrapped = b.emit_opt_unwrap(
                    payload.value(), bool_ty.value(), {term.span.line, term.span.col});
                if (!unwrapped) return frontend_error(FrontendError::OutOfMemory, term.span);
                cond_id = unwrapped.value();
            } else {
                cond_id = cond.value();
            }
        }
        if (!b.emit_br(cond_id,
                       block_ids[term.then_block],
                       block_ids[term.else_block],
                       {term.span.line, term.span.col})) {
            return frontend_error(FrontendError::OutOfMemory, term.span);
        }
        return {};
    }
    if (term.kind == MirTerminatorKind::ReturnStatus) {
        if (term.commit_response_mutations &&
            !b.emit_resp_commit_headers({term.span.line, term.span.col}))
            return frontend_error(FrontendError::OutOfMemory, term.span);
        if (term.source_kind == MirTerminatorSourceKind::LocalRef) {
            if (term.local_ref_index >= local_count)
                return frontend_error(FrontendError::UnsupportedSyntax, term.span);
            // Runtime-value status doesn't carry a body literal today
            // (source syntax is `return <local>`, no response()
            // builder form on this path). Body plumbing on that path
            // can follow when response(localVar) becomes valid.
            const auto code_id = locals[term.local_ref_index];
            if (!b.emit_ret_status(code_id, {term.span.line, term.span.col}))
                return frontend_error(FrontendError::OutOfMemory, term.span);
            return {};
        }
        // Literal form: intern the body (if any) into the module table
        // and pack the 1-based idx into RetStatus's immediate. Empty /
        // missing body ⇒ idx = 0 ⇒ runtime uses default status-reason.
        u16 body_idx = 0;
        if (term.response_body.ptr != nullptr && term.response_body.len > 0) {
            body_idx = b.intern_response_body(term.response_body);
            if (body_idx == 0) {
                // intern returns 0 for both "table full" and "arena
                // OOM for the body-bytes copy". Distinguish here so
                // the diagnostic isn't misleading: if the count is
                // still under the cap, the arena must have failed.
                const auto err = b.mod->response_body_count < rir::Module::kMaxResponseBodies
                                     ? FrontendError::OutOfMemory
                                     : FrontendError::TooManyItems;
                return frontend_error(err, term.span);
            }
        }
        // Intern the header set (if any) into the module's flat pool
        // and pack its 1-based idx into the same RetStatus imm slot.
        // Missing kwarg ⇒ idx = 0 ⇒ runtime emits no custom headers.
        u16 headers_idx = 0;
        if (term.response_headers.len > 0) {
            headers_idx =
                b.intern_response_headers(&term.response_headers[0], term.response_headers.len);
            if (headers_idx == 0) {
                // Same failure disambiguation as intern_response_body:
                // distinguish "sets table full" or "pool full" from
                // "arena OOM mid-copy".
                const bool sets_full = b.mod->header_set_count >= rir::Module::kMaxHeaderSets;
                const bool pool_full = term.response_headers.len >
                                       rir::Module::kMaxHeaderPoolEntries - b.mod->header_pool_used;
                const auto err = (sets_full || pool_full) ? FrontendError::TooManyItems
                                                          : FrontendError::OutOfMemory;
                return frontend_error(err, term.span);
            }
        }
        if (!b.emit_ret_status(
                term.status_code, {term.span.line, term.span.col}, body_idx, headers_idx))
            return frontend_error(FrontendError::OutOfMemory, term.span);
        return {};
    }
    if (term.kind == MirTerminatorKind::Redirect) {
        if (term.commit_response_mutations || term.redirect_policy_id == 0 ||
            term.redirect_policy_id > mir.redirect_policies.len ||
            !redirect_policy_spec_valid(mir.redirect_policies[term.redirect_policy_id - 1]))
            return frontend_error(FrontendError::UnsupportedSyntax, term.span);
        if (!b.emit_ret_redirect(term.redirect_policy_id,
                                 {term.span.line, term.span.col}))
            return frontend_error(FrontendError::OutOfMemory, term.span);
        return {};
    }
    if (term.kind == MirTerminatorKind::ForwardUpstream) {
        // forward(set_path: "..."): emit ReqSetPath(const-str) before the
        // terminator so the handler records the path override at runtime.
        if (term.forward_set_path.ptr != nullptr) {
            auto path = b.emit_const_str(term.forward_set_path, {term.span.line, term.span.col});
            if (!path || !b.emit_req_set_path(path.value(), {term.span.line, term.span.col}))
                return frontend_error(FrontendError::OutOfMemory, term.span);
        }
        // forward(set_header: {...}): one ReqSetHeader(name, const-str value) per
        // entry before the terminator (name is the op immediate, value a register).
        for (u32 i = 0; i < term.forward_set_headers.len; i++) {
            const auto& kv = term.forward_set_headers[i];
            auto val = b.emit_const_str(kv.value, {term.span.line, term.span.col});
            if (!val ||
                !b.emit_req_set_header(kv.key, val.value(), {term.span.line, term.span.col}))
                return frontend_error(FrontendError::OutOfMemory, term.span);
        }
        const u16 upstream_id = mir.upstreams[term.upstream_index].id;
        auto upstream =
            b.emit_const_i32(static_cast<i32>(upstream_id), {term.span.line, term.span.col});
        if (!upstream) return frontend_error(FrontendError::OutOfMemory, term.span);
        rir::ValueId policy = rir::kNoValue;
        if (term.forward_request_policy_id != 0) {
            auto p = b.emit_const_i32(static_cast<i32>(term.forward_request_policy_id),
                                      {term.span.line, term.span.col});
            if (!p) return frontend_error(FrontendError::OutOfMemory, term.span);
            policy = p.value();
        }
        rir::ValueId response_policy = rir::kNoValue;
        if (term.forward_response_policy_id != 0) {
            if (policy == rir::kNoValue) {
                auto p0 = b.emit_const_i32(0, {term.span.line, term.span.col});
                if (!p0) return frontend_error(FrontendError::OutOfMemory, term.span);
                policy = p0.value();
            }
            auto p = b.emit_const_i32(static_cast<i32>(term.forward_response_policy_id),
                                      {term.span.line, term.span.col});
            if (!p) return frontend_error(FrontendError::OutOfMemory, term.span);
            response_policy = p.value();
        }
        if (term.forward_failure_policy_id != 0 ||
            term.forward_timeout_failure_policy_id != 0) {
            if (term.forward_failure_policy_id == 0 ||
                term.forward_response_policy_id > b.mod->response_policy_count ||
                term.forward_failure_policy_id > b.mod->failure_policy_count ||
                term.forward_timeout_failure_policy_id > b.mod->failure_policy_count)
                return frontend_error(FrontendError::UnsupportedSyntax, term.span);
            if (!forward_failure_policy_spec_valid(
                    b.mod->failure_policies[term.forward_failure_policy_id - 1]))
                return frontend_error(FrontendError::UnsupportedSyntax, term.span);
            if (term.forward_timeout_failure_policy_id != 0 &&
                (term.forward_response_policy_id == 0 ||
                 !forward_timeout_failure_policy_spec_valid(
                     b.mod->failure_policies[term.forward_timeout_failure_policy_id - 1])))
                return frontend_error(FrontendError::UnsupportedSyntax, term.span);
            u16 bundle_id = 0;
            for (u32 i = 0; i < b.mod->policy_bundle_count; i++) {
                const auto& existing = b.mod->policy_bundles[i];
                if (existing.response_policy_id == term.forward_response_policy_id &&
                    existing.failure_policy_id == term.forward_failure_policy_id &&
                    existing.timeout_failure_policy_id ==
                        term.forward_timeout_failure_policy_id) {
                    bundle_id = static_cast<u16>(i + 1);
                    break;
                }
            }
            if (bundle_id == 0) {
                if (b.mod->policy_bundle_count >= kMaxForwardFailurePolicies)
                    return frontend_error(FrontendError::TooManyItems, term.span);
                bundle_id = static_cast<u16>(++b.mod->policy_bundle_count);
                b.mod->policy_bundles[bundle_id - 1] = {
                    term.forward_response_policy_id,
                    term.forward_failure_policy_id,
                    term.forward_timeout_failure_policy_id};
            }
            auto bundle = b.emit_const_i32(static_cast<i32>(bundle_id),
                                           {term.span.line, term.span.col});
            if (!bundle) return frontend_error(FrontendError::OutOfMemory, term.span);
            if (policy == rir::kNoValue) {
                auto p0 = b.emit_const_i32(0, {term.span.line, term.span.col});
                if (!p0) return frontend_error(FrontendError::OutOfMemory, term.span);
                policy = p0.value();
            }
            u16 target_transform_id = 0;
            if (term.has_forward_target_transform) {
                auto transform = intern_target_transform(*b.mod,
                                                         term.forward_target_transform,
                                                         term.span);
                if (!transform) return core::make_unexpected(transform.error());
                target_transform_id = transform.value();
            }
            if (term.commit_response_mutations &&
                !b.emit_resp_commit_headers({term.span.line, term.span.col}))
                return frontend_error(FrontendError::OutOfMemory, term.span);
            if (target_transform_id != 0 &&
                !b.emit_req_set_target_transform(target_transform_id,
                                                 {term.span.line, term.span.col}))
                return frontend_error(FrontendError::OutOfMemory, term.span);
            if (!b.emit_ret_forward_bundle(upstream.value(), policy, bundle.value(),
                                           {term.span.line, term.span.col}))
                return frontend_error(FrontendError::OutOfMemory, term.span);
            return {};
        }
        u16 target_transform_id = 0;
        if (term.has_forward_target_transform) {
            auto transform = intern_target_transform(*b.mod,
                                                     term.forward_target_transform,
                                                     term.span);
            if (!transform) return core::make_unexpected(transform.error());
            target_transform_id = transform.value();
        }
        if (term.commit_response_mutations &&
            !b.emit_resp_commit_headers({term.span.line, term.span.col}))
            return frontend_error(FrontendError::OutOfMemory, term.span);
        if (target_transform_id != 0 &&
            !b.emit_req_set_target_transform(target_transform_id,
                                             {term.span.line, term.span.col}))
            return frontend_error(FrontendError::OutOfMemory, term.span);
        if (!b.emit_ret_forward(upstream.value(),
                                policy,
                                response_policy,
                                {term.span.line, term.span.col}))
            return frontend_error(FrontendError::OutOfMemory, term.span);
        return {};
    }
    if (term.kind == MirTerminatorKind::YieldTimer) {
        if (!b.emit_yield_event(yield_kind_abi(term.yield_event_kind),
                                term.yield_ms,
                                term.yield_next_state,
                                {term.span.line, term.span.col}))
            return frontend_error(FrontendError::OutOfMemory, term.span);
        return {};
    }
    return frontend_error(FrontendError::UnsupportedSyntax, term.span);
}

}  // namespace

bool FrontendRirModule::init(u32 func_cap, u32 struct_cap) {
    destroy();
    if (!arena.init(4096)) return false;
    module.name = source_name.len != 0 ? source_name : lit("frontend.rut");
    module.arena = &arena;
    module.functions = arena.alloc_array<rir::Function>(func_cap);
    if (!module.functions) {
        destroy();
        return false;
    }
    module.func_count = 0;
    module.func_cap = func_cap;
    module.struct_defs = arena.alloc_array<rir::StructDef*>(struct_cap);
    if (!module.struct_defs) {
        destroy();
        return false;
    }
    module.struct_count = 0;
    module.struct_cap = struct_cap;
    return true;
}

void FrontendRirModule::destroy() {
    arena.destroy();
    auto saved_source_name = source_name;
    module = {};
    source_name = saved_source_name;
}

FrontendResult<void> lower_to_rir(const MirModule& mir, FrontendRirModule& out) {
    if (!out.init(mir.functions.len == 0 ? 1 : mir.functions.len,
                  mir.variants.len * 2 + mir.structs.len + 8))
        return frontend_error(FrontendError::OutOfMemory);

    rir::Builder b;
    b.init(&out.module);

    // Carry upstream declarations (name + optional address) verbatim
    // into the RIR module so a compile→config helper can translate
    // them into RouteConfig::add_upstream calls without re-parsing.
    // Names must be copied into the RIR arena — MIR's name Str points
    // at the caller's (possibly transient) source buffer; when that
    // goes away before populate_route_config runs, the pointer would
    // dangle. Response bodies and header sets already do this copy
    // via intern_response_body / intern_response_headers.
    if (mir.upstreams.len > rir::Module::kMaxUpstreams) {
        return frontend_error(FrontendError::TooManyItems,
                              mir.upstreams.len > 0 ? mir.upstreams[0].span : Span{});
    }
    for (u32 i = 0; i < mir.upstreams.len; i++) {
        const Str src_name = mir.upstreams[i].name;
        char* name_buf = nullptr;
        if (src_name.len > 0) {
            name_buf = out.module.arena->alloc_array<char>(src_name.len);
            if (!name_buf) return frontend_error(FrontendError::OutOfMemory, mir.upstreams[i].span);
            for (u32 k = 0; k < src_name.len; k++) name_buf[k] = src_name.ptr[k];
        }
        out.module.upstreams[i].name = {name_buf, src_name.len};
        out.module.upstreams[i].has_address = mir.upstreams[i].has_address;
        out.module.upstreams[i].ip = mir.upstreams[i].ip;
        out.module.upstreams[i].port = mir.upstreams[i].port;
        out.module.upstreams[i].extra_count = mir.upstreams[i].extra_count;
        for (u32 b = 0; b < mir.upstreams[i].extra_count; b++) {
            out.module.upstreams[i].extra_ips[b] = mir.upstreams[i].extra_ips[b];
            out.module.upstreams[i].extra_ports[b] = mir.upstreams[i].extra_ports[b];
        }
        // Active health-check config. hc_path is copied into arena memory (like
        // name) so the RIR module owns it independently of the AST/HIR/MIR.
        out.module.upstreams[i].hc_enabled = mir.upstreams[i].hc_enabled;
        const Str src_hc_path = mir.upstreams[i].hc_path;
        char* hc_path_buf = nullptr;
        if (src_hc_path.len > 0) {
            hc_path_buf = out.module.arena->alloc_array<char>(src_hc_path.len);
            if (!hc_path_buf)
                return frontend_error(FrontendError::OutOfMemory, mir.upstreams[i].span);
            for (u32 k = 0; k < src_hc_path.len; k++) hc_path_buf[k] = src_hc_path.ptr[k];
        }
        out.module.upstreams[i].hc_path = {hc_path_buf, src_hc_path.len};
        out.module.upstreams[i].hc_interval_ms = mir.upstreams[i].hc_interval_ms;
        out.module.upstreams[i].hc_expected_status = mir.upstreams[i].hc_expected_status;
    }
    out.module.upstream_count = mir.upstreams.len;

    // Copy validated response-policy metadata into the RIR arena. The
    // compiler's source/HIR/MIR storage may be temporary; the RIR module is
    // the owner that survives until RouteConfig activation.
    if (mir.response_policies.len > kMaxResponsePolicies)
        return frontend_error(FrontendError::TooManyItems, {});
    auto copy_policy_str = [&](Str src, Str& dst) {
        if (src.len > 0 && src.ptr == nullptr) return false;
        char* buf = nullptr;
        if (src.len > 0) {
            buf = out.module.arena->alloc_array<char>(src.len);
            if (!buf) return false;
            for (u32 k = 0; k < src.len; k++) buf[k] = src.ptr[k];
        }
        dst = {buf, src.len};
        return true;
    };
    for (u32 i = 0; i < mir.response_policies.len; i++) {
        const auto& src = mir.response_policies[i];
        if (!response_policy_spec_valid(src))
            return frontend_error(FrontendError::UnsupportedSyntax);
        auto& dst = out.module.response_policies[i];
        dst.version = src.version;
        dst.framing = src.framing;
        dst.connection = src.connection;
        dst.date = src.date;
        dst.head_mode = src.head_mode;
        if (!copy_policy_str(src.server, dst.server))
            return frontend_error(FrontendError::OutOfMemory);
        dst.hide_header_count = src.hide_header_count;
        for (u32 h = 0; h < src.hide_header_count; h++) {
            if (!copy_policy_str(src.hide_headers[h], dst.hide_headers[h]))
                return frontend_error(FrontendError::OutOfMemory);
        }
    }
    out.module.response_policy_count = mir.response_policies.len;

    if (mir.failure_policies.len > kMaxForwardFailurePolicies)
        return frontend_error(FrontendError::TooManyItems);
    auto copy_failure_str = [&](Str src, Str& dst) {
        if (src.len > 0 && src.ptr == nullptr) return false;
        char* buf = nullptr;
        if (src.len > 0) {
            buf = out.module.arena->alloc_array<char>(src.len);
            if (!buf) return false;
            for (u32 k = 0; k < src.len; k++) buf[k] = src.ptr[k];
        }
        dst = {buf, src.len};
        return true;
    };
    for (u32 i = 0; i < mir.failure_policies.len; i++) {
        const auto& src = mir.failure_policies[i];
        if (!forward_failure_policy_table_spec_valid(src))
            return frontend_error(FrontendError::UnsupportedSyntax);
        auto& dst = out.module.failure_policies[i];
        dst.version = src.version;
        dst.status_code = src.status_code;
        dst.date = src.date;
        dst.connection = src.connection;
        dst.head_mode = src.head_mode;
        if (!copy_failure_str(src.reason, dst.reason) ||
            !copy_failure_str(src.content_type, dst.content_type) ||
            !copy_failure_str(src.server, dst.server) ||
            !copy_failure_str(src.body, dst.body))
            return frontend_error(FrontendError::OutOfMemory);
    }
    out.module.failure_policy_count = mir.failure_policies.len;

    if (mir.redirect_policies.len > kMaxRedirectPolicies)
        return frontend_error(FrontendError::TooManyItems);
    for (u32 i = 0; i < mir.redirect_policies.len; i++) {
        const auto& src = mir.redirect_policies[i];
        if (!redirect_policy_spec_valid(src))
            return frontend_error(FrontendError::UnsupportedSyntax);
        auto& dst = out.module.redirect_policies[i];
        dst = src;
        auto copy_redirect_str = [&](Str value, Str& out_str) {
            if (value.len > 0 && value.ptr == nullptr) return false;
            char* ptr = nullptr;
            if (value.len > 0) {
                ptr = out.module.arena->alloc_array<char>(value.len);
                if (!ptr) return false;
                for (u32 j = 0; j < value.len; j++) ptr[j] = value.ptr[j];
            }
            out_str = {ptr, value.len};
            return true;
        };
        if (!copy_redirect_str(src.reason, dst.reason) ||
            !copy_redirect_str(src.server, dst.server) ||
            !copy_redirect_str(src.content_type, dst.content_type) ||
            !copy_redirect_str(src.target_path, dst.target_path) ||
            !copy_redirect_str(src.body, dst.body))
            return frontend_error(FrontendError::OutOfMemory);
    }
    out.module.redirect_policy_count = mir.redirect_policies.len;

    // Cache instance descriptors, names arena-copied like upstream names.
    if (mir.caches.len > rir::Module::kMaxCacheInstances) {
        return frontend_error(FrontendError::TooManyItems,
                              mir.caches.len > 0 ? mir.caches[0].span : Span{});
    }
    for (u32 i = 0; i < mir.caches.len; i++) {
        const Str src_name = mir.caches[i].name;
        char* name_buf = nullptr;
        if (src_name.len > 0) {
            name_buf = out.module.arena->alloc_array<char>(src_name.len);
            if (!name_buf) return frontend_error(FrontendError::OutOfMemory, mir.caches[i].span);
            for (u32 k = 0; k < src_name.len; k++) name_buf[k] = src_name.ptr[k];
        }
        out.module.cache_instances[i].name = {name_buf, src_name.len};
        out.module.cache_instances[i].capacity = mir.caches[i].capacity;
    }
    out.module.cache_instance_count = mir.caches.len;

    VariantLoweringInfo variant_infos[MirModule::kMaxVariants]{};
    TupleLoweringInfo tuple_infos[64]{};
    u32 tuple_info_count = 0;
    ErrorLoweringInfo error_scalar_infos[4]{};
    ErrorLoweringInfo error_variant_infos[MirModule::kMaxVariants]{};
    ErrorLoweringInfo error_struct_infos[MirModule::kMaxStructs]{};
    const rir::StructDef* user_struct_defs[MirModule::kMaxStructs]{};

    auto i32_ty = b.make_type(rir::TypeKind::I32);
    if (!i32_ty) return frontend_error(FrontendError::OutOfMemory);
    auto str_ty = b.make_type(rir::TypeKind::Str);
    if (!str_ty) return frontend_error(FrontendError::OutOfMemory);
    rir::FieldDef error_fields[5] = {
        {error_code_field_name(), i32_ty.value()},
        {error_msg_field_name(), str_ty.value()},
        {error_file_field_name(), str_ty.value()},
        {error_func_field_name(), str_ty.value()},
        {error_line_field_name(), i32_ty.value()},
    };
    auto error_struct_def = b.create_struct(lit("Error"), error_fields, 5);
    if (!error_struct_def) return frontend_error(FrontendError::OutOfMemory);
    auto error_struct_ty = b.make_type(rir::TypeKind::Struct, nullptr, error_struct_def.value());
    if (!error_struct_ty) return frontend_error(FrontendError::OutOfMemory);

    bool variant_has_tuple_payload[MirModule::kMaxVariants]{};
    bool variant_has_variant_payload[MirModule::kMaxVariants]{};
    bool variant_has_struct_payload[MirModule::kMaxVariants]{};
    bool variant_built[MirModule::kMaxVariants]{};
    for (u32 vi = 0; vi < mir.variants.len; vi++) {
        const bool unresolved_generic_instance =
            !instance_fully_concrete(mir,
                                     mir.variants[vi].instance_type_arg_count,
                                     mir.variants[vi].instance_type_args,
                                     mir.variants[vi].instance_shape_indices);
        if (is_open_generic_variant_decl(mir.variants[vi])) {
            variant_built[vi] = true;
            continue;
        }
        if (unresolved_generic_instance) {
            variant_built[vi] = true;
            continue;
        }
        bool has_tuple_payload = false;
        bool has_variant_payload = false;
        bool has_struct_payload = false;
        for (u32 ci = 0; ci < mir.variants[vi].cases.len; ci++) {
            const auto payload_shape = resolved_shape(mir, mir.variants[vi].cases[ci]);
            if (!mir.variants[vi].cases[ci].has_payload) continue;
            if (payload_shape.type == MirTypeKind::Tuple) {
                if (!has_tuple_payload) {
                    has_tuple_payload = true;
                    variant_infos[vi].payload_shape_index =
                        mir.variants[vi].cases[ci].payload_shape_index;
                    variant_infos[vi].payload_tuple_len = payload_shape.tuple_len;
                    for (u32 ti = 0; ti < payload_shape.tuple_len; ti++) {
                        variant_infos[vi].payload_tuple_types[ti] = payload_shape.tuple_types[ti];
                        variant_infos[vi].payload_tuple_variant_indices[ti] =
                            payload_shape.tuple_variant_indices[ti];
                        variant_infos[vi].payload_tuple_struct_indices[ti] =
                            payload_shape.tuple_struct_indices[ti];
                    }
                } else if (!same_tuple_shape(variant_infos[vi],
                                             payload_shape.tuple_len,
                                             payload_shape.tuple_types,
                                             payload_shape.tuple_variant_indices,
                                             payload_shape.tuple_struct_indices)) {
                    out.destroy();
                    return frontend_error(FrontendError::UnsupportedSyntax, mir.variants[vi].span);
                }
            } else if (payload_shape.type == MirTypeKind::Variant) {
                if (!has_variant_payload) {
                    has_variant_payload = true;
                    variant_infos[vi].payload_shape_index =
                        mir.variants[vi].cases[ci].payload_shape_index;
                    variant_infos[vi].payload_variant_index = payload_shape.variant_index;
                } else if (variant_infos[vi].payload_variant_index != payload_shape.variant_index) {
                    out.destroy();
                    return frontend_error(FrontendError::UnsupportedSyntax, mir.variants[vi].span);
                }
            } else if (payload_shape.type == MirTypeKind::Struct) {
                if (!has_struct_payload) {
                    has_struct_payload = true;
                    variant_infos[vi].payload_shape_index =
                        mir.variants[vi].cases[ci].payload_shape_index;
                    variant_infos[vi].payload_struct_index = payload_shape.struct_index;
                } else if (variant_infos[vi].payload_struct_index != payload_shape.struct_index) {
                    out.destroy();
                    return frontend_error(FrontendError::UnsupportedSyntax, mir.variants[vi].span);
                }
            }
        }
        variant_has_tuple_payload[vi] = has_tuple_payload;
        variant_has_variant_payload[vi] = has_variant_payload;
        variant_has_struct_payload[vi] = has_struct_payload;
    }

    bool struct_built[MirModule::kMaxStructs]{};
    auto build_user_struct = [&](u32 si) -> FrontendResult<bool> {
        if (struct_built[si]) return true;
        if (!instance_fully_concrete(mir,
                                     mir.structs[si].instance_type_arg_count,
                                     mir.structs[si].instance_type_args,
                                     mir.structs[si].instance_shape_indices)) {
            struct_built[si] = true;
            return true;
        }
        if (is_open_generic_struct_decl(mir.structs[si])) {
            struct_built[si] = true;
            return true;
        }
        rir::FieldDef fields[MirStruct::kMaxFields]{};
        for (u32 fi = 0; fi < mir.structs[si].fields.len; fi++) {
            const auto& field = mir.structs[si].fields[fi];
            const rir::Type* field_ty = nullptr;
            if (field.is_error_type) {
                field_ty = error_struct_ty.value();
            } else {
                const auto field_shape = resolved_shape(mir, field);
                if (field_shape.type == MirTypeKind::Bool) {
                    auto ty = b.make_type(rir::TypeKind::Bool);
                    if (!ty)
                        return frontend_error(FrontendError::OutOfMemory, mir.structs[si].span);
                    field_ty = ty.value();
                } else if (field_shape.type == MirTypeKind::I32) {
                    field_ty = i32_ty.value();
                } else if (field_shape.type == MirTypeKind::Str) {
                    field_ty = str_ty.value();
                } else if (field_shape.type == MirTypeKind::Variant) {
                    if (field_shape.variant_index >= mir.variants.len ||
                        variant_infos[field_shape.variant_index].struct_type == nullptr)
                        return false;
                    field_ty = variant_infos[field_shape.variant_index].struct_type;
                } else if (field_shape.type == MirTypeKind::Struct) {
                    if (field_shape.struct_index >= mir.structs.len ||
                        user_struct_defs[field_shape.struct_index] == nullptr)
                        return false;
                    auto ty = b.make_type(
                        rir::TypeKind::Struct,
                        nullptr,
                        const_cast<rir::StructDef*>(user_struct_defs[field_shape.struct_index]));
                    if (!ty)
                        return frontend_error(FrontendError::OutOfMemory, mir.structs[si].span);
                    field_ty = ty.value();
                } else if (field_shape.type == MirTypeKind::Tuple) {
                    auto tuple_info =
                        get_or_create_tuple_lowering(field_shape.tuple_len,
                                                     field_shape.tuple_types,
                                                     field_shape.tuple_variant_indices,
                                                     field_shape.tuple_struct_indices,
                                                     variant_infos,
                                                     user_struct_defs,
                                                     tuple_infos,
                                                     &tuple_info_count,
                                                     b,
                                                     mir.structs[si].span);
                    if (!tuple_info) return core::make_unexpected(tuple_info.error());
                    field_ty = tuple_info.value()->struct_type;
                } else {
                    return frontend_error(
                        FrontendError::UnsupportedSyntax, mir.structs[si].span, field.type_name);
                }
            }
            fields[fi] = {field.name, field_ty};
        }
        auto sd = b.create_struct(mir.structs[si].name, fields, mir.structs[si].fields.len);
        if (!sd) return frontend_error(FrontendError::OutOfMemory, mir.structs[si].span);
        user_struct_defs[si] = sd.value();
        struct_built[si] = true;
        return true;
    };

    auto build_variant_carrier = [&](u32 vi) -> FrontendResult<bool> {
        if (variant_built[vi]) return true;
        const bool has_tuple_payload = variant_has_tuple_payload[vi];
        const bool has_variant_payload = variant_has_variant_payload[vi];
        const bool has_struct_payload = variant_has_struct_payload[vi];
        const auto payload_shape = resolved_payload_shape(mir, variant_infos[vi]);
        u32 payload_variant_index = payload_shape.variant_index;
        u32 payload_struct_index = payload_shape.struct_index;
        if (has_variant_payload) {
            if (payload_variant_index >= mir.variants.len ||
                !variant_built[payload_variant_index] ||
                variant_infos[payload_variant_index].struct_type == nullptr) {
                return false;
            }
        }
        if (has_struct_payload) {
            if (payload_struct_index >= mir.structs.len ||
                user_struct_defs[payload_struct_index] == nullptr) {
                return false;
            }
        }
        auto bool_ty = b.make_type(rir::TypeKind::Bool);
        if (!bool_ty) {
            out.destroy();
            return frontend_error(FrontendError::OutOfMemory, mir.variants[vi].span);
        }
        auto i32_ty = b.make_type(rir::TypeKind::I32);
        if (!i32_ty) {
            out.destroy();
            return frontend_error(FrontendError::OutOfMemory, mir.variants[vi].span);
        }
        auto str_ty = b.make_type(rir::TypeKind::Str);
        if (!str_ty) {
            out.destroy();
            return frontend_error(FrontendError::OutOfMemory, mir.variants[vi].span);
        }
        auto bool_opt_ty = b.make_type(rir::TypeKind::Optional, bool_ty.value());
        if (!bool_opt_ty) {
            out.destroy();
            return frontend_error(FrontendError::OutOfMemory, mir.variants[vi].span);
        }
        auto i32_opt_ty = b.make_type(rir::TypeKind::Optional, i32_ty.value());
        if (!i32_opt_ty) {
            out.destroy();
            return frontend_error(FrontendError::OutOfMemory, mir.variants[vi].span);
        }
        auto str_opt_ty = b.make_type(rir::TypeKind::Optional, str_ty.value());
        if (!str_opt_ty) {
            out.destroy();
            return frontend_error(FrontendError::OutOfMemory, mir.variants[vi].span);
        }
        const rir::Type* tuple_ty = nullptr;
        const rir::Type* tuple_opt_ty = nullptr;
        const rir::Type* variant_ty = nullptr;
        const rir::Type* variant_opt_ty = nullptr;
        const rir::Type* struct_ty_payload = nullptr;
        const rir::Type* struct_opt_ty = nullptr;
        if (has_tuple_payload) {
            auto tuple_info = get_or_create_tuple_lowering(payload_shape.tuple_len,
                                                           payload_shape.tuple_types,
                                                           payload_shape.tuple_variant_indices,
                                                           payload_shape.tuple_struct_indices,
                                                           variant_infos,
                                                           user_struct_defs,
                                                           tuple_infos,
                                                           &tuple_info_count,
                                                           b,
                                                           mir.variants[vi].span);
            if (!tuple_info) {
                out.destroy();
                return core::make_unexpected(tuple_info.error());
            }
            auto tuple_optional_ty =
                b.make_type(rir::TypeKind::Optional, tuple_info.value()->struct_type);
            if (!tuple_optional_ty) {
                out.destroy();
                return frontend_error(FrontendError::OutOfMemory, mir.variants[vi].span);
            }
            variant_infos[vi].payload_tuple_struct_def = tuple_info.value()->struct_def;
            variant_infos[vi].payload_tuple_type = tuple_info.value()->struct_type;
            variant_infos[vi].payload_tuple_opt_type = tuple_optional_ty.value();
            tuple_ty = tuple_info.value()->struct_type;
            tuple_opt_ty = tuple_optional_ty.value();
        }
        if (has_variant_payload) {
            variant_ty = variant_infos[payload_variant_index].struct_type;
            auto opt_ty = b.make_type(rir::TypeKind::Optional, variant_ty);
            if (!opt_ty) {
                out.destroy();
                return frontend_error(FrontendError::OutOfMemory, mir.variants[vi].span);
            }
            variant_opt_ty = opt_ty.value();
        }
        if (has_struct_payload) {
            auto ty =
                b.make_type(rir::TypeKind::Struct,
                            nullptr,
                            const_cast<rir::StructDef*>(user_struct_defs[payload_struct_index]));
            if (!ty) {
                out.destroy();
                return frontend_error(FrontendError::OutOfMemory, mir.variants[vi].span);
            }
            struct_ty_payload = ty.value();
            auto opt_ty = b.make_type(rir::TypeKind::Optional, struct_ty_payload);
            if (!opt_ty) {
                out.destroy();
                return frontend_error(FrontendError::OutOfMemory, mir.variants[vi].span);
            }
            struct_opt_ty = opt_ty.value();
        }
        rir::FieldDef fields[7] = {
            {lit("tag"), i32_ty.value()},
            {lit("payload_bool"), bool_opt_ty.value()},
            {lit("payload_i32"), i32_opt_ty.value()},
            {lit("payload_str"), str_opt_ty.value()},
            {lit("payload_tuple"), has_tuple_payload ? tuple_opt_ty : i32_opt_ty.value()},
            {lit("payload_variant"), has_variant_payload ? variant_opt_ty : i32_opt_ty.value()},
            {lit("payload_struct"), has_struct_payload ? struct_opt_ty : i32_opt_ty.value()},
        };
        auto sd = b.create_struct(mir.variants[vi].name, fields, 7);
        if (!sd) {
            out.destroy();
            return frontend_error(FrontendError::OutOfMemory, mir.variants[vi].span);
        }
        auto struct_ty = b.make_type(rir::TypeKind::Struct, nullptr, sd.value());
        if (!struct_ty) {
            out.destroy();
            return frontend_error(FrontendError::OutOfMemory, mir.variants[vi].span);
        }
        variant_infos[vi].payload_bool_type = bool_ty.value();
        variant_infos[vi].payload_i32_type = i32_ty.value();
        variant_infos[vi].payload_str_type = str_ty.value();
        variant_infos[vi].payload_bool_opt_type = bool_opt_ty.value();
        variant_infos[vi].payload_i32_opt_type = i32_opt_ty.value();
        variant_infos[vi].payload_str_opt_type = str_opt_ty.value();
        if (has_tuple_payload) {
            variant_infos[vi].payload_tuple_type = tuple_ty;
            variant_infos[vi].payload_tuple_opt_type = tuple_opt_ty;
        }
        if (has_variant_payload) {
            variant_infos[vi].payload_variant_type = variant_ty;
            variant_infos[vi].payload_variant_opt_type = variant_opt_ty;
        }
        if (has_struct_payload) {
            variant_infos[vi].payload_struct_type = struct_ty_payload;
            variant_infos[vi].payload_struct_opt_type = struct_opt_ty;
        }
        variant_infos[vi].struct_type = struct_ty.value();
        variant_infos[vi].struct_def = sd.value();
        variant_built[vi] = true;
        return true;
    };

    for (;;) {
        bool progress = false;
        for (u32 si = 0; si < mir.structs.len; si++) {
            if (struct_built[si]) continue;
            auto built = build_user_struct(si);
            if (!built) return core::make_unexpected(built.error());
            if (built.value()) progress = true;
        }
        for (u32 vi = 0; vi < mir.variants.len; vi++) {
            if (variant_built[vi]) continue;
            auto built = build_variant_carrier(vi);
            if (!built) return core::make_unexpected(built.error());
            if (built.value()) progress = true;
        }
        if (!progress) {
            for (u32 si = 0; si < mir.structs.len; si++) {
                if (!struct_built[si]) {
                    out.destroy();
                    return frontend_error(FrontendError::UnsupportedSyntax, mir.structs[si].span);
                }
            }
            for (u32 vi = 0; vi < mir.variants.len; vi++) {
                if (!variant_built[vi]) {
                    out.destroy();
                    return frontend_error(FrontendError::UnsupportedSyntax, mir.variants[vi].span);
                }
            }
            break;
        }
    }

    auto make_error_info =
        [&](Str name, const rir::Type* payload_inner) -> FrontendResult<ErrorLoweringInfo> {
        ErrorLoweringInfo info{};
        auto error_opt_ty = b.make_type(rir::TypeKind::Optional, error_struct_ty.value());
        if (!error_opt_ty) return frontend_error(FrontendError::OutOfMemory);
        auto payload_opt_ty = b.make_type(rir::TypeKind::Optional, payload_inner);
        if (!payload_opt_ty) return frontend_error(FrontendError::OutOfMemory);
        rir::FieldDef fields[2] = {
            {error_field_name(), error_opt_ty.value()},
            {error_payload_field_name(), payload_opt_ty.value()},
        };
        auto sd = b.create_struct(name, fields, 2);
        if (!sd) return frontend_error(FrontendError::OutOfMemory);
        auto struct_ty = b.make_type(rir::TypeKind::Struct, nullptr, sd.value());
        if (!struct_ty) return frontend_error(FrontendError::OutOfMemory);
        info.struct_type = struct_ty.value();
        info.error_type = error_struct_ty.value();
        info.error_opt_type = error_opt_ty.value();
        info.payload_inner_type = payload_inner;
        info.payload_opt_type = payload_opt_ty.value();
        info.struct_def = sd.value();
        return info;
    };

    {
        auto bool_ty = b.make_type(rir::TypeKind::Bool);
        if (!bool_ty) return frontend_error(FrontendError::OutOfMemory);
        auto err_bool = make_error_info(lit("__error_bool"), bool_ty.value());
        if (!err_bool) return core::make_unexpected(err_bool.error());
        error_scalar_infos[0] = err_bool.value();
        auto err_i32 = make_error_info(lit("__error_i32"), i32_ty.value());
        if (!err_i32) return core::make_unexpected(err_i32.error());
        error_scalar_infos[1] = err_i32.value();
        auto err_str = make_error_info(lit("__error_str"), str_ty.value());
        if (!err_str) return core::make_unexpected(err_str.error());
        error_scalar_infos[2] = err_str.value();
        auto err_unknown = make_error_info(lit("__error_unknown"), i32_ty.value());
        if (!err_unknown) return core::make_unexpected(err_unknown.error());
        error_scalar_infos[3] = err_unknown.value();
    }
    for (u32 vi = 0; vi < mir.variants.len; vi++) {
        const rir::Type* payload_inner = variant_infos[vi].struct_type;
        if (!payload_inner) {
            auto i32_ty = b.make_type(rir::TypeKind::I32);
            if (!i32_ty) return frontend_error(FrontendError::OutOfMemory);
            payload_inner = i32_ty.value();
        }
        char buf[32];
        const char* prefix = "__error_variant_";
        u32 pos = 0;
        while (prefix[pos]) {
            buf[pos] = prefix[pos];
            pos++;
        }
        char tmp[10];
        u32 n = 0;
        u32 v = vi;
        if (v == 0)
            tmp[n++] = '0';
        else
            while (v > 0) {
                tmp[n++] = static_cast<char>('0' + (v % 10));
                v /= 10;
            }
        while (n > 0) buf[pos++] = tmp[--n];
        auto err_variant = make_error_info({buf, pos}, payload_inner);
        if (!err_variant) return core::make_unexpected(err_variant.error());
        error_variant_infos[vi] = err_variant.value();
    }
    for (u32 si = 0; si < mir.structs.len; si++) {
        if (!mir.structs[si].conforms_error) continue;
        auto struct_ty = b.make_type(
            rir::TypeKind::Struct, nullptr, const_cast<rir::StructDef*>(user_struct_defs[si]));
        if (!struct_ty) return frontend_error(FrontendError::OutOfMemory, mir.structs[si].span);
        char buf[64];
        const char* prefix = "__error_struct_";
        u32 pos = 0;
        while (prefix[pos]) {
            buf[pos] = prefix[pos];
            pos++;
        }
        for (u32 i = 0; i < mir.structs[si].name.len && pos < sizeof(buf); i++) {
            buf[pos++] = mir.structs[si].name.ptr[i];
        }
        auto err_struct = make_error_info({buf, pos}, struct_ty.value());
        if (!err_struct) return core::make_unexpected(err_struct.error());
        error_struct_infos[si] = err_struct.value();
    }

    for (u32 i = 0; i < mir.functions.len; i++) {
        Str name{};
        Str path{};
        if (!build_route_name(out.arena, i, &name) ||
            !copy_str(out.arena, mir.functions[i].path, &path)) {
            out.destroy();
            return frontend_error(FrontendError::OutOfMemory, mir.functions[i].span);
        }

        auto fn = b.create_function(name, path, mir.functions[i].method);
        if (!fn) {
            out.destroy();
            return frontend_error(FrontendError::OutOfMemory, mir.functions[i].span);
        }
        fn.value()->rate_limit = mir.functions[i].rate_limit;
        fn.value()->throttle_down_bps = mir.functions[i].throttle_down_bps;
        fn.value()->is_timer = mir.functions[i].is_timer;
        fn.value()->timer_interval_ms = mir.functions[i].timer_interval_ms;
        fn.value()->timer_shard = mir.functions[i].timer_shard;
        if (mir.functions[i].waits.len > 0) {
            u32 ms_list[MirFunction::kMaxWaits]{};
            u8 kind_list[MirFunction::kMaxWaits]{};
            u8 arm_mask_list[MirFunction::kMaxWaits]{};
            for (u32 wi = 0; wi < mir.functions[i].waits.len; wi++) {
                ms_list[wi] = mir.functions[i].waits[wi].ms;
                kind_list[wi] = yield_kind_abi(mir.functions[i].waits[wi].event_kind);
                arm_mask_list[wi] = mir.functions[i].waits[wi].arm_mask;
            }
            if (!b.set_yield_payload(
                    fn.value(), ms_list, mir.functions[i].waits.len, kind_list, arm_mask_list)) {
                out.destroy();
                return frontend_error(FrontendError::OutOfMemory, mir.functions[i].span);
            }
        }
        struct RecoveryScan {
            // The carrier local plus everything statically derived from it.
            // alias[k]: local k IS the carrier — a bare `let alias = value`
            // copy materializes to the same RIR value, so a presence test on
            // the alias observes the same error field as one on the carrier.
            // presence_bool[k]: bool local whose init folds to a known value
            // once the carrier is absent (`let missing = value == nil`), the
            // folded value in presence_outcome[k] — branching on it routes an
            // error exactly like branching on the presence test directly.
            struct CarrierInfo {
                bool alias[MirFunction::kMaxLocals]{};
                bool presence_bool[MirFunction::kMaxLocals]{};
                bool presence_outcome[MirFunction::kMaxLocals]{};
            };

            static bool local_ref_matches(const MirValue* value, const CarrierInfo& ci) {
                return value != nullptr && value->kind == MirValueKind::LocalRef &&
                       value->local_index < MirFunction::kMaxLocals && ci.alias[value->local_index];
            }

            // A pure rename of the carrier (`let alias = value`) — joins the
            // alias set and is NOT an observing use (nothing is read; the
            // alias materializes to the same RIR value).
            static bool is_alias_copy_init(const MirValue& init, const CarrierInfo& ci) {
                return init.kind == MirValueKind::LocalRef &&
                       init.local_index < MirFunction::kMaxLocals && ci.alias[init.local_index];
            }

            // The analyze-emitted presence test `local == nil` / `local != nil`:
            // one or more Eq wraps whose other side is a bool literal, ending
            // at HasValue(local). Its value is ABOUT presence — error uniformly
            // reads as "absent" — so like a coalescing use it consumes the
            // error in any position (a stored `let missing = x == nil`
            // included). At least one Eq wrap is required so the equality
            // lowering's internal bare HasValue shapes never match.
            static bool is_presence_test_use(const MirValue* value, const CarrierInfo& ci) {
                if (value == nullptr || value->kind != MirValueKind::Eq) return false;
                while (value != nullptr && value->kind == MirValueKind::Eq) {
                    if (value->rhs != nullptr && value->rhs->kind == MirValueKind::BoolConst)
                        value = value->lhs;
                    else if (value->lhs != nullptr && value->lhs->kind == MirValueKind::BoolConst)
                        value = value->rhs;
                    else
                        return false;
                }
                return value != nullptr && value->kind == MirValueKind::HasValue &&
                       local_ref_matches(value->lhs, ci);
            }

            // Coalescing shapes that consume the local's error inline (`x || y`,
            // `x.has ? x.value : ...`). These genuinely recover the error no
            // matter how deeply they are nested, so they are matched anywhere.
            static bool is_coalescing_use(const MirValue* value, const CarrierInfo& ci) {
                if (value == nullptr) return false;
                if (value->kind == MirValueKind::Or && local_ref_matches(value->lhs, ci))
                    return true;
                if (value->kind == MirValueKind::IfElse && value->lhs != nullptr &&
                    value->lhs->kind == MirValueKind::HasValue &&
                    local_ref_matches(value->lhs->lhs, ci) && value->rhs != nullptr &&
                    value->rhs->kind == MirValueKind::ValueOf &&
                    local_ref_matches(value->rhs->lhs, ci))
                    return true;
                return false;
            }

            // A bare usable-value test — the guard-let condition shape. It only
            // recovers the error when it IS the guard branch's condition (the
            // guard's else branch consumes the error, so the state-0 error
            // prelude must not intercept it with a generic 500). It must be
            // matched only at the top level of a branch terminator's condition:
            // equality lowering emits its own nested `HasValue(local)` to decide
            // whether to compare a fallible payload, and that internal test is
            // NOT a recovering use — treating it as one would wrongly suppress
            // the error prelude for a compare-only fallible local.
            static bool is_guard_condition(const MirValue* value, const CarrierInfo& ci) {
                // The bare guard-let shape, plus the presence-test shape
                // `local == nil` / `local != nil`: Eq nodes whose other side is
                // a bool literal only negate the bare HasValue guard, so as a
                // top-level condition they consume the error exactly the same
                // way (both branch arms know the presence outcome; nothing
                // escapes). An Eq whose sides are VALUES (an optional compare)
                // does not match — its nested HasValue stays error-masking.
                while (value != nullptr && value->kind == MirValueKind::Eq) {
                    if (value->rhs != nullptr && value->rhs->kind == MirValueKind::BoolConst)
                        value = value->lhs;
                    else if (value->lhs != nullptr && value->lhs->kind == MirValueKind::BoolConst)
                        value = value->rhs;
                    else
                        return false;
                }
                return value != nullptr && value->kind == MirValueKind::HasValue &&
                       local_ref_matches(value->lhs, ci);
            }

            // Try to fold `value` to a compile-time constant under the ERROR
            // outcome (the carrier reads as absent): HasValue(carrier/alias)
            // is false, a stored presence bool has its recorded outcome, bool
            // literals are themselves, and an Eq folds when both sides fold.
            // Returns false when the value is not determined by the carrier's
            // absence alone (then nothing may be assumed about it).
            static bool fold_error_outcome(const MirValue* value,
                                           const CarrierInfo& ci,
                                           bool* out) {
                if (value == nullptr) return false;
                if (value->kind == MirValueKind::BoolConst) {
                    *out = value->bool_value;
                    return true;
                }
                if (value->kind == MirValueKind::HasValue && local_ref_matches(value->lhs, ci)) {
                    *out = false;
                    return true;
                }
                if (value->kind == MirValueKind::LocalRef &&
                    value->local_index < MirFunction::kMaxLocals &&
                    ci.presence_bool[value->local_index]) {
                    *out = ci.presence_outcome[value->local_index];
                    return true;
                }
                if (value->kind == MirValueKind::Eq) {
                    bool lhs_value = false;
                    bool rhs_value = false;
                    if (fold_error_outcome(value->lhs, ci, &lhs_value) &&
                        fold_error_outcome(value->rhs, ci, &rhs_value)) {
                        *out = lhs_value == rhs_value;
                        return true;
                    }
                }
                // Conditional selections fold through their condition
                // (`a && b` is IfElse(a, b, false)) — and even with an
                // unknown condition, the result is known when BOTH arms fold
                // to the same value: `(a && x == nil) || x == nil` reads true
                // under the error outcome whichever way `a` went. Sound for
                // eager shapes too — select still picks one of two equal
                // values.
                if (value->kind == MirValueKind::IfElse && value->args.len == 1) {
                    bool cond_value = false;
                    if (fold_error_outcome(value->lhs, ci, &cond_value))
                        return fold_error_outcome(
                            cond_value ? value->rhs : value->args[0], ci, out);
                    bool then_value = false;
                    bool else_value = false;
                    if (fold_error_outcome(value->rhs, ci, &then_value) &&
                        fold_error_outcome(value->args[0], ci, &else_value) &&
                        then_value == else_value) {
                        *out = then_value;
                        return true;
                    }
                }
                // Coalescing `carrier || fallback` (the EAGER any/.or form —
                // both operands materialize, then select on presence): under
                // the error outcome the carrier reads absent, so the result
                // is the fallback's.
                if (value->kind == MirValueKind::Or && local_ref_matches(value->lhs, ci))
                    return fold_error_outcome(value->rhs, ci, out);
                return false;
            }

            // Result-path recovery: rec_true = every evaluation path of
            // `value` that ends with result TRUE has evaluated a construct
            // that consumes the carrier's error (presence test / coalescing
            // use); rec_false the same for FALSE results. Tracking the two
            // outcomes separately credits a test on exactly the paths that
            // ran it: in `(a && x == nil) || x == nil` the || RHS only runs
            // on paths where the LHS came out false WITHOUT having evaluated
            // the test, and those are exactly the paths the RHS then covers.
            static void recovers_on_paths(const MirValue* value,
                                          const CarrierInfo& ci,
                                          bool* rec_true,
                                          bool* rec_false) {
                *rec_true = false;
                *rec_false = false;
                if (value == nullptr) return;
                if (is_presence_test_use(value, ci) || is_coalescing_use(value, ci)) {
                    *rec_true = true;
                    *rec_false = true;
                    return;
                }
                if (value->kind == MirValueKind::BoolConst) {
                    // The impossible result side is vacuously covered.
                    *rec_true = !value->bool_value;
                    *rec_false = value->bool_value;
                    return;
                }
                if (value->kind == MirValueKind::Eq) {
                    // Bool-literal wraps only relabel the result sides.
                    if (value->rhs != nullptr && value->rhs->kind == MirValueKind::BoolConst) {
                        bool wrapped_true = false;
                        bool wrapped_false = false;
                        recovers_on_paths(value->lhs, ci, &wrapped_true, &wrapped_false);
                        *rec_true = value->rhs->bool_value ? wrapped_true : wrapped_false;
                        *rec_false = value->rhs->bool_value ? wrapped_false : wrapped_true;
                        return;
                    }
                    if (value->lhs != nullptr && value->lhs->kind == MirValueKind::BoolConst) {
                        bool wrapped_true = false;
                        bool wrapped_false = false;
                        recovers_on_paths(value->rhs, ci, &wrapped_true, &wrapped_false);
                        *rec_true = value->lhs->bool_value ? wrapped_true : wrapped_false;
                        *rec_false = value->lhs->bool_value ? wrapped_false : wrapped_true;
                        return;
                    }
                }
                if (value->kind == MirValueKind::IfElse && value->args.len == 1 &&
                    !value->is_eager_fallback && !value->is_pipe_conditional) {
                    bool cond_true = false;
                    bool cond_false = false;
                    bool then_true = false;
                    bool then_false = false;
                    bool else_true = false;
                    bool else_false = false;
                    recovers_on_paths(value->lhs, ci, &cond_true, &cond_false);
                    recovers_on_paths(value->rhs, ci, &then_true, &then_false);
                    recovers_on_paths(value->args[0], ci, &else_true, &else_false);
                    *rec_true = (cond_true || then_true) && (cond_false || else_true);
                    *rec_false = (cond_true || then_false) && (cond_false || else_false);
                    return;
                }
                // Any other node — including the EAGER Or (any/.or fallback:
                // both operands materialize before the select) — evaluates
                // its children unconditionally: a child covered on both
                // result sides covers every path.
                //
                // KNOWN PRECISION LIMIT: coverage split across SIBLING
                // children under complementary predicates — e.g.
                // `(a && x == nil) == (!a && x == nil)`, where one operand
                // recovers when `a` and the other when `!a` — is not
                // recognized: the per-child (rec_true, rec_false) pair
                // cannot express correlation through an unrelated condition;
                // that needs predicate-domain dataflow. The miss is in the
                // conservative direction only (the prelude stays: a generic
                // 500 instead of the programmed branch, never an error
                // escaping as success).
                bool child_true = false;
                bool child_false = false;
                recovers_on_paths(value->lhs, ci, &child_true, &child_false);
                if (child_true && child_false) {
                    *rec_true = true;
                    *rec_false = true;
                    return;
                }
                recovers_on_paths(value->rhs, ci, &child_true, &child_false);
                if (child_true && child_false) {
                    *rec_true = true;
                    *rec_false = true;
                    return;
                }
                for (u32 ai = 0; ai < value->args.len; ai++) {
                    recovers_on_paths(value->args[ai], ci, &child_true, &child_false);
                    if (child_true && child_false) {
                        *rec_true = true;
                        *rec_false = true;
                        return;
                    }
                }
                for (u32 fi = 0; fi < value->field_inits.len; fi++) {
                    recovers_on_paths(value->field_inits[fi].value, ci, &child_true, &child_false);
                    if (child_true && child_false) {
                        *rec_true = true;
                        *rec_false = true;
                        return;
                    }
                }
            }

            static bool recovers_on_all_paths(const MirValue* value, const CarrierInfo& ci) {
                bool rec_true = false;
                bool rec_false = false;
                recovers_on_paths(value, ci, &rec_true, &rec_false);
                return rec_true && rec_false;
            }

            // `match_presence` gates the presence-test match on whether this
            // value is guaranteed to evaluate. Local inits materialize eagerly
            // at state 0, so a presence test there always consumes the error
            // (match_presence=true). A terminator slot only evaluates if its
            // block runs — a presence test reached through a conditional
            // branch does NOT recover the error on the sibling path (the
            // sibling could return success with the error unobserved), so
            // callers pass linearly_dominated[bi] there. Coalescing keeps its
            // established match-anywhere stance.
            static bool contains_recovering_use(const MirValue* value,
                                                const CarrierInfo& ci,
                                                bool match_presence) {
                if (value == nullptr) return false;
                if (is_coalescing_use(value, ci)) return true;
                if (match_presence && is_presence_test_use(value, ci)) return true;
                // Short-circuit conditionals evaluate only their FIRST
                // operand unconditionally: `a && b` / `a || b` lower to
                // IfElse(a, ..). A presence test inside a conditionally-
                // evaluated arm is not guaranteed to run — the untaken path
                // could return success with the error live — so it must not
                // count as recovering there. The eager shapes are exempt:
                // eager-fallback IfElse and Or (any/.or) materialize every
                // operand before selecting, so a presence test in any
                // operand always runs and genuinely consumes the error.
                // Pipe-conditional stays gated (conditional evaluation).
                const bool operand_presence =
                    (value->kind == MirValueKind::IfElse && !value->is_eager_fallback)
                        ? false
                        : match_presence;
                if (contains_recovering_use(value->lhs, ci, match_presence)) return true;
                if (contains_recovering_use(value->rhs, ci, operand_presence)) return true;
                for (u32 ai = 0; ai < value->args.len; ai++) {
                    if (contains_recovering_use(value->args[ai], ci, operand_presence)) return true;
                }
                for (u32 fi = 0; fi < value->field_inits.len; fi++) {
                    if (contains_recovering_use(value->field_inits[fi].value, ci, match_presence))
                        return true;
                }
                return false;
            }

            // A use that OBSERVES the local's error without recovering it: a
            // nested `HasValue(local)` (an equality/optional test that masks the
            // error as a default value) or a bare `LocalRef(local)` reached
            // outside any recovery construct. Such a use needs the state-0 error
            // prelude so the carrier's error cannot masquerade as success — even
            // when a SIBLING branch recovers the same local via guard-let (the
            // prelude is emitted once per local, so it must be kept whenever any
            // path fails to recover). The recovery constructs — coalescing
            // `Or`/`IfElse`, the guard-narrowing `ValueOf(local)` success-path
            // unwrap, and the top-level guard condition — are NOT observing uses
            // and are skipped without descending into the recovered operands.
            static bool contains_non_recovering_use(const MirValue* value,
                                                    const CarrierInfo& ci,
                                                    bool top_level_cond) {
                if (value == nullptr) return false;
                // Coalescing `local || fallback`: the local is recovered; only
                // the fallback arm can carry a fresh observing use.
                if (value->kind == MirValueKind::Or && local_ref_matches(value->lhs, ci)) {
                    if (contains_non_recovering_use(value->rhs, ci, false)) return true;
                    for (u32 ai = 0; ai < value->args.len; ai++)
                        if (contains_non_recovering_use(value->args[ai], ci, false)) return true;
                    return false;
                }
                // Coalescing `local.has ? local.value : fallback`: recovered.
                if (value->kind == MirValueKind::IfElse && value->lhs != nullptr &&
                    value->lhs->kind == MirValueKind::HasValue &&
                    local_ref_matches(value->lhs->lhs, ci) && value->rhs != nullptr &&
                    value->rhs->kind == MirValueKind::ValueOf &&
                    local_ref_matches(value->rhs->lhs, ci)) {
                    for (u32 ai = 0; ai < value->args.len; ai++)
                        if (contains_non_recovering_use(value->args[ai], ci, false)) return true;
                    return false;
                }
                // Short-circuit operand the error path cannot evaluate:
                // `value != nil && value == 200` lowers to
                // IfElse(presence, compare, false) — under the error outcome
                // the condition folds false, the compare never runs, and the
                // else branch handles the error, so the compare must not
                // force the prelude (it cannot mask what it never sees). The
                // condition operand itself is still scanned — an equality
                // lowering's IfElse has the masking HasValue as its
                // CONDITION, so plain optional compares keep observing.
                // (Analyzer note: optional payload compares as `&&`/`||`
                // operands are rejected today, so this branch is latent
                // hardening for when they land.) Eager-fallback / pipe
                // IfElse shapes evaluate BOTH arms at runtime — the skip
                // only applies to genuine short-circuit conditionals.
                if (value->kind == MirValueKind::IfElse && value->args.len == 1 &&
                    !value->is_eager_fallback && !value->is_pipe_conditional) {
                    bool cond_value = false;
                    if (fold_error_outcome(value->lhs, ci, &cond_value)) {
                        if (contains_non_recovering_use(value->lhs, ci, false)) return true;
                        return contains_non_recovering_use(
                            cond_value ? value->rhs : value->args[0], ci, false);
                    }
                }
                // (Or gets no such skip: it is the EAGER any/.or fallback —
                // both operands materialize before the select, so every
                // operand must be scanned. The coalescing case above already
                // handled Or over this carrier.)
                // Top-level guard condition (bare HasValue or the bool-literal
                // presence-test wrap): the guard's else consumes the error.
                if (top_level_cond && is_guard_condition(value, ci)) return false;
                // A presence test in VALUE position (`let missing = x == nil`,
                // `(x == nil) == flag`) also consumes the error: its result is
                // about presence only — error reads as "absent" — and the
                // shape cannot leak the carrier's value. Nothing to descend
                // into (operands are HasValue(local) and bool literals only).
                if (is_presence_test_use(value, ci)) return false;
                // Guard-narrowing / success-path unwrap: only reached once the
                // error is already handled, so not an observing use.
                if (value->kind == MirValueKind::ValueOf && local_ref_matches(value->lhs, ci))
                    return false;
                // A nested usable-value test masks the error as a default value
                // (equality/optional compare) — that path needs the prelude.
                if (value->kind == MirValueKind::HasValue && local_ref_matches(value->lhs, ci))
                    return true;
                // A bare reference propagates/observes the error.
                if (local_ref_matches(value, ci)) return true;
                if (contains_non_recovering_use(value->lhs, ci, false)) return true;
                if (contains_non_recovering_use(value->rhs, ci, false)) return true;
                for (u32 ai = 0; ai < value->args.len; ai++)
                    if (contains_non_recovering_use(value->args[ai], ci, false)) return true;
                for (u32 fi = 0; fi < value->field_inits.len; fi++)
                    if (contains_non_recovering_use(value->field_inits[fi].value, ci, false))
                        return true;
                return false;
            }
        };
        // Cheap dominance set for unconditional entry continuations. The full
        // per-local exit analysis below additionally handles conditional paths
        // that either recover the carrier or terminate fail-closed.
        bool linearly_dominated[MirFunction::kMaxBlocks]{};
        if (mir.functions[i].blocks.len != 0) {
            linearly_dominated[0] = true;
            u32 cur = 0;
            for (u32 walk = 0; walk < mir.functions[i].blocks.len; walk++) {
                const auto& term = mir.functions[i].blocks[cur].term;
                u32 next = 0;
                bool has_next = false;
                if (term.kind == MirTerminatorKind::YieldTimer &&
                    mir.functions[i].has_explicit_resume_blocks &&
                    term.yield_next_state <= mir.functions[i].waits.len) {
                    // A `wait` yields, then resumes unconditionally at the
                    // recorded continuation block — a linear transfer.
                    next = mir.functions[i].resume_blocks[term.yield_next_state];
                    has_next = true;
                } else if (term.kind == MirTerminatorKind::Branch &&
                           term.then_block == term.else_block) {
                    // Both arms land on the same block: unconditional.
                    next = term.then_block;
                    has_next = true;
                }
                // Single-continuation conditional branches are intentionally
                // excluded here: their terminating sibling may return success.
                // The exit-aware walk below distinguishes that case from a
                // fail-closed pre-reject before a later recovery.
                if (!has_next || next >= mir.functions[i].blocks.len || linearly_dominated[next])
                    break;
                linearly_dominated[next] = true;
                cur = next;
            }
        }
        // A guard-let / if-let condition whose false/else arm consumes the
        // local's error, in a block that dominates the local's exits. Two
        // lowered shapes recover: the plain branch condition
        // (`term.cond = HasValue(local)`, from guard-let / simple if-let) and
        // the complex if-let form lowered to a match, whose usable-value test
        // lands in the match SUBJECT (`use_cmp && term.lhs = HasValue(local)`,
        // not term.cond). Both recover only at a linearly-dominated block; a
        // condition reached through a conditional branch does not (its sibling
        // arm could escape with the error unrecovered).
        // Locals derived from the carrier, in declaration order (an alias or
        // presence bool can only reference locals declared before it, so one
        // forward pass closes the sets — including chains like an alias of an
        // alias or a bool derived from a stored presence bool).
        auto build_carrier_info = [&](u32 local_index) -> RecoveryScan::CarrierInfo {
            RecoveryScan::CarrierInfo ci{};
            if (local_index < MirFunction::kMaxLocals) ci.alias[local_index] = true;
            for (u32 li = 0; li < mir.functions[i].locals.len; li++) {
                const auto& lc = mir.functions[i].locals[li];
                if (lc.ref_index >= MirFunction::kMaxLocals || lc.ref_index == local_index)
                    continue;
                if (RecoveryScan::is_alias_copy_init(lc.init, ci)) {
                    ci.alias[lc.ref_index] = true;
                    continue;
                }
                bool outcome = false;
                if (RecoveryScan::fold_error_outcome(&lc.init, ci, &outcome)) {
                    ci.presence_bool[lc.ref_index] = true;
                    ci.presence_outcome[lc.ref_index] = outcome;
                }
            }
            return ci;
        };
        auto is_dominating_recovery = [&](u32 bi, const RecoveryScan::CarrierInfo& ci) -> bool {
            if (!linearly_dominated[bi]) return false;
            const auto& term = mir.functions[i].blocks[bi].term;
            if (RecoveryScan::is_guard_condition(&term.cond, ci)) return true;
            if (term.use_cmp && RecoveryScan::is_guard_condition(&term.lhs, ci)) return true;
            return false;
        };
        // Per-local exit-dominance: every control path from entry must either
        // recover the carrier or terminate with a literal fail-closed HTTP
        // response. A 4xx/5xx pre-reject is safe without observing the carrier;
        // a 2xx/3xx, dynamic status, forward, or unknown exit is not — accepting
        // it would let an error masquerade as a successful/redirected request.
        // This subsumes the single-dominating-branch rule and recognizes split
        // recovery across sibling paths.
        auto all_error_paths_safe = [&](const RecoveryScan::CarrierInfo& ci) -> bool {
            i8 memo[MirFunction::kMaxBlocks];
            for (u32 bi = 0; bi < MirFunction::kMaxBlocks; bi++) memo[bi] = -1;
            auto rec = [&](auto&& self, u32 bi) -> bool {
                if (bi >= mir.functions[i].blocks.len) return false;
                if (memo[bi] != -1) return memo[bi] == 1;
                memo[bi] = 0;  // revisit-while-computing reads as false
                const auto& block = mir.functions[i].blocks[bi];
                const auto& term = block.term;
                bool covered = false;
                // Effects execute whenever their owning block is selected. A
                // recovering effect therefore covers this path before the
                // terminator; sibling blocks are handled independently by the
                // recursive all-paths check.
                for (u32 ei = 0; ei < block.effects.len; ei++) {
                    const u32 value_index = block.effects[ei].value_index;
                    if (value_index >= mir.functions[i].values.len) continue;
                    const auto* effect = &mir.functions[i].values[value_index];
                    if (RecoveryScan::contains_recovering_use(
                            effect, ci, /*match_presence=*/true) ||
                        RecoveryScan::recovers_on_all_paths(effect, ci)) {
                        covered = true;
                        break;
                    }
                }
                if (!covered && term.kind == MirTerminatorKind::ReturnStatus &&
                    term.source_kind == MirTerminatorSourceKind::Literal &&
                    term.status_code >= 400 && term.status_code <= 599)
                    covered = true;
                if (!covered && term.kind == MirTerminatorKind::Branch) {
                    // A match/use_cmp SUBJECT recovers the same way a plain
                    // condition does — directly guard-shaped or covered on
                    // every evaluation path.
                    if (RecoveryScan::is_guard_condition(&term.cond, ci) ||
                        RecoveryScan::recovers_on_all_paths(&term.cond, ci) ||
                        (term.use_cmp && (RecoveryScan::is_guard_condition(&term.lhs, ci) ||
                                          RecoveryScan::recovers_on_all_paths(&term.lhs, ci))))
                        covered = true;
                    else
                        covered = self(self, term.then_block) && self(self, term.else_block);
                } else if (!covered && term.kind == MirTerminatorKind::YieldTimer &&
                           mir.functions[i].has_explicit_resume_blocks &&
                           term.yield_next_state <= mir.functions[i].waits.len) {
                    covered = self(self, mir.functions[i].resume_blocks[term.yield_next_state]);
                }
                memo[bi] = covered ? 1 : 0;
                return covered;
            };
            return mir.functions[i].blocks.len > 0 && rec(rec, 0);
        };
        auto has_recovering_or_use = [&](const RecoveryScan::CarrierInfo& ci) -> bool {
            for (u32 li = 0; li < mir.functions[i].locals.len; li++) {
                // Local inits evaluate eagerly at state 0, so a presence test
                // here always runs and consumes the error (match_presence).
                if (RecoveryScan::contains_recovering_use(
                        &mir.functions[i].locals[li].init, ci, /*match_presence=*/true))
                    return true;
                // A stored path-complete expression (`let covered = a && x ==
                // nil || x == nil`) also recovers: the init evaluates eagerly
                // and every one of its evaluation paths runs a presence test,
                // even though no single unconditional operand does.
                if (RecoveryScan::recovers_on_all_paths(&mir.functions[i].locals[li].init, ci))
                    return true;
            }
            if (all_error_paths_safe(ci)) return true;
            for (u32 bi = 0; bi < mir.functions[i].blocks.len; bi++) {
                const auto& term = mir.functions[i].blocks[bi].term;
                // A top-level guard/if-let condition (plain-branch cond OR match
                // subject) counts as an unconditional recovery only when its
                // block dominates every path out of the local (linearly_dominated
                // — block 0, or a linear `wait` continuation). A condition nested
                // inside a conditional branch (`if c { guard let x = value } else
                // { ... }`) lives in a non-dominated block, so it does NOT recover
                // the error on the sibling path — keep the prelude there
                // (conservative over-keep: a spurious prelude just returns the
                // default error, a missing one lets an error masquerade as
                // success). The condition must be at the top level of its slot,
                // not nested inside an equality comparison's internal HasValue.
                if (is_dominating_recovery(bi, ci)) return true;
                // A terminator only evaluates if its block runs. A presence
                // test in a NON-dominated block (reached through a conditional
                // branch) does not recover: the sibling arm can return success
                // with the error unobserved, so it needs the same dominance
                // restriction as guard-let recovery (match_presence gates it).
                const bool presence_dominates = linearly_dominated[bi];
                if (RecoveryScan::contains_recovering_use(&term.cond, ci, presence_dominates) ||
                    RecoveryScan::contains_recovering_use(&term.lhs, ci, presence_dominates) ||
                    RecoveryScan::contains_recovering_use(&term.rhs, ci, presence_dominates))
                    return true;
            }
            return false;
        };
        // The state-0 error prelude is emitted once per local (all-or-nothing).
        // Suppress it ONLY when EVERY use of the local recovers its error;
        // if any path merely observes/masks the error (compare, bare use), the
        // prelude must stay so that path cannot fall through as success — even
        // if a sibling branch recovers the same local. Erring toward keeping is
        // safe: a spurious prelude returns the default error; a missing one lets
        // an error masquerade as success.
        auto has_non_recovering_use = [&](const RecoveryScan::CarrierInfo& ci) -> bool {
            // Blocks that may execute while the carrier still holds an
            // unhandled error (assuming the state-0 prelude were suppressed).
            // The error is live from block 0. At ANY branch the flood visits,
            // the error is live by construction — so whenever the branch
            // condition folds under the error outcome (a presence test on the
            // carrier or an alias, a stored presence bool, a guard HasValue),
            // the error provably enters exactly one arm and only that arm is
            // followed; no dominance requirement is needed for reachability
            // narrowing (unlike recovery RECOGNITION, which needs it). An
            // observing use in a block the error can never reach (an optional
            // compare in the present arm below a `x == nil` branch, say)
            // cannot mask anything and must not force the prelude back —
            // that would turn the programmed absent-arm response into a
            // generic 500. Uses in the arm the error DOES enter still count
            // (a compare there masks the error as a plain value — the
            // masquerade the prelude exists to stop), as do eager local
            // inits: both evaluate with the error live.
            bool error_reachable[MirFunction::kMaxBlocks]{};
            if (mir.functions[i].blocks.len > 0) {
                u32 stack[MirFunction::kMaxBlocks]{};
                u32 sp = 0;
                error_reachable[0] = true;
                stack[sp++] = 0;
                while (sp > 0) {
                    const u32 bi = stack[--sp];
                    const auto& term = mir.functions[i].blocks[bi].term;
                    u32 succ[2]{};
                    u32 succ_count = 0;
                    if (term.kind == MirTerminatorKind::Branch) {
                        bool err_then = true;
                        bool err_else = true;
                        bool outcome = false;
                        if (!term.use_cmp &&
                            RecoveryScan::fold_error_outcome(&term.cond, ci, &outcome)) {
                            err_then = outcome;
                            err_else = !outcome;
                        } else if (term.use_cmp && term.rhs.kind == MirValueKind::BoolConst &&
                                   RecoveryScan::fold_error_outcome(&term.lhs, ci, &outcome)) {
                            // Match-subject form: branch taken when the folded
                            // subject equals the arm's pattern.
                            err_then = outcome == term.rhs.bool_value;
                            err_else = !err_then;
                        }
                        if (err_then) succ[succ_count++] = term.then_block;
                        if (err_else) succ[succ_count++] = term.else_block;
                    } else if (term.kind == MirTerminatorKind::YieldTimer) {
                        if (mir.functions[i].has_explicit_resume_blocks &&
                            term.yield_next_state <= mir.functions[i].waits.len) {
                            succ[succ_count++] =
                                mir.functions[i].resume_blocks[term.yield_next_state];
                        } else {
                            // Resume target unknown — conservatively treat
                            // every block as error-reachable.
                            for (u32 all = 0; all < mir.functions[i].blocks.len; all++)
                                error_reachable[all] = true;
                            break;
                        }
                    }
                    for (u32 si = 0; si < succ_count; si++) {
                        if (succ[si] >= mir.functions[i].blocks.len) continue;
                        if (error_reachable[succ[si]]) continue;
                        error_reachable[succ[si]] = true;
                        stack[sp++] = succ[si];
                    }
                }
            }
            for (u32 li = 0; li < mir.functions[i].locals.len; li++) {
                // A pure alias copy is a rename, not an observation — the
                // alias set already tracks every use made through it.
                if (RecoveryScan::is_alias_copy_init(mir.functions[i].locals[li].init, ci))
                    continue;
                if (RecoveryScan::contains_non_recovering_use(
                        &mir.functions[i].locals[li].init, ci, /*top_level_cond=*/false))
                    return true;
            }
            for (u32 bi = 0; bi < mir.functions[i].blocks.len; bi++) {
                if (!error_reachable[bi]) continue;
                const auto& block = mir.functions[i].blocks[bi];
                for (u32 ei = 0; ei < block.effects.len; ei++) {
                    const u32 value_index = block.effects[ei].value_index;
                    if (value_index >= mir.functions[i].values.len) continue;
                    if (RecoveryScan::contains_non_recovering_use(
                            &mir.functions[i].values[value_index],
                            ci,
                            /*top_level_cond=*/false))
                        return true;
                }
                const auto& term = block.term;
                // The complex if-let form lowers to a match whose usable-value
                // test is the match SUBJECT (`use_cmp && term.lhs =
                // HasValue(local)`). Like a plain guard condition, that subject
                // RECOVERS the error (its false arm is the if-let else) — it is
                // not an error-masking compare — so scan term.lhs as a top-level
                // guard condition there, exactly as term.cond is treated. Any
                // genuinely observing use nested deeper is still caught (the
                // top-level skip does not propagate into operands).
                const bool lhs_is_match_subject =
                    term.use_cmp && RecoveryScan::is_guard_condition(&term.lhs, ci);
                if (RecoveryScan::contains_non_recovering_use(
                        &term.cond, ci, /*top_level_cond=*/true) ||
                    RecoveryScan::contains_non_recovering_use(
                        &term.lhs, ci, /*top_level_cond=*/lhs_is_match_subject) ||
                    RecoveryScan::contains_non_recovering_use(
                        &term.rhs, ci, /*top_level_cond=*/false))
                    return true;
            }
            return false;
        };
        auto local_needs_error_prelude = [&](const MirLocal& local) -> bool {
            if (!(local.may_error && local.init.kind == MirValueKind::IfElse &&
                  local.init.lhs != nullptr &&
                  (local.init.lhs->kind == MirValueKind::HasValue ||
                   (local.init.is_eager_fallback &&
                    local.init.lhs->kind == MirValueKind::BoolConst &&
                    local.init.lhs->bool_value)) &&
                  !local.init.is_pipe_conditional))
                return false;
            const RecoveryScan::CarrierInfo ci = build_carrier_info(local.ref_index);
            return !has_recovering_or_use(ci) || has_non_recovering_use(ci);
        };

        u32 error_local_count = 0;
        for (u32 li = 0; li < mir.functions[i].locals.len; li++) {
            if (local_needs_error_prelude(mir.functions[i].locals[li])) error_local_count++;
        }
        const bool has_error_prelude = error_local_count != 0;
        rir::BlockId prelude_block{};
        if (has_error_prelude) {
            auto block = b.create_block(fn.value(), prelude_label());
            if (!block) {
                out.destroy();
                return frontend_error(FrontendError::OutOfMemory, mir.functions[i].span);
            }
            prelude_block = block.value();
        }

        rir::BlockId block_ids[MirFunction::kMaxBlocks]{};
        for (u32 bi = 0; bi < mir.functions[i].blocks.len; bi++) {
            auto block = b.create_block(fn.value(), mir.functions[i].blocks[bi].label);
            if (!block) {
                out.destroy();
                return frontend_error(FrontendError::OutOfMemory, mir.functions[i].span);
            }
            block_ids[bi] = block.value();
        }
        if (mir.functions[i].blocks.len == 0) {
            out.destroy();
            return frontend_error(FrontendError::OutOfMemory, mir.functions[i].span);
        }
        if (mir.functions[i].has_explicit_resume_blocks) {
            if (mir.functions[i].waits.len + 1 > rir::Function::kMaxResumeBlocks) {
                out.destroy();
                return frontend_error(FrontendError::TooManyItems, mir.functions[i].span);
            }
            rir::BlockId resume_blocks[rir::Function::kMaxResumeBlocks]{};
            for (u32 ri = 0; ri <= mir.functions[i].waits.len; ri++) {
                if (mir.functions[i].resume_blocks[ri] >= mir.functions[i].blocks.len) {
                    out.destroy();
                    return frontend_error(FrontendError::UnsupportedSyntax, mir.functions[i].span);
                }
                resume_blocks[ri] = block_ids[mir.functions[i].resume_blocks[ri]];
            }
            if (has_error_prelude) resume_blocks[0] = prelude_block;
            if (!b.set_explicit_resume_blocks(
                    fn.value(), resume_blocks, mir.functions[i].waits.len + 1)) {
                out.destroy();
                return frontend_error(FrontendError::UnsupportedSyntax, mir.functions[i].span);
            }
        } else if (mir.functions[i].state_zero_enters_entry) {
            if (mir.functions[i].resume_terminal_block >= mir.functions[i].blocks.len ||
                !b.set_state_zero_entry_resume(fn.value(),
                                               block_ids[mir.functions[i].resume_terminal_block],
                                               has_error_prelude ? prelude_block : block_ids[0])) {
                out.destroy();
                return frontend_error(FrontendError::UnsupportedSyntax, mir.functions[i].span);
            }
        }
        rir::BlockId error_return_block{};
        rir::BlockId error_check_blocks[MirFunction::kMaxLocals]{};
        if (has_error_prelude) {
            auto error_block = b.create_block(fn.value(), error_return_label());
            if (!error_block) {
                out.destroy();
                return frontend_error(FrontendError::OutOfMemory, mir.functions[i].span);
            }
            error_return_block = error_block.value();
            for (u32 ei = 1; ei < error_local_count; ei++) {
                auto check_block = b.create_block(fn.value(), error_check_label());
                if (!check_block) {
                    out.destroy();
                    return frontend_error(FrontendError::OutOfMemory, mir.functions[i].span);
                }
                error_check_blocks[ei - 1] = check_block.value();
            }
        }

        b.set_insert_point(fn.value(), has_error_prelude ? prelude_block : block_ids[0]);

        rir::ValueId local_vals[MirFunction::kMaxLocals]{};
        for (u32 li = 0; li < mir.functions[i].locals.len; li++) {
            auto val = materialize_local_init(mir.functions[i].locals[li],
                                              mir,
                                              variant_infos,
                                              tuple_infos,
                                              &tuple_info_count,
                                              error_scalar_infos,
                                              error_variant_infos,
                                              error_struct_infos,
                                              error_struct_def.value(),
                                              user_struct_defs,
                                              b,
                                              local_vals,
                                              MirFunction::kMaxLocals,
                                              mir.functions[i].name,
                                              out.module.name);
            if (!val) {
                out.destroy();
                return core::make_unexpected(val.error());
            }
            local_vals[mir.functions[i].locals[li].ref_index] = val.value();
        }

        if (has_error_prelude) {
            u32 error_index = 0;
            for (u32 li = 0; li < mir.functions[i].locals.len; li++) {
                const auto& local = mir.functions[i].locals[li];
                if (!local_needs_error_prelude(local)) continue;
                if (local.ref_index >= MirFunction::kMaxLocals) {
                    out.destroy();
                    return frontend_error(FrontendError::UnsupportedSyntax, local.span);
                }
                const auto local_shape = resolved_shape(mir, local);
                auto& err_info = error_info_for(local_shape,
                                                local.error_struct_index,
                                                error_scalar_infos,
                                                error_variant_infos,
                                                error_struct_infos);
                auto err = b.emit_struct_field(local_vals[local.ref_index],
                                               error_field_name(),
                                               err_info.error_opt_type,
                                               {local.span.line, local.span.col});
                if (!err) {
                    out.destroy();
                    return frontend_error(FrontendError::OutOfMemory, local.span);
                }
                auto no_error = b.emit_opt_is_nil(err.value(), {local.span.line, local.span.col});
                if (!no_error) {
                    out.destroy();
                    return frontend_error(FrontendError::OutOfMemory, local.span);
                }
                const rir::BlockId next_block = error_index + 1 < error_local_count
                                                    ? error_check_blocks[error_index]
                                                    : block_ids[0];
                if (!b.emit_br(no_error.value(),
                               next_block,
                               error_return_block,
                               {local.span.line, local.span.col})) {
                    out.destroy();
                    return frontend_error(FrontendError::OutOfMemory, local.span);
                }
                error_index++;
                if (error_index < error_local_count)
                    b.set_insert_point(fn.value(), error_check_blocks[error_index - 1]);
            }
            b.set_insert_point(fn.value(), error_return_block);
            if (!b.emit_ret_status(500, {mir.functions[i].span.line, mir.functions[i].span.col})) {
                out.destroy();
                return frontend_error(FrontendError::OutOfMemory, mir.functions[i].span);
            }
        }

        for (u32 bi = 0; bi < mir.functions[i].blocks.len; bi++) {
            b.set_insert_point(fn.value(), block_ids[bi]);
            if (mir.functions[i].has_explicit_resume_blocks) {
                const Span store_span = mir.functions[i].blocks[bi].term.span;
                for (u32 wi = 0; wi < mir.functions[i].waits.len; wi++) {
                    if (mir.functions[i].resume_blocks[wi + 1] != bi) continue;
                    // Slot persistence is optional at runtime: some callers run
                    // handlers without frame slots by leaving ctx.slot_count==0.
                    // Codegen defends against this by guarding slot writes with
                    // the stored slot_count.
                    auto kind = b.emit_resume_event_kind({store_span.line, store_span.col});
                    if (!kind ||
                        !b.emit_ctx_store_slot_i32(
                            wait_kind_slot(wi), kind.value(), {store_span.line, store_span.col})) {
                        out.destroy();
                        return frontend_error(FrontendError::OutOfMemory, store_span);
                    }
                    auto result = b.emit_resume_event_result({store_span.line, store_span.col});
                    if (!result || !b.emit_ctx_store_slot_i32(wait_result_slot(wi),
                                                              result.value(),
                                                              {store_span.line, store_span.col})) {
                        out.destroy();
                        return frontend_error(FrontendError::OutOfMemory, store_span);
                    }
                }
            }
            for (u32 ei = 0; ei < mir.functions[i].blocks[bi].effects.len; ei++) {
                const auto& effect = mir.functions[i].blocks[bi].effects[ei];
                if (effect.value_index >= mir.functions[i].values.len) {
                    out.destroy();
                    return frontend_error(FrontendError::UnsupportedSyntax, effect.span);
                }
                auto emitted = materialize_value(mir.functions[i].values[effect.value_index],
                                                 mir,
                                                 variant_infos,
                                                 tuple_infos,
                                                 &tuple_info_count,
                                                 error_scalar_infos,
                                                 error_variant_infos,
                                                 error_struct_infos,
                                                 user_struct_defs,
                                                 b,
                                                 local_vals,
                                                 MirFunction::kMaxLocals,
                                                 effect.span);
                if (!emitted) {
                    out.destroy();
                    return core::make_unexpected(emitted.error());
                }
            }
            auto emitted = emit_term(mir.functions[i].blocks[bi].term,
                                     mir,
                                     variant_infos,
                                     tuple_infos,
                                     &tuple_info_count,
                                     error_scalar_infos,
                                     error_variant_infos,
                                     error_struct_infos,
                                     user_struct_defs,
                                     b,
                                     fn.value(),
                                     block_ids,
                                     local_vals,
                                     MirFunction::kMaxLocals);
            if (!emitted) {
                out.destroy();
                return core::make_unexpected(emitted.error());
            }
        }
    }

    return {};
}

}  // namespace rut
