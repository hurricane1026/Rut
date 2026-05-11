#include "rut/jit/codegen.h"

#include "rut/compiler/rir.h"
#include "rut/jit/handler_abi.h"
#include <atomic>
#include <cstddef>

#include <llvm-c/Core.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace rut::jit {

u32 format_handler_symbol(Str name, char* out, u32 out_size) {
    if (!out || out_size == 0) return 0;

    static constexpr char kPrefix[] = "handler_";
    u32 pos = 0;
    while (kPrefix[pos] && pos + 1 < out_size) {
        out[pos] = kPrefix[pos];
        pos++;
    }

    u32 max_pos = 0;
    if (out_size > 1) max_pos = out_size - 2;
    if (max_pos > 254) max_pos = 254;
    for (u32 i = 0; i < name.len && pos < max_pos; i++) {
        out[pos++] = name.ptr[i];
    }
    out[pos] = '\0';
    return pos;
}

// ── Codegen Context ────────────────────────────────────────────────
// Per-compilation state. Holds LLVM context, module, builder, and
// mapping tables from RIR IDs to LLVM values/blocks.

struct Ctx {
    LLVMContextRef llvm_ctx;
    LLVMModuleRef llvm_mod;
    LLVMBuilderRef builder;

    // Per-function maps (sized to function's value_cap / block_cap).
    LLVMValueRef* value_map;
    u32 value_map_cap;
    LLVMBasicBlockRef* block_map;
    u32 block_map_cap;

    // Cached LLVM types
    LLVMTypeRef i1_ty;
    LLVMTypeRef i8_ty;
    LLVMTypeRef i16_ty;
    LLVMTypeRef i32_ty;
    LLVMTypeRef i64_ty;
    LLVMTypeRef ptr_ty;
    LLVMTypeRef void_ty;

    // Str type: {ptr, i32} — matches rut::Str layout
    LLVMTypeRef str_ty;

    // Optional(Str): {i8, ptr, i32} — has_value byte + ptr + len
    LLVMTypeRef opt_str_ty;

    // Optional(I32): {i8, i32}
    LLVMTypeRef opt_i32_ty;

    // HandlerResult: i64 (packed 8-byte struct, passed as integer)
    LLVMTypeRef result_ty;

    // Handler function type: i64 (ptr, ptr, ptr, i32, ptr)
    LLVMTypeRef handler_fn_ty;

    // Current RIR function (set per-function, for type lookups).
    const rir::Function* cur_fn;

    // Function parameters (set per-function)
    LLVMValueRef param_conn;
    LLVMValueRef param_ctx;
    LLVMValueRef param_req_data;
    LLVMValueRef param_req_len;
    LLVMValueRef param_arena;

    // Lazily declared runtime helpers
    LLVMValueRef fn_req_path;
    LLVMValueRef fn_req_method;
    LLVMValueRef fn_req_header;
    LLVMValueRef fn_req_remote_addr;
    LLVMValueRef fn_str_has_prefix;
    LLVMValueRef fn_str_eq;
    LLVMValueRef fn_str_cmp;
    LLVMValueRef fn_str_regex_match;
    LLVMValueRef fn_str_trim_prefix;

    // Cache for map_type: LLVM literal structs (Optional<composite>, Struct
    // with a StructDef) are identity-compared, so emitting a fresh
    // LLVMStructTypeInContext call per lookup produces *different* LLVM types
    // for the same RIR type — breaking PHIs, selects, and other operations
    // that require exact type equality. Key by the rir::Type pointer, which
    // is arena-allocated and stable for the module's lifetime.
    static constexpr u32 kMaxCachedTypes = 256;
    struct TypeCacheEntry {
        const rir::Type* key;
        LLVMTypeRef value;
    };
    TypeCacheEntry type_cache[kMaxCachedTypes];
    u32 type_cache_count;
    u32 regex_module_id;
    u32 regex_count;
    struct RegexGlobalEntry {
        Str pattern;
        LLVMValueRef db_global;
    };
    RegexGlobalEntry* regex_globals;
    u32 regex_global_count;
    u32 regex_global_cap;

    void init_types() {
        i1_ty = LLVMInt1TypeInContext(llvm_ctx);
        i8_ty = LLVMInt8TypeInContext(llvm_ctx);
        i16_ty = LLVMInt16TypeInContext(llvm_ctx);
        i32_ty = LLVMInt32TypeInContext(llvm_ctx);
        i64_ty = LLVMInt64TypeInContext(llvm_ctx);
        ptr_ty = LLVMPointerTypeInContext(llvm_ctx, 0);
        void_ty = LLVMVoidTypeInContext(llvm_ctx);

        // Str: {ptr, i32}
        LLVMTypeRef str_fields[] = {ptr_ty, i32_ty};
        str_ty = LLVMStructTypeInContext(llvm_ctx, str_fields, 2, 0);

        // Optional(Str): {i8, ptr, i32}
        LLVMTypeRef opt_str_fields[] = {i8_ty, ptr_ty, i32_ty};
        opt_str_ty = LLVMStructTypeInContext(llvm_ctx, opt_str_fields, 3, 0);

        // Optional(I32): {i8, i32}
        LLVMTypeRef opt_i32_fields[] = {i8_ty, i32_ty};
        opt_i32_ty = LLVMStructTypeInContext(llvm_ctx, opt_i32_fields, 2, 0);

        // HandlerResult is returned as i64 (8-byte packed struct)
        result_ty = i64_ty;

        // Handler fn: i64 (ptr %conn, ptr %ctx, ptr %req_data, i32 %req_len, ptr %arena)
        LLVMTypeRef param_types[] = {ptr_ty, ptr_ty, ptr_ty, i32_ty, ptr_ty};
        handler_fn_ty = LLVMFunctionType(result_ty, param_types, 5, 0);
    }

    // ── Lazy Helper Declaration ────────────────────────────────────

    // void rut_helper_req_path(ptr, i32, ptr, ptr)
    LLVMValueRef get_req_path() {
        if (!fn_req_path) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 4, 0);
            fn_req_path = LLVMAddFunction(llvm_mod, "rut_helper_req_path", ft);
        }
        return fn_req_path;
    }

    // u8 rut_helper_req_method(ptr, i32)
    LLVMValueRef get_req_method() {
        if (!fn_req_method) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(i8_ty, params, 2, 0);
            fn_req_method = LLVMAddFunction(llvm_mod, "rut_helper_req_method", ft);
        }
        return fn_req_method;
    }

    // void rut_helper_req_header(ptr, i32, ptr, i32, ptr, ptr, ptr)
    LLVMValueRef get_req_header() {
        if (!fn_req_header) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty, ptr_ty, ptr_ty, ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 7, 0);
            fn_req_header = LLVMAddFunction(llvm_mod, "rut_helper_req_header", ft);
        }
        return fn_req_header;
    }

    // u32 rut_helper_req_remote_addr(ptr)
    LLVMValueRef get_req_remote_addr() {
        if (!fn_req_remote_addr) {
            LLVMTypeRef params[] = {ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(i32_ty, params, 1, 0);
            fn_req_remote_addr = LLVMAddFunction(llvm_mod, "rut_helper_req_remote_addr", ft);
        }
        return fn_req_remote_addr;
    }

    // u8 rut_helper_str_has_prefix(ptr, i32, ptr, i32)
    LLVMValueRef get_str_has_prefix() {
        if (!fn_str_has_prefix) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(i8_ty, params, 4, 0);
            fn_str_has_prefix = LLVMAddFunction(llvm_mod, "rut_helper_str_has_prefix", ft);
        }
        return fn_str_has_prefix;
    }

    // u8 rut_helper_str_eq(ptr, i32, ptr, i32)
    LLVMValueRef get_str_eq() {
        if (!fn_str_eq) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(i8_ty, params, 4, 0);
            fn_str_eq = LLVMAddFunction(llvm_mod, "rut_helper_str_eq", ft);
        }
        return fn_str_eq;
    }

    // i32 rut_helper_str_cmp(ptr, i32, ptr, i32)
    LLVMValueRef get_str_cmp() {
        if (!fn_str_cmp) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(i32_ty, params, 4, 0);
            fn_str_cmp = LLVMAddFunction(llvm_mod, "rut_helper_str_cmp", ft);
        }
        return fn_str_cmp;
    }

    // u8 rut_helper_str_regex_match(ptr, i32, ptr)
    LLVMValueRef get_str_regex_match() {
        if (!fn_str_regex_match) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(i8_ty, params, 3, 0);
            fn_str_regex_match = LLVMAddFunction(llvm_mod, "rut_helper_str_regex_match", ft);
        }
        return fn_str_regex_match;
    }

    // void rut_helper_str_trim_prefix(ptr, i32, ptr, i32, ptr, ptr)
    LLVMValueRef get_str_trim_prefix() {
        if (!fn_str_trim_prefix) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty, ptr_ty, ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 6, 0);
            fn_str_trim_prefix = LLVMAddFunction(llvm_mod, "rut_helper_str_trim_prefix", ft);
        }
        return fn_str_trim_prefix;
    }

    // ── RIR Type Queries ─────────────────────────────────────────────

    // Check if an RIR value has unsigned integer semantics.
    // Used to select signed vs unsigned LLVM comparison predicates.
    bool is_unsigned_operand(rir::ValueId id) const {
        if (!cur_fn || id.id >= cur_fn->value_cap) return false;
        const rir::Type* ty = cur_fn->values[id.id].type;
        if (!ty) return false;
        switch (ty->kind) {
            case rir::TypeKind::U32:
            case rir::TypeKind::U64:
            case rir::TypeKind::ByteSize:
            case rir::TypeKind::Duration:
            case rir::TypeKind::Time:
            case rir::TypeKind::StatusCode:
            case rir::TypeKind::IP:
                return true;
            default:
                return false;
        }
    }

    // ── String Globals ──────────────────────────────────────────────
    // Create a global constant from a Str (which is NOT null-terminated).
    // Returns a pointer to the first character. Uses LLVMConstStringInContext
    // with explicit length instead of LLVMBuildGlobalStringPtr (which uses strlen).
    LLVMValueRef make_global_str(Str s, const char* name) {
        // Create constant with null terminator appended (for C compatibility)
        LLVMValueRef str_const =
            LLVMConstStringInContext(llvm_ctx, s.ptr, s.len, /*DontNullTerminate=*/0);
        LLVMValueRef global = LLVMAddGlobal(llvm_mod, LLVMTypeOf(str_const), name);
        LLVMSetInitializer(global, str_const);
        LLVMSetGlobalConstant(global, 1);
        LLVMSetLinkage(global, LLVMPrivateLinkage);
        LLVMSetUnnamedAddress(global, LLVMGlobalUnnamedAddr);
        // GEP to get ptr to first char
        LLVMValueRef zero = LLVMConstInt(i32_ty, 0, 0);
        LLVMValueRef indices[] = {zero, zero};
        return LLVMBuildInBoundsGEP2(builder, LLVMTypeOf(str_const), global, indices, 2, name);
    }

    LLVMValueRef make_regex_db_load(Str pattern) {
        for (u32 i = 0; i < regex_global_count; i++) {
            const Str cached = regex_globals[i].pattern;
            if (cached.len == pattern.len &&
                (pattern.len == 0 || memcmp(cached.ptr, pattern.ptr, pattern.len) == 0)) {
                return LLVMBuildLoad2(builder, ptr_ty, regex_globals[i].db_global, "regex.db");
            }
        }

        char pattern_name[96];
        char db_name[96];
        const u32 id = regex_count++;
        snprintf(
            pattern_name, sizeof(pattern_name), "__rut_regex_pattern_%u_%u", regex_module_id, id);
        snprintf(db_name, sizeof(db_name), "__rut_regex_db_%u_%u", regex_module_id, id);

        LLVMValueRef str_const =
            LLVMConstStringInContext(llvm_ctx, pattern.ptr, pattern.len, /*DontNullTerminate=*/0);
        LLVMValueRef pattern_global = LLVMAddGlobal(llvm_mod, LLVMTypeOf(str_const), pattern_name);
        LLVMSetInitializer(pattern_global, str_const);
        LLVMSetGlobalConstant(pattern_global, 1);
        LLVMSetLinkage(pattern_global, LLVMPrivateLinkage);
        LLVMSetUnnamedAddress(pattern_global, LLVMGlobalUnnamedAddr);

        LLVMValueRef db_global = LLVMAddGlobal(llvm_mod, ptr_ty, db_name);
        LLVMSetLinkage(db_global, LLVMExternalLinkage);
        if (regex_global_count == regex_global_cap) {
            u32 new_cap = regex_global_cap ? regex_global_cap * 2 : 32;
            void* p = realloc(regex_globals, sizeof(RegexGlobalEntry) * new_cap);
            if (p) {
                regex_globals = static_cast<RegexGlobalEntry*>(p);
                regex_global_cap = new_cap;
            }
        }
        if (regex_global_count < regex_global_cap) {
            regex_globals[regex_global_count++] = {pattern, db_global};
        }
        return LLVMBuildLoad2(builder, ptr_ty, db_global, "regex.db");
    }

    // ── Value / Block access ───────────────────────────────────────

    void set_value(rir::ValueId id, LLVMValueRef val) {
        if (id.id < value_map_cap) value_map[id.id] = val;
    }

    LLVMValueRef get_value(rir::ValueId id) {
        if (id.id < value_map_cap) return value_map[id.id];
        return nullptr;
    }

    LLVMBasicBlockRef get_block(rir::BlockId id) {
        if (id.id < block_map_cap) return block_map[id.id];
        return nullptr;
    }

    // ── HandlerResult construction ─────────────────────────────────
    // Build an i64 from packed fields: {action:8, status:16, upstream:16, next_state:16,
    // yield_kind:8} Layout (little-endian byte offsets): [0]=action [1-2]=status [3-4]=upstream
    // [5-6]=next_state [7]=yield_kind

    LLVMValueRef make_result_status(u16 code) {
        // Pack: action=ReturnStatus, status_code=code, rest=0
        u64 packed = 0;
        packed |= static_cast<u64>(HandlerAction::ReturnStatus);  // action
        packed |= static_cast<u64>(code) << 8;                    // status_code
        return LLVMConstInt(i64_ty, packed, 0);
    }

    LLVMValueRef make_result_forward(u16 upstream) {
        u64 packed = 0;
        packed |= static_cast<u64>(HandlerAction::Forward);  // action
        packed |= static_cast<u64>(upstream) << 24;          // upstream_id
        return LLVMConstInt(i64_ty, packed, 0);
    }

    // Build packed HandlerResult for a Yield. Payload spans bytes 1-4
    // (status_code + upstream_id), giving 32 bits for kinds like Timer
    // where ms can exceed u16. See HandlerResult::make_yield_payload.
    LLVMValueRef make_result_yield(u16 next_state, u8 yield_kind, u32 payload) {
        u64 packed = 0;
        packed |= static_cast<u64>(HandlerAction::Yield);  // action
        packed |= static_cast<u64>(payload) << 8;          // status + upstream slots
        packed |= static_cast<u64>(next_state) << 40;      // next_state
        packed |= static_cast<u64>(yield_kind) << 56;      // yield_kind
        return LLVMConstInt(i64_ty, packed, 0);
    }

    // ── Type mapping ───────────────────────────────────────────────

    LLVMTypeRef cache_type(const rir::Type* ty, LLVMTypeRef t) {
        if (type_cache_count < kMaxCachedTypes) {
            type_cache[type_cache_count++] = {ty, t};
        }
        return t;
    }

    LLVMTypeRef map_type(const rir::Type* ty) {
        if (!ty) return void_ty;
        for (u32 i = 0; i < type_cache_count; i++) {
            if (type_cache[i].key == ty) return type_cache[i].value;
        }
        switch (ty->kind) {
            case rir::TypeKind::Void:
                return void_ty;
            case rir::TypeKind::Bool:
                return i1_ty;
            case rir::TypeKind::I32:
                return i32_ty;
            case rir::TypeKind::I64:
                return i64_ty;
            case rir::TypeKind::U32:
                return i32_ty;
            case rir::TypeKind::U64:
                return i64_ty;
            case rir::TypeKind::F64:
                return LLVMDoubleTypeInContext(llvm_ctx);
            case rir::TypeKind::Str:
                return str_ty;
            case rir::TypeKind::ByteSize:
            case rir::TypeKind::Duration:
            case rir::TypeKind::Time:
                return i64_ty;
            case rir::TypeKind::IP:
            case rir::TypeKind::StatusCode:
                return i32_ty;
            case rir::TypeKind::Method:
                return i8_ty;
            case rir::TypeKind::Optional:
                if (ty->inner && ty->inner->kind == rir::TypeKind::I32) return opt_i32_ty;
                if (ty->inner && ty->inner->kind == rir::TypeKind::Str) return opt_str_ty;
                {
                    LLVMTypeRef payload = map_type(ty->inner);
                    LLVMTypeRef fields[] = {i8_ty, payload};
                    return cache_type(ty, LLVMStructTypeInContext(llvm_ctx, fields, 2, 0));
                }
            case rir::TypeKind::Struct:
                if (ty->struct_def) {
                    auto* sd = ty->struct_def;
                    // Stack buffer capped at 16 to avoid heap/arena plumbing in
                    // the type mapper. MirStruct::kMaxFields is 8 upstream, so
                    // 16 is 2x headroom; if frontend capacity ever grows, raise
                    // this in lockstep. Trap instead of silently truncating.
                    static constexpr u32 kMaxStructFields = 16;
                    if (sd->field_count > kMaxStructFields) __builtin_trap();
                    LLVMTypeRef fields[kMaxStructFields]{};
                    for (u32 i = 0; i < sd->field_count; i++) {
                        fields[i] = map_type(sd->fields()[i].type);
                    }
                    return cache_type(
                        ty, LLVMStructTypeInContext(llvm_ctx, fields, sd->field_count, 0));
                }
                return ptr_ty;
            default:
                return ptr_ty;
        }
    }
};

// ── Instruction Emission ───────────────────────────────────────────

static void emit_instruction(Ctx& c, const rir::Instruction& inst) {
    switch (inst.op) {
        // ── Constants ──
        case rir::Opcode::ConstI32: {
            LLVMValueRef v = LLVMConstInt(c.i32_ty, static_cast<u64>(inst.imm.i32_val), 1);
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::ConstI64: {
            LLVMValueRef v = LLVMConstInt(c.i64_ty, static_cast<u64>(inst.imm.i64_val), 1);
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::ConstBool: {
            LLVMValueRef v = LLVMConstInt(c.i1_ty, inst.imm.bool_val ? 1 : 0, 0);
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::ConstStr: {
            // Create a global constant string, then build {ptr, i32} struct.
            // Uses make_global_str() with explicit length (Str is not null-terminated).
            Str s = inst.imm.str_val;
            LLVMValueRef gs = c.make_global_str(s, "str");
            LLVMValueRef len = LLVMConstInt(c.i32_ty, s.len, 0);
            LLVMValueRef strval = LLVMGetUndef(c.str_ty);
            strval = LLVMBuildInsertValue(c.builder, strval, gs, 0, "str.ptr");
            strval = LLVMBuildInsertValue(c.builder, strval, len, 1, "str.len");
            c.set_value(inst.result, strval);
            break;
        }
        case rir::Opcode::ConstDuration:
        case rir::Opcode::ConstByteSize: {
            LLVMValueRef v = LLVMConstInt(c.i64_ty, static_cast<u64>(inst.imm.i64_val), 1);
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::ConstMethod: {
            LLVMValueRef v = LLVMConstInt(c.i8_ty, inst.imm.method_val, 0);
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::ConstStatus: {
            LLVMValueRef v = LLVMConstInt(c.i32_ty, static_cast<u64>(inst.imm.i32_val), 0);
            c.set_value(inst.result, v);
            break;
        }

        // ── Request access ──
        case rir::Opcode::ReqPath: {
            // Alloca for out params, call helper, load result into Str struct.
            LLVMValueRef out_ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "path.ptr");
            LLVMValueRef out_len = LLVMBuildAlloca(c.builder, c.i32_ty, "path.len");
            LLVMValueRef args[] = {c.param_req_data, c.param_req_len, out_ptr, out_len};
            LLVMBuildCall2(
                c.builder, LLVMGlobalGetValueType(c.get_req_path()), c.get_req_path(), args, 4, "");
            LLVMValueRef p = LLVMBuildLoad2(c.builder, c.ptr_ty, out_ptr, "p");
            LLVMValueRef l = LLVMBuildLoad2(c.builder, c.i32_ty, out_len, "l");
            LLVMValueRef strval = LLVMGetUndef(c.str_ty);
            strval = LLVMBuildInsertValue(c.builder, strval, p, 0, "path.s.ptr");
            strval = LLVMBuildInsertValue(c.builder, strval, l, 1, "path.s.len");
            c.set_value(inst.result, strval);
            break;
        }
        case rir::Opcode::ReqMethod: {
            LLVMValueRef args[] = {c.param_req_data, c.param_req_len};
            LLVMValueRef v = LLVMBuildCall2(c.builder,
                                            LLVMGlobalGetValueType(c.get_req_method()),
                                            c.get_req_method(),
                                            args,
                                            2,
                                            "method");
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::ResumeEventKind: {
            LLVMValueRef off = LLVMConstInt(
                c.i32_ty, static_cast<u32>(offsetof(HandlerCtx, resume_event_kind)), 0);
            LLVMValueRef ptr =
                LLVMBuildGEP2(c.builder, c.i8_ty, c.param_ctx, &off, 1, "ev.kind.ptr");
            LLVMValueRef v = LLVMBuildLoad2(c.builder, c.i32_ty, ptr, "ev.kind");
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::ResumeEventResult: {
            LLVMValueRef off = LLVMConstInt(
                c.i32_ty, static_cast<u32>(offsetof(HandlerCtx, resume_event_result)), 0);
            LLVMValueRef ptr =
                LLVMBuildGEP2(c.builder, c.i8_ty, c.param_ctx, &off, 1, "ev.result.ptr");
            LLVMValueRef v = LLVMBuildLoad2(c.builder, c.i32_ty, ptr, "ev.result");
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::CtxLoadSlotI32: {
            const u32 slot = static_cast<u32>(inst.imm.i32_val);
            LLVMValueRef count_off =
                LLVMConstInt(c.i32_ty, static_cast<u32>(offsetof(HandlerCtx, slot_count)), 0);
            LLVMValueRef count_ptr =
                LLVMBuildGEP2(c.builder, c.i8_ty, c.param_ctx, &count_off, 1, "ctx.slot.count.ptr");
            LLVMValueRef count = LLVMBuildLoad2(c.builder, c.i32_ty, count_ptr, "ctx.slot.count");
            LLVMValueRef has_slot = LLVMBuildICmp(
                c.builder, LLVMIntUGT, count, LLVMConstInt(c.i32_ty, slot, 0), "ctx.has.slot");

            const u32 byte_offset = static_cast<u32>(sizeof(HandlerCtx)) + slot * 8u;
            LLVMValueRef off = LLVMConstInt(c.i32_ty, byte_offset, 0);
            LLVMValueRef ptr =
                LLVMBuildGEP2(c.builder, c.i8_ty, c.param_ctx, &off, 1, "ctx.slot.ptr");
            LLVMTypeRef slot_ptr_ty = LLVMPointerType(c.i32_ty, 0);
            LLVMValueRef slot_i32_ptr =
                LLVMBuildBitCast(c.builder, ptr, slot_ptr_ty, "ctx.slot.ptr32");

            LLVMValueRef fallback_ptr = nullptr;
            if ((slot & 1u) == 0) {
                LLVMValueRef kind_off = LLVMConstInt(
                    c.i32_ty, static_cast<u32>(offsetof(HandlerCtx, resume_event_kind)), 0);
                LLVMValueRef kind_ptr =
                    LLVMBuildGEP2(c.builder, c.i8_ty, c.param_ctx, &kind_off, 1, "ev.kind.ptr");
                fallback_ptr =
                    LLVMBuildBitCast(c.builder, kind_ptr, slot_ptr_ty, "ctx.slot.fallback.ptr32");
            } else {
                LLVMValueRef result_off = LLVMConstInt(
                    c.i32_ty, static_cast<u32>(offsetof(HandlerCtx, resume_event_result)), 0);
                LLVMValueRef result_ptr =
                    LLVMBuildGEP2(c.builder, c.i8_ty, c.param_ctx, &result_off, 1, "ev.result.ptr");
                fallback_ptr =
                    LLVMBuildBitCast(c.builder, result_ptr, slot_ptr_ty, "ctx.slot.fallback.ptr32");
            }
            LLVMValueRef slot_or_fallback_ptr = LLVMBuildSelect(
                c.builder, has_slot, slot_i32_ptr, fallback_ptr, "ctx.slot.ptr.sel");
            LLVMValueRef v =
                LLVMBuildLoad2(c.builder, c.i32_ty, slot_or_fallback_ptr, "ctx.slot.value");
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::ReqHeader: {
            Str name = inst.imm.str_val;
            LLVMValueRef name_ptr = c.make_global_str(name, "hdr.name");
            LLVMValueRef name_len = LLVMConstInt(c.i32_ty, name.len, 0);
            LLVMValueRef out_has = LLVMBuildAlloca(c.builder, c.i8_ty, "hdr.has");
            LLVMValueRef out_ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "hdr.ptr");
            LLVMValueRef out_len = LLVMBuildAlloca(c.builder, c.i32_ty, "hdr.len");
            LLVMValueRef args[] = {
                c.param_req_data, c.param_req_len, name_ptr, name_len, out_has, out_ptr, out_len};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_req_header()),
                           c.get_req_header(),
                           args,
                           7,
                           "");
            LLVMValueRef h = LLVMBuildLoad2(c.builder, c.i8_ty, out_has, "h");
            LLVMValueRef p = LLVMBuildLoad2(c.builder, c.ptr_ty, out_ptr, "p");
            LLVMValueRef l = LLVMBuildLoad2(c.builder, c.i32_ty, out_len, "l");
            LLVMValueRef opt = LLVMGetUndef(c.opt_str_ty);
            opt = LLVMBuildInsertValue(c.builder, opt, h, 0, "opt.has");
            opt = LLVMBuildInsertValue(c.builder, opt, p, 1, "opt.ptr");
            opt = LLVMBuildInsertValue(c.builder, opt, l, 2, "opt.len");
            c.set_value(inst.result, opt);
            break;
        }
        case rir::Opcode::ReqRemoteAddr: {
            LLVMValueRef args[] = {c.param_conn};
            LLVMValueRef v = LLVMBuildCall2(c.builder,
                                            LLVMGlobalGetValueType(c.get_req_remote_addr()),
                                            c.get_req_remote_addr(),
                                            args,
                                            1,
                                            "addr");
            c.set_value(inst.result, v);
            break;
        }

        // ── String operations ──
        case rir::Opcode::StrHasPrefix: {
            LLVMValueRef s = c.get_value(inst.operands[0]);
            LLVMValueRef pfx = c.get_value(inst.operands[1]);
            LLVMValueRef s_ptr = LLVMBuildExtractValue(c.builder, s, 0, "s.ptr");
            LLVMValueRef s_len = LLVMBuildExtractValue(c.builder, s, 1, "s.len");
            LLVMValueRef p_ptr = LLVMBuildExtractValue(c.builder, pfx, 0, "p.ptr");
            LLVMValueRef p_len = LLVMBuildExtractValue(c.builder, pfx, 1, "p.len");
            LLVMValueRef args[] = {s_ptr, s_len, p_ptr, p_len};
            LLVMValueRef r = LLVMBuildCall2(c.builder,
                                            LLVMGlobalGetValueType(c.get_str_has_prefix()),
                                            c.get_str_has_prefix(),
                                            args,
                                            4,
                                            "hp");
            // Convert u8 result to i1 for branch usage
            LLVMValueRef b =
                LLVMBuildICmp(c.builder, LLVMIntNE, r, LLVMConstInt(c.i8_ty, 0, 0), "hp.bool");
            c.set_value(inst.result, b);
            break;
        }
        case rir::Opcode::StrRegexMatch: {
            LLVMValueRef s = c.get_value(inst.operands[0]);
            LLVMValueRef s_ptr = LLVMBuildExtractValue(c.builder, s, 0, "s.ptr");
            LLVMValueRef s_len = LLVMBuildExtractValue(c.builder, s, 1, "s.len");
            LLVMValueRef db = c.make_regex_db_load(inst.imm.str_val);
            LLVMValueRef args[] = {s_ptr, s_len, db};
            LLVMValueRef fn = c.get_str_regex_match();
            LLVMValueRef r =
                LLVMBuildCall2(c.builder, LLVMGlobalGetValueType(fn), fn, args, 3, "rx");
            LLVMValueRef b =
                LLVMBuildICmp(c.builder, LLVMIntNE, r, LLVMConstInt(c.i8_ty, 0, 0), "rx.bool");
            c.set_value(inst.result, b);
            break;
        }
        case rir::Opcode::StrTrimPrefix: {
            LLVMValueRef s = c.get_value(inst.operands[0]);
            LLVMValueRef pfx = c.get_value(inst.operands[1]);
            LLVMValueRef s_ptr = LLVMBuildExtractValue(c.builder, s, 0, "s.ptr");
            LLVMValueRef s_len = LLVMBuildExtractValue(c.builder, s, 1, "s.len");
            LLVMValueRef p_ptr = LLVMBuildExtractValue(c.builder, pfx, 0, "p.ptr");
            LLVMValueRef p_len = LLVMBuildExtractValue(c.builder, pfx, 1, "p.len");
            LLVMValueRef out_ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "tp.ptr");
            LLVMValueRef out_len = LLVMBuildAlloca(c.builder, c.i32_ty, "tp.len");
            LLVMValueRef args[] = {s_ptr, s_len, p_ptr, p_len, out_ptr, out_len};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_str_trim_prefix()),
                           c.get_str_trim_prefix(),
                           args,
                           6,
                           "");
            LLVMValueRef rp = LLVMBuildLoad2(c.builder, c.ptr_ty, out_ptr, "tp.rp");
            LLVMValueRef rl = LLVMBuildLoad2(c.builder, c.i32_ty, out_len, "tp.rl");
            LLVMValueRef strval = LLVMGetUndef(c.str_ty);
            strval = LLVMBuildInsertValue(c.builder, strval, rp, 0, "tp.s.ptr");
            strval = LLVMBuildInsertValue(c.builder, strval, rl, 1, "tp.s.len");
            c.set_value(inst.result, strval);
            break;
        }

        // ── Comparisons ──
        case rir::Opcode::CmpEq:
        case rir::Opcode::CmpNe:
        case rir::Opcode::CmpLt:
        case rir::Opcode::CmpGt:
        case rir::Opcode::CmpLe:
        case rir::Opcode::CmpGe: {
            LLVMValueRef a = c.get_value(inst.operands[0]);
            LLVMValueRef b = c.get_value(inst.operands[1]);
            const rir::Type* lhs_ty = c.cur_fn && inst.operands[0].id < c.cur_fn->value_cap
                                          ? c.cur_fn->values[inst.operands[0].id].type
                                          : nullptr;
            if (lhs_ty && lhs_ty->kind == rir::TypeKind::Str) {
                LLVMValueRef a_ptr = LLVMBuildExtractValue(c.builder, a, 0, "cmp.s.a.ptr");
                LLVMValueRef a_len = LLVMBuildExtractValue(c.builder, a, 1, "cmp.s.a.len");
                LLVMValueRef b_ptr = LLVMBuildExtractValue(c.builder, b, 0, "cmp.s.b.ptr");
                LLVMValueRef b_len = LLVMBuildExtractValue(c.builder, b, 1, "cmp.s.b.len");
                LLVMValueRef args[] = {a_ptr, a_len, b_ptr, b_len};
                if (inst.op == rir::Opcode::CmpEq || inst.op == rir::Opcode::CmpNe) {
                    LLVMValueRef eq = LLVMBuildCall2(c.builder,
                                                     LLVMGlobalGetValueType(c.get_str_eq()),
                                                     c.get_str_eq(),
                                                     args,
                                                     4,
                                                     "str.eq");
                    LLVMValueRef as_bool = LLVMBuildICmp(
                        c.builder, LLVMIntNE, eq, LLVMConstInt(c.i8_ty, 0, 0), "str.eq.bool");
                    if (inst.op == rir::Opcode::CmpNe) {
                        as_bool = LLVMBuildNot(c.builder, as_bool, "str.ne.bool");
                    }
                    c.set_value(inst.result, as_bool);
                    break;
                }
                LLVMValueRef cmp = LLVMBuildCall2(c.builder,
                                                  LLVMGlobalGetValueType(c.get_str_cmp()),
                                                  c.get_str_cmp(),
                                                  args,
                                                  4,
                                                  "str.cmp");
                LLVMIntPredicate pred;
                switch (inst.op) {
                    case rir::Opcode::CmpLt:
                        pred = LLVMIntSLT;
                        break;
                    case rir::Opcode::CmpGt:
                        pred = LLVMIntSGT;
                        break;
                    case rir::Opcode::CmpLe:
                        pred = LLVMIntSLE;
                        break;
                    case rir::Opcode::CmpGe:
                        pred = LLVMIntSGE;
                        break;
                    default:
                        pred = LLVMIntEQ;
                        break;
                }
                LLVMValueRef as_bool = LLVMBuildICmp(
                    c.builder, pred, cmp, LLVMConstInt(c.i32_ty, 0, 0), "str.ord.bool");
                c.set_value(inst.result, as_bool);
                break;
            }
            // Eq/Ne are sign-agnostic. For ordered comparisons, pick
            // signed vs unsigned predicates based on the RIR operand type.
            bool uns = c.is_unsigned_operand(inst.operands[0]);
            LLVMIntPredicate pred;
            switch (inst.op) {
                case rir::Opcode::CmpEq:
                    pred = LLVMIntEQ;
                    break;
                case rir::Opcode::CmpNe:
                    pred = LLVMIntNE;
                    break;
                case rir::Opcode::CmpLt:
                    pred = uns ? LLVMIntULT : LLVMIntSLT;
                    break;
                case rir::Opcode::CmpGt:
                    pred = uns ? LLVMIntUGT : LLVMIntSGT;
                    break;
                case rir::Opcode::CmpLe:
                    pred = uns ? LLVMIntULE : LLVMIntSLE;
                    break;
                case rir::Opcode::CmpGe:
                    pred = uns ? LLVMIntUGE : LLVMIntSGE;
                    break;
                default:
                    pred = LLVMIntEQ;
                    break;
            }
            LLVMValueRef v = LLVMBuildICmp(c.builder, pred, a, b, "cmp");
            c.set_value(inst.result, v);
            break;
        }

        // ── Optional operations ──
        case rir::Opcode::OptNil: {
            LLVMTypeRef out_ty = c.map_type(c.cur_fn->values[inst.result.id].type);
            LLVMValueRef opt = LLVMGetUndef(out_ty);
            opt =
                LLVMBuildInsertValue(c.builder, opt, LLVMConstInt(c.i8_ty, 0, 0), 0, "opt.nil.has");
            if (out_ty == c.opt_i32_ty) {
                opt = LLVMBuildInsertValue(
                    c.builder, opt, LLVMConstInt(c.i32_ty, 0, 0), 1, "opt.nil.i32");
            } else if (out_ty == c.opt_str_ty) {
                opt =
                    LLVMBuildInsertValue(c.builder, opt, LLVMConstNull(c.ptr_ty), 1, "opt.nil.ptr");
                opt = LLVMBuildInsertValue(
                    c.builder, opt, LLVMConstInt(c.i32_ty, 0, 0), 2, "opt.nil.len");
            } else {
                LLVMTypeRef payload_ty = LLVMStructGetTypeAtIndex(out_ty, 1);
                opt = LLVMBuildInsertValue(
                    c.builder, opt, LLVMGetUndef(payload_ty), 1, "opt.nil.payload");
            }
            c.set_value(inst.result, opt);
            break;
        }
        case rir::Opcode::OptWrap: {
            LLVMValueRef val = c.get_value(inst.operands[0]);
            LLVMTypeRef out_ty = c.map_type(c.cur_fn->values[inst.result.id].type);
            LLVMValueRef opt = LLVMGetUndef(out_ty);
            opt = LLVMBuildInsertValue(
                c.builder, opt, LLVMConstInt(c.i8_ty, 1, 0), 0, "opt.wrap.has");
            if (out_ty == c.opt_i32_ty) {
                opt = LLVMBuildInsertValue(c.builder, opt, val, 1, "opt.wrap.i32");
            } else if (out_ty == c.opt_str_ty) {
                LLVMValueRef p = LLVMBuildExtractValue(c.builder, val, 0, "opt.wrap.ptr");
                LLVMValueRef l = LLVMBuildExtractValue(c.builder, val, 1, "opt.wrap.len");
                opt = LLVMBuildInsertValue(c.builder, opt, p, 1, "opt.wrap.ptr.set");
                opt = LLVMBuildInsertValue(c.builder, opt, l, 2, "opt.wrap.len.set");
            } else {
                opt = LLVMBuildInsertValue(c.builder, opt, val, 1, "opt.wrap.payload");
            }
            c.set_value(inst.result, opt);
            break;
        }
        case rir::Opcode::OptIsNil: {
            LLVMValueRef opt = c.get_value(inst.operands[0]);
            LLVMValueRef has = LLVMBuildExtractValue(c.builder, opt, 0, "opt.has");
            LLVMValueRef is_nil =
                LLVMBuildICmp(c.builder, LLVMIntEQ, has, LLVMConstInt(c.i8_ty, 0, 0), "is_nil");
            c.set_value(inst.result, is_nil);
            break;
        }
        case rir::Opcode::OptUnwrap: {
            LLVMValueRef opt = c.get_value(inst.operands[0]);
            LLVMTypeRef out_ty = c.map_type(c.cur_fn->values[inst.result.id].type);
            if (out_ty == c.i32_ty) {
                LLVMValueRef v = LLVMBuildExtractValue(c.builder, opt, 1, "uw.i32");
                c.set_value(inst.result, v);
            } else if (out_ty == c.str_ty) {
                LLVMValueRef p = LLVMBuildExtractValue(c.builder, opt, 1, "uw.ptr");
                LLVMValueRef l = LLVMBuildExtractValue(c.builder, opt, 2, "uw.len");
                LLVMValueRef strval = LLVMGetUndef(c.str_ty);
                strval = LLVMBuildInsertValue(c.builder, strval, p, 0, "uw.s.ptr");
                strval = LLVMBuildInsertValue(c.builder, strval, l, 1, "uw.s.len");
                c.set_value(inst.result, strval);
            } else {
                LLVMValueRef v = LLVMBuildExtractValue(c.builder, opt, 1, "uw.payload");
                c.set_value(inst.result, v);
            }
            break;
        }
        case rir::Opcode::Select: {
            LLVMValueRef cond = c.get_value(inst.operands[0]);
            LLVMValueRef then_v = c.get_value(inst.operands[1]);
            LLVMValueRef else_v = c.get_value(inst.operands[2]);
            LLVMValueRef v = LLVMBuildSelect(c.builder, cond, then_v, else_v, "sel");
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::CtxStoreSlotI32: {
            const u32 slot = static_cast<u32>(inst.imm.i32_val);
            LLVMValueRef count_off =
                LLVMConstInt(c.i32_ty, static_cast<u32>(offsetof(HandlerCtx, slot_count)), 0);
            LLVMValueRef count_ptr =
                LLVMBuildGEP2(c.builder, c.i8_ty, c.param_ctx, &count_off, 1, "ctx.slot.count.ptr");
            LLVMValueRef count = LLVMBuildLoad2(c.builder, c.i32_ty, count_ptr, "ctx.slot.count");
            LLVMValueRef has_slot = LLVMBuildICmp(
                c.builder, LLVMIntUGT, count, LLVMConstInt(c.i32_ty, slot, 0), "ctx.has.slot");

            LLVMBasicBlockRef cur_bb = LLVMGetInsertBlock(c.builder);
            LLVMValueRef fn = LLVMGetBasicBlockParent(cur_bb);
            LLVMBasicBlockRef store_bb =
                LLVMAppendBasicBlockInContext(c.llvm_ctx, fn, "ctx.slot.store");
            LLVMBasicBlockRef cont_bb =
                LLVMAppendBasicBlockInContext(c.llvm_ctx, fn, "ctx.slot.store.cont");
            LLVMBuildCondBr(c.builder, has_slot, store_bb, cont_bb);

            LLVMPositionBuilderAtEnd(c.builder, store_bb);
            const u32 byte_offset = static_cast<u32>(sizeof(HandlerCtx)) + slot * 8u;
            LLVMValueRef off = LLVMConstInt(c.i32_ty, byte_offset, 0);
            LLVMValueRef ptr =
                LLVMBuildGEP2(c.builder, c.i8_ty, c.param_ctx, &off, 1, "ctx.slot.ptr");
            LLVMTypeRef slot_ptr_ty = LLVMPointerType(c.i64_ty, 0);
            LLVMValueRef slot_ptr = LLVMBuildBitCast(c.builder, ptr, slot_ptr_ty, "ctx.slot.ptr64");
            LLVMValueRef value64 =
                LLVMBuildZExt(c.builder, c.get_value(inst.operands[0]), c.i64_ty, "ctx.slot.value");
            LLVMBuildStore(c.builder, value64, slot_ptr);
            LLVMBuildBr(c.builder, cont_bb);

            LLVMPositionBuilderAtEnd(c.builder, cont_bb);
            break;
        }
        case rir::Opcode::StructCreate: {
            LLVMTypeRef out_ty = c.map_type(c.cur_fn->values[inst.result.id].type);
            LLVMValueRef s = LLVMGetUndef(out_ty);
            for (u32 i = 0; i < inst.operand_count; i++) {
                s = LLVMBuildInsertValue(c.builder, s, c.get_value(inst.operand(i)), i, "st.ins");
            }
            c.set_value(inst.result, s);
            break;
        }
        case rir::Opcode::StructField: {
            LLVMValueRef s = c.get_value(inst.operands[0]);
            auto* struct_ty = c.cur_fn->values[inst.operands[0].id].type;
            u32 field_index =
                struct_ty && struct_ty->struct_def ? struct_ty->struct_def->field_count : 0;
            if (struct_ty && struct_ty->struct_def) {
                for (u32 i = 0; i < struct_ty->struct_def->field_count; i++) {
                    if (struct_ty->struct_def->fields()[i].name.eq(inst.imm.struct_ref.name)) {
                        field_index = i;
                        break;
                    }
                }
            }
            LLVMValueRef v = LLVMBuildExtractValue(c.builder, s, field_index, "st.field");
            c.set_value(inst.result, v);
            break;
        }

        // ── Terminators ──
        case rir::Opcode::Br: {
            LLVMValueRef cond = c.get_value(inst.operands[0]);
            LLVMBasicBlockRef then_bb = c.get_block(inst.imm.block_targets[0]);
            LLVMBasicBlockRef else_bb = c.get_block(inst.imm.block_targets[1]);
            LLVMBuildCondBr(c.builder, cond, then_bb, else_bb);
            break;
        }
        case rir::Opcode::Jmp: {
            LLVMBasicBlockRef target = c.get_block(inst.imm.block_targets[0]);
            LLVMBuildBr(c.builder, target);
            break;
        }
        case rir::Opcode::RetStatus: {
            // Pack HandlerResult as i64: action=ReturnStatus,
            // status_code in bytes 1-2 (low 16 of status slot),
            // body_idx in bytes 3-4 (the "upstream_id" slot repurposed
            // per handler ABI — 1-based index into RouteConfig's
            // response_bodies; 0 = default status-reason body),
            // headers_idx in bytes 5-6 (the "next_state" slot repurposed
            // for ReturnStatus — 1-based index into RouteConfig's
            // response_header_sets; 0 = no custom headers).
            //
            // For the operand form (runtime-value status), both idx
            // fields are always 0 because that source path doesn't
            // support custom bodies/headers today. For the literal
            // form, RIR packs all three into imm.i64_val:
            //   bits [ 0:16): status
            //   bits [16:32): body_idx
            //   bits [32:48): headers_idx — decode all three here.
            LLVMValueRef status;
            u32 body_idx_imm = 0;
            u32 headers_idx_imm = 0;
            if (inst.operand_count > 0) {
                status = c.get_value(inst.operands[0]);
                if (LLVMTypeOf(status) != c.i32_ty) {
                    status = LLVMBuildZExt(c.builder, status, c.i32_ty, "code.ext");
                }
                // Mask to 16 bits so a runtime-produced status value
                // above 0xffff can't spill into the upstream_id slot
                // (which carries the body_idx for ReturnStatus). The
                // operand form doesn't carry idx fields today.
                status = LLVMBuildAnd(
                    c.builder, status, LLVMConstInt(c.i32_ty, 0xffffu, 0), "code.mask");
            } else {
                const u64 packed = static_cast<u64>(inst.imm.i64_val);
                const u32 status_u = static_cast<u32>(packed & 0xffffu);
                body_idx_imm = static_cast<u32>((packed >> 16) & 0xffffu);
                headers_idx_imm = static_cast<u32>((packed >> 32) & 0xffffu);
                status = LLVMConstInt(c.i32_ty, status_u, 0);
            }
            LLVMValueRef action =
                LLVMConstInt(c.i64_ty, static_cast<u64>(HandlerAction::ReturnStatus), 0);
            LLVMValueRef status_ext = LLVMBuildZExt(c.builder, status, c.i64_ty, "st.ext");
            LLVMValueRef status_shifted =
                LLVMBuildShl(c.builder, status_ext, LLVMConstInt(c.i64_ty, 8, 0), "st.shl");
            LLVMValueRef result = LLVMBuildOr(c.builder, action, status_shifted, "result.st");
            if (body_idx_imm != 0) {
                LLVMValueRef body_slot =
                    LLVMConstInt(c.i64_ty, static_cast<u64>(body_idx_imm) << 24, 0);
                result = LLVMBuildOr(c.builder, result, body_slot, "result.body");
            }
            if (headers_idx_imm != 0) {
                LLVMValueRef headers_slot =
                    LLVMConstInt(c.i64_ty, static_cast<u64>(headers_idx_imm) << 40, 0);
                result = LLVMBuildOr(c.builder, result, headers_slot, "result.headers");
            }
            LLVMBuildRet(c.builder, result);
            break;
        }
        case rir::Opcode::RetForward: {
            // Pack: action=Forward, upstream_id from operand or immediate.
            LLVMValueRef upstream;
            if (inst.operand_count > 0) {
                upstream = c.get_value(inst.operands[0]);
                if (LLVMTypeOf(upstream) != c.i32_ty) {
                    upstream = LLVMBuildZExt(c.builder, upstream, c.i32_ty, "up.ext");
                }
            } else {
                upstream = LLVMConstInt(c.i32_ty, 0, 0);
            }
            LLVMValueRef action =
                LLVMConstInt(c.i64_ty, static_cast<u64>(HandlerAction::Forward), 0);
            LLVMValueRef up_ext = LLVMBuildZExt(c.builder, upstream, c.i64_ty, "up.e");
            LLVMValueRef shifted =
                LLVMBuildShl(c.builder, up_ext, LLVMConstInt(c.i64_ty, 24, 0), "up.shl");
            LLVMValueRef result = LLVMBuildOr(c.builder, action, shifted, "result");
            LLVMBuildRet(c.builder, result);
            break;
        }
        case rir::Opcode::YieldTimer: {
            const u64 packed = static_cast<u64>(inst.imm.i64_val);
            const u32 payload = static_cast<u32>(packed & 0xffffffffu);
            const u16 next_state = static_cast<u16>((packed >> 32) & 0xffffu);
            u8 yield_kind = static_cast<u8>((packed >> 48) & 0xffu);
            if (yield_kind == 0) yield_kind = static_cast<u8>(YieldKind::Timer);
            LLVMBuildRet(c.builder, c.make_result_yield(next_state, yield_kind, payload));
            break;
        }

        default:
            // Unhandled opcode in Phase 1 — emit unreachable as a placeholder.
            // The test should not exercise these paths.
            if (inst.is_terminator()) {
                LLVMBuildUnreachable(c.builder);
            }
            break;
    }
}

// ── Function Codegen ───────────────────────────────────────────────

static bool emit_function(Ctx& c, const rir::Function& fn) {
    c.cur_fn = &fn;

    // Build function name: "handler_<name>"
    char fname[256];
    format_handler_symbol(fn.name, fname, sizeof(fname));

    LLVMValueRef func = LLVMAddFunction(c.llvm_mod, fname, c.handler_fn_ty);

    // Name parameters for readability
    c.param_conn = LLVMGetParam(func, 0);
    c.param_ctx = LLVMGetParam(func, 1);
    c.param_req_data = LLVMGetParam(func, 2);
    c.param_req_len = LLVMGetParam(func, 3);
    c.param_arena = LLVMGetParam(func, 4);
    LLVMSetValueName2(c.param_conn, "conn", 4);
    LLVMSetValueName2(c.param_ctx, "ctx", 3);
    LLVMSetValueName2(c.param_req_data, "req_data", 8);
    LLVMSetValueName2(c.param_req_len, "req_len", 7);
    LLVMSetValueName2(c.param_arena, "arena", 5);

    // Reset per-function maps
    c.value_map_cap = fn.value_cap;
    c.block_map_cap = fn.block_cap;

    // Allocate maps (use alloca-style stack allocation for small functions,
    // mmap for large ones). For Phase 1, stack is fine.
    LLVMValueRef value_buf[512];
    LLVMBasicBlockRef block_buf[64];

    if (fn.value_cap > 512 || fn.block_cap > 64) return false;  // too large for Phase 1

    for (u32 i = 0; i < fn.value_cap; i++) value_buf[i] = nullptr;
    for (u32 i = 0; i < fn.block_cap; i++) block_buf[i] = nullptr;
    c.value_map = value_buf;
    c.block_map = block_buf;

    // Create all basic blocks upfront (forward references from Br/Jmp).
    for (u32 i = 0; i < fn.block_count; i++) {
        auto& blk = fn.blocks[i];
        const char* label = blk.label.ptr ? blk.label.ptr : "bb";
        c.block_map[blk.id.id] = LLVMAppendBasicBlockInContext(c.llvm_ctx, func, label);
    }

    // State-machine prologue. When the RIR function has yield points, the
    // handler is called multiple times (once per state) and the first
    // LLVM basic block dispatches on HandlerCtx::state. The default mapping
    // uses state 0..N-1 for prologue yield blocks and any later state for
    // terminal execution:
    //
    //   dispatch:
    //     switch state {
    //       0 -> yield_0   // emit Yield(next=1, payload=payload[0])
    //       1 -> yield_1   // ... up to yield_{N-1}
    //       default -> <original entry block>   // terminal state
    //     }
    //
    // Each yield_k block returns a packed Yield HandlerResult without
    // running any of the original code; the terminal state runs the
    // original RIR blocks unchanged. Single-function model — no frame
    // needed for this slice (nothing lives across the yield).
    //
    // Decorated wait routes can set state_zero_enters_entry. In that mode,
    // state 0 enters the original entry block so decorator guards run before
    // the first timer yield, yield_0 is omitted from the prologue, and
    // resumed states dispatch to the recorded terminal block by default.
    if (fn.yield_count > 0) {
        LLVMBasicBlockRef dispatch_bb = LLVMAppendBasicBlockInContext(c.llvm_ctx, func, "dispatch");
        // Move dispatch to be the first block; it will become the function's
        // entry point automatically because LLVM uses block-append order and
        // we append it AFTER the other blocks — so move it to the front.
        LLVMMoveBasicBlockBefore(dispatch_bb, c.block_map[fn.blocks[0].id.id]);

        LLVMPositionBuilderAtEnd(c.builder, dispatch_bb);
        // HandlerCtx layout: state (u16) @ offset 0.
        LLVMValueRef state = LLVMBuildLoad2(c.builder, c.i16_ty, c.param_ctx, "state");

        const u32 terminal_block_id =
            fn.has_explicit_resume_blocks
                ? fn.resume_blocks[0]
                : (fn.state_zero_enters_entry ? fn.resume_terminal_block : fn.blocks[0].id.id);
        LLVMBasicBlockRef terminal_bb = c.block_map[terminal_block_id];
        LLVMValueRef sw = LLVMBuildSwitch(
            c.builder,
            state,
            terminal_bb,
            fn.yield_count +
                ((fn.state_zero_enters_entry || fn.has_explicit_resume_blocks) ? 1 : 0));
        if (fn.has_explicit_resume_blocks) {
            for (u32 si = 0; si <= fn.yield_count && si < rir::Function::kMaxResumeBlocks; si++) {
                LLVMAddCase(sw, LLVMConstInt(c.i16_ty, si, 0), c.block_map[fn.resume_blocks[si]]);
            }
        } else if (fn.state_zero_enters_entry) {
            LLVMAddCase(sw, LLVMConstInt(c.i16_ty, 0, 0), c.block_map[fn.blocks[0].id.id]);
        }

        const u32 first_prologue_yield = fn.state_zero_enters_entry ? 1 : 0;
        for (u32 si = fn.has_explicit_resume_blocks ? fn.yield_count : first_prologue_yield;
             si < fn.yield_count;
             si++) {
            char ylabel[24];
            u32 lpos = 0;
            const char* prefix = "yield_";
            while (*prefix && lpos < sizeof(ylabel) - 1) ylabel[lpos++] = *prefix++;
            // minimal itoa for single-digit state indices; slice 0 limits wait_count <= 4
            if (si < 10) {
                ylabel[lpos++] = static_cast<char>('0' + si);
            } else {
                ylabel[lpos++] = '?';
            }
            ylabel[lpos] = 0;
            LLVMBasicBlockRef yield_bb = LLVMAppendBasicBlockInContext(c.llvm_ctx, func, ylabel);
            LLVMMoveBasicBlockBefore(yield_bb, terminal_bb);
            const u32 payload = fn.yield_payload ? fn.yield_payload[si] : 0;
            u8 yield_kind = fn.yield_kinds ? fn.yield_kinds[si] : static_cast<u8>(YieldKind::Timer);
            if (yield_kind == 0) yield_kind = static_cast<u8>(YieldKind::Timer);
            LLVMPositionBuilderAtEnd(c.builder, yield_bb);
            LLVMValueRef result =
                c.make_result_yield(static_cast<u16>(si + 1), yield_kind, payload);
            LLVMBuildRet(c.builder, result);
            LLVMAddCase(sw, LLVMConstInt(c.i16_ty, si, 0), yield_bb);
        }
    }

    // Emit instructions block by block.
    for (u32 i = 0; i < fn.block_count; i++) {
        auto& blk = fn.blocks[i];
        LLVMBasicBlockRef bb = c.block_map[blk.id.id];
        LLVMPositionBuilderAtEnd(c.builder, bb);

        for (u32 j = 0; j < blk.inst_count; j++) {
            emit_instruction(c, blk.insts[j]);
        }

        // If block has no terminator, add unreachable (shouldn't happen in valid RIR).
        if (!blk.terminator()) {
            LLVMBuildUnreachable(c.builder);
        }
    }

    return true;
}

// ── Module Codegen ─────────────────────────────────────────────────

CodegenResult codegen(const rir::Module& rir_mod) {
    static std::atomic<u32> next_regex_module_id{1};
    Ctx c{};
    c.llvm_ctx = LLVMContextCreate();
    c.llvm_mod = LLVMModuleCreateWithNameInContext(
        rir_mod.name.ptr ? rir_mod.name.ptr : "rue_module", c.llvm_ctx);
    c.builder = LLVMCreateBuilderInContext(c.llvm_ctx);

    // Zero out lazy helper pointers
    c.fn_req_path = nullptr;
    c.fn_req_method = nullptr;
    c.fn_req_header = nullptr;
    c.fn_req_remote_addr = nullptr;
    c.fn_str_has_prefix = nullptr;
    c.fn_str_eq = nullptr;
    c.fn_str_cmp = nullptr;
    c.fn_str_regex_match = nullptr;
    c.fn_str_trim_prefix = nullptr;
    c.cur_fn = nullptr;
    c.type_cache_count = 0;
    c.regex_module_id = next_regex_module_id.fetch_add(1);
    c.regex_count = 0;
    c.regex_globals = nullptr;
    c.regex_global_count = 0;
    c.regex_global_cap = 0;

    c.init_types();

    // Set target triple + data layout from host
    // (LLJIT will override, but setting these helps verification)

    bool ok = true;
    for (u32 i = 0; i < rir_mod.func_count && ok; i++) {
        ok = emit_function(c, rir_mod.functions[i]);
    }

    LLVMDisposeBuilder(c.builder);
    free(c.regex_globals);

    if (!ok) {
        LLVMDisposeModule(c.llvm_mod);
        LLVMContextDispose(c.llvm_ctx);
        return {nullptr, nullptr, false};
    }

    return {c.llvm_mod, c.llvm_ctx, true};
}

}  // namespace rut::jit
