#pragma once

#include "rut/compiler/rir.h"
#include "rut/jit/handler_abi.h"

namespace rut {
namespace rir {

inline u8 default_yield_arm_mask(u8 kind, u32 payload) {
    switch (static_cast<jit::YieldKind>(kind)) {
        case jit::YieldKind::Timer:
            return 1u << 0;
        case jit::YieldKind::Any:
            return static_cast<u8>((1u << 1) | (payload != 0 ? (1u << 0) : 0));
        case jit::YieldKind::Recv:
            return 1u << 1;
        case jit::YieldKind::Send:
            return 1u << 2;
        case jit::YieldKind::UpstreamConnect:
            return 1u << 3;
        case jit::YieldKind::UpstreamRecv:
            return 1u << 4;
        case jit::YieldKind::UpstreamSend:
            return 1u << 5;
        case jit::YieldKind::HttpGet:
        case jit::YieldKind::HttpPost:
        case jit::YieldKind::Forward:
            return 0;
    }
    return 0;
}

// ── RIR Builder ─────────────────────────────────────────────────────
// Stateful builder for constructing RIR functions. All memory is
// allocated from the module's arena — no malloc, no stdlib.
//
// All fallible operations return Expected<T, RirError>. Use the TRY()
// macro for ergonomic error propagation:
//
//   Str name = {.ptr = "handler", .len = 7};
//   auto* fn = TRY(b.create_function(name, route, method));
//   auto entry = TRY(b.create_block(fn, label));
//   b.set_insert_point(fn, entry);
//   auto v0 = TRY(b.emit_const_str(prefix));

// Convenience aliases.
template <typename T>
using Result = core::Expected<T, RirError>;
using VoidResult = core::Expected<void, RirError>;

inline auto err(RirError e) {
    return core::make_unexpected(e);
}

struct Builder {
    static constexpr u8 kDefaultYieldKind = static_cast<u8>(jit::YieldKind::Timer);

    Module* mod;

    // Current insert point — stored as index to survive grow_blocks().
    Function* cur_func;
    BlockId cur_block_id;
    Block* cur_block;

    // Interned primitive types — allocated once, reused across all emissions.
    static constexpr u32 kTypeKindCount = static_cast<u32>(TypeKind::Array) + 1;
    const Type* type_cache[kTypeKindCount];

    void init(Module* m) {
        mod = m;
        cur_func = nullptr;
        cur_block_id = kNoBlock;
        cur_block = nullptr;
        opt_i64_cache = nullptr;
        for (u32 i = 0; i < kTypeKindCount; i++) type_cache[i] = nullptr;
    }

    // ── Module-level ────────────────────────────────────────────────

    Result<StructDef*> create_struct(Str name, const FieldDef* fields, u32 count) {
        // Check capacity before allocating to avoid wasting arena space.
        if (!mod->struct_defs || mod->struct_count >= mod->struct_cap) {
            return err(RirError::CapacityFull);
        }
        auto* arena = mod->arena;
        u64 size = sizeof(StructDef) + sizeof(FieldDef) * count;
        auto* sd = static_cast<StructDef*>(arena->alloc(size));
        if (!sd) return err(RirError::OutOfMemory);
        sd->name = name;
        sd->field_count = count;
        for (u32 i = 0; i < count; i++) {
            sd->fields()[i] = fields[i];
        }
        mod->struct_defs[mod->struct_count++] = sd;
        return sd;
    }

    Result<const Type*> make_type(TypeKind kind,
                                  const Type* inner = nullptr,
                                  StructDef* sd = nullptr) {
        // Validate composite type metadata.
        if ((kind == TypeKind::Optional || kind == TypeKind::Array) && !inner) {
            return err(RirError::InvalidState);
        }
        if (kind == TypeKind::Struct && !sd) return err(RirError::InvalidState);
        // Return cached primitive type if available (no inner/struct_def).
        auto idx = static_cast<u32>(kind);
        if (!inner && !sd && idx < kTypeKindCount && type_cache[idx]) {
            return type_cache[idx];
        }
        auto* t = mod->arena->alloc_t<Type>();
        if (!t) return err(RirError::OutOfMemory);
        t->kind = kind;
        t->inner = inner;
        t->struct_def = sd;
        // Cache primitive types for reuse.
        if (!inner && !sd && idx < kTypeKindCount) {
            type_cache[idx] = t;
        }
        return static_cast<const Type*>(t);
    }

    // ── Function / Block ────────────────────────────────────────────

    Result<Function*> create_function(Str name, Str route_pattern, u8 http_method) {
        auto* arena = mod->arena;
        if (mod->func_count >= mod->func_cap) return err(RirError::CapacityFull);

        static constexpr u32 kInitBlocks = 32;
        static constexpr u32 kInitValues = 256;
        auto* blocks = arena->alloc_array<Block>(kInitBlocks);
        auto* values = arena->alloc_array<Value>(kInitValues);
        if (!blocks || !values) return err(RirError::OutOfMemory);

        auto* fn = &mod->functions[mod->func_count++];
        fn->name = name;
        fn->route_pattern = route_pattern;
        fn->http_method = http_method;
        fn->yield_count = 0;
        fn->state_zero_enters_entry = false;
        fn->state_zero_entry_block = 0;
        fn->resume_terminal_block = 0;
        fn->has_explicit_resume_blocks = false;
        for (u32 i = 0; i < Function::kMaxResumeBlocks; i++) fn->resume_blocks[i] = 0;
        fn->yield_payload = nullptr;
        fn->yield_kinds = nullptr;
        fn->yield_arm_masks = nullptr;
        fn->blocks = blocks;
        fn->block_count = 0;
        fn->block_cap = kInitBlocks;
        fn->values = values;
        fn->value_count = 0;
        fn->value_cap = kInitValues;

        return fn;
    }

    // Record the wait list for a function. After this call, fn->yield_count
    // reflects the number of state-machine yield points, and codegen can
    // consume fn->yield_payload[i] and fn->yield_kinds[i]. Explicit
    // YieldTimer terminators reuse this bookkeeping; emit_yield_timer
    // validates that the metadata table already covers its next state.
    VoidResult set_yield_payload(Function* fn,
                                 const u32* ms_list,
                                 u32 count,
                                 const u8* kind_list = nullptr,
                                 const u8* arm_mask_list = nullptr) {
        if (count == 0) {
            fn->yield_count = 0;
            fn->yield_payload = nullptr;
            fn->yield_kinds = nullptr;
            fn->yield_arm_masks = nullptr;
            return {};
        }
        auto* buf = mod->arena->alloc_array<u32>(count);
        auto* kinds = mod->arena->alloc_array<u8>(count);
        auto* arm_masks = mod->arena->alloc_array<u8>(count);
        if (!buf || !kinds || !arm_masks) return err(RirError::OutOfMemory);
        for (u32 i = 0; i < count; i++) {
            buf[i] = ms_list[i];
            kinds[i] = kind_list ? kind_list[i] : kDefaultYieldKind;
            arm_masks[i] =
                arm_mask_list ? arm_mask_list[i] : default_yield_arm_mask(kinds[i], buf[i]);
        }
        fn->yield_payload = buf;
        fn->yield_kinds = kinds;
        fn->yield_arm_masks = arm_masks;
        fn->yield_count = count;
        return {};
    }

    VoidResult set_state_zero_entry_resume(Function* fn,
                                           BlockId terminal_block,
                                           BlockId entry_block) {
        if (!fn || terminal_block.id >= fn->block_count || entry_block.id >= fn->block_count)
            return err(RirError::InvalidState);
        fn->state_zero_enters_entry = true;
        fn->state_zero_entry_block = entry_block.id;
        fn->resume_terminal_block = terminal_block.id;
        return {};
    }

    VoidResult set_explicit_resume_blocks(Function* fn, const BlockId* blocks, u32 count) {
        if (!fn || count > Function::kMaxResumeBlocks) return err(RirError::InvalidState);
        for (u32 i = 0; i < count; i++) {
            if (blocks[i].id >= fn->block_count) return err(RirError::InvalidState);
            fn->resume_blocks[i] = blocks[i].id;
        }
        for (u32 i = count; i < Function::kMaxResumeBlocks; i++) fn->resume_blocks[i] = 0;
        fn->has_explicit_resume_blocks = true;
        fn->state_zero_enters_entry = true;
        fn->state_zero_entry_block = count != 0 ? blocks[0].id : 0;
        fn->resume_terminal_block = count != 0 ? blocks[count - 1].id : 0;
        return {};
    }

    Result<BlockId> create_block(Function* fn, Str label) {
        if (fn->block_count >= fn->block_cap) {
            TRY_VOID(grow_blocks(fn));
        }

        auto* arena = mod->arena;
        static constexpr u32 kInitInsts = 32;
        auto* insts = arena->alloc_array<Instruction>(kInitInsts);
        if (!insts) return err(RirError::OutOfMemory);

        BlockId bid = {fn->block_count};
        auto* blk = &fn->blocks[fn->block_count++];
        blk->id = bid;
        blk->label = label;
        blk->insts = insts;
        blk->inst_count = 0;
        blk->inst_cap = kInitInsts;

        return bid;
    }

    void set_insert_point(Function* fn, BlockId block) {
        if (!fn || block.id >= fn->block_count) {
            cur_func = nullptr;
            cur_block_id = kNoBlock;
            cur_block = nullptr;
            return;
        }
        cur_func = fn;
        cur_block_id = block;
        cur_block = &fn->blocks[block.id];
    }

    // ── Capacity growth ───────────────────────────────────────────

    // Upper bound for doubling: cap * 2 stays within u32, with extra headroom.
    static constexpr u32 kMaxCap = 0x3FFFFFFFu;

    VoidResult grow_values(Function* fn) {
        if (fn->value_cap > kMaxCap) return err(RirError::CapacityFull);
        u32 new_cap = fn->value_cap * 2;
        auto* new_vals = mod->arena->alloc_array<Value>(new_cap);
        if (!new_vals) return err(RirError::OutOfMemory);
        for (u32 i = 0; i < fn->value_count; i++) {
            new_vals[i] = fn->values[i];
        }
        fn->values = new_vals;
        fn->value_cap = new_cap;
        return {};
    }

    VoidResult grow_insts(Block* blk) {
        if (blk->inst_cap > kMaxCap) return err(RirError::CapacityFull);
        u32 new_cap = blk->inst_cap * 2;
        auto* new_insts = mod->arena->alloc_array<Instruction>(new_cap);
        if (!new_insts) return err(RirError::OutOfMemory);
        for (u32 i = 0; i < blk->inst_count; i++) {
            new_insts[i] = blk->insts[i];
        }
        blk->insts = new_insts;
        blk->inst_cap = new_cap;
        return {};
    }

    VoidResult grow_blocks(Function* fn) {
        if (fn->block_cap > kMaxCap) return err(RirError::CapacityFull);
        u32 new_cap = fn->block_cap * 2;
        auto* new_blocks = mod->arena->alloc_array<Block>(new_cap);
        if (!new_blocks) return err(RirError::OutOfMemory);
        for (u32 i = 0; i < fn->block_count; i++) {
            new_blocks[i] = fn->blocks[i];
        }
        fn->blocks = new_blocks;
        fn->block_cap = new_cap;
        if (cur_func == fn && cur_block_id.id < fn->block_count) {
            cur_block = &fn->blocks[cur_block_id.id];
        }
        return {};
    }

    // Check that a ValueId is a valid SSA reference in the current function.
    // Note: cannot detect cross-function misuse (ValueId is a bare index by
    // design — see rir.h comment). Callers must not mix IDs across functions.
    bool valid_val(ValueId v) const {
        return v != kNoValue && cur_func && v.id < cur_func->value_count;
    }

    // Structural type equality — handles composites (Optional, Array, Struct)
    // that may have distinct Type* pointers but identical semantics.
    static bool types_equal(const Type* a, const Type* b) {
        if (a == b) return true;
        if (!a || !b || a->kind != b->kind) return false;
        if (a->kind == TypeKind::Optional || a->kind == TypeKind::Array)
            return types_equal(a->inner, b->inner);
        if (a->kind == TypeKind::Struct) return a->struct_def == b->struct_def;
        return true;  // primitives with same kind
    }

    // Check that a value has a specific type kind (for operand type enforcement).
    bool val_has_type(ValueId v, TypeKind kind) const {
        if (!valid_val(v)) return false;
        auto* ty = cur_func->values[v.id].type;
        return ty && ty->kind == kind;
    }

    // ── Instruction emission ────────────────────────────────────────

    struct EmitResult {
        Instruction* inst;
        ValueId vid;
    };

    Result<EmitResult> emit(Opcode op, const Type* result_type, SourceLoc loc) {
        if (!cur_block || !cur_func) return err(RirError::InvalidState);

        // Refuse to emit into a block that already has a terminator.
        if (cur_block->inst_count > 0) {
            auto& last = cur_block->insts[cur_block->inst_count - 1];
            if (last.is_terminator()) return err(RirError::InvalidState);
        }

        if (cur_block->inst_count >= cur_block->inst_cap) {
            TRY_VOID(grow_insts(cur_block));
        }

        ValueId vid = kNoValue;
        if (result_type) {
            if (cur_func->value_count >= cur_func->value_cap) {
                TRY_VOID(grow_values(cur_func));
            }
            vid = {cur_func->value_count};
            auto* v = &cur_func->values[cur_func->value_count++];
            v->type = result_type;
            v->def_block = cur_block_id;
            v->def_inst = cur_block->inst_count;
        }

        auto* inst = &cur_block->insts[cur_block->inst_count++];
        inst->op = op;
        inst->result = vid;
        inst->loc = loc;
        inst->operand_count = 0;
        inst->extra_operands = nullptr;
        for (u32 i = 0; i < sizeof(inst->imm); i++) {
            reinterpret_cast<u8*>(&inst->imm)[i] = 0;
        }
        return EmitResult{inst, vid};
    }

    // Roll back a previously committed emit() — used when a post-emit
    // step (e.g., set_operands) fails, to keep the IR consistent.
    void rollback_emit(const EmitResult& r) {
        if (cur_block && cur_block->inst_count > 0) cur_block->inst_count--;
        if (r.vid != kNoValue && cur_func && cur_func->value_count > 0) cur_func->value_count--;
    }

    // ── Helpers for variadic operand storage ────────────────────────

    VoidResult set_operands(Instruction* inst, const ValueId* ops, u32 count) {
        if (count > 0 && !ops) return err(RirError::InvalidState);
        for (u32 i = 0; i < count; i++) {
            if (!valid_val(ops[i])) return err(RirError::InvalidState);
        }
        if (count <= kMaxInlineOperands) {
            for (u32 i = 0; i < count; i++) inst->operands[i] = ops[i];
            inst->operand_count = count;
            return {};
        }
        u32 extra = count - kMaxInlineOperands;
        auto* extra_ops = mod->arena->alloc_array<ValueId>(extra);
        if (!extra_ops) return err(RirError::OutOfMemory);
        for (u32 i = 0; i < kMaxInlineOperands; i++) {
            inst->operands[i] = ops[i];
        }
        for (u32 i = 0; i < extra; i++) {
            extra_ops[i] = ops[kMaxInlineOperands + i];
        }
        inst->extra_operands = extra_ops;
        inst->operand_count = count;
        return {};
    }

    // ── Constants ───────────────────────────────────────────────────

    Result<ValueId> emit_const_str(Str val, SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::Str));
        auto [inst, vid] = TRY(emit(Opcode::ConstStr, ty, loc));
        inst->imm.str_val = val;
        return vid;
    }

    Result<ValueId> emit_const_i32(i32 val, SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::I32));
        auto [inst, vid] = TRY(emit(Opcode::ConstI32, ty, loc));
        inst->imm.i32_val = val;
        return vid;
    }

    Result<ValueId> emit_const_i64(i64 val, SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::I64));
        auto [inst, vid] = TRY(emit(Opcode::ConstI64, ty, loc));
        inst->imm.i64_val = val;
        return vid;
    }

    Result<ValueId> emit_const_bool(bool val, SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::Bool));
        auto [inst, vid] = TRY(emit(Opcode::ConstBool, ty, loc));
        inst->imm.bool_val = val;
        return vid;
    }

    Result<ValueId> emit_const_duration(i64 seconds, SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::Duration));
        auto [inst, vid] = TRY(emit(Opcode::ConstDuration, ty, loc));
        inst->imm.i64_val = seconds;
        return vid;
    }

    Result<ValueId> emit_const_bytesize(i64 bytes, SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::ByteSize));
        auto [inst, vid] = TRY(emit(Opcode::ConstByteSize, ty, loc));
        inst->imm.i64_val = bytes;
        return vid;
    }

    Result<ValueId> emit_const_method(u8 method, SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::Method));
        auto [inst, vid] = TRY(emit(Opcode::ConstMethod, ty, loc));
        inst->imm.method_val = method;
        return vid;
    }

    Result<ValueId> emit_const_status(i32 code, SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::StatusCode));
        auto [inst, vid] = TRY(emit(Opcode::ConstStatus, ty, loc));
        inst->imm.i32_val = code;
        return vid;
    }

    // ── Request access ──────────────────────────────────────────────

    Result<ValueId> emit_req_header(Str name, SourceLoc loc = {}) {
        auto* inner = TRY(make_type(TypeKind::Str));
        auto* ty = TRY(make_type(TypeKind::Optional, inner));
        auto [inst, vid] = TRY(emit(Opcode::ReqHeader, ty, loc));
        inst->imm.str_val = name;
        return vid;
    }

    Result<ValueId> emit_req_param(Str name, SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::Str));
        auto [inst, vid] = TRY(emit(Opcode::ReqParam, ty, loc));
        inst->imm.str_val = name;
        return vid;
    }

    Result<ValueId> emit_req_method(SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::Method));
        return TRY(emit(Opcode::ReqMethod, ty, loc)).vid;
    }

    Result<ValueId> emit_req_path(SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::Str));
        return TRY(emit(Opcode::ReqPath, ty, loc)).vid;
    }

    Result<ValueId> emit_req_path_only(SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::Str));
        return TRY(emit(Opcode::ReqPathOnly, ty, loc)).vid;
    }

    Result<ValueId> emit_req_body(SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::Str));
        return TRY(emit(Opcode::ReqBody, ty, loc)).vid;
    }

    Result<ValueId> emit_req_keep_alive(SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::Bool));
        return TRY(emit(Opcode::ReqKeepAlive, ty, loc)).vid;
    }

    Result<ValueId> emit_req_chunked(SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::Bool));
        return TRY(emit(Opcode::ReqChunked, ty, loc)).vid;
    }

    Result<ValueId> emit_req_has_content_length(SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::Bool));
        return TRY(emit(Opcode::ReqHasContentLength, ty, loc)).vid;
    }

    Result<ValueId> emit_req_http10(SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::Bool));
        return TRY(emit(Opcode::ReqHttp10, ty, loc)).vid;
    }

    Result<ValueId> emit_req_http11(SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::Bool));
        return TRY(emit(Opcode::ReqHttp11, ty, loc)).vid;
    }

    Result<ValueId> emit_req_http_version(SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::Str));
        return TRY(emit(Opcode::ReqHttpVersion, ty, loc)).vid;
    }

    Result<ValueId> emit_resume_event_kind(SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::I32));
        return TRY(emit(Opcode::ResumeEventKind, ty, loc)).vid;
    }

    Result<ValueId> emit_resume_event_result(SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::I32));
        return TRY(emit(Opcode::ResumeEventResult, ty, loc)).vid;
    }

    Result<ValueId> emit_ctx_load_slot_i32(u32 slot, SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::I32));
        auto [inst, vid] = TRY(emit(Opcode::CtxLoadSlotI32, ty, loc));
        inst->imm.i32_val = static_cast<i32>(slot);
        return vid;
    }

    Result<ValueId> emit_req_remote_addr(SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::IP));
        return TRY(emit(Opcode::ReqRemoteAddr, ty, loc)).vid;
    }

    Result<ValueId> emit_req_content_length(SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::ByteSize));
        return TRY(emit(Opcode::ReqContentLength, ty, loc)).vid;
    }

    Result<ValueId> emit_req_cookie(Str name, SourceLoc loc = {}) {
        auto* inner = TRY(make_type(TypeKind::Str));
        auto* ty = TRY(make_type(TypeKind::Optional, inner));
        auto [inst, vid] = TRY(emit(Opcode::ReqCookie, ty, loc));
        inst->imm.str_val = name;
        return vid;
    }

    Result<ValueId> emit_req_query(Str name, SourceLoc loc = {}) {
        auto* inner = TRY(make_type(TypeKind::Str));
        auto* ty = TRY(make_type(TypeKind::Optional, inner));
        auto [inst, vid] = TRY(emit(Opcode::ReqQuery, ty, loc));
        inst->imm.str_val = name;
        return vid;
    }

    Result<ValueId> emit_req_query_string(SourceLoc loc = {}) {
        auto* inner = TRY(make_type(TypeKind::Str));
        auto* ty = TRY(make_type(TypeKind::Optional, inner));
        return TRY(emit(Opcode::ReqQueryString, ty, loc)).vid;
    }

    // ── Request mutation ────────────────────────────────────────────

    VoidResult emit_req_set_header(Str name, ValueId val, SourceLoc loc = {}) {
        if (!val_has_type(val, TypeKind::Str)) return err(RirError::InvalidState);
        auto r = TRY(emit(Opcode::ReqSetHeader, nullptr, loc));
        r.inst->imm.str_val = name;
        r.inst->operands[0] = val;
        r.inst->operand_count = 1;
        return {};
    }

    VoidResult emit_req_add_header(Str name, ValueId val, SourceLoc loc = {}) {
        if (!val_has_type(val, TypeKind::Str)) return err(RirError::InvalidState);
        auto r = TRY(emit(Opcode::ReqAddHeader, nullptr, loc));
        r.inst->imm.str_val = name;
        r.inst->operands[0] = val;
        r.inst->operand_count = 1;
        return {};
    }

    Result<ValueId> emit_resp_header(Str name, ValueId fallback, SourceLoc loc = {}) {
        auto* inner = TRY(make_type(TypeKind::Str));
        auto* ty = TRY(make_type(TypeKind::Optional, inner));
        auto r = TRY(emit(Opcode::RespHeader, ty, loc));
        r.inst->imm.str_val = name;
        r.inst->operands[0] = fallback;
        r.inst->operand_count = 1;
        return r.vid;
    }

    VoidResult emit_resp_set_header(Str name, ValueId val, SourceLoc loc = {}) {
        auto r = TRY(emit(Opcode::RespSetHeader, nullptr, loc));
        r.inst->imm.str_val = name;
        r.inst->operands[0] = val;
        r.inst->operand_count = 1;
        return {};
    }

    VoidResult emit_resp_add_header(Str name, ValueId val, SourceLoc loc = {}) {
        auto r = TRY(emit(Opcode::RespAddHeader, nullptr, loc));
        r.inst->imm.str_val = name;
        r.inst->operands[0] = val;
        r.inst->operand_count = 1;
        return {};
    }

    VoidResult emit_resp_remove_header(Str name, SourceLoc loc = {}) {
        auto r = TRY(emit(Opcode::RespRemoveHeader, nullptr, loc));
        r.inst->imm.str_val = name;
        return {};
    }

    VoidResult emit_req_set_path(ValueId path, SourceLoc loc = {}) {
        if (!val_has_type(path, TypeKind::Str)) return err(RirError::InvalidState);
        auto r = TRY(emit(Opcode::ReqSetPath, nullptr, loc));
        r.inst->operands[0] = path;
        r.inst->operand_count = 1;
        return {};
    }

    VoidResult emit_ctx_store_slot_i32(u32 slot, ValueId value, SourceLoc loc = {}) {
        if (!val_has_type(value, TypeKind::I32)) return err(RirError::InvalidState);
        auto r = TRY(emit(Opcode::CtxStoreSlotI32, nullptr, loc));
        r.inst->imm.i32_val = static_cast<i32>(slot);
        r.inst->operands[0] = value;
        r.inst->operand_count = 1;
        return {};
    }

    // ── String operations ───────────────────────────────────────────

    Result<ValueId> emit_str_has_prefix(ValueId str, ValueId prefix, SourceLoc loc = {}) {
        if (!val_has_type(str, TypeKind::Str) || !val_has_type(prefix, TypeKind::Str))
            return err(RirError::InvalidState);
        auto* ty = TRY(make_type(TypeKind::Bool));
        auto [inst, vid] = TRY(emit(Opcode::StrHasPrefix, ty, loc));
        inst->operands[0] = str;
        inst->operands[1] = prefix;
        inst->operand_count = 2;
        return vid;
    }

    Result<ValueId> emit_str_trim_prefix(ValueId str, ValueId prefix, SourceLoc loc = {}) {
        if (!val_has_type(str, TypeKind::Str) || !val_has_type(prefix, TypeKind::Str))
            return err(RirError::InvalidState);
        auto* ty = TRY(make_type(TypeKind::Str));
        auto [inst, vid] = TRY(emit(Opcode::StrTrimPrefix, ty, loc));
        inst->operands[0] = str;
        inst->operands[1] = prefix;
        inst->operand_count = 2;
        return vid;
    }

    Result<ValueId> emit_str_regex_match(ValueId str, Str pattern, SourceLoc loc = {}) {
        if (!val_has_type(str, TypeKind::Str)) return err(RirError::InvalidState);
        auto* ty = TRY(make_type(TypeKind::Bool));
        auto [inst, vid] = TRY(emit(Opcode::StrRegexMatch, ty, loc));
        inst->operands[0] = str;
        inst->operand_count = 1;
        inst->imm.str_val = pattern;
        return vid;
    }

    Result<ValueId> emit_str_interpolate(const ValueId* parts, u32 count, SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::Str));
        auto r = TRY(emit(Opcode::StrInterpolate, ty, loc));
        auto ops = set_operands(r.inst, parts, count);
        if (!ops) {
            rollback_emit(r);
            return err(ops.error());
        }
        return r.vid;
    }

    // ── Comparisons ─────────────────────────────────────────────────

    static bool is_cmp_opcode(Opcode op) {
        switch (op) {
            case Opcode::CmpEq:
            case Opcode::CmpNe:
            case Opcode::CmpLt:
            case Opcode::CmpGt:
            case Opcode::CmpLe:
            case Opcode::CmpGe:
                return true;
            default:
                return false;
        }
    }

    Result<ValueId> emit_cmp(Opcode cmp_op, ValueId lhs, ValueId rhs, SourceLoc loc = {}) {
        if (!is_cmp_opcode(cmp_op) || !valid_val(lhs) || !valid_val(rhs))
            return err(RirError::InvalidState);
        // Operands must have matching types (structural comparison).
        auto* lhs_ty = cur_func->values[lhs.id].type;
        if (!types_equal(lhs_ty, cur_func->values[rhs.id].type)) return err(RirError::InvalidState);
        // Ordered comparisons (lt/gt/le/ge) only valid on orderable types.
        if (cmp_op != Opcode::CmpEq && cmp_op != Opcode::CmpNe) {
            if (!lhs_ty) return err(RirError::InvalidState);
            auto k = lhs_ty->kind;
            bool orderable = k == TypeKind::I32 || k == TypeKind::I64 || k == TypeKind::U32 ||
                             k == TypeKind::U64 || k == TypeKind::F64 || k == TypeKind::ByteSize ||
                             k == TypeKind::Duration || k == TypeKind::Time ||
                             k == TypeKind::StatusCode || k == TypeKind::Str;
            if (!orderable) return err(RirError::InvalidState);
        }
        auto* ty = TRY(make_type(TypeKind::Bool));
        auto [inst, vid] = TRY(emit(cmp_op, ty, loc));
        inst->operands[0] = lhs;
        inst->operands[1] = rhs;
        inst->operand_count = 2;
        return vid;
    }

    // ── Bitwise ─────────────────────────────────────────────────────

    static bool is_bit_opcode(Opcode op) {
        switch (op) {
            case Opcode::BitAnd:
            case Opcode::BitOr:
            case Opcode::BitXor:
            case Opcode::BitShl:
            case Opcode::BitShr:
                return true;
            default:
                return false;
        }
    }

    Result<ValueId> emit_bit(Opcode bit_op, ValueId lhs, ValueId rhs, SourceLoc loc = {}) {
        if (!is_bit_opcode(bit_op) || !valid_val(lhs) || !valid_val(rhs))
            return err(RirError::InvalidState);
        // Same-width integer operands only: both i32 or both i64 (shift
        // amounts share the operand width).
        const bool both_i32 = val_has_type(lhs, TypeKind::I32) && val_has_type(rhs, TypeKind::I32);
        const bool both_i64 = val_has_type(lhs, TypeKind::I64) && val_has_type(rhs, TypeKind::I64);
        if (!both_i32 && !both_i64) return err(RirError::InvalidState);
        auto* ty = TRY(make_type(both_i64 ? TypeKind::I64 : TypeKind::I32));
        auto [inst, vid] = TRY(emit(bit_op, ty, loc));
        inst->operands[0] = lhs;
        inst->operands[1] = rhs;
        inst->operand_count = 2;
        return vid;
    }

    // ── Arithmetic ──────────────────────────────────────────────────

    static bool is_arith_opcode(Opcode op) {
        switch (op) {
            case Opcode::Add:
            case Opcode::Sub:
            case Opcode::Mul:
            case Opcode::Div:
            case Opcode::Mod:
            case Opcode::MaxInt:
            case Opcode::MinInt:
                return true;
            default:
                return false;
        }
    }

    Result<ValueId> emit_arith(Opcode arith_op, ValueId lhs, ValueId rhs, SourceLoc loc = {}) {
        if (!is_arith_opcode(arith_op) || !valid_val(lhs) || !valid_val(rhs))
            return err(RirError::InvalidState);
        // Same-width integer operands only: both i32 or both i64.
        const bool both_i32 = val_has_type(lhs, TypeKind::I32) && val_has_type(rhs, TypeKind::I32);
        const bool both_i64 = val_has_type(lhs, TypeKind::I64) && val_has_type(rhs, TypeKind::I64);
        if (!both_i32 && !both_i64) return err(RirError::InvalidState);
        auto* ty = TRY(make_type(both_i64 ? TypeKind::I64 : TypeKind::I32));
        auto [inst, vid] = TRY(emit(arith_op, ty, loc));
        inst->operands[0] = lhs;
        inst->operands[1] = rhs;
        inst->operand_count = 2;
        return vid;
    }

    Result<ValueId> emit_sext_i64(ValueId v, SourceLoc loc = {}) {
        if (!valid_val(v) || !val_has_type(v, TypeKind::I32)) return err(RirError::InvalidState);
        auto* ty = TRY(make_type(TypeKind::I64));
        auto [inst, vid] = TRY(emit(Opcode::SextI64, ty, loc));
        inst->operands[0] = v;
        inst->operand_count = 1;
        return vid;
    }

    // ── Domain operations ───────────────────────────────────────────

    Result<ValueId> emit_time_now_micros(SourceLoc loc = {}) {
        auto* ty = TRY(make_type(TypeKind::I64));
        return TRY(emit(Opcode::TimeNowMicros, ty, loc)).vid;
    }

    Result<ValueId> emit_ip_in_cidr(ValueId ip, Str cidr_lit, SourceLoc loc = {}) {
        if (!val_has_type(ip, TypeKind::IP)) return err(RirError::InvalidState);
        auto* ty = TRY(make_type(TypeKind::Bool));
        auto [inst, vid] = TRY(emit(Opcode::IpInCidr, ty, loc));
        inst->operands[0] = ip;
        inst->operand_count = 1;
        inst->imm.str_val = cidr_lit;
        return vid;
    }

    // ── Optional operations ─────────────────────────────────────────

    Result<ValueId> emit_opt_nil(const Type* inner_type, SourceLoc loc = {}) {
        if (!inner_type) return err(RirError::InvalidState);
        auto* ty = TRY(make_type(TypeKind::Optional, inner_type));
        return TRY(emit(Opcode::OptNil, ty, loc)).vid;
    }

    Result<ValueId> emit_opt_wrap(ValueId val, SourceLoc loc = {}) {
        if (!valid_val(val)) return err(RirError::InvalidState);
        auto* inner = cur_func->values[val.id].type;
        if (!inner) return err(RirError::InvalidState);
        auto* ty = TRY(make_type(TypeKind::Optional, inner));
        auto [inst, vid] = TRY(emit(Opcode::OptWrap, ty, loc));
        inst->operands[0] = val;
        inst->operand_count = 1;
        return vid;
    }

    Result<ValueId> emit_opt_is_nil(ValueId opt, SourceLoc loc = {}) {
        if (!val_has_type(opt, TypeKind::Optional)) return err(RirError::InvalidState);
        auto* ty = TRY(make_type(TypeKind::Bool));
        auto [inst, vid] = TRY(emit(Opcode::OptIsNil, ty, loc));
        inst->operands[0] = opt;
        inst->operand_count = 1;
        return vid;
    }

    Result<ValueId> emit_select(ValueId cond,
                                ValueId then_val,
                                ValueId else_val,
                                SourceLoc loc = {}) {
        if (!val_has_type(cond, TypeKind::Bool)) return err(RirError::InvalidState);
        if (!valid_val(then_val) || !valid_val(else_val)) return err(RirError::InvalidState);
        auto* then_ty = cur_func->values[then_val.id].type;
        auto* else_ty = cur_func->values[else_val.id].type;
        if (!types_equal(then_ty, else_ty)) return err(RirError::InvalidState);
        auto [inst, vid] = TRY(emit(Opcode::Select, then_ty, loc));
        inst->operands[0] = cond;
        inst->operands[1] = then_val;
        inst->operands[2] = else_val;
        inst->operand_count = 3;
        return vid;
    }

    Result<ValueId> emit_opt_unwrap(ValueId opt, const Type* inner_type, SourceLoc loc = {}) {
        if (!valid_val(opt) || !inner_type) return err(RirError::InvalidState);
        // Verify operand is Optional and inner_type matches the payload.
        auto* opt_ty = cur_func->values[opt.id].type;
        if (!opt_ty || opt_ty->kind != TypeKind::Optional ||
            !types_equal(opt_ty->inner, inner_type))
            return err(RirError::InvalidState);
        auto [inst, vid] = TRY(emit(Opcode::OptUnwrap, inner_type, loc));
        inst->operands[0] = opt;
        inst->operand_count = 1;
        return vid;
    }

    // ── Struct operations ───────────────────────────────────────────

    Result<ValueId> emit_struct_field(ValueId s,
                                      Str field_name,
                                      const Type* field_type,
                                      SourceLoc loc = {}) {
        if (!val_has_type(s, TypeKind::Struct) || !field_type) return err(RirError::InvalidState);
        // Validate field exists in the struct definition with matching type.
        auto* s_ty = cur_func->values[s.id].type;
        if (s_ty->struct_def) {
            auto* sd = s_ty->struct_def;
            bool found = false;
            for (u32 i = 0; i < sd->field_count; i++) {
                if (sd->fields()[i].name.eq(field_name)) {
                    if (!types_equal(sd->fields()[i].type, field_type))
                        return err(RirError::InvalidState);
                    found = true;
                    break;
                }
            }
            if (!found) return err(RirError::InvalidState);
        }
        auto [inst, vid] = TRY(emit(Opcode::StructField, field_type, loc));
        inst->operands[0] = s;
        inst->operand_count = 1;
        inst->imm.struct_ref.name = field_name;
        inst->imm.struct_ref.type = field_type;
        return vid;
    }

    Result<ValueId> emit_struct_create(StructDef* sd,
                                       const ValueId* values,
                                       u32 count,
                                       SourceLoc loc = {}) {
        if (!sd || (!values && count != 0)) return err(RirError::InvalidState);
        if (count != sd->field_count) return err(RirError::InvalidState);
        for (u32 i = 0; i < count; i++) {
            if (!valid_val(values[i])) return err(RirError::InvalidState);
            auto* got = cur_func->values[values[i].id].type;
            if (!types_equal(got, sd->fields()[i].type)) return err(RirError::InvalidState);
        }
        auto* ty = TRY(make_type(TypeKind::Struct, nullptr, sd));
        auto [inst, vid] = TRY(emit(Opcode::StructCreate, ty, loc));
        inst->operand_count = count;
        if (count <= kMaxInlineOperands) {
            for (u32 i = 0; i < count; i++) inst->operands[i] = values[i];
        } else {
            inst->extra_operands = static_cast<ValueId*>(
                mod->arena->alloc(sizeof(ValueId) * (count - kMaxInlineOperands)));
            if (!inst->extra_operands) return err(RirError::OutOfMemory);
            for (u32 i = 0; i < count; i++) {
                if (i < kMaxInlineOperands)
                    inst->operands[i] = values[i];
                else
                    inst->extra_operands[i - kMaxInlineOperands] = values[i];
            }
        }
        inst->imm.struct_ref.name = sd->name;
        inst->imm.struct_ref.type = ty;
        return vid;
    }

    Result<ValueId> emit_body_parse(const Type* target_type, SourceLoc loc = {}) {
        if (!target_type) return err(RirError::InvalidState);
        auto [inst, vid] = TRY(emit(Opcode::BodyParse, target_type, loc));
        inst->imm.struct_ref.type = target_type;
        return vid;
    }

    // ── Cache state ─────────────────────────────────────────────────

    // One canonical Optional<I64> for every cache.get result: LLVM literal
    // structs are structurally uniqued so fresh types WOULD map to one LLVM
    // type, but a single rir::Type* keeps identity-based comparisons (and
    // the codegen type cache) trivially correct as well.
    const Type* opt_i64_cache = nullptr;

    Result<ValueId> emit_cache_get(u32 instance, ValueId key, SourceLoc loc = {}) {
        if (!valid_val(key) || !val_has_type(key, TypeKind::IP)) return err(RirError::InvalidState);
        if (opt_i64_cache == nullptr) {
            auto* inner = TRY(make_type(TypeKind::I64));
            opt_i64_cache = TRY(make_type(TypeKind::Optional, inner));
        }
        auto* ty = opt_i64_cache;
        auto [inst, vid] = TRY(emit(Opcode::CacheGet, ty, loc));
        inst->operands[0] = key;
        inst->operand_count = 1;
        inst->imm.i32_val = static_cast<i32>(instance);
        return vid;
    }

    Result<ValueId> emit_cache_set(u32 instance, ValueId key, ValueId value, SourceLoc loc = {}) {
        if (!valid_val(key) || !val_has_type(key, TypeKind::IP) || !valid_val(value) ||
            !val_has_type(value, TypeKind::I64))
            return err(RirError::InvalidState);
        auto* ty = TRY(make_type(TypeKind::I64));
        auto [inst, vid] = TRY(emit(Opcode::CacheSet, ty, loc));
        inst->operands[0] = key;
        inst->operands[1] = value;
        inst->operand_count = 2;
        inst->imm.i32_val = static_cast<i32>(instance);
        return vid;
    }

    // ── Terminators ─────────────────────────────────────────────────

    VoidResult emit_br(ValueId cond, BlockId then_blk, BlockId else_blk, SourceLoc loc = {}) {
        if (!cur_func || !val_has_type(cond, TypeKind::Bool)) return err(RirError::InvalidState);
        if (then_blk.id >= cur_func->block_count || else_blk.id >= cur_func->block_count) {
            return err(RirError::InvalidState);
        }
        auto r = TRY(emit(Opcode::Br, nullptr, loc));
        r.inst->operands[0] = cond;
        r.inst->operand_count = 1;
        r.inst->imm.block_targets[0] = then_blk;
        r.inst->imm.block_targets[1] = else_blk;
        return {};
    }

    VoidResult emit_jmp(BlockId target, SourceLoc loc = {}) {
        if (!cur_func) return err(RirError::InvalidState);
        if (target.id >= cur_func->block_count) return err(RirError::InvalidState);
        auto r = TRY(emit(Opcode::Jmp, nullptr, loc));
        r.inst->imm.block_targets[0] = target;
        return {};
    }

    // Literal status form. body_idx / headers_idx are 1-based indices
    // into the module's response_bodies / header_sets tables (0 = no
    // custom body / no custom headers). Status fits in 16 bits
    // (100..999), each idx fits in 16 bits. All three pack into the
    // immediate i64 slot:
    //   bits [ 0:16): status
    //   bits [16:32): body_idx
    //   bits [32:48): headers_idx
    //   bits [48:64): reserved (0)
    VoidResult emit_ret_status(i32 code,
                               SourceLoc loc = {},
                               u16 body_idx = 0,
                               u16 headers_idx = 0) {
        auto r = TRY(emit(Opcode::RetStatus, nullptr, loc));
        const u64 packed = (static_cast<u64>(code) & 0xffffu) | (static_cast<u64>(body_idx) << 16) |
                           (static_cast<u64>(headers_idx) << 32);
        r.inst->imm.i64_val = static_cast<i64>(packed);
        return {};
    }

    // Intern a response body literal into the module's table. Returns
    // a 1-based index suitable for emit_ret_status. Deduplicates
    // byte-identical literals. Returns 0 ONLY on failure (table full
    // or arena OOM) — callers should surface this as a hard error;
    // 0 does NOT mean "no custom body" (that's the absence of a
    // terminator's response_body in the first place).
    //
    // Body bytes are copied into the module's arena so entries survive
    // after the caller's source buffer (e.g. transient file-read
    // storage) goes away. Downstream consumers (RouteConfig::
    // add_response_body) still make their own copy into config-owned
    // storage, but the module is self-contained between lowering and
    // config population.
    u16 intern_response_body(Str body) {
        if (!mod || !mod->arena) return 0;
        for (u32 i = 0; i < mod->response_body_count; i++) {
            if (mod->response_bodies[i].eq(body)) return static_cast<u16>(i + 1);
        }
        if (mod->response_body_count >= Module::kMaxResponseBodies) return 0;
        char* buf = nullptr;
        if (body.len > 0) {
            buf = mod->arena->alloc_array<char>(body.len);
            if (!buf) return 0;
            for (u32 i = 0; i < body.len; i++) buf[i] = body.ptr[i];
        }
        const u32 idx = mod->response_body_count++;
        mod->response_bodies[idx] = {buf, body.len};
        return static_cast<u16>(idx + 1);
    }

    // Intern a response header set (array of {key, value} pairs) into
    // the module's flat pool. Returns a 1-based index suitable for
    // emit_ret_status; 0 means failure (sets table full, pool full,
    // or arena OOM). Dedup is by full ordered sequence — two sets
    // with the same pairs in a different order are NOT dedup'd.
    //
    // Key and value bytes are copied into the module's arena so
    // entries outlive the caller's source buffer.
    template <typename Pair>
    u16 intern_response_headers(const Pair* pairs, u32 count) {
        if (!mod || !mod->arena) return 0;
        if (count == 0) return 0;
        // Dedup: scan existing sets for an exact-sequence match.
        for (u32 i = 0; i < mod->header_set_count; i++) {
            const auto& ref = mod->header_sets[i];
            if (ref.count != count) continue;
            bool match = true;
            for (u32 j = 0; j < count; j++) {
                if (!mod->header_keys[ref.offset + j].eq(pairs[j].key) ||
                    !mod->header_values[ref.offset + j].eq(pairs[j].value)) {
                    match = false;
                    break;
                }
            }
            if (match) return static_cast<u16>(i + 1);
        }
        if (mod->header_set_count >= Module::kMaxHeaderSets) return 0;
        // Subtraction-safe capacity check for the flat pool.
        if (count > Module::kMaxHeaderPoolEntries - mod->header_pool_used) return 0;
        const u16 offset = static_cast<u16>(mod->header_pool_used);
        for (u32 j = 0; j < count; j++) {
            auto copy_into_arena = [&](Str s) -> Str {
                if (s.len == 0) return {nullptr, 0};
                char* buf = mod->arena->template alloc_array<char>(s.len);
                if (!buf) return {nullptr, 0xffffffffu};  // sentinel for failure
                for (u32 k = 0; k < s.len; k++) buf[k] = s.ptr[k];
                return {buf, s.len};
            };
            const Str k = copy_into_arena(pairs[j].key);
            if (k.len == 0xffffffffu) return 0;
            const Str v = copy_into_arena(pairs[j].value);
            if (v.len == 0xffffffffu) return 0;
            mod->header_keys[offset + j] = k;
            mod->header_values[offset + j] = v;
        }
        mod->header_pool_used += count;
        const u32 idx = mod->header_set_count++;
        mod->header_sets[idx] = {offset, static_cast<u16>(count)};
        return static_cast<u16>(idx + 1);
    }

    // Runtime-value form: status code is read from a SSA value (e.g. result
    // of a decorator call) instead of a compile-time literal. Codegen reads
    // the value via inst.operands[0] (see codegen.cc RetStatus handling).
    VoidResult emit_ret_status(ValueId code, SourceLoc loc = {}) {
        if (!valid_val(code)) return err(RirError::InvalidState);
        auto r = TRY(emit(Opcode::RetStatus, nullptr, loc));
        r.inst->operands[0] = code;
        r.inst->operand_count = 1;
        return {};
    }

    VoidResult emit_ret_forward(ValueId upstream, SourceLoc loc = {}) {
        if (!valid_val(upstream)) return err(RirError::InvalidState);
        // Upstream operand must be an integer type (upstream id).
        if (!val_has_type(upstream, TypeKind::I32) && !val_has_type(upstream, TypeKind::U32))
            return err(RirError::InvalidState);
        auto r = TRY(emit(Opcode::RetForward, nullptr, loc));
        r.inst->operands[0] = upstream;
        r.inst->operand_count = 1;
        return {};
    }

    // ── Yields (I/O suspend points) ────────────────────────────────

    Result<ValueId> emit_yield_http_get(Str url, ValueId headers, SourceLoc loc = {}) {
        // Validate headers before emit() to avoid phantom instructions.
        if (headers != kNoValue && !valid_val(headers)) return err(RirError::InvalidState);
        auto* ty = TRY(make_type(TypeKind::Str));
        auto [inst, vid] = TRY(emit(Opcode::YieldHttpGet, ty, loc));
        inst->imm.str_val = url;
        if (headers != kNoValue) {
            inst->operands[0] = headers;
            inst->operand_count = 1;
        }
        cur_func->yield_count++;
        return vid;
    }

    VoidResult emit_yield_timer(u32 ms, u16 next_state, SourceLoc loc = {}) {
        return emit_yield_event(kDefaultYieldKind, ms, next_state, loc);
    }

    VoidResult emit_yield_event(u8 kind, u32 payload, u16 next_state, SourceLoc loc = {}) {
        if (!cur_func) return err(RirError::InvalidState);
        if (cur_func->yield_count == 0 || next_state == 0 || next_state > cur_func->yield_count)
            return err(RirError::InvalidState);
        auto r = TRY(emit(Opcode::YieldTimer, nullptr, loc));
        r.inst->imm.i64_val = (static_cast<i64>(kind) << 48) |
                              (static_cast<i64>(next_state) << 32) | static_cast<i64>(payload);
        return {};
    }
};

}  // namespace rir
}  // namespace rut
