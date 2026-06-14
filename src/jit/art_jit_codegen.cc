/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

// ART JIT specialization codegen.
//
// Walks the populated ArtTrie depth-first and emits an LLVM IR
// function that decides match() entirely via constant-folded
// per-node blocks. No runtime type switch, no children-array load:
// every node's type/edge bytes/terminals are baked in as IR
// constants. The compiled function is structurally equivalent to a
// hand-written monomorphic state machine for THIS specific trie
// shape — with the additional advantage that edge bytes are
// immediate operands rather than memory loads.
//
// Function signature:
//   u16 match(const char* canon_ptr, u32 canon_len, u8 method)
//
// Input contract: arguments are already canonical (no leading '/',
// no trailing '/', no '?'/'#'). Canon was lifted out of the IR and
// into the HTTP parser's URI SIMD scan — see route_canon.h. The JIT
// body is therefore pure trie descent with no canon stage.
//
// Generated stages:
//   1. Route-method key → slot-index translation (matches method_slot()
//      from route_trie.h). Unknown methods short-circuit to
//      kInvalidRoute.
//   2. Recursive descent emitter — depth-first walk over ArtTrie
//      nodes, each emits its own basic block(s) with constants
//      baked from the C++ trie state.

#include "rut/jit/art_jit_codegen.h"

#include "rut/jit/jit_engine.h"
#include "rut/runtime/route_art.h"

#include <llvm-c/Core.h>
#include <unistd.h>  // write (error logging)

namespace rut::jit {

namespace {

// Tiny error-print helper — matches jit_engine.cc style (no stdlib).
void log_err(const char* msg) {
    int len = 0;
    while (msg[len]) len++;
    (void)::write(2, msg, len);
    (void)::write(2, "\n", 1);
}

// Per-emission state. The builder is positioned-and-repositioned
// across blocks as we walk the trie.
struct EmitCtx {
    LLVMContextRef ctx;
    LLVMModuleRef mod;
    LLVMBuilderRef builder;
    LLVMValueRef fn;

    // Function args. The JIT'd function expects CANONICAL input —
    // canonicalization is lifted out to RouteConfig::match (PR #50
    // round 6). eff_ptr / eff_len just alias the function args; the
    // names are kept for code-clarity of the descent logic.
    LLVMValueRef eff_ptr;
    LLVMValueRef eff_len;

    // Per-call method slot: result of mapping method key → 0..9.
    // Unknown methods produce kMethodSlotInvalid — we short-circuit
    // to return_invalid_bb in that case so the descent never runs.
    LLVMValueRef method_slot;

    // Allocas
    LLVMValueRef best_alloca;  // i16

    // Block emit-end-points
    LLVMBasicBlockRef return_best_bb;     // descent miss/break — return load(best)
    LLVMBasicBlockRef return_invalid_bb;  // pre-descent miss — return kInvalidRoute

    // Cached types
    LLVMTypeRef i1_ty;
    LLVMTypeRef i8_ty;
    LLVMTypeRef i16_ty;
    LLVMTypeRef i32_ty;
    LLVMTypeRef ptr_ty;

    const ArtTrie* trie;
};

// Load a single byte from `eff_ptr[offset]`. `offset` is an i32 IR
// value; result is i8. Caller is responsible for the bound check.
LLVMValueRef emit_load_byte(EmitCtx& c, LLVMValueRef offset) {
    LLVMValueRef gep = LLVMBuildGEP2(c.builder, c.i8_ty, c.eff_ptr, &offset, 1, "byte_gep");
    return LLVMBuildLoad2(c.builder, c.i8_ty, gep, "byte");
}

// Branch to return_best_bb if `cond` (i1) is false; else fall through
// into a fresh block. Returns the new "on-pass" block (already
// positioned for further emission).
LLVMBasicBlockRef emit_check_or_break(EmitCtx& c, LLVMValueRef cond, const char* on_pass_name) {
    LLVMBasicBlockRef pass_bb = LLVMAppendBasicBlockInContext(c.ctx, c.fn, on_pass_name);
    LLVMBuildCondBr(c.builder, cond, pass_bb, c.return_best_bb);
    LLVMPositionBuilderAtEnd(c.builder, pass_bb);
    return pass_bb;
}

// Header accessor — pulls the right pool entry for a child ref.
const ArtNodeHeader& header_of(const ArtTrie& trie, ArtChildRef ref) {
    const u16 i = art_idx(ref);
    switch (art_type(ref)) {
        case kArtN4:
            return trie.n4_pool_[i].hdr;
        case kArtN16:
            return trie.n16_pool_[i].hdr;
        case kArtN48:
            return trie.n48_pool_[i].hdr;
        case kArtN256:
            return trie.n256_pool_[i].hdr;
    }
    __builtin_unreachable();
}

// Generate the per-method-slot terminal pickup for a node. Mirrors
// the logic of ArtTrie::pick_terminal:
//
//   if (slot != 0 && terminals[slot] != kInvalid) best = terminals[slot]
//   else if (terminals[0] != kInvalid)            best = terminals[0]
//
// Cleverness: at codegen time we know which slots are valid for
// THIS node. Most nodes only have terminals[0] — those emit just one
// unconditional store. Nodes with method-specific terminals emit a
// switch on method_slot picking the right constant.
void emit_terminal_pickup(EmitCtx& c, const ArtNodeHeader& hdr) {
    const u16* t = hdr.route_idx_by_method;
    // Quick scan: which slots are valid?
    bool valid_any = false;
    bool any_specific_valid = false;
    for (u32 s = 1; s < kMethodSlots; s++) {
        if (t[s] != TrieNode::kInvalidRoute) {
            any_specific_valid = true;
            break;
        }
    }
    if (t[0] != TrieNode::kInvalidRoute) valid_any = true;

    if (!valid_any && !any_specific_valid) return;  // node not a terminal at all

    if (!any_specific_valid) {
        // Common case: only slot 0 (any) terminal. Unconditional update.
        LLVMBuildStore(c.builder, LLVMConstInt(c.i16_ty, t[0], 0), c.best_alloca);
        return;
    }

    // Mixed: emit switch on method_slot. Cases for valid specific
    // slots, default = slot 0 path.
    LLVMBasicBlockRef cont_bb = LLVMAppendBasicBlockInContext(c.ctx, c.fn, "term_done");
    LLVMBasicBlockRef any_bb = LLVMAppendBasicBlockInContext(c.ctx, c.fn, "term_any");

    // Count specific cases
    u32 ncases = 0;
    for (u32 s = 1; s < kMethodSlots; s++) {
        if (t[s] != TrieNode::kInvalidRoute) ncases++;
    }

    LLVMValueRef sw = LLVMBuildSwitch(c.builder, c.method_slot, any_bb, ncases);
    for (u32 s = 1; s < kMethodSlots; s++) {
        if (t[s] == TrieNode::kInvalidRoute) continue;
        LLVMBasicBlockRef case_bb = LLVMAppendBasicBlockInContext(c.ctx, c.fn, "term_specific");
        LLVMAddCase(sw, LLVMConstInt(c.i32_ty, s, 0), case_bb);
        LLVMPositionBuilderAtEnd(c.builder, case_bb);
        LLVMBuildStore(c.builder, LLVMConstInt(c.i16_ty, t[s], 0), c.best_alloca);
        LLVMBuildBr(c.builder, cont_bb);
    }

    // Default / fallback to slot 0 path. This is also taken when the
    // requested method's specific slot is invalid (we land here from
    // the "any" arm of the switch when method_slot is not in the
    // valid-specific set). We unconditionally use slot[0] when
    // available.
    LLVMPositionBuilderAtEnd(c.builder, any_bb);
    if (valid_any) {
        LLVMBuildStore(c.builder, LLVMConstInt(c.i16_ty, t[0], 0), c.best_alloca);
    }
    LLVMBuildBr(c.builder, cont_bb);

    // Continue at cont_bb.
    LLVMPositionBuilderAtEnd(c.builder, cont_bb);
}

// Forward declaration for recursion.
void emit_node_dispatch(EmitCtx& c, ArtChildRef node_ref, u32 depth);

// Emit the per-child block: edge match → terminal pickup → recurse.
void emit_child_descent(EmitCtx& c, ArtChildRef child_ref, u32 depth) {
    const ArtNodeHeader& hdr = header_of(*c.trie, child_ref);
    const Str edge = hdr.edge;

    // Edge bound check: depth + edge.len <= eff_len.
    LLVMValueRef end = LLVMConstInt(c.i32_ty, depth + edge.len, 0);
    LLVMValueRef fits = LLVMBuildICmp(c.builder, LLVMIntULE, end, c.eff_len, "edge_fits");
    emit_check_or_break(c, fits, "edge_fits_ok");

    // Per-byte edge compare (constants on the route side).
    for (u32 k = 0; k < edge.len; k++) {
        LLVMValueRef off = LLVMConstInt(c.i32_ty, depth + k, 0);
        LLVMValueRef p_byte = emit_load_byte(c, off);
        LLVMValueRef e_byte = LLVMConstInt(c.i8_ty, static_cast<u8>(edge.ptr[k]), 0);
        LLVMValueRef eq = LLVMBuildICmp(c.builder, LLVMIntEQ, p_byte, e_byte, "edge_eq");
        emit_check_or_break(c, eq, "edge_byte_ok");
    }

    // Edge fully matched. Update best from child's terminal slots.
    emit_terminal_pickup(c, hdr);

    // Recurse: emit dispatch for child's own children.
    emit_node_dispatch(c, child_ref, depth + edge.len);
}

// Emit dispatch for `node_ref` at `depth`: read the next byte,
// switch on it to one of the child blocks, default to break.
// If the node has no children, fall through to break.
void emit_node_dispatch(EmitCtx& c, ArtChildRef node_ref, u32 depth) {
    static constexpr u32 kMaxKeys = 256;
    u8 keys[kMaxKeys];
    ArtChildRef refs[kMaxKeys];
    u32 nkeys = 0;
    const u16 idx = art_idx(node_ref);
    switch (art_type(node_ref)) {
        case kArtN4: {
            const auto& n = c.trie->n4_pool_[idx];
            nkeys = n.child_count;
            for (u32 i = 0; i < nkeys; i++) {
                keys[i] = n.keys[i];
                refs[i] = n.children[i];
            }
            break;
        }
        case kArtN16: {
            const auto& n = c.trie->n16_pool_[idx];
            nkeys = n.child_count;
            for (u32 i = 0; i < nkeys; i++) {
                keys[i] = n.keys[i];
                refs[i] = n.children[i];
            }
            break;
        }
        case kArtN48: {
            const auto& n = c.trie->n48_pool_[idx];
            for (u32 b = 0; b < 256; b++) {
                const u8 slot1 = n.child_index[b];
                if (slot1 == 0) continue;
                keys[nkeys] = static_cast<u8>(b);
                refs[nkeys] = n.children[slot1 - 1];
                nkeys++;
            }
            break;
        }
        case kArtN256: {
            const auto& n = c.trie->n256_pool_[idx];
            for (u32 b = 0; b < 256; b++) {
                if (n.children[b] == kArtInvalidChildRef) continue;
                keys[nkeys] = static_cast<u8>(b);
                refs[nkeys] = n.children[b];
                nkeys++;
            }
            break;
        }
    }

    if (nkeys == 0) {
        // Leaf — no children to dispatch. Caller's terminal pickup
        // already updated best.
        LLVMBuildBr(c.builder, c.return_best_bb);
        return;
    }

    // Bound check before reading next byte.
    LLVMValueRef cur_off = LLVMConstInt(c.i32_ty, depth, 0);
    LLVMValueRef has_more = LLVMBuildICmp(c.builder, LLVMIntULT, cur_off, c.eff_len, "has_more");
    emit_check_or_break(c, has_more, "has_more_ok");

    LLVMValueRef next_byte = emit_load_byte(c, cur_off);
    LLVMValueRef sw = LLVMBuildSwitch(c.builder, next_byte, c.return_best_bb, nkeys);

    LLVMBasicBlockRef child_blocks[kMaxKeys];
    for (u32 i = 0; i < nkeys; i++) {
        child_blocks[i] = LLVMAppendBasicBlockInContext(c.ctx, c.fn, "child");
        LLVMAddCase(sw, LLVMConstInt(c.i8_ty, keys[i], 0), child_blocks[i]);
    }

    for (u32 i = 0; i < nkeys; i++) {
        LLVMPositionBuilderAtEnd(c.builder, child_blocks[i]);
        emit_child_descent(c, refs[i], depth);
    }
}

// Map canonical route method key (0..9) to slot 0..9. Unknown methods
// short-circuit to kInvalidRoute. Mirrors method_key_slot() in
// route_trie.h.
//
// The IR is a big switch with the method key as the discriminator;
// LLVM's optimizer turns this into a jump table or compact branch
// tree depending on target.
LLVMValueRef emit_method_to_slot(EmitCtx& c, LLVMValueRef method_key) {
    LLVMBasicBlockRef invalid_bb = LLVMAppendBasicBlockInContext(c.ctx, c.fn, "method_invalid");
    LLVMBasicBlockRef cont_bb = LLVMAppendBasicBlockInContext(c.ctx, c.fn, "method_done");

    static const struct {
        u8 byte;
        u32 slot;
    } kCases[] = {{kRouteMethodAny, kRouteMethodAny},
                  {kRouteMethodGet, kRouteMethodGet},
                  {kRouteMethodPost, kRouteMethodPost},
                  {kRouteMethodPut, kRouteMethodPut},
                  {kRouteMethodDelete, kRouteMethodDelete},
                  {kRouteMethodPatch, kRouteMethodPatch},
                  {kRouteMethodHead, kRouteMethodHead},
                  {kRouteMethodOptions, kRouteMethodOptions},
                  {kRouteMethodConnect, kRouteMethodConnect},
                  {kRouteMethodTrace, kRouteMethodTrace}};
    constexpr u32 ncases = sizeof(kCases) / sizeof(kCases[0]);

    LLVMValueRef sw = LLVMBuildSwitch(c.builder, method_key, invalid_bb, ncases);

    LLVMBasicBlockRef case_bbs[ncases];
    LLVMValueRef case_slot_vals[ncases];
    for (u32 i = 0; i < ncases; i++) {
        case_bbs[i] = LLVMAppendBasicBlockInContext(c.ctx, c.fn, "method_case");
        LLVMAddCase(sw, LLVMConstInt(c.i8_ty, kCases[i].byte, 0), case_bbs[i]);
        LLVMPositionBuilderAtEnd(c.builder, case_bbs[i]);
        case_slot_vals[i] = LLVMConstInt(c.i32_ty, kCases[i].slot, 0);
        LLVMBuildBr(c.builder, cont_bb);
    }

    // Invalid method: short-circuit the whole match() to return
    // kInvalidRoute. The route_trie.h contract is that an unknown
    // method key means "no route can match" — we honor that here by
    // branching directly to return_invalid_bb.
    LLVMPositionBuilderAtEnd(c.builder, invalid_bb);
    LLVMBuildBr(c.builder, c.return_invalid_bb);

    // Continue with a phi merging the slot value across the valid
    // cases.
    LLVMPositionBuilderAtEnd(c.builder, cont_bb);
    LLVMValueRef phi = LLVMBuildPhi(c.builder, c.i32_ty, "method_slot");
    LLVMAddIncoming(phi, case_slot_vals, case_bbs, ncases);
    return phi;
}

}  // namespace

ArtJitMatchFn art_jit_specialize(JitEngine& engine, const ArtTrie& trie, const char* unique_name) {
    EmitCtx c{};
    c.trie = &trie;

    c.ctx = LLVMContextCreate();
    c.mod = LLVMModuleCreateWithNameInContext("art_jit", c.ctx);
    c.builder = LLVMCreateBuilderInContext(c.ctx);

    c.i1_ty = LLVMInt1TypeInContext(c.ctx);
    c.i8_ty = LLVMInt8TypeInContext(c.ctx);
    c.i16_ty = LLVMInt16TypeInContext(c.ctx);
    c.i32_ty = LLVMInt32TypeInContext(c.ctx);
    c.ptr_ty = LLVMPointerTypeInContext(c.ctx, 0);

    // Function signature: i16 (ptr, i32, i8)
    LLVMTypeRef param_tys[3] = {c.ptr_ty, c.i32_ty, c.i8_ty};
    LLVMTypeRef fn_ty = LLVMFunctionType(c.i16_ty, param_tys, 3, 0);
    c.fn = LLVMAddFunction(c.mod, unique_name, fn_ty);

    // The function args ARE the canonical path — caller (RouteConfig::
    // match) canonicalized once at dispatch entry. The eff_ptr / eff_len
    // names are kept inside descent code for clarity.
    c.eff_ptr = LLVMGetParam(c.fn, 0);
    c.eff_len = LLVMGetParam(c.fn, 1);
    LLVMValueRef method_key = LLVMGetParam(c.fn, 2);

    LLVMBasicBlockRef entry_bb = LLVMAppendBasicBlockInContext(c.ctx, c.fn, "entry");
    c.return_best_bb = LLVMAppendBasicBlockInContext(c.ctx, c.fn, "return_best");
    c.return_invalid_bb = LLVMAppendBasicBlockInContext(c.ctx, c.fn, "return_invalid");

    LLVMPositionBuilderAtEnd(c.builder, entry_bb);

    // Allocate `best`, init with kInvalidRoute (root terminal pickup
    // happens after we've translated method to slot, since terminal
    // selection depends on slot).
    c.best_alloca = LLVMBuildAlloca(c.builder, c.i16_ty, "best");
    LLVMBuildStore(c.builder, LLVMConstInt(c.i16_ty, TrieNode::kInvalidRoute, 0), c.best_alloca);

    // Method key → slot index. Unknown methods short-circuit to
    // return_invalid_bb.
    c.method_slot = emit_method_to_slot(c, method_key);

    // Root terminal pickup (root is always at art_pack(kArtN4, 0) /
    // initially, but root_ref_ may have been upgraded — read it).
    const ArtChildRef root = trie.root_ref_;
    emit_terminal_pickup(c, header_of(trie, root));

    // Walk into root's children dispatch.
    emit_node_dispatch(c, root, 0);

    // return_best: load best and return.
    LLVMPositionBuilderAtEnd(c.builder, c.return_best_bb);
    LLVMValueRef best_val = LLVMBuildLoad2(c.builder, c.i16_ty, c.best_alloca, "best_v");
    LLVMBuildRet(c.builder, best_val);

    // return_invalid: hard-coded kInvalidRoute (no descent ran).
    LLVMPositionBuilderAtEnd(c.builder, c.return_invalid_bb);
    LLVMBuildRet(c.builder, LLVMConstInt(c.i16_ty, TrieNode::kInvalidRoute, 0));

    LLVMDisposeBuilder(c.builder);

    if (!engine.compile(c.mod, c.ctx)) {
        log_err("art_jit_specialize: compile failed");
        return nullptr;
    }

    void* sym = engine.lookup(unique_name);
    if (!sym) {
        log_err("art_jit_specialize: symbol lookup failed");
        return nullptr;
    }
    return reinterpret_cast<ArtJitMatchFn>(sym);
}

}  // namespace rut::jit
