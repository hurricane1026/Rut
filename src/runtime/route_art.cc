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

#include "rut/runtime/route_art.h"

#include "rut/runtime/route_canon.h"

namespace rut {

namespace {

// insert() canonicalizes the registered route path through the same
// shared helper that the request side uses, so a route registered
// as "/api" and a request canon "api" land on the same trie key.
// Shared with route_canon.h's finalize_path_canonical() — strips
// the entire leading-'/' run and the trailing-'/' run. match() does
// not need this because it consumes already-canonical input
// (RouteConfig::match canonicalizes once at dispatch entry; the
// HTTP parser populates path_canon via finalize_path_canonical).

// Per-type find_child. Inlined into the descent loop below.
ArtChildRef find_in_n4(const ArtNode4& n, u8 b) {
    for (u32 i = 0; i < n.child_count; i++) {
        if (n.keys[i] == b) return n.children[i];
    }
    return kArtInvalidChildRef;
}

ArtChildRef find_in_n16(const ArtNode16& n, u8 b) {
    // Linear scan — at ≤16 entries this is competitive with the
    // SIMD-accelerated standard-ART approach and stays portable.
    // Switch to PCMPEQB if a bench ever shows this loop on top.
    for (u32 i = 0; i < n.child_count; i++) {
        if (n.keys[i] == b) return n.children[i];
    }
    return kArtInvalidChildRef;
}

ArtChildRef find_in_n48(const ArtNode48& n, u8 b) {
    const u8 idx_1based = n.child_index[b];
    if (idx_1based == 0) return kArtInvalidChildRef;
    return n.children[idx_1based - 1];
}

ArtChildRef find_in_n256(const ArtNode256& n, u8 b) {
    return n.children[b];
}

}  // namespace

void ArtTrie::clear() {
    n4_pool_len_ = 0;
    n16_pool_len_ = 0;
    n48_pool_len_ = 0;
    n256_pool_len_ = 0;
    // Seed the root as a fresh Node4 at slot 0.
    n4_pool_[0] = ArtNode4{};
    n4_pool_len_ = 1;
    root_ref_ = art_pack(kArtN4, 0);
    is_uniform_n4_ = true;
}

ArtNodeHeader& ArtTrie::header(ArtChildRef ref) {
    const u16 i = art_idx(ref);
    switch (art_type(ref)) {
        case kArtN4:
            return n4_pool_[i].hdr;
        case kArtN16:
            return n16_pool_[i].hdr;
        case kArtN48:
            return n48_pool_[i].hdr;
        case kArtN256:
            return n256_pool_[i].hdr;
    }
    __builtin_unreachable();
}

const ArtNodeHeader& ArtTrie::header(ArtChildRef ref) const {
    const u16 i = art_idx(ref);
    switch (art_type(ref)) {
        case kArtN4:
            return n4_pool_[i].hdr;
        case kArtN16:
            return n16_pool_[i].hdr;
        case kArtN48:
            return n48_pool_[i].hdr;
        case kArtN256:
            return n256_pool_[i].hdr;
    }
    __builtin_unreachable();
}

ArtChildRef ArtTrie::find_child(ArtChildRef parent, u8 b) const {
    const u16 i = art_idx(parent);
    switch (art_type(parent)) {
        case kArtN4:
            return find_in_n4(n4_pool_[i], b);
        case kArtN16:
            return find_in_n16(n16_pool_[i], b);
        case kArtN48:
            return find_in_n48(n48_pool_[i], b);
        case kArtN256:
            return find_in_n256(n256_pool_[i], b);
    }
    __builtin_unreachable();
}

u16 ArtTrie::pick_terminal(const ArtNodeHeader& h, u32 slot) {
    if (slot != 0 && h.route_idx_by_method[slot] != TrieNode::kInvalidRoute) {
        return h.route_idx_by_method[slot];
    }
    return h.route_idx_by_method[0];
}

ArtChildRef ArtTrie::alloc_n4() {
    if (n4_pool_len_ >= kMaxN4) return kArtInvalidChildRef;
    const u16 i = static_cast<u16>(n4_pool_len_++);
    n4_pool_[i] = ArtNode4{};
    return art_pack(kArtN4, i);
}

ArtChildRef ArtTrie::alloc_n16() {
    if (n16_pool_len_ >= kMaxN16) return kArtInvalidChildRef;
    const u16 i = static_cast<u16>(n16_pool_len_++);
    n16_pool_[i] = ArtNode16{};
    is_uniform_n4_ = false;
    return art_pack(kArtN16, i);
}

ArtChildRef ArtTrie::alloc_n48() {
    if (n48_pool_len_ >= kMaxN48) return kArtInvalidChildRef;
    const u16 i = static_cast<u16>(n48_pool_len_++);
    n48_pool_[i] = ArtNode48{};
    is_uniform_n4_ = false;
    return art_pack(kArtN48, i);
}

ArtChildRef ArtTrie::alloc_n256() {
    if (n256_pool_len_ >= kMaxN256) return kArtInvalidChildRef;
    const u16 i = static_cast<u16>(n256_pool_len_++);
    n256_pool_[i] = ArtNode256{};
    is_uniform_n4_ = false;
    return art_pack(kArtN256, i);
}

ArtChildRef ArtTrie::add_child(ArtChildRef parent, u8 b, ArtChildRef child) {
    const u16 pi = art_idx(parent);
    switch (art_type(parent)) {
        case kArtN4: {
            ArtNode4& n = n4_pool_[pi];
            if (n.child_count < 4) {
                n.keys[n.child_count] = b;
                n.children[n.child_count] = child;
                n.child_count++;
                return parent;
            }
            // Upgrade to Node16. Allocate fresh, copy state.
            const ArtChildRef new_ref = alloc_n16();
            if (new_ref == kArtInvalidChildRef) return kArtInvalidChildRef;
            ArtNode16& n16 = n16_pool_[art_idx(new_ref)];
            n16.hdr = n.hdr;
            for (u32 k = 0; k < 4; k++) {
                n16.keys[k] = n.keys[k];
                n16.children[k] = n.children[k];
            }
            n16.keys[4] = b;
            n16.children[4] = child;
            n16.child_count = 5;
            return new_ref;
        }
        case kArtN16: {
            ArtNode16& n = n16_pool_[pi];
            if (n.child_count < 16) {
                n.keys[n.child_count] = b;
                n.children[n.child_count] = child;
                n.child_count++;
                return parent;
            }
            const ArtChildRef new_ref = alloc_n48();
            if (new_ref == kArtInvalidChildRef) return kArtInvalidChildRef;
            ArtNode48& n48 = n48_pool_[art_idx(new_ref)];
            n48.hdr = n.hdr;
            for (u32 k = 0; k < 16; k++) {
                n48.children[k] = n.children[k];
                n48.child_index[n.keys[k]] = static_cast<u8>(k + 1);
            }
            n48.children[16] = child;
            n48.child_index[b] = 17;
            n48.child_count = 17;
            return new_ref;
        }
        case kArtN48: {
            ArtNode48& n = n48_pool_[pi];
            if (n.child_count < 48) {
                const u8 slot = n.child_count;
                n.children[slot] = child;
                n.child_index[b] = static_cast<u8>(slot + 1);
                n.child_count++;
                return parent;
            }
            const ArtChildRef new_ref = alloc_n256();
            if (new_ref == kArtInvalidChildRef) return kArtInvalidChildRef;
            ArtNode256& n256 = n256_pool_[art_idx(new_ref)];
            n256.hdr = n.hdr;
            for (u32 byte = 0; byte < 256; byte++) {
                const u8 slot1 = n.child_index[byte];
                if (slot1 != 0) {
                    n256.children[byte] = n.children[slot1 - 1];
                }
            }
            n256.children[b] = child;
            n256.child_count = 49;
            return new_ref;
        }
        case kArtN256: {
            ArtNode256& n = n256_pool_[pi];
            // Caller guarantees b is unseen, so this is always an
            // append (no overwrite of an existing child slot).
            n.children[b] = child;
            n.child_count++;
            return parent;
        }
    }
    __builtin_unreachable();
}

bool ArtTrie::insert(Str path, u8 method_char, u16 route_idx) {
    const u32 slot = method_slot(method_char);
    if (slot == kMethodSlotInvalid) return false;

    const Str p = finalize_path_canonical(path.ptr, path.len);

    // Atomic insert — snapshot all four pools + the root_ref_ so any
    // allocation failure during descent rolls the trie back to pre-
    // insert state. Snapshot stack reservation equals the sum of the
    // four full-capacity pool arrays — ~35 KB at the current cap
    // configuration documented in route_art.h. Tiny next to a default
    // 8 MB pthread stack;
    // dominated by the live data we'd need to copy out anyway if we
    // tried to shrink the snapshot to live-prefix only.
    const u32 saved_n4_len = n4_pool_len_;
    const u32 saved_n16_len = n16_pool_len_;
    const u32 saved_n48_len = n48_pool_len_;
    const u32 saved_n256_len = n256_pool_len_;
    const ArtChildRef saved_root = root_ref_;
    const bool saved_is_uniform_n4 = is_uniform_n4_;
    ArtNode4 saved_n4[kMaxN4];
    ArtNode16 saved_n16[kMaxN16];
    ArtNode48 saved_n48[kMaxN48];
    ArtNode256 saved_n256[kMaxN256];
    for (u32 i = 0; i < saved_n4_len; i++) saved_n4[i] = n4_pool_[i];
    for (u32 i = 0; i < saved_n16_len; i++) saved_n16[i] = n16_pool_[i];
    for (u32 i = 0; i < saved_n48_len; i++) saved_n48[i] = n48_pool_[i];
    for (u32 i = 0; i < saved_n256_len; i++) saved_n256[i] = n256_pool_[i];

    auto rollback = [&]() {
        for (u32 i = 0; i < saved_n4_len; i++) n4_pool_[i] = saved_n4[i];
        for (u32 i = 0; i < saved_n16_len; i++) n16_pool_[i] = saved_n16[i];
        for (u32 i = 0; i < saved_n48_len; i++) n48_pool_[i] = saved_n48[i];
        for (u32 i = 0; i < saved_n256_len; i++) n256_pool_[i] = saved_n256[i];
        n4_pool_len_ = saved_n4_len;
        n16_pool_len_ = saved_n16_len;
        n48_pool_len_ = saved_n48_len;
        n256_pool_len_ = saved_n256_len;
        root_ref_ = saved_root;
        is_uniform_n4_ = saved_is_uniform_n4;
    };

    // We descend through the trie. At each step we may need to
    // upgrade the parent node type (Node4→16→48→256) which produces
    // a new ref; we then have to write that new ref back into the
    // slot that was holding `cur`. We track that slot as a "patch
    // site" — a pointer into either &root_ref_ (when cur is the root)
    // or the corresponding child slot in cur's parent.
    //
    // The pools (n4_pool_, n16_pool_, n48_pool_, n256_pool_) are fixed
    // arrays sized at compile time, so interior pointers into them are
    // stable across allocations: we can safely capture and reuse a
    // child slot pointer through subsequent inserts.

    ArtChildRef cur = root_ref_;
    ArtChildRef* cur_patch_site = &root_ref_;
    u32 i = 0;
    while (i < p.len) {
        const u8 b = static_cast<u8>(p.ptr[i]);
        const ArtChildRef child = find_child(cur, b);
        if (child == kArtInvalidChildRef) {
            // No matching child — append a leaf with the rest of the
            // path as its edge. Always a Node4 (zero children, fits).
            const ArtChildRef leaf = alloc_n4();
            if (leaf == kArtInvalidChildRef) {
                rollback();
                return false;
            }
            n4_pool_[art_idx(leaf)].hdr.edge = Str{p.ptr + i, p.len - i};

            const ArtChildRef new_parent = add_child(cur, b, leaf);
            if (new_parent == kArtInvalidChildRef) {
                rollback();
                return false;
            }
            if (new_parent != cur) {
                // Parent upgraded — rewrite the slot that was pointing
                // at cur (either &root_ref_ or a slot in the grandparent)
                // to point at the new, upgraded node.
                *cur_patch_site = new_parent;
            }
            cur = leaf;
            i = p.len;
            break;
        }
        // Match as many bytes of the existing edge as possible.
        const Str e = header(child).edge;
        u32 k = 0;
        while (k < e.len && i + k < p.len && e.ptr[k] == p.ptr[i + k]) k++;
        if (k == e.len) {
            // Full edge match — descend. Capture the slot in cur that
            // holds `child` so a future upgrade of child's children can
            // patch back through it. Pool arrays don't move, so the
            // pointer is stable for the rest of insert(). For Node4/16
            // we scan keys[] for byte b; for Node48 we use child_index[b]
            // - 1; for Node256 we index by b directly.
            ArtChildRef* site = nullptr;
            const u16 ci = art_idx(cur);
            switch (art_type(cur)) {
                case kArtN4: {
                    ArtNode4& n = n4_pool_[ci];
                    for (u32 j = 0; j < n.child_count; j++) {
                        if (n.keys[j] == b) {
                            site = &n.children[j];
                            break;
                        }
                    }
                    break;
                }
                case kArtN16: {
                    ArtNode16& n = n16_pool_[ci];
                    for (u32 j = 0; j < n.child_count; j++) {
                        if (n.keys[j] == b) {
                            site = &n.children[j];
                            break;
                        }
                    }
                    break;
                }
                case kArtN48: {
                    ArtNode48& n = n48_pool_[ci];
                    site = &n.children[n.child_index[b] - 1];
                    break;
                }
                case kArtN256: {
                    ArtNode256& n = n256_pool_[ci];
                    site = &n.children[b];
                    break;
                }
            }
            cur_patch_site = site;
            cur = child;
            i += k;
            continue;
        }
        // Partial match — split the existing child's edge at byte k.
        // The original child becomes the SHARED-PREFIX node (edge
        // truncated to [0, k), terminals cleared, children replaced
        // with [tail, new_leaf]). A new tail node takes the original's
        // post-split edge tail [k, e.len), terminals, and children.
        const ArtChildRef tail = alloc_n4();
        if (tail == kArtInvalidChildRef) {
            rollback();
            return false;
        }
        // Copy original child's terminals and children into `tail`,
        // then clear them on the original. The "tail" has whatever
        // children the original had — fan-out is preserved across
        // the split, so we may need to upgrade `tail` to match
        // original's type. To keep the split simple we always make
        // tail a Node4 at first and `add_child` the original's
        // children onto it; this auto-upgrades as needed.
        ArtNode4& tail_node = n4_pool_[art_idx(tail)];
        tail_node.hdr.edge = Str{e.ptr + k, e.len - k};
        // Copy header fields (terminals) from original's header.
        for (u32 m = 0; m < kMethodSlots; m++) {
            tail_node.hdr.route_idx_by_method[m] = header(child).route_idx_by_method[m];
        }
        // Move the original's children to the tail. Iterate per-type
        // so we visit each (key, child) pair exactly once, then
        // clear on the original after.
        ArtChildRef tail_ref = tail;
        const u16 chi = art_idx(child);
        switch (art_type(child)) {
            case kArtN4: {
                ArtNode4& n = n4_pool_[chi];
                for (u32 j = 0; j < n.child_count; j++) {
                    tail_ref = add_child(tail_ref, n.keys[j], n.children[j]);
                    if (tail_ref == kArtInvalidChildRef) {
                        rollback();
                        return false;
                    }
                }
                break;
            }
            case kArtN16: {
                ArtNode16& n = n16_pool_[chi];
                for (u32 j = 0; j < n.child_count; j++) {
                    tail_ref = add_child(tail_ref, n.keys[j], n.children[j]);
                    if (tail_ref == kArtInvalidChildRef) {
                        rollback();
                        return false;
                    }
                }
                break;
            }
            case kArtN48: {
                ArtNode48& n = n48_pool_[chi];
                for (u32 byte = 0; byte < 256; byte++) {
                    const u8 slot1 = n.child_index[byte];
                    if (slot1 == 0) continue;
                    tail_ref = add_child(tail_ref, static_cast<u8>(byte), n.children[slot1 - 1]);
                    if (tail_ref == kArtInvalidChildRef) {
                        rollback();
                        return false;
                    }
                }
                break;
            }
            case kArtN256: {
                ArtNode256& n = n256_pool_[chi];
                for (u32 byte = 0; byte < 256; byte++) {
                    if (n.children[byte] == kArtInvalidChildRef) continue;
                    tail_ref = add_child(tail_ref, static_cast<u8>(byte), n.children[byte]);
                    if (tail_ref == kArtInvalidChildRef) {
                        rollback();
                        return false;
                    }
                }
                break;
            }
        }

        // Clear original's terminals + children, set its edge to
        // shared prefix, install tail as its only child for byte
        // e.ptr[k]. The "original" stays the same node ref so the
        // parent's pointer remains valid.
        switch (art_type(child)) {
            case kArtN4: {
                ArtNode4& n = n4_pool_[chi];
                n = ArtNode4{};
                n.hdr.edge = Str{e.ptr, k};
                break;
            }
            case kArtN16: {
                ArtNode16& n = n16_pool_[chi];
                n = ArtNode16{};
                n.hdr.edge = Str{e.ptr, k};
                break;
            }
            case kArtN48: {
                ArtNode48& n = n48_pool_[chi];
                n = ArtNode48{};
                n.hdr.edge = Str{e.ptr, k};
                break;
            }
            case kArtN256: {
                ArtNode256& n = n256_pool_[chi];
                n = ArtNode256{};
                n.hdr.edge = Str{e.ptr, k};
                break;
            }
        }
        // Re-add the tail (and possibly the new leaf below) to the
        // truncated original. add_child may upgrade the original's
        // type — propagate that to the patch site.
        ArtChildRef new_child_ref = add_child(child, static_cast<u8>(e.ptr[k]), tail_ref);
        if (new_child_ref == kArtInvalidChildRef) {
            rollback();
            return false;
        }
        if (new_child_ref != child) {
            *cur_patch_site = new_child_ref;
        }
        // The post-split path either continues (new path has more
        // bytes after the split point) or ends right here (new path
        // ends at the split). Loop body re-reads `cur` to decide.
        cur = new_child_ref;
        i += k;
        // Re-establish patch site for the new cur (we just rewrote
        // it). Resolve it the same way as the full-match branch.
        {
            ArtChildRef* site = nullptr;
            const u16 ni = art_idx(cur);
            // For the patch site of the next iteration's child of
            // cur, we'll resolve lazily on the next descent step;
            // setting it to nullptr here is safe because the next
            // iteration will recompute it. But cur itself was just
            // written through cur_patch_site, so future writes to
            // *cur_patch_site would clobber it. Reset cur_patch_site
            // to point at where cur lives in its parent so future
            // upgrades of cur propagate correctly. Since we just
            // wrote cur via *cur_patch_site, that pointer is still
            // valid and points at cur's slot in the parent.
            (void)site;
            (void)ni;
            // cur_patch_site stays as-is (still pointing at the slot
            // that holds cur in its parent).
        }
    }

    // Set the per-method terminal slot at `cur`. First-insert-wins.
    ArtNodeHeader& h = header(cur);
    if (h.route_idx_by_method[slot] == TrieNode::kInvalidRoute) {
        h.route_idx_by_method[slot] = route_idx;
    }
    return true;
}

u16 ArtTrie::match(Str path, u8 method_char) const {
    // Convenience wrapper for direct callers (tests, ad-hoc usage).
    // Canonicalizes input then delegates to match_canonical. The
    // production hot path (RouteConfig::match) calls match_canonical
    // directly to skip the redundant canon scan.
    if (path.len == 0 || path.ptr[0] != '/') return TrieNode::kInvalidRoute;
    return match_canonical(canonicalize_request(path), method_char);
}

u16 ArtTrie::match_canonical(Str path, u8 method_char) const {
    const u32 want_slot = method_slot(method_char);
    return match_canonical_key(path, static_cast<u8>(want_slot));
}

u16 ArtTrie::match_canonical_key(Str path, u8 method_key) const {
    const u32 want_slot = method_key_slot(method_key);
    if (want_slot == kMethodSlotInvalid) return TrieNode::kInvalidRoute;

    const Str p = path;

    // Fast path: when the trie is 100% Node4 (the common case for
    // realistic SaaS configs — fan-out 1-3 at almost every node),
    // skip all type switches and run a tight homogeneous loop. This
    // is structurally equivalent to ByteRadixTrie::match's inner
    // loop and closes the bench gap on the saas shape (otherwise
    // the polymorphic descent paid 2 indirect-branches per step).
    // is_uniform_n4_ is set true on clear() and cleared the first
    // time alloc_n16/48/256 succeeds.
    if (is_uniform_n4_) {
        const ArtNode4& root = n4_pool_[art_idx(root_ref_)];
        u16 best =
            (want_slot != 0 && root.hdr.route_idx_by_method[want_slot] != TrieNode::kInvalidRoute)
                ? root.hdr.route_idx_by_method[want_slot]
                : root.hdr.route_idx_by_method[0];
        u16 cur_idx = art_idx(root_ref_);
        u32 i = 0;
        while (i < p.len) {
            const u8 b = static_cast<u8>(p.ptr[i]);
            const ArtNode4& parent = n4_pool_[cur_idx];
            ArtChildRef child = kArtInvalidChildRef;
            for (u32 j = 0; j < parent.child_count; j++) {
                if (parent.keys[j] == b) {
                    child = parent.children[j];
                    break;
                }
            }
            if (child == kArtInvalidChildRef) return best;
            const ArtNode4& cn = n4_pool_[art_idx(child)];
            const Str e = cn.hdr.edge;
            if (i + e.len > p.len) return best;
            for (u32 k = 0; k < e.len; k++) {
                if (e.ptr[k] != p.ptr[i + k]) return best;
            }
            cur_idx = art_idx(child);
            i += e.len;
            const u16 cand =
                (want_slot != 0 && cn.hdr.route_idx_by_method[want_slot] != TrieNode::kInvalidRoute)
                    ? cn.hdr.route_idx_by_method[want_slot]
                    : cn.hdr.route_idx_by_method[0];
            if (cand != TrieNode::kInvalidRoute) best = cand;
        }
        return best;
    }

    // General path — heterogeneous node types. Each descent step
    // needs three pieces of information from the CURRENT node —
    // find_child, header.edge, and pick_terminal. Doing them as
    // three separate switch-on-type calls (the "obvious" structure)
    // compiles to three independent branches per step, ~3× the
    // dispatch overhead vs a homogeneous node. We collapse them
    // into ONE switch per iteration that sets up `child` from the
    // parent and reads the child's header inline.
    ArtChildRef cur = root_ref_;
    u16 best = pick_terminal(header(cur), want_slot);
    u32 i = 0;
    // The general path uses inline `if (type == kArtN4) { fast } else
    // { switch }` checks. Realistic SaaS configs are ~95% Node4 with
    // an upgraded root — the if-N4 branch becomes predicted-taken
    // after the first iteration and runs at homogeneous-loop speed.
    // Bench data: this two-step optimization closes the saas gap
    // from -27% to within ~5% of ByteRadix.
    while (i < p.len) {
        const u8 b = static_cast<u8>(p.ptr[i]);

        ArtChildRef child = kArtInvalidChildRef;
        const u16 ci = art_idx(cur);
        if (art_type(cur) == kArtN4) [[likely]] {
            const ArtNode4& n = n4_pool_[ci];
            for (u32 j = 0; j < n.child_count; j++) {
                if (n.keys[j] == b) {
                    child = n.children[j];
                    break;
                }
            }
        } else {
            switch (art_type(cur)) {
                case kArtN4:
                    __builtin_unreachable();
                case kArtN16: {
                    const ArtNode16& n = n16_pool_[ci];
                    for (u32 j = 0; j < n.child_count; j++) {
                        if (n.keys[j] == b) {
                            child = n.children[j];
                            break;
                        }
                    }
                    break;
                }
                case kArtN48: {
                    const ArtNode48& n = n48_pool_[ci];
                    const u8 idx1 = n.child_index[b];
                    if (idx1 != 0) child = n.children[idx1 - 1];
                    break;
                }
                case kArtN256: {
                    child = n256_pool_[ci].children[b];
                    break;
                }
            }
        }
        if (child == kArtInvalidChildRef) break;

        // Read child's header — same N4 fast path. The first
        // iteration may hit a non-N4 root child (e.g., Node16 root
        // promoted from saas top-level fan-out), but subsequent
        // descent steps land in N4 land 95% of the time.
        Str child_edge;
        const u16* child_terminals = nullptr;
        const u16 chi = art_idx(child);
        if (art_type(child) == kArtN4) [[likely]] {
            const ArtNode4& cn = n4_pool_[chi];
            child_edge = cn.hdr.edge;
            child_terminals = cn.hdr.route_idx_by_method;
        } else {
            switch (art_type(child)) {
                case kArtN4:
                    __builtin_unreachable();
                case kArtN16: {
                    child_edge = n16_pool_[chi].hdr.edge;
                    child_terminals = n16_pool_[chi].hdr.route_idx_by_method;
                    break;
                }
                case kArtN48: {
                    child_edge = n48_pool_[chi].hdr.edge;
                    child_terminals = n48_pool_[chi].hdr.route_idx_by_method;
                    break;
                }
                case kArtN256: {
                    child_edge = n256_pool_[chi].hdr.edge;
                    child_terminals = n256_pool_[chi].hdr.route_idx_by_method;
                    break;
                }
            }
        }

        if (i + child_edge.len > p.len) break;
        for (u32 k = 0; k < child_edge.len; k++) {
            if (child_edge.ptr[k] != p.ptr[i + k]) return best;
        }
        cur = child;
        i += child_edge.len;
        const u16 candidate =
            (want_slot != 0 && child_terminals[want_slot] != TrieNode::kInvalidRoute)
                ? child_terminals[want_slot]
                : child_terminals[0];
        if (candidate != TrieNode::kInvalidRoute) best = candidate;
    }
    return best;
}

}  // namespace rut
