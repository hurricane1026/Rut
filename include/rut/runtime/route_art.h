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

#pragma once

// ART — Adaptive Radix Tree.
//
// Drop-in semantic replacement for ByteRadixTrie: same byte-level
// longest-prefix matching, same '?' / '#' / trailing-'/' handling, same
// per-method terminal slot model, same atomic-insert contract. The
// difference is internal layout — instead of a single homogeneous node
// type with a 128-wide children FixedVec at every node, ART uses four
// node types sized to actual fan-out:
//
//   Node4    fan-out ≤ 4    parallel keys[]/children[] arrays (linear)
//   Node16   fan-out ≤ 16   parallel keys[]/children[] arrays (linear)
//   Node48   fan-out ≤ 48   256-entry byte→slot index + 48 children
//   Node256  fan-out ≤ 256  full 256-entry direct-indexed children
//
// A node grows to the next type when its fan-out cap is reached and an
// insert needs another child. Standard ART has no shrink: realistic
// route trees don't churn fan-out at runtime, and RouteConfig is
// rebuilt from scratch on RCU reload anyway.
//
// Why this beats ByteRadixTrie on the same workload:
//   - Memory: real SaaS configs have fan-out 1-3 at most nodes →
//     mostly Node4 (~64 B) + occasional Node16 (~88 B). ByteRadix
//     pays ~290 B/node uniformly. Typical 200-node trie: ~12 KB
//     (ART) vs ~58 KB (ByteRadix). Even adversarial dense fan-out
//     (1 catchall + 127 single-byte tops) stays under ART's
//     budget because only the offending node grows to Node256.
//   - Cache: smaller nodes pack more of the descent path into L1.
//     ByteRadix's 290-B node spans 5 cache lines whose 256-B
//     children buffer is mostly empty (and cold).
//   - Lookup: Node4/16 use a tight linear scan (≤16 cmp), Node48
//     does a single byte-indexed lookup, Node256 is one direct
//     load. ByteRadix is always a linear scan over a 128-wide
//     buffer — dense at most a few entries, sparse the rest.
//
// Why type tags live in child indices (not in the node header):
//   Each child reference is a packed u16: high 2 bits = node type
//   (0=N4, 1=N16, 2=N48, 3=N256), low 14 bits = pool index. The
//   parent already holds the typed pointer needed for the child's
//   `find_child` dispatch — we read the type before the load lands,
//   so the type-switch overlaps with the cache miss latency rather
//   than serializing after it. Tagged-pointer ART is the standard
//   technique for this; a node-header byte would force one extra
//   load per descent step.
//
// Sentinel sharing with the rest of the trie family:
//   - Per-method route slots use TrieNode::kInvalidRoute (same as
//     SegmentTrie / ByteRadix) so the dispatch adapter can reuse
//     the existing translation to kRouteIdxInvalid.
//   - "No child for this byte" is kInvalidChildIdx == 0xffffu.
//     Note this cannot collide with any valid (type, idx) combination
//     because per-type pool caps × 4 type-tags fit easily in 14 bits.
//
// Atomic insert — same contract as ByteRadixTrie::insert:
//   On any allocation failure mid-insert, the four pools are restored
//   to pre-insert state. Snapshot is per-pool (lengths + element
//   contents); failure modes are method byte unrecognized, any pool
//   at cap, or split-during-insert that can't allocate the second
//   node. Cost analysed in the .cc.
//
// First-insert-wins on duplicate (path, method): the per-method
// terminal slot is set only if currently kInvalidRoute, matching
// ByteRadixTrie and the trie/hash family.
//
// What's intentionally NOT supported (matches ByteRadix):
//   - `:param` dynamic segment routing/capture — that's SegmentTrie's contract.
//   - Segment-boundary-aware matching — selector won't pick this
//     dispatch when boundary semantics are needed.

#include "rut/common/types.h"
#include "rut/runtime/route_trie.h"  // for kMethodSlots, method_slot, TrieNode::kInvalidRoute

namespace rut {

// Packed child reference. High 2 bits = node-type tag, low 14 bits =
// pool index. Stored across all 4 node types so descent code can
// dispatch on the tag without reading the child node.
using ArtChildRef = u16;
constexpr ArtChildRef kArtInvalidChildRef = 0xffffu;

constexpr u32 kArtTypeBits = 2;
constexpr u32 kArtIdxBits = 16 - kArtTypeBits;
constexpr ArtChildRef kArtIdxMask = static_cast<ArtChildRef>((1u << kArtIdxBits) - 1u);

enum ArtNodeType : u8 {
    kArtN4 = 0,
    kArtN16 = 1,
    kArtN48 = 2,
    kArtN256 = 3,
};

constexpr ArtChildRef art_pack(ArtNodeType t, u16 idx) {
    return static_cast<ArtChildRef>((static_cast<u16>(t) << kArtIdxBits) | (idx & kArtIdxMask));
}
constexpr ArtNodeType art_type(ArtChildRef ref) {
    return static_cast<ArtNodeType>(ref >> kArtIdxBits);
}
constexpr u16 art_idx(ArtChildRef ref) {
    return ref & kArtIdxMask;
}

// Common header carried by every ART node — edge label and per-method
// terminal slots are independent of fan-out. Reads/writes are uniform
// across node types so the descent code touches them without dispatch.
struct ArtNodeHeader {
    // Edge label: byte run leading INTO this node (non-owning view
    // into RouteEntry::path; safe for the config's RCU lifetime).
    Str edge{};

    // Per-method terminal slot. kInvalidRoute means "this node is not
    // a terminal for that method". Slot 0 is "any".
    u16 route_idx_by_method[kMethodSlots] = {TrieNode::kInvalidRoute,
                                             TrieNode::kInvalidRoute,
                                             TrieNode::kInvalidRoute,
                                             TrieNode::kInvalidRoute,
                                             TrieNode::kInvalidRoute,
                                             TrieNode::kInvalidRoute,
                                             TrieNode::kInvalidRoute,
                                             TrieNode::kInvalidRoute,
                                             TrieNode::kInvalidRoute,
                                             TrieNode::kInvalidRoute};
};

struct ArtNode4 {
    ArtNodeHeader hdr;
    u8 keys[4]{};
    ArtChildRef children[4]{
        kArtInvalidChildRef, kArtInvalidChildRef, kArtInvalidChildRef, kArtInvalidChildRef};
    u8 child_count = 0;
};

struct ArtNode16 {
    ArtNodeHeader hdr;
    // Keys in insertion order — find_in_n16() linear-scans without
    // assuming sortedness, and add_child() appends without sorting.
    // A future SIMD-accelerated find (one PCMPEQB across all 16
    // keys + tzcnt) also works on unsorted keys, so leaving the
    // order unsorted keeps options open. (Earlier comment claimed
    // "sorted for early-exit" — incorrect; corrected on PR #50 review.)
    u8 keys[16]{};
    ArtChildRef children[16]{};
    u8 child_count = 0;
};

struct ArtNode48 {
    ArtNodeHeader hdr;
    // child_index[byte] = 1-based index into children[] (0 = absent).
    // 1-based is standard ART so the all-zero default == "empty".
    u8 child_index[256]{};
    ArtChildRef children[48]{};
    u8 child_count = 0;
};

struct ArtNode256 {
    ArtNodeHeader hdr;
    // children[byte] = child ref or kArtInvalidChildRef.
    ArtChildRef children[256];
    u16 child_count = 0;

    ArtNode256() {
        for (u32 i = 0; i < 256; i++) children[i] = kArtInvalidChildRef;
    }
};

class ArtTrie {
public:
    // Pool caps, sized so the worst-case route shape (1 + 2N nodes
    // with N = RouteConfig::kMaxRoutes = 128 → 257 nodes total) fits
    // any combination of node types the build can produce, with
    // generous headroom on the upgrade-prone tiers (Node48/Node256)
    // for adversarial fan-out patterns.
    //
    // Theoretical bound: a radix tree with N leaves has ≤ 2N-1 internal
    // nodes. Upgrades (Node4→16→48→256) leave the source slot "wasted"
    // since we don't recycle, so each tier needs headroom ≥ live count
    // + upgrade churn. For N=128 the tight upper bound on Node48 is
    // floor(2N / 17) ≈ 15 (each Node48 has ≥17 children, total parent-
    // child edges ≤ 2N), and for Node256 it's floor(2N / 49) ≈ 5.
    // Caps are 2× those bounds to leave room for routes registered in
    // unusual orders that drive extra upgrade churn through edge
    // splits and method-slot indirection.
    //
    // Worst-case inline memory:
    //   Node4   × 256 × 48  B = 12.3 KB
    //   Node16  ×  64 × 88  B =  5.6 KB
    //   Node48  ×  32 × 392 B = 12.5 KB
    //   Node256 ×   8 × 552 B =  4.3 KB
    //   plus per-pool len / index overhead                ~ <1 KB
    //   ≈ 35 KB total inline — vs ByteRadixTrie's ~75 KB.
    static constexpr u32 kMaxN4 = 256;
    static constexpr u32 kMaxN16 = 64;
    static constexpr u32 kMaxN48 = 32;
    static constexpr u32 kMaxN256 = 8;

    ArtTrie() { clear(); }

    // Wipe and re-seed with the empty root node (a Node4 at idx 0).
    void clear();

    // Insert a (path, method, route_idx). Returns false if:
    //   - method byte isn't recognized,
    //   - any pool is at capacity at any step. Insert is atomic — any
    //     mutation is rolled back to pre-insert state on failure.
    //
    // CONTRACT: route_idx is monotonic with insertion order. First-
    // insert-wins on duplicate (path, method).
    bool insert(Str path, u8 method_char, u16 route_idx);

    // Look up `path` — returns the longest-prefix terminal's
    // route_idx for the matching method slot, or kInvalidRoute on no
    // match.
    //
    // Two entry points:
    //
    //   match(raw_path, method)         — canonicalizes internally
    //                                      (strips leading '/', '?',
    //                                      '#', trailing '/'), then
    //                                      descends. Convenient for
    //                                      direct unit tests.
    //   match_canonical(canon_path, method) — assumes input is already
    //                                      canonical. Used by
    //                                      RouteConfig::match where
    //                                      canon is done once at
    //                                      dispatch entry. Saves the
    //                                      ~7 ns canon scan per
    //                                      lookup on the production
    //                                      hot path.
    //
    // PR #50 round 6: lifted the canon-inside-match design out so
    // both scalar and JIT'd paths can share a single canon scan.
    u16 match(Str path, u8 method_char) const;
    u16 match_canonical(Str canon_path, u8 method_char) const;

    // Same as match_canonical(), but `method_key` must already be a
    // canonical route method key. Used by RouteConfig's production hot
    // path to keep legacy first-char compatibility out of dispatch.
    u16 match_canonical_key(Str canon_path, u8 method_key) const;

    // Introspection (tests / bench). node_count returns the sum
    // across pools (root included).
    u32 node_count() const { return n4_pool_len_ + n16_pool_len_ + n48_pool_len_ + n256_pool_len_; }
    u32 n4_count() const { return n4_pool_len_; }
    u32 n16_count() const { return n16_pool_len_; }
    u32 n48_count() const { return n48_pool_len_; }
    u32 n256_count() const { return n256_pool_len_; }

    // Pools are intentionally public, not behind accessor methods:
    // the JIT codegen in src/jit/art_jit_codegen.cc walks the trie
    // depth-first at IR-emission time and needs random access to the
    // node arrays. An accessor API would add either virtual dispatch
    // (rejected by -fno-rtti / -fno-exceptions style) or a header-
    // bloat surface that exposes the same fields anyway. Layout
    // stability is enforced by tests + the JIT's bench parity gate;
    // changes to these fields are an acknowledged ABI change between
    // rut_runtime and rut_jit.
    ArtNode4 n4_pool_[kMaxN4];
    ArtNode16 n16_pool_[kMaxN16];
    ArtNode48 n48_pool_[kMaxN48];
    ArtNode256 n256_pool_[kMaxN256];
    u32 n4_pool_len_ = 0;
    u32 n16_pool_len_ = 0;
    u32 n48_pool_len_ = 0;
    u32 n256_pool_len_ = 0;
    ArtChildRef root_ref_ = 0;

private:
    // True iff every node in the trie is a Node4 (no Node16/48/256
    // has ever been allocated). Set on clear(), cleared the first
    // time alloc_n16/48/256 succeeds. match() checks this flag and
    // uses a specialized hot-path loop that skips all type switches
    // when it holds — closes the bench gap vs ByteRadix on the
    // realistic-saas shape, where ~95% of nodes are Node4 in
    // practice. Bench data drove this: the polymorphic descent loop
    // was paying ~2 cycles/step for indirect-branch dispatch.
    bool is_uniform_n4_ = true;

    // Header accessor — uniform across types so descent reads it
    // without a switch.
    ArtNodeHeader& header(ArtChildRef ref);
    const ArtNodeHeader& header(ArtChildRef ref) const;

    // Find the child of `parent` whose first edge byte equals `b`.
    // Returns kArtInvalidChildRef on no match.
    ArtChildRef find_child(ArtChildRef parent, u8 b) const;

    // Add `child` to `parent` keyed at byte `b`. Caller guarantees no
    // existing child has key `b`. May upgrade parent to a wider node
    // type if its current type's cap is reached. Returns the new
    // parent ref (same as input unless an upgrade happened, in which
    // case the caller must update its parent-of-parent link).
    // Returns kArtInvalidChildRef on pool capacity exhaustion.
    ArtChildRef add_child(ArtChildRef parent, u8 b, ArtChildRef child);

    // Allocate a fresh node of the given type. Returns
    // kArtInvalidChildRef on pool exhaustion.
    ArtChildRef alloc_n4();
    ArtChildRef alloc_n16();
    ArtChildRef alloc_n48();
    ArtChildRef alloc_n256();

    // Pick the per-method terminal at `node` honouring slot-0 fallback
    // for "any". Same logic as ByteRadixTrie::pick_terminal.
    static u16 pick_terminal(const ArtNodeHeader& h, u32 slot);
};

}  // namespace rut
