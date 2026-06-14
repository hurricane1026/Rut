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

#include "rut/common/types.h"
#include "rut/runtime/route_method.h"
#include "rut/runtime/route_params.h"

namespace rut {

// RouteTrie — segment-aware radix router for RouteConfig.
//
// Replaces the O(n) linear scan in RouteConfig::match() with a trie lookup
// that gives O(segments × fanout) match time. At 128 routes the trie is
// ~2.6× faster than the linear scan in hot-cache microbenchmarks (see
// bench/bench_route_trie.cc). Crossover is around 32 routes; below that,
// linear scan wins because tokenize() adds fixed per-lookup overhead that
// the flat byte-compare doesn't pay.
//
// Child lookup is a plain linear scan over the children array with full
// segment comparison. The benchmark also evaluated the common
// httprouter / matchit "parallel u8 first-byte index" optimization: it is
// within 1–3% of this simple layout at our segment-length distribution
// (3–6 byte segments, small fan-outs), which is inside run-to-run noise
// and well under the ~7–10% overhead of the translation-unit boundary
// production calls cross anyway. We take the simpler design — fewer
// bytes per node, less code to maintain — and leave the first-byte index
// as an optimization that can be re-added if workloads change (longer segments,
// larger fan-outs, or SIMD-ready eq).
//
// Semantics: segment-aware prefix match with longest-match-wins.
//   - Path is split on '/' into segments.
//   - Empty segments are dropped (so "/api//v1" == "/api/v1", "/api/" == "/api").
//   - Matching is case-sensitive (per RFC 3986).
//   - Route segments beginning with ':' match one request segment.
//     Callers may request captured (name, value) views for the matched route.
//   - A route attached at the root ("/") acts as a catch-all for any request.
//   - If multiple routes share a path, the first-inserted wins (build-order
//     determinism for duplicate keys; the trie is built incrementally via
//     add_* calls during RouteConfig construction, then treated as
//     read-only once the RouteConfig is published via RCU swap).
//
// Method dispatch: each terminal node holds a small per-method slot table so
// two routes with the same path but different HTTP methods both fit. Lookup
// prefers a method-specific slot and falls back to the "any" slot. (This is
// a semantic refinement over the old linear scan's first-match-wins across
// method boundaries; see commit message for details.)

// ---------------------------------------------------------------------------
// Method slot encoding
// ---------------------------------------------------------------------------
// method_slot() packs route-method keys into a dense
// [0..kMethodSlots) index for use as an array subscript. Slot 0 =
// "any"; slots 1..9 are the full HTTP methods, so POST/PUT/PATCH no
// longer collide. Legacy hand-built configs that still pass first
// chars ('G', 'P', etc.) are normalized by route_method_slot(); legacy
// 'P' maps to POST only.
static constexpr u32 kMethodSlots = kRouteMethodSlots;
static constexpr u32 kMethodSlotInvalid = kRouteMethodSlotInvalid;
inline u32 method_slot(u8 method_key_or_legacy_char) {
    return route_method_slot(method_key_or_legacy_char);
}
inline u32 method_key_slot(u8 method_key) {
    return route_method_slot_from_key(method_key);
}

// ---------------------------------------------------------------------------
// TrieNode
// ---------------------------------------------------------------------------
// Nodes live in a flat `RouteTrie::nodes` pool and reference each other via
// u16 indices (not pointers) so the whole trie is a single contiguous region
// safe to atomically swap under RCU.
//
// The root node (index 0) has an empty `segment`; every other node's
// `segment` is the non-empty text of the path segment leading into it.

struct TrieNode {
    // Sized to match RouteConfig::kMaxRoutes exactly. A config that
    // declares 128 routes all as distinct children of the same parent
    // (e.g. 128 top-level paths under root) must not be rejected on
    // topology alone — that would narrow the capacity contract the
    // pre-trie linear scan already honored (Codex P1 on #41). Most
    // inner nodes use very little of this (gateway routes rarely
    // have wide fan-out past root); the wasted-slots memory is
    // 128 × 2B − actual_children × 2B per node, tolerable at 512
    // nodes total.
    static constexpr u32 kMaxChildren = 128;

    // Edge label: the path segment that leads INTO this node. Non-owning,
    // points into the original RouteEntry::path buffer on RouteConfig.
    Str segment{};

    // Child node-pool indices. find_child scans these linearly with a full
    // segment compare — see the comment at the top of this file for why
    // we don't layer a separate first-byte index on top.
    FixedVec<u16, kMaxChildren> children;

    // Per-method route index at this terminal. kInvalidRoute means "this
    // node is not terminal for that method". Slot 0 is "any"; other slots
    // are per-method (see method_slot()).
    static constexpr u16 kInvalidRoute = 0xffffu;
    // "No child found" sentinel returned by find_child(). Numerically
    // equal to kInvalidRoute (both are 0xffffu — u16's max value used
    // as a "missing" sentinel) but kept as a distinct constant so
    // call sites read clearly: a node-pool index lookup is not the
    // same kind of thing as a route-table index lookup, even though
    // u16 happens to carry both. Copilot caught the conflation on
    // #43 round 4.
    static constexpr u16 kInvalidNodeIdx = 0xffffu;
    u16 route_idx_by_method[kMethodSlots] = {kInvalidRoute,
                                             kInvalidRoute,
                                             kInvalidRoute,
                                             kInvalidRoute,
                                             kInvalidRoute,
                                             kInvalidRoute,
                                             kInvalidRoute,
                                             kInvalidRoute,
                                             kInvalidRoute,
                                             kInvalidRoute};
};

// ---------------------------------------------------------------------------
// RouteTrie
// ---------------------------------------------------------------------------
// Owns the node pool. Built incrementally via insert() calls (RouteConfig
// drives these from its add_* methods). Once the enclosing RouteConfig is
// published, treat the trie as read-only — RCU-friendly.

class RouteTrie {
public:
    // 128 routes × 32-segment distinct paths (no prefix sharing) need
    // 1 + 128*32 = 4097 nodes — the +1 covers the root. Earlier
    // values were off by one at the documented boundary: 2048
    // rejected a valid 16-seg flat config (Codex P2 on #41 round 9),
    // and 4096 then rejected the very 32-seg shape its own doc
    // claimed to cover (Codex P2 on #41 round 13). 4097 is the exact
    // worst-case for the advertised coverage; we deliberately don't
    // round up further because deeper "pathological" configs (33-64
    // segs per route, no sharing) are vanishingly rare and a smaller
    // pool keeps the inline RouteConfig footprint near the existing
    // ~1.2 MB. Memory cost: 4097 × ~290 B/node ≈ 1.2 MB per
    // RouteConfig.
    static constexpr u32 kMaxNodes = 4097;
    // Sized so any legal request URI or registered route fits without
    // truncation. RouteEntry::kMaxPathLen is 128 bytes, which at a
    // minimum per-segment cost of 2 bytes ('/' + one content byte)
    // gives 64 segments worst case; ConnectionBase::kMaxReqPathLen is
    // 64 bytes (→ 32 segments). Pick the larger to cover route
    // admission. Codex flagged #41 P2 where a 16-cap rejected valid
    // 17-segment route configs.
    static constexpr u32 kMaxPathSegments = 64;

    RouteTrie() { clear(); }

    // Wipe and re-seed with the root node.
    void clear();

    // Insert a route. `path` must be a RouteEntry::path view (persistent
    // across the trie's lifetime — we store non-owning segment views into it).
    // `method_char` is a route method key (or a legacy first-char
    // method byte accepted by method_slot()).
    // `route_idx` is the position in RouteConfig::routes.
    //
    // Returns false if the trie is out of node-pool capacity or a node is
    // out of child-slots — callers should treat either as a build-time
    // "route table too complex" failure and refuse the config.
    bool insert(Str path, u8 method_char, u16 route_idx);

    // Look up `path` and return the route index of the longest-matching
    // terminal whose method slot is compatible with `method_char`. Returns
    // TrieNode::kInvalidRoute if nothing matches.
    u16 match(Str path, u8 method_char) const;

    // Same as match(), but `method_key` must already be a canonical
    // route method key. Used by RouteConfig's production hot path so
    // legacy first-char normalization stays out of request dispatch.
    u16 match_key(Str path, u8 method_key) const;

    // Same as match_key(), but also materializes route params from the
    // winning dynamic route into caller-owned storage. `out_param_count`
    // is set to 0 on miss and to the number copied on hit.
    u16 match_key(Str path,
                  u8 method_key,
                  RouteParam* out_params,
                  u32* out_param_count,
                  u32 out_param_cap) const;

    // Introspection helpers (for tests / bench).
    u32 node_count() const { return nodes.len; }

private:
    FixedVec<TrieNode, kMaxNodes> nodes;

    // Split `path` into segments according to the normalization policy.
    //   - Drop empty segments ("/api//v1" → ["api", "v1"], "/" → []).
    //   - A trailing '/' produces an empty final segment that is then
    //     dropped — so "/api/" and "/api" both yield ["api"].
    //   - Match case-sensitively; preserve bytes verbatim (no tolower).
    //
    // Query and fragment stripping (the '?' / '#' bytes) is the
    // caller's concern, not tokenize's. RouteConfig::add_* rejects
    // route paths containing those bytes before we ever see them;
    // match() shortens the incoming request path above the first '?'
    // or '#' before calling tokenize. Keeping tokenize pure means
    // the insert-vs-match round-trip always agrees on what counts
    // as a segment.
    //
    // Returns the segment count on success, or kMaxPathSegments + 1 as
    // a sentinel when the path would produce more segments than `out`
    // can hold. `insert()` rejects sentinel results so a build-time
    // config with too-deep paths fails cleanly; `match()` ignores the
    // sentinel and runs with the (truncated) segments so deep request
    // URIs still fall back to a catchall or prefix route.
    //
    // Does not allocate — `out` is caller-provided storage, emitted
    // Str views point into the path portion of `path.ptr`.
    static u32 tokenize_segments(Str path, FixedVec<Str, kMaxPathSegments>& out);

    // Linear-scan child lookup: walks `children` and compares the full
    // segment via Str::eq. Returns the child's node-pool index, or
    // TrieNode::kInvalidNodeIdx if no child matches. See the comment
    // at the top of this file for why we don't layer a u8 first-byte
    // index on top — at our segment-length distribution it's a net
    // cost, not a savings.
    u16 find_child(u16 parent, Str segment) const;

    static bool is_param_segment(Str segment);
};

}  // namespace rut
