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

#include "rut/runtime/route_trie.h"

namespace rut {

// ---------------------------------------------------------------------------
// Path tokenization — encodes the normalization policies
// ---------------------------------------------------------------------------
//   P1a: drop empty segments (consecutive '/' collapse; leading '/' yields
//        no segment)
//   P2a: trailing '/' is equivalent to no trailing '/' — falls out of P1a
//        once the trailing empty run is skipped
//   P3a: case-sensitive — bytes are preserved verbatim, no tolower
//
// Returns the segment count, or kMaxPathSegments + 1 as a sentinel when the
// path would produce more segments than `out` can hold. The two callers
// treat the sentinel differently:
//   - insert() rejects sentinel results at build time (registering a
//     truncated path would land the route at the wrong depth relative
//     to what the user wrote).
//   - match() ignores the sentinel and routes using whatever segment
//     prefix `out` does hold, so a request that exceeds the cap still
//     hits the deepest applicable terminal — preserving catchall and
//     longest-prefix semantics rather than failing-closed on input
//     length alone (Codex P1 caught the earlier fail-closed match()).

u32 RouteTrie::tokenize_segments(Str path, FixedVec<Str, kMaxPathSegments>& out) {
    // Pure segment split — query/fragment stripping is the caller's
    // job. Routes arrive here via RouteConfig::add_* which already
    // rejected inputs containing '?' / '#', so insert() sees a clean
    // path. Incoming requests go through match(), which shortens the
    // Str above any '?' / '#' before calling tokenize. Keeping
    // tokenize pure means the insert-vs-match round-trip always
    // agrees on what a segment is: bytes between slashes.
    u32 start = 0;
    for (u32 i = 0; i <= path.len; i++) {
        const bool at_sep = (i == path.len) || (path.ptr[i] == '/');
        if (!at_sep) continue;
        if (i > start) {
            if (!out.push(Str{path.ptr + start, i - start})) return kMaxPathSegments + 1;
        }
        start = i + 1;
    }
    return out.len;
}

// ---------------------------------------------------------------------------
// Trie storage and lookup helpers
// ---------------------------------------------------------------------------

void RouteTrie::clear() {
    nodes.len = 0;
    TrieNode root{};
    [[maybe_unused]] bool ok = nodes.push(root);
    // push cannot fail on a fresh FixedVec; nodes starts empty.
}

u16 RouteTrie::find_child(u16 parent, Str segment) const {
    if (segment.len == 0) return TrieNode::kInvalidNodeIdx;
    const auto& p = nodes[parent];
    // Linear scan with full segment compare. Str::eq short-circuits on
    // length mismatch (usually the common case for heterogeneous
    // siblings) and then on first-byte mismatch if lengths coincide,
    // giving the same "first-byte fast path" as a separate u8 index —
    // but without the extra array and extra branch. Bench data confirms
    // this is faster than the httprouter-style parallel index for our
    // segment-length distribution.
    for (u32 i = 0; i < p.children.len; i++) {
        const u16 child_idx = p.children[i];
        if (nodes[child_idx].segment.eq(segment)) return child_idx;
    }
    return TrieNode::kInvalidNodeIdx;
}

bool RouteTrie::is_param_segment(Str segment) {
    return segment.len > 0 && segment.ptr[0] == ':';
}

bool RouteTrie::insert(Str path, u8 method_char, u16 route_idx) {
    // Reject unsupported method bytes up-front. An earlier revision
    // fell back to slot 0 ("any") for unknown chars, which would
    // silently broaden a route's method filter; fail fast instead so
    // callers notice (Codex P2 on #41).
    const u32 slot = method_slot(method_char);
    if (slot == kMethodSlotInvalid) return false;

    FixedVec<Str, kMaxPathSegments> segs{};
    const u32 n = tokenize_segments(path, segs);
    // Sentinel: a path with more segments than we can hold is rejected
    // at insert time. Silently truncating would create a route
    // registered at the wrong depth relative to what the user wrote.
    if (n > kMaxPathSegments) return false;

    // Snapshot state before any mutation so a mid-insert failure can
    // fully undo everything we've done so far. Per-iteration
    // pre-flights aren't sufficient on their own: a deep route that
    // creates k-1 nodes successfully and then fails at segment k was
    // still leaving k-1 ghost nodes (and the children-array pushes
    // that pointed at them) in place, consuming capacity until the
    // pool filled up and legitimate later routes got rejected. Codex
    // P1 on #41.
    const u32 saved_nodes_len = nodes.len;
    // Parents whose children list grew during this insert, one entry
    // per appended child. Rollback pops each parent's children list
    // in reverse order so they return to their pre-insert length.
    FixedVec<u16, kMaxPathSegments> pushed_parents{};

    auto rollback = [&]() {
        for (u32 r = pushed_parents.len; r > 0; r--) {
            nodes[pushed_parents[r - 1]].children.len--;
        }
        nodes.len = saved_nodes_len;
    };

    u16 cur = 0;  // root
    for (u32 i = 0; i < n; i++) {
        u16 child = find_child(cur, segs[i]);
        if (child == TrieNode::kInvalidNodeIdx) {
            // Capacity pre-flight — no mutation if either cap would
            // be exceeded. This avoids the usual "push succeeded,
            // dangling node left behind" leak on a same-iteration
            // failure.
            if (nodes.len >= kMaxNodes || nodes[cur].children.full()) {
                rollback();
                return false;
            }
            TrieNode nn{};
            nn.segment = segs[i];
            if (!nodes.push(nn)) {
                rollback();
                return false;
            }
            child = static_cast<u16>(nodes.len - 1);
            if (!nodes[cur].children.push(child)) {
                // Pre-flight above rules this out, but if a future
                // FixedVec invariant change makes it reachable, fall
                // into the full rollback so the pool stays clean.
                rollback();
                return false;
            }
            if (!pushed_parents.push(cur)) {
                // Unreachable: pushed_parents has the same cap as
                // segs (kMaxPathSegments) and we push at most one
                // entry per iteration. Roll back defensively anyway.
                rollback();
                return false;
            }
        }
        cur = child;
    }
    // Record at the terminal. First-insert-wins on the same (path, method)
    // pair — preserves the existing add-order semantics for duplicates.
    if (nodes[cur].route_idx_by_method[slot] == TrieNode::kInvalidRoute) {
        nodes[cur].route_idx_by_method[slot] = route_idx;
    }
    return true;
}

u16 RouteTrie::match(Str path, u8 method_char) const {
    // Unsupported method bytes can't match anything — bail before
    // touching the trie. Consistent with the insert-time rejection.
    const u32 want_slot = method_slot(method_char);
    return match_key(path, static_cast<u8>(want_slot));
}

u16 RouteTrie::match_key(Str path, u8 method_key) const {
    return match_key(path, method_key, nullptr, nullptr, 0);
}

u16 RouteTrie::match_key(Str path,
                         u8 method_key,
                         RouteParam* out_params,
                         u32* out_param_count,
                         u32 out_param_cap) const {
    if (out_param_count) *out_param_count = 0;
    const u32 want_slot = method_key_slot(method_key);
    if (want_slot == kMethodSlotInvalid) return TrieNode::kInvalidRoute;

    // Caller passes canonical input (PR #50 round 6 — RouteConfig::
    // match canonicalizes once at dispatch entry and rejects non-
    // origin-form targets there). The previous internal
    // canonicalization scan + origin-form guard moved to the caller.

    FixedVec<Str, kMaxPathSegments> segs{};
    // Ignore tokenize's return value on overflow: `segs` still holds
    // the first kMaxPathSegments, and we want to walk the trie as deep
    // as we have data for. Bailing out on overflow would let a request
    // that's deeper than cap bypass a '/' catchall or a matching
    // prefix route — insert() already rejects too-deep route configs,
    // so the trie never contains a terminal we'd miss.
    (void)tokenize_segments(path, segs);
    struct Candidate {
        u16 route_idx = TrieNode::kInvalidRoute;
        u32 depth = 0;
        u32 static_segments = 0;
        u64 static_mask = 0;
        bool method_specific = false;
        FixedVec<RouteParam, kMaxRouteParams> params{};
    };
    Candidate best{};

    struct Terminal {
        u16 route_idx;
        bool method_specific;
    };
    auto pick_terminal = [](const TrieNode& node, u32 slot) -> Terminal {
        // Prefer a method-specific slot; fall back to slot 0 ("any").
        if (slot != 0 && node.route_idx_by_method[slot] != TrieNode::kInvalidRoute) {
            return {node.route_idx_by_method[slot], true};
        }
        return {node.route_idx_by_method[0], false};
    };

    auto consider = [&](Terminal terminal,
                        u32 depth,
                        u32 static_segments,
                        u64 static_mask,
                        const FixedVec<RouteParam, kMaxRouteParams>& params) {
        if (terminal.route_idx == TrieNode::kInvalidRoute) return;
        if (best.route_idx == TrieNode::kInvalidRoute || depth > best.depth ||
            (depth == best.depth && static_segments > best.static_segments) ||
            (depth == best.depth && static_segments == best.static_segments &&
             static_mask > best.static_mask) ||
            (depth == best.depth && static_segments == best.static_segments &&
             static_mask == best.static_mask && terminal.method_specific &&
             !best.method_specific)) {
            best.route_idx = terminal.route_idx;
            best.depth = depth;
            best.static_segments = static_segments;
            best.static_mask = static_mask;
            best.method_specific = terminal.method_specific;
            best.params = params;
        }
    };

    struct Frame {
        u16 node;
        u32 seg_i;
        u32 depth;
        u32 static_segments;
        u64 static_mask;
        FixedVec<RouteParam, kMaxRouteParams> params;
    };
    FixedVec<Frame, kMaxNodes> stack{};
    [[maybe_unused]] bool pushed = stack.push(Frame{});

    while (stack.len > 0) {
        const Frame frame = stack[stack.len - 1];
        stack.len--;
        consider(pick_terminal(nodes[frame.node], want_slot),
                 frame.depth,
                 frame.static_segments,
                 frame.static_mask,
                 frame.params);
        if (frame.seg_i >= segs.len) continue;

        const auto& node = nodes[frame.node];
        for (u32 child_i = node.children.len; child_i > 0; child_i--) {
            const u16 param_child = node.children[child_i - 1];
            const Str name = nodes[param_child].segment;
            if (!is_param_segment(name)) continue;
            Frame next = frame;
            next.node = param_child;
            next.seg_i = frame.seg_i + 1;
            next.depth = frame.depth + 1;
            if (next.params.len < kMaxRouteParams) {
                [[maybe_unused]] bool ok = next.params.push(RouteParam{
                    name.ptr + 1, name.len - 1, segs[frame.seg_i].ptr, segs[frame.seg_i].len});
            }
            [[maybe_unused]] bool ok = stack.push(next);
        }

        const u16 literal_child = find_child(frame.node, segs[frame.seg_i]);
        if (literal_child != TrieNode::kInvalidNodeIdx &&
            !is_param_segment(nodes[literal_child].segment)) {
            Frame next = frame;
            next.node = literal_child;
            next.seg_i = frame.seg_i + 1;
            next.depth = frame.depth + 1;
            next.static_segments = frame.static_segments + 1;
            if (next.depth < 64) next.static_mask |= 1ull << (63 - next.depth);
            [[maybe_unused]] bool ok = stack.push(next);
        }
    }
    if (out_params && out_param_count) {
        const u32 n = best.params.len < out_param_cap ? best.params.len : out_param_cap;
        for (u32 i = 0; i < n; i++) out_params[i] = best.params[i];
        *out_param_count = n;
    }
    return best.route_idx;
}

}  // namespace rut
