#include "rut/runtime/route_trie.h"

#include "rut/common/types.h"
#include "rut/runtime/route_params.h"

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
    method_mask_ = 0;
    needs_backtracking_ = false;
    TrieNode root{};
    [[maybe_unused]] bool ok = nodes.push(root);
    // push cannot fail on a fresh FixedVec; nodes starts empty.
}

u16 RouteTrie::find_child(u16 parent, Str segment, u32 first_child) const {
    if (segment.len == 0) return TrieNode::kInvalidNodeIdx;
    const auto& p = nodes[parent];
    // Linear scan with full segment compare. Str::eq short-circuits on
    // length mismatch (usually the common case for heterogeneous
    // siblings) and then on first-byte mismatch if lengths coincide,
    // giving the same "first-byte fast path" as a separate u8 index —
    // but without the extra array and extra branch. Bench data confirms
    // this is faster than the httprouter-style parallel index for our
    // segment-length distribution.
    for (u32 i = first_child; i < p.children.len; i++) {
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

    FixedVec<u16, kMaxPathSegments + 1> visited;
    [[maybe_unused]] const bool kRootRecorded = visited.push(0);
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
        [[maybe_unused]] const bool kRecorded = visited.push(cur);
    }
    // Record at the terminal. First-insert-wins on the same (path, method)
    // pair — preserves the existing add-order semantics for duplicates.
    if (nodes[cur].route_idx_by_method[slot] == TrieNode::kInvalidRoute) {
        nodes[cur].route_idx_by_method[slot] = route_idx;
    }
    // Publish the parameter partition only after all fallible work succeeds.
    // Until here every new child was merely appended, so rollback remains
    // a simple pop and cannot corrupt an existing parameter prefix.
    for (u32 i = 0; i < pushed_parents.len; ++i) {
        auto& parent = nodes[pushed_parents[i]];
        const u32 kLast = parent.children.len - 1;
        const u16 kChild = parent.children[kLast];
        if (is_param_segment(nodes[kChild].segment)) {
            for (u32 j = kLast; j > parent.children.param_count; --j)
                parent.children[j] = parent.children[j - 1];
            parent.children[parent.children.param_count++] = kChild;
        }
        needs_backtracking_ |= parent.children.param_count != 0 && parent.children.len > 1;
    }
    const u16 kMethodBit = static_cast<u16>(1u << slot);
    for (u32 i = 0; i < visited.len; ++i) nodes[visited[i]].children.method_mask |= kMethodBit;
    method_mask_ |= kMethodBit;
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
    const u16 kEligibleMethods = static_cast<u16>(1u | (1u << want_slot));
    if ((method_mask_ & kEligibleMethods) == 0) return TrieNode::kInvalidRoute;

    // Caller passes canonical input (PR #50 round 6 — RouteConfig::
    // match canonicalizes once at dispatch entry and rejects non-
    // origin-form targets there). The previous internal
    // canonicalization scan + origin-form guard moved to the caller.

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

    // Literal siblings are mutually exclusive, as is a sole parameter child.
    // These deterministic trees need no backtracking even when they branch.
    // Stream the path and remember the deepest method-compatible terminal.
    if (!needs_backtracking_) {
        u16 current = 0;
        u16 winner = TrieNode::kInvalidRoute;
        u32 position = 0;
        u32 captured = 0;
        u32 winner_captures = 0;
        const u32 kCap = out_params && out_param_count
                             ? (out_param_cap < kMaxRouteParams ? out_param_cap : kMaxRouteParams)
                             : 0;
        for (;;) {
            const auto& node = nodes[current];
            const auto kTerminal = pick_terminal(node, want_slot);
            if (kTerminal.route_idx != TrieNode::kInvalidRoute) {
                winner = kTerminal.route_idx;
                winner_captures = captured;
            }
            // A leaf already decides this prefix match. Never scan the suffix
            // or tokenize unrelated segments after an early mismatch.
            if (node.children.empty()) break;
            while (position < path.len && path.ptr[position] == '/') ++position;
            if (position == path.len) break;
            const u32 kStart = position;
            while (position < path.len && path.ptr[position] != '/') ++position;
            const Str kValue{path.ptr + kStart, position - kStart};
            const u16 kChild =
                node.children.len == 1 ? node.children[0] : find_child(current, kValue);
            if (kChild == TrieNode::kInvalidNodeIdx) break;
            const Str kName = nodes[kChild].segment;
            if (is_param_segment(kName)) {
                if (captured < kCap) {
                    out_params[captured++] =
                        RouteParam{kName.ptr + 1, kName.len - 1, kValue.ptr, kValue.len};
                }
            } else if (!kName.eq(kValue)) {
                break;
            }
            current = kChild;
        }
        // A deeper method-ineligible prefix may have written extra captures;
        // only the winning prefix's entries are part of the output.
        if (out_param_count) *out_param_count = winner_captures;
        return winner;
    }

    FixedVec<Str, kMaxPathSegments> segs;
    // Ignore tokenize's return value on overflow: `segs` still holds
    // the first kMaxPathSegments, and we want to walk the trie as deep
    // as we have data for. Bailing out on overflow would let a request
    // that's deeper than cap bypass a '/' catchall or a matching
    // prefix route — insert() already rejects too-deep route configs,
    // so the trie never contains a terminal we'd miss.
    (void)tokenize_segments(path, segs);
    // Keep only the active DFS path, not a node-pool-sized collection of
    // copied capture arrays. Each pushed frame is initialized before reading.
    struct Frame {
        u16 node;
        u32 depth;
        u32 next_child;
        u32 static_segments;
        u64 static_mask;
    };
    FixedVec<Frame, kMaxPathSegments + 1> stack;
    [[maybe_unused]] const bool kPushed = stack.push(Frame{});

    struct Candidate {
        u16 route_idx = TrieNode::kInvalidRoute;
        u32 depth = 0;
        u32 static_segments = 0;
        u64 static_mask = 0;
        bool method_specific = false;
    };
    Candidate best{};
    u16 best_path[kMaxPathSegments];

    auto consider = [&](Terminal terminal, u32 depth, u32 static_segments, u64 static_mask) {
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
            // Record only node IDs for the winning path. Capture views are
            // materialized once, after the search, and only when requested.
            if (out_params && out_param_count && out_param_cap != 0 && depth != static_segments) {
                for (u32 i = 1; i < stack.len; ++i) best_path[i - 1] = stack[i].node;
            }
        }
    };

    while (stack.len > 0) {
        Frame& frame = stack[stack.len - 1];
        const auto& node = nodes[frame.node];
        if (frame.next_child == 0) {
            consider(pick_terminal(node, want_slot),
                     frame.depth,
                     frame.static_segments,
                     frame.static_mask);
            // A complete all-literal match has maximal depth and specificity.
            // No parameter sibling can improve it; captures are necessarily empty.
            if (best.route_idx != TrieNode::kInvalidRoute && best.depth == segs.len &&
                best.static_segments == best.depth)
                return best.route_idx;
            if (frame.depth >= segs.len) {
                --stack.len;
                continue;
            }
            // Visit the literal first, then parameter children in insertion
            // order, preserving the original tie-breaking traversal order.
            frame.next_child = 1;
            const u16 kLiteral =
                find_child(frame.node, segs[frame.depth], node.children.param_count);
            if (kLiteral != TrieNode::kInvalidNodeIdx) {
                const u32 kDepth = frame.depth + 1;
                const u64 kMask = frame.static_mask | (kDepth < 64 ? 1ull << (63 - kDepth) : 0);
                [[maybe_unused]] const bool kOk =
                    stack.push(Frame{kLiteral, kDepth, 0, frame.static_segments + 1, kMask});
                continue;
            }
        }
        bool descended = false;
        while (frame.next_child <= node.children.param_count) {
            const u16 kChild = node.children[frame.next_child++ - 1];
            if ((nodes[kChild].children.method_mask & kEligibleMethods) == 0) continue;
            [[maybe_unused]] const bool kOk = stack.push(
                Frame{kChild, frame.depth + 1, 0, frame.static_segments, frame.static_mask});
            descended = true;
            break;
        }
        if (!descended) --stack.len;
    }
    if (out_params && out_param_count && best.route_idx != TrieNode::kInvalidRoute &&
        best.static_segments != best.depth) {
        const u32 kCap = out_param_cap < kMaxRouteParams ? out_param_cap : kMaxRouteParams;
        for (u32 i = 0; i < best.depth && *out_param_count < kCap; ++i) {
            const Str kName = nodes[best_path[i]].segment;
            if (!is_param_segment(kName)) continue;
            const Str kValue = segs[i];
            out_params[(*out_param_count)++] =
                RouteParam{kName.ptr + 1, kName.len - 1, kValue.ptr, kValue.len};
        }
    }
    return best.route_idx;
}

}  // namespace rut
