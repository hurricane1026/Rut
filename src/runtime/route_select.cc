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

// 2-way decision helpers for Phase 2 dispatch — see route_select.h
// for the public contract. The earlier multi-dispatch RouteAnalysis +
// pick_dispatch tree was retired in PR #50 round 5.

#include "rut/runtime/route_select.h"

#include "rut/runtime/route_canon.h"

namespace rut {

namespace {

// True iff `a` is a strict byte-prefix of `b` (a.len < b.len, and
// the first a.len bytes are equal).
bool is_strict_byte_prefix(Str a, Str b) {
    if (a.len >= b.len) return false;
    for (u32 i = 0; i < a.len; i++) {
        if (a.ptr[i] != b.ptr[i]) return false;
    }
    return true;
}

// Given that `a` is a strict byte-prefix of `b` after route-path
// canonicalization, returns true iff the next byte in `b`
// (immediately past the shared prefix) is not '/'. That's the
// "segment-boundary-sensitive overlap" case — /api vs /apix, where
// byte-prefix and segment-prefix matching would diverge for in-
// between requests like /apij.
//
// Exception: the root "/" catchall canonicalizes to the empty
// string. Any sibling path is a new segment under root, so it is not
// boundary-sensitive.
bool boundary_sensitive_after_prefix(Str shorter, Str longer) {
    if (shorter.len == 0) return false;
    return longer.ptr[shorter.len] != '/';
}

}  // namespace

bool path_has_param_segment(Str path) {
    bool at_segment_start = true;
    for (u32 i = 0; i < path.len; i++) {
        const char c = path.ptr[i];
        if (c == '/') {
            at_segment_start = true;
            continue;
        }
        if (at_segment_start && c == ':') return true;
        at_segment_start = false;
    }
    return false;
}

bool has_boundary_sensitive_overlap(const Str* paths, u32 n) {
    for (u32 i = 0; i < n; i++) {
        for (u32 j = i + 1; j < n; j++) {
            const Str a = finalize_path_canonical(paths[i].ptr, paths[i].len);
            const Str b = finalize_path_canonical(paths[j].ptr, paths[j].len);
            Str shorter;
            Str longer;
            if (is_strict_byte_prefix(a, b)) {
                shorter = a;
                longer = b;
            } else if (is_strict_byte_prefix(b, a)) {
                shorter = b;
                longer = a;
            } else {
                continue;
            }
            if (boundary_sensitive_after_prefix(shorter, longer)) return true;
        }
    }
    return false;
}

bool needs_segment_aware(const Str* paths, u32 n) {
    for (u32 i = 0; i < n; i++) {
        if (path_has_param_segment(paths[i])) return true;
    }
    return has_boundary_sensitive_overlap(paths, n);
}

}  // namespace rut
