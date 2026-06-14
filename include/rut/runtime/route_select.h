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

// route_select — minimal 2-way decision helpers for Phase 2 dispatch.
//
// Phase 2 architecture (PR #50):
//   - ART (with optional JIT specialization): byte-prefix matching,
//     covers all configs that don't need segment-aware semantics
//   - SegmentTrie: segment-aware matching for boundary-sensitive
//     overlap (e.g., `/api` registered alongside `/apix`).
//     Note: `:param`-style route paths require SegmentTrie. They are
//     supported as dynamic segments with request-time parameter capture.
//
// The picker is a single boolean:
//
//   if (needs_segment_aware(paths, n)) cfg.use_segment_trie();
//   else                               cfg.use_art();
//
// The earlier multi-dispatch RouteAnalysis + pick_dispatch
// abstraction was retired in PR #50 round 5 once the spike data
// (commit c694c19) showed JIT-specialized ART ran 5× faster than
// ByteRadix on saas configs, making the fan-out gating obsolete.
//
// Tests in `tests/test_route_select.cc` cover the helpers' edge
// cases (segment-aligned overlap, colon-mid-segment, insertion
// order independence).

#include "rut/common/types.h"

namespace rut {

// True iff `path` contains a `:param`-style segment (a segment
// starting with ':'). Single-path check; no pairwise scan.
bool path_has_param_segment(Str path);

// True iff any pair (i, j) in `paths[0..n)` has a strict byte-prefix
// relationship where the byte in the longer path immediately AFTER
// the shared prefix is NOT '/'. E.g. `/api` + `/apix` — byte-prefix
// matching would mis-route `/apij` to `/api` whereas segment-aware
// matching treats it as a miss. O(N²) in n; called once at config-
// build time so the cost is negligible.
bool has_boundary_sensitive_overlap(const Str* paths, u32 n);

// True iff the route set requires segment-aware dispatch — the
// composition of the two checks above. Caller installs SegmentTrie
// for true configs, ART (+JIT) for false. This is the entire
// dispatch decision in Phase 2.
bool needs_segment_aware(const Str* paths, u32 n);

}  // namespace rut
