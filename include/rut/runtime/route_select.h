#pragma once

// Route dispatch eligibility: ART handles literal segment-prefix routes,
// including overlapping byte prefixes. SegmentTrie is required only for
// dynamic parameter segments. Performance specialization remains inside ART.

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

// True iff any route needs parameter matching/capture. Literal boundary
// collisions are handled directly by scalar and JIT ART.
bool needs_segment_aware(const Str* paths, u32 n);

}  // namespace rut
