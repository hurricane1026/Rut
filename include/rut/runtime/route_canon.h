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

// Path canonicalization for dispatch. Lifted out of the per-dispatch
// match() functions in PR #50 round 6 — both scalar ART and the
// JIT'd code now assume their input is already canonical, so the
// canon scan happens exactly once per request regardless of which
// dispatch is active.
//
// PR #50 round 7 (path A): the HTTP parser's URI scan now produces
// canon_end (position of first '?'/'#' in the URI) as a free byproduct
// of the same SIMD pass that finds the request-line space. The parser
// uses finalize_path_canonical() to strip leading '/' and trailing '/'
// from [uri_start, canon_end), producing path_canon directly. Callers
// with a pre-parsed canonical input use RouteConfig::match_canonical
// to skip the redundant scan in canonicalize_request.
//
// Two entry points:
//   - canonicalize_request(Str): full canon from a raw URI (no parser
//     help available). Used by tests and integration code that hand
//     raw paths to RouteConfig::match.
//   - finalize_path_canonical(ptr, len): cheap finalizer for inputs
//     that have already been trimmed at the first '?'/'#'. Used by
//     the HTTP parser after its SIMD-fused scan.
//
// Output: a Str view into the input buffer. Never allocates, never
// touches bytes outside the input range.

#include "rut/common/types.h"

namespace rut {

// Strip leading '/' and trailing '/' runs from a path slice that has
// already had query-string and fragment bytes trimmed off (e.g. from
// the HTTP parser's canon_end output). Returns a sub-view.
//
// Both the leading and trailing strips collapse runs, so "//api//"
// canonicalizes to "api//" — the leading slashes are gone and the
// trailing slash run is gone, but embedded multi-slashes are
// preserved verbatim (RFC 3986 leaves embedded slashes semantic;
// most servers including nginx normalize them, but doing that here
// would conflate distinct routes that happen to share a prefix
// modulo collapsed slashes — left to the route owner).
//
// Stripping all leading slashes (rather than just one) is required
// by the match_canonical contract: "no leading '/'". Otherwise an
// input like "//api" would canon to "/api" with a stray leading
// slash, and the trie descent — which compares byte-by-byte against
// terminals registered without the leading slash — would not match.
//
// Empty / null input fast path: ptr == nullptr is allowed and maps
// to the empty canon view {nullptr, 0}. Without this guard the
// final `Str{ptr + lo, ...}` would do pointer arithmetic on nullptr
// (technically UB even when the offset is 0), so we short-circuit.
inline Str finalize_path_canonical(const char* ptr, u32 len) {
    if (ptr == nullptr) return Str{nullptr, 0};
    u32 lo = 0;
    while (lo < len && ptr[lo] == '/') lo++;
    u32 hi = len;
    while (hi > lo && ptr[hi - 1] == '/') hi--;
    return Str{ptr + lo, hi - lo};
}

// Canonicalize a raw URI: scan for first '?'/'#' to find the canon-end
// upper bound, then finalize. For callers without a parser-provided
// canon_end (tests, integration helpers). Empty-Str / null-ptr input
// is handled cleanly via finalize_path_canonical's null guard.
inline Str canonicalize_request(Str path) {
    if (path.ptr == nullptr) return Str{nullptr, 0};
    u32 hi = 0;
    while (hi < path.len && path.ptr[hi] != '?' && path.ptr[hi] != '#') hi++;
    return finalize_path_canonical(path.ptr, hi);
}

}  // namespace rut
