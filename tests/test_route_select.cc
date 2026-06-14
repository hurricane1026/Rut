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

// Tests for the Phase 2 2-way decision helpers in route_select.h.
// The earlier RouteAnalysis + pick_dispatch tests were retired
// alongside the multi-dispatch architecture in PR #50 round 5.

#include "rut/runtime/route_select.h"
#include "test.h"

using namespace rut;

namespace {
constexpr Str S(const char* s) {
    u32 n = 0;
    while (s[n]) n++;
    return Str{s, n};
}
}  // namespace

// ============================================================================
// path_has_param_segment
// ============================================================================

TEST(route_select, path_has_param_segment_detects_colon_at_segment_start) {
    CHECK(path_has_param_segment(S("/api/:id")));
    CHECK(path_has_param_segment(S("/users/:user_id/posts")));
    CHECK(path_has_param_segment(S("/:tenant/api/v1")));
}

TEST(route_select, path_has_param_segment_ignores_colon_mid_segment) {
    CHECK(!path_has_param_segment(S("/api/foo:bar")));
    CHECK(!path_has_param_segment(S("/api/v1/users")));
    CHECK(!path_has_param_segment(S("/")));
    CHECK(!path_has_param_segment(S("")));
}

// ============================================================================
// has_boundary_sensitive_overlap
// ============================================================================

TEST(route_select, has_boundary_sensitive_overlap_detects_apix_pair) {
    Str paths[] = {S("/api"), S("/apix")};
    CHECK(has_boundary_sensitive_overlap(paths, 2));
}

TEST(route_select, has_boundary_sensitive_overlap_rejects_segment_aligned_pair) {
    // /api + /api/v1 — /api is strict prefix but next byte is '/'
    // (segment boundary respected).
    Str paths[] = {S("/api"), S("/api/v1")};
    CHECK(!has_boundary_sensitive_overlap(paths, 2));
}

TEST(route_select, has_boundary_sensitive_overlap_rejects_trailing_slash_prefix) {
    // /api/ canonicalizes to /api, so /api/ + /api/v1 is segment-
    // aligned and should not force SegmentTrie.
    Str paths[] = {S("/api/"), S("/api/v1")};
    CHECK(!has_boundary_sensitive_overlap(paths, 2));
}

TEST(route_select, has_boundary_sensitive_overlap_detects_canonicalized_apix_pair) {
    // /api/ canonicalizes to /api, so /api/ + /apix is still the
    // same boundary-sensitive pair as /api + /apix.
    Str trailing[] = {S("/api/"), S("/apix")};
    CHECK(has_boundary_sensitive_overlap(trailing, 2));

    // Leading slash runs are also stripped before runtime matching.
    Str leading[] = {S("//api"), S("/apix")};
    CHECK(has_boundary_sensitive_overlap(leading, 2));
}

TEST(route_select, has_boundary_sensitive_overlap_handles_either_order) {
    // Reverse insert order: /apix first, /api second.
    Str paths[] = {S("/apix"), S("/api")};
    CHECK(has_boundary_sensitive_overlap(paths, 2));
}

TEST(route_select, has_boundary_sensitive_overlap_root_catchall_not_sensitive) {
    // "/" is a strict byte-prefix of "/api", but the root catchall is
    // not boundary-sensitive — it's designed to match everything, so
    // there is no ambiguity with any sibling route.
    Str paths_root_api[] = {S("/"), S("/api")};
    CHECK(!has_boundary_sensitive_overlap(paths_root_api, 2));
    Str paths_root_multi[] = {S("/"), S("/api"), S("/admin"), S("/apix")};
    // "/api" + "/apix" is still boundary-sensitive even with "/" present.
    CHECK(has_boundary_sensitive_overlap(paths_root_multi, 4));
    // "/" alone with segment-aligned routes is fine.
    Str paths_root_seg[] = {S("/"), S("/api"), S("/api/v1")};
    CHECK(!has_boundary_sensitive_overlap(paths_root_seg, 3));
}

TEST(route_select, has_boundary_sensitive_overlap_empty_or_disjoint) {
    CHECK(!has_boundary_sensitive_overlap(nullptr, 0));
    Str disjoint[] = {S("/api"), S("/admin"), S("/oauth")};
    CHECK(!has_boundary_sensitive_overlap(disjoint, 3));
}

// ============================================================================
// needs_segment_aware (composition)
// ============================================================================

TEST(route_select, needs_segment_aware_combines_both_signals) {
    // (a) :param triggers it
    Str a[] = {S("/api/:id")};
    CHECK(needs_segment_aware(a, 1));

    // (b) boundary-sensitive overlap triggers it
    Str b[] = {S("/api"), S("/apix")};
    CHECK(needs_segment_aware(b, 2));

    // (c) neither — pure byte-prefix-friendly config
    Str c[] = {S("/api/v1/users"), S("/api/v1/orders"), S("/admin")};
    CHECK(!needs_segment_aware(c, 3));

    // (d) segment-aligned overlap is fine — not segment-sensitive
    Str d[] = {S("/api"), S("/api/v1"), S("/api/v1/users")};
    CHECK(!needs_segment_aware(d, 3));

    // (e) root "/" with normal siblings — not segment-sensitive
    Str e[] = {S("/"), S("/api"), S("/admin")};
    CHECK(!needs_segment_aware(e, 3));
}

TEST(route_select, needs_segment_aware_empty_config) {
    CHECK(!needs_segment_aware(nullptr, 0));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
