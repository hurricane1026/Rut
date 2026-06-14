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

// Tests for ArtTrie — semantic parity with test_route_byte_radix
// (every test there has a counterpart here under the same name) plus
// ART-specific coverage for node-type upgrades, root upgrades, and
// the partial-snapshot rollback.

#include "rut/runtime/route_art.h"
#include "rut/runtime/route_table.h"  // RouteConfig::kMaxRoutes
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
// Basic byte-prefix semantics — parity with byte_radix
// ============================================================================

TEST(route_art, exact_match_single_route) {
    ArtTrie t;
    REQUIRE(t.insert(S("/api"), 0, 7));
    CHECK_EQ(t.match(S("/api"), 0), 7u);
}

TEST(route_art, no_match_when_no_routes) {
    ArtTrie t;
    CHECK_EQ(t.match(S("/api"), 0), TrieNode::kInvalidRoute);
}

TEST(route_art, longest_prefix_match_wins) {
    ArtTrie t;
    REQUIRE(t.insert(S("/api"), 0, 1));
    REQUIRE(t.insert(S("/api/v1"), 0, 2));
    REQUIRE(t.insert(S("/api/v1/users"), 0, 3));
    CHECK_EQ(t.match(S("/api"), 0), 1u);
    CHECK_EQ(t.match(S("/api/v1"), 0), 2u);
    CHECK_EQ(t.match(S("/api/v1/users"), 0), 3u);
    CHECK_EQ(t.match(S("/api/v1/users/42"), 0), 3u);
    CHECK_EQ(t.match(S("/api/somewhere"), 0), 1u);
}

TEST(route_art, longest_prefix_independent_of_insert_order) {
    ArtTrie t;
    // Reverse of the previous test — semantically identical.
    REQUIRE(t.insert(S("/api/v1/users"), 0, 3));
    REQUIRE(t.insert(S("/api/v1"), 0, 2));
    REQUIRE(t.insert(S("/api"), 0, 1));
    CHECK_EQ(t.match(S("/api"), 0), 1u);
    CHECK_EQ(t.match(S("/api/v1"), 0), 2u);
    CHECK_EQ(t.match(S("/api/v1/users/x"), 0), 3u);
}

TEST(route_art, edge_split_on_partial_match) {
    ArtTrie t;
    REQUIRE(t.insert(S("/apple"), 0, 1));
    REQUIRE(t.insert(S("/apricot"), 0, 2));
    CHECK_EQ(t.match(S("/apple"), 0), 1u);
    CHECK_EQ(t.match(S("/apricot"), 0), 2u);
    CHECK_EQ(t.match(S("/apple/seed"), 0), 1u);
    CHECK_EQ(t.match(S("/apricot/pit"), 0), 2u);
    CHECK_EQ(t.match(S("/ap"), 0), TrieNode::kInvalidRoute);
}

TEST(route_art, multiple_splits_preserve_terminals) {
    ArtTrie t;
    REQUIRE(t.insert(S("/abcdefgh"), 0, 1));
    REQUIRE(t.insert(S("/abcd1234"), 0, 2));  // splits at "/abcd"
    REQUIRE(t.insert(S("/ab"), 0, 3));        // splits at "/ab"
    CHECK_EQ(t.match(S("/abcdefgh"), 0), 1u);
    CHECK_EQ(t.match(S("/abcd1234"), 0), 2u);
    CHECK_EQ(t.match(S("/ab"), 0), 3u);
    CHECK_EQ(t.match(S("/abxxx"), 0), 3u);
    CHECK_EQ(t.match(S("/abcdyyy"), 0), 3u);  // shared prefix /ab beats nothing
}

TEST(route_art, byte_match_crosses_segment_boundaries) {
    ArtTrie t;
    REQUIRE(t.insert(S("/api"), 0, 1));
    // "/apix" and "/apij" both byte-prefix-match /api — same as
    // ByteRadix, NOT the same as SegmentTrie. The selector is
    // responsible for not picking ART when boundary semantics matter.
    CHECK_EQ(t.match(S("/apix"), 0), 1u);
    CHECK_EQ(t.match(S("/apij"), 0), 1u);
}

TEST(route_art, request_strips_query_and_fragment) {
    ArtTrie t;
    REQUIRE(t.insert(S("/api"), 0, 1));
    CHECK_EQ(t.match(S("/api?q=1"), 0), 1u);
    CHECK_EQ(t.match(S("/api#frag"), 0), 1u);
    CHECK_EQ(t.match(S("/api/v1?check=true"), 0), 1u);
}

TEST(route_art, trailing_slash_normalized) {
    ArtTrie t;
    REQUIRE(t.insert(S("/api/"), 0, 1));    // trailing-/
    CHECK_EQ(t.match(S("/api"), 0), 1u);    // request without
    CHECK_EQ(t.match(S("/api/"), 0), 1u);   // request with
    CHECK_EQ(t.match(S("/api//"), 0), 1u);  // multi
}

TEST(route_art, leading_slash_run_normalized) {
    // Routes registered with multiple leading slashes share the same
    // canonical key as routes with one — both insert and match strip
    // the entire leading-'/' run via finalize_path_canonical. Without
    // this, a config doing add_static("//api", ...) would store the
    // route under a different shape than what requests canonicalize
    // to, leaving it permanently unmatchable.
    ArtTrie t;
    REQUIRE(t.insert(S("//api"), 0, 1));
    CHECK_EQ(t.match(S("/api"), 0), 1u);
    CHECK_EQ(t.match(S("//api"), 0), 1u);
    CHECK_EQ(t.match(S("///api"), 0), 1u);

    // And the reverse — single-slash registration matches multi-slash
    // requests, which is the common-case (config likely writes "/api",
    // request might arrive with extra slashes).
    ArtTrie t2;
    REQUIRE(t2.insert(S("/v2"), 0, 7));
    CHECK_EQ(t2.match(S("//v2"), 0), 7u);
    CHECK_EQ(t2.match(S("////v2"), 0), 7u);
}

TEST(route_art, method_specific_beats_any_at_same_path) {
    ArtTrie t;
    REQUIRE(t.insert(S("/x"), 0, 1));    // any
    REQUIRE(t.insert(S("/x"), 'G', 2));  // GET-specific
    CHECK_EQ(t.match(S("/x"), 'G'), 2u);
    CHECK_EQ(t.match(S("/x"), 'P'), 1u);  // falls back to "any"
    CHECK_EQ(t.match(S("/x"), 0), 1u);
}

TEST(route_art, method_post_put_patch_are_distinct) {
    ArtTrie t;
    REQUIRE(t.insert(S("/x"), kRouteMethodPost, 10));
    REQUIRE(t.insert(S("/x"), kRouteMethodPut, 20));
    REQUIRE(t.insert(S("/x"), kRouteMethodPatch, 30));
    CHECK_EQ(t.match(S("/x"), kRouteMethodPost), 10u);
    CHECK_EQ(t.match(S("/x"), kRouteMethodPut), 20u);
    CHECK_EQ(t.match(S("/x"), kRouteMethodPatch), 30u);
    CHECK_EQ(t.match(S("/x"), 'G'), TrieNode::kInvalidRoute);
}

TEST(route_config, post_put_patch_are_distinct_on_art_dispatch) {
    RouteConfig cfg;
    REQUIRE(cfg.use_art());
    REQUIRE(cfg.add_static("/x", kRouteMethodPost, 201));
    REQUIRE(cfg.add_static("/x", kRouteMethodPut, 202));
    REQUIRE(cfg.add_static("/x", kRouteMethodPatch, 203));
    const auto* post = cfg.match(reinterpret_cast<const u8*>("/x"), 2, kRouteMethodPost);
    const auto* put = cfg.match(reinterpret_cast<const u8*>("/x"), 2, kRouteMethodPut);
    const auto* patch = cfg.match(reinterpret_cast<const u8*>("/x"), 2, kRouteMethodPatch);
    REQUIRE(post != nullptr);
    REQUIRE(put != nullptr);
    REQUIRE(patch != nullptr);
    CHECK_EQ(post->status_code, 201u);
    CHECK_EQ(put->status_code, 202u);
    CHECK_EQ(patch->status_code, 203u);
}

TEST(route_art, first_insert_wins_on_dup_method_slot) {
    ArtTrie t;
    REQUIRE(t.insert(S("/x"), 'G', 0));
    REQUIRE(t.insert(S("/x"), 'G', 1));  // duplicate (path, method)
    CHECK_EQ(t.match(S("/x"), 'G'), 0u);
}

TEST(route_art, rejects_unsupported_method_byte_at_insert) {
    ArtTrie t;
    CHECK(!t.insert(S("/x"), 'g', 0));
    CHECK(!t.insert(S("/x"), 'X', 0));
}

TEST(route_art, rejects_unsupported_method_byte_at_match) {
    ArtTrie t;
    REQUIRE(t.insert(S("/x"), 'G', 0));
    CHECK_EQ(t.match(S("/x"), 'g'), TrieNode::kInvalidRoute);
    CHECK_EQ(t.match(S("/x"), 'X'), TrieNode::kInvalidRoute);
}

TEST(route_art, rejects_non_origin_form_request_targets) {
    ArtTrie t;
    REQUIRE(t.insert(S("/"), 0, 99));
    REQUIRE(t.insert(S("/api"), 0, 7));
    CHECK_EQ(t.match(S("/api"), 0), 7u);
    CHECK_EQ(t.match(S("/anything"), 0), 99u);
    CHECK_EQ(t.match(S("*"), 0), TrieNode::kInvalidRoute);
    CHECK_EQ(t.match(S("example.com:443"), 0), TrieNode::kInvalidRoute);
    CHECK_EQ(t.match(S(""), 0), TrieNode::kInvalidRoute);
}

TEST(route_art, root_path_matches_root_terminal) {
    ArtTrie t;
    REQUIRE(t.insert(S("/"), 0, 42));
    CHECK_EQ(t.match(S("/"), 0), 42u);
    CHECK_EQ(t.match(S("/anything"), 0), 42u);  // root catchall
}

TEST(route_art, clear_resets_state) {
    ArtTrie t;
    REQUIRE(t.insert(S("/a"), 0, 0));
    REQUIRE(t.insert(S("/b"), 0, 1));
    REQUIRE(t.node_count() > 1u);
    t.clear();
    CHECK_EQ(t.node_count(), 1u);  // root only
    CHECK_EQ(t.match(S("/a"), 0), TrieNode::kInvalidRoute);
    REQUIRE(t.insert(S("/c"), 0, 0));
    CHECK_EQ(t.match(S("/c"), 0), 0u);
    CHECK_EQ(t.match(S("/a"), 0), TrieNode::kInvalidRoute);
}

// ============================================================================
// ART-specific — node-type upgrades along the root spine
// ============================================================================

TEST(route_art, root_grows_node4_to_node16_at_fanout_5) {
    ArtTrie t;
    // 4 distinct first-bytes — root stays Node4.
    REQUIRE(t.insert(S("/a"), 0, 0));
    REQUIRE(t.insert(S("/b"), 0, 1));
    REQUIRE(t.insert(S("/c"), 0, 2));
    REQUIRE(t.insert(S("/d"), 0, 3));
    CHECK_EQ(t.n4_count(), 5u);  // root + 4 leaves
    CHECK_EQ(t.n16_count(), 0u);
    // 5th — root upgrades to Node16, leaving the old Node4 in the
    // pool (forward-only upgrades). +1 leaf, +1 Node16 (the new
    // root).
    REQUIRE(t.insert(S("/e"), 0, 4));
    CHECK_EQ(t.n16_count(), 1u);
    // Verify all 5 still match.
    CHECK_EQ(t.match(S("/a"), 0), 0u);
    CHECK_EQ(t.match(S("/c"), 0), 2u);
    CHECK_EQ(t.match(S("/e"), 0), 4u);
}

TEST(route_art, root_grows_node16_to_node48_at_fanout_17) {
    ArtTrie t;
    char paths[17][3];
    for (u32 i = 0; i < 17; i++) {
        paths[i][0] = '/';
        paths[i][1] = static_cast<char>('a' + i);
        paths[i][2] = '\0';
        REQUIRE(t.insert(Str{paths[i], 2}, 0, static_cast<u16>(i)));
    }
    CHECK_EQ(t.n48_count(), 1u);  // root upgraded to Node48
    for (u32 i = 0; i < 17; i++) {
        CHECK_EQ(t.match(Str{paths[i], 2}, 0), static_cast<u16>(i));
    }
}

TEST(route_art, root_grows_node48_to_node256_at_fanout_49) {
    ArtTrie t;
    char paths[49][3];
    for (u32 i = 0; i < 49; i++) {
        paths[i][0] = '/';
        paths[i][1] = static_cast<char>(0x40 + i);
        paths[i][2] = '\0';
        REQUIRE(t.insert(Str{paths[i], 2}, 0, static_cast<u16>(i)));
    }
    CHECK_EQ(t.n256_count(), 1u);
    for (u32 i = 0; i < 49; i++) {
        CHECK_EQ(t.match(Str{paths[i], 2}, 0), static_cast<u16>(i));
    }
}

TEST(route_art, nested_node16_child_dispatches_by_next_byte) {
    ArtTrie t;
    char paths[5][4];
    for (u32 i = 0; i < 5; i++) {
        paths[i][0] = '/';
        paths[i][1] = 'a';
        paths[i][2] = static_cast<char>('0' + i);
        paths[i][3] = '\0';
        REQUIRE(t.insert(Str{paths[i], 3}, 0, static_cast<u16>(10 + i)));
    }
    CHECK_EQ(t.n16_count(), 1u);
    CHECK_EQ(t.match(Str{paths[0], 3}, 0), 10u);
    CHECK_EQ(t.match(Str{paths[4], 3}, 0), 14u);
    CHECK_EQ(t.match(S("/az"), 0), TrieNode::kInvalidRoute);
}

TEST(route_art, nested_node256_child_dispatches_by_next_byte) {
    ArtTrie t;
    char paths[49][4];
    for (u32 i = 0; i < 49; i++) {
        paths[i][0] = '/';
        paths[i][1] = 'a';
        paths[i][2] = static_cast<char>(0x40 + i);
        paths[i][3] = '\0';
        REQUIRE(t.insert(Str{paths[i], 3}, 0, static_cast<u16>(20 + i)));
    }
    CHECK_EQ(t.n256_count(), 1u);
    CHECK_EQ(t.match(Str{paths[0], 3}, 0), 20u);
    CHECK_EQ(t.match(Str{paths[48], 3}, 0), 68u);
    CHECK_EQ(t.match(S("/a!"), 0), TrieNode::kInvalidRoute);
}

TEST(route_art, split_node48_edge_preserves_existing_children) {
    ArtTrie t;
    char paths[17][9];
    for (u32 i = 0; i < 17; i++) {
        paths[i][0] = '/';
        paths[i][1] = 'a';
        paths[i][2] = 'b';
        paths[i][3] = 'c';
        paths[i][4] = 'd';
        paths[i][5] = 'e';
        paths[i][6] = 'f';
        paths[i][7] = static_cast<char>('A' + i);
        paths[i][8] = '\0';
        REQUIRE(t.insert(Str{paths[i], 8}, 0, static_cast<u16>(100 + i)));
    }
    REQUIRE_GE(t.n48_count(), 1u);

    REQUIRE(t.insert(S("/abcxyz"), 0, 500));
    CHECK_EQ(t.match(S("/abcxyz"), 0), 500u);
    CHECK_EQ(t.match(Str{paths[0], 8}, 0), 100u);
    CHECK_EQ(t.match(Str{paths[16], 8}, 0), 116u);
}

TEST(route_art, split_node256_edge_preserves_existing_children) {
    ArtTrie t;
    char paths[49][9];
    for (u32 i = 0; i < 49; i++) {
        paths[i][0] = '/';
        paths[i][1] = 'a';
        paths[i][2] = 'b';
        paths[i][3] = 'c';
        paths[i][4] = 'd';
        paths[i][5] = 'e';
        paths[i][6] = 'f';
        paths[i][7] = static_cast<char>(0x40 + i);
        paths[i][8] = '\0';
        REQUIRE(t.insert(Str{paths[i], 8}, 0, static_cast<u16>(200 + i)));
    }
    REQUIRE_GE(t.n256_count(), 1u);

    REQUIRE(t.insert(S("/abcxyz"), 0, 600));
    CHECK_EQ(t.match(S("/abcxyz"), 0), 600u);
    CHECK_EQ(t.match(Str{paths[0], 8}, 0), 200u);
    CHECK_EQ(t.match(Str{paths[48], 8}, 0), 248u);
}

TEST(route_art, match_canonical_key_rejects_invalid_method_key) {
    ArtTrie t;
    REQUIRE(t.insert(S("/x"), 0, 7));
    CHECK_EQ(t.match_canonical_key(S("x"), 250), TrieNode::kInvalidRoute);
}

TEST(route_art, accepts_kMaxRoutes_distinct_top_level_prefixes) {
    // Same shape as the byte_radix counterpart — 128 distinct first
    // bytes after '/', driving the root all the way to Node256.
    ArtTrie t;
    char paths[128][2];
    for (u32 i = 0; i < 128; i++) {
        paths[i][0] = '/';
        paths[i][1] = static_cast<char>(0x40 + i);
        REQUIRE(t.insert(Str{paths[i], 2}, 0, static_cast<u16>(i)));
    }
    CHECK_EQ(t.n256_count(), 1u);
    CHECK_EQ(t.match(Str{paths[0], 2}, 0), 0u);
    CHECK_EQ(t.match(Str{paths[64], 2}, 0), 64u);
    CHECK_EQ(t.match(Str{paths[127], 2}, 0), 127u);
}

// ============================================================================
// Capacity / atomic rollback
// ============================================================================

TEST(route_art, atomic_insert_on_pool_exhaustion) {
    // Drive the Node4 pool to its cap with single-byte distinct
    // top-level paths. Each insert adds one Node4 leaf. Fill to
    // kMaxN4 - 1, add one more leaf to consume the last slot, then
    // verify the next insert fails cleanly and leaves the pool count
    // unchanged.
    ArtTrie t;
    // Phase 1 — fill up to kMaxN4 - 2 with single-byte distinct
    // top-level paths under root. Each insert: 1 N4 leaf. Plus the
    // root upgrades start eating slots once fan-out exceeds 4 (one
    // Node16 retains the old Node4, etc) — let's keep things simple
    // by capping fan-out at 4 to avoid root upgrades, then add
    // enough depth to fill N4.
    char p1_paths[5][3];
    for (u32 i = 0; i < 4; i++) {
        p1_paths[i][0] = '/';
        p1_paths[i][1] = static_cast<char>('a' + i);
        p1_paths[i][2] = '\0';
        REQUIRE(t.insert(Str{p1_paths[i], 2}, 0, static_cast<u16>(i)));
    }
    REQUIRE_EQ(t.n4_count(), 5u);  // root + 4 leaves

    // Now extend each leaf with a single-byte tail until the N4 pool
    // approaches its cap. Each insert: 1 N4 leaf. Stop when n4_count
    // == kMaxN4 - 1, leaving 1 slot.
    char p2_buf[ArtTrie::kMaxN4][4];
    u32 added = 0;
    for (u32 i = 0; i < 4 && t.n4_count() < ArtTrie::kMaxN4 - 1; i++) {
        for (u32 j = 0; j < 256 && t.n4_count() < ArtTrie::kMaxN4 - 1; j++) {
            // Skip bytes that would collide with previously inserted tails.
            if (j == 0 || j == '/') continue;
            const u32 idx = added++;
            if (idx >= ArtTrie::kMaxN4) break;
            p2_buf[idx][0] = '/';
            p2_buf[idx][1] = static_cast<char>('a' + i);
            p2_buf[idx][2] = static_cast<char>(j);
            p2_buf[idx][3] = '\0';
            REQUIRE(t.insert(Str{p2_buf[idx], 3}, 0, static_cast<u16>(1000 + idx)));
        }
    }
    REQUIRE_EQ(t.n4_count(), ArtTrie::kMaxN4 - 1);

    // Phase 2 — consume the last free slot with one more top-level
    // leaf, then attempt another single-leaf insert. The second insert
    // must fail without changing the pool count.
    p1_paths[4][0] = '/';
    p1_paths[4][1] = static_cast<char>('e');
    p1_paths[4][2] = '\0';
    REQUIRE(t.insert(Str{p1_paths[4], 2}, 0, 9000));  // succeeds, fills last slot
    REQUIRE_EQ(t.n4_count(), ArtTrie::kMaxN4);

    const u32 nodes_before = t.n4_count();
    char fail_path[3] = {'/', 'f', '\0'};
    CHECK(!t.insert(Str{fail_path, 2}, 0, 9001));  // pool full, must fail
    CHECK_EQ(t.n4_count(), nodes_before);          // rollback restored

    // Originals still match.
    CHECK_EQ(t.match(Str{p1_paths[4], 2}, 0), 9000u);
}

TEST(route_art, fills_max_routes_under_node48_pressure) {
    // Adversarial route shape that drives multiple Node48 internal
    // nodes: 7 top-level letter prefixes ("a/" through "g/") each
    // with 17 single-byte distinct second segments (digits 0-9 +
    // uppercase A-G). The byte slot under each prefix gets exactly
    // 17 children → promotes to Node48. Total: 7 Node48s + 119 routes.
    //
    // Why this matters: the theoretical bound on live Node48s in a
    // 128-route trie is floor(2N/17) ≈ 14 (each Node48 has ≥17
    // children, total parent-child edges ≤ 2N). Add upgrade-churn
    // (each Node48→Node256 leaves a "wasted" Node48 slot since the
    // pool doesn't recycle) and the worst-case pool high-water mark
    // can creep above kMaxN48=16 — which is what motivated bumping
    // the cap to 32.
    //
    // This verifies the adversarial set inserts successfully with
    // headroom in the bumped cap. Required: live Node48 count ≥ 5
    // (sanity check that the test really exercises the Node48 path).
    //
    // Paths must outlive the trie — ArtTrie stores Str views into
    // the caller's buffer for edge comparisons. Stack-reused buffers
    // dangle. Use a 2D array kept alive for the test scope.
    ArtTrie t;
    static constexpr char kSecondBytes[] = "0123456789ABCDEFG";  // 17 distinct
    static_assert(sizeof(kSecondBytes) - 1 == 17);
    static constexpr u32 kPrefixes = 7;
    static constexpr u32 kPerPrefix = 17;
    char paths[kPrefixes * kPerPrefix][5];
    u32 idx = 0;
    for (u32 pi = 0; pi < kPrefixes; pi++) {
        for (u32 j = 0; j < kPerPrefix; j++) {
            paths[idx][0] = '/';
            paths[idx][1] = static_cast<char>('a' + pi);
            paths[idx][2] = '/';
            paths[idx][3] = kSecondBytes[j];
            paths[idx][4] = '\0';
            REQUIRE(t.insert(Str{paths[idx], 4}, 0, static_cast<u16>(idx)));
            idx++;
        }
    }
    CHECK_EQ(idx, kPrefixes * kPerPrefix);
    CHECK_LE(idx, RouteConfig::kMaxRoutes);
    // Each "<letter>/" subtree gets 17 distinct second bytes → Node48.
    CHECK_GE(t.n48_count(), 5u);
    // And every route must match — guards against the dangling-Str
    // bug we hit while writing this test (where stack-reused buffers
    // made later inserts spuriously look like duplicates of the
    // first leaf and silently no-op).
    for (u32 i = 0; i < idx; i++) {
        CHECK_EQ(t.match(Str{paths[i], 4}, 0), static_cast<u16>(i));
    }
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
