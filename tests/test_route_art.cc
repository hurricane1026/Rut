// Tests for ArtTrie — semantic parity with test_route_byte_radix
// (every test there has a counterpart here under the same name) plus
// ART-specific coverage for node-type upgrades, root upgrades, and
// the partial-snapshot rollback.

#include "rut/runtime/route_art.h"
#include "rut/runtime/route_table.h"  // RouteConfig::kMaxRoutes
#include "test.h"
#include <memory>
#include <new>
#include <string>
#include <vector>

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

TEST(route_config, cache_capacity_matches_frontend_limit) {
    RouteConfig cfg;
    REQUIRE(cfg.add_cache_instance("max", 3, RouteConfig::kMaxCacheCapacity));
    CHECK_FALSE(cfg.add_cache_instance("too_big", 7, RouteConfig::kMaxCacheCapacity + 1));
    CHECK_FALSE(cfg.add_cache_instance("wrap", 4, 0xffffffffu));
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

namespace {
StrictLocalResponsePolicySpec local_policy(
    Str reason,
    Str content_type,
    Str server,
    Str body,
    u16 status = 400,
    StrictLocalResponseHeadMode head_mode = StrictLocalResponseHeadMode::Reject) {
    StrictLocalResponsePolicySpec p{};
    p.version = StrictLocalResponseVersion::Http11;
    p.status_code = status;
    p.date = StrictLocalResponseDate::Current;
    p.connection = StrictLocalResponseConnection::Request;
    p.head_mode = head_mode;
    p.reason = reason;
    p.content_type = content_type;
    p.server = server;
    p.body = body;
    return p;
}

ExactStrictLocalResponseBinding exact_local_binding(const char* path,
                                                    u8 method,
                                                    u16 policy_id,
                                                    ExactPathView path_view = ExactPathView::Raw) {
    ExactStrictLocalResponseBinding binding{};
    const u32 len = static_cast<u32>(strlen(path));
    if (len > kMaxExactStrictLocalResponsePathLen) return binding;
    __builtin_memcpy(binding.path, path, len);
    binding.path_len = static_cast<u8>(len);
    binding.method = method;
    binding.path_view = path_view;
    binding.policy_id = policy_id;
    return binding;
}
}  // namespace

TEST(route_config, unmatched_owned_table_exact_pool_dedup_and_atomic_rejection) {
    const std::string reason1(1, 'a'), type1(1, 'b'), server1(1, 'c');
    const std::string reason2(1, 'd'), type2(1, 'e'), server2(1, 'f');
    const std::string body1(4096, 'x'), body2(4090, 'y');
    StrictLocalResponsePolicySpec exact[2] = {
        local_policy({reason1.data(), 1},
                     {type1.data(), 1},
                     {server1.data(), 1},
                     {body1.data(), static_cast<u32>(body1.size())}),
        local_policy({reason2.data(), 1},
                     {type2.data(), 1},
                     {server2.data(), 1},
                     {body2.data(), static_cast<u32>(body2.size())},
                     405)};
    u16 ids[kStrictLocalResponseMethodSlots]{};
    ids[kRouteMethodOptions] = 1;
    ids[kRouteMethodConnect] = 2;
    auto cfg = std::make_unique<RouteConfig>();
    REQUIRE(cfg->add_static("/kept", kRouteMethodGet, 204));
    REQUIRE(cfg->install_unmatched_policy_table(exact, 2, ids));
    CHECK_EQ(cfg->strict_local_response_bytes_used, 8192u);
    CHECK_EQ(cfg->strict_local_response_policy_count, 2u);
    CHECK(cfg->unmatched_policy_table_is_valid());
    CHECK(cfg->strict_local_response_policy_id_is_owned(1));
    CHECK_EQ(cfg->routes[0].status_code, 204u);

    const std::string body_over(4091, 'z');
    exact[1].body = {body_over.data(), static_cast<u32>(body_over.size())};
    auto overflow = std::make_unique<RouteConfig>();
    CHECK_FALSE(overflow->install_unmatched_policy_table(exact, 2, ids));
    CHECK_FALSE(overflow->has_unmatched_metadata());
    auto unrelated = std::make_unique<RouteConfig>();
    REQUIRE(unrelated->add_static("/kept", kRouteMethodGet, 207));
    std::vector<u8> unrelated_before(sizeof(RouteConfig));
    __builtin_memcpy(unrelated_before.data(), unrelated.get(), sizeof(RouteConfig));
    CHECK_FALSE(unrelated->install_unmatched_policy_table(exact, 2, ids));
    CHECK_EQ(__builtin_memcmp(unrelated_before.data(), unrelated.get(), sizeof(RouteConfig)), 0);
    std::vector<u8> before(sizeof(RouteConfig));
    __builtin_memcpy(before.data(), cfg.get(), sizeof(RouteConfig));
    CHECK_FALSE(cfg->install_unmatched_policy_table(exact, 2, ids));
    CHECK_EQ(__builtin_memcmp(before.data(), cfg.get(), sizeof(RouteConfig)), 0);

    StrictLocalResponsePolicySpec duplicate[2] = {
        local_policy({"Bad", 3}, {"text/plain", 10}, {"rut", 3}, {"x", 1}),
        local_policy({"Bad", 3}, {"text/plain", 10}, {"rut", 3}, {"x", 1})};
    auto dedup = std::make_unique<RouteConfig>();
    REQUIRE(dedup->install_unmatched_policy_table(duplicate, 2, ids));
    CHECK_EQ(dedup->strict_local_response_policy_count, 1u);
    CHECK_EQ(dedup->unmatched_policy_ids[kRouteMethodOptions], 1u);
    CHECK_EQ(dedup->unmatched_policy_ids[kRouteMethodConnect], 1u);
    CHECK(dedup->unmatched_policy_table_is_valid());
}

TEST(route_config, unmatched_empty_body_lifetime_owned_ranges_and_reset) {
    auto cfg = std::make_unique<RouteConfig>();
    {
        std::string reason = "Nope";
        std::string type = "text/plain";
        std::string server = "rut";
        StrictLocalResponsePolicySpec p =
            local_policy({reason.data(), 4}, {type.data(), 10}, {server.data(), 3}, {nullptr, 0});
        u16 ids[kStrictLocalResponseMethodSlots]{};
        ids[kRouteMethodOptions] = 1;
        REQUIRE(cfg->install_unmatched_policy_table(&p, 1, ids));
    }
    REQUIRE(cfg->unmatched_policy_table_is_valid());
    CHECK_EQ(cfg->strict_local_response_policies[0].body.len, 0u);
    CHECK(cfg->strict_local_response_policies[0].body.ptr >= cfg->strict_local_response_bytes);
    CHECK(cfg->strict_local_response_policies[0].body.ptr <=
          cfg->strict_local_response_bytes + cfg->strict_local_response_bytes_used);

    const Str saved = cfg->strict_local_response_policies[0].body;
    const Str saved_reason = cfg->strict_local_response_policies[0].reason;
    cfg->strict_local_response_policies[0].reason = {"external", 1};
    CHECK_FALSE(cfg->unmatched_policy_table_is_valid());
    cfg->strict_local_response_policies[0].reason = {
        cfg->strict_local_response_bytes + cfg->strict_local_response_bytes_used, 1};
    CHECK_FALSE(cfg->unmatched_policy_table_is_valid());
    cfg->strict_local_response_policies[0].reason = saved_reason;
    cfg->strict_local_response_policies[0].body = {"external", 1};
    CHECK_FALSE(cfg->unmatched_policy_table_is_valid());
    cfg->strict_local_response_policies[0].body = {
        cfg->strict_local_response_bytes + cfg->strict_local_response_bytes_used, 1};
    CHECK_FALSE(cfg->unmatched_policy_table_is_valid());
    cfg->strict_local_response_policies[0].body = saved;
    REQUIRE(cfg->unmatched_policy_table_is_valid());

    cfg->~RouteConfig();
    new (cfg.get()) RouteConfig();
    CHECK_FALSE(cfg->has_unmatched_metadata());
    CHECK(cfg->unmatched_policy_table_is_valid());
}

TEST(route_config, unmatched_copy_rebases_integer_addresses_without_pointer_subtraction) {
    const std::string body1(4096, 'x');
    const std::string body2(4087, 'y');
    StrictLocalResponsePolicySpec policies[3] = {
        local_policy({"a", 1}, {"b", 1}, {"c", 1}, {body1.data(), 4096}),
        local_policy({"d", 1}, {"e", 1}, {"f", 1}, {body2.data(), 4087}),
        local_policy({"g", 1}, {"h", 1}, {"i", 1}, {nullptr, 0}),
    };
    auto source = std::make_unique<RouteConfig>();
    u16 ids[kStrictLocalResponseMethodSlots]{};
    ids[kRouteMethodOptions] = 1;
    ids[kRouteMethodConnect] = 2;
    ids[kRouteMethodTrace] = 3;
    REQUIRE(source->install_unmatched_policy_table(policies, 3, ids));
    REQUIRE_EQ(source->strict_local_response_bytes_used,
               RouteConfig::kStrictLocalResponseBytesPoolBytes);

    // Reconstitute every view solely from its numeric address. This models a
    // forged public view whose value falls inside the owned pool but whose C++
    // array provenance cannot be assumed by the copy/rebase implementation.
    auto numeric_view = [](Str value) {
        return Str{reinterpret_cast<const char*>(reinterpret_cast<uintptr_t>(value.ptr)),
                   value.len};
    };
    for (u32 i = 0; i < source->strict_local_response_policy_count; i++) {
        auto& stored = source->strict_local_response_policies[i];
        stored.reason = numeric_view(stored.reason);
        stored.content_type = numeric_view(stored.content_type);
        stored.server = numeric_view(stored.server);
        stored.body = numeric_view(stored.body);
    }
    const uintptr_t source_base = reinterpret_cast<uintptr_t>(source->strict_local_response_bytes);
    auto& one_past = source->strict_local_response_policies[2].body;
    one_past = {
        reinterpret_cast<const char*>(source_base + source->strict_local_response_bytes_used), 0};
    REQUIRE(source->unmatched_policy_table_is_valid());

    auto copied = std::make_unique<RouteConfig>();
    REQUIRE(copied->copy_unmatched_policy_table_from_owned(*source));
    REQUIRE(copied->unmatched_policy_table_is_valid());
    CHECK(copied->strict_local_response_policies[0].reason.eq({"a", 1}));
    CHECK(copied->strict_local_response_policies[2].body.ptr ==
          copied->strict_local_response_bytes + copied->strict_local_response_bytes_used);

    // The actual array-one-past numeric address is only valid for an empty view.
    // A nonempty view must reject before any destination byte changes.
    one_past.len = 1;
    auto rejected = std::make_unique<RouteConfig>();
    REQUIRE(rejected->add_static("/kept", kRouteMethodGet, 207));
    std::vector<u8> before(sizeof(RouteConfig));
    __builtin_memcpy(before.data(), rejected.get(), sizeof(RouteConfig));
    CHECK_FALSE(rejected->copy_unmatched_policy_table_from_owned(*source));
    CHECK_EQ(__builtin_memcmp(before.data(), rejected.get(), sizeof(RouteConfig)), 0);
}

TEST(route_config, unmatched_complete_install_rejects_partial_destination_and_bad_head_mapping) {
    StrictLocalResponsePolicySpec reject =
        local_policy({"Bad", 3}, {"text/plain", 10}, {"rut", 3}, {"x", 1});
    u16 options[kStrictLocalResponseMethodSlots]{};
    options[kRouteMethodOptions] = 1;

    auto rejects_unchanged = [&](auto prepopulate) {
        auto cfg = std::make_unique<RouteConfig>();
        prepopulate(*cfg);
        std::vector<u8> before(sizeof(RouteConfig));
        __builtin_memcpy(before.data(), cfg.get(), sizeof(RouteConfig));
        CHECK_FALSE(cfg->install_unmatched_policy_table(&reject, 1, options));
        CHECK_EQ(__builtin_memcmp(before.data(), cfg.get(), sizeof(RouteConfig)), 0);
    };
    rejects_unchanged([](RouteConfig& c) { c.strict_local_response_policy_count = 1; });
    rejects_unchanged([](RouteConfig& c) { c.strict_local_response_bytes_used = 1; });
    rejects_unchanged([](RouteConfig& c) { c.unmatched_policy_ids[kRouteMethodOptions] = 1; });

    auto invalid_id = std::make_unique<RouteConfig>();
    u16 bad[kStrictLocalResponseMethodSlots]{};
    bad[kRouteMethodOptions] = 2;
    CHECK_FALSE(invalid_id->install_unmatched_policy_table(&reject, 1, bad));
    CHECK_FALSE(invalid_id->has_unmatched_metadata());

    for (u8 slot : {kRouteMethodAny, kRouteMethodHead}) {
        auto invalid_head = std::make_unique<RouteConfig>();
        u16 mapped[kStrictLocalResponseMethodSlots]{};
        mapped[slot] = 1;
        CHECK_FALSE(invalid_head->install_unmatched_policy_table(&reject, 1, mapped));
        CHECK_FALSE(invalid_head->has_unmatched_metadata());
    }
}

TEST(route_config, exact_strict_table_dedups_remaps_owns_copies_and_rolls_back_atomically) {
    std::string reason = "Local";
    std::string type = "text/plain";
    std::string server = "rut";
    std::string body = "owned-body";
    StrictLocalResponsePolicySpec policies[3] = {
        local_policy({reason.data(), 5}, {type.data(), 10}, {server.data(), 3}, {body.data(), 10}),
        local_policy({reason.data(), 5}, {type.data(), 10}, {server.data(), 3}, {body.data(), 10}),
        local_policy({reason.data(), 5}, {type.data(), 10}, {server.data(), 3}, {body.data(), 10}),
    };
    u16 unmatched[kStrictLocalResponseMethodSlots]{};
    unmatched[kRouteMethodOptions] = 1;
    ExactStrictLocalResponseBinding exact[kMaxExactStrictLocalResponseBindings]{};
    exact[0] = exact_local_binding("/static", kRouteMethodGet, 2);
    exact[1] = exact_local_binding("/submit", kRouteMethodPost, 3);

    auto installed = std::make_unique<RouteConfig>();
    REQUIRE(installed->install_strict_local_response_table(policies, 3, unmatched, exact, 2));
    REQUIRE(installed->strict_local_response_table_is_valid());
    CHECK(installed->has_exact_strict_local_response_inventory());
    CHECK_EQ(installed->strict_local_response_policy_count, 1u);
    CHECK_EQ(installed->unmatched_policy_ids[kRouteMethodOptions], 1u);
    CHECK_EQ(installed->exact_strict_local_response_binding_count, 2u);
    CHECK_EQ(installed->exact_strict_local_response_bindings[0].policy_id, 1u);
    CHECK_EQ(installed->exact_strict_local_response_bindings[1].policy_id, 1u);
    CHECK_EQ(installed->match_exact_strict_local_response({"/static", 7}, kRouteMethodGet), 1u);
    CHECK_EQ(installed->match_exact_strict_local_response({"/static?x=1", 11}, kRouteMethodGet),
             1u);
    CHECK_EQ(installed->match_exact_strict_local_response({"/static/", 8}, kRouteMethodGet), 0u);
    CHECK_EQ(installed->match_exact_strict_local_response({"/static/child", 13}, kRouteMethodGet),
             0u);
    CHECK_EQ(installed->match_exact_strict_local_response({"//static", 8}, kRouteMethodGet), 0u);
    CHECK_EQ(installed->match_exact_strict_local_response({"/static", 7}, kRouteMethodPost), 0u);

    reason.assign("xxxxx");
    type.assign("xxxxxxxxxx");
    server.assign("xxx");
    body.assign("xxxxxxxxxx");
    CHECK(installed->strict_local_response_policies[0].reason.eq({"Local", 5}));
    CHECK(installed->strict_local_response_policies[0].body.eq({"owned-body", 10}));
    CHECK_EQ(
        __builtin_memcmp(installed->exact_strict_local_response_bindings[0].path, "/static", 7), 0);

    auto copied = std::make_unique<RouteConfig>();
    REQUIRE(copied->copy_strict_local_response_table_from_owned(*installed));
    REQUIRE(copied->strict_local_response_table_is_valid());
    CHECK(copied->strict_local_response_policies[0].body.ptr >=
          copied->strict_local_response_bytes);
    CHECK(copied->strict_local_response_policies[0].body.ptr <
          copied->strict_local_response_bytes + copied->strict_local_response_bytes_used);
    CHECK(copied->strict_local_response_policies[0].body.ptr !=
          installed->strict_local_response_policies[0].body.ptr);
    CHECK_EQ(__builtin_memcmp(copied->exact_strict_local_response_bindings,
                              installed->exact_strict_local_response_bindings,
                              sizeof(copied->exact_strict_local_response_bindings)),
             0);

    auto partial_destination = std::make_unique<RouteConfig>();
    partial_destination->exact_strict_local_response_bindings[15].reserved1 = 1;
    std::vector<u8> before(sizeof(RouteConfig));
    __builtin_memcpy(before.data(), partial_destination.get(), sizeof(RouteConfig));
    CHECK_FALSE(
        partial_destination->install_strict_local_response_table(policies, 3, unmatched, exact, 2));
    CHECK_EQ(__builtin_memcmp(before.data(), partial_destination.get(), sizeof(RouteConfig)), 0);

    ExactStrictLocalResponseBinding invalid_source[kMaxExactStrictLocalResponseBindings]{};
    __builtin_memcpy(invalid_source, exact, sizeof(invalid_source));
    invalid_source[1].method = kRouteMethodGet;
    invalid_source[1].path_len = invalid_source[0].path_len;
    __builtin_memcpy(
        invalid_source[1].path, invalid_source[0].path, sizeof(invalid_source[1].path));
    auto rejected = std::make_unique<RouteConfig>();
    REQUIRE(rejected->add_static("/kept", kRouteMethodGet, 207));
    std::vector<u8> rejected_before(sizeof(RouteConfig));
    __builtin_memcpy(rejected_before.data(), rejected.get(), sizeof(RouteConfig));
    CHECK_FALSE(
        rejected->install_strict_local_response_table(policies, 3, unmatched, invalid_source, 2));
    CHECK_EQ(__builtin_memcmp(rejected_before.data(), rejected.get(), sizeof(RouteConfig)), 0);

    ExactStrictLocalResponseBinding reused_source_id[kMaxExactStrictLocalResponseBindings]{};
    __builtin_memcpy(reused_source_id, exact, sizeof(reused_source_id));
    reused_source_id[1].policy_id = 2;
    auto source_contract_rejected = std::make_unique<RouteConfig>();
    CHECK_FALSE(source_contract_rejected->install_strict_local_response_table(
        policies, 3, unmatched, reused_source_id, 2));
    CHECK_FALSE(source_contract_rejected->has_strict_local_response_table_inventory());

    StrictLocalResponsePolicySpec normalized_policies[2] = {policies[0], policies[0]};
    u16 normalized_unmatched[kStrictLocalResponseMethodSlots]{};
    ExactStrictLocalResponseBinding normalized_source[kMaxExactStrictLocalResponseBindings]{};
    normalized_source[0] = exact_local_binding("/normalized", kRouteMethodGet, 1);
    normalized_source[1] = exact_local_binding("/normalized", kRouteMethodGet, 2);
    normalized_source[1].path_view = ExactPathView::SlashNormalized;
    REQUIRE(strict_local_response_source_table_valid(normalized_policies,
                                                     2,
                                                     normalized_unmatched,
                                                     normalized_source,
                                                     2));
    auto normalized_installed = std::make_unique<RouteConfig>();
    REQUIRE(normalized_installed->install_strict_local_response_table(
        normalized_policies, 2, normalized_unmatched, normalized_source, 2));
    REQUIRE(normalized_installed->strict_local_response_table_is_valid());
    CHECK_EQ(normalized_installed->exact_strict_local_response_binding_count, 2u);
    CHECK_EQ(normalized_installed->exact_strict_local_response_bindings[0].path_view,
             ExactPathView::Raw);
    CHECK_EQ(normalized_installed->exact_strict_local_response_bindings[1].path_view,
             ExactPathView::SlashNormalized);
    CHECK_EQ(normalized_installed->strict_local_response_policy_count, 1u);
    CHECK_EQ(normalized_installed->exact_strict_local_response_bindings[0].policy_id, 1u);
    CHECK_EQ(normalized_installed->exact_strict_local_response_bindings[1].policy_id, 1u);

    auto normalized_copy = std::make_unique<RouteConfig>();
    REQUIRE(normalized_copy->copy_strict_local_response_table_from_owned(*normalized_installed));
    REQUIRE(normalized_copy->strict_local_response_table_is_valid());
    CHECK_EQ(__builtin_memcmp(normalized_copy->exact_strict_local_response_bindings,
                              normalized_installed->exact_strict_local_response_bindings,
                              sizeof(normalized_copy->exact_strict_local_response_bindings)),
             0);
}

TEST(route_config, exact_strict_runtime_validator_rejects_every_binding_forgery_class) {
    const auto policy = local_policy({"Local", 5}, {"text/plain", 10}, {"rut", 3}, {"body", 4});
    u16 unmatched[kStrictLocalResponseMethodSlots]{};
    ExactStrictLocalResponseBinding exact[kMaxExactStrictLocalResponseBindings]{};
    exact[0] = exact_local_binding("/static", kRouteMethodGet, 1);

    auto valid = std::make_unique<RouteConfig>();
    REQUIRE(valid->install_strict_local_response_table(&policy, 1, unmatched, exact, 1));
    REQUIRE(valid->strict_local_response_table_is_valid());
    CHECK_FALSE(valid->unmatched_policy_table_is_valid());

    auto rejects = [&](auto forge) {
        auto candidate = std::make_unique<RouteConfig>();
        REQUIRE(candidate->copy_strict_local_response_table_from_owned(*valid));
        forge(*candidate);
        CHECK(candidate->has_exact_strict_local_response_inventory());
        CHECK_FALSE(candidate->strict_local_response_table_is_valid());
    };
    rejects([](RouteConfig& c) {
        c.exact_strict_local_response_binding_count = kMaxExactStrictLocalResponseBindings + 1;
    });
    rejects([](RouteConfig& c) { c.exact_strict_local_response_bindings[0].path_len = 0; });
    rejects([](RouteConfig& c) { c.exact_strict_local_response_bindings[0].path[0] = 'x'; });
    rejects([](RouteConfig& c) { c.exact_strict_local_response_bindings[0].path[1] = '#'; });
    rejects([](RouteConfig& c) { c.exact_strict_local_response_bindings[0].path[7] = 'x'; });
    rejects([](RouteConfig& c) { c.exact_strict_local_response_bindings[0].method = 10; });
    rejects([](RouteConfig& c) {
        c.exact_strict_local_response_bindings[0].path_view =
            static_cast<ExactPathView>(255);
    });
    rejects([](RouteConfig& c) {
        auto& binding = c.exact_strict_local_response_bindings[0];
        binding.path_view = ExactPathView::SlashNormalized;
        binding.path[2] = '/';
        binding.path[3] = '/';
    });
    rejects([](RouteConfig& c) { c.exact_strict_local_response_bindings[0].reserved1 = 1; });
    rejects([](RouteConfig& c) { c.exact_strict_local_response_bindings[0].policy_id = 0; });
    rejects([](RouteConfig& c) { c.exact_strict_local_response_bindings[0].policy_id = 2; });
    rejects([](RouteConfig& c) {
        c.exact_strict_local_response_binding_count = 0;
        c.exact_strict_local_response_bindings[0].path_len = 0;
    });
    rejects([](RouteConfig& c) { c.exact_strict_local_response_bindings[1].reserved1 = 1; });

    auto duplicate = std::make_unique<RouteConfig>();
    REQUIRE(duplicate->copy_strict_local_response_table_from_owned(*valid));
    duplicate->exact_strict_local_response_bindings[1] =
        duplicate->exact_strict_local_response_bindings[0];
    duplicate->exact_strict_local_response_binding_count = 2;
    CHECK_FALSE(duplicate->strict_local_response_table_is_valid());

    auto method_plus_any = std::make_unique<RouteConfig>();
    REQUIRE(method_plus_any->copy_strict_local_response_table_from_owned(*valid));
    auto any = method_plus_any->exact_strict_local_response_bindings[0];
    any.method = kRouteMethodAny;
    method_plus_any->strict_local_response_policies[0].head_mode =
        StrictLocalResponseHeadMode::SuppressBody;
    method_plus_any->exact_strict_local_response_bindings[1] = any;
    method_plus_any->exact_strict_local_response_binding_count = 2;
    CHECK(method_plus_any->strict_local_response_table_is_valid());

    StrictLocalResponsePolicySpec precedence_policies[2] = {
        valid->strict_local_response_policies[0], valid->strict_local_response_policies[0]};
    precedence_policies[1].status_code = 405;
    precedence_policies[1].head_mode = StrictLocalResponseHeadMode::SuppressBody;
    ExactStrictLocalResponseBinding precedence_bindings[kMaxExactStrictLocalResponseBindings]{};
    precedence_bindings[0] = exact_local_binding("/priority", kRouteMethodGet, 1);
    precedence_bindings[1] = exact_local_binding("/priority", kRouteMethodAny, 2);
    u16 precedence_unmatched[kStrictLocalResponseMethodSlots]{};
    auto precedence = std::make_unique<RouteConfig>();
    REQUIRE(precedence->install_strict_local_response_table(
        precedence_policies, 2, precedence_unmatched, precedence_bindings, 2));
    CHECK_EQ(precedence->match_exact_strict_local_response({"/priority", 9}, kRouteMethodGet), 1u);
    CHECK_EQ(precedence->match_exact_strict_local_response({"/priority", 9}, kRouteMethodPost), 2u);
}

TEST(route_config, exact_strict_mixed_views_are_owned_and_match_with_explicit_precedence) {
    StrictLocalResponsePolicySpec policies[4] = {
        local_policy({"Raw GET", 7}, {"text/plain", 10}, {"rut", 3}, {"raw-get", 7}, 400),
        local_policy({"Norm GET", 8}, {"text/plain", 10}, {"rut", 3}, {"norm-get", 8}, 401),
        local_policy({"Raw ANY", 7},
                     {"text/plain", 10},
                     {"rut", 3},
                     {"raw-any", 7},
                     402,
                     StrictLocalResponseHeadMode::SuppressBody),
        local_policy({"Norm ANY", 8},
                     {"text/plain", 10},
                     {"rut", 3},
                     {"norm-any", 8},
                     403,
                     StrictLocalResponseHeadMode::SuppressBody),
    };
    u16 unmatched[kStrictLocalResponseMethodSlots]{};
    ExactStrictLocalResponseBinding bindings[kMaxExactStrictLocalResponseBindings]{};
    bindings[0] = exact_local_binding("/health/check/", kRouteMethodGet, 1);
    bindings[1] =
        exact_local_binding("/health/check/", kRouteMethodGet, 2, ExactPathView::SlashNormalized);
    bindings[2] = exact_local_binding("/health/check/", kRouteMethodAny, 3);
    bindings[3] =
        exact_local_binding("/health/check/", kRouteMethodAny, 4, ExactPathView::SlashNormalized);

    auto config = std::make_unique<RouteConfig>();
    REQUIRE(config->install_strict_local_response_table(policies, 4, unmatched, bindings, 4));
    REQUIRE(config->strict_local_response_table_is_valid());
    CHECK(config->has_slash_normalized_exact_strict_local_response_inventory());

    const auto expect = [&](Str raw, Str normalized, u8 method, u16 policy_id) {
        const auto result =
            config->match_exact_strict_local_response_views(raw, normalized, method);
        CHECK_EQ(result.state, ExactStrictLocalResponseMatchState::Match);
        CHECK_EQ(result.policy_id, policy_id);
    };
    // Raw concrete beats normalized concrete, including raw query-boundary matching.
    expect({"/health/check/?x=1", 18}, {"/health/check/", 14}, kRouteMethodGet, 1);
    // A doubled slash misses Raw but selects the supplied normalized concrete view.
    expect({"/health/check//", 15}, {"/health/check/", 14}, kRouteMethodGet, 2);
    expect({"/health/check//?x=1", 19}, {"/health/check/", 14}, kRouteMethodGet, 2);
    // Concrete method classes are exhausted before either ANY class.
    expect({"/health/check/", 14}, {"/health/check/", 14}, kRouteMethodPost, 3);
    expect({"/health/check//", 15}, {"/health/check/", 14}, kRouteMethodPost, 4);

    const auto no_slash = config->match_exact_strict_local_response_views(
        {"/health/check", 13}, {"/health/check", 13}, kRouteMethodGet);
    CHECK_EQ(no_slash.state, ExactStrictLocalResponseMatchState::Miss);
    CHECK_EQ(no_slash.policy_id, 0u);
    const auto unrelated = config->match_exact_strict_local_response_views(
        {"/other", 6}, {"/other", 6}, kRouteMethodDelete);
    CHECK_EQ(unrelated.state, ExactStrictLocalResponseMatchState::Miss);
    CHECK_EQ(unrelated.policy_id, 0u);
    const auto opaque = config->match_exact_strict_local_response_views(
        {"/opaque:%2F/../", 15}, {"/opaque:%2F/../", 15}, kRouteMethodGet);
    CHECK_EQ(opaque.state, ExactStrictLocalResponseMatchState::Miss);
    CHECK_EQ(opaque.policy_id, 0u);

    // The legacy raw API remains byte-compatible and ignores normalized rows.
    CHECK_EQ(config->match_exact_strict_local_response({"/health/check//", 15}, kRouteMethodGet),
             0u);
    CHECK_EQ(config->match_exact_strict_local_response({"/health/check/?x=1", 18}, kRouteMethodGet),
             1u);

    const auto invalid = [&](Str normalized) {
        const auto result = config->match_exact_strict_local_response_views(
            {"/health/check/", 14}, normalized, kRouteMethodGet);
        CHECK_EQ(result.state, ExactStrictLocalResponseMatchState::InvalidInput);
        CHECK_EQ(result.policy_id, 0u);
    };
    invalid({nullptr, 0});
    invalid({"", 0});
    invalid({"health/check/", 13});
    invalid({"/health//check/", 15});
    invalid({"/health/check/?x", 16});
    const char too_long[63] = {'/'};
    invalid({too_long, 63});

    auto copied = std::make_unique<RouteConfig>();
    REQUIRE(copied->copy_strict_local_response_table_from_owned(*config));
    config.reset();
    REQUIRE(copied->strict_local_response_table_is_valid());
    const auto after_source_lifetime = copied->match_exact_strict_local_response_views(
        {"/health/check//", 15}, {"/health/check/", 14}, kRouteMethodGet);
    CHECK_EQ(after_source_lifetime.state, ExactStrictLocalResponseMatchState::Match);
    CHECK_EQ(after_source_lifetime.policy_id, 2u);
    CHECK(copied->strict_local_response_policies[1].body.eq({"norm-get", 8}));
    copied->exact_strict_local_response_bindings[0].reserved1 = 1;
    CHECK_FALSE(copied->has_slash_normalized_exact_strict_local_response_inventory());
    const auto invalid_table = copied->match_exact_strict_local_response_views(
        {"/health/check/", 14}, {"/health/check/", 14}, kRouteMethodGet);
    CHECK_EQ(invalid_table.state, ExactStrictLocalResponseMatchState::InvalidInput);
    CHECK_EQ(invalid_table.policy_id, 0u);

    auto forged_count = std::make_unique<RouteConfig>();
    forged_count->exact_strict_local_response_binding_count =
        kMaxExactStrictLocalResponseBindings + 1;
    CHECK_FALSE(forged_count->has_slash_normalized_exact_strict_local_response_inventory());
}

TEST(route_config, exact_strict_mixed_view_capacity_and_normalized_duplicates_are_atomic) {
    StrictLocalResponsePolicySpec policies[kMaxStrictLocalResponsePolicies]{};
    ExactStrictLocalResponseBinding bindings[kMaxExactStrictLocalResponseBindings]{};
    const auto shared = local_policy({"Bad", 3}, {"text/plain", 10}, {"rut", 3}, {"owned", 5}, 400);
    for (u32 i = 0; i < kMaxExactStrictLocalResponseBindings; i++) {
        policies[i] = shared;
        const std::string path = "/capacity/" + std::to_string(i);
        bindings[i] = exact_local_binding(
            path.c_str(),
            kRouteMethodGet,
            static_cast<u16>(i + 1),
            (i & 1u) == 0u ? ExactPathView::Raw : ExactPathView::SlashNormalized);
    }
    u16 unmatched[kStrictLocalResponseMethodSlots]{};
    auto full = std::make_unique<RouteConfig>();
    REQUIRE(full->install_strict_local_response_table(policies,
                                                      kMaxStrictLocalResponsePolicies,
                                                      unmatched,
                                                      bindings,
                                                      kMaxExactStrictLocalResponseBindings));
    REQUIRE(full->strict_local_response_table_is_valid());
    CHECK_EQ(full->exact_strict_local_response_binding_count, kMaxExactStrictLocalResponseBindings);
    CHECK_EQ(full->strict_local_response_policy_count, 1u);

    auto overflow = std::make_unique<RouteConfig>();
    REQUIRE(overflow->add_static("/kept", kRouteMethodGet, 207));
    std::vector<u8> overflow_before(sizeof(RouteConfig));
    __builtin_memcpy(overflow_before.data(), overflow.get(), sizeof(RouteConfig));
    CHECK_FALSE(
        overflow->install_strict_local_response_table(policies,
                                                      kMaxStrictLocalResponsePolicies,
                                                      unmatched,
                                                      bindings,
                                                      kMaxExactStrictLocalResponseBindings + 1));
    CHECK_EQ(__builtin_memcmp(overflow_before.data(), overflow.get(), sizeof(RouteConfig)), 0);

    StrictLocalResponsePolicySpec duplicate_policies[2] = {shared, shared};
    ExactStrictLocalResponseBinding duplicate[kMaxExactStrictLocalResponseBindings]{};
    duplicate[0] =
        exact_local_binding("/duplicate", kRouteMethodGet, 1, ExactPathView::SlashNormalized);
    duplicate[1] =
        exact_local_binding("/duplicate", kRouteMethodGet, 2, ExactPathView::SlashNormalized);
    auto rejected = std::make_unique<RouteConfig>();
    REQUIRE(rejected->add_static("/kept-duplicate", kRouteMethodGet, 208));
    std::vector<u8> rejected_before(sizeof(RouteConfig));
    __builtin_memcpy(rejected_before.data(), rejected.get(), sizeof(RouteConfig));
    CHECK_FALSE(rejected->install_strict_local_response_table(
        duplicate_policies, 2, unmatched, duplicate, 2));
    CHECK_EQ(__builtin_memcmp(rejected_before.data(), rejected.get(), sizeof(RouteConfig)), 0);
}

TEST(route_config, pre_route_strict_table_is_concrete_owned_transactional_and_combined) {
    std::string trace_body = "trace-owned";
    StrictLocalResponsePolicySpec policies[4] = {
        local_policy({"Method Not Allowed", 18},
                     {"text/html", 9},
                     {"nginx/1.29.7", 12},
                     {trace_body.data(), static_cast<u32>(trace_body.size())},
                     405),
        local_policy({"Generic", 7}, {"text/plain", 10}, {"rut", 3}, {"opt", 3}, 418),
        local_policy({"Unmatched", 9}, {"text/plain", 10}, {"rut", 3}, {"miss", 4}, 400),
        local_policy({"OK", 2},
                     {"text/plain", 10},
                     {"nginx/1.29.7", 12},
                     {"exact", 5},
                     200,
                     StrictLocalResponseHeadMode::SuppressBody),
    };
    u16 pre_route[kStrictLocalResponseMethodSlots]{};
    pre_route[kRouteMethodTrace] = 1;
    pre_route[kRouteMethodOptions] = 2;
    u16 unmatched[kStrictLocalResponseMethodSlots]{};
    unmatched[kRouteMethodTrace] = 3;
    ExactStrictLocalResponseBinding exact[kMaxExactStrictLocalResponseBindings]{};
    exact[0] = exact_local_binding("/static", kRouteMethodAny, 4);

    auto installed = std::make_unique<RouteConfig>();
    REQUIRE(installed->add_static("/", kRouteMethodAny, 207));
    REQUIRE(installed->install_strict_local_response_table_with_pre_route(
        policies, 4, pre_route, unmatched, exact, 1));
    REQUIRE(installed->strict_local_response_table_is_valid());
    CHECK(installed->has_pre_route_metadata());
    CHECK(installed->has_unmatched_metadata());
    CHECK_EQ(installed->pre_route_policy_id(kRouteMethodTrace), 1u);
    CHECK_EQ(installed->pre_route_policy_id(kRouteMethodOptions), 2u);
    CHECK_EQ(installed->pre_route_policy_id(kRouteMethodGet), 0u);
    CHECK_EQ(installed->pre_route_policy_id(kRouteMethodAny), 0u);
    CHECK_EQ(installed->unmatched_policy_ids[kRouteMethodTrace], 3u);
    CHECK_EQ(installed->exact_strict_local_response_bindings[0].policy_id, 4u);
    trace_body.assign("overwritten!");
    CHECK(installed->strict_local_response_policies[0].body.eq({"trace-owned", 11}));

    auto copied = std::make_unique<RouteConfig>();
    REQUIRE(copied->copy_strict_local_response_table_from_owned(*installed));
    REQUIRE(copied->strict_local_response_table_is_valid());
    CHECK_EQ(copied->pre_route_policy_ids[kRouteMethodTrace], 1u);
    CHECK(copied->strict_local_response_policies[0].body.ptr !=
          installed->strict_local_response_policies[0].body.ptr);
    CHECK(copied->strict_local_response_policies[0].body.eq({"trace-owned", 11}));

    // Equal policy values from distinct source storage are each referenced
    // exactly once across the three selector families.  Installation performs
    // semantic deduplication only after validating that source ownership, then
    // remaps every selector to the single deep-owned policy.
    std::string dedup_reason[3] = {"OK", "OK", "OK"};
    std::string dedup_type[3] = {"text/plain", "text/plain", "text/plain"};
    std::string dedup_server[3] = {"nginx/1.29.7", "nginx/1.29.7", "nginx/1.29.7"};
    std::string dedup_body[3] = {"same-owned", "same-owned", "same-owned"};
    StrictLocalResponsePolicySpec equal_policies[3]{};
    for (u32 i = 0; i < 3; i++) {
        equal_policies[i] =
            local_policy({dedup_reason[i].data(), static_cast<u32>(dedup_reason[i].size())},
                         {dedup_type[i].data(), static_cast<u32>(dedup_type[i].size())},
                         {dedup_server[i].data(), static_cast<u32>(dedup_server[i].size())},
                         {dedup_body[i].data(), static_cast<u32>(dedup_body[i].size())},
                         200,
                         StrictLocalResponseHeadMode::SuppressBody);
    }
    u16 dedup_pre_route[kStrictLocalResponseMethodSlots]{};
    dedup_pre_route[kRouteMethodTrace] = 1;
    u16 dedup_unmatched[kStrictLocalResponseMethodSlots]{};
    dedup_unmatched[kRouteMethodOptions] = 2;
    ExactStrictLocalResponseBinding dedup_exact[kMaxExactStrictLocalResponseBindings]{};
    dedup_exact[0] = exact_local_binding("/dedup", kRouteMethodAny, 3);
    auto deduplicated = std::make_unique<RouteConfig>();
    REQUIRE(deduplicated->install_strict_local_response_table_with_pre_route(
        equal_policies, 3, dedup_pre_route, dedup_unmatched, dedup_exact, 1));
    REQUIRE(deduplicated->strict_local_response_table_is_valid());
    CHECK_EQ(deduplicated->strict_local_response_policy_count, 1u);
    CHECK_EQ(deduplicated->pre_route_policy_ids[kRouteMethodTrace], 1u);
    CHECK_EQ(deduplicated->unmatched_policy_ids[kRouteMethodOptions], 1u);
    CHECK_EQ(deduplicated->exact_strict_local_response_binding_count, 1u);
    CHECK_EQ(deduplicated->exact_strict_local_response_bindings[0].policy_id, 1u);
    CHECK_EQ(deduplicated->exact_strict_local_response_bindings[0].method, kRouteMethodAny);
    CHECK_EQ(deduplicated->exact_strict_local_response_bindings[0].path_len, 6u);
    CHECK_EQ(
        __builtin_memcmp(deduplicated->exact_strict_local_response_bindings[0].path, "/dedup", 6),
        0);
    auto dedup_copy = std::make_unique<RouteConfig>();
    REQUIRE(dedup_copy->copy_strict_local_response_table_from_owned(*deduplicated));
    REQUIRE(dedup_copy->strict_local_response_table_is_valid());
    CHECK_EQ(dedup_copy->strict_local_response_policy_count, 1u);
    CHECK_EQ(dedup_copy->pre_route_policy_ids[kRouteMethodTrace], 1u);
    CHECK_EQ(dedup_copy->unmatched_policy_ids[kRouteMethodOptions], 1u);
    CHECK_EQ(dedup_copy->exact_strict_local_response_bindings[0].policy_id, 1u);
    CHECK_EQ(
        __builtin_memcmp(dedup_copy->exact_strict_local_response_bindings[0].path, "/dedup", 6), 0);
    CHECK(dedup_copy->strict_local_response_policies[0].body.ptr !=
          deduplicated->strict_local_response_policies[0].body.ptr);
    CHECK(dedup_copy->strict_local_response_policies[0].body.eq({"same-owned", 10}));

    auto dedup_rejected = std::make_unique<RouteConfig>();
    REQUIRE(dedup_rejected->add_static("/kept-dedup", kRouteMethodGet, 208));
    std::vector<u8> dedup_before(sizeof(RouteConfig));
    __builtin_memcpy(dedup_before.data(), dedup_rejected.get(), sizeof(RouteConfig));
    dedup_pre_route[kRouteMethodAny] = 1;
    CHECK_FALSE(dedup_rejected->install_strict_local_response_table_with_pre_route(
        equal_policies, 3, dedup_pre_route, dedup_unmatched, dedup_exact, 1));
    CHECK_EQ(__builtin_memcmp(dedup_before.data(), dedup_rejected.get(), sizeof(RouteConfig)), 0);
    for (u32 i = 0; i < 3; i++) dedup_body[i].assign("source-mutated");
    CHECK(deduplicated->strict_local_response_policies[0].body.eq({"same-owned", 10}));
    CHECK(dedup_copy->strict_local_response_policies[0].body.eq({"same-owned", 10}));

    auto forged = std::make_unique<RouteConfig>();
    REQUIRE(forged->copy_strict_local_response_table_from_owned(*installed));
    forged->pre_route_policy_ids[kRouteMethodAny] = 1;
    CHECK_FALSE(forged->strict_local_response_table_is_valid());
    forged->pre_route_policy_ids[kRouteMethodAny] = 0;
    forged->pre_route_policy_ids[kRouteMethodTrace] = 9;
    CHECK_FALSE(forged->strict_local_response_table_is_valid());

    auto rejected = std::make_unique<RouteConfig>();
    REQUIRE(rejected->add_static("/kept", kRouteMethodGet, 209));
    std::vector<u8> before(sizeof(RouteConfig));
    __builtin_memcpy(before.data(), rejected.get(), sizeof(RouteConfig));
    pre_route[kRouteMethodAny] = 1;
    CHECK_FALSE(rejected->install_strict_local_response_table_with_pre_route(
        policies, 4, pre_route, unmatched, exact, 1));
    CHECK_EQ(__builtin_memcmp(before.data(), rejected.get(), sizeof(RouteConfig)), 0);
}

TEST(route_config, no_content204_owned_install_normalizes_empty_views_and_deduplicates) {
    std::string reasons[4] = {"No Content", "No Content", "No Content", "No Content"};
    std::string servers[4] = {"nginx/1.29.7", "nginx/1.29.7", "nginx/1.29.7", "rut"};
    char empty_a = 0;
    char empty_b = 0;
    const Str empty_views[4] = {{nullptr, 0}, {&empty_a, 0}, {&empty_b + 1, 0}, {nullptr, 0}};
    StrictLocalResponsePolicySpec policies[4]{};
    for (u32 i = 0; i < 4; i++) {
        policies[i] = local_policy({reasons[i].data(), static_cast<u32>(reasons[i].size())},
                                   empty_views[i],
                                   {servers[i].data(), static_cast<u32>(servers[i].size())},
                                   empty_views[3 - i],
                                   204,
                                   StrictLocalResponseHeadMode::SuppressBody);
        REQUIRE_EQ(strict_local_response_policy_profile(policies[i]),
                   StrictLocalResponseProfile::NoContent204);
    }
    CHECK(strict_local_response_policy_spec_equal(policies[0], policies[1]));
    CHECK(strict_local_response_policy_spec_equal(policies[1], policies[2]));
    CHECK_FALSE(strict_local_response_policy_spec_equal(policies[2], policies[3]));

    u16 pre_route[kStrictLocalResponseMethodSlots]{};
    pre_route[kRouteMethodTrace] = 1;
    pre_route[kRouteMethodOptions] = 2;
    u16 unmatched[kStrictLocalResponseMethodSlots]{};
    unmatched[kRouteMethodAny] = 3;
    ExactStrictLocalResponseBinding exact[kMaxExactStrictLocalResponseBindings]{};
    exact[0] = exact_local_binding("/distinct", kRouteMethodGet, 4);

    auto public_add = std::make_unique<RouteConfig>();
    REQUIRE_EQ(public_add->add_strict_local_response_policy(policies[0]), 1u);
    REQUIRE_EQ(public_add->add_strict_local_response_policy_for_internal_propagation(policies[0]),
               1u);
    CHECK(public_add->strict_local_response_policy_id_is_owned(1));

    auto public_install = std::make_unique<RouteConfig>();
    REQUIRE(public_install->install_strict_local_response_table_with_pre_route(
        policies, 4, pre_route, unmatched, exact, 1));
    REQUIRE(public_install->strict_local_response_table_is_valid());
    CHECK_EQ(public_install->strict_local_response_policy_count, 2u);

    u16 public_unmatched[kStrictLocalResponseMethodSlots]{};
    public_unmatched[kRouteMethodAny] = 1;
    ExactStrictLocalResponseBinding public_exact[kMaxExactStrictLocalResponseBindings]{};
    auto public_unmatched_config = std::make_unique<RouteConfig>();
    REQUIRE(public_unmatched_config->install_strict_local_response_table(
        policies, 1, public_unmatched, public_exact, 0));
    auto public_unmatched_alias = std::make_unique<RouteConfig>();
    REQUIRE(public_unmatched_alias->install_unmatched_policy_table(policies, 1, public_unmatched));

    auto installed = std::make_unique<RouteConfig>();
    REQUIRE(installed->install_strict_local_response_table_with_pre_route_for_internal_propagation(
        policies, 4, pre_route, unmatched, exact, 1));
    REQUIRE(installed->strict_local_response_table_is_valid());
    REQUIRE_EQ(installed->strict_local_response_policy_count, 2u);
    CHECK_EQ(installed->pre_route_policy_ids[kRouteMethodTrace], 1u);
    CHECK_EQ(installed->pre_route_policy_ids[kRouteMethodOptions], 1u);
    CHECK_EQ(installed->unmatched_policy_ids[kRouteMethodAny], 1u);
    CHECK_EQ(installed->exact_strict_local_response_bindings[0].policy_id, 2u);
    CHECK_EQ(installed->strict_local_response_bytes_used, 35u);
    for (u32 i = 0; i < installed->strict_local_response_policy_count; i++) {
        const auto& owned = installed->strict_local_response_policies[i];
        CHECK_EQ(strict_local_response_policy_profile(owned),
                 StrictLocalResponseProfile::NoContent204);
        CHECK(owned.content_type.ptr != nullptr);
        CHECK(owned.body.ptr != nullptr);
        CHECK_EQ(owned.content_type.len, 0u);
        CHECK_EQ(owned.body.len, 0u);
        CHECK(installed->strict_local_response_bytes_owned(owned.content_type));
        CHECK(installed->strict_local_response_bytes_owned(owned.body));
    }

    auto copied = std::make_unique<RouteConfig>();
    REQUIRE(copied->copy_strict_local_response_table_from_owned(*installed));
    REQUIRE(copied->strict_local_response_table_is_valid());
    CHECK_EQ(copied->strict_local_response_bytes_used, 35u);
    CHECK(copied->strict_local_response_policies[0].reason.ptr !=
          installed->strict_local_response_policies[0].reason.ptr);
    CHECK(copied->strict_local_response_policies[0].content_type.ptr != nullptr);
    CHECK(copied->strict_local_response_policies[0].body.ptr != nullptr);

    auto internal_copy = std::make_unique<RouteConfig>();
    REQUIRE(internal_copy->copy_strict_local_response_table_from_owned_for_internal_propagation(
        *installed));
    REQUIRE(internal_copy->strict_local_response_table_is_valid());

    for (auto& reason : reasons) reason.assign(reason.size(), 'x');
    for (auto& server : servers) server.assign(server.size(), 'x');
    REQUIRE(installed->strict_local_response_table_is_valid());
    REQUIRE(copied->strict_local_response_table_is_valid());
    CHECK(installed->strict_local_response_policies[0].reason.eq({"No Content", 10}));
    CHECK(copied->strict_local_response_policies[1].server.eq({"rut", 3}));

    auto rejected = std::make_unique<RouteConfig>();
    REQUIRE(rejected->add_static("/kept", kRouteMethodGet, 207));
    std::vector<u8> before(sizeof(RouteConfig));
    __builtin_memcpy(before.data(), rejected.get(), sizeof(RouteConfig));
    auto forged = policies[0];
    forged.reason = {"No Content", 10};
    forged.server = {"nginx/1.29.7", 12};
    forged.content_type = {nullptr, 1};
    u16 forged_unmatched[kStrictLocalResponseMethodSlots]{};
    forged_unmatched[kRouteMethodAny] = 1;
    u16 empty_pre_route[kStrictLocalResponseMethodSlots]{};
    ExactStrictLocalResponseBinding neutral[kMaxExactStrictLocalResponseBindings]{};
    CHECK_FALSE(rejected->install_strict_local_response_table_with_pre_route(
        &forged, 1, empty_pre_route, forged_unmatched, neutral, 0));
    CHECK_EQ(__builtin_memcmp(before.data(), rejected.get(), sizeof(RouteConfig)), 0);

    forged = policies[0];
    forged.reason = {"No Content", 10};
    forged.server = {"nginx/1.29.7", 12};
    forged.reserved1 = 1;
    CHECK_FALSE(rejected->install_strict_local_response_table_with_pre_route(
        &forged, 1, empty_pre_route, forged_unmatched, neutral, 0));
    CHECK_EQ(__builtin_memcmp(before.data(), rejected.get(), sizeof(RouteConfig)), 0);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
