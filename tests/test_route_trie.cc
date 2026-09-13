// Tests for runtime/route_trie.h: segment tokenization + trie insert/match.
//
// Coverage strategy: the trie has four moving parts — tokenize_segments
// (policy), find_child (linear scan with full segment compare), insert
// (build), match (longest-match + method fallback). Tokenize is
// covered by public observation: insert/match depend on it, so
// asserting correct lookup behavior across the canonical edge-case
// paths (multi-slash, trailing slash, case) exercises tokenize
// indirectly, while dedicated tests below pin the policy at the
// per-path level.

#include "rut/runtime/route_canon.h"
#include "rut/runtime/route_trie.h"
#include "test.h"

using namespace rut;

namespace {

// PR #50 round 6 lifted canonicalization out of RouteTrie::match.
// Tests that exercise the public match() contract through RouteConfig
// still get canonicalization for free, but these direct-trie tests
// pre-canonicalize so we're testing the trie's behavior on canonical
// input (its actual contract).
inline u16 canon_match(const RouteTrie& t, Str raw, u8 method) {
    if (raw.len == 0 || raw.ptr[0] != '/') return TrieNode::kInvalidRoute;
    return t.match(canonicalize_request(raw), method);
}

constexpr Str S(const char* s) {
    u32 n = 0;
    while (s[n]) n++;
    return Str{s, n};
}

// Insert a (path, method, idx) tuple; a bool-returning helper so callers can
// use REQUIRE in the test scope (the REQUIRE macro needs the `_tc` context
// variable that only exists inside TEST macros).
struct Insert {
    const char* path;
    u8 method;
    u16 idx;
};

bool build_ok(RouteTrie& t, const Insert* items, u32 n) {
    t.clear();
    for (u32 i = 0; i < n; i++) {
        if (!t.insert(S(items[i].path), items[i].method, items[i].idx)) return false;
    }
    return true;
}

}  // namespace

// ============================================================================
// Basic match
// ============================================================================

TEST(route_trie, exact_match_single_route) {
    RouteTrie t;
    const Insert items[] = {{"/health", 0, 7}};
    REQUIRE(build_ok(t, items, 1));
    CHECK_EQ(canon_match(t, S("/health"), 0), 7u);
}

TEST(route_trie, no_match_returns_sentinel_when_no_catchall) {
    RouteTrie t;
    const Insert items[] = {{"/health", 0, 7}};
    REQUIRE(build_ok(t, items, 1));
    CHECK_EQ(canon_match(t, S("/missing"), 0), TrieNode::kInvalidRoute);
    CHECK_EQ(canon_match(t, S("/"), 0), TrieNode::kInvalidRoute);
}

TEST(route_trie, rejects_non_origin_form_request_targets) {
    // Verifies the contract enforced by the canon_match wrapper (and
    // by RouteConfig::match / match_canonical in production): non-
    // origin-form request-targets — "*" (OPTIONS asterisk-form),
    // "host:port" (CONNECT authority-form), the empty string —
    // never reach RouteTrie::match. The wrapper canonicalizes raw
    // input and short-circuits to kInvalidRoute when path[0] != '/'.
    //
    // RouteTrie::match itself assumes canonical input as of #50
    // round 6 — it doesn't have its own origin-form guard anymore;
    // this test exercises the wrapper that *is* the guard for raw-
    // input callers.
    RouteTrie t;
    const Insert items[] = {{"/", 0, 99}};
    REQUIRE(build_ok(t, items, 1));
    // Origin-form paths still hit the catchall.
    CHECK_EQ(canon_match(t, S("/"), 0), 99u);
    CHECK_EQ(canon_match(t, S("/deep/path"), 0), 99u);
    // Non-origin-form request targets — no leading '/', no match.
    CHECK_EQ(canon_match(t, S("*"), 0), TrieNode::kInvalidRoute);
    CHECK_EQ(canon_match(t, S("example.com:443"), 0), TrieNode::kInvalidRoute);
    CHECK_EQ(canon_match(t, S(""), 0), TrieNode::kInvalidRoute);
}

TEST(route_trie, catchall_root_matches_unrouted_paths) {
    RouteTrie t;
    const Insert items[] = {{"/health", 0, 7}, {"/", 0, 99}};
    REQUIRE(build_ok(t, items, 2));
    CHECK_EQ(canon_match(t, S("/health"), 0), 7u);    // specific wins over catchall
    CHECK_EQ(canon_match(t, S("/missing"), 0), 99u);  // falls through to catchall
    CHECK_EQ(canon_match(t, S("/"), 0), 99u);         // root path hits catchall
}

TEST(route_trie, param_segment_matches_one_request_segment) {
    RouteTrie t;
    const Insert items[] = {{"/users/:id", 0, 11}};
    REQUIRE(build_ok(t, items, 1));
    CHECK_EQ(canon_match(t, S("/users/42"), 0), 11u);
    CHECK_EQ(canon_match(t, S("/users/alice"), 0), 11u);
    CHECK_EQ(canon_match(t, S("/users"), 0), TrieNode::kInvalidRoute);
}

TEST(route_trie, literal_segment_wins_over_param_at_same_depth) {
    RouteTrie t;
    const Insert items[] = {{"/users/:id", 0, 11}, {"/users/me", 0, 12}};
    REQUIRE(build_ok(t, items, 2));
    CHECK_EQ(canon_match(t, S("/users/me"), 0), 12u);
    CHECK_EQ(canon_match(t, S("/users/42"), 0), 11u);
}

TEST(route_trie, param_branch_can_win_when_literal_branch_dead_ends) {
    RouteTrie t;
    const Insert items[] = {{"/users/me", 0, 12}, {"/users/:id/settings", 0, 13}};
    REQUIRE(build_ok(t, items, 2));
    CHECK_EQ(canon_match(t, S("/users/me/settings"), 0), 13u);
}

TEST(route_trie, distinct_param_names_keep_distinct_dynamic_children) {
    RouteTrie t;
    const Insert items[] = {{"/users/:id/settings", 0, 21}, {"/users/:name/profile", 0, 22}};
    REQUIRE(build_ok(t, items, 2));
    CHECK_EQ(canon_match(t, S("/users/42/settings"), 0), 21u);
    CHECK_EQ(canon_match(t, S("/users/alice/profile"), 0), 22u);

    RouteParam params[kMaxRouteParams]{};
    u32 param_count = 0;
    CHECK_EQ(
        t.match_key(canonicalize_request(S("/users/alice/profile")), 0, params, &param_count, 16),
        22u);
    REQUIRE_EQ(param_count, 1u);
    CHECK((Str{params[0].name, params[0].name_len}.eq(S("name"))));
    CHECK((Str{params[0].value, params[0].value_len}.eq(S("alice"))));
}

TEST(route_trie, earlier_param_sibling_wins_equal_precedence_tie) {
    RouteTrie t;
    const Insert items[] = {{"/users/:id", 0, 41}, {"/users/:name", 0, 42}};
    REQUIRE(build_ok(t, items, 2));

    RouteParam params[kMaxRouteParams]{};
    u32 param_count = 0;
    CHECK_EQ(t.match_key(canonicalize_request(S("/users/alice")), 0, params, &param_count, 16),
             41u);
    REQUIRE_EQ(param_count, 1u);
    CHECK((Str{params[0].name, params[0].name_len}.eq(S("id"))));
    CHECK((Str{params[0].value, params[0].value_len}.eq(S("alice"))));
}

TEST(route_trie, earlier_literal_position_wins_same_depth_static_count_tie) {
    RouteTrie t;
    const Insert items[] = {{"/:a/:x/z", 0, 51}, {"/:b/x/:z", 0, 52}};
    REQUIRE(build_ok(t, items, 2));

    RouteParam params[kMaxRouteParams]{};
    u32 param_count = 0;
    CHECK_EQ(t.match_key(canonicalize_request(S("/foo/x/z")), 0, params, &param_count, 16), 52u);
    REQUIRE_EQ(param_count, 2u);
    CHECK((Str{params[0].name, params[0].name_len}.eq(S("b"))));
    CHECK((Str{params[0].value, params[0].value_len}.eq(S("foo"))));
    CHECK((Str{params[1].name, params[1].name_len}.eq(S("z"))));
    CHECK((Str{params[1].value, params[1].value_len}.eq(S("z"))));
}

TEST(route_trie, param_child_is_not_reused_as_literal_match_for_colon_segment) {
    RouteTrie t;
    const Insert items[] = {{"/:id/:x", 0, 61}, {"/:name/y", 0, 62}};
    REQUIRE(build_ok(t, items, 2));

    RouteParam params[kMaxRouteParams]{};
    u32 param_count = 0;
    CHECK_EQ(t.match_key(canonicalize_request(S("/:id/y")), 0, params, &param_count, 16), 62u);
    REQUIRE_EQ(param_count, 1u);
    CHECK((Str{params[0].name, params[0].name_len}.eq(S("name"))));
    CHECK((Str{params[0].value, params[0].value_len}.eq(S(":id"))));
}

TEST(route_trie, param_capture_reports_names_and_values_for_winning_route) {
    RouteTrie t;
    const Insert items[] = {{"/users/:id/books/:book", 0, 31}, {"/users/me/books/:book", 0, 32}};
    REQUIRE(build_ok(t, items, 2));

    RouteParam params[kMaxRouteParams]{};
    u32 param_count = 99;
    const u16 route =
        t.match_key(canonicalize_request(S("/users/42/books/rust")), 0, params, &param_count, 16);
    CHECK_EQ(route, 31u);
    REQUIRE_EQ(param_count, 2u);
    CHECK((Str{params[0].name, params[0].name_len}.eq(S("id"))));
    CHECK((Str{params[0].value, params[0].value_len}.eq(S("42"))));
    CHECK((Str{params[1].name, params[1].name_len}.eq(S("book"))));
    CHECK((Str{params[1].value, params[1].value_len}.eq(S("rust"))));

    param_count = 99;
    const u16 literal =
        t.match_key(canonicalize_request(S("/users/me/books/rut")), 0, params, &param_count, 16);
    CHECK_EQ(literal, 32u);
    REQUIRE_EQ(param_count, 1u);
    CHECK((Str{params[0].name, params[0].name_len}.eq(S("book"))));
    CHECK((Str{params[0].value, params[0].value_len}.eq(S("rut"))));
}

TEST(route_trie, longest_match_wins_regardless_of_insert_order) {
    // Two orderings of the same routes must produce the same match — the
    // whole point of moving off the linear first-match-wins scan.
    const Insert forward[] = {{"/api", 0, 1}, {"/api/v1", 0, 2}, {"/api/v1/users", 0, 3}};
    const Insert reverse[] = {{"/api/v1/users", 0, 3}, {"/api/v1", 0, 2}, {"/api", 0, 1}};
    RouteTrie ta, tb;
    REQUIRE(build_ok(ta, forward, 3));
    REQUIRE(build_ok(tb, reverse, 3));
    const char* reqs[] = {
        "/api", "/api/", "/api/v2", "/api/v1", "/api/v1/users", "/api/v1/users/42"};
    for (const char* req : reqs) {
        const u16 a = canon_match(ta, S(req), 0);
        const u16 b = canon_match(tb, S(req), 0);
        CHECK_EQ(a, b);
    }
    // Spot-check expectations:
    CHECK_EQ(canon_match(ta, S("/api"), 0), 1u);
    CHECK_EQ(canon_match(ta, S("/api/"), 0), 1u);    // P2a: trailing slash ≡ no slash
    CHECK_EQ(canon_match(ta, S("/api/v2"), 0), 1u);  // deeper sibling not in trie → fall back
    CHECK_EQ(canon_match(ta, S("/api/v1"), 0), 2u);  // exact intermediate
    CHECK_EQ(canon_match(ta, S("/api/v1/users"), 0), 3u);
    CHECK_EQ(canon_match(ta, S("/api/v1/users/42"), 0),
             3u);  // deeper request → longest prefix wins
}

// ============================================================================
// Normalization policies (P1a, P2a, P3a)
// ============================================================================

TEST(route_trie, P1a_consecutive_slashes_collapse) {
    RouteTrie t;
    const Insert items[] = {{"/api/v1", 0, 10}};
    REQUIRE(build_ok(t, items, 1));
    CHECK_EQ(canon_match(t, S("/api//v1"), 0), 10u);   // client double-slash → normalize
    CHECK_EQ(canon_match(t, S("//api/v1"), 0), 10u);   // leading double-slash
    CHECK_EQ(canon_match(t, S("/api///v1"), 0), 10u);  // triple
    CHECK_EQ(canon_match(t, S("///"), 0),
             TrieNode::kInvalidRoute);  // all-slash path has no segments
}

TEST(route_trie, P1a_insert_path_with_extra_slashes_normalizes) {
    // Inserting "/api//v1" should be equivalent to inserting "/api/v1".
    RouteTrie t;
    const Insert items[] = {{"/api//v1", 0, 10}};
    REQUIRE(build_ok(t, items, 1));
    CHECK_EQ(canon_match(t, S("/api/v1"), 0), 10u);
    CHECK_EQ(canon_match(t, S("/api//v1"), 0), 10u);
}

TEST(route_trie, P2a_trailing_slash_equivalent) {
    RouteTrie t;
    const Insert items[] = {{"/api", 0, 5}};
    REQUIRE(build_ok(t, items, 1));
    CHECK_EQ(canon_match(t, S("/api"), 0), 5u);
    CHECK_EQ(canon_match(t, S("/api/"), 0), 5u);
    CHECK_EQ(canon_match(t, S("/api//"), 0), 5u);
}

TEST(route_trie, strips_query_string_before_matching) {
    // Request paths from the HTTP parser include the raw request-target
    // (path + query + fragment). Routing must run on the path component
    // only, or GET /health?check=1 won't match a route registered as
    // /health.
    RouteTrie t;
    const Insert items[] = {{"/health", 0, 1}, {"/api/users", 0, 2}};
    REQUIRE(build_ok(t, items, 2));
    CHECK_EQ(canon_match(t, S("/health?check=1"), 0), 1u);
    CHECK_EQ(canon_match(t, S("/health?"), 0), 1u);
    CHECK_EQ(canon_match(t, S("/health#frag"), 0), 1u);
    CHECK_EQ(canon_match(t, S("/api/users?page=3&limit=10"), 0), 2u);
    // Query on a miss still falls through cleanly (no match).
    CHECK_EQ(canon_match(t, S("/unknown?x=1"), 0), TrieNode::kInvalidRoute);
}

TEST(route_trie, P3a_case_sensitive) {
    RouteTrie t;
    const Insert items[] = {{"/api", 0, 1}, {"/API", 0, 2}};
    REQUIRE(build_ok(t, items, 2));
    CHECK_EQ(canon_match(t, S("/api"), 0), 1u);
    CHECK_EQ(canon_match(t, S("/API"), 0), 2u);
    CHECK_EQ(canon_match(t, S("/Api"), 0),
             TrieNode::kInvalidRoute);  // different case, different route
}

// ============================================================================
// Method dispatch
// ============================================================================

TEST(route_trie, method_specific_beats_any_slot) {
    // When a path has both a method-specific and an any-method route, the
    // specific slot wins for matching methods, any wins for others.
    RouteTrie t;
    const Insert items[] = {{"/x", 0, 10}, {"/x", 'G', 20}};
    REQUIRE(build_ok(t, items, 2));
    CHECK_EQ(canon_match(t, S("/x"), 'G'), 20u);
    CHECK_EQ(canon_match(t, S("/x"), 'P'), 10u);  // POST → any slot
    CHECK_EQ(canon_match(t, S("/x"), 'D'), 10u);  // DELETE → any slot
}

TEST(route_trie, any_method_precedence_covers_all_runtime_methods_and_order) {
    const Insert orders[][2] = {
        {{"/x", kRouteMethodAny, 10}, {"/x", kRouteMethodGet, 20}},
        {{"/x", kRouteMethodGet, 20}, {"/x", kRouteMethodAny, 10}},
    };
    for (const auto& items : orders) {
        RouteTrie t;
        REQUIRE(build_ok(t, items, 2));
        CHECK_EQ(canon_match(t, S("/x"), kRouteMethodGet), 20u);
        CHECK_EQ(canon_match(t, S("/x"), kRouteMethodPost), 10u);
        CHECK_EQ(canon_match(t, S("/x"), kRouteMethodTrace), 10u);
        CHECK_EQ(canon_match(t, S("/x"), kRouteMethodConnect), 10u);
    }
}

TEST(route_trie, match_strips_query_and_fragment) {
    // Stripping '?' / '#' from the incoming request is match()'s job
    // (tokenize_segments stays pure). A route registered at "/api"
    // should match requests like "/api?x=1" or "/api#frag" despite
    // the extra bytes after the path component. (Insert-time paths
    // containing '?' / '#' are rejected earlier at RouteConfig::
    // add_*, so insert() never sees such a path; the trie itself
    // would happily store them as distinct bytes if it did.)
    RouteTrie t;
    const Insert items[] = {{"/api", 0, 1}};
    REQUIRE(build_ok(t, items, 1));
    CHECK_EQ(canon_match(t, S("/api?x=1"), 0), 1u);
    CHECK_EQ(canon_match(t, S("/api#frag"), 0), 1u);
}

TEST(route_trie, rejects_unsupported_method_at_insert) {
    // Codex P2 on #41: the earlier method_slot() mapped unknown method
    // bytes to slot 0 (any), which would silently broaden a typoed
    // route into an all-methods route. Now unknown bytes reject at
    // insert() cleanly so callers see the failure.
    RouteTrie t;
    t.clear();
    // Lowercase 'g' (typo for GET), uppercase 'X', or any unsupported
    // first byte must fail.
    CHECK(!t.insert(S("/x"), 'g', 1));
    CHECK(!t.insert(S("/x"), 'X', 1));
    CHECK(!t.insert(S("/x"), 'Z', 1));
    // Known chars still work.
    CHECK(t.insert(S("/x"), 'G', 1));
    CHECK(t.insert(S("/y"), 0, 2));  // method=0 is "any", still valid
}

TEST(route_trie, rejects_unsupported_method_at_match) {
    // Symmetric: a request with an unsupported method byte can't
    // match anything, even routes at the same path.
    RouteTrie t;
    const Insert items[] = {{"/x", 0, 10}, {"/x", 'G', 20}};
    REQUIRE(build_ok(t, items, 2));
    CHECK_EQ(canon_match(t, S("/x"), 'G'), 20u);
    CHECK_EQ(canon_match(t, S("/x"), 'g'), TrieNode::kInvalidRoute);  // typo
    CHECK_EQ(canon_match(t, S("/x"), 'X'), TrieNode::kInvalidRoute);  // unknown verb
}

TEST(route_trie, admits_routes_with_more_than_16_segments) {
    // Codex P2 on #41: kMaxPathSegments was 16, which rejected valid
    // route configs with 17+ segments even when the path fit within
    // RouteEntry::kMaxPathLen. Bumped to 64 to cover the worst-case
    // 128-byte path (= 64 two-byte segments). A 17-segment path must
    // now insert and match.
    RouteTrie t;
    const char* deep = "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q";  // 17 segments
    CHECK(t.insert(S(deep), 0, 99));
    CHECK_EQ(canon_match(t, S(deep), 0), 99u);
}

TEST(route_trie, method_first_insert_wins_on_exact_dup) {
    RouteTrie t;
    const Insert items[] = {{"/x", 'G', 1}, {"/x", 'G', 2}};  // same method-slot, duplicate
    REQUIRE(build_ok(t, items, 2));
    CHECK_EQ(canon_match(t, S("/x"), 'G'), 1u);  // first insert pins the slot
}

TEST(route_trie, method_post_put_patch_are_distinct) {
    RouteTrie t;
    const Insert items[] = {
        {"/x", kRouteMethodPost, 10}, {"/x", kRouteMethodPut, 20}, {"/x", kRouteMethodPatch, 30}};
    REQUIRE(build_ok(t, items, 3));
    CHECK_EQ(canon_match(t, S("/x"), kRouteMethodPost), 10u);
    CHECK_EQ(canon_match(t, S("/x"), kRouteMethodPut), 20u);
    CHECK_EQ(canon_match(t, S("/x"), kRouteMethodPatch), 30u);
    CHECK_EQ(canon_match(t, S("/x"), 'G'), TrieNode::kInvalidRoute);
}

// ============================================================================
// Build-time guards
// ============================================================================

TEST(route_trie, empty_path_inserts_at_root) {
    RouteTrie t;
    const Insert items[] = {{"", 0, 42}};
    REQUIRE(build_ok(t, items, 1));
    // Inserting "" is semantically the same as inserting "/" — both
    // tokenize to the empty-segment root terminal, so the slot is
    // populated and origin-form requests hit it.
    CHECK_EQ(canon_match(t, S("/"), 0), 42u);          // "/" normalizes to root
    CHECK_EQ(canon_match(t, S("/anything"), 0), 42u);  // catchall
    // An empty request target is NOT origin-form and must not match
    // path-based routing (Codex P2 on #41 — don't let a catchall
    // swallow asterisk-form / authority-form / empty targets).
    CHECK_EQ(canon_match(t, S(""), 0), TrieNode::kInvalidRoute);
}

TEST(route_trie, node_count_shows_prefix_sharing) {
    RouteTrie t;
    const Insert items[] = {
        {"/api/v1/users", 0, 1}, {"/api/v1/orders", 0, 2}, {"/api/v2/users", 0, 3}};
    REQUIRE(build_ok(t, items, 3));
    // Root + {"api"} + {"v1", "v2"} + {"users", "orders", "users"} = 1 + 1 + 2 + 3 = 7.
    // If tokenize or insert accidentally didn't share the "api" prefix, we'd see 10.
    CHECK_EQ(t.node_count(), 7u);
}

TEST(route_trie, deep_path_still_falls_through_to_catchall_or_prefix) {
    // Regression guard (Codex P1): an earlier match() returned
    // kInvalidRoute the moment tokenize reported segment-count
    // overflow, letting requests with > kMaxPathSegments segments
    // bypass a '/' catchall or a matching prefix route. match() must
    // walk as deep as the trie has data for and return the longest-
    // match terminal it saw, not bail when tokenize trips its cap.
    //
    // Although a real request hits ConnectionBase::kMaxReqPathLen
    // (64 bytes → at most 32 segments) before the trie ever sees
    // it, match() is also called from tests, replay capture, and
    // future tooling that may legitimately feed paths past the
    // segment cap; the contract here is robustness, not coverage of
    // every wire shape. Build the over-cap path at runtime so the
    // assertion remains tight as kMaxPathSegments evolves
    // (Codex P2 on #41 round 14 — 17 segments stopped exercising
    // the overflow path the moment kMaxPathSegments grew to 64).
    RouteTrie t;
    const Insert items[] = {{"/", 0, 42}, {"/api", 0, 7}};
    REQUIRE(build_ok(t, items, 2));

    // /api + (kMaxPathSegments + 1) "/a" segments = guaranteed
    // overflow regardless of how the cap is retuned later. Buffer
    // is sized statically since constexpr u32 mul is fine in this
    // no-stdlib code; the path doesn't need a NUL terminator (Str
    // carries length).
    constexpr u32 kSegs = RouteTrie::kMaxPathSegments + 1;
    char prefixed[4 + kSegs * 2];
    u32 n = 0;
    prefixed[n++] = '/';
    prefixed[n++] = 'a';
    prefixed[n++] = 'p';
    prefixed[n++] = 'i';
    for (u32 i = 0; i < kSegs; i++) {
        prefixed[n++] = '/';
        prefixed[n++] = 'a';
    }
    // Starts with /api — the /api terminal must win even though
    // tokenize will overflow before reaching the deepest segment.
    CHECK_EQ(t.match(Str{prefixed, n}, 0), 7u);

    // Same depth, no /api prefix — catchall '/' must still fire
    // instead of a spurious no-match.
    char unprefixed[kSegs * 2];
    n = 0;
    for (u32 i = 0; i < kSegs; i++) {
        unprefixed[n++] = '/';
        unprefixed[n++] = 'a';
    }
    CHECK_EQ(t.match(Str{unprefixed, n}, 0), 42u);
}

TEST(route_trie, insert_atomic_on_node_pool_exhaustion_midpath) {
    // Codex P1 regression: a deep path insert that creates k-1 nodes
    // successfully and then hits kMaxNodes at segment k used to leave
    // the k-1 ghost nodes in the pool. Repeated failures would eat
    // capacity until legitimate shorter routes were rejected — the
    // "bricked" route admission scenario.
    //
    // Setup: fill the pool to within `kDeepSegs - 1` of kMaxNodes so
    // a kDeepSegs-segment insert is guaranteed to overflow partway
    // through. Without rollback, the partial pushes would leak and
    // the follow-up short insert would fail. kMaxNodes-agnostic: the
    // exact fill shape is computed from the current cap.
    RouteTrie t;
    // kDeepSegs × 3-byte segments ("/zX") must fit in
    // RouteEntry::kMaxPathLen=128. 40 segments × 3 = 120 bytes.
    static constexpr u32 kDeepSegs = 40;
    static_assert(kDeepSegs * 3 <= 128, "deep_path must fit RouteEntry::kMaxPathLen");

    // Main 2-level fill: "/pNN/cMM" paths stay within
    // TrieNode::kMaxChildren at every level. Target budget leaves a
    // small margin; a top-up loop below tightens the headroom.
    static constexpr u32 kParents = 40;
    static constexpr u32 kChildren = (RouteTrie::kMaxNodes - 1 - kParents - kDeepSegs) / kParents;
    static constexpr u32 kFillRoutes = kParents * kChildren;
    static_assert(kChildren > 0 && kChildren <= TrieNode::kMaxChildren,
                  "children count must stay within per-node cap");
    static char fill_paths[kFillRoutes][12] = {};
    for (u32 i = 0; i < kFillRoutes; i++) {
        const u32 p = i / kChildren;
        const u32 c = i % kChildren;
        u32 n = 0;
        fill_paths[i][n++] = '/';
        fill_paths[i][n++] = 'p';
        fill_paths[i][n++] = static_cast<char>('0' + p / 10);
        fill_paths[i][n++] = static_cast<char>('0' + p % 10);
        fill_paths[i][n++] = '/';
        fill_paths[i][n++] = 'c';
        if (c >= 100) fill_paths[i][n++] = static_cast<char>('0' + c / 100);
        fill_paths[i][n++] = static_cast<char>('0' + (c / 10) % 10);
        fill_paths[i][n++] = static_cast<char>('0' + c % 10);
        REQUIRE(t.insert(Str{fill_paths[i], n}, 0, static_cast<u16>(i)));
    }

    // Top up with single-segment routes at root ("/tNN") to close
    // the remaining slack below kDeepSegs. Each adds exactly one
    // node (a new root child). Root has TrieNode::kMaxChildren=128
    // total slots, of which kParents are already used.
    static char topup_paths[128][6] = {};
    u32 topup = 0;
    while (t.node_count() + kDeepSegs <= RouteTrie::kMaxNodes) {
        topup_paths[topup][0] = '/';
        topup_paths[topup][1] = 't';
        topup_paths[topup][2] = static_cast<char>('0' + topup / 10);
        topup_paths[topup][3] = static_cast<char>('0' + topup % 10);
        REQUIRE(t.insert(Str{topup_paths[topup], 4}, 0, 0));
        topup++;
        REQUIRE(topup < 128);  // guard against infinite loop
    }
    const u32 before = t.node_count();
    // With this setup, a kDeepSegs insert needs more nodes than are
    // actually free, so it MUST hit kMaxNodes partway through.
    CHECK_GT(before + kDeepSegs, RouteTrie::kMaxNodes);

    // Attempt the deep insert. With rollback, node_count returns to
    // `before`. Without rollback, the partial pushes leak and
    // node_count ends up at RouteTrie::kMaxNodes (or close to it).
    char deep_path[kDeepSegs * 3];
    u32 dpi = 0;
    for (u32 i = 0; i < kDeepSegs; i++) {
        deep_path[dpi++] = '/';
        deep_path[dpi++] = 'z';
        deep_path[dpi++] = static_cast<char>('a' + i % 26);
    }
    CHECK(!t.insert(Str{deep_path, dpi}, 0, 999));
    CHECK_EQ(t.node_count(), before);

    // A short route must still fit. If rollback leaked, we'd have
    // burned through the remaining headroom and this would fail.
    CHECK(t.insert(S("/ok"), 0, 500));
    CHECK_EQ(canon_match(t, S("/ok"), 0), 500u);
}

TEST(route_trie, insert_atomic_on_child_cap_overflow) {
    // Regression guard (Copilot P1 + Codex P2): an earlier insert()
    // could push a new node into the pool and then fail on the
    // subsequent children.push(), leaving a dangling unreferenced
    // node. Repeated overflow attempts used to leak pool capacity
    // until legitimate inserts started failing. This test asserts
    // the pool size stays stable across 100 failed inserts after
    // saturating a parent's child cap.
    //
    // Important: TrieNode::segment is a non-owning Str view into the
    // path buffer the caller provided. Use a 2D array so every
    // inserted path keeps its own backing storage alive for the
    // lifetime of the trie — a single scratch buffer would alias
    // and all children would collapse onto the same segment.
    RouteTrie t;
    static constexpr u32 kN = TrieNode::kMaxChildren;
    // 3-digit decimal encoding (/000../127) — fits kMaxChildren up to
    // 999 and keeps every segment's bytes distinct so find_child can't
    // coincidentally match two of our fill paths onto the same child.
    char paths[kN][8] = {};
    for (u32 i = 0; i < kN; i++) {
        paths[i][0] = '/';
        paths[i][1] = static_cast<char>('0' + (i / 100) % 10);
        paths[i][2] = static_cast<char>('0' + (i / 10) % 10);
        paths[i][3] = static_cast<char>('0' + i % 10);
        REQUIRE(t.insert(Str{paths[i], 4}, 0, static_cast<u16>(i)));
    }
    const u32 saturated_count = t.node_count();
    // Every insert from here on must hit root's child cap. None
    // should grow node_count (what the old insert() used to leak).
    // Use /zXX segments that can't collide with any /NNN above.
    char overflow_paths[100][4] = {};
    for (u32 i = 0; i < 100; i++) {
        overflow_paths[i][0] = '/';
        overflow_paths[i][1] = 'z';
        overflow_paths[i][2] = static_cast<char>('a' + (i % 26));
        CHECK(!t.insert(Str{overflow_paths[i], 3}, 0, 0));
    }
    CHECK_EQ(t.node_count(), saturated_count);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
