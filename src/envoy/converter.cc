#include "rut/envoy/converter.h"

namespace rut::envoy {
namespace {

auto invalid(Span span, Str detail) {
    return frontend_error(FrontendError::UnexpectedToken, span, detail);
}

auto unsupported(Span span, Str detail) {
    return frontend_error(FrontendError::UnsupportedSyntax, span, detail);
}

auto out_of_memory(Span span, Str detail) {
    return frontend_error(FrontendError::OutOfMemory, span, detail);
}

// PR #692 round-4 review: `validate` below must not trust that `model` came
// from `parse_bootstrap_json` — the public explicit-capabilities overload
// accepts a caller-built `Bootstrap`, and `RouterFilter::name`/
// `has_typed_config` are public fields a caller can set to anything (e.g.
// copy a parsed model and retarget the router filter at
// "envoy.filters.http.lua", or clear `has_typed_config`). The parser itself
// re-checks this name against the same literal (src/envoy/parser.cc,
// `parse_router_filter`) before ever producing a model, so this mirrors that
// check rather than duplicating new policy.
constexpr Str kRouterFilterName = lit_str("envoy.filters.http.router");

// PR #692 round-5 review: the same forgery is possible one level up.
// `FilterChain::filter_name` is a public field a caller can retarget at
// another network filter (e.g. "envoy.filters.network.tcp_proxy") while
// leaving the nested `hcm` populated as if it were still behind the HTTP
// connection manager, and `HttpConnectionManager::type_url_span` — the only
// evidence the model records that `parse_hcm`'s `expect_type_url` ever
// checked the typed_config's `@type` against the v3 HttpConnectionManager
// type — defaults to the zero `Span{}` on a hand-built model that never ran
// that check. The parser re-checks the filter name against the same literal
// (src/envoy/parser.cc, `parse_filter_chain`) before ever producing a model,
// so this mirrors that check plus the round-4 router pattern rather than
// duplicating new policy.
constexpr Str kNetworkFilterName = lit_str("envoy.filters.network.http_connection_manager");

// PROVISIONAL: reconcile with oracle. Recorded from docs/envoy-converter.md
// pending the pinned Envoy differential (PR2) and the local-reply capability
// (PR5), which replaces this literal with the pinned bytes.
static constexpr char kEnvoyConnectFailureBody[] =
    "upstream connect error or disconnect/reset before headers. reset reason: remote connection "
    "failure, transport failure reason: delayed connect error: 111";

// Minimal bounded text writer, copied from rut::nginx's converter Writer
// (src/nginx/converter.cc) rather than shared, so this frontend does not
// depend on the nginx frontend.
class Writer {
public:
    explicit Writer(RutSource& output) : output_(output) {}

    bool put_lit(const char* text, u32 len) {
        if (len >= RutSource::kCapacity - output_.len) return false;
        for (u32 i = 0; i < len; i++) output_.data[output_.len + i] = text[i];
        output_.len += len;
        return true;
    }

    bool put_cstr(const char* text) {
        return put_lit(text, static_cast<u32>(__builtin_strlen(text)));
    }

    // Writes `text` into a RUT string literal body, escaping `\` and `"`.
    // Defense in depth only: `validate()` below now rejects both bytes in
    // every route match value it lowers through this function (Codex P2 on
    // PR #695 round 4 -- the RUT lexer never decodes a `\`-escape, so
    // inserting one here would change the runtime string's byte content
    // instead of preserving it), so neither branch should be reachable from
    // that call site today. Kept because `put_escaped` is a small, general
    // "make text literal-safe" helper, not one hand-tuned to its current
    // only caller's already-validated input.
    bool put_escaped(Str text) {
        for (u32 i = 0; i < text.len; i++) {
            const char c = text.ptr[i];
            if ((c == '"' || c == '\\') && !put_lit("\\", 1)) return false;
            if (!put_lit(&c, 1)) return false;
        }
        return true;
    }

    bool put_u16(u16 value) {
        char digits[5];
        u32 count = 0;
        do {
            digits[count++] = static_cast<char>('0' + (value % 10));
            value = static_cast<u16>(value / 10);
        } while (value != 0);
        if (count >= RutSource::kCapacity - output_.len) return false;
        for (u32 i = 0; i < count; i++) output_.data[output_.len + i] = digits[count - i - 1];
        output_.len += count;
        return true;
    }

    bool put_ipv4_host(u32 address) {
        const u8 octets[4] = {
            static_cast<u8>(address >> 24u),
            static_cast<u8>(address >> 16u),
            static_cast<u8>(address >> 8u),
            static_cast<u8>(address),
        };
        for (u32 i = 0; i < 4; i++) {
            if (!put_u8(octets[i])) return false;
            if (i != 3 && !put_lit(".", 1)) return false;
        }
        return true;
    }

private:
    bool put_u8(u8 value) {
        char digits[3];
        u32 count = 0;
        do {
            digits[count++] = static_cast<char>('0' + (value % 10));
            value = static_cast<u8>(value / 10);
        } while (value != 0);
        if (count >= RutSource::kCapacity - output_.len) return false;
        for (u32 i = 0; i < count; i++) output_.data[output_.len + i] = digits[count - i - 1];
        output_.len += count;
        return true;
    }

    RutSource& output_;
};

// The Envoy "no route" 404 (docs/envoy-converter.md, "Routing"): empty body,
// lowercase header names, the date/server/length-only layout. Fixed shape;
// nothing from the model is emitted here beyond what the grammar requires.
bool put_unmatched(Writer& w) {
    return w.put_cstr(
        "unmatched { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 404, reason: \"Not Found\", server: \"envoy\",\n"
        "  date: \"current\", connection: \"request\", connection_header: \"close_only\",\n"
        "  header_names: \"lowercase\", header_order: \"date_server_length\",\n"
        "  head_mode: \"suppress_body\", body: b\"\"\n"
        "}) }\n");
}

// One `route exact "<node_text>" { return local_response(...) }` — the same
// fixed 404 shape as `put_unmatched`. NOT CURRENTLY CALLED: `build_node_plan`
// (below) used to request this whenever a node's own prefix action never
// matched its literal node path, but its ANY-method strict local-response
// admission cannot serve every method Envoy's real no-route 404 would
// (Codex P1: TRACE/CONNECT close the connection instead), so lowering fails
// closed for that shape instead (see the algorithm doc comment, "Remainder").
// Kept for the day an all-method local_response surface makes it usable
// again.
bool put_route_exact_404(Writer& w, Str node_text) {
    if (!w.put_cstr("route exact \"") || !w.put_escaped(node_text) || !w.put_cstr("\" {\n"))
        return false;
    return w.put_cstr(
        "    return local_response({\n"
        "        version: \"HTTP/1.1\", status: 404, reason: \"Not Found\", server: \"envoy\",\n"
        "        date: \"current\", connection: \"request\", connection_header: \"close_only\",\n"
        "        header_names: \"lowercase\", header_order: \"date_server_length\",\n"
        "        head_mode: \"suppress_body\", body: b\"\"\n"
        "    })\n"
        "}\n");
}

// The `forward(envoy_cluster_<cluster_index>, ...)` call body shared by every
// node's arms and by PR1's single-route milestone-S golden. Byte-identical to
// PR1's `put_forward_route` kwargs except for the upstream identifier;
// `include_head_mode` is true only for the HEAD variant of a node's body.
// Deliberately ends at the closing `)` of the `forward(...)` call (no
// enclosing `route "..." { }` braces) so it can be reused both as the sole
// statement of a `route "N" { ... }` body and nested inside if/else arms.
bool put_forward_call(Writer& w, u32 cluster_index, bool include_head_mode) {
    if (!w.put_cstr("    return forward(envoy_cluster_")) return false;
    if (!w.put_u16(static_cast<u16>(cluster_index))) return false;
    if (!w.put_cstr(
            ", request_policy: {\n"
            "            version: \"HTTP/1.1\",\n"
            "            host: \"preserve\",\n"
            "            connection: \"omit\",\n"
            "            header_names: \"lowercase\",\n"
            "            forwarded_proto: \"http\",\n"
            "            strip_headers: [\"Connection\", \"Keep-Alive\", \"TE\", \"Expect\", "
            "\"Upgrade\", \"Proxy-Connection\"]\n"
            "        },\n"
            "        response_policy: {\n"
            "            version: \"HTTP/1.1\",\n"
            "            framing: \"content_length\",\n"
            "            connection: \"request\",\n"))
        return false;
    if (include_head_mode && !w.put_cstr("            head_mode: \"suppress_body\",\n"))
        return false;
    if (!w.put_cstr("            header_order: \"upstream\",\n"
                    "            header_names: \"lowercase\",\n"
                    "            connection_header: \"close_only\",\n"
                    "            status_reason: \"canonical\",\n"
                    "            server: \"envoy\",\n"
                    "            date: \"preserve_or_current\",\n"
                    "            hide_headers: []\n"
                    "        },\n"
                    "        failure_policy: {\n"
                    "            version: \"HTTP/1.1\",\n"
                    "            status: 503,\n"
                    "            reason: \"Service Unavailable\",\n"
                    "            content_type: \"text/plain\",\n"
                    "            server: \"envoy\",\n"
                    "            date: \"current\",\n"
                    "            connection: \"request\",\n"
                    "            connection_header: \"close_only\",\n"
                    "            header_names: \"lowercase\",\n"
                    "            header_order: \"length_type_date_server\",\n"))
        return false;
    if (include_head_mode && !w.put_cstr("            head_mode: \"suppress_body\",\n"))
        return false;
    return w.put_cstr("            body: b\"") && w.put_cstr(kEnvoyConnectFailureBody) &&
           w.put_cstr("\"\n        }\n    )\n");
}

// ── Increment-4 ordered route-list lowering (envoy-pr-plan.md, PR 8) ───────
//
// Envoy selects the first route (in declared list order) whose match applies;
// Rut's route trie selects the *longest* matching declared prefix. This
// section reconciles the two by building, for every RUT route entry we
// declare ("node"), a linear if/else chain that reproduces Envoy's
// first-match order restricted to the routes that could ever apply to a
// request the trie hands to that node — instead of rejecting any input where
// list order and longest-prefix order could disagree (owner decision D3,
// "lowered correctly by construction").
//
// Nodes. `"/"` (the root) always exists as a node, whether or not Envoy
// explicitly declares a `prefix: "/"` route. For every OTHER declared
// `prefix` route `P` (`P != "/"`), `N(P)` is `P` with its trailing `/`
// removed (e.g. `"/api/"` -> `"/api"`); duplicate `N(P)` values (two routes
// naming the same prefix) collapse to one node. `path` (exact) routes never
// create a node; each is attached to the SINGLE node whose text is the
// longest declared node under which it falls ("owner" below).
//
// "Under": path `p` is under node `N` iff `N == "/"` (root is under
// everything) or `p == N` or `p` starts with `N + "/"`. `M` is a *strict
// ancestor* of `N` iff `M != N` and `N` is under `M`.
//
// Owner: for an exact route with path `q`, its owner is the node with the
// LONGEST text among all node candidates (every declared node plus the
// always-present root) under which `q` falls. Root is always a candidate, so
// an owner always exists.
//
// Per-node body (`route "N" { ... }` / `route HEAD "N" { ... }`): walk every
// Envoy route in DECLARATION order and classify it against `N`:
//   - exact `path q` owned by `N`, `q != N`               -> conditional arm
//     `if req.pathOnly == "q" { <forward> } else { <continue> }`.
//   - exact `path q` owned by `N`, `q == N` (Envoy declared an exact route
//     for N's own literal text)                            -> conditional
//     arm UNLESS a same-node prefix arm (below) was already placed earlier
//     in the walk, in which case `req.pathOnly == N` is already guaranteed
//     true at this point in the chain (see "Remainder" below) and the arm
//     becomes the chain's unconditional terminator.
//   - prefix route naming exactly `N` ("N's own arm"): for the root, this is
//     UNCONDITIONAL and terminates the chain immediately wherever it
//     appears (Envoy's own `"/"` prefix matches the literal path `"/"` too,
//     so root's body never needs to exclude `p == "/"`). For a non-root
//     node, Envoy's `prefix: "N/"` never matches the literal path `N`
//      itself (`"N"` does not start with `"N/"`), so the FIRST such arm is
//     conditional: `if req.pathOnly != "N" { <forward> } else { <continue> }`.
//     A second (duplicate) declaration of N's own prefix is dead — Envoy
//     already resolved every request that could reach it via the first one
//     — and is dropped.
//   - prefix route naming a STRICT ANCESTOR of `N`: UNCONDITIONAL — every
//     request the trie ever hands to `N`'s handler already satisfies this
//     ancestor's prefix, so it terminates the chain wherever it appears,
//     dropping every route declared after it in Envoy's order (this is the
//     "shadowing" case; see golden (e), where a `prefix` arm declared before
//     an exact route for one of its own descendants makes that exact route
//     permanently dead and it is omitted from the emitted RUT entirely,
//     rather than nested unreachably inside the chain).
//   - anything else (a prefix naming a strict DESCENDANT of `N`, or an exact
//     route owned by a different node) is irrelevant to `N` and skipped.
// The chain always ends at the first UNCONDITIONAL arm it places (ancestor,
// root's own arm, or a same-node exact `q == N` arm reached after `N`'s own
// prefix arm already fired conditionally) — dropping everything Envoy would
// never reach past that point for a request under `N`.
//
// Remainder ("only p == N can remain"). A non-root node N always owns at
// least one prefix arm naming itself (that is what makes it a node), so the
// walk above always terminates UNLESS the chain never finds an unconditional
// arm at all. That can only happen when N's own prefix arm ends up as the
// LAST arm the walk keeps (everything declared after it is either dead, per
// the dead-arm rules above, or would have already resolved the chain). At
// that point the only request value that has not been accounted for is the
// literal path `p == N` itself: N's own prefix action never matches it
// (established above), no ancestor arm exists anywhere in the route list
// (else it would have terminated the chain earlier). Two cases:
//   - An exact route for `q == N` WAS declared before N's own prefix route:
//     the walk already placed a conditional `req.pathOnly == "N"` arm for it
//     earlier in the chain (the `saw_own_exact` bullet above), so dropping
//     the final arm's condition is correct and no further action is needed —
//     `p == N` already forwards through that earlier arm.
//   - No exact route for `q == N` was ever declared: `req.pathOnly == "N"`
//     therefore has no Envoy route at all — a genuine 404 — but there is no
//     RUT form for "respond 404" nested inside an `if` branch
//     (`local_response(...)` parses only as the sole statement of a
//     top-level `unmatched` / `pre_route` / `route exact "..."` item — see
//     VERIFY below), and `route exact "N"` cannot stand in for it either: its
//     strict local-response admission (`callbacks_impl.h`,
//     `exact_strict_local_response_common_request_shape_is_admitted` plus the
//     per-method "fresh method" checks) serves only GET/HEAD/POST/OPTIONS/
//     PUT/DELETE/PATCH, so an ANY-method `route exact "N"` 404 would silently
//     close the connection instead of responding for TRACE/CONNECT, which
//     Envoy's real no-route 404 still answers (Codex P1). So lowering fails
//     closed here instead of emitting that fallback: `BLOCKED_BY_RUT: a
//     no-route 404 for this node's own literal path has no RUT form that
//     serves every method Envoy would 404`.
//
// Root has no such escape hatch either (there is no "ancestor of the root"
// to delegate to, and it has no earlier-exact-arm case: `"/"` can never be
// under a longer node). If root's own body ends up with exact arms but no
// unconditional terminator (Envoy never declares a `prefix: "/"` route, so
// nothing ever resolves the fallthrough), lowering fails closed the same
// way: `BLOCKED_BY_RUT: a no-route 404 inside a route branch has no RUT
// form`. If root has NO arms at all in that situation, `route "/"` is
// omitted entirely — any request that would reach it falls through Rut's
// trie to the `unmatched` policy declared above, which correctly answers
// every method (its per-method policy table falls back to the ANY slot;
// unlike `route exact`, `handle_configured_unmatched_response` admits every
// route-method slot including TRACE), so it is exactly Envoy's real
// no-matching-route 404.
//
// VERIFY outcomes this algorithm depends on (src/compiler/parser.cc,
// include/rut/runtime/route_trie.h, include/rut/runtime/callbacks_impl.h):
//   - `else if` is NOT supported; every `else` must be followed immediately
//     by `{` (parse_stmt's `If` handling always calls `expect(LBrace)` right
//     after `expect(KwElse)`). Nested arms are therefore always written as
//     `else { if ... }`, never `else if ...`.
//   - `req.pathOnly == "..."` / `!= "..."` both parse and analyze (Eq is
//     type-generic over same-typed operands including Str;
//     `!=` desugars to `(a == b) == false` at parse time) and `req.pathOnly`
//     is the RAW request path with only `?`/`#` stripped (never slash- or
//     percent-normalized) — see "Not implemented" below.
//   - `return local_response(...)` is accepted ONLY inside `unmatched`,
//     `pre_route`, and `route exact "..."` items (all three route through
//     `parse_strict_local_response_block`, which hard-requires the callee
//     name `local_response`); it is not reachable from `parse_stmt`'s
//     general `if`/`else` bodies used inside an ordinary `route`, so a
//     no-route 404 can never be nested inside a route's `if` branch.
//   - Exact routes are matched before the prefix trie: in
//     `callbacks_impl.h`'s request path, `exact_view.match_exact_strict_local_response`
//     (and its slash-normalized variant) runs and, on a hit, serves the
//     configured local response and returns BEFORE `config->match_canonical`
//     (the trie lookup) is ever called. `route exact "N"` therefore always
//     wins over `route "N"` for the literal path `N`.
// Not implemented (documented, not fixed here): the prefix trie normalizes
// empty path segments (`route_trie.h`: "/api/" and "/api//v1" collapse the
// same as "/api" and "/api/v1"), so which declared NODE a request reaches is
// segment-normalized, while `req.pathOnly`'s own byte comparisons inside a
// node's body are not. Envoy's literal string-prefix matching does neither
// by default (`merge_slashes` and percent-decoding are separate, unmodeled
// knobs). This does not affect the golden/equivalence tests below (all
// probe paths are already normalized), but it is a real divergence for
// requests containing redundant slashes or percent-encoded segments; see the
// compatibility matrix.
//
// A DIFFERENT, separately-confirmed divergence (Codex P1 on PR #695 round 4)
// lives one layer BELOW the trie entirely and is NOT fixable from this file:
// `include/rut/runtime/compile_to_config.h`'s `configure_route_dispatch`
// chooses between two dispatch engines for the WHOLE compiled module --
// `RouteTrie` (segment-aware, as this algorithm assumes throughout) or `ART`
// (`src/runtime/route_art.cc`: pure byte-prefix descent, no segment-boundary
// check at all) -- based on `needs_segment_aware`
// (`src/runtime/route_select.cc`), a pairwise scan over the DECLARED route
// paths only. That scan's root exemption ("root canonicalizes to the empty
// string, so pairing it with any other route is never boundary-sensitive")
// is unsound whenever the OTHER route in the pair has no byte-diverging
// declared sibling of its OWN: confirmed by direct reproduction --
// `RouteConfig` with exactly the routes `"/"` and `"/api"` (precisely PR8's
// `golden_routes_a_prefix_then_root` shape) makes `needs_segment_aware`
// return false, so `configure_route_dispatch` selects ART, under which a
// request for `/apifoo` incorrectly matches `/api`'s handler instead of
// falling back to `/`'s (SegmentTrie, forced on the same two routes,
// correctly falls back to `/`). This reproduces from a plain hand-written
// `.rut` file with nothing Envoy-specific about it, so it is a
// `route_select.cc`/`route_art.cc` bug, not a `build_node_plan` one -- this
// algorithm's own if/else arm logic is exactly right FOR WHICHEVER node the
// active dispatch engine hands it (proven by `rut_dispatch` in
// tests/test_envoy_convert.cc, which re-parses the real emitted RUT text and
// re-runs a segment-aware node selection over it) -- and the converter has
// no hook into the RUT compiler's later dispatch-engine choice for the
// module it emits. See docs/envoy-compatibility.md for the tracked row; the
// fix belongs in a runtime PR that can rebuild and test `route_select.cc`
// and `route_art.cc` (out of this PR's build scope).

// One arm of a node's if/else chain. All but the last arm in a chain are
// conditional (`is_terminal == false`); the last is the chain's unconditional
// terminator (`is_terminal == true`), always a `forward(...)` to
// `cluster_index` (never a `route "N"` body ends in a 404 — see the
// "Remainder" section above).
struct RouteArm {
    bool is_terminal = false;
    // Only meaningful when `!is_terminal`: true for an exact-path arm
    // (`req.pathOnly == "compare_text"`), false for a node's-own-prefix arm
    // (`req.pathOnly != "compare_text"`).
    bool exact_match = false;
    Str compare_text{};
    u32 cluster_index = 0;
};

using RouteArms = FixedVec<RouteArm, kMaxEnvoyRoutes>;

Str strip_trailing_slash(Str prefix) {
    // Classify by LENGTH, not content: `prefix_shape_ok` in src/envoy/parser.cc
    // guarantees a length-1 prefix is always exactly "/" (the only other
    // accepted shape starts AND ends with '/', so it is at least 2 bytes).
    // Checking length instead of comparing bytes keeps this decision (and
    // the literal "/" this returns for the root case) immune to a caller
    // mutating the JSON source buffer after parsing but before lowering
    // (api_all_capabilities_matches_golden's mutation check) — `len` is a
    // plain integer captured at parse time, not re-read from the buffer.
    // Non-root node text is genuinely borrowed from the source (PR8 lowers
    // real path/prefix bytes), so no such guarantee applies there.
    if (prefix.len == 1u) return lit_str("/");
    return prefix.slice(0, prefix.len - 1u);
}

// Is `p` located under node `N` (`N == p`, or `N` is a segment-boundary
// prefix of `p`)? Root (`N == "/"`) is under everything.
bool is_under(Str node, Str p) {
    if (node.eq(lit_str("/"))) return true;
    if (node.eq(p)) return true;
    if (p.len <= node.len) return false;
    for (u32 i = 0; i < node.len; i++) {
        if (p.ptr[i] != node.ptr[i]) return false;
    }
    return p.ptr[node.len] == '/';
}

bool is_strict_ancestor(Str maybe_ancestor, Str node) {
    return !maybe_ancestor.eq(node) && is_under(maybe_ancestor, node);
}

// The node whose text is the longest match under which `q` falls. Root is
// always a candidate, so this always returns a value.
Str owner_node(Str q, const FixedVec<Str, kMaxEnvoyRoutes + 1>& candidates) {
    Str best = lit_str("/");
    for (u32 i = 0; i < candidates.len; i++) {
        if (candidates[i].len > best.len && is_under(candidates[i], q)) best = candidates[i];
    }
    return best;
}

u32 cluster_index_of(const Bootstrap& model, Str name) {
    for (u32 i = 0; i < model.clusters.len; i++) {
        if (model.clusters[i].name.eq(name)) return i;
    }
    return model.clusters.len;  // unreachable post-validation: every forward
                                // route's cluster is checked in `validate`.
}

// Builds one node's arm chain (see the algorithm comment above).
// `needs_exact_fallback` would be set when the chain's last arm had its
// condition dropped with no earlier exact arm covering the node's own
// literal path, but `build_node_plan` currently fails closed in that case
// instead (see "Remainder" above), so this is always false on a successful
// return; kept for the day an all-method local_response surface lands.
// `omit` (root only) means the node has no arms at all and should not be
// emitted; leaving `omit` false with an empty `arms` for a non-root node
// cannot happen (a non-root node's own prefix arm is always present).
struct NodePlanResult {
    RouteArms arms{};
    bool needs_exact_fallback = false;
    bool omit = false;
};

FrontendResult<NodePlanResult> build_node_plan(
    Str node_text,
    bool is_root,
    const VirtualHost& virtual_host,
    const FixedVec<Str, kMaxEnvoyRoutes + 1>& node_candidates,
    const Bootstrap& model) {
    NodePlanResult result{};
    bool saw_own_prefix = false;
    // True once a conditional `req.pathOnly == node_text` arm has been placed
    // for an exact `path` route declared before the node's own prefix route.
    // Without tracking this, a node ending in its own (now-unconditional)
    // prefix arm always requested the "node's own literal has no Envoy
    // route" fallback below, even when an earlier exact arm already resolves
    // that literal correctly (Codex P1: the fallback would then shadow the
    // earlier exact arm with a 404 Envoy never returns for that path).
    bool saw_own_exact = false;
    Span last_span{};

    for (u32 route_index = 0; route_index < virtual_host.routes.len; route_index++) {
        const Route& route = virtual_host.routes[route_index];
        const RouteMatch& match = route.match;
        const u32 cluster_index = cluster_index_of(model, route.action.cluster);

        if (match.kind == RouteMatchKind::Path) {
            const Str q = match.path;
            if (!owner_node(q, node_candidates).eq(node_text)) continue;
            if (q.eq(node_text)) {
                RouteArm arm{};
                arm.cluster_index = cluster_index;
                if (!saw_own_prefix) {
                    arm.exact_match = true;
                    arm.compare_text = q;
                    if (!result.arms.push(arm))
                        return out_of_memory(route.span, lit_str("too many routes to lower"));
                    saw_own_exact = true;
                    last_span = route.span;
                    continue;
                }
                arm.is_terminal = true;
                if (!result.arms.push(arm))
                    return out_of_memory(route.span, lit_str("too many routes to lower"));
                return result;  // resolved
            }
            if (saw_own_prefix) continue;  // dead: path == node_text already excluded
            RouteArm arm{};
            arm.exact_match = true;
            arm.compare_text = q;
            arm.cluster_index = cluster_index;
            if (!result.arms.push(arm))
                return out_of_memory(route.span, lit_str("too many routes to lower"));
            last_span = route.span;
            continue;
        }

        // Prefix route.
        const Str prefix_node = strip_trailing_slash(match.prefix);
        if (prefix_node.eq(node_text)) {
            if (is_root) {
                RouteArm arm{};
                arm.is_terminal = true;
                arm.cluster_index = cluster_index;
                if (!result.arms.push(arm))
                    return out_of_memory(route.span, lit_str("too many routes to lower"));
                return result;  // resolved: root's own prefix always matches
            }
            if (saw_own_prefix) continue;  // duplicate declaration: dead
            RouteArm arm{};
            arm.exact_match = false;
            arm.compare_text = node_text;
            arm.cluster_index = cluster_index;
            if (!result.arms.push(arm))
                return out_of_memory(route.span, lit_str("too many routes to lower"));
            saw_own_prefix = true;
            last_span = route.span;
            continue;
        }
        if (is_strict_ancestor(prefix_node, node_text)) {
            RouteArm arm{};
            arm.is_terminal = true;
            arm.cluster_index = cluster_index;
            if (!result.arms.push(arm))
                return out_of_memory(route.span, lit_str("too many routes to lower"));
            return result;  // resolved: an ancestor prefix always matches
        }
        // Strict descendant of `node_text`, or unrelated: irrelevant to this
        // node's chain.
    }

    // The walk finished without an unconditional arm.
    if (is_root) {
        if (result.arms.len == 0u) {
            result.omit = true;
            return result;
        }
        return unsupported(
            last_span,
            lit_str("BLOCKED_BY_RUT: a no-route 404 inside a route branch has no RUT form"));
    }
    // Non-root: the last kept arm is always this node's own prefix arm (see
    // the algorithm comment, "Remainder"). Drop its condition.
    result.arms[result.arms.len - 1].is_terminal = true;
    if (saw_own_exact) return result;  // the earlier exact arm already covers p == N
    // p == N has no Envoy route: same "no RUT form for a nested 404" problem
    // root hits below, PLUS `route exact` cannot stand in for it here either
    // (Codex P1: its strict local-response admission serves only GET/HEAD/
    // POST/OPTIONS/PUT/DELETE/PATCH, so an ANY-method `route exact "N"` 404
    // would close the connection instead of responding for e.g. TRACE, which
    // Envoy's real no-route 404 still answers). Fail closed until an
    // all-method local_response surface exists.
    return unsupported(
        last_span,
        lit_str("BLOCKED_BY_RUT: a no-route 404 for this node's own literal path has no RUT form "
                "that serves every method Envoy would 404 (route exact excludes TRACE/CONNECT)"));
}

bool put_route_arms(Writer& w, const RouteArms& arms, u32 index, bool include_head_mode) {
    const RouteArm& arm = arms[index];
    if (arm.is_terminal) return put_forward_call(w, arm.cluster_index, include_head_mode);
    if (!w.put_cstr("    if req.pathOnly ")) return false;
    if (!w.put_cstr(arm.exact_match ? "== \"" : "!= \"")) return false;
    if (!w.put_escaped(arm.compare_text) || !w.put_cstr("\" {\n")) return false;
    if (!put_forward_call(w, arm.cluster_index, include_head_mode)) return false;
    if (!w.put_cstr("    } else {\n")) return false;
    if (!put_route_arms(w, arms, index + 1u, include_head_mode)) return false;
    return w.put_cstr("    }\n");
}

// PR #692 round-3 review found that a method-omitted (any-method)
// `route "N" { ... }` / `route HEAD "N" { ... }` declaration, in the
// PR1-era `put_forward_route` this function replaced, also matches CONNECT —
// confirmed live against this converter's own shape (nginx-era policy
// fixture, since that branch predates PR3-PR5): `CONNECT / HTTP/1.1` matched
// the any-method route, Rut opened the upstream connection, and the origin's
// response was relayed back to the client, whereas Envoy rejects that
// request locally (a non-empty `:path` on a CONNECT request fails HCM's
// `ConnectionManagerImpl::ActiveStream::decodeHeaders` validation) without
// ever contacting an upstream — a real mis-forward, not a fail-closed
// refusal. The same any-method emission shape (`method_len == 0`) is used
// here for every non-root/root forwarding node, so the finding still
// applies. Two ways to prevent it inside the grammar were tried and both
// failed: (1) splitting every forwarded method into its own `route <METHOD>
// "N"` blows the lexer's fixed `kMaxTokens` budget
// (`include/rut/compiler/lexer.h`) once duplicated across all 7 non-HEAD
// forwarded methods (confirmed by compiling that shape with `rut`); (2) a
// `guard req.method == GET || … else { return 400 }` inside a node's body
// stays within the token budget, but CONNECT and TRACE are both plain
// identifiers with no `req.method == <KW>` expression-position keyword and
// no `route <METHOD> "N"` declaration spelling (`is_method_keyword`,
// `src/compiler/parser.cc`, covers only GET/POST/PUT/DELETE/PATCH/HEAD/
// OPTIONS; confirmed live that `route TRACE "/"` and `pre_route TRACE {
// return forward(...) }` are both parse errors — `pre_route`/`unmatched`
// bodies are fixed-shape local-response policies only, per
// `AstPreRouteDecl`/`AstUnmatchedDecl`, include/rut/compiler/ast.h), so a
// guard that excludes CONNECT is indistinguishable from one that also
// excludes TRACE, and TRACE must keep forwarding (Envoy forwards it like any
// other method; docs/envoy-converter.md, "Routing"). Trading the CONNECT
// mis-forward for a new TRACE mis-forward-turned-fail-closed is not an
// improvement, so this converter does not attempt a code fix here; see
// docs/envoy-compatibility.md for the recorded bug row and
// docs/envoy-converter.md's round-3 section for the full investigation.
bool put_route_node(
    Writer& w, Str node_text, const RouteArms& arms, const char* method, u32 method_len) {
    const bool include_head_mode = method_len != 0u;
    if (!w.put_cstr("route ")) return false;
    if (method_len != 0u && (!w.put_lit(method, method_len) || !w.put_cstr(" "))) return false;
    if (!w.put_cstr("\"") || !w.put_escaped(node_text) || !w.put_cstr("\" {\n")) return false;
    if (!put_route_arms(w, arms, 0u, include_head_mode)) return false;
    return w.put_cstr("}\n");
}

struct NodePlanEntry {
    Str text{};
    RouteArms arms{};
    bool needs_exact_fallback = false;
};

struct LoweringPlan {
    FixedVec<NodePlanEntry, kMaxEnvoyRoutes + 1> emit_order{};
};

FrontendResult<LoweringPlan> build_lowering_plan(const Bootstrap& model) {
    const VirtualHost& virtual_host = model.listener.filter_chain.hcm.route_config.virtual_host;
    LoweringPlan plan{};

    FixedVec<Str, kMaxEnvoyRoutes + 1> node_candidates{};
    node_candidates.push(lit_str("/"));
    FixedVec<Str, kMaxEnvoyRoutes> declared_nodes{};
    bool root_declared = false;

    for (u32 route_index = 0; route_index < virtual_host.routes.len; route_index++) {
        const Route& route = virtual_host.routes[route_index];
        if (route.match.kind != RouteMatchKind::Prefix) continue;
        const Str node_text = strip_trailing_slash(route.match.prefix);
        bool seen = false;
        for (const Str& existing : declared_nodes) {
            if (existing.eq(node_text)) {
                seen = true;
                break;
            }
        }
        if (seen) continue;
        if (!declared_nodes.push(node_text))
            return out_of_memory(route.span, lit_str("too many routes to lower"));
        if (node_text.eq(lit_str("/"))) {
            root_declared = true;
        } else if (!node_candidates.push(node_text)) {
            return out_of_memory(route.span, lit_str("too many routes to lower"));
        }
    }

    for (const Str& node_text : declared_nodes) {
        const bool is_root = node_text.eq(lit_str("/"));
        auto planned = build_node_plan(node_text, is_root, virtual_host, node_candidates, model);
        if (!planned) return core::make_unexpected(planned.error());
        NodePlanEntry entry{};
        entry.text = node_text;
        entry.arms = planned.value().arms;
        entry.needs_exact_fallback = planned.value().needs_exact_fallback;
        if (!plan.emit_order.push(entry))
            return out_of_memory(model.span, lit_str("too many routes to lower"));
    }

    if (!root_declared) {
        auto planned = build_node_plan(lit_str("/"), true, virtual_host, node_candidates, model);
        if (!planned) return core::make_unexpected(planned.error());
        if (!planned.value().omit) {
            NodePlanEntry entry{};
            entry.text = lit_str("/");
            entry.arms = planned.value().arms;
            entry.needs_exact_fallback = false;
            if (!plan.emit_order.push(entry))
                return out_of_memory(model.span, lit_str("too many routes to lower"));
        }
    }
    return plan;
}

// Capability validation (docs/envoy-converter.md; PR1 plan, "Capability
// validation", generalized to an ordered route list in PR8). Defensive model
// checks come first because a hand-built `Bootstrap` (as opposed to one
// produced by `parse_bootstrap_json`) must still fail closed rather than
// emit an upstream with no address or a route to an undeclared cluster.
// `direct_response` / `redirect` and raw prefixes remain rejected (PR
// 9/10 lower them); every remaining route must be `route.cluster`-only, with
// `timeout: "0s"`. The six BLOCKED_BY_RUT checks then run in a fixed order;
// the first failure wins.
FrontendResult<bool> validate(const Bootstrap& model, const RutCapabilities& caps) {
    const HttpConnectionManager& hcm = model.listener.filter_chain.hcm;
    const RouterFilter& router = hcm.router;
    const VirtualHost& virtual_host = hcm.route_config.virtual_host;
    if (model.listener.address.port == 0u)
        return invalid(model.listener.address.span, lit_str("listener port must be non-zero"));
    // Codex round-10 review: `FixedVec::len` (include/rut/common/types.h) is
    // a public field with no accompanying bound check, and the
    // fixed-capacity `data` array beneath it is only ever `Cap` (here
    // `kMaxEnvoyClusters`/`kMaxEnvoyRoutes`) elements wide. `parse_clusters`/
    // `parse_routes` (src/envoy/parser.cc) never produce a `len` past their
    // respective caps, but the public hand-built-model overload can set
    // `model.clusters.len` or `virtual_host.routes.len` to anything: the
    // cluster loop immediately below indexes `model.clusters[i]` for every
    // `i` up to `model.clusters.len`, so an oversized forged count runs that
    // loop past the end of `data` -- undefined behavior, reproducible as an
    // ASan stack-buffer-overflow -- before the `len > 1u` "not lowered yet"
    // rejection further down ever gets a chance to run. Reject both
    // out-of-bounds counts here, before any loop over either vector.
    if (model.clusters.len > kMaxEnvoyClusters)
        return invalid(model.span, lit_str("cluster count exceeds the bounded capacity"));
    if (virtual_host.routes.len > kMaxEnvoyRoutes)
        return invalid(virtual_host.span, lit_str("route count exceeds the bounded capacity"));
    // PR #692 round-15 review: `listener.name` and `hcm.route_config.name`
    // are optional (`name_string(..., allow_empty=true)`,
    // src/envoy/parser.cc:350-352 and :538-540) but the parser still bounds
    // either by `kMaxEnvoyNameLen` when present. Nothing here re-enforced
    // that bound, so a caller of the public `lower_to_rut(model,
    // capabilities)` overload could set either to a non-empty string over
    // the limit and still lower successfully, accepting a model
    // `parse_bootstrap_json` would reject.
    if (model.listener.name.len > kMaxEnvoyNameLen)
        return unsupported(model.listener.name_span, lit_str("name exceeds the bounded length"));
    if (hcm.route_config.name.len > kMaxEnvoyNameLen)
        return unsupported(hcm.route_config.name_span, lit_str("name exceeds the bounded length"));
    // `model.clusters` may legitimately be empty for a local-only route
    // table (every route `direct_response`/`redirect`; see the
    // `direct_response`/`redirect` checks in the per-route loop below and
    // docs/envoy-compatibility.md, "Allow local-only route tables to omit
    // clusters"), so cluster-count is not checked unconditionally here. A
    // `Forward` route with no declared clusters still fails closed below:
    // the per-route "declared" search over an empty `model.clusters` never
    // finds a match, so it falls through to "route cluster does not name a
    // declared cluster".
    //
    // PR #692 round-9/round-8 review, ported to the route-list model:
    // `name.empty()` guards the `Str::eq` empty-vs-empty forgery the
    // per-route `action.cluster` check below relies on being impossible (a
    // caller of the public `lower_to_rut(model, capabilities)` overload who
    // clears a declared cluster's `name` on a parsed copy, or hand-builds a
    // `Bootstrap` that never sets it, would otherwise let an also-cleared
    // `action.cluster` pass an equality check it should fail; the parser
    // requires both non-empty, `min_len: 1` on both the v3 `Cluster.name`
    // and the route action's `cluster`). `load_assignment_name_present` is
    // the model's only record that `parse_bootstrap_json` ever saw and
    // validated that cluster's `load_assignment.cluster_name` (required,
    // non-empty, and equal to `name` per Envoy's v3
    // `ClusterLoadAssignment.cluster_name` `min_len: 1`). Checked for every
    // declared cluster now that route lists may name more than one.
    for (u32 i = 0; i < model.clusters.len; i++) {
        if (model.clusters[i].endpoint.address.port == 0u)
            return invalid(model.clusters[i].endpoint.address.span,
                           lit_str("endpoint port must be non-zero"));
        // `parse_cluster` (src/envoy/parser.cc) guarantees every parsed
        // cluster name is backed, non-empty, and at most `kMaxEnvoyNameLen`
        // bytes (`name_string(node, /*allow_empty=*/false, ...)`). A
        // hand-built `Bootstrap` bypasses the parser entirely: a malformed
        // name such as `Str{nullptr, 1}` reaching `Str::eq` below (or the
        // RUT emission further down) would dereference a null pointer
        // instead of producing a diagnostic. Reapply that invariant here,
        // before comparing names, for every cluster.
        if (model.clusters[i].name.len == 0u || model.clusters[i].name.ptr == nullptr)
            return invalid(model.clusters[i].name_span,
                           lit_str("cluster name must be a non-empty string"));
        // PR #692 round-12 review / Codex round-5 review on PR #695
        // (independently the same finding): revalidate the bounded length
        // too, not just non-emptiness/equality. `name_string`
        // (src/envoy/parser.cc:179-185) rejects every name over
        // `kMaxEnvoyNameLen` during parsing, but nothing above re-checks
        // that bound; a caller of the public `lower_to_rut(model,
        // capabilities)` overload who sets a declared cluster's `name` (and
        // the matching `action.cluster`) to the same overlong string still
        // passes the equality check below and would otherwise lower
        // successfully, accepting a model `parse_bootstrap_json` would
        // reject. Checked for every declared cluster now that route lists
        // may name more than one.
        if (model.clusters[i].name.len > kMaxEnvoyNameLen)
            return unsupported(model.clusters[i].name_span,
                               lit_str("name exceeds the bounded length"));
        // PR #692 round-9/round-8 review, ported: `load_assignment_name_present`
        // is the model's only record that `parse_bootstrap_json` ever saw and
        // validated this cluster's `load_assignment.cluster_name` (required,
        // non-empty, and equal to `name` per Envoy's v3
        // `ClusterLoadAssignment.cluster_name` `min_len: 1`). A hand-built
        // `Bootstrap`, or a parsed copy with the bit cleared, still has a
        // matching `action.cluster` / cluster `name` pair and would
        // otherwise lower successfully, emitting a working gateway for a
        // bootstrap Envoy would reject at startup.
        if (!model.clusters[i].load_assignment_name_present)
            return invalid(model.clusters[i].span,
                           lit_str("cluster load_assignment.cluster_name is required"));
        // PR #692 round-12 review, ported: presence of the bit is not proof
        // that the *current* `name`/a route's `action.cluster` still match
        // what `parse_bootstrap_json` validated `load_assignment.cluster_
        // name` against -- a caller of the public `lower_to_rut(model,
        // capabilities)` overload can rename both a route's `action.cluster`
        // and this declared cluster's `name` on a parsed copy (to the same
        // new string, so the equality check below still passes) while
        // leaving `load_assignment_name_present` true and
        // `load_assignment_name` holding the old, now-stale name. Retaining
        // the parsed value (`Cluster::load_assignment_name`,
        // include/rut/envoy/parser.h) lets this revalidate the equality at
        // lowering time instead of trusting historical presence. Checked for
        // every declared cluster now that route lists may name more than
        // one.
        if (!model.clusters[i].load_assignment_name.eq(model.clusters[i].name))
            return invalid(model.clusters[i].load_assignment_name_span,
                           lit_str("load_assignment.cluster_name must equal the cluster name"));
        // PR #692 round-10 review, ported: revalidate `connect_timeout` too
        // -- the parser requires it strictly positive (`parse_duration(...,
        // allow_zero=false)`, src/envoy/parser.cc, same "duration must be
        // positive" diagnostic reused here) because Envoy itself rejects a
        // zero `connect_timeout`, but the emitted RUT program never reads
        // this field. A hand-built `Bootstrap` passed to the public
        // `lower_to_rut(model, capabilities)` overload that sets a declared
        // cluster's `connect_timeout.milliseconds` to zero (or a caller who
        // mutates it on a parsed copy) would otherwise still lower
        // successfully, returning a working gateway for a bootstrap Envoy
        // would reject at startup. Checked for every declared cluster now
        // that route lists may name more than one.
        if (model.clusters[i].connect_timeout.milliseconds == 0u)
            return invalid(model.clusters[i].connect_timeout.span,
                           lit_str("duration must be positive"));
        // The JSON parser (`parse_clusters`) already rejects a duplicate
        // cluster name; a hand-built `Bootstrap` bypasses that, and
        // `cluster_index_of` silently resolves every same-named reference to
        // the FIRST match while every cluster is still emitted as its own
        // `upstream envoy_cluster_<i>` — reapply the invariant here.
        for (u32 j = 0; j < i; j++) {
            if (model.clusters[j].name.eq(model.clusters[i].name))
                return invalid(model.clusters[i].name_span, lit_str("duplicate cluster name"));
        }
    }
    if (virtual_host.routes.len == 0u)
        return invalid(virtual_host.span, lit_str("at least one route is required"));

    // direct_response / redirect actions are modeled (RouteActionKind) but
    // not lowered yet (PR 9/10 lower them). Reject precisely, before the
    // capability checks below, so a model that would also hit a
    // BLOCKED_BY_RUT row gets the more specific diagnostic. Route lists with
    // multiple routes, multiple clusters, `match.path`, and non-root
    // `match.prefix` are lowered by `build_lowering_plan` below.
    for (u32 i = 0; i < virtual_host.routes.len; i++) {
        const RouteMatch& match = virtual_host.routes[i].match;
        // Codex round-6 review, ported: the public hand-built-model overload
        // does not go through the parser, whose `parse_route_match` only
        // ever produces one of the two declared `RouteMatchKind`
        // enumerators. Without this explicit check, a forged `match.kind`
        // outside {Prefix, Path} would skip both branches below (neither
        // `if` nor `else if` matches it) and reach `build_lowering_plan`
        // unvalidated, which treats every non-`Path` kind as a `Prefix`
        // using the untouched (possibly default-empty) `match.prefix`.
        if (match.kind != RouteMatchKind::Prefix && match.kind != RouteMatchKind::Path)
            return invalid(match.span, lit_str("match kind is not recognized"));
        // The JSON parser (`prefix_shape_ok` / `path_shape_ok`,
        // src/envoy/parser.cc) guarantees every parsed prefix is either "/"
        // or at least 2 bytes starting and ending with '/', and every parsed
        // path starts with '/'. A hand-built `Bootstrap` bypasses the parser
        // entirely: an empty or malformed prefix reaching
        // `strip_trailing_slash` in `build_lowering_plan` below would
        // underflow `prefix.len - 1u` into a huge slice length instead of
        // producing a diagnostic. Revalidate the same shape here so every
        // caller of the public `Bootstrap` overload fails closed.
        if (match.kind == RouteMatchKind::Prefix) {
            const Str prefix = match.prefix;
            // A length-1 prefix must actually BE "/" (content, not just
            // length): `strip_trailing_slash` below classifies by length
            // alone and returns the literal "/" for every length-1 input
            // (see its own comment for why -- immunity to a caller mutating
            // the JSON source buffer after parsing but before lowering), so
            // a hand-built `Bootstrap` with e.g. prefix "x" (`Str{"x", 1}`)
            // would otherwise be silently accepted and routed as root
            // instead of failing closed (Codex P2 on PR #695 round 4); a
            // direct-model `Str{nullptr, 1}` would additionally dereference
            // `ptr[0]` in the byte-validation loop below without the
            // `ptr != nullptr` guard here. Content IS still compared for
            // this one case -- unlike `strip_trailing_slash`'s
            // length-only return, which only ever needs to produce the
            // literal "/" once shape_ok has already confirmed the content.
            const bool shape_ok =
                (prefix.len == 1u && prefix.ptr != nullptr && prefix.ptr[0] == '/') ||
                (prefix.len >= 2u && prefix.ptr != nullptr && prefix.ptr[0] == '/' &&
                 prefix.ptr[prefix.len - 1u] == '/');
            if (!shape_ok)
                return invalid(match.span,
                               lit_str("route match prefix must be \"/\" or start and end with "
                                       "\"/\""));
        } else if (match.kind == RouteMatchKind::Path) {
            const Str path = match.path;
            if (path.len == 0u || path.ptr == nullptr || path.ptr[0] != '/')
                return invalid(match.span, lit_str("route match path must start with \"/\""));
        } else {
            // The JSON parser only ever produces `Prefix` or `Path`. A
            // hand-built `Bootstrap` can set `match.kind` to a value outside
            // that two-member enum; without this branch it silently falls
            // through both checks above with no shape validation, and
            // `build_node_plan` below treats every non-`Path` kind as a
            // prefix using the untouched (possibly default-empty)
            // `match.prefix` — reaching `strip_trailing_slash`, underflowing
            // `prefix.len - 1u`, and producing a huge out-of-bounds view
            // instead of a diagnostic. Fail closed on the unknown
            // discriminator here instead.
            return invalid(match.span, lit_str("route match kind is not recognized"));
        }
        const Str text = match.kind == RouteMatchKind::Prefix ? match.prefix : match.path;
        // `validate_route_match_bytes` (src/envoy/parser.cc) is a private
        // `Parser` method, so a hand-built `Bootstrap` never goes through
        // it. Reapply the same byte-set and length bound here so a
        // caller-supplied prefix/path like "/ok\n..." (or one over 64
        // bytes) cannot reach `put_escaped`/node-text emission below, which
        // only escapes `\` and `"`, and produce syntactically invalid --or
        // merely unintended-- RUT.
        // Mirrors src/envoy/parser.cc's private `kMaxRouteMatchLen` (same
        // value, not exported to this translation unit).
        constexpr u32 kMaxRouteMatchLen = 64u;
        if (text.len > kMaxRouteMatchLen)
            return unsupported(match.span, lit_str("route match value exceeds 64 bytes"));
        for (u32 c = 0; c < text.len; c++) {
            const auto b = static_cast<unsigned char>(text.ptr[c]);
            // `"` and `\` are additionally excluded here (beyond the parser's
            // own `route_match_byte_ok`, src/envoy/parser.cc): `put_escaped`
            // below inserts a `\` before either byte so the emitted RUT
            // string literal cannot break out early, but the RUT lexer
            // (src/compiler/lexer.cc) never decodes that escape -- it only
            // skips `\`+next-byte pairs while scanning for the closing
            // quote, and keeps BOTH bytes verbatim in `Token::text`, which
            // `parse_primary`'s `StrLit` case and `parse_route_entry`'s
            // `item.route.path` assignment then copy unchanged. A path like
            // `/a"b` would therefore round-trip through this converter as
            // the five-byte runtime string `/a\"b`, not the original four
            // bytes, so `req.pathOnly == "..."` / `route "..."` comparisons
            // would never match the real request (Codex P2 on PR #695 round
            // 4). The JSON-parsed path already can't carry these bytes --
            // `plain_string` rejects any escaped JSON string outright -- so
            // this only ever fires for a hand-built `Bootstrap` caller.
            const bool byte_ok = b >= 0x21u && b <= 0x7eu && text.ptr[c] != '?' &&
                                 text.ptr[c] != '#' && text.ptr[c] != '%' && text.ptr[c] != '"' &&
                                 text.ptr[c] != '\\';
            if (!byte_ok)
                return unsupported(match.span,
                                   lit_str("route match value must be printable ASCII excluding "
                                           "?, #, %, \", and \\"));
        }
        // Only a `prefix` match's text ever becomes a RUT route declaration
        // (`route "<node_text>" { ... }`, via `strip_trailing_slash` in
        // `build_lowering_plan` below): an exact `path` match is never
        // emitted as a route declaration -- `build_node_plan` only ever
        // compares it as a string literal (`req.pathOnly == "..."`) or
        // drops it entirely behind an ancestor's terminal arm -- so it
        // carries neither of the two risks below and must not be rejected
        // for them.
        if (match.kind == RouteMatchKind::Prefix) {
            // Envoy treats every byte of a `prefix` literally, but a
            // generated RUT node interprets any segment beginning with ':'
            // as a route parameter (include/rut/runtime/route_trie.h): a
            // prefix like "/:tenant/" would emit `route "/:tenant"`, which
            // then captures and forwards `/anything/x` where Envoy finds no
            // matching route at all. Reject rather than silently change the
            // match semantics.
            for (u32 c = 0; c + 1u < text.len; c++) {
                if (text.ptr[c] == '/' && text.ptr[c + 1u] == ':')
                    return unsupported(
                        match.span,
                        lit_str("route match segments beginning with \":\" would become a RUT "
                                "route parameter, not a literal match; not lowered"));
            }
            // A prefix containing an internal "//" collapses, in Rut's
            // route trie (route_trie.h: "empty segments are dropped, so
            // \"/api//v1\" == \"/api/v1\""), to the same node text as its
            // single-slash form, but this converter treats the two Str
            // values as distinct declared nodes. A bootstrap that ever
            // declared both forms would therefore emit two RUT route
            // declarations the runtime resolves as one (build order decides
            // which wins), silently dropping one route. Reject the
            // directly-detectable case -- the configured text itself
            // containing "//" -- here; a request path reaching an
            // already-distinct declared node via slash collapsing (no
            // "//" in any declared text) is the separate, broader
            // divergence already recorded as NOT_IMPLEMENTED in
            // docs/envoy-compatibility.md ("Path normalization").
            for (u32 c = 0; c + 1u < text.len; c++) {
                if (text.ptr[c] == '/' && text.ptr[c + 1u] == '/')
                    return unsupported(
                        match.span,
                        lit_str("route match prefix contains \"//\", which Rut's route trie "
                                "collapses; not lowered"));
            }
        }

        const RouteAction& action = virtual_host.routes[i].action;
        if (action.kind == RouteActionKind::DirectResponse)
            return unsupported(action.span, lit_str("direct_response is not lowered yet"));
        if (action.kind == RouteActionKind::Redirect)
            return unsupported(action.span, lit_str("redirect is not lowered yet"));
        // The public hand-built-model overload does not go through the
        // parser, whose `parse_route_action` only ever produces one of the
        // three `RouteActionKind` enumerators. Without this explicit check,
        // an out-of-range discriminator (a forged model, or a future
        // enumerator this function hasn't been taught about) would fall
        // through the two checks above and reach the Forward-only lowering
        // below by elimination rather than by being verified as `Forward` —
        // `lower_to_rut` would then silently emit a forwarding route for an
        // action kind it does not actually recognize.
        if (action.kind != RouteActionKind::Forward)
            return invalid(action.span, lit_str("route action kind is not recognized"));
        // PR #692 round-9 review, ported: reject an empty `action.cluster`
        // explicitly too (see the per-cluster `name.empty()` loop above for
        // the matching declared-name-emptiness guard the forgery needed
        // both sides of).
        if (action.cluster.empty())
            return invalid(action.cluster_span,
                           lit_str("route cluster does not name a declared cluster"));
        bool declared = false;
        for (u32 j = 0; j < model.clusters.len; j++) {
            if (action.cluster.eq(model.clusters[j].name)) {
                declared = true;
                break;
            }
        }
        if (!declared)
            return invalid(action.cluster_span,
                           lit_str("route cluster does not name a declared cluster"));
        // PR #692 round-12 review, ported to the route-list model: revalidate
        // the bounded length too, not just non-emptiness/equality.
        // `name_string` (src/envoy/parser.cc:179-185) rejects every name
        // over `kMaxEnvoyNameLen` during parsing, but nothing above
        // re-checks that bound; a caller of the public
        // `lower_to_rut(model, capabilities)` overload who sets a route's
        // `action.cluster` and a declared cluster's `name` to the same
        // overlong string still passes the equality check above and would
        // otherwise lower successfully, accepting a model
        // `parse_bootstrap_json` would reject. Checked for every route now
        // that route lists may have more than one. The matching per-cluster
        // `name` bound (and the `load_assignment_name` presence/equality
        // revalidation) is ported into the per-cluster loop above instead of
        // repeated here.
        if (action.cluster.len > kMaxEnvoyNameLen)
            return unsupported(action.cluster_span, lit_str("name exceeds the bounded length"));
    }
    // PR #692 round-10 review: revalidate `virtual_host.name` too — the
    // parser requires it non-empty (`parse_virtual_host`, "virtual host name
    // must be a non-empty string", src/envoy/parser.cc), but the emitted RUT
    // program never reads this field. A hand-built `Bootstrap` that clears
    // `virtual_host.name` on a parsed copy (or never sets it) would
    // otherwise still lower successfully, silently accepting a model
    // `parse_bootstrap_json` would reject.
    if (virtual_host.name.empty())
        return invalid(virtual_host.name_span,
                       lit_str("virtual host name must be a non-empty string"));
    // PR #692 round-12 review: revalidate the bounded length too, the same
    // gap the `action.cluster`/`cluster.name` length checks above close —
    // `name_string` (src/envoy/parser.cc:179-185) rejects every name over
    // `kMaxEnvoyNameLen` during parsing, but nothing re-checks that bound
    // here, so a hand-built or mutated `Bootstrap` with an overlong
    // `virtual_host.name` would otherwise still lower successfully.
    if (virtual_host.name.len > kMaxEnvoyNameLen)
        return unsupported(virtual_host.name_span, lit_str("name exceeds the bounded length"));
    // PR #692 round-9 review, ported to the route-list model: validation
    // never checked that parsing established `domains: ["*"]` on the
    // virtual host. A hand-built `Bootstrap`, or a parsed copy with
    // `virtual_host.domains_span` cleared, still lowers even though the
    // generated route has no host dimension and therefore matches every
    // authority, which widens routing beyond what the model claims.
    // `domains_span` is the model's only record that `parse_virtual_host`
    // ever saw and accepted the exact single-element `["*"]` array (the
    // parser rejects every other `domains` value), the same evidence-bit
    // shape as `hcm.type_url_span` and `hcm.generate_request_id_span` below.
    if (virtual_host.domains_span.start == 0u && virtual_host.domains_span.end == 0u)
        return invalid(virtual_host.span, lit_str("virtual host domains must be [\"*\"]"));
    // PR #692 round-4 review: revalidate the router filter's identity here
    // too, not just `suppress_envoy_headers` on it — a forged `router.name`
    // or a cleared `has_typed_config` would otherwise still lower
    // successfully and silently omit whatever filter the model actually
    // named (e.g. a Lua filter's behavior).
    if (!router.name.eq(kRouterFilterName))
        return invalid(router.name_span,
                       lit_str("router filter name must be envoy.filters.http.router"));
    if (!router.has_typed_config)
        return invalid(router.span, lit_str("router filter typed_config is required"));
    // PR #692 round-5 review: revalidate the network filter's identity too —
    // the same class of gap the router checks above close, one level up.
    // `filter_chain.filter_name` is a public field a caller can retarget at
    // another network filter (e.g. "envoy.filters.network.tcp_proxy") while
    // leaving `hcm` populated, and `hcm.type_url_span` — the model's only
    // record that the typed_config's `@type` was ever checked against the
    // v3 HttpConnectionManager type — stays the zero `Span{}` on a
    // hand-built model that skipped that check. Either forgery must not
    // still lower successfully and silently discard the modeled network
    // filter's behavior.
    if (!model.listener.filter_chain.filter_name.eq(kNetworkFilterName))
        return invalid(
            model.listener.filter_chain.filter_name_span,
            lit_str("network filter name must be envoy.filters.network.http_connection_manager"));
    if (hcm.type_url_span.start == 0u && hcm.type_url_span.end == 0u)
        return invalid(hcm.span, lit_str("network filter typed_config is required"));
    // PR #692 round-10 review: revalidate `hcm.stat_prefix` too — the parser
    // requires it non-empty (`stat_prefix must be a non-empty string`,
    // src/envoy/parser.cc:419-425), but the emitted RUT program never reads
    // this field. A hand-built `Bootstrap` that clears `stat_prefix` on a
    // parsed copy (or never sets it) would otherwise still lower
    // successfully, silently accepting a model `parse_bootstrap_json` would
    // reject.
    if (hcm.stat_prefix.empty())
        return invalid(hcm.stat_prefix_span, lit_str("stat_prefix must be a non-empty string"));
    // PR #692 round-12 review: revalidate the bounded length too, the same
    // gap the `action.cluster`/`cluster.name`/`virtual_host.name` length
    // checks close elsewhere in this function — `name_string`
    // (src/envoy/parser.cc:179-185) rejects every name over
    // `kMaxEnvoyNameLen` during parsing, but nothing re-checks that bound
    // here, so a hand-built or mutated `Bootstrap` with an overlong
    // `stat_prefix` would otherwise still lower successfully.
    if (hcm.stat_prefix.len > kMaxEnvoyNameLen)
        return unsupported(hcm.stat_prefix_span, lit_str("name exceeds the bounded length"));
    // PR #692 round-9 review: revalidate `codec_type` too, the same class of
    // gap the `type_url_span` check above closes one field over.
    // `codec_type_present` is the model's only record that `parse_hcm` ever
    // saw and accepted an explicit `codec_type: "HTTP1"` (the parser rejects
    // the implicit proto3-default `AUTO`, which admits downstream h2c on
    // this plaintext listener — see `CodecType` in
    // include/rut/envoy/parser.h); a hand-built `Bootstrap` passed to the
    // public `lower_to_rut(model, capabilities)` overload that clears
    // `codec_type_present`, or sets `codec_type` back to `Auto` while
    // leaving the presence bit set, would otherwise still lower
    // successfully, silently admitting the exact divergence this milestone
    // is scoped to exclude (the emitted request policy is pinned to
    // HTTP/1.1).
    if (!hcm.codec_type_present || hcm.codec_type != CodecType::Http1) {
        const Span span = hcm.codec_type_present ? hcm.codec_type_span : hcm.span;
        return invalid(span, lit_str("codec_type must be explicit HTTP1"));
    }
    // PR #692 round-6 review: revalidate `generate_request_id`'s evidence
    // too, the same class of gap the `type_url_span` check above closes one
    // field over. `HttpConnectionManager::generate_request_id_span` is the
    // model's only record that `parse_hcm` ever saw and accepted
    // `generate_request_id: false` (it stays the zero `Span{}` on a
    // hand-built model that never set the field, or that a caller cleared
    // after parsing); an omitted `generate_request_id` defaults to `true` in
    // real Envoy, which adds a random `x-request-id` to every upstream
    // request that this emitted RUT program never generates. Without this
    // check, a forged or incomplete model still lowers successfully and
    // silently admits that divergence.
    if (hcm.generate_request_id_span.start == 0u && hcm.generate_request_id_span.end == 0u)
        return invalid(hcm.span,
                       lit_str("generate_request_id: false is required; Rut does not generate "
                               "x-request-id"));

    // PR #692 round-9 review: require the presence bit too, not just the
    // value — a hand-built model with `suppress_envoy_headers = true` but
    // `suppress_envoy_headers_present = false` used to lower successfully,
    // even though an omitted field defaults to `false` in real Envoy (which
    // then adds the headers this emitted policy assumes are suppressed).
    if (!router.suppress_envoy_headers_present || !router.suppress_envoy_headers) {
        const Span span = router.suppress_envoy_headers_present ? router.suppress_envoy_headers_span
                                                                : router.span;
        return unsupported(
            span,
            lit_str("BLOCKED_BY_RUT: x-envoy-upstream-service-time has no RUT equivalent; set "
                    "suppress_envoy_headers: true on the router filter"));
    }

    for (u32 i = 0; i < virtual_host.routes.len; i++) {
        const RouteAction& action = virtual_host.routes[i].action;
        if (!action.timeout_present)
            return unsupported(
                action.span,
                lit_str("BLOCKED_BY_RUT: Envoy's default 15s route timeout has no RUT equivalent "
                        "here; set route timeout \"0s\""));
        if (action.timeout.milliseconds != 0u)
            return unsupported(
                action.timeout.span,
                lit_str("BLOCKED_BY_RUT: a non-zero route timeout has no RUT equivalent here; set "
                        "route timeout \"0s\""));
    }

    if (!caps.request_envoy_h1)
        return unsupported(
            virtual_host.routes[0].action.cluster_span,
            lit_str("BLOCKED_BY_RUT: Envoy preserves Host and lowercases upstream request header "
                    "names; RUT request_policy lacks host: \"preserve\""));
    if (!caps.response_envoy_h1)
        return unsupported(
            hcm.span,
            lit_str("BLOCKED_BY_RUT: Envoy lowercases response header names and preserves the "
                    "upstream date; RUT response_policy lacks header_order: \"upstream\""));
    if (!caps.local_reply_envoy_h1)
        return unsupported(
            hcm.route_config.span,
            lit_str("BLOCKED_BY_RUT: Envoy local replies (404 no route, 503 connect failure) need "
                    "the lowercase local_response/failure_policy layout"));
    return true;
}

}  // namespace

FrontendResult<RutSource> lower_to_rut(const Bootstrap& model,
                                       const RutCapabilities& capabilities) {
    auto validated = validate(model, capabilities);
    if (!validated) return core::make_unexpected(validated.error());

    auto planned = build_lowering_plan(model);
    if (!planned) return core::make_unexpected(planned.error());
    const LoweringPlan& plan = planned.value();

    RutSource output{};
    Writer writer(output);
    auto fail_overflow = [&]() -> FrontendResult<RutSource> {
        return out_of_memory(model.span, lit_str("generated RUT source is too large"));
    };

    const SocketAddress& listen = model.listener.address;

    if (!writer.put_cstr("listen ")) return fail_overflow();
    if (listen.ipv4_host == 0u) {
        if (!writer.put_cstr(":")) return fail_overflow();
    } else if (!writer.put_ipv4_host(listen.ipv4_host) || !writer.put_cstr(":")) {
        return fail_overflow();
    }
    if (!writer.put_u16(listen.port) || !writer.put_cstr("\n")) return fail_overflow();

    for (u32 i = 0; i < model.clusters.len; i++) {
        const SocketAddress& upstream = model.clusters[i].endpoint.address;
        if (!writer.put_cstr("upstream envoy_cluster_") || !writer.put_u16(static_cast<u16>(i)) ||
            !writer.put_cstr(" at \"") || !writer.put_ipv4_host(upstream.ipv4_host) ||
            !writer.put_cstr(":") || !writer.put_u16(upstream.port) || !writer.put_cstr("\"\n"))
            return fail_overflow();
    }

    if (!put_unmatched(writer)) return fail_overflow();

    for (u32 i = 0; i < plan.emit_order.len; i++) {
        const NodePlanEntry& node = plan.emit_order[i];
        if (node.needs_exact_fallback && !put_route_exact_404(writer, node.text))
            return fail_overflow();
        if (!put_route_node(writer, node.text, node.arms, "HEAD", 4u)) return fail_overflow();
        if (!put_route_node(writer, node.text, node.arms, "", 0u)) return fail_overflow();
    }

    return output;
}

FrontendResult<RutSource> lower_to_rut(const Bootstrap& model) {
    return lower_to_rut(model, kShippedRutCapabilities);
}

bool needs_h2c_preface_warning(const Bootstrap& model) {
    return model.listener.filter_chain.hcm.codec_type == CodecType::Http1;
}

}  // namespace rut::envoy
