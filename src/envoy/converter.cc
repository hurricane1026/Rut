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

// Recorded verbatim from the pinned Envoy oracle transcript
// (tests/fixtures/envoy_oracle_milestone_s.inc, `kEnvoyOracle_connect_failure_downstream`):
// 98 bytes, `content-length: 98`.
static constexpr char kEnvoyConnectFailureBody[] =
    "upstream connect error or disconnect/reset before headers. reset reason: remote connection "
    "failure";

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

// One `forward(envoy_cluster_0, ...)` route body. `include_head_mode` is true
// only for the HEAD route, where the response/failure bodies must be
// suppressed even though the policies otherwise describe a bodied response.
//
// PR #692 round-3 review found that this route, when emitted with a
// method-omitted (any-method) declaration, also matches CONNECT — confirmed
// live against this converter's own shape (nginx-era policy fixture, since
// this branch predates PR3-PR5): `CONNECT / HTTP/1.1` matched the any-method
// route, Rut opened the upstream connection, and the origin's response was
// relayed back to the client, whereas Envoy rejects that request locally (a
// non-empty `:path` on a CONNECT request fails HCM's
// `ConnectionManagerImpl::ActiveStream::decodeHeaders` validation) without
// ever contacting an upstream — a real mis-forward, not a fail-closed
// refusal. Two ways to prevent it inside the grammar were tried and both
// failed: (1) splitting every forwarded method into its own `route <METHOD>
// "/"` blows the lexer's fixed `kMaxTokens` budget
// (`include/rut/compiler/lexer.h`) once duplicated across all 7 non-HEAD
// forwarded methods (confirmed by compiling that shape with `rut`); (2) a
// `guard req.method == GET || … else { return 400 }` inside this route body
// stays within the token budget, but CONNECT and TRACE are both plain
// identifiers with no `req.method == <KW>` expression-position keyword and
// no `route <METHOD> "/"` declaration spelling (`is_method_keyword`,
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
bool put_forward_route(Writer& w, const char* method, u32 method_len, bool include_head_mode) {
    if (!w.put_cstr("route ")) return false;
    if (method_len != 0u && (!w.put_lit(method, method_len) || !w.put_cstr(" "))) return false;
    if (!w.put_cstr("\"/\" {\n")) return false;
    if (!w.put_cstr(
            "    return forward(envoy_cluster_0, request_policy: {\n"
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
           w.put_cstr(
               "\"\n"
               "        }\n"
               "    )\n"
               "}\n");
}

// Capability validation (docs/envoy-converter.md; PR1 plan, "Capability
// validation"). Defensive model checks come first because a hand-built
// `Bootstrap` (as opposed to one produced by `parse_bootstrap_json`) must
// still fail closed rather than emit an upstream with no address or a route
// to an undeclared cluster. The six BLOCKED_BY_RUT checks then run in a fixed
// order; the first failure wins.
FrontendResult<bool> validate(const Bootstrap& model, const RutCapabilities& caps) {
    const HttpConnectionManager& hcm = model.listener.filter_chain.hcm;
    const RouterFilter& router = hcm.router;
    const VirtualHost& virtual_host = hcm.route_config.virtual_host;
    const Route& route = virtual_host.route;
    const RouteAction& action = route.action;

    if (model.listener.address.port == 0u)
        return invalid(model.listener.address.span, lit_str("listener port must be non-zero"));
    if (model.cluster.endpoint.address.port == 0u)
        return invalid(model.cluster.endpoint.address.span,
                       lit_str("endpoint port must be non-zero"));
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
    // PR #692 round-10 review: revalidate `cluster.connect_timeout` too — the
    // parser requires it strictly positive (`parse_duration(...,
    // allow_zero=false)`, src/envoy/parser.cc:674, same "duration must be
    // positive" diagnostic reused here) because Envoy itself rejects a zero
    // `connect_timeout`, but the emitted RUT program never reads this field.
    // A hand-built `Bootstrap` passed to the public `lower_to_rut(model,
    // capabilities)` overload that sets `connect_timeout.milliseconds` to
    // zero (or a caller who mutates it on a parsed copy) would otherwise
    // still lower successfully, returning a working gateway for a bootstrap
    // Envoy would reject at startup.
    if (model.cluster.connect_timeout.milliseconds == 0u)
        return invalid(model.cluster.connect_timeout.span, lit_str("duration must be positive"));
    // PR #692 round-9 review: `Str::eq` treats two empty views as equal, so
    // a caller of the public `lower_to_rut(model, capabilities)` overload
    // who clears both `action.cluster` and `model.cluster.name` on a parsed
    // copy (or hand-builds a `Bootstrap` that never sets either) passes this
    // check and reaches the hard-coded `envoy_cluster_0` upstream below. The
    // parser requires both names non-empty (`min_len: 1` on both the v3
    // `Cluster.name` and the route action's `cluster`), so an empty/empty
    // pairing is a forgery this converter must also reject.
    if (action.cluster.empty() || model.cluster.name.empty() ||
        !action.cluster.eq(model.cluster.name))
        return invalid(action.cluster_span,
                       lit_str("route cluster does not name a declared cluster"));
    // PR #692 round-12 review: revalidate the bounded length too, not just
    // non-emptiness/equality. `name_string` (src/envoy/parser.cc:179-185)
    // rejects every name over `kMaxEnvoyNameLen` during parsing, but nothing
    // above re-checks that bound; a caller of the public `lower_to_rut(model,
    // capabilities)` overload who sets both `action.cluster` and
    // `model.cluster.name` to the same overlong string still passes the
    // equality check above and would otherwise lower successfully, accepting
    // a model `parse_bootstrap_json` would reject.
    if (action.cluster.len > kMaxEnvoyNameLen)
        return unsupported(action.cluster_span, lit_str("name exceeds the bounded length"));
    if (model.cluster.name.len > kMaxEnvoyNameLen)
        return unsupported(model.cluster.name_span, lit_str("name exceeds the bounded length"));
    // PR #692 round-8 review: `load_assignment_name_present` is the model's
    // only record that `parse_bootstrap_json` ever saw and validated
    // `load_assignment.cluster_name` (required, non-empty, and equal to
    // `cluster.name` per Envoy's v3 `ClusterLoadAssignment.cluster_name`
    // `min_len: 1`) — the same evidence-bit shape as `hcm.type_url_span`
    // (round-5) and `hcm.generate_request_id_span` (round-6). A hand-built
    // `Bootstrap` passed to the public `lower_to_rut(model, capabilities)`
    // overload that never populated `load_assignment` (or a caller who
    // cleared the bit on a parsed copy) still has a matching `action.cluster`
    // / `cluster.name` pair and would otherwise lower successfully, emitting
    // a working gateway for a bootstrap Envoy would reject at startup.
    if (!model.cluster.load_assignment_name_present)
        return invalid(model.cluster.span,
                       lit_str("cluster load_assignment.cluster_name is required"));
    // PR #692 round-12 review: presence of the bit is not proof that the
    // *current* `cluster.name`/`action.cluster` still match what
    // `parse_bootstrap_json` validated `load_assignment.cluster_name`
    // against — a caller of the public `lower_to_rut(model, capabilities)`
    // overload can rename both `action.cluster` and `model.cluster.name` on
    // a parsed copy (to the same new string, so the equality check above
    // still passes) while leaving `load_assignment_name_present` true and
    // `load_assignment_name` holding the old, now-stale name. Retaining the
    // parsed value (`Cluster::load_assignment_name`,
    // include/rut/envoy/parser.h) lets this revalidate the equality at
    // lowering time instead of trusting historical presence.
    if (!model.cluster.load_assignment_name.eq(model.cluster.name))
        return invalid(model.cluster.load_assignment_name_span,
                       lit_str("load_assignment.cluster_name must equal the cluster name"));
    // PR #692 round-3 review: the emitted route is always the literal `"/"`
    // catch-all (see put_forward_route below) — nothing about the route's
    // actual `match.prefix` value ever reaches the generated text. A model
    // built by `parse_bootstrap_json` always has `match.prefix.eq("/")`
    // already (the parser rejects every other prefix), but a caller of the
    // public `lower_to_rut(model, capabilities)` overload can copy a parsed
    // `Bootstrap` and mutate `match.prefix` (e.g. to "/admin") before passing
    // it back in; without this check, lowering still succeeds and silently
    // widens what the emitted RUT actually matches relative to what the
    // model claims. Reject any forged prefix here, alongside the other
    // defensive model checks above.
    // PR #692 round-10 review: revalidate `virtual_host.name` too — the
    // parser requires it non-empty (`parse_virtual_host`, "virtual host name
    // must be a non-empty string", src/envoy/parser.cc:562-563), but the
    // emitted RUT program never reads this field. A hand-built `Bootstrap`
    // that clears `virtual_host.name` on a parsed copy (or never sets it)
    // would otherwise still lower successfully, silently accepting a model
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
    // PR #692 round-9 review: validation never checked that parsing
    // established `domains: ["*"]` on the virtual host — only the nested
    // route's `match.prefix` (round-3, immediately below). A hand-built
    // `Bootstrap`, or a parsed copy with `virtual_host.domains_span`
    // cleared, still lowers even though the generated route has no host
    // dimension and therefore matches every authority, which widens routing
    // beyond what the model claims. `domains_span` is the model's only
    // record that `parse_virtual_host` ever saw and accepted the exact
    // single-element `["*"]` array (the parser rejects every other
    // `domains` value), the same evidence-bit shape as `hcm.type_url_span`
    // and `hcm.generate_request_id_span` above.
    if (virtual_host.domains_span.start == 0u && virtual_host.domains_span.end == 0u)
        return invalid(virtual_host.span, lit_str("virtual host domains must be [\"*\"]"));
    if (!route.match.prefix.eq(lit_str("/")))
        return invalid(route.match.prefix_span, lit_str("route match prefix must be \"/\""));
    // PR #692 round-4 review: revalidate the router filter's identity here
    // too, not just `suppress_envoy_headers` on it — a forged `router.name`
    // or a cleared `has_typed_config` would otherwise still lower
    // successfully and silently omit whatever filter the model actually
    // named (e.g. a Lua filter's behavior), the same class of gap the
    // `route.match.prefix` check above closes for the route.
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
    if (!caps.request_envoy_h1)
        return unsupported(
            action.cluster_span,
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

    RutSource output{};
    Writer writer(output);
    auto fail_overflow = [&]() -> FrontendResult<RutSource> {
        return out_of_memory(model.span, lit_str("generated RUT source is too large"));
    };

    const SocketAddress& listen = model.listener.address;
    const SocketAddress& upstream = model.cluster.endpoint.address;

    if (!writer.put_cstr("listen ")) return fail_overflow();
    if (listen.ipv4_host == 0u) {
        if (!writer.put_cstr(":")) return fail_overflow();
    } else if (!writer.put_ipv4_host(listen.ipv4_host) || !writer.put_cstr(":")) {
        return fail_overflow();
    }
    if (!writer.put_u16(listen.port) || !writer.put_cstr("\n")) return fail_overflow();

    if (!writer.put_cstr("upstream envoy_cluster_0 at \"") ||
        !writer.put_ipv4_host(upstream.ipv4_host) || !writer.put_cstr(":") ||
        !writer.put_u16(upstream.port) || !writer.put_cstr("\"\n"))
        return fail_overflow();

    if (!put_unmatched(writer)) return fail_overflow();
    if (!put_forward_route(writer, "HEAD", 4u, /*include_head_mode=*/true)) return fail_overflow();
    if (!put_forward_route(writer, "", 0u, /*include_head_mode=*/false)) return fail_overflow();

    return output;
}

FrontendResult<RutSource> lower_to_rut(const Bootstrap& model) {
    return lower_to_rut(model, kShippedRutCapabilities);
}

bool needs_h2c_preface_warning(const Bootstrap& model) {
    return model.listener.filter_chain.hcm.codec_type == CodecType::Http1;
}

}  // namespace rut::envoy
