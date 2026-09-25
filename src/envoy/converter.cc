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
    const Route& route = hcm.route_config.virtual_host.route;
    const RouteAction& action = route.action;

    if (model.listener.address.port == 0u)
        return invalid(model.listener.address.span, lit_str("listener port must be non-zero"));
    if (model.cluster.endpoint.address.port == 0u)
        return invalid(model.cluster.endpoint.address.span,
                       lit_str("endpoint port must be non-zero"));
    if (!action.cluster.eq(model.cluster.name))
        return invalid(action.cluster_span,
                       lit_str("route cluster does not name a declared cluster"));
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
    if (!route.match.prefix.eq(lit_str("/")))
        return invalid(route.match.prefix_span, lit_str("route match prefix must be \"/\""));

    if (!router.suppress_envoy_headers) {
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

}  // namespace rut::envoy
