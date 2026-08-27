#pragma once

#include "rut/common/listener_address.h"
#include "rut/common/types.h"
#include "rut/compiler/diagnostic.h"

namespace rut::nginx {

struct Listen {
    u16 port = 0;
    Span span{};
    // Address and port are normalized semantic startup metadata. `value`
    // borrows the complete endpoint token from the nginx source and
    // `value_span` pins that token's provenance.
    ListenerAddress address = ListenerAddress::IPv4Wildcard;
    u32 ipv4_host = 0;
    Str value{};
    Span value_span{};
};

// The bounded proxy replacement-URI slice accepts an absolute clean replacement
// path, optionally followed by one literal `?` and a non-empty static query.
// `uri` and `uri_span` below retain the complete configured replacement target,
// including that query. This limit intentionally matches the ordinary RUT
// forward-target transform capacity; wider nginx URI and normalization semantics
// remain unsupported.
static constexpr u32 kMaxProxyPassUriLen = 128;

// Validate the complete bounded replacement URI retained by ProxyPass. This is
// the parser/model grammar shared with converter validation so accepted models
// cannot drift between parsing and lowering. Callers must provide a readable
// view; converter callers establish source provenance before invoking it.
bool proxy_pass_replacement_uri_is_clean(Str uri);

struct ProxyPass {
    u8 address[4]{};
    u16 port = 0;
    bool has_uri = false;
    Str uri{};
    Span uri_span{};
    Span span{};
};

struct ProxyReadTimeout {
    bool present = false;
    u32 milliseconds = 0;
    Span span{};
    Span value_span{};
};

// A proxy location prefix must fit completely in the runtime request-path
// observation buffer, including its trailing slash. The runtime reserves one
// byte for termination, so the semantic model admits at most 63 source bytes.
// Broader nginx location-selection and normalization semantics remain
// unsupported.
static constexpr u32 kMaxProxyLocationPathLen = 63;

// Existing bounded prefix-location proxy action. This remains separate from
// the exact local-return action below so source order cannot change their
// semantic roles.
struct Location {
    Str path{};
    Span path_span{};
    Span span{};
    ProxyPass proxy_pass{};
    ProxyReadTimeout proxy_read_timeout{};
};

// This bounded local-response slice borrows one non-empty raw quoted body of at
// most 64 bytes from source. It accepts safe printable ASCII bytes plus any
// number of internal ASCII spaces between non-space endpoints; escapes,
// variables, controls, and broader nginx quoted-string semantics remain outside
// the model.
static constexpr u32 kMaxLocalReturnBodyLen = 64;

struct LocalReturn {
    u16 status = 0;
    Str body{};
    Span body_span{};
    Span span{};
};

// Exact local-return paths use the ordinary RUT exact-selector capacity.  This
// parser slice is deliberately narrower than the runtime byte grammar: only
// clean absolute ASCII-unreserved paths are admitted, and exact `/` remains
// outside the proven nginx-compatibility profile.
static constexpr u32 kMaxExactLocalReturnPathLen = 62;

struct ExactLocalReturnLocation {
    bool present = false;
    Str path{};
    Span path_span{};
    Span span{};
    LocalReturn response{};
};

// A distinct bounded nginx semantic action for literal `return 204;`.  It is
// intentionally not represented as an empty-body LocalReturn: ordinary RUT
// status-only responses have different observable framing.  The accepted
// location uses the bounded clean exact-path profile above; lowering decides
// which modeled paths it can faithfully emit as the public strict no-content
// policy.
struct NoContentReturn {
    u16 status = 0;
    Span status_span{};
    Span span{};
};

struct ExactNoContentReturnLocation {
    bool present = false;
    Str path{};
    Span path_span{};
    Span span{};
    NoContentReturn response{};
};

// A distinct semantic action for the bounded literal 301/302 absolute redirect
// slice.
// The status lexeme, complete target, and its authority/path decomposition
// borrow directly from the nginx source so later lowering never needs to
// reinterpret source text.
struct AbsoluteRedirect {
    u16 status = 0;
    Str status_lexeme{};
    Span status_span{};
    Str target{};
    Span target_span{};
    Str authority{};
    Span authority_span{};
    Str path{};
    Span path_span{};
    Span span{};
};

struct ExactAbsoluteRedirectLocation {
    bool present = false;
    Str path{};
    Span path_span{};
    Span span{};
    AbsoluteRedirect response{};
};

// Closed canonical profiles for implicit nginx behavior that precedes route
// selection.  This is semantic-model metadata, not an nginx directive or a
// runtime mode; the converter owns every emitted policy byte for each profile.
enum class ImplicitPreRouteProfile : u8 {
    None,
    Nginx1297PreLocationTrace405,
};

// nginx rejects TRACE during request processing, before location selection, in
// every accepted bounded root-proxy fragment. `span` is the complete semantic
// server span whose accepted shape establishes that fact; using one server-
// level provenance convention keeps root-only and exact-root models identical.
struct ImplicitPreRouteTrace {
    ImplicitPreRouteProfile profile = ImplicitPreRouteProfile::None;
    Span span{};
};

struct Server {
    Span span{};
    Listen listen{};
    // `location` is always the proxy fallback, independent of declaration
    // order. At most one exact selector/action is populated by the parser.
    Location location{};
    ExactLocalReturnLocation exact_local_return{};
    ExactNoContentReturnLocation exact_no_content_return{};
    ExactAbsoluteRedirectLocation exact_absolute_redirect{};
    ImplicitPreRouteTrace pre_route_trace{};
};

// Parse exactly one minimal nginx server fragment. The returned model borrows
// strings from source; the caller owns the source storage for its lifetime.
FrontendResult<Server> parse(Str source);

}  // namespace rut::nginx
