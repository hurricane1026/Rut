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
// path, optionally followed by one literal `?` and a possibly empty static query.
// `uri` and `uri_span` below retain the complete configured replacement target,
// including that delimiter and query. This limit intentionally matches the ordinary RUT
// forward-target transform capacity; wider nginx URI and normalization semantics
// remain unsupported.
static constexpr u32 kMaxProxyPassUriLen = 128;

// Validate the current lowering grammar for the complete bounded replacement
// URI retained by ProxyPass. The parser additionally models exact `/?`; the
// converter privately admits only its proven exact-loopback `/api/` composition
// after complete provenance and listener validation. Callers must provide a
// readable view; converter callers establish source provenance before invoking
// it.
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

// The first bounded access-log compatibility slice accepts one clean absolute
// path token. This is a syntax/semantic destination classification only: the
// parser does not inspect or claim the type of the eventual filesystem node.
static constexpr u32 kMaxAccessLogPathLen = 255;

enum class LogFormatProfile : u8 {
    None,
    RequestLengthOnly,
};

struct LogFormat {
    LogFormatProfile profile = LogFormatProfile::None;
    Str name{};
    Span name_span{};
    // `value` is the exact inner value while `token_span` includes quotes.
    Str value{};
    Span value_span{};
    Span token_span{};
    Span span{};
};

enum class AccessLogDestinationProfile : u8 {
    None,
    FilePath,
};

struct AccessLog {
    AccessLogDestinationProfile destination_profile = AccessLogDestinationProfile::None;
    Str path{};
    Span path_span{};
    Str format_name{};
    Span format_name_span{};
    Span span{};
};

// One deliberately bounded `http` profile. All Str fields, including `source`,
// borrow the caller-owned input. Child spans are absolute within that complete
// source; later lowering must independently revalidate any externally forged
// model before reading those borrows.
struct HttpProfile {
    Str source{};
    Span span{};
    LogFormat log_format{};
    AccessLog access_log{};
    Server server{};
};

// Parse exactly one minimal nginx server fragment. The returned model borrows
// strings from source; the caller owns the source storage for its lifetime.
FrontendResult<Server> parse(Str source);

// Parse only the explicitly bounded request-length http profile documented by
// HttpProfile. This is not a general nginx.conf grammar.
FrontendResult<HttpProfile> parse_http_profile(Str source);

}  // namespace rut::nginx
