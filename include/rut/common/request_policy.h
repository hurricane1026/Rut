#pragma once

#include "rut/common/types.h"

namespace rut {

// The first explicit upstream request policy. Zero means transparent forwarding;
// the non-zero values are immutable source-level policy ids carried by the RIR
// forward terminator and interpreted by the runtime before an upstream connect.
enum class RequestPolicyId : u16 {
    None = 0,
    Http11FixedStrip = 1,
    Http11FixedStripContentLengthAfterHost = 2,
    Http11FixedTrimSpPreserveHtab = 3,
    // Envoy-compatible H1 profile: preserves the client's Host header instead
    // of writing the upstream endpoint, lowercases every forwarded header
    // name, drops Envoy's fixed hop-by-hop set (Connection, Keep-Alive,
    // Proxy-Connection, Expect, Upgrade) by default. `Transfer-Encoding` is
    // not dropped: `inspect_request_policy_body` fails the whole request
    // closed (400) the moment it sees that field name, before the
    // serializer ever runs, so no request carrying it -- bodyless or not --
    // reaches the drop logic at all; this is the one fixed-list name that is
    // fail-closed rather than stripped. Separately drops every header the
    // client's Connection value nominates
    // -- except a nomination of `content-length`, `host`, `x-forwarded-for`,
    // `x-forwarded-host`, `x-forwarded-proto`, or a pseudo-header-shaped
    // token (first byte `:`), each of which fails the whole request closed
    // instead of being dropped, and except a nomination of `te`, which is
    // not dropped at all and does not affect persistence -- its sibling `TE`
    // field is evaluated the same as always (see below) and forwarded as
    // `te: trailers` when warranted. Keeps a `te` field only when one of its
    // comma-separated tokens is "trailers" (any casing; `TE: gzip, trailers`
    // is kept, `TE: gzip` is dropped) and rewrites the kept field to exactly
    // `te: trailers` -- never the whole client value -- emitted at the first
    // physical `TE` field's position, with several such fields collapsing to
    // one line. A single client-supplied `x-forwarded-proto` field whose
    // trimmed value is case-insensitively exactly `http`/`https` is
    // preserved unchanged in its original position; an empty, OWS-only, or
    // otherwise invalid value is overwritten in place at that same position
    // with `http`; a trailing `x-forwarded-proto: http` is appended only
    // when the client sent no such field at all. Rejects a second physical
    // occurrence of any header name Envoy stores as a single inline slot
    // (every name in `kInlineRequestHeaders`,
    // `include/rut/runtime/callbacks_impl.h` -- includes, among others,
    // `Content-Type`, `User-Agent`, `Authorization`, `Referer`, and every
    // `X-Forwarded-*`/`X-Envoy-*` name this profile does not already
    // unconditionally strip) with a 400 before upstream contact, unless the
    // client's `Connection` value also nominates that name, in which case
    // every physical occurrence is dropped instead and no duplicate ever
    // reaches the wire; this profile does not replicate Envoy's own
    // duplicate-coalescing for these names, so a client sending two such
    // fields diverges from Envoy's forwarding behavior and is fail-closed
    // rather than silently accepted. Targets Envoy's cleartext (non-TLS)
    // listener profile only: the connection-derived `x-forwarded-proto`
    // fallback above is hardcoded to `http`, so this policy is rejected
    // outright (fail closed, no upstream contact, same status as every
    // other unsupported combination) on a connection this runtime itself
    // terminated with TLS (`conn.tls_active`) -- it never synthesizes
    // `https` instead. Ordinary-forward-only: never admitted alongside a
    // response read deadline or response buffering (see the closed
    // admission predicates below).
    Http11PreserveHostLowercase = 4,
    // Reserved in the 16-bit forward-result slot for invalid direct-RIR values.
    Invalid = 0xffffu,
};

inline bool request_policy_is_supported(u16 id) {
    return id == static_cast<u16>(RequestPolicyId::Http11FixedStrip) ||
           id == static_cast<u16>(RequestPolicyId::Http11FixedStripContentLengthAfterHost) ||
           id == static_cast<u16>(RequestPolicyId::Http11FixedTrimSpPreserveHtab) ||
           id == static_cast<u16>(RequestPolicyId::Http11PreserveHostLowercase);
}

inline bool request_policy_trims_sp_preserves_htab(u16 id) {
    return id == static_cast<u16>(RequestPolicyId::Http11FixedTrimSpPreserveHtab);
}

// ID4 preserves the client's Host header verbatim instead of writing the
// upstream endpoint authority. Every other supported policy writes Host.
inline bool request_policy_preserves_host(u16 id) {
    return id == static_cast<u16>(RequestPolicyId::Http11PreserveHostLowercase);
}

// ID3 is intentionally admitted only by the closed bodyless GET + complete
// response-buffering profile.  The ordinary complete-buffering predicate below
// remains unchanged so adding this policy cannot widen other routes.
inline bool bodyless_get_complete_content_length_request_policy_is_admitted(u16 id) {
    return id == static_cast<u16>(RequestPolicyId::Http11FixedStrip) ||
           id == static_cast<u16>(RequestPolicyId::Http11FixedTrimSpPreserveHtab);
}

inline bool request_policy_places_content_length_after_host(u16 id) {
    return id == static_cast<u16>(RequestPolicyId::Http11FixedStripContentLengthAfterHost);
}

// Closed admission set for every response-read-deadline profile. New request
// policies remain ordinary-forward-only until their timing custody is proven.
inline bool response_read_deadline_request_policy_is_admitted(u16 id) {
    return id == static_cast<u16>(RequestPolicyId::None) ||
           id == static_cast<u16>(RequestPolicyId::Http11FixedStrip);
}

// Closed request-policy set for the positive fixed-upload HEAD deadline
// profile.  ID2 is not admitted by the general deadline predicate above.
inline bool fixed_upload_head_request_policy_is_admitted(u16 id) {
    return id == static_cast<u16>(RequestPolicyId::Http11FixedStrip) ||
           id == static_cast<u16>(RequestPolicyId::Http11FixedStripContentLengthAfterHost);
}

// Closed admission set for the bounded complete-content-length response
// buffering profile. Keep this separate from request_policy_is_supported():
// adding a future request policy must not silently widen this profile.
inline bool complete_content_length_request_policy_is_admitted(u16 id) {
    return id == static_cast<u16>(RequestPolicyId::None) ||
           id == static_cast<u16>(RequestPolicyId::Http11FixedStrip);
}

inline const char* request_policy_version(u16 id) {
    return request_policy_is_supported(id) ? "HTTP/1.1" : nullptr;
}

}  // namespace rut
