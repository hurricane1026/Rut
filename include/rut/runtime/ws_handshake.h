#pragma once

#include "rut/common/http_header_validation.h"
#include "rut/common/types.h"
#include "rut/runtime/http_parser.h"
#include "rut/runtime/ws_extensions.h"

namespace rut {

enum class WsHandshakeRequestResult : u8 { Ready, BadRequest, VersionRequired, InternalError };

inline constexpr u32 kWsHandshakeAcceptLength = 28;

// RFC 6455 subprotocol identifiers are nonempty, case-sensitive HTTP tokens.
inline bool ws_valid_subprotocol(Str value) {
    if (value.ptr == nullptr || value.len == 0) return false;
    for (u32 i = 0; i < value.len; i++)
        if (!is_http_tchar(static_cast<u8>(value.ptr[i]))) return false;
    return true;
}

// Validate the bounded HTTP/1.1 opening request and write its expected Accept
// plus canonical offered-protocol list into caller-owned SlicePool storage.
// Request bytes are borrowed only for this synchronous call.
WsHandshakeRequestResult ws_prepare_handshake(const u8* request,
                                              u32 header_len,
                                              u8* storage,
                                              u32 storage_capacity,
                                              u32* out_offers_len,
                                              Str required_subprotocol = {},
                                              WsDeflateAgreement* downstream_deflate = nullptr);

bool ws_handshake_response_matches(const ParsedResponse& response,
                                   const u8* storage,
                                   u32 offers_len,
                                   Str required_subprotocol = {},
                                   WsDeflateAgreement* upstream_deflate = nullptr,
                                   bool opaque_extensions = false);

// Translate a validated Extended CONNECT request to a fresh HTTP/1.1 Upgrade.
// The generated Key and expected Accept are owned by the gateway, not the client.
u32 ws_build_h1_handshake(const ParsedRequest& request,
                          u8* output,
                          u32 capacity,
                          u8* storage,
                          u32 storage_capacity,
                          u32* offers_len);

// RFC 8441 uses :protocol rather than Key/Accept. Storage has the same owned
// canonical protocol-list layout as the HTTP/1 handshake (Accept bytes unused).
WsHandshakeRequestResult ws_prepare_h2_handshake(const ParsedRequest& request,
                                                 u8* storage,
                                                 u32 capacity,
                                                 u32* offers_len);
bool ws_h2_response_matches(const Header* headers, u32 count, const u8* storage, u32 offers_len);

// Restrict validated request protocol fields to one required offer, without growing
// the header or touching the coalesced WebSocket bytes. Returns the new header length.
// The input must already have passed ws_prepare_handshake with this policy.
u32 ws_restrict_subprotocol(u8* request, u32 header_len, u32 total_len, Str required_subprotocol);

}  // namespace rut
