#pragma once

#include "rut/common/types.h"
#include "rut/runtime/http_parser.h"

namespace rut {

enum class WsHandshakeRequestResult : u8 { Ready, BadRequest, VersionRequired, InternalError };

inline constexpr u32 kWsHandshakeAcceptLength = 28;

// Validate the bounded HTTP/1.1 opening request and write its expected Accept
// plus canonical offered-protocol list into caller-owned SlicePool storage.
// Request bytes are borrowed only for this synchronous call.
WsHandshakeRequestResult ws_prepare_handshake(
    const u8* request, u32 header_len, u8* storage, u32 storage_capacity, u32* out_offers_len);

bool ws_handshake_response_matches(const ParsedResponse& response,
                                   const u8* storage,
                                   u32 offers_len);

}  // namespace rut
