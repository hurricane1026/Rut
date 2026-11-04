#pragma once

#include "rut/common/types.h"
#include "rut/runtime/http_parser.h"

namespace rut {
struct WsDeflateAgreement {
    bool enabled = false;
    bool server_no_context_takeover = false;
    bool client_no_context_takeover = false;
    bool server_window_present = false;
    bool client_window_present = false;
    u8 server_window = 15;
    u8 client_window = 15;
};

// This offer permits server context takeover and every supported window size.
// client_no_context_takeover is only a hint until echoed in the response.
inline constexpr Str kWsDeflateOffer =
    lit_str("permessage-deflate; client_no_context_takeover; client_max_window_bits");

// Parse every extension field, including comma alternatives and quoted values.
// Unknown/unsupported offers can be declined; malformed grammar fails the request.
// Output contains only owned scalar agreement facts, never request-backed views.
bool ws_select_deflate_offer(const Header* headers, u32 count, WsDeflateAgreement* agreement);
// Validate a response to kWsDeflateOffer. Unknown or duplicate selections and
// invalid parameters fail; an absent selection leaves compression disabled.
bool ws_accept_deflate_response(const Header* headers, u32 count, WsDeflateAgreement* agreement);
// Format a canonical extension VALUE (no header name or CRLF). Zero means no
// negotiated extension, invalid agreement, or insufficient destination storage.
u32 ws_format_deflate_agreement(const WsDeflateAgreement& agreement, char* output, u32 capacity);
}  // namespace rut
