#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/error.h"

#include <openssl/base.h>

namespace rut {

// Application-Layer Protocol Negotiation result. None = the client sent no
// ALPN extension or offered nothing we support; callers treat None as HTTP/1.1.
enum class AlpnProtocol : u8 {
    None,
    Http11,
    H2,
};

struct TlsServerContext {
    SSL_CTX* ssl_ctx;
    // Whether the ALPN select callback advertises "h2". When false the server
    // only ever selects "http/1.1", so an h2-capable client downgrades.
    bool offer_h2;
};

// offer_h2: advertise HTTP/2 over ALPN. Leave false until the HTTP/2 data
// path is wired, otherwise an h2 client would be handed to the HTTP/1 parser.
core::Expected<TlsServerContext*, Error> create_tls_server_context(const char* cert_path,
                                                                   const char* key_path,
                                                                   bool offer_h2 = false);
void destroy_tls_server_context(TlsServerContext* ctx);
core::Expected<SSL*, Error> create_tls_server_ssl(TlsServerContext* ctx, i32 fd);
void destroy_tls_server_ssl(SSL* ssl);

// Pure ALPN selection: given the client's ALPN protocol list (wire format:
// repeated 1-byte-length-prefixed names) pick the server-preferred protocol.
// Server preference is h2 (only if offer_h2) before http/1.1. Returns None when
// nothing overlaps. Exposed for unit testing; the select callback wraps it.
AlpnProtocol alpn_pick(bool offer_h2, const u8* client_protos, u32 client_len);

// Read the ALPN protocol negotiated on a completed handshake. None when the
// handshake selected no ALPN protocol (plain HTTP/1.1).
AlpnProtocol tls_negotiated_protocol(SSL* ssl);

}  // namespace rut
