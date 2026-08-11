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
    static constexpr u32 kMaxSniIdentities = 16;
    static constexpr u32 kMaxServerNameLen = 253;

    struct SniIdentity {
        SSL_CTX* ssl_ctx = nullptr;
        char server_name[kMaxServerNameLen + 1]{};
        u32 server_name_len = 0;
    };

    SSL_CTX* ssl_ctx;
    // Whether the ALPN select callback advertises "h2". When false the server
    // only ever selects "http/1.1", so an h2-capable client downgrades.
    bool offer_h2;
    SniIdentity sni_identities[kMaxSniIdentities];
    u32 sni_identity_count;
};

struct TlsClientContext {
    SSL_CTX* ssl_ctx;
};

// offer_h2 advertises HTTP/2 over ALPN; false limits TLS negotiation to HTTP/1.1.
core::Expected<TlsServerContext*, Error> create_tls_server_context(
    const char* cert_path,
    const char* key_path,
    bool offer_h2 = false,
    const char* client_ca_file = nullptr);
core::Expected<void, Error> add_tls_server_sni_identity(TlsServerContext* ctx,
                                                        const char* server_name,
                                                        const char* cert_path,
                                                        const char* key_path,
                                                        const char* client_ca_file = nullptr);
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

// Verified upstream TLS. A null ca_file uses the platform trust store. The
// client certificate and key are optional, but must be supplied together when
// the upstream requires mutual TLS.
core::Expected<TlsClientContext*, Error> create_tls_client_context(const char* ca_file = nullptr,
                                                                   const char* cert_path = nullptr,
                                                                   const char* key_path = nullptr);
void destroy_tls_client_context(TlsClientContext* ctx);
core::Expected<SSL*, Error> create_tls_client_ssl(TlsClientContext* ctx,
                                                  i32 fd,
                                                  const char* server_name);
void destroy_tls_client_ssl(SSL* ssl);

}  // namespace rut
