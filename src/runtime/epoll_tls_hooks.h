#pragma once

#include "rut/common/types.h"
#include "rut/runtime/tls.h"

#include <openssl/types.h>

namespace rut {

// Runtime-private seam for forcing specific TLS state-machine transitions in
// epoll tests. Production code always uses the default OpenSSL hooks.
struct EpollTlsHooks {
    i32 (*ssl_accept)(SSL* ssl);
    i32 (*ssl_read)(SSL* ssl, void* buf, i32 len);
    i32 (*ssl_write)(SSL* ssl, const void* buf, i32 len);
    i32 (*ssl_get_error)(SSL* ssl, i32 rc);
    // Negotiated ALPN protocol after handshake. May be null in test hook
    // tables that predate ALPN; callers must null-check and default to Http11.
    AlpnProtocol (*alpn_negotiated)(SSL* ssl);
    bool (*capture_client_fingerprint)(SSL* ssl, char fingerprint[64], bool& valid);
    i32 (*ssl_shutdown)(SSL* ssl) = nullptr;
};

}  // namespace rut
