/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

#include "rut/runtime/tls.h"

#include <mutex>

#include <errno.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <stdlib.h>

namespace rut {

namespace {

core::Expected<void, Error> tls_init_once() {
    static std::once_flag init_once;
    static bool init_ok = false;

    std::call_once(init_once, []() { init_ok = (OPENSSL_init_ssl(0, nullptr) == 1); });

    if (init_ok) return {};
    return core::make_unexpected(Error::make(EIO, Error::Source::Socket));
}

}  // namespace

core::Expected<TlsServerContext*, Error> create_tls_server_context(const char* cert_path,
                                                                   const char* key_path) {
    TRY_VOID(tls_init_once());

    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) return core::make_unexpected(Error::make(EIO, Error::Source::Socket));

    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_path) != 1) {
        SSL_CTX_free(ssl_ctx);
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ssl_ctx);
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    }
    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        SSL_CTX_free(ssl_ctx);
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    }

    auto* ctx = static_cast<TlsServerContext*>(malloc(sizeof(TlsServerContext)));
    if (!ctx) {
        SSL_CTX_free(ssl_ctx);
        return core::make_unexpected(Error::make(ENOMEM, Error::Source::Socket));
    }
    ctx->ssl_ctx = ssl_ctx;
    return ctx;
}

void destroy_tls_server_context(TlsServerContext* ctx) {
    if (!ctx) return;
    if (ctx->ssl_ctx) SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
}

core::Expected<SSL*, Error> create_tls_server_ssl(TlsServerContext* ctx, i32 fd) {
    if (!ctx || !ctx->ssl_ctx)
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));

    SSL* ssl = SSL_new(ctx->ssl_ctx);
    if (!ssl) return core::make_unexpected(Error::make(EIO, Error::Source::Socket));

    BIO* bio = BIO_new_socket(fd, BIO_NOCLOSE);
    if (!bio) {
        SSL_free(ssl);
        return core::make_unexpected(Error::make(EIO, Error::Source::Socket));
    }
    SSL_set_bio(ssl, bio, bio);
    SSL_set_accept_state(ssl);
    SSL_set_mode(ssl,
                 SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
                     SSL_MODE_RELEASE_BUFFERS);
    return ssl;
}

void destroy_tls_server_ssl(SSL* ssl) {
    if (ssl) SSL_free(ssl);
}

}  // namespace rut
