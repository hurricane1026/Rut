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

// Wire-format ALPN protocol names (1-byte length prefix per RFC 7301).
constexpr u8 kAlpnH2[] = {2, 'h', '2'};
constexpr u8 kAlpnHttp11[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

// Does the client's ALPN list contain `name` (length `nlen`, no prefix)?
bool client_offers(const u8* in, u32 len, const char* name, u8 nlen) {
    u32 i = 0;
    while (i < len) {
        const u8 kEntryLen = in[i];
        if (i + 1u + kEntryLen > len) break;  // truncated entry
        if (kEntryLen == nlen && __builtin_memcmp(in + i + 1, name, nlen) == 0) return true;
        i += 1u + kEntryLen;
    }
    return false;
}

// ALPN select callback. arg points at the owning TlsServerContext so the
// callback reads its offer_h2 flag. Picks server-preferred protocol; on no
// overlap returns NOACK so the handshake proceeds without ALPN (HTTP/1.1).
int alpn_select_cb(
    SSL* /*ssl*/, const u8** out, u8* outlen, const u8* in, unsigned inlen, void* arg) {
    const auto* ctx = static_cast<const TlsServerContext*>(arg);
    const bool kOfferH2 = ctx && ctx->offer_h2;
    const AlpnProtocol kPick = alpn_pick(kOfferH2, in, inlen);
    if (kPick == AlpnProtocol::H2) {
        *out = kAlpnH2 + 1;
        *outlen = kAlpnH2[0];
        return SSL_TLSEXT_ERR_OK;
    }
    if (kPick == AlpnProtocol::Http11) {
        *out = kAlpnHttp11 + 1;
        *outlen = kAlpnHttp11[0];
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

}  // namespace

AlpnProtocol alpn_pick(bool offer_h2, const u8* client_protos, u32 client_len) {
    if (!client_protos || client_len == 0) return AlpnProtocol::None;
    if (offer_h2 && client_offers(client_protos, client_len, "h2", 2)) return AlpnProtocol::H2;
    if (client_offers(client_protos, client_len, "http/1.1", 8)) return AlpnProtocol::Http11;
    return AlpnProtocol::None;
}

AlpnProtocol tls_negotiated_protocol(SSL* ssl) {
    if (!ssl) return AlpnProtocol::None;
    const u8* proto = nullptr;
    unsigned len = 0;
    SSL_get0_alpn_selected(ssl, &proto, &len);
    if (!proto || len == 0) return AlpnProtocol::None;
    if (len == 2 && __builtin_memcmp(proto, "h2", 2) == 0) return AlpnProtocol::H2;
    if (len == 8 && __builtin_memcmp(proto, "http/1.1", 8) == 0) return AlpnProtocol::Http11;
    return AlpnProtocol::None;
}

core::Expected<TlsServerContext*, Error> create_tls_server_context(const char* cert_path,
                                                                   const char* key_path,
                                                                   bool offer_h2) {
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
    ctx->offer_h2 = offer_h2;
    // Register ALPN negotiation. arg = ctx so the callback can read offer_h2.
    // ctx outlives ssl_ctx (freed together in destroy_tls_server_context).
    SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_cb, ctx);
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

core::Expected<TlsClientContext*, Error> create_tls_client_context(const char* ca_file) {
    TRY_VOID(tls_init_once());
    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) return core::make_unexpected(Error::make(EIO, Error::Source::Socket));
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, nullptr);
    i32 loaded = 0;
    if (ca_file) {
        loaded = SSL_CTX_load_verify_locations(ssl_ctx, ca_file, nullptr);
    } else {
        // BoringSSL's default-path helper does not populate a platform trust
        // store. Load the standard Linux bundle explicitly instead.
        static constexpr const char* kSystemCaBundles[] = {
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
        };
        for (const char* path : kSystemCaBundles) {
            if (SSL_CTX_load_verify_locations(ssl_ctx, path, nullptr) == 1) {
                loaded = 1;
                break;
            }
        }
    }
    if (loaded != 1) {
        SSL_CTX_free(ssl_ctx);
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    }
    auto* ctx = static_cast<TlsClientContext*>(malloc(sizeof(TlsClientContext)));
    if (!ctx) {
        SSL_CTX_free(ssl_ctx);
        return core::make_unexpected(Error::make(ENOMEM, Error::Source::Socket));
    }
    ctx->ssl_ctx = ssl_ctx;
    return ctx;
}

void destroy_tls_client_context(TlsClientContext* ctx) {
    if (!ctx) return;
    if (ctx->ssl_ctx) SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
}

core::Expected<SSL*, Error> create_tls_client_ssl(TlsClientContext* ctx,
                                                  i32 fd,
                                                  const char* server_name) {
    if (!ctx || !ctx->ssl_ctx || fd < 0 || !server_name || server_name[0] == '\0')
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    SSL* ssl = SSL_new(ctx->ssl_ctx);
    if (!ssl) return core::make_unexpected(Error::make(EIO, Error::Source::Socket));
    BIO* bio = BIO_new_socket(fd, BIO_NOCLOSE);
    if (!bio) {
        SSL_free(ssl);
        return core::make_unexpected(Error::make(EIO, Error::Source::Socket));
    }
    SSL_set_bio(ssl, bio, bio);
    if (SSL_set_tlsext_host_name(ssl, server_name) != 1 || SSL_set1_host(ssl, server_name) != 1) {
        SSL_free(ssl);
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    }
    SSL_set_connect_state(ssl);
    SSL_set_mode(ssl,
                 SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
                     SSL_MODE_RELEASE_BUFFERS);
    return ssl;
}

void destroy_tls_client_ssl(SSL* ssl) {
    if (ssl) SSL_free(ssl);
}

}  // namespace rut
