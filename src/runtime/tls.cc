#include "rut/runtime/tls.h"

#include "core/expected.h"
#include "rut/common/upstream_tls.h"
#include "rut/platform/socket.h"
#include "tls_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>

namespace rut {

namespace {

// The standard socket BIO writes with write(2), which raises SIGPIPE when the
// peer has already closed. This BIO sends with platform::kSendFlags
// (MSG_NOSIGNAL; macOS sockets set SO_NOSIGPIPE instead), so a disconnect
// surfaces as EPIPE on its own connection. It never owns the descriptor.
int nosigpipe_socket_fd(BIO* bio) {
    return static_cast<int>(reinterpret_cast<intptr_t>(BIO_get_data(bio)));
}

bool nosigpipe_socket_should_retry() {
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
}

int nosigpipe_socket_write(BIO* bio, const char* in, int len) {
    BIO_clear_retry_flags(bio);
    if (len <= 0) return 0;
    const ssize_t n =
        ::send(nosigpipe_socket_fd(bio), in, static_cast<size_t>(len), platform::kSendFlags);
    if (n < 0 && nosigpipe_socket_should_retry()) BIO_set_retry_write(bio);
    return static_cast<int>(n);
}

int nosigpipe_socket_read(BIO* bio, char* out, int len) {
    BIO_clear_retry_flags(bio);
    if (len <= 0) return 0;
    const ssize_t n = ::recv(nosigpipe_socket_fd(bio), out, static_cast<size_t>(len), 0);
    if (n < 0 && nosigpipe_socket_should_retry()) BIO_set_retry_read(bio);
    if (n == 0) BIO_set_flags(bio, BIO_FLAGS_IN_EOF);
    return static_cast<int>(n);
}

long nosigpipe_socket_ctrl(BIO* bio, int cmd, long /*num*/, void* /*ptr*/) {
    // OpenSSL distinguishes a transport EOF from other BIO failures through
    // this control operation. A missing close_notify must remain a TLS error.
    if (cmd == BIO_CTRL_EOF) return BIO_test_flags(bio, BIO_FLAGS_IN_EOF) != 0;
    return cmd == BIO_CTRL_FLUSH ? 1 : 0;
}

BIO_METHOD* make_nosigpipe_socket_method() {
    BIO_METHOD* m = BIO_meth_new(BIO_TYPE_SOCKET, "rut socket (no SIGPIPE)");
    if (m == nullptr) return nullptr;
    if (!BIO_meth_set_write(m, nosigpipe_socket_write) ||
        !BIO_meth_set_read(m, nosigpipe_socket_read) ||
        !BIO_meth_set_ctrl(m, nosigpipe_socket_ctrl)) {
        BIO_meth_free(m);
        return nullptr;
    }
    return m;
}

BIO* new_nosigpipe_socket_bio(BIO_METHOD* method, i32 fd) {
    if (method == nullptr || fd < 0) return nullptr;
    BIO* bio = BIO_new(method);
    if (bio == nullptr) return nullptr;
    // The descriptor lives in BIO's opaque data pointer; it is never dereferenced.
    BIO_set_data(bio,
                 reinterpret_cast<void*>(  // NOLINT(performance-no-int-to-ptr)
                     static_cast<intptr_t>(fd)));
    BIO_set_init(bio, 1);
    return bio;
}

// Configuration has no passphrase source. Reject encrypted private keys rather
// than invoking OpenSSL's interactive default password prompt on a shard.
int no_client_key_password(char*, int, int, void*) {
    return 0;
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
    if (OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr) != 1)
        return core::make_unexpected(Error::make(EIO, Error::Source::Socket));

    BIO_METHOD* socket_bio_method = make_nosigpipe_socket_method();
    if (socket_bio_method == nullptr)
        return core::make_unexpected(Error::make(EIO, Error::Source::Socket));
    BIO_METHOD* bridge_bio_method = make_tls_engine_bridge_method();
    if (bridge_bio_method == nullptr) {
        BIO_meth_free(socket_bio_method);
        return core::make_unexpected(Error::make(EIO, Error::Source::Socket));
    }

    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        BIO_meth_free(bridge_bio_method);
        BIO_meth_free(socket_bio_method);
        return core::make_unexpected(Error::make(EIO, Error::Source::Socket));
    }

    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_path) != 1) {
        SSL_CTX_free(ssl_ctx);
        BIO_meth_free(bridge_bio_method);
        BIO_meth_free(socket_bio_method);
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ssl_ctx);
        BIO_meth_free(bridge_bio_method);
        BIO_meth_free(socket_bio_method);
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    }
    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        SSL_CTX_free(ssl_ctx);
        BIO_meth_free(bridge_bio_method);
        BIO_meth_free(socket_bio_method);
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    }

    auto* ctx = static_cast<TlsServerContext*>(malloc(sizeof(TlsServerContext)));
    if (!ctx) {
        SSL_CTX_free(ssl_ctx);
        BIO_meth_free(bridge_bio_method);
        BIO_meth_free(socket_bio_method);
        return core::make_unexpected(Error::make(ENOMEM, Error::Source::Socket));
    }
    ctx->ssl_ctx = ssl_ctx;
    ctx->socket_bio_method = socket_bio_method;
    ctx->bridge_bio_method = bridge_bio_method;
    ctx->offer_h2 = offer_h2;
    // Register ALPN negotiation. arg = ctx so the callback can read offer_h2.
    // ctx outlives ssl_ctx (freed together in destroy_tls_server_context).
    SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_cb, ctx);
    return ctx;
}

void destroy_tls_server_context(TlsServerContext* ctx) {
    if (!ctx) return;
    if (ctx->ssl_ctx) SSL_CTX_free(ctx->ssl_ctx);
    if (ctx->bridge_bio_method) BIO_meth_free(ctx->bridge_bio_method);
    if (ctx->socket_bio_method) BIO_meth_free(ctx->socket_bio_method);
    free(ctx);
}

core::Expected<SSL*, Error> create_tls_server_ssl(TlsServerContext* ctx, i32 fd) {
    if (!ctx || !ctx->ssl_ctx)
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    SSL* ssl = SSL_new(ctx->ssl_ctx);
    if (!ssl) return core::make_unexpected(Error::make(EIO, Error::Source::Socket));

    BIO* bio = new_nosigpipe_socket_bio(ctx->socket_bio_method, fd);
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

void destroy_tls_client_context(TlsClientContext& ctx) {
    if (ctx.ssl_ctx) SSL_CTX_free(ctx.ssl_ctx);
    if (ctx.bridge_bio_method) BIO_meth_free(ctx.bridge_bio_method);
    if (ctx.socket_bio_method) BIO_meth_free(ctx.socket_bio_method);
    ctx = {};
}

core::Expected<void, Error> init_tls_client_context(TlsClientContext& ctx,
                                                    const UpstreamTlsSpec& spec) {
    if (ctx.ssl_ctx || !spec.enabled || !valid_upstream_tls(spec))
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    if (OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr) != 1)
        return core::make_unexpected(Error::make(EIO, Error::Source::Socket));
    ctx.ssl_ctx = SSL_CTX_new(TLS_client_method());
    ctx.socket_bio_method = make_nosigpipe_socket_method();
    ctx.bridge_bio_method = make_tls_engine_bridge_method();
    if (!ctx.ssl_ctx || !ctx.socket_bio_method || !ctx.bridge_bio_method) {
        destroy_tls_client_context(ctx);
        return core::make_unexpected(Error::make(ENOMEM, Error::Source::Socket));
    }
    SSL_CTX_set_verify(ctx.ssl_ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_default_passwd_cb(ctx.ssl_ctx, no_client_key_password);
    if (SSL_CTX_set_min_proto_version(ctx.ssl_ctx, TLS1_2_VERSION) != 1 ||
        SSL_CTX_load_verify_locations(ctx.ssl_ctx, spec.ca, nullptr) != 1 ||
        (spec.cert[0] &&
         (SSL_CTX_use_certificate_chain_file(ctx.ssl_ctx, spec.cert) != 1 ||
          SSL_CTX_use_PrivateKey_file(ctx.ssl_ctx, spec.key, SSL_FILETYPE_PEM) != 1 ||
          SSL_CTX_check_private_key(ctx.ssl_ctx) != 1))) {
        destroy_tls_client_context(ctx);
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    }
    return {};
}

bool configure_tls_client_ssl(SSL* ssl, const char* server_name) {
    if (!ssl || !server_name || !server_name[0]) return false;
    in_addr address{};
    const bool kIsIp = inet_pton(AF_INET, server_name, &address) == 1;
    if (kIsIp) {
        if (X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), server_name) != 1) return false;
    } else if (SSL_set1_host(ssl, server_name) != 1 ||
               SSL_set_tlsext_host_name(ssl, server_name) != 1) {
        return false;
    }
    SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    SSL_set_connect_state(ssl);
    SSL_set_mode(ssl,
                 SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
                     SSL_MODE_RELEASE_BUFFERS);
    return SSL_set_alpn_protos(ssl, kAlpnH2, sizeof(kAlpnH2)) == 0;
}

core::Expected<SSL*, Error> create_tls_client_ssl(TlsClientContext& ctx,
                                                  i32 fd,
                                                  const char* server_name) {
    SSL* ssl = ctx.ssl_ctx ? SSL_new(ctx.ssl_ctx) : nullptr;
    if (!ssl) return core::make_unexpected(Error::make(EIO, Error::Source::Socket));
    BIO* bio = new_nosigpipe_socket_bio(ctx.socket_bio_method, fd);
    if (!bio) {
        SSL_free(ssl);
        return core::make_unexpected(Error::make(EIO, Error::Source::Socket));
    }
    SSL_set_bio(ssl, bio, bio);
    if (!configure_tls_client_ssl(ssl, server_name)) {
        SSL_free(ssl);
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    }
    return ssl;
}

bool tls_handshake_finished(SSL* ssl) {
    return ssl && SSL_is_init_finished(ssl);
}

bool tls_client_peer_valid(SSL* ssl) {
    return ssl && SSL_is_init_finished(ssl) && SSL_get_verify_result(ssl) == X509_V_OK &&
           tls_negotiated_protocol(ssl) == AlpnProtocol::H2;
}

}  // namespace rut
