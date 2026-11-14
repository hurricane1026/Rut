#include "rut/runtime/tls.h"

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/common/upstream_tls.h"
#include "rut/platform/socket.h"
#include "rut/runtime/error.h"
#include "tls_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/prov_ssl.h>
#include <openssl/safestack.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace rut {

namespace {

// Cold startup only: one complete direct-issuer PEM CRL, at most 64 KiB.
// Import CRLs explicitly so this file can never add a trusted CA certificate.
// The store owns its reference; no BIO/file/input views outlive this function.
bool load_client_crl(SSL_CTX* ctx, const char* path) {
    if (!path || path[0] == '\0') return false;
    X509_STORE* store = SSL_CTX_get_cert_store(ctx);
    if (!store) return false;
    // A certificate-only CA bundle keeps this explicit CRL authoritative.
    // Do not let another CRL imported by the CA loader compete with it.
    const STACK_OF(X509_OBJECT)* objects = X509_STORE_get0_objects(store);
    for (int i = 0; i < sk_X509_OBJECT_num(objects); ++i)
        if (X509_OBJECT_get_type(sk_X509_OBJECT_value(objects, i)) == X509_LU_CRL) return false;
    const int kFd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (kFd < 0) return false;
    struct stat info{};
    if (fstat(kFd, &info) != 0 || !S_ISREG(info.st_mode)) {
        close(kFd);
        return false;
    }
    char pem[65536];
    u32 length = 0;
    bool ok = true;
    while (length < sizeof(pem)) {
        const ssize_t kRead = read(kFd, pem + length, sizeof(pem) - length);
        if (kRead < 0 && errno == EINTR) continue;
        if (kRead < 0) ok = false;
        if (kRead <= 0) break;
        length += static_cast<u32>(kRead);
    }
    char extra;
    ssize_t remaining;
    do {
        remaining = read(kFd, &extra, 1);
    } while (remaining < 0 && errno == EINTR);
    close(kFd);
    constexpr char kBegin[] = "-----BEGIN X509 CRL-----";
    if (!ok || remaining != 0 || length < sizeof(kBegin) - 1 ||
        memcmp(pem, kBegin, sizeof(kBegin) - 1) != 0)
        return false;
    BIO* input = BIO_new_mem_buf(pem, static_cast<int>(length));
    if (!input) return false;
    BIO_set_mem_eof_return(input, 0);
    X509_CRL* crl = PEM_read_bio_X509_CRL(input, nullptr, nullptr, nullptr);
    ok = crl != nullptr;
    char tail[256];
    int count;
    while ((count = BIO_read(input, tail, sizeof(tail))) > 0) {
        for (int i = 0; i < count; ++i)
            if (tail[i] != ' ' && tail[i] != '\t' && tail[i] != '\r' && tail[i] != '\n') ok = false;
    }
    BIO_free(input);
    ok = ok && count == 0;
    if (ok) {
        const ASN1_TIME* last = X509_CRL_get0_lastUpdate(crl);
        const ASN1_TIME* next = X509_CRL_get0_nextUpdate(crl);
        ok = last && next && X509_cmp_current_time(last) < 0 && X509_cmp_current_time(next) > 0 &&
             X509_CRL_get_ext_by_NID(crl, NID_delta_crl, -1) < 0 &&
             X509_CRL_get_ext_by_NID(crl, NID_issuing_distribution_point, -1) < 0;
    }
    if (ok) {
        ok = X509_STORE_add_crl(store, crl) == 1 &&
             X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK) == 1;
    }
    X509_CRL_free(crl);
    return ok;
}

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

bool tls_capture_verified_client_fingerprint(SSL* ssl, char out_hex[64], bool& out_valid) {
    out_valid = false;
    if (out_hex == nullptr) return false;
    __builtin_memset(out_hex, 0, 64);
    if (ssl == nullptr) return false;
    if ((SSL_get_verify_mode(ssl) & SSL_VERIFY_FAIL_IF_NO_PEER_CERT) == 0) return true;
    if (!SSL_is_init_finished(ssl) || SSL_get_verify_result(ssl) != X509_V_OK) return false;
    X509* peer = SSL_get1_peer_certificate(ssl);
    if (peer == nullptr) return false;
    u8 digest[EVP_MAX_MD_SIZE]{};
    unsigned digest_len = 0;
    const bool kOk = X509_digest(peer, EVP_sha256(), digest, &digest_len) == 1 && digest_len == 32;
    X509_free(peer);
    if (!kOk) return false;
    static constexpr char kHex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        const size_t kOffset = i * 2;
        out_hex[kOffset] = kHex[digest[i] >> 4];
        out_hex[kOffset + 1] = kHex[digest[i] & 0x0f];
    }
    out_valid = true;
    return true;
}

core::Expected<TlsServerContext*, Error> create_tls_server_context(const char* cert_path,
                                                                   const char* key_path,
                                                                   bool offer_h2,
                                                                   const char* client_ca_path,
                                                                   const char* client_crl_path) {
    if (client_crl_path && !client_ca_path)
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
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

    const bool kRequireClientCertificate = client_ca_path != nullptr;
    if (kRequireClientCertificate) {
        if (client_ca_path[0] == '\0' ||
            SSL_CTX_load_verify_locations(ssl_ctx, client_ca_path, nullptr) != 1 ||
            (client_crl_path && !load_client_crl(ssl_ctx, client_crl_path))) {
            SSL_CTX_free(ssl_ctx);
            BIO_meth_free(bridge_bio_method);
            BIO_meth_free(socket_bio_method);
            return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
        }
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        // This profile has startup-static CA trust and no session/renegotiation
        // path that could inherit authentication from an earlier handshake.
        SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_OFF);
        SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION);
        if (SSL_CTX_set_num_tickets(ssl_ctx, 0) != 1) {
            SSL_CTX_free(ssl_ctx);
            BIO_meth_free(bridge_bio_method);
            BIO_meth_free(socket_bio_method);
            return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
        }
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
    ctx->require_client_certificate = kRequireClientCertificate;
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
                                                    const UpstreamTlsSpec& spec,
                                                    bool http2) {
    if (ctx.ssl_ctx || !spec.enabled || !valid_upstream_tls(spec))
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    if (OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr) != 1)
        return core::make_unexpected(Error::make(EIO, Error::Source::Socket));
    ctx.ssl_ctx = SSL_CTX_new(TLS_client_method());
    ctx.http2 = http2;
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

bool configure_tls_client_ssl(SSL* ssl, const char* server_name, bool http2) {
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
    return http2 ? SSL_set_alpn_protos(ssl, kAlpnH2, sizeof(kAlpnH2)) == 0
                 : SSL_set_alpn_protos(ssl, kAlpnHttp11, sizeof(kAlpnHttp11)) == 0;
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
    if (!configure_tls_client_ssl(ssl, server_name, ctx.http2)) {
        SSL_free(ssl);
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    }
    return ssl;
}

bool tls_handshake_finished(SSL* ssl) {
    return ssl && SSL_is_init_finished(ssl);
}

bool tls_client_peer_valid(SSL* ssl, bool http2) {
    return ssl && SSL_is_init_finished(ssl) && SSL_get_verify_result(ssl) == X509_V_OK &&
           (http2 ? tls_negotiated_protocol(ssl) == AlpnProtocol::H2
                  : tls_negotiated_protocol(ssl) != AlpnProtocol::H2);
}

}  // namespace rut
