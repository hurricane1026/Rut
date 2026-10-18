#include "rut/runtime/tls_engine.h"

#include "tls_internal.h"

#include <errno.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace rut {

namespace {

// --- Custom zero-copy BIO bridging SSL to TlsEngine's caller buffers ---
//
// SSL pulls network ciphertext through bridge_bio_read (from eng->in) and pushes
// outgoing ciphertext through bridge_bio_write (into eng->out). When a region is
// exhausted/full the callback returns -1 with the retry flag set, which SSL maps
// to WANT_READ / WANT_WRITE — telling the backend to recv more or flush+retry.

int bridge_bio_write(BIO* bio, const char* data, int len) {
    BIO_clear_retry_flags(bio);
    if (len <= 0) return 0;
    auto* eng = static_cast<TlsEngine*>(BIO_get_data(bio));
    if (!eng || !eng->out) {
        BIO_set_retry_write(bio);
        return -1;
    }
    const u32 kSpace = eng->out_cap - eng->out_len;
    if (kSpace == 0) {
        BIO_set_retry_write(bio);
        return -1;
    }
    const u32 kN = static_cast<u32>(len) < kSpace ? static_cast<u32>(len) : kSpace;
    __builtin_memcpy(eng->out + eng->out_len, data, kN);
    eng->out_len += kN;
    return static_cast<int>(kN);
}

int bridge_bio_read(BIO* bio, char* data, int len) {
    BIO_clear_retry_flags(bio);
    if (len <= 0) return 0;
    auto* eng = static_cast<TlsEngine*>(BIO_get_data(bio));
    if (!eng) {
        BIO_set_retry_read(bio);
        return -1;
    }
    const u32 kAvail = eng->in_len - eng->in_off;
    if (kAvail == 0) {
        BIO_set_retry_read(bio);
        return -1;
    }
    const u32 kN = static_cast<u32>(len) < kAvail ? static_cast<u32>(len) : kAvail;
    __builtin_memcpy(data, eng->in + eng->in_off, kN);
    eng->in_off += kN;
    return static_cast<int>(kN);
}

long bridge_bio_ctrl(BIO*, int cmd, long, void*) {
    // SSL flushes the write BIO after each record; a memory bridge needs no
    // flush. Every other control op is irrelevant to a source/sink memory BIO.
    return cmd == BIO_CTRL_FLUSH ? 1 : 0;
}

int bridge_bio_create(BIO* bio) {
    BIO_set_init(bio, 1);
    BIO_set_data(bio, nullptr);
    return 1;
}

int bridge_bio_destroy(BIO* bio) {
    if (bio) BIO_set_data(bio, nullptr);
    return 1;
}

BIO_METHOD* make_tls_engine_bridge_method_impl() {
    // The bridge is only used through its BIO callbacks, so it needs no
    // process-global custom type index. A fixed source/sink type is sufficient.
    BIO_METHOD* method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "rut-tls-bridge");
    if (method == nullptr) return nullptr;
    if (!BIO_meth_set_write(method, bridge_bio_write) ||
        !BIO_meth_set_read(method, bridge_bio_read) ||
        !BIO_meth_set_ctrl(method, bridge_bio_ctrl) ||
        !BIO_meth_set_create(method, bridge_bio_create) ||
        !BIO_meth_set_destroy(method, bridge_bio_destroy)) {
        BIO_meth_free(method);
        return nullptr;
    }
    return method;
}

TlsOp classify(SSL* ssl, int rc) {
    switch (SSL_get_error(ssl, rc)) {
        case SSL_ERROR_WANT_READ:
            return TlsOp::WantRead;
        case SSL_ERROR_WANT_WRITE:
            return TlsOp::WantWrite;
        case SSL_ERROR_ZERO_RETURN:
            return TlsOp::Closed;
        default:
            return TlsOp::Error;
    }
}

}  // namespace

BIO_METHOD* make_tls_engine_bridge_method() {
    return make_tls_engine_bridge_method_impl();
}

core::Expected<void, Error> tls_engine_init(TlsEngine& eng, TlsServerContext* ctx) {
    if (!ctx || !ctx->ssl_ctx)
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    BIO_METHOD* method = ctx->bridge_bio_method;
    if (!method) return core::make_unexpected(Error::make(EIO, Error::Source::Socket));

    SSL* ssl = SSL_new(ctx->ssl_ctx);
    if (!ssl) return core::make_unexpected(Error::make(EIO, Error::Source::Socket));
    const u64 session_tickets = SSL_get_num_tickets(ssl);
    if (SSL_set_num_tickets(ssl, 0) != 1) {
        SSL_free(ssl);
        return core::make_unexpected(Error::make(EIO, Error::Source::Socket));
    }

    BIO* bio = BIO_new(method);
    if (!bio) {
        SSL_free(ssl);
        return core::make_unexpected(Error::make(EIO, Error::Source::Socket));
    }
    BIO_set_data(bio, &eng);
    // SSL takes ownership of the BIO for both directions (freed by SSL_free).
    SSL_set_bio(ssl, bio, bio);
    SSL_set_accept_state(ssl);
    SSL_set_mode(ssl,
                 SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
                     SSL_MODE_RELEASE_BUFFERS);

    eng.ssl = ssl;
    eng.handshake_done = false;
    eng.deferred_session_tickets = session_tickets;
    return {};
}

core::Expected<void, Error> tls_engine_init_client(TlsEngine& eng,
                                                   TlsClientContext& ctx,
                                                   const char* server_name) {
    if (!ctx.ssl_ctx || !ctx.bridge_bio_method)
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    SSL* ssl = SSL_new(ctx.ssl_ctx);
    if (!ssl) return core::make_unexpected(Error::make(EIO, Error::Source::Socket));
    BIO* bio = BIO_new(ctx.bridge_bio_method);
    if (!bio) {
        SSL_free(ssl);
        return core::make_unexpected(Error::make(EIO, Error::Source::Socket));
    }
    BIO_set_data(bio, &eng);
    SSL_set_bio(ssl, bio, bio);
    if (!configure_tls_client_ssl(ssl, server_name)) {
        SSL_free(ssl);
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    }
    eng.ssl = ssl;
    eng.handshake_done = false;
    eng.deferred_session_tickets = 0;
    return {};
}

void tls_engine_free(TlsEngine& eng) {
    if (eng.ssl) {
        SSL_free(eng.ssl);  // frees the attached BIO too
        eng.ssl = nullptr;
    }
    eng.deferred_session_tickets = 0;
}

TlsOp tls_engine_handshake(TlsEngine& eng) {
    if (!eng.ssl) return TlsOp::Error;
    ERR_clear_error();
    const int kRc = SSL_do_handshake(eng.ssl);
    if (kRc == 1) {
        eng.handshake_done = true;
        return TlsOp::Ok;
    }
    return classify(eng.ssl, kRc);
}

i32 tls_engine_read(TlsEngine& eng, u8* dst, u32 cap, TlsOp& st) {
    if (!eng.ssl) {
        st = TlsOp::Error;
        return 0;
    }
    ERR_clear_error();
    const int kN = SSL_read(eng.ssl, dst, static_cast<int>(cap));
    if (kN > 0) {
        st = TlsOp::Ok;
        return kN;
    }
    st = classify(eng.ssl, kN);
    return 0;
}

i32 tls_engine_write(TlsEngine& eng, const u8* src, u32 n, TlsOp& st) {
    if (!eng.ssl) {
        st = TlsOp::Error;
        return 0;
    }
    ERR_clear_error();
    if (eng.handshake_done && eng.deferred_session_tickets != 0) {
        const u64 requested = eng.deferred_session_tickets;
        eng.deferred_session_tickets = 0;
        if (SSL_version(eng.ssl) == TLS1_3_VERSION) {
            // Match the configured full-handshake count and OpenSSL's one-ticket
            // limit for a resumed session. Queue once, before SSL_write can
            // return WANT_WRITE; retries must not request duplicate tickets.
            const u64 count = SSL_session_reused(eng.ssl) ? 1 : requested;
            for (u64 i = 0; i < count; ++i) {
                if (SSL_new_session_ticket(eng.ssl) != 1) {
                    st = TlsOp::Error;
                    return 0;
                }
            }
        }
    }
    const int kW = SSL_write(eng.ssl, src, static_cast<int>(n));
    if (kW > 0) {
        st = TlsOp::Ok;
        return kW;
    }
    st = classify(eng.ssl, kW);
    return 0;
}

}  // namespace rut
