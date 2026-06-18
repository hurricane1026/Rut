#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/error.h"
#include "rut/runtime/tls.h"

#include <openssl/base.h>

namespace rut {

// TlsEngine bridges BoringSSL to caller-owned ciphertext buffers for a
// completion-model backend (io_uring), where SSL must NEVER touch the fd.
//
// The epoll backend uses a socket BIO (BIO_new_socket): SSL_read/SSL_write do
// their own recv()/send() at the moment epoll signals readiness. io_uring hands
// us bytes that already arrived in a kernel-chosen buffer, so SSL must instead
// pull ciphertext from memory we fill and push ciphertext to memory we drain.
//
// Rather than BIO_s_mem (which mallocs and adds a second copy), the engine wires
// a custom zero-copy BIO_METHOD: its read callback memcpy's straight out of the
// caller's `in` region and its write callback straight into the caller's `out`
// region — the single copy each crypto layer fundamentally needs, no malloc.
//
// Per-call protocol: the backend points the engine at the current ciphertext
// regions (set_input / set_output), then drives a crypto op (handshake / read /
// write). Afterwards it reads input_consumed() (advance the recv ring) and
// output_len() (ciphertext to io_uring-send).
enum class TlsOp : u8 {
    Ok,         // operation produced data / completed
    WantRead,   // need more network ciphertext — submit another recv
    WantWrite,  // output region full — flush ciphertext, then retry
    Closed,     // peer sent close_notify (clean shutdown)
    Error,      // fatal protocol/crypto error — drop the connection
};

struct TlsEngine {
    SSL* ssl = nullptr;
    // Network ciphertext fed to SSL via the read BIO (set_input).
    const u8* in = nullptr;
    u32 in_len = 0;
    u32 in_off = 0;
    // Ciphertext produced by SSL via the write BIO (set_output), to be sent.
    u8* out = nullptr;
    u32 out_cap = 0;
    u32 out_len = 0;
    bool handshake_done = false;
};

// Create the SSL object in server-accept state, wired to the custom BIO with
// `eng` as the bridge state. On success `eng.ssl` is non-null.
core::Expected<void, Error> tls_engine_init(TlsEngine& eng, TlsServerContext* ctx);
void tls_engine_free(TlsEngine& eng);

// Point the engine at the current ciphertext regions for the next crypto op.
inline void tls_engine_set_input(TlsEngine& eng, const u8* p, u32 n) {
    eng.in = p;
    eng.in_len = n;
    eng.in_off = 0;
}
inline void tls_engine_set_output(TlsEngine& eng, u8* p, u32 cap) {
    eng.out = p;
    eng.out_cap = cap;
    eng.out_len = 0;
}
inline u32 tls_engine_input_consumed(const TlsEngine& eng) {
    return eng.in_off;
}
inline u32 tls_engine_output_len(const TlsEngine& eng) {
    return eng.out_len;
}

// Advance the handshake. On TlsOp::Ok the handshake is complete and
// eng.handshake_done is set. May produce ciphertext into the output region.
TlsOp tls_engine_handshake(TlsEngine& eng);

// Decrypt application data into `dst` (capacity `cap`). Returns bytes written;
// `st` carries the status (WantRead = drained all available ciphertext).
i32 tls_engine_read(TlsEngine& eng, u8* dst, u32 cap, TlsOp& st);

// Encrypt `src` (length `n`) application data; ciphertext lands in the output
// region. Returns plaintext bytes consumed; `st` carries the status
// (WantWrite = output region filled before all plaintext was encrypted).
i32 tls_engine_write(TlsEngine& eng, const u8* src, u32 n, TlsOp& st);

}  // namespace rut
